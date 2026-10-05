"""M2-B synthetic harness cases (A-N) with explicit expected results.

Each case is a raw x86-64 function plus a full harness description. The expected values in this
table were derived by hand from the instruction semantics *before* running Triton; where the engine
disagreed, the disagreement was investigated rather than silently adopted.

Layout used by every case unless stated otherwise:

* code       0x400000 (r-x) source=binary, size 0x200
* destination 0x600000 (rw-) zero-filled; "descriptor" output region 0x600000 size 0x40
* source     0x610000 (r--) literal 0xAA, input region 0x610000 size 0x40
* stack      0x700000 (rw-) size 0x1000
* callee target 0x500000 (never mapped; only reachable through a declared stub)
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

CODE_BASE = 0x400000
CODE_SIZE = 0x200
DESCRIPTOR_BASE = 0x600000
SOURCE_BASE = 0x610000
STACK_BASE = 0x700000
STACK_SIZE = 0x1000
STUB_TARGET = 0x500000


@dataclass
class HarnessCase:
    case_id: str
    code_hex: str
    description: str
    initial_registers: dict[str, int]
    taint_sources: list[dict[str, Any]]
    callee_stubs: list[dict[str, Any]]
    input_regions: list[dict[str, Any]]
    expected_status: str
    expected_stop: str
    expected_sink_types: set[str] = field(default_factory=set)
    expected_tainted_sources: set[str] = field(default_factory=set)
    expected_violations: int = 0
    expected_stub_behaviors: set[str] = field(default_factory=set)
    expected_min_branches: int = 0
    expected_memory_writes: int | None = None
    expected_min_constraints: int = 0
    expected_return_value: int | None = None
    #: Per-source sink attribution: which tainted source is allowed to reach which sink.
    expected_sink_by_source: dict[str, set[str]] = field(default_factory=dict)
    notes: str = ""

    def binary_bytes(self) -> bytes:
        code = bytes.fromhex(self.code_hex)
        if len(code) > CODE_SIZE:
            raise ValueError(f"{self.case_id}: code does not fit the code region")
        return code + b"\x00" * (CODE_SIZE - len(code))

    def binary_sha256(self) -> str:
        return hashlib.sha256(self.binary_bytes()).hexdigest()

    def document(self) -> dict[str, Any]:
        return {
            "harness_id": f"m2b-{self.case_id}",
            "binary_sha256": self.binary_sha256(),
            "architecture": "x86_64",
            "base": CODE_BASE,
            "function_entry": CODE_BASE,
            "function_end": CODE_BASE + CODE_SIZE,
            "calling_convention": "sysv-amd64",
            "initial_registers": {"rsp": STACK_BASE + STACK_SIZE - 0x10, **self.initial_registers},
            "stack_base": STACK_BASE,
            "stack_size": STACK_SIZE,
            "memory_regions": [
                {
                    "name": "code",
                    "base": CODE_BASE,
                    "size": CODE_SIZE,
                    "permissions": "rx",
                    "source": "binary",
                },
                {
                    "name": "descriptor",
                    "base": DESCRIPTOR_BASE,
                    "size": 0x1000,
                    "permissions": "rw",
                    "source": "zero",
                },
                {
                    "name": "user",
                    "base": SOURCE_BASE,
                    "size": 0x100,
                    "permissions": "r",
                    "source": "literal",
                    "initial_data": "aa" * 0x100,
                },
                {
                    "name": "stack",
                    "base": STACK_BASE,
                    "size": STACK_SIZE,
                    "permissions": "rw",
                    "source": "zero",
                },
            ],
            "input_regions": self.input_regions,
            "output_regions": [{"name": "descriptor", "address": DESCRIPTOR_BASE, "size": 0x40}],
            "taint_sources": self.taint_sources,
            "expected_sinks": [],
            "callee_stubs": self.callee_stubs,
            "stop_conditions": [{"kind": "RETURN"}],
            "instruction_limit": 128,
            "branch_limit": 16,
            "timeout_seconds": 30,
            "max_trace_entries": 64,
            "notes": self.description,
        }


def _call_to(address: int, target: int = STUB_TARGET) -> str:
    rel = target - (address + 5)
    raw = rel & 0xFFFFFFFF
    return "e8 " + " ".join(f"{byte:02x}" for byte in raw.to_bytes(4, "little"))


def _mov_relaxed_ja(address: int, target: int) -> str:
    rel = target - (address + 2)
    return "77 " + f"{rel & 0xFF:02x}"


def _stub(name: str, behavior: str, **extra: Any) -> dict[str, Any]:
    stub: dict[str, Any] = {"target": STUB_TARGET, "name": name, "behavior": behavior}
    stub.update(extra)
    return stub


def _memcpy_stub() -> dict[str, Any]:
    return _stub(
        "memcpy_stub",
        "memcpy",
        memory_effects=[{"kind": "WRITE", "address": DESCRIPTOR_BASE, "size": 0x40}],
    )


def _status_stub() -> dict[str, Any]:
    return _stub("status_stub", "status_ok", return_value=0)


def _base_registers() -> dict[str, int]:
    return {"rdi": DESCRIPTOR_BASE, "rsi": SOURCE_BASE, "rdx": 0x20}


CASES: tuple[HarnessCase, ...] = (
    HarnessCase(
        case_id="A-tainted-length-memcpy",
        description="tainted length register reaches the memcpy stub",
        code_hex=(
            "48 89 f8 " + _call_to(CODE_BASE + 3) + " c3"
        ),
        initial_registers={**_base_registers(), "rdx": 0x20},
        input_regions=[{"name": "user", "address": SOURCE_BASE, "size": 0x40, "tainted": True}],
        taint_sources=[
            {"kind": "memory", "address": SOURCE_BASE, "size": 0x40, "label": "user.data"},
            {"kind": "register", "register": "rdx", "label": "user.length"},
        ],
        callee_stubs=[_memcpy_stub()],
        expected_status="COMPLETED",
        expected_stop="RETURN",
        expected_sink_types={"MEMORY_LENGTH", "MEMORY_WRITE_FROM_TAINTED_SOURCE"},
        expected_tainted_sources={"user.data", "user.length"},
        expected_stub_behaviors={"memcpy"},
        expected_return_value=DESCRIPTOR_BASE,
    ),
    HarnessCase(
        case_id="B-tainted-index",
        description="tainted register used as an array index",
        code_hex="48 8b 04 d7 48 89 46 08 c3",
        initial_registers={"rdi": SOURCE_BASE, "rsi": DESCRIPTOR_BASE, "rdx": 0x01},
        input_regions=[],
        taint_sources=[{"kind": "register", "register": "rdx", "label": "user.index"}],
        callee_stubs=[],
        expected_status="COMPLETED",
        expected_stop="RETURN",
        expected_sink_types={"ARRAY_INDEX"},
        expected_tainted_sources={"user.index"},
    ),
    HarnessCase(
        case_id="C-tainted-pointer-to-descriptor",
        description="tainted pointer value is stored into a descriptor field",
        code_hex="48 89 77 08 c3",
        initial_registers={"rdi": DESCRIPTOR_BASE, "rsi": SOURCE_BASE, "rdx": 0},
        input_regions=[],
        taint_sources=[{"kind": "register", "register": "rsi", "label": "user.ptr"}],
        callee_stubs=[],
        expected_status="COMPLETED",
        expected_stop="RETURN",
        expected_sink_types={"DESCRIPTOR_FIELD"},
        expected_tainted_sources={"user.ptr"},
    ),
    HarnessCase(
        case_id="D-overwrite-clears-taint",
        description="a redefinition without taint removes the stale taint label",
        code_hex="48 89 c1 31 c0 48 89 47 08 c3",
        initial_registers={"rdi": DESCRIPTOR_BASE, "rsi": SOURCE_BASE, "rdx": 0, "rax": SOURCE_BASE},
        input_regions=[],
        taint_sources=[{"kind": "register", "register": "rax", "label": "user.value"}],
        callee_stubs=[],
        expected_status="COMPLETED",
        expected_stop="RETURN",
        expected_sink_types=set(),
        expected_tainted_sources=set(),
    ),
    HarnessCase(
        case_id="E-caller-saved-clobber",
        description="stub return register replaces tainted caller-saved data",
        code_hex=("48 89 f0 " + _call_to(CODE_BASE + 3) + " 48 89 47 08 c3"),
        initial_registers={"rdi": DESCRIPTOR_BASE, "rsi": SOURCE_BASE, "rdx": 0},
        input_regions=[],
        taint_sources=[{"kind": "register", "register": "rsi", "label": "user.ptr"}],
        callee_stubs=[_status_stub()],
        expected_status="COMPLETED",
        expected_stop="RETURN",
        expected_sink_types=set(),
        expected_tainted_sources=set(),
        expected_stub_behaviors={"status_ok"},
    ),
    HarnessCase(
        case_id="F-callee-saved-preserved",
        description="callee-saved register keeps its taint across a stub call",
        code_hex=("48 89 f3 " + _call_to(CODE_BASE + 3) + " 48 89 5f 08 c3"),
        initial_registers={"rdi": DESCRIPTOR_BASE, "rsi": SOURCE_BASE, "rdx": 0},
        input_regions=[],
        taint_sources=[{"kind": "register", "register": "rsi", "label": "user.ptr"}],
        callee_stubs=[_status_stub()],
        expected_status="COMPLETED",
        expected_stop="RETURN",
        expected_sink_types={"DESCRIPTOR_FIELD"},
        expected_tainted_sources={"user.ptr"},
        expected_stub_behaviors={"status_ok"},
    ),
    HarnessCase(
        case_id="G-symbolic-branch",
        description="symbolic input produces a recorded branch constraint",
        code_hex="48 8b 16 48 83 fa 20 " + _mov_relaxed_ja(CODE_BASE + 7, CODE_BASE + 0x0D) + " 48 89 57 08 c3",
        initial_registers={"rdi": DESCRIPTOR_BASE, "rsi": SOURCE_BASE, "rdx": 0},
        input_regions=[
            {
                "name": "user_len",
                "address": SOURCE_BASE,
                "size": 8,
                "concrete_value": "2000000000000000",
                "symbolic": True,
                "symbolic_name": "user_len",
                "tainted": True,
            }
        ],
        taint_sources=[{"kind": "memory", "address": SOURCE_BASE, "size": 8, "label": "user.len"}],
        callee_stubs=[],
        expected_status="COMPLETED",
        expected_stop="RETURN",
        expected_min_branches=1,
        expected_min_constraints=1,
        expected_sink_types={"BRANCH_CONDITION", "DESCRIPTOR_FIELD"},
        expected_tainted_sources={"user.len"},
        expected_sink_by_source={"user.len": {"BRANCH_CONDITION", "DESCRIPTOR_FIELD"}},
    ),
    HarnessCase(
        case_id="H-dead-store",
        description="tainted store that is immediately overwritten",
        code_hex="48 89 77 08 48 c7 47 08 00 00 00 00 c3",
        initial_registers={"rdi": DESCRIPTOR_BASE, "rsi": SOURCE_BASE, "rdx": 0},
        input_regions=[],
        taint_sources=[{"kind": "register", "register": "rsi", "label": "user.ptr"}],
        callee_stubs=[],
        expected_status="COMPLETED",
        expected_stop="RETURN",
        expected_sink_types={"DESCRIPTOR_FIELD"},
        expected_tainted_sources={"user.ptr"},
        expected_memory_writes=2,
    ),
    HarnessCase(
        case_id="I-dead-stack-slot",
        description="tainted value written to a stack slot that is never read",
        code_hex="48 89 74 24 f8 c3",
        initial_registers={"rdi": DESCRIPTOR_BASE, "rsi": SOURCE_BASE, "rdx": 0},
        input_regions=[],
        taint_sources=[{"kind": "register", "register": "rsi", "label": "user.ptr"}],
        callee_stubs=[],
        expected_status="COMPLETED",
        expected_stop="RETURN",
        expected_sink_types=set(),
        expected_tainted_sources=set(),
        expected_memory_writes=1,
    ),
    HarnessCase(
        case_id="J-validated-length",
        description="tainted length checked against a bound and then used by memcpy",
        code_hex=(
            "48 83 fa 40 "
            + _mov_relaxed_ja(CODE_BASE + 4, CODE_BASE + 0x10)
            + " 48 89 f8 "
            + _call_to(CODE_BASE + 9)
            + " c3 90 31 c0 c3"
        ),
        initial_registers={**_base_registers(), "rdx": 0x20},
        input_regions=[],
        taint_sources=[{"kind": "register", "register": "rdx", "label": "user.length"}],
        callee_stubs=[_memcpy_stub()],
        expected_status="COMPLETED",
        expected_stop="RETURN",
        expected_sink_types={"MEMORY_LENGTH", "BRANCH_CONDITION"},
        expected_tainted_sources={"user.length"},
        expected_stub_behaviors={"memcpy"},
        expected_min_branches=1,
    ),
    HarnessCase(
        case_id="K-stale-validation",
        description="validated length is replaced by an unvalidated value before the copy",
        code_hex=(
            "48 83 fa 40 "
            + _mov_relaxed_ja(CODE_BASE + 4, CODE_BASE + 0x16)
            + " 48 8b 96 80 00 00 00 48 89 f8 "
            + _call_to(CODE_BASE + 0x10)
            + " c3 90 31 c0 c3"
        ),
        initial_registers={**_base_registers(), "rdx": 0x20},
        input_regions=[
            {
                "name": "second_len",
                "address": SOURCE_BASE + 0x80,
                "size": 8,
                "concrete_value": "3000000000000000",
                "tainted": True,
            }
        ],
        taint_sources=[
            {"kind": "register", "register": "rdx", "label": "user.length.validated"},
            {
                "kind": "memory",
                "address": SOURCE_BASE + 0x80,
                "size": 8,
                "label": "user.length.second",
            },
        ],
        callee_stubs=[_memcpy_stub()],
        expected_status="COMPLETED",
        expected_stop="RETURN",
        expected_sink_types={"MEMORY_LENGTH", "BRANCH_CONDITION"},
        expected_tainted_sources={"user.length.second", "user.length.validated"},
        expected_sink_by_source={
            "user.length.second": {"MEMORY_LENGTH"},
            "user.length.validated": {"BRANCH_CONDITION"},
        },
        expected_stub_behaviors={"memcpy"},
        expected_min_branches=1,
    ),
    HarnessCase(
        case_id="L-concrete-safe-invariant",
        description="fixed length and untouched taint source: no flow reaches a sink",
        code_hex=("48 89 f8 ba 20 00 00 00 " + _call_to(CODE_BASE + 8) + " c3"),
        initial_registers={"rdi": DESCRIPTOR_BASE, "rsi": SOURCE_BASE, "rdx": 0},
        input_regions=[],
        taint_sources=[{"kind": "register", "register": "rbx", "label": "user.unused"}],
        callee_stubs=[_memcpy_stub()],
        expected_status="COMPLETED",
        expected_stop="RETURN",
        expected_sink_types=set(),
        expected_tainted_sources=set(),
        expected_stub_behaviors={"memcpy"},
    ),
    HarnessCase(
        case_id="M-r15-overwrite",
        description="r15 loses its taint when redefined by a zeroing instruction",
        code_hex="49 89 f7 45 31 ff 4c 89 7f 08 c3",
        initial_registers={"rdi": DESCRIPTOR_BASE, "rsi": SOURCE_BASE, "rdx": 0},
        input_regions=[],
        taint_sources=[{"kind": "register", "register": "rsi", "label": "user.value"}],
        callee_stubs=[],
        expected_status="COMPLETED",
        expected_stop="RETURN",
        expected_sink_types=set(),
        expected_tainted_sources=set(),
    ),
    HarnessCase(
        case_id="N-rbx-overwrite",
        description="rbx loses its taint when redefined by a zeroing instruction",
        code_hex="48 89 f3 31 db 48 89 5f 08 c3",
        initial_registers={"rdi": DESCRIPTOR_BASE, "rsi": SOURCE_BASE, "rdx": 0},
        input_regions=[],
        taint_sources=[{"kind": "register", "register": "rsi", "label": "user.value"}],
        callee_stubs=[],
        expected_status="COMPLETED",
        expected_stop="RETURN",
        expected_sink_types=set(),
        expected_tainted_sources=set(),
    ),
)


def case_by_id(case_id: str) -> HarnessCase:
    for case in CASES:
        if case.case_id == case_id:
            return case
    raise KeyError(case_id)


def materialize(case: HarnessCase, root: Path) -> Path:
    """Write the case binary and return its path."""

    root.mkdir(parents=True, exist_ok=True)
    path = root / f"{case.case_id}.bin"
    path.write_bytes(case.binary_bytes())
    return path


def write_harness_file(case: HarnessCase, root: Path) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    path = root / f"{case.case_id}.harness.json"
    path.write_text(json.dumps(case.document(), indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path
