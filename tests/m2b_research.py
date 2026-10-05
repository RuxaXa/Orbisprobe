"""M2-B real-harness documents for the three frozen research cases (P2-1, CASE-003, SVM).

Every builder returns a plain harness document plus the bytes of the binary it describes, so a
caller can materialize the file, hash it, and hand both to the dynamic backend. CASE-003 and the
SVM slice are derived from the frozen M2-A fixtures; nothing here contacts a live target, and the
SVM slice is a 64-byte immutable copy of the real FW9 kernel image (see the fixture's
``source_sha256``).
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

SCHEMA = "m2b-harness-v1"
CODE_SIZE = 0x200
STACK_BASE = 0x700000
STACK_SIZE = 0x1000
STACK_TOP = STACK_BASE + STACK_SIZE - 0x10

FIXTURES = Path(__file__).parent / "fixtures"

#: P2-1 guarded index function (real firmware-derived 18-byte fragment, M2-A fixture).
P2_1_BASE = 0x631AD0
P2_1_CODE = bytes.fromhex("55 48 89 e5 49 83 fc 01 77 05 4c 89 e0 90 c3 31 c0 c3")
#: ``ja`` at this offset decides whether the index is used directly or replaced by zero.
P2_1_BRANCH_OFFSET = 8
P2_1_BRANCH_SIZE = 2
#: Observed control flow for concrete index values: 0/1 fall through, 2/3 take the branch.
P2_1_GUARD_TAKEN = {0: False, 1: False, 2: True, 3: True}
P2_1_RETURN_VALUE = {0: 0, 1: 1, 2: 0, 3: 0}

#: CASE-003 host-side descriptor fixture.
CASE003_BASE = 0x638000
CASE003_DESCRIPTOR = 0x600000
CASE003_SCRATCH = 0x601000
CASE003_DESCRIPTOR_SIZE = 0x80
#: The two call instructions are call-to-next-instruction idioms, so the fragment loops through
#: itself until the outer-return sentinel no longer matches.
CASE003_EXPECTED_SINKS = ((CASE003_DESCRIPTOR + 0x08), (CASE003_DESCRIPTOR + 0x10))

#: 64-byte immutable slice of the real FW9 kernel image at the SVM address.
SVM_BASE = 0xFFFFFFFFDA3C9CB1
SVM_SLICE_SIZE = 64


def _padded(code: bytes, size: int = CODE_SIZE) -> bytes:
    if len(code) > size:
        raise ValueError("code does not fit the code region")
    return code + b"\x00" * (size - len(code))


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _svm_slice_hex() -> str:
    fixture = json.loads(
        (FIXTURES / "m2a" / "fw900_svm_angr_incomplete.json").read_text(encoding="utf-8")
    )
    return str(fixture["binary_hex"]).replace(" ", "")


def p2_1_binary() -> bytes:
    return _padded(P2_1_CODE)


def p2_1_document(index: int) -> dict[str, Any]:
    """Harness for P2-1 with one concrete value in the index register ``r12``."""

    document = {
        "schema_version": SCHEMA,
        "harness_id": f"m2b-p2-1-r12-{index}",
        "binary_sha256": _sha256(p2_1_binary()),
        "architecture": "x86_64",
        "base": P2_1_BASE,
        "function_entry": P2_1_BASE,
        "function_end": P2_1_BASE + len(P2_1_CODE),
        "calling_convention": "sysv-amd64",
        "initial_registers": {"rsp": STACK_TOP, "r12": index},
        "stack_base": STACK_BASE,
        "stack_size": STACK_SIZE,
        "memory_regions": [
            {
                "name": "code",
                "base": P2_1_BASE,
                "size": CODE_SIZE,
                "permissions": "rx",
                "source": "binary",
            },
            {
                "name": "stack",
                "base": STACK_BASE,
                "size": STACK_SIZE,
                "permissions": "rw",
                "source": "zero",
            },
        ],
        "input_regions": [],
        "output_regions": [],
        "taint_sources": [{"kind": "register", "register": "r12", "label": "user.index"}],
        "expected_sinks": [],
        "callee_stubs": [],
        "stop_conditions": [{"kind": "RETURN"}],
        "instruction_limit": 32,
        "branch_limit": 8,
        "timeout_seconds": 30,
        "max_trace_entries": 16,
        "notes": (
            "P2-1 guarded index fragment; the 18-byte snippet has no epilogue that restores RSP, "
            "so the run ends with an unmapped return instead of the harness sentinel"
        ),
    }
    return document


def case003_binary() -> bytes:
    fixture = json.loads(
        (FIXTURES / "case003_host_descriptor.json").read_text(encoding="utf-8")
    )
    return _padded(bytes.fromhex(str(fixture["binary_hex"]).replace(" ", "")))


def case003_document(taint_range_size: int | None = CASE003_DESCRIPTOR_SIZE) -> dict[str, Any]:
    """Harness for the CASE-003 host descriptor fragment.

    ``taint_range_size`` selects a single memory taint source of that many bytes (the natural
    form); pass ``None`` for register-only taint, or a smaller size to exercise chunked input.
    """

    taint_sources: list[dict[str, Any]] = [
        {"kind": "register", "register": "rsi", "label": "user.descriptor"}
    ]
    if taint_range_size is not None:
        taint_sources.append(
            {
                "kind": "memory",
                "address": CASE003_DESCRIPTOR,
                "size": taint_range_size,
                "label": "user.descriptor.bytes",
            }
        )
    return {
        "schema_version": SCHEMA,
        "harness_id": "m2b-case003-host-descriptor",
        "binary_sha256": _sha256(case003_binary()),
        "architecture": "x86_64",
        "base": CASE003_BASE,
        "function_entry": CASE003_BASE,
        "function_end": CASE003_BASE + 66,
        "calling_convention": "sysv-amd64",
        "initial_registers": {
            "rsp": STACK_TOP,
            "rsi": CASE003_DESCRIPTOR,
            "r15": CASE003_SCRATCH,
            "rax": 0,
            "rdx": 0,
        },
        "stack_base": STACK_BASE,
        "stack_size": STACK_SIZE,
        "memory_regions": [
            {
                "name": "code",
                "base": CASE003_BASE,
                "size": CODE_SIZE,
                "permissions": "rx",
                "source": "binary",
            },
            {
                "name": "descriptor",
                "base": CASE003_DESCRIPTOR,
                "size": 0x1000,
                "permissions": "rw",
                "source": "zero",
            },
            {
                "name": "scratch",
                "base": CASE003_SCRATCH,
                "size": 0x1000,
                "permissions": "rw",
                "source": "zero",
            },
            {
                "name": "stack",
                "base": STACK_BASE,
                "size": STACK_SIZE,
                "permissions": "rw",
                "source": "zero",
            },
        ],
        "input_regions": [
            {
                "name": "descriptor_in",
                "address": CASE003_DESCRIPTOR,
                "size": CASE003_DESCRIPTOR_SIZE,
                "tainted": True,
            }
        ],
        "output_regions": [
            {
                "name": "descriptor_out",
                "address": CASE003_DESCRIPTOR,
                "size": CASE003_DESCRIPTOR_SIZE,
            }
        ],
        "taint_sources": taint_sources,
        "expected_sinks": [],
        "callee_stubs": [],
        "stop_conditions": [{"kind": "RETURN"}],
        "instruction_limit": 64,
        "branch_limit": 16,
        "timeout_seconds": 30,
        "max_trace_entries": 64,
        "notes": "CASE-003 host-descriptor fragment executed offline under the M2-B harness",
    }


def svm_binary() -> bytes:
    return bytes.fromhex(_svm_slice_hex())


def svm_document() -> dict[str, Any]:
    """Harness for the 64-byte SVM slice; no taint source is claimed for foreign kernel bytes."""

    return {
        "schema_version": SCHEMA,
        "harness_id": "m2b-svm-fw900-slice",
        "binary_sha256": _sha256(svm_binary()),
        "architecture": "x86_64",
        "base": SVM_BASE,
        "function_entry": SVM_BASE,
        "function_end": SVM_BASE + SVM_SLICE_SIZE,
        "calling_convention": "sysv-amd64",
        "initial_registers": {"rsp": STACK_TOP},
        "stack_base": STACK_BASE,
        "stack_size": STACK_SIZE,
        "memory_regions": [
            {
                "name": "code",
                "base": SVM_BASE,
                "size": SVM_SLICE_SIZE,
                "permissions": "rx",
                "source": "binary",
            },
            {
                "name": "stack",
                "base": STACK_BASE,
                "size": STACK_SIZE,
                "permissions": "rw",
                "source": "zero",
            },
        ],
        "input_regions": [],
        "output_regions": [],
        "taint_sources": [],
        "expected_sinks": [],
        "callee_stubs": [],
        "stop_conditions": [{"kind": "RETURN"}],
        "instruction_limit": 32,
        "branch_limit": 8,
        "timeout_seconds": 30,
        "max_trace_entries": 32,
        "notes": "immutable 64-byte FW9 kernel slice at the SVM address, executed offline",
    }
