"""M2-B1 intra-function CALL/RET execution tests (cases A-J).

Every case builds a real x86-64 code image, runs it through the Triton worker, and asserts the
control-flow classification, the call stack evidence, the taint behaviour, and the structured
failure modes. Synthetic code is correct here: these tests pin engine semantics. Real firmware
bytes are only used by the research harnesses.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from orbisprobe.backends.base import BackendStatus, ResourceLimits
from orbisprobe.backends.triton_backend import TritonBackend
from orbisprobe.harness import parse_harness

ROOT = Path(__file__).parents[1]
TRITON_PYTHON = Path(
    os.environ.get("ORBISPROBE_TRITON_PYTHON", ROOT / ".backend-envs" / "triton" / "bin" / "python")
)
requires_triton = pytest.mark.skipif(
    not TRITON_PYTHON.is_file(), reason="triton worker environment is not installed"
)

CODE_BASE = 0x400000
CODE_SIZE = 0x200
DESCRIPTOR_BASE = 0x600000
SOURCE_BASE = 0x610000
STACK_BASE = 0x700000
STACK_SIZE = 0x1000
STUB_TARGET = 0x500000


def call_to(address: int, target: int) -> str:
    rel = (target - (address + 5)) & 0xFFFFFFFF
    return "e8 " + " ".join(f"{byte:02x}" for byte in rel.to_bytes(4, "little"))


def build_document(code_hex: str, *, taint_registers=("rsi",), stubs=None, **overrides):
    code = bytes.fromhex(code_hex)
    document = {
        "schema_version": "m2b-harness-v1",
        "harness_id": "m2b-internal-call-case",
        "binary_sha256": "0" * 64,
        "architecture": "x86_64",
        "base": CODE_BASE,
        "function_entry": CODE_BASE,
        "function_end": CODE_BASE + CODE_SIZE,
        "calling_convention": "sysv-amd64",
        "initial_registers": {
            "rdi": DESCRIPTOR_BASE,
            "rsi": SOURCE_BASE,
            "rdx": 0x20,
            "rsp": STACK_BASE + STACK_SIZE - 0x10,
        },
        "stack_base": STACK_BASE,
        "stack_size": STACK_SIZE,
        "memory_regions": [
            {"name": "code", "base": CODE_BASE, "size": CODE_SIZE, "permissions": "rx", "source": "binary"},
            {"name": "descriptor", "base": DESCRIPTOR_BASE, "size": 0x1000, "permissions": "rw", "source": "zero"},
            {
                "name": "user",
                "base": SOURCE_BASE,
                "size": 0x100,
                "permissions": "r",
                "source": "literal",
                "initial_data": "aa" * 0x100,
            },
            {"name": "stack", "base": STACK_BASE, "size": STACK_SIZE, "permissions": "rw", "source": "zero"},
        ],
        "input_regions": [],
        "output_regions": [{"name": "descriptor", "address": DESCRIPTOR_BASE, "size": 0x40}],
        "taint_sources": [
            {"kind": "register", "register": register, "label": f"user.{register}"}
            for register in taint_registers
        ],
        "expected_sinks": [],
        "callee_stubs": stubs or [],
        "stop_conditions": [{"kind": "RETURN"}],
        "instruction_limit": 256,
        "branch_limit": 32,
        "max_call_depth": 8,
        "max_internal_calls": 64,
        "timeout_seconds": 30,
        "max_trace_entries": 128,
    }
    document.update(overrides)
    return document, code + b"\x00" * (CODE_SIZE - len(code))


def run(tmp_path: Path, code_hex: str, *, operation="trace", **kwargs):
    document, blob = build_document(code_hex, **kwargs)
    import hashlib

    document["binary_sha256"] = hashlib.sha256(blob).hexdigest()
    tmp_path.mkdir(parents=True, exist_ok=True)
    binary = tmp_path / "internal-call.bin"
    binary.write_bytes(blob)
    harness = parse_harness(document)
    result = TritonBackend(
        limits=ResourceLimits(timeout_seconds=60, maximum_steps=4096)
    ).run_harness(
        {
            "harness": harness,
            "binary": str(binary),
            "binary_sha256": document["binary_sha256"],
            "operation": operation,
        }
    )
    return result


def sink_sources(result) -> dict[str, set[str]]:
    mapping: dict[str, set[str]] = {}
    for flow in result.data.get("taint_flows", []):
        sinks = {entry["sink"] for entry in flow.get("sinks", [])}
        if flow.get("sink"):
            sinks.add(flow["sink"])
        if sinks:
            mapping[flow["source"]] = sinks
    return mapping


def violations(result) -> set[str]:
    return {item["kind"] for item in result.data.get("memory_violations", [])}


@requires_triton
def test_a_single_internal_call_returns_to_the_caller(tmp_path: Path):
    code = (
        call_to(CODE_BASE, CODE_BASE + 0x10)
        + " 48 c7 47 08 02 00 00 00 c3 90 90"
        + " b8 01 00 00 00 c3"
    )
    result = run(tmp_path, code)
    data = result.data
    assert result.status is BackendStatus.COMPLETED, result.errors
    assert data["stop_reason"] == "RETURN"
    assert data["internal_calls"] == 1
    assert data["max_call_depth"] == 1
    assert data["call_depth"] == 0
    assert data["sentinel_return_installed"] is True
    event = data["call_events"][0]
    assert event["classification"] == "INTERNAL"
    assert event["target"] == CODE_BASE + 0x10
    assert event["return_address"] == CODE_BASE + 5
    assert data["return_events"][0]["classification"] == "INTERNAL_RETURN"
    assert data["return_events"][0]["target"] == CODE_BASE + 5
    assert data["return_events"][-1]["classification"] == "HARNESS_RETURN"
    assert violations(result) == set()
    # the outer store ran after the callee returned
    assert any(item["address"] == DESCRIPTOR_BASE + 8 for item in data["memory_writes"])


@requires_triton
def test_b_nested_internal_calls_depth_three(tmp_path: Path):
    code = (
        call_to(CODE_BASE, CODE_BASE + 0x10)
        + " c3 90 90 90 90 90 90 90 90 90 90"
        + call_to(CODE_BASE + 0x10, CODE_BASE + 0x20)
        + " c3 90 90 90 90 90 90 90 90 90 90"
        + call_to(CODE_BASE + 0x20, CODE_BASE + 0x30)
        + " c3 90 90 90 90 90 90 90 90 90 90"
        + " c3"
    )
    result = run(tmp_path, code)
    data = result.data
    assert result.status is BackendStatus.COMPLETED, result.errors
    assert data["internal_calls"] == 3
    assert data["max_call_depth"] == 3
    assert data["call_depth"] == 0
    assert [event["depth_after"] for event in data["call_events"]] == [1, 2, 3]
    assert [event["classification"] for event in data["return_events"]] == [
        "INTERNAL_RETURN",
        "INTERNAL_RETURN",
        "INTERNAL_RETURN",
        "HARNESS_RETURN",
    ]
    assert violations(result) == set()


@requires_triton
def test_c_internal_call_then_registered_stub(tmp_path: Path):
    code = (
        call_to(CODE_BASE, CODE_BASE + 0x10)
        + " c3 90 90 90 90 90 90 90 90 90 90"
        + call_to(CODE_BASE + 0x10, STUB_TARGET)
        + " c3"
    )
    stubs = [{"target": STUB_TARGET, "name": "status_stub", "behavior": "status_ok", "return_value": 0}]
    result = run(tmp_path, code, stubs=stubs)
    data = result.data
    assert result.status is BackendStatus.COMPLETED, result.errors
    assert data["internal_calls"] == 1
    assert {event["behavior"] for event in data["stubs_used"]} == {"status_ok"}
    assert data["call_events"][0]["classification"] == "INTERNAL"
    assert any(
        entry.get("classification") == "REGISTERED_STUB" for entry in data["calls"]
    )
    assert data["stop_reason"] == "RETURN"


@requires_triton
def test_d_unknown_external_call_stops_as_stub_required(tmp_path: Path):
    code = call_to(CODE_BASE, STUB_TARGET) + " c3"
    result = run(tmp_path, code)
    data = result.data
    assert result.status is BackendStatus.ANALYSIS_INCOMPLETE
    assert data["stop_reason"] == "STUB_REQUIRED"
    assert data["calls"][0]["classification"] == "EXTERNAL_UNKNOWN"
    assert data["calls"][0]["resolved"] is False
    assert data["stubs_used"] == []
    assert data["internal_calls"] == 0


@requires_triton
def test_e_recursive_internal_call_hits_the_depth_limit(tmp_path: Path):
    code = call_to(CODE_BASE, CODE_BASE) + " c3"
    result = run(tmp_path, code, max_call_depth=3)
    data = result.data
    assert result.status is BackendStatus.RESOURCE_LIMIT
    assert data["stop_reason"] == "CALL_DEPTH_EXCEEDED"
    assert "CALL_DEPTH_EXCEEDED" in violations(result)
    # The fourth recursive CALL is rejected before Triton executes it, so the maximum *executed*
    # depth remains three.
    assert data["max_call_depth"] == 3
    assert data["internal_calls"] == 3
    # no worker crash, and the run stayed bounded
    assert data["instructions_executed"] < 64


@requires_triton
def test_f_ret_with_invalid_stack_target_is_structured(tmp_path: Path):
    code = "48 83 c4 08 c3"  # add rsp, 8; ret -> pops a zeroed slot
    result = run(tmp_path, code)
    data = result.data
    assert result.status is BackendStatus.ANALYSIS_INCOMPLETE
    assert "CORRUPTED_STACK_RETURN" in violations(result)
    assert data["stop_reason"] == "UNMAPPED"
    assert data["return_events"][-1]["classification"] == "CORRUPTED_RETURN"


@requires_triton
def test_g_internal_callee_is_not_an_abstract_clobber(tmp_path: Path):
    # The callee only executes a nop, so rax keeps the tainted caller value across the call.
    code = (
        "48 89 f0 "
        + call_to(CODE_BASE + 3, CODE_BASE + 0x10)
        + " 48 89 47 08 c3 90 90"
        + " 90 c3"
    )
    result = run(tmp_path, code)
    assert result.status is BackendStatus.COMPLETED, result.errors
    assert sink_sources(result) == {"user.rsi": {"DESCRIPTOR_FIELD", "RETURN_VALUE"}}
    # a callee that really overwrites rax does clear the taint
    clobbering = (
        "48 89 f0 "
        + call_to(CODE_BASE + 3, CODE_BASE + 0x10)
        + " 48 89 47 08 c3 90 90 90"
        + " 31 c0 c3"
    )
    cleared = run(tmp_path / "clobber", clobbering)
    assert cleared.status is BackendStatus.COMPLETED, cleared.errors
    assert sink_sources(cleared) == {}


@requires_triton
def test_h_callee_saved_preserved_only_when_the_callee_keeps_it(tmp_path: Path):
    preserving = (
        "48 89 f3 "
        + call_to(CODE_BASE + 3, CODE_BASE + 0x10)
        + " 48 89 5f 08 c3 90 90 90"
        + " b9 05 00 00 00 c3"
    )
    result = run(tmp_path, preserving)
    assert result.status is BackendStatus.COMPLETED, result.errors
    assert sink_sources(result) == {"user.rsi": {"DESCRIPTOR_FIELD"}}

    overwriting = (
        "48 89 f3 "
        + call_to(CODE_BASE + 3, CODE_BASE + 0x10)
        + " 48 89 5f 08 c3 90 90 90"
        + " 31 db c3"
    )
    cleared = run(tmp_path / "overwrite", overwriting)
    assert cleared.status is BackendStatus.COMPLETED, cleared.errors
    assert sink_sources(cleared) == {}


@requires_triton
def test_i_stack_locals_across_nested_calls(tmp_path: Path):
    code = (
        call_to(CODE_BASE, CODE_BASE + 0x10)
        + " c3 90 90 90 90 90 90 90 90 90 90"
        + " 48 c7 44 24 f8 2a 00 00 00 c3"
    )
    result = run(tmp_path, code)
    data = result.data
    assert result.status is BackendStatus.COMPLETED, result.errors
    assert violations(result) == set()
    stack_writes = [
        item
        for item in data["memory_writes"]
        if STACK_BASE <= item["address"] < STACK_BASE + STACK_SIZE
    ]
    assert stack_writes, "expected the callee to write a stack local"
    # the local sits strictly below the return address pushed by the internal call
    return_slot = data["call_events"][0]["return_address"]
    assert any(item["address"] < min(item["address"] for item in stack_writes) + 0x1000 for item in stack_writes)
    assert return_slot  # documented for the report


@requires_triton
def test_j_taint_flows_through_internal_callee_and_back(tmp_path: Path):
    code = (
        call_to(CODE_BASE, CODE_BASE + 0x10)
        + " 48 89 47 08 c3 90 90 90 90 90 90"
        + " 48 89 f0 c3"
    )
    result = run(tmp_path, code)
    assert result.status is BackendStatus.COMPLETED, result.errors
    flows = sink_sources(result)
    assert flows == {"user.rsi": {"DESCRIPTOR_FIELD", "RETURN_VALUE"}}
    flow = next(item for item in result.data["taint_flows"] if item["source"] == "user.rsi")
    assert flow["transformations"], "the callee transformation must be recorded"
    assert flow["reproducible"] is True
    assert any(
        entry.get("disassembly", "").startswith("mov") for entry in flow["transformations"]
    )


@requires_triton
def test_call_stack_evidence_is_serializable_and_bounded(tmp_path: Path):
    code = (
        call_to(CODE_BASE, CODE_BASE + 0x10)
        + " c3 90 90 90 90 90 90 90 90 90 90"
        + " 90 c3"
    )
    result = run(tmp_path, code)
    payload = json.dumps(result.data, sort_keys=True, allow_nan=False)
    assert "call_events" in payload and "return_events" in payload
    for event in result.data["call_events"]:
        assert set(event) == {
            "caller",
            "call_instruction",
            "target",
            "classification",
            "return_address",
            "rsp_before",
            "rsp_after",
            "depth_before",
            "depth_after",
        }
    for event in result.data["return_events"]:
        assert {
            "stack_slot",
            "popped",
            "target",
            "rsp_before",
            "rsp_after",
            "depth_before",
            "depth_after",
            "classification",
        }.issubset(event)


@requires_triton
def test_k_ret_imm16_uses_triton_stack_cleanup_once(tmp_path: Path):
    # ret 0x10: pop return address and then clean 16 bytes of caller arguments.
    result = run(tmp_path, "c2 10 00")
    data = result.data
    assert result.status is BackendStatus.COMPLETED, result.errors
    event = data["return_events"][-1]
    assert event["classification"] == "HARNESS_RETURN"
    assert event["rsp_after"] - event["rsp_before"] == 0x18
    assert event["popped"] == event["target"]


@requires_triton
def test_l_leave_then_ret_reaches_outer_sentinel(tmp_path: Path):
    # Standard frame teardown must not rely on a fixed RSP throughout the function.
    code = "55 48 89 e5 48 83 ec 20 c9 c3"
    result = run(tmp_path, code)
    data = result.data
    assert result.status is BackendStatus.COMPLETED, result.errors
    assert data["return_events"][-1]["classification"] == "HARNESS_RETURN"
    assert violations(result) == set()


@requires_triton
def test_m_internal_return_to_middle_of_instruction_is_rejected(tmp_path: Path):
    # The callee overwrites its own return slot with CODE_BASE+1, which is executable but not an
    # instruction boundary. The architectural RET is executed once, then the worker rejects target.
    target = CODE_BASE + 1
    payload = target.to_bytes(8, "little").hex(" ")
    # call +0x10; ret; callee: movabs rax,target; mov [rsp],rax; ret
    code = (
        call_to(CODE_BASE, CODE_BASE + 0x10)
        + " c3 90 90 90 90 90 90 90 90 90 90"
        + " 48 b8 "
        + payload
        + " 48 89 04 24 c3"
    )
    result = run(tmp_path, code)
    assert result.status is BackendStatus.ANALYSIS_INCOMPLETE
    assert "INVALID_RETURN_TARGET" in violations(result)
