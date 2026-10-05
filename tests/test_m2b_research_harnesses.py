"""M2-B real-harness regression for P2-1, CASE-003, and the FW9 SVM slice.

The numbers asserted here were measured on this exact tree with the pinned Triton environment and
are re-checked on every run; the taint-size and branch-`taken` expectations are the regressions for
the two worker defects found by the first real-harness pass (memory taint ranges were chunked
incorrectly, and every conditional branch was recorded as taken).
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

import pytest
from m2b_research import (
    CASE003_EXPECTED_SINKS,
    P2_1_BASE,
    P2_1_BRANCH_OFFSET,
    P2_1_BRANCH_SIZE,
    P2_1_GUARD_TAKEN,
    P2_1_RETURN_VALUE,
    SVM_BASE,
    case003_binary,
    case003_document,
    p2_1_binary,
    p2_1_document,
    svm_binary,
    svm_document,
)

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


def _run(document: dict, payload: bytes, tmp_path: Path, operation: str = "trace"):
    tmp_path.mkdir(parents=True, exist_ok=True)
    binary = tmp_path / f"{document['harness_id']}.bin"
    binary.write_bytes(payload)
    harness = parse_harness(document)
    result = TritonBackend(
        interpreter=TRITON_PYTHON, limits=ResourceLimits(timeout_seconds=60, maximum_steps=4096)
    ).run_harness(
        {
            "harness": harness,
            "binary": str(binary),
            "binary_sha256": harness.binary_sha256,
            "operation": operation,
        }
    )
    return harness, result


@pytest.mark.parametrize("name", ["p2_1", "case003", "svm"])
def test_research_harness_documents_validate(name: str, tmp_path: Path):
    builders = {
        "p2_1": (lambda: p2_1_document(0), p2_1_binary),
        "case003": (case003_document, case003_binary),
        "svm": (svm_document, svm_binary),
    }[name]
    document_fn, binary_fn = builders
    document = document_fn()
    payload = binary_fn()
    harness = parse_harness(document)
    assert harness.binary_sha256 == hashlib.sha256(payload).hexdigest()
    assert harness.harness_sha256 == parse_harness(document).harness_sha256


def test_svm_slice_stays_bound_to_the_real_fw9_image():
    fixture = json.loads(
        (ROOT / "tests" / "fixtures" / "m2a" / "fw900_svm_angr_incomplete.json").read_text()
    )
    slice_bytes = svm_binary()
    assert len(slice_bytes) == 64
    assert hashlib.sha256(slice_bytes).hexdigest() == fixture["segment_sha256"]
    assert SVM_BASE == int(fixture["function"])


@requires_triton
@pytest.mark.parametrize("index,expected_taken", sorted(P2_1_GUARD_TAKEN.items()))
def test_p2_1_guard_reports_the_executed_branch_decision(
    index: int, expected_taken: bool, tmp_path: Path
):
    """Regression for the hardcoded ``taken: True``: 0/1 must fall through, 2/3 must branch."""

    harness, result = _run(p2_1_document(index), p2_1_binary(), tmp_path)
    assert result.status is BackendStatus.ANALYSIS_INCOMPLETE, result.errors
    branches = result.data["branches"]
    assert len(branches) == 1
    branch = branches[0]
    fallthrough = P2_1_BASE + P2_1_BRANCH_OFFSET + P2_1_BRANCH_SIZE
    assert branch["address"] == P2_1_BASE + P2_1_BRANCH_OFFSET
    assert branch["taken"] is expected_taken
    assert branch["fallthrough"] == fallthrough
    assert (branch["next_rip"] != fallthrough) is expected_taken
    assert result.data["return_value"] == P2_1_RETURN_VALUE[index]
    assert result.data["instructions_executed"] == (6 if expected_taken else 7)
    assert harness.harness_sha256


@requires_triton
def test_p2_1_guard_is_the_declared_index_sink(tmp_path: Path):
    _, result = _run(p2_1_document(0), p2_1_binary(), tmp_path)
    sinks = {flow["sink"] for flow in result.data["taint_flows"] if flow.get("sink")}
    assert "BRANCH_CONDITION" in sinks


@requires_triton
def test_case003_full_range_taint_does_not_crash_the_worker(tmp_path: Path):
    """Regression for the memory-taint range defect: a 128-byte range must be executable."""

    harness, result = _run(case003_document(), case003_binary(), tmp_path)
    assert result.status is not BackendStatus.ERROR, result.errors
    assert result.status is BackendStatus.ANALYSIS_INCOMPLETE
    assert result.data["execution_status"] == "ANALYSIS_INCOMPLETE"
    assert result.data["stop_reason"] == "UNMAPPED"
    assert result.data["instructions_executed"] == 26
    assert harness.harness_sha256


@requires_triton
def test_case003_descriptor_pointer_evidence_and_no_verdict(tmp_path: Path):
    _, result = _run(case003_document(), case003_binary(), tmp_path)
    flows = result.data["taint_flows"]
    addresses = {item["address"] for flow in flows for item in flow.get("sinks", [])}
    assert addresses == set(CASE003_EXPECTED_SINKS)
    assert {flow["sink"] for flow in flows if flow.get("sink")} == {"MEMORY_ADDRESS"}
    violations = result.data["memory_violations"]
    assert [item["kind"] for item in violations] == ["CORRUPTED_STACK_RETURN"]
    call_events = result.data["call_events"]
    assert len(call_events) == 3
    assert {event["classification"] for event in call_events} == {"INTERNAL"}
    serialized = json.dumps(result.to_dict()).lower()
    assert "confirmed" not in serialized
    assert "exploit" not in serialized


@requires_triton
def test_case003_taint_chunking_does_not_change_the_result(tmp_path: Path):
    """A range source and its aligned 8-byte decomposition must execute identically."""

    _, ranged = _run(case003_document(), case003_binary(), tmp_path / "range")
    _, chunked = _run(
        case003_document(taint_range_size=16), case003_binary(), tmp_path / "chunked16"
    )
    _, register_only = _run(
        case003_document(taint_range_size=None), case003_binary(), tmp_path / "register"
    )
    keys = ("instructions_executed", "stop_reason", "execution_status", "memory_violations")
    assert {key: ranged.data[key] for key in keys} == {key: chunked.data[key] for key in keys}
    assert register_only.data["stop_reason"] == ranged.data["stop_reason"]


@requires_triton
def test_svm_slice_run_returns_a_limit_and_never_a_negative_claim(tmp_path: Path):
    harness, result = _run(svm_document(), svm_binary(), tmp_path, operation="emulate")
    assert result.status is BackendStatus.RESOURCE_LIMIT
    assert result.data["stop_reason"] == "INSTRUCTION_LIMIT"
    assert result.data["instructions_executed"] == 32
    assert result.data["memory_violations"] == []
    serialized = json.dumps(result.to_dict()).lower()
    for forbidden in ("confirmed", "disproved", "not vulnerable", "no svm"):
        assert forbidden not in serialized
    assert harness.binary_sha256 == hashlib.sha256(svm_binary()).hexdigest()
