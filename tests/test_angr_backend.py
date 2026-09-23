from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

import pytest

from orbisprobe.backends.angr_backend import AngrBackend
from orbisprobe.backends.base import BackendCapability, BackendStatus, ResourceLimits

ANGR_PYTHON = Path(
    os.environ.get(
        "ORBISPROBE_ANGR_PYTHON",
        Path(__file__).parents[1] / ".backend-envs" / "angr" / "bin" / "python",
    )
)


def raw_function(tmp_path: Path) -> Path:
    # push rbp; mov rbp,rsp; cmp r12,1; ja invalid; mov rax,r12; nop; ret; xor eax,eax; ret
    path = tmp_path / "bounded.bin"
    path.write_bytes(bytes.fromhex("55 48 89 e5 49 83 fc 01 77 05 4c 89 e0 90 c3 31 c0 c3"))
    return path


def backend() -> AngrBackend:
    return AngrBackend(
        interpreter=ANGR_PYTHON,
        limits=ResourceLimits(timeout_seconds=20, state_ceiling=16, maximum_steps=64),
    )


def fake_interpreter(tmp_path: Path, name: str, body: str) -> Path:
    path = tmp_path / name
    path.write_text(f"#!/usr/bin/env python3\n{body}\n", encoding="utf-8")
    path.chmod(0o700)
    return path


def test_angr_availability_and_capabilities():
    result = backend().availability()
    assert result.status is BackendStatus.COMPLETED
    assert result.data["available"] is True
    assert result.identity.version == "9.2.184"
    assert {
        BackendCapability.CFG,
        BackendCapability.DATAFLOW,
        BackendCapability.SYMBOLIC,
        BackendCapability.MEMORY_MODEL,
    } <= result.identity.capabilities


def test_angr_cfgfast_recovers_bounded_function(tmp_path: Path):
    binary = raw_function(tmp_path)
    result = backend().recover_cfg(
        {
            "binary": str(binary),
            "architecture": "x86_64",
            "base": 0x400000,
            "function": 0x400000,
            "function_end": 0x400012,
        }
    )
    assert result.status is BackendStatus.COMPLETED
    assert result.data["function"] == 0x400000
    assert result.data["blocks"]
    assert result.metrics["elapsed_seconds"] < 20

    analyzed = backend().analyze_function(
        {
            "binary": str(binary),
            "architecture": "x86_64",
            "base": 0x400000,
            "function": 0x400000,
            "function_end": 0x400012,
        }
    )
    assert analyzed.data["reaching_definitions"]
    assert analyzed.data["dependency_edges"]


def test_angr_symbolic_register_domain_is_bounded(tmp_path: Path):
    binary = raw_function(tmp_path)
    result = backend().trace_value(
        {
            "binary": str(binary),
            "architecture": "x86_64",
            "base": 0x400000,
            "function": 0x400000,
            "function_end": 0x400012,
            "source": {"register": "r12", "symbolic_bits": 64},
            "consumer": 0x40000D,
            "observe": {"register": "r12", "max_values": 8},
        }
    )
    assert result.status is BackendStatus.COMPLETED
    assert result.data["value_domain"] == [0, 1]
    assert result.data["consumer_reachable"] is True
    assert result.evidence[0].subject == "r12@0x40000d"


def test_angr_path_proof_is_bounded_and_reports_unreachable(tmp_path: Path):
    binary = raw_function(tmp_path)
    result = backend().evaluate_branch_constraints(
        {
            "binary": str(binary),
            "architecture": "x86_64",
            "base": 0x400000,
            "function": 0x400000,
            "function_end": 0x400012,
            "from": 0x400000,
            "to": 0x500000,
            "symbolic_registers": ["r12"],
        }
    )
    assert result.status in {BackendStatus.COMPLETED, BackendStatus.ANALYSIS_INCOMPLETE}
    assert result.data.get("reachable", False) is False


def test_angr_missing_interpreter_is_backend_unavailable(tmp_path: Path):
    missing = AngrBackend(interpreter=tmp_path / "missing-python")
    result = missing.availability()
    assert result.status is BackendStatus.BACKEND_UNAVAILABLE


def test_angr_timeout_is_structured_and_worker_is_killed(tmp_path: Path):
    fake = tmp_path / "slow-python"
    fake.write_text("#!/bin/sh\nsleep 5\n", encoding="utf-8")
    fake.chmod(0o700)
    result = AngrBackend(
        interpreter=fake,
        limits=ResourceLimits(timeout_seconds=1),
    ).availability()
    assert result.status is BackendStatus.TIMEOUT
    assert result.partial is True


def test_angr_forces_blob_loader_for_high_kernel_base(tmp_path: Path):
    binary = raw_function(tmp_path)
    base = 0xFFFFFFFFD9918000
    result = backend().recover_cfg(
        {
            "binary": str(binary),
            "architecture": "x86_64",
            "base": base,
            "function": base,
            "function_end": base + 18,
        }
    )
    assert result.status is BackendStatus.COMPLETED
    assert result.data["function"] == base


def test_real_fw900_svm_cfg_failure_is_incomplete_not_negative(tmp_path: Path):
    fixture = json.loads(
        (Path(__file__).parent / "fixtures" / "m2a" / "fw900_svm_angr_incomplete.json").read_text()
    )
    binary = tmp_path / "fw900-svm.bin"
    binary.write_bytes(bytes.fromhex(fixture["binary_hex"]))
    assert hashlib.sha256(binary.read_bytes()).hexdigest() == fixture["segment_sha256"]
    result = backend().analyze_function(
        {
            "binary": str(binary),
            "architecture": "x86_64",
            "base": fixture["base"],
            "function": fixture["function"],
            "function_end": fixture["function_end"],
        }
    )
    assert result.status is BackendStatus.ANALYSIS_INCOMPLETE
    assert result.partial is True
    assert result.unknowns == [fixture["expected_unknown"]]
    assert result.evidence == []
    assert result.data["cfg"]["complete"] is False


@pytest.mark.parametrize(
    "payload",
    [
        "not-json",
        '{"status":',
        "[]",
        "null",
        "42",
        '"text"',
        '{"status":"COMPLETED"}',
        '{"status":"COMPLETED","version":"9.2.184","evidence":[{"kind":"v","subject":"r","value":NaN}]}',
        '{"status":"COMPLETED","version":"9.2.184","evidence":[{"kind":"v","subject":"r","value":Infinity}]}',
        '{"status":"COMPLETED","version":"9.2.184","data":{"domain":[-Infinity]}}',
        '{"status":"COMPLETED","version":"9.2.184","evidence":[{"kind":"v","subject":"r","value":1,"address":"0x400000"}]}',
        '{"status":"COMPLETED","version":"9.2.184","evidence":[{"kind":"v","subject":"r","value":1,"address":null,"confidence":"CONFIRMED"}]}',
    ],
)
def test_angr_malformed_or_truncated_json_is_structured_error(tmp_path: Path, payload: str):
    fake = fake_interpreter(tmp_path, "bad-json", f"import sys; sys.stdout.write({payload!r})")
    result = AngrBackend(interpreter=fake).availability()
    assert result.status is BackendStatus.ERROR
    assert result.evidence == []
    assert "invalid JSON response" in result.errors[0]


def test_angr_huge_external_output_hits_resource_limit(tmp_path: Path):
    fake = fake_interpreter(
        tmp_path,
        "huge-output",
        "import sys; sys.stdout.write('x' * (16 * 1024 * 1024 + 1))",
    )
    result = AngrBackend(interpreter=fake).availability()
    assert result.status is BackendStatus.RESOURCE_LIMIT
    assert result.partial is True
    assert result.evidence == []


def test_angr_nonzero_exit_cannot_report_completed(tmp_path: Path):
    payload = json.dumps({"status": "COMPLETED", "version": "fake", "data": {}})
    fake = fake_interpreter(
        tmp_path,
        "nonzero",
        f"import sys; sys.stdout.write({payload!r}); sys.exit(7)",
    )
    result = AngrBackend(interpreter=fake).availability()
    assert result.status is BackendStatus.ERROR
    assert "angr worker exited 7" in result.errors


def test_angr_invalid_inputs_fail_closed_without_core_crash(tmp_path: Path):
    missing = backend().analyze_function(
        {"binary": str(tmp_path / "missing.bin"), "base": 0, "function": 0}
    )
    invalid_base = backend().analyze_function(
        {"binary": str(raw_function(tmp_path)), "base": -1, "function": 0}
    )
    assert missing.status is BackendStatus.ERROR
    assert invalid_base.status is BackendStatus.ERROR
    assert missing.evidence == invalid_base.evidence == []


def test_angr_unsafe_filename_is_data_not_shell(tmp_path: Path):
    sentinel = tmp_path / "PWNED"
    binary = tmp_path / "x;touch PWNED.bin"
    binary.write_bytes(bytes.fromhex("c3"))
    result = backend().recover_cfg(
        {
            "binary": str(binary),
            "architecture": "x86_64",
            "base": 0x800000,
            "function": 0x800000,
            "function_end": 0x800001,
        }
    )
    assert result.status in {
        BackendStatus.COMPLETED,
        BackendStatus.ANALYSIS_INCOMPLETE,
        BackendStatus.ERROR,
    }
    assert not sentinel.exists()


def test_angr_worker_cannot_declare_runtime_evidence(tmp_path: Path):
    payload = json.dumps(
        {
            "status": "COMPLETED",
            "version": "9.2.184",
            "data": {},
            "evidence": [
                {
                    "kind": "value_domain",
                    "subject": "r12@0x40000d",
                    "value": [0, 1],
                    "confidence": "SUPPORTED",
                    "provenance": {"source_class": "runtime_real"},
                }
            ],
        }
    )
    fake = fake_interpreter(
        tmp_path, "runtime-claim", f"import sys; sys.stdout.write({payload!r})"
    )
    result = AngrBackend(interpreter=fake).availability()
    assert result.status is BackendStatus.ERROR
    assert result.evidence == []
    assert "source_class" in result.errors[0]
