from __future__ import annotations

import os
from pathlib import Path

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
