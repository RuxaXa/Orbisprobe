import json
import os
from pathlib import Path

import pytest

from orbisprobe.analysis.binary import BinaryImage
from orbisprobe.analysis.memop import analyze_memop_facts
from orbisprobe.backends.angr_backend import AngrBackend
from orbisprobe.backends.base import BackendStatus, ResourceLimits
from orbisprobe.backends.consensus import ConsensusClassification, ConsensusEngine
from orbisprobe.backends.ghidra_backend import GhidraBackend
from orbisprobe.backends.native_backend import NativeBackend
from orbisprobe.surfaces.svm import scan_svm

ROOT = Path(__file__).parent / "fixtures" / "m2a"
ANGR_PYTHON = Path(
    os.environ.get(
        "ORBISPROBE_ANGR_PYTHON",
        Path(__file__).parents[1] / ".backend-envs" / "angr" / "bin" / "python",
    )
)
GHIDRA_HOME = Path("/home/hermes/tools/ghidra_12.1.3_PUBLIC")


def flow_fixtures():
    return json.loads((ROOT / "backend_flow_fixtures.json").read_text())["fixtures"]


def write_fixture(tmp_path: Path, fixture: dict) -> Path:
    path = tmp_path / f"{fixture['id']}.bin"
    path.write_bytes(bytes.fromhex(fixture["binary_hex"]))
    return path


def request(path: Path, fixture: dict) -> dict:
    return {
        "binary": str(path),
        "architecture": "x86_64",
        "base": fixture["base"],
        "function": fixture["function"],
        "function_end": fixture["function_end"],
    }


def test_memop_fixture_matrix_has_expected_verdicts():
    fixtures = json.loads((ROOT / "memop_fixtures.json").read_text())["fixtures"]
    for fixture in fixtures:
        assert analyze_memop_facts(fixture).verdict.value == fixture["expected"]


@pytest.mark.parametrize("fixture_id", ["r15-overwrite", "rbx-overwrite"])
def test_native_and_angr_agree_overwritten_register_is_zero(tmp_path: Path, fixture_id: str):
    fixture = next(item for item in flow_fixtures() if item["id"] == fixture_id)
    path = write_fixture(tmp_path, fixture)
    base_request = request(path, fixture)
    native_request = {
        **base_request,
        "source": {"register": fixture["source_register"]},
        "consumer": fixture["consumer"],
        "observe": {"register": fixture["observe_register"]},
    }
    native = NativeBackend().trace_value(native_request)
    consumer_events = [
        item
        for item in native.data["events"]
        if item["kind"] == "consumer" and item["address"] == fixture["consumer"]
    ]
    assert consumer_events == []

    angr = AngrBackend(
        interpreter=ANGR_PYTHON,
        limits=ResourceLimits(timeout_seconds=20, state_ceiling=16, maximum_steps=64),
    ).trace_value(
        {
            **base_request,
            "source": {"register": fixture["source_register"], "symbolic_bits": 64},
            "consumer": fixture["consumer"],
            "observe": {"register": fixture["observe_register"], "max_values": 8},
        }
    )
    assert angr.status is BackendStatus.COMPLETED
    assert angr.data["value_domain"] == fixture["expected_domain"]
    consensus = ConsensusEngine().combine([native, angr])
    lifetime = next(item for item in consensus.claims if item.kind == "register_lifetime")
    assert lifetime.value is False
    assert lifetime.classification is ConsensusClassification.STRONGLY_SUPPORTED


def test_native_callee_saved_and_call_clobber_regressions(tmp_path: Path):
    for fixture in flow_fixtures():
        if fixture["id"] not in {"call-clobber", "callee-saved-propagation"}:
            continue
        path = write_fixture(tmp_path, fixture)
        result = NativeBackend().trace_value(
            {
                **request(path, fixture),
                "source": {"register": fixture["source_register"]},
                "consumer": fixture["consumer"],
            }
        )
        consumers = [
            item
            for item in result.data["events"]
            if item["kind"] == "consumer" and item["address"] == fixture["consumer"]
        ]
        assert bool(consumers) is fixture["expected_native_consumer"]


def test_dead_stack_slot_and_getter_are_not_writes_or_consumers(tmp_path: Path):
    selected = {item["id"]: item for item in flow_fixtures()}
    native = NativeBackend()
    dead = selected["dead-stack-slot"]
    dead_access = native.analyze_memory_access(request(write_fixture(tmp_path, dead), dead))
    assert dead_access.data["memory_accesses"]
    assert all(item["access"] & 1 == 0 for item in dead_access.data["memory_accesses"])

    getter = selected["getter-c92aae80"]
    getter_access = native.analyze_memory_access(request(write_fixture(tmp_path, getter), getter))
    assert getter_access.data["memory_accesses"]
    assert all(item["access"] & 2 == 0 for item in getter_access.data["memory_accesses"])


def test_ghidra_pcode_confirms_getter_and_dead_store_shapes(tmp_path: Path):
    selected = {item["id"]: item for item in flow_fixtures()}
    ghidra = GhidraBackend(
        ghidra_home=GHIDRA_HOME,
        limits=ResourceLimits(timeout_seconds=60, maximum_graph_size=5000),
    )
    getter = selected["getter-c92aae80"]
    getter_result = ghidra.analyze_function(request(write_fixture(tmp_path, getter), getter))
    getter_ops = {item["opcode"] for item in getter_result.data["pcode"]}
    assert "LOAD" in getter_ops
    assert "STORE" not in getter_ops

    dead = selected["dead-stack-slot"]
    dead_result = ghidra.analyze_function(request(write_fixture(tmp_path, dead), dead))
    dead_ops = {item["opcode"] for item in dead_result.data["pcode"]}
    assert "STORE" in dead_ops
    # RET legitimately loads its return target from the stack. Prove the specific
    # [rbp-0x90] slot is written once and never read in decompiler output.
    decompiled = dead_result.data["decompiler_c"]
    assert "unaff_RBP + -0x90" in decompiled
    assert decompiled.count("-0x90") == 1


def test_tag_0xf_snapshot_fixture_has_required_native_constants(tmp_path: Path):
    fixture = next(item for item in flow_fixtures() if item["id"] == "tag-0xf-snapshot-0x400")
    path = write_fixture(tmp_path, fixture)
    result = NativeBackend().analyze_function(request(path, fixture))
    text = " ".join(item["op_str"] for item in result.data["instructions"])
    assert "0xf" in text
    assert "0x400" in text
    assert "[rdi + 0x18]" in text


def test_stale_eax_and_edx_do_not_prove_svm_initialization(tmp_path: Path):
    for fixture in flow_fixtures():
        if fixture["id"] not in {"stale-eax", "stale-edx"}:
            continue
        path = write_fixture(tmp_path, fixture)
        result = scan_svm(
            BinaryImage.open(path, architecture="x86_64", base=fixture["base"])
        )
        assert result.classification == fixture["expected_native_classification"]
        assert "EFER.SVME initialization sequence" in result.surfaces[0].unknowns
