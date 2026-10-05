import json
import os
from pathlib import Path

from orbisprobe.analysis.binary import BinaryImage
from orbisprobe.analysis.memop import MemopVerdict, analyze_memop_facts
from orbisprobe.backends.angr_backend import AngrBackend
from orbisprobe.backends.base import (
    BackendEvidence,
    BackendIdentity,
    BackendResult,
    ResourceLimits,
)
from orbisprobe.backends.consensus import ConsensusClassification, ConsensusEngine
from orbisprobe.backends.ghidra_backend import GhidraBackend
from orbisprobe.surfaces.secure import scan_secure

ROOT = Path(__file__).parent
ANGR_PYTHON = Path(
    os.environ.get(
        "ORBISPROBE_ANGR_PYTHON",
        ROOT.parents[0] / ".backend-envs" / "angr" / "bin" / "python",
    )
)
GHIDRA_HOME = Path("/home/hermes/tools/ghidra_12.1.3_PUBLIC")


def test_p2_1_cross_engine_safe_invariant(tmp_path: Path):
    facts = json.loads((ROOT / "fixtures" / "p2_1_631ad0.json").read_text())
    native_proof = analyze_memop_facts(facts)
    assert native_proof.verdict is MemopVerdict.SAFE_INVARIANT
    assert native_proof.length == 0xA8
    assert native_proof.index_domain == [0, 1]
    assert native_proof.destination_slot_size == 0xC0

    base = 0x631AD0
    binary = tmp_path / "p2-1-symbolic.bin"
    binary.write_bytes(bytes.fromhex("55 48 89 e5 49 83 fc 01 77 05 4c 89 e0 90 c3 31 c0 c3"))
    request = {
        "binary": str(binary),
        "architecture": "x86_64",
        "base": base,
        "function": base,
        "function_end": base + 18,
    }
    angr = AngrBackend(
        interpreter=ANGR_PYTHON,
        limits=ResourceLimits(timeout_seconds=20, state_ceiling=16, maximum_steps=64),
    ).trace_value(
        {
            **request,
            "source": {"register": "r12", "symbolic_bits": 64},
            "consumer": base + 13,
            "observe": {"register": "r12", "max_values": 8},
        }
    )
    assert angr.data["value_domain"] == [0, 1]

    ghidra = GhidraBackend(
        ghidra_home=GHIDRA_HOME,
        limits=ResourceLimits(timeout_seconds=60, maximum_graph_size=5000),
    ).analyze_function(request)
    assert "CBRANCH" in {item["opcode"] for item in ghidra.data["pcode"]}

    native_identity = BackendIdentity("native-memop", "1", "capstone-native", frozenset())
    native_result = BackendResult.completed(
        native_identity,
        {},
        [
            BackendEvidence(
                "value_domain",
                f"r12@0x{base + 13:x}",
                [0, 1],
                address=base + 13,
                provenance={"source_class": "static", "fixture": "P2-1"},
            )
        ],
    )
    consensus = ConsensusEngine().combine([native_result, angr])
    claim = next(item for item in consensus.claims if item.kind == "value_domain")
    assert claim.classification is ConsensusClassification.STRONGLY_SUPPORTED
    assert claim.value == [0, 1]


def test_case003_cross_engine_is_candidate_not_exploit(tmp_path: Path):
    fixture = json.loads((ROOT / "fixtures" / "case003_host_descriptor.json").read_text())
    binary = tmp_path / "case003.bin"
    binary.write_bytes(bytes.fromhex(fixture["binary_hex"]))
    base = 0x638000
    native = scan_secure(BinaryImage.open(binary, architecture="x86_64", base=base))
    assert native.classification == "CROSS-PROCESSOR-CANDIDATE"
    assert native.surfaces[0].candidate_priority == "P3"
    assert "secure consumer semantics unknown" in native.surfaces[0].unknowns

    request = {
        "binary": str(binary),
        "architecture": "x86_64",
        "base": base,
        "function": base,
        "function_end": base + binary.stat().st_size,
    }
    angr = AngrBackend(
        interpreter=ANGR_PYTHON,
        limits=ResourceLimits(timeout_seconds=20, maximum_graph_size=5000),
    ).analyze_function(request)
    ghidra = GhidraBackend(
        ghidra_home=GHIDRA_HOME,
        limits=ResourceLimits(timeout_seconds=60, maximum_graph_size=5000),
    ).analyze_function(request)
    assert angr.data["memory_accesses"]
    pcode_ops = {item["opcode"] for item in ghidra.data["pcode"]}
    assert "LOAD" in pcode_ops
    assert any(opcode.startswith("INT_") for opcode in pcode_ops)
    serialized = json.dumps(
        {
            "native": native.to_dict(),
            "angr": angr.to_dict(),
            "ghidra": ghidra.to_dict(),
        }
    ).lower()
    assert "exploit confirmed" not in serialized
