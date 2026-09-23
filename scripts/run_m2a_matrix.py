from __future__ import annotations

import argparse
import json
import tempfile
import time
from pathlib import Path

from orbisprobe.analysis.binary import BinaryImage
from orbisprobe.analysis.memop import analyze_memop_facts
from orbisprobe.backends.angr_backend import AngrBackend
from orbisprobe.backends.base import (
    BackendEvidence,
    BackendIdentity,
    BackendResult,
    ResourceLimits,
)
from orbisprobe.backends.consensus import ConsensusEngine
from orbisprobe.backends.ghidra_backend import GhidraBackend
from orbisprobe.backends.native_backend import NativeBackend
from orbisprobe.surfaces.secure import scan_secure

ROOT = Path(__file__).parents[1]
FIXTURES = ROOT / "tests" / "fixtures"


def write_binary(root: Path, name: str, hex_data: str) -> Path:
    path = root / f"{name}.bin"
    path.write_bytes(bytes.fromhex(hex_data))
    return path


def timed(callable_):
    started = time.monotonic()
    result = callable_()
    return result, round(time.monotonic() - started, 6)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", required=True)
    parser.add_argument("--angr-python", default=str(ROOT / ".backend-envs" / "angr" / "bin" / "python"))
    parser.add_argument("--ghidra-home", default="/home/hermes/tools/ghidra_12.1.3_PUBLIC")
    args = parser.parse_args()

    limits = ResourceLimits(timeout_seconds=60, state_ceiling=32, maximum_steps=256, maximum_graph_size=10000)
    native = NativeBackend(limits)
    angr = AngrBackend(limits, interpreter=args.angr_python)
    ghidra = GhidraBackend(limits, ghidra_home=args.ghidra_home)
    output = {
        "scope": "offline-only",
        "live_target_contact": False,
        "backends": {
            backend.identity.name: backend.availability().to_dict()
            for backend in (native, angr, ghidra)
        },
        "cases": {},
        "conflicts": [],
        "technical_unknowns": [],
    }

    p2 = json.loads((FIXTURES / "p2_1_631ad0.json").read_text())
    p2_native = analyze_memop_facts(p2)
    with tempfile.TemporaryDirectory(prefix="orbisprobe-m2a-matrix-") as temporary:
        temp = Path(temporary)
        p2_base = 0x631AD0
        p2_binary = write_binary(
            temp,
            "p2-1",
            "55 48 89 e5 49 83 fc 01 77 05 4c 89 e0 90 c3 31 c0 c3",
        )
        p2_request = {
            "binary": str(p2_binary),
            "architecture": "x86_64",
            "base": p2_base,
            "function": p2_base,
            "function_end": p2_base + 18,
        }
        p2_angr, p2_angr_seconds = timed(
            lambda: angr.trace_value(
                {
                    **p2_request,
                    "source": {"register": "r12", "symbolic_bits": 64},
                    "consumer": p2_base + 13,
                    "observe": {"register": "r12", "max_values": 8},
                }
            )
        )
        p2_ghidra, p2_ghidra_seconds = timed(lambda: ghidra.analyze_function(p2_request))
        native_claim = BackendResult.completed(
            BackendIdentity("native-memop", native.version(), "capstone-native", frozenset()),
            {},
            [
                BackendEvidence(
                    "value_domain",
                    f"r12@0x{p2_base + 13:x}",
                    p2_native.index_domain,
                    address=p2_base + 13,
                    provenance={"source_class": "static", "fixture": "P2-1"},
                )
            ],
        )
        p2_consensus = ConsensusEngine().combine([native_claim, p2_angr])
        output["cases"]["P2-1"] = {
            "native": p2_native.to_dict(),
            "angr": p2_angr.to_dict(),
            "ghidra": {
                "status": p2_ghidra.status.value,
                "pcode_operations": sorted({item["opcode"] for item in p2_ghidra.data.get("pcode", [])}),
                "unknown": "Ghidra P-code supports branch structure but does not independently solve the index domain",
            },
            "consensus": p2_consensus.to_dict(),
            "runtime_seconds": {"angr": p2_angr_seconds, "ghidra": p2_ghidra_seconds},
            "false_positive": False,
        }

        case = json.loads((FIXTURES / "case003_host_descriptor.json").read_text())
        case_base = 0x638000
        case_binary = write_binary(temp, "case003", case["binary_hex"])
        case_request = {
            "binary": str(case_binary),
            "architecture": "x86_64",
            "base": case_base,
            "function": case_base,
            "function_end": case_base + case_binary.stat().st_size,
        }
        case_native = scan_secure(BinaryImage.open(case_binary, architecture="x86_64", base=case_base))
        case_angr, case_angr_seconds = timed(lambda: angr.analyze_function(case_request))
        case_ghidra, case_ghidra_seconds = timed(lambda: ghidra.analyze_function(case_request))
        output["cases"]["CASE-003"] = {
            "native": case_native.to_dict(),
            "angr": {
                "status": case_angr.status.value,
                "memory_access_count": len(case_angr.data.get("memory_accesses", [])),
                "unknown": "secure-side semantics unavailable",
            },
            "ghidra": {
                "status": case_ghidra.status.value,
                "pcode_operations": sorted({item["opcode"] for item in case_ghidra.data.get("pcode", [])}),
                "unknown": "secure-side semantics unavailable",
            },
            "runtime_seconds": {"angr": case_angr_seconds, "ghidra": case_ghidra_seconds},
            "final": "CROSS-PROCESSOR-CANDIDATE; no exploit claim",
        }

        flows = json.loads((FIXTURES / "m2a" / "backend_flow_fixtures.json").read_text())["fixtures"]
        for fixture in flows:
            if fixture["id"] not in {"r15-overwrite", "rbx-overwrite"}:
                continue
            binary = write_binary(temp, fixture["id"], fixture["binary_hex"])
            request = {
                "binary": str(binary),
                "architecture": "x86_64",
                "base": fixture["base"],
                "function": fixture["function"],
                "function_end": fixture["function_end"],
                "source": {"register": fixture["source_register"], "symbolic_bits": 64},
                "consumer": fixture["consumer"],
                "observe": {"register": fixture["observe_register"], "max_values": 8},
            }
            native_result, native_seconds = timed(lambda current=request: native.trace_value(current))
            angr_result, angr_seconds = timed(lambda current=request: angr.trace_value(current))
            ghidra_result, ghidra_seconds = timed(lambda current=request: ghidra.analyze_function(current))
            consensus = ConsensusEngine().combine([native_result, angr_result])
            output["cases"][fixture["id"]] = {
                "native": native_result.to_dict(),
                "angr": angr_result.to_dict(),
                "ghidra": {
                    "status": ghidra_result.status.value,
                    "definition_count": len(ghidra_result.data.get("definitions", [])),
                    "unknown": "raw P-code export is not yet a claim-specific SSA lifetime proof",
                },
                "consensus": consensus.to_dict(),
                "runtime_seconds": {
                    "native": native_seconds,
                    "angr": angr_seconds,
                    "ghidra": ghidra_seconds,
                },
            }

    for case_name, case in output["cases"].items():
        consensus = case.get("consensus", {})
        for claim in consensus.get("claims", []):
            if claim["classification"] == "EVIDENCE_CONFLICT":
                output["conflicts"].append({"case": case_name, "claim": claim})
    output["technical_unknowns"] = [
        "Ghidra raw P-code is not yet claim-specific SSA lifetime evidence",
        "angr raw-blob models omit PS4 kernel environment and external callees",
        "CASE-003 secure consumer remains unavailable",
    ]
    Path(args.out).write_text(json.dumps(output, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"output": args.out, "cases": sorted(output["cases"]), "conflicts": len(output["conflicts"])}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
