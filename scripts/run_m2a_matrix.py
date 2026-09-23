from __future__ import annotations

import argparse
import json
import statistics
import tempfile
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

from orbisprobe.analysis.binary import BinaryImage
from orbisprobe.analysis.memop import analyze_memop_facts
from orbisprobe.backends.angr_backend import AngrBackend
from orbisprobe.backends.base import (
    BackendEvidence,
    BackendIdentity,
    BackendResult,
    BackendStatus,
    ResourceLimits,
)
from orbisprobe.backends.consensus import ConsensusEngine
from orbisprobe.backends.ghidra_backend import GhidraBackend
from orbisprobe.backends.native_backend import NativeBackend
from orbisprobe.surfaces.secure import scan_secure
from orbisprobe.surfaces.svm import scan_svm

ROOT = Path(__file__).parents[1]
FIXTURES = ROOT / "tests" / "fixtures"
USABLE = {
    BackendStatus.COMPLETED,
    BackendStatus.PARTIAL,
    BackendStatus.ANALYSIS_INCOMPLETE,
}


def write_binary(root: Path, name: str, hex_data: str) -> Path:
    path = root / f"{name}.bin"
    path.write_bytes(bytes.fromhex(hex_data))
    return path


def timed(callable_: Callable[[], Any]) -> tuple[Any, float]:
    started = time.monotonic()
    result = callable_()
    return result, round(time.monotonic() - started, 6)


def backend_summary(result: BackendResult, seconds: float) -> dict[str, Any]:
    return {
        "backend": result.identity.name,
        "version": result.identity.version,
        "status": result.status.value,
        "partial": result.partial,
        "analysis_mode": result.data.get("analysis_mode"),
        "effective_capabilities": result.data.get("effective_capabilities", []),
        "unknowns": result.unknowns,
        "errors": result.errors,
        "runtime_seconds": seconds,
        "instruction_count": len(result.data.get("instructions", [])),
        "pcode_count": len(result.data.get("pcode", [])),
        "memory_access_count": len(result.data.get("memory_accesses", [])),
    }


def result_consensus(results: list[BackendResult]) -> dict[str, Any]:
    return ConsensusEngine().combine(results).to_dict()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", required=True)
    parser.add_argument(
        "--angr-python",
        default=str(ROOT / ".backend-envs" / "angr" / "bin" / "python"),
    )
    parser.add_argument("--ghidra-home", default="/home/hermes/tools/ghidra_12.1.3_PUBLIC")
    args = parser.parse_args()

    limits = ResourceLimits(
        timeout_seconds=60,
        state_ceiling=32,
        maximum_steps=256,
        maximum_graph_size=10_000,
    )
    native = NativeBackend(limits)
    angr = AngrBackend(limits, interpreter=args.angr_python)
    ghidra = GhidraBackend(limits, ghidra_home=args.ghidra_home)
    output: dict[str, Any] = {
        "scope": "offline-only",
        "live_target_contact": False,
        "required_fixture_count": 17,
        "backends": {
            backend.identity.name: backend.availability().to_dict()
            for backend in (native, angr, ghidra)
        },
        "fixtures": [],
        "conflicts": [],
        "performance": {},
        "technical_unknowns": [
            "Ghidra raw P-code is not claim-specific SSA lifetime evidence",
            "angr raw-blob models omit PS4 kernel environment and external callees",
            "CASE-003 secure consumer remains unavailable",
        ],
    }
    runtime_samples: dict[str, list[float]] = {"native": [], "angr": [], "ghidra": []}

    def add(record: dict[str, Any]) -> None:
        output["fixtures"].append(record)
        for backend_name, samples in runtime_samples.items():
            value = record.get(backend_name, {}).get("runtime_seconds")
            if isinstance(value, (int, float)):
                samples.append(float(value))
        for claim in record.get("consensus", {}).get("claims", []):
            if claim["classification"] == "EVIDENCE_CONFLICT":
                output["conflicts"].append({"fixture": record["fixture"], "claim": claim})

    with tempfile.TemporaryDirectory(prefix="orbisprobe-m2a-matrix-") as temporary:
        temp = Path(temporary)

        # P2-1: explicit memop invariant plus independently solved symbolic index domain.
        p2 = json.loads((FIXTURES / "p2_1_631ad0.json").read_text())
        p2_native, p2_native_seconds = timed(lambda: analyze_memop_facts(p2))
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
        p2_consensus = result_consensus([native_claim, p2_angr])
        p2_pass = (
            p2_native.verdict.value == "SAFE-INVARIANT"
            and p2_angr.data.get("value_domain") == [0, 1]
            and any(
                claim["kind"] == "value_domain"
                and claim["classification"] == "STRONGLY_SUPPORTED"
                and claim["value"] == [0, 1]
                for claim in p2_consensus["claims"]
            )
            and not p2_consensus["has_conflicts"]
            and p2_ghidra.status in USABLE
        )
        add(
            {
                "fixture": "P2-1",
                "expected": "SAFE-INVARIANT; index domain {0,1}; no OOB claim",
                "native": {
                    "status": "COMPLETED",
                    "version": native.version(),
                    "verdict": p2_native.verdict.value,
                    "runtime_seconds": p2_native_seconds,
                },
                "angr": backend_summary(p2_angr, p2_angr_seconds),
                "ghidra": backend_summary(p2_ghidra, p2_ghidra_seconds),
                "consensus": p2_consensus,
                "result": "PASS" if p2_pass else "FAIL",
            }
        )

        # CASE-003: retain host-side structural evidence and secure-side unknowns.
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
        case_native, case_native_seconds = timed(
            lambda: scan_secure(BinaryImage.open(case_binary, architecture="x86_64", base=case_base))
        )
        case_angr, case_angr_seconds = timed(lambda: angr.analyze_function(case_request))
        case_ghidra, case_ghidra_seconds = timed(lambda: ghidra.analyze_function(case_request))
        surface = case_native.surfaces[0]
        evidence_kinds = {item.kind for item in surface.evidence}
        forbidden = ("confirmed exploit", "arbitrary address primitive", "confirmed secure oob")
        serialized = json.dumps(
            {"native": case_native.to_dict(), "angr": case_angr.to_dict(), "ghidra": case_ghidra.to_dict()}
        ).lower()
        case_pass = (
            case_native.classification == "CROSS-PROCESSOR-CANDIDATE"
            and surface.candidate_priority == "P3"
            and {"descriptor_size", "repeated_mutable_read", "address_field"} <= evidence_kinds
            and "secure consumer semantics unknown" in surface.unknowns
            and all(item not in serialized for item in forbidden)
            and case_angr.status in USABLE
            and case_ghidra.status in USABLE
        )
        add(
            {
                "fixture": "CASE-003",
                "expected": "CROSS-PROCESSOR-CANDIDATE/P3; Secure consumer UNKNOWN",
                "native": {
                    "status": "COMPLETED",
                    "version": native.version(),
                    "classification": case_native.classification,
                    "candidate_priority": surface.candidate_priority,
                    "evidence_kinds": sorted(evidence_kinds),
                    "unknowns": surface.unknowns,
                    "runtime_seconds": case_native_seconds,
                },
                "angr": backend_summary(case_angr, case_angr_seconds),
                "ghidra": backend_summary(case_ghidra, case_ghidra_seconds),
                "consensus": {"claims": [], "has_conflicts": False, "note": "no shared secure-consumer claim"},
                "result": "PASS" if case_pass else "FAIL",
            }
        )

        flows = json.loads((FIXTURES / "m2a" / "backend_flow_fixtures.json").read_text())["fixtures"]
        for fixture in flows:
            binary = write_binary(temp, fixture["id"], fixture["binary_hex"])
            request = {
                "binary": str(binary),
                "architecture": "x86_64",
                "base": fixture["base"],
                "function": fixture["function"],
                "function_end": fixture["function_end"],
            }
            angr_result, angr_seconds = timed(lambda current=request: angr.analyze_function(current))
            ghidra_result, ghidra_seconds = timed(lambda current=request: ghidra.analyze_function(current))
            native_result: BackendResult | None = None
            native_details: dict[str, Any]
            consensus: dict[str, Any] = {"claims": [], "has_conflicts": False}
            passed = angr_result.status in USABLE and ghidra_result.status in USABLE
            expected = "structural regression"

            if "expected_native_classification" in fixture:
                svm, native_seconds = timed(
                    lambda path=binary, base=fixture["base"]: scan_svm(
                        BinaryImage.open(path, architecture="x86_64", base=base)
                    )
                )
                expected = fixture["expected_native_classification"]
                passed &= svm.classification == expected
                native_details = {
                    "status": "COMPLETED",
                    "version": native.version(),
                    "classification": svm.classification,
                    "runtime_seconds": native_seconds,
                }
            elif "source_register" in fixture or "source_memory_base" in fixture:
                source = (
                    {"register": fixture["source_register"]}
                    if "source_register" in fixture
                    else {
                        "memory_base": fixture["source_memory_base"],
                        "memory_displacement": fixture["source_memory_offset"],
                    }
                )
                native_request = {
                    **request,
                    "source": source,
                    "consumer": fixture["consumer"],
                }
                if "observe_register" in fixture:
                    native_request["observe"] = {"register": fixture["observe_register"]}
                native_result, native_seconds = timed(
                    lambda current=native_request: native.trace_value(current)
                )
                consumers = [
                    item
                    for item in native_result.data.get("events", [])
                    if item["kind"] == "consumer" and item["address"] == fixture["consumer"]
                ]
                expected_consumer = fixture["expected_native_consumer"]
                passed &= bool(consumers) is expected_consumer
                expected = f"native consumer={expected_consumer}"
                native_details = {
                    **backend_summary(native_result, native_seconds),
                    "consumer_reached": bool(consumers),
                }
                if fixture["id"] in {"r15-overwrite", "rbx-overwrite"}:
                    angr_trace_request = {
                        **request,
                        "source": {"register": fixture["source_register"], "symbolic_bits": 64},
                        "consumer": fixture["consumer"],
                        "observe": {"register": fixture["observe_register"], "max_values": 8},
                    }
                    angr_result, angr_seconds = timed(
                        lambda current=angr_trace_request: angr.trace_value(current)
                    )
                    consensus = result_consensus([native_result, angr_result])
                    passed &= angr_result.data.get("value_domain") == fixture["expected_domain"]
                    passed &= any(
                        claim["kind"] == "register_lifetime"
                        and claim["classification"] == "STRONGLY_SUPPORTED"
                        and claim["value"] is False
                        for claim in consensus["claims"]
                    )
            elif fixture["id"] == "tag-0xf-snapshot-0x400":
                analyzed, native_seconds = timed(
                    lambda current=request: native.analyze_function(current)
                )
                text = " ".join(item["op_str"] for item in analyzed.data["instructions"])
                passed &= "0xf" in text and "0x400" in text and "[rdi + 0x18]" in text
                expected = "tag 0xF, limit 0x400, snapshot offset 0x18"
                native_details = {
                    **backend_summary(analyzed, native_seconds),
                    "decoded_operands": text,
                }
            else:
                memory_result, native_seconds = timed(
                    lambda current=request: native.analyze_memory_access(current)
                )
                accesses = memory_result.data.get("memory_accesses", [])
                passed &= bool(accesses)
                if fixture["expected_memory"] == "STORE_ONLY":
                    passed &= all(item["access"] & 1 == 0 for item in accesses)
                elif fixture["expected_memory"] == "GETTER_READONLY":
                    passed &= all(item["access"] & 2 == 0 for item in accesses)
                expected = fixture["expected_memory"]
                native_details = {
                    **backend_summary(memory_result, native_seconds),
                    "accesses": accesses,
                }

            add(
                {
                    "fixture": fixture["id"],
                    "expected": expected,
                    "native": native_details,
                    "angr": backend_summary(angr_result, angr_seconds),
                    "ghidra": backend_summary(ghidra_result, ghidra_seconds),
                    "consensus": consensus,
                    "result": "PASS" if passed else "FAIL",
                }
            )

        # Fact-level memop fixtures have no binary program; external engines abstain explicitly.
        memops = json.loads((FIXTURES / "m2a" / "memop_fixtures.json").read_text())["fixtures"]
        for fixture in memops:
            proof, native_seconds = timed(lambda current=fixture: analyze_memop_facts(current))
            passed = proof.verdict.value == fixture["expected"]
            add(
                {
                    "fixture": fixture["id"],
                    "expected": fixture["expected"],
                    "native": {
                        "status": "COMPLETED",
                        "version": native.version(),
                        "verdict": proof.verdict.value,
                        "runtime_seconds": native_seconds,
                    },
                    "angr": {
                        "status": "NOT_APPLICABLE",
                        "reason": "fact-level invariant fixture has no executable binary",
                    },
                    "ghidra": {
                        "status": "NOT_APPLICABLE",
                        "reason": "fact-level invariant fixture has no executable binary",
                    },
                    "consensus": {
                        "claims": [],
                        "has_conflicts": False,
                        "note": "external engines abstain; native invariant checker is authoritative for this fixture",
                    },
                    "result": "PASS" if passed else "FAIL",
                }
            )

    for name, samples in runtime_samples.items():
        output["performance"][name] = {
            "count": len(samples),
            "median_seconds": round(statistics.median(samples), 6) if samples else None,
            "min_seconds": min(samples) if samples else None,
            "max_seconds": max(samples) if samples else None,
        }
    output["fixture_count"] = len(output["fixtures"])
    output["passed"] = sum(item["result"] == "PASS" for item in output["fixtures"])
    output["failed"] = sum(item["result"] == "FAIL" for item in output["fixtures"])
    output["all_passed"] = (
        output["fixture_count"] == output["required_fixture_count"] and output["failed"] == 0
    )
    Path(args.out).write_text(json.dumps(output, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(
        json.dumps(
            {
                "output": args.out,
                "fixture_count": output["fixture_count"],
                "passed": output["passed"],
                "failed": output["failed"],
                "conflicts": len(output["conflicts"]),
            },
            indent=2,
        )
    )
    return 0 if output["all_passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
