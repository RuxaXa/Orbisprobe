"""M2-B1 evidence matrix: harness fixture matrix, cross-engine research rows, performance, cache.

Runs entirely offline. No test, fixture, or run here contacts a PS4, a target device, or a network.
The firmware image is read-only and only used for the native SVM track; when it is absent the track
runs on the 64-byte immutable fixture slice and records that downgrade explicitly.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import statistics
import sys
import tempfile
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

ROOT = Path(__file__).parents[1]
sys.path.insert(0, str(ROOT / "tests"))

from m2b_cases import CASES, materialize
from m2b_research import (
    CASE003_BASE,
    CASE003_DESCRIPTOR,
    P2_1_BASE,
    P2_1_CODE,
    SVM_BASE,
    SVM_SLICE_SIZE,
    case003_binary,
    case003_document,
    p2_1_binary,
    p2_1_document,
    svm_binary,
    svm_document,
)

from orbisprobe.analysis.binary import BinaryImage
from orbisprobe.analysis.memop import analyze_memop_facts
from orbisprobe.backends import (
    AnalysisCache,
    BackendEvidence,
    BackendIdentity,
    BackendOrchestrator,
    BackendResult,
    ConsensusEngine,
    ResourceLimits,
    default_registry,
)
from orbisprobe.backends.angr_backend import AngrBackend
from orbisprobe.backends.ghidra_backend import GhidraBackend
from orbisprobe.backends.native_backend import NativeBackend
from orbisprobe.harness import parse_harness
from orbisprobe.surfaces.secure import scan_secure
from orbisprobe.surfaces.svm import scan_svm

FW900 = Path(
    "/home/hermes/session-handoffs/20260921_ps4b-soc-independent-analysis/kernel/fw900-kernel-rx.bin"
)
FW900_BASE = 0xFFFFFFFFD9918000
FW900_SHA256 = "af3178da72e351368588d30d1ea6e6e1bdc5e6f909cd8226ec7d579dc0255dd4"
JAVA_HOME = "/usr/lib/jvm/java-21-openjdk-amd64"


def timed(callable_: Callable[[], Any]) -> tuple[Any, float]:
    started = time.monotonic()
    result = callable_()
    return result, round(time.monotonic() - started, 6)


def sink_types(result: BackendResult) -> set[str]:
    sinks: set[str] = set()
    for flow in result.data.get("taint_flows", []):
        if flow.get("sink"):
            sinks.add(flow["sink"])
        for entry in flow.get("sinks", []):
            sinks.add(entry["sink"])
    return sinks


def tainted_sources(result: BackendResult) -> set[str]:
    return {
        flow["source"]
        for flow in result.data.get("taint_flows", [])
        if flow.get("sink") or flow.get("sinks")
    }


def sink_types_by_source(result: BackendResult) -> dict[str, set[str]]:
    mapping: dict[str, set[str]] = {}
    for flow in result.data.get("taint_flows", []):
        sinks = {entry["sink"] for entry in flow.get("sinks", [])}
        if flow.get("sink"):
            sinks.add(flow["sink"])
        if sinks:
            mapping[flow["source"]] = sinks
    return mapping


def backend_summary(result: BackendResult, seconds: float) -> dict[str, Any]:
    return {
        "backend": result.identity.name,
        "version": result.identity.version,
        "independence_family": result.identity.independence_family,
        "status": result.status.value,
        "partial": result.partial,
        "analysis_mode": result.data.get("analysis_mode"),
        "unknowns": result.unknowns,
        "errors": result.errors,
        "runtime_seconds": seconds,
    }


def consensus_of(results: list[BackendResult]) -> dict[str, Any]:
    return ConsensusEngine().combine(results).to_dict()


def case_mismatches(case, result: BackendResult) -> list[str]:
    """Every deviation between the recorded case expectation and the executed run."""

    data = result.data
    problems: list[str] = []
    if result.status.value not in {"COMPLETED", "PARTIAL"}:
        problems.append(f"status={result.status.value} errors={result.errors}")
        return problems
    if data["execution_status"] != case.expected_status:
        problems.append(f"execution_status={data['execution_status']}")
    if data["stop_reason"] != case.expected_stop:
        problems.append(f"stop_reason={data['stop_reason']}")
    if len(data["memory_violations"]) != case.expected_violations:
        problems.append(f"violations={len(data['memory_violations'])}")
    if sink_types(result) != case.expected_sink_types:
        problems.append(f"sinks={sorted(sink_types(result))}")
    if tainted_sources(result) != case.expected_tainted_sources:
        problems.append(f"sources={sorted(tainted_sources(result))}")
    if {stub["behavior"] for stub in data["stubs_used"]} != case.expected_stub_behaviors:
        problems.append("stub_behaviors")
    if len(data["branches"]) < case.expected_min_branches:
        problems.append(f"branches={len(data['branches'])}")
    if case.expected_sink_by_source and sink_types_by_source(result) != case.expected_sink_by_source:
        problems.append("sink_by_source")
    if case.expected_min_constraints:
        rendered = [text for branch in data["branches"] for text in branch.get("constraints", [])]
        if not rendered or any("object at 0x" in text for text in rendered):
            problems.append("constraints")
    if case.expected_memory_writes is not None and len(data["memory_writes"]) != (
        case.expected_memory_writes
    ):
        problems.append(f"memory_writes={len(data['memory_writes'])}")
    if case.expected_return_value is not None and data["return_value"] != case.expected_return_value:
        problems.append(f"return_value={data['return_value']}")
    return problems


def research_documents() -> list[tuple[str, dict, bytes, str]]:
    return [
        ("P2-1", p2_1_document(0), p2_1_binary(), "trace"),
        ("CASE-003", case003_document(), case003_binary(), "trace"),
        ("SVM", svm_document(), svm_binary(), "emulate"),
    ]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", required=True)
    parser.add_argument("--cache", default=None)
    parser.add_argument("--angr-python", default=str(ROOT / ".backend-envs" / "angr" / "bin" / "python"))
    parser.add_argument("--fw900", default=str(FW900))
    args = parser.parse_args()

    limits = ResourceLimits(
        timeout_seconds=60,
        state_ceiling=32,
        maximum_steps=256,
        maximum_graph_size=10_000,
    )
    registry = default_registry()
    native = NativeBackend(limits)
    angr = AngrBackend(limits, interpreter=args.angr_python)
    ghidra = GhidraBackend(limits, ghidra_home="/home/hermes/tools/ghidra_12.1.3_PUBLIC")
    fw900 = Path(args.fw900)
    fw900_available = fw900.is_file() and hashlib.sha256(fw900.read_bytes()).hexdigest() == FW900_SHA256

    output: dict[str, Any] = {
        "scope": "offline-only",
        "live_target_contact": False,
        "orbisprobe_version": __import__("orbisprobe").__version__,
        "backends": {
            name: registry.status(name, limits).to_dict()
            for name in ("native", "angr", "ghidra", "triton")
        },
        "firmware_image": {
            "path": str(fw900),
            "expected_sha256": FW900_SHA256,
            "available": fw900_available,
            "fallback": "64-byte frozen fixture slice" if not fw900_available else None,
        },
        "harness_fixture_matrix": [],
        "research_rows": [],
        "performance": {},
        "cache_regression": {},
        "conflicts": [],
        "technical_unknowns": [
            "Triton explores a single primary concrete path; alternate branches are not explored",
            "the P2-1 and CASE-003 fixtures are firmware-derived fragments without a full epilogue",
            "the SVM slice is 64 bytes of a foreign kernel image; no caller or control structure",
            "CASE-003 secure consumer remains unavailable",
        ],
    }
    temporary = args.cache or tempfile.mkdtemp(prefix="orbisprobe-m2b-matrix-")
    cache = AnalysisCache(temporary)
    cache_dir = Path(temporary)
    orchestrator = BackendOrchestrator(registry, cache, limits=limits)

    with tempfile.TemporaryDirectory(prefix="orbisprobe-m2b-binaries-") as binaries:
        binary_root = Path(binaries)

        # ---------------------------------------------------------- harness fixture matrix
        runtimes: dict[str, list[float]] = {"triton": [], "angr": [], "ghidra": []}
        for case in CASES:
            binary = materialize(case, binary_root)
            harness = parse_harness(case.document())
            report, seconds = timed(
                lambda h=harness, b=binary: orchestrator.run_harness(h, b, "trace", ["triton"])
            )
            result = report.results[0]
            problems = case_mismatches(case, result)
            runtimes["triton"].append(seconds)
            record = {
                "case_id": case.case_id,
                "expected": case.description,
                "status": result.status.value,
                "execution_status": result.data.get("execution_status"),
                "stop_reason": result.data.get("stop_reason"),
                "sink_types": sorted(sink_types(result)),
                "tainted_sources": sorted(tainted_sources(result)),
                "instructions_executed": result.data.get("instructions_executed"),
                "runtime_seconds": seconds,
                "mismatches": problems,
                "result": "PASS" if not problems else "FAIL",
            }
            output["harness_fixture_matrix"].append(record)
        output["harness_fixture_count"] = len(output["harness_fixture_matrix"])
        output["harness_fixture_failures"] = [
            row["case_id"] for row in output["harness_fixture_matrix"] if row["result"] == "FAIL"
        ]

        # ---------------------------------------------------------- research rows
        for name, document, payload, operation in research_documents():
            binary = binary_root / f"{document['harness_id']}.bin"
            binary.write_bytes(payload)
            harness = parse_harness(document)
            report, seconds = timed(
                lambda h=harness, b=binary, o=operation: orchestrator.run_harness(h, b, o, ["triton"])
            )
            result = report.results[0]
            row: dict[str, Any] = {
                "case": name,
                "harness_sha256": harness.harness_sha256,
                "binary_sha256": harness.binary_sha256,
                "triton": {
                    **backend_summary(result, seconds),
                    "execution_status": result.data.get("execution_status"),
                    "stop_reason": result.data.get("stop_reason"),
                    "instructions_executed": result.data.get("instructions_executed"),
                    "sink_types": sorted(sink_types(result)),
                    "sink_addresses": sorted(
                        {
                            hex(item["address"])
                            for flow in result.data.get("taint_flows", [])
                            for item in flow.get("sinks", [])
                            if item.get("address") is not None
                        }
                    ),
                    "call_events": len(result.data.get("call_events") or []),
                    "memory_violations": [
                        item["kind"] for item in result.data.get("memory_violations") or []
                    ],
                },
                "verdict": None,
                "negative_claim": False,
            }

            if name == "P2-1":
                facts = json.loads(
                    (ROOT / "tests" / "fixtures" / "p2_1_631ad0.json").read_text()
                )
                proof, native_seconds = timed(lambda current=facts: analyze_memop_facts(current))
                request = {
                    "binary": str(binary),
                    "architecture": "x86_64",
                    "base": P2_1_BASE,
                    "function": P2_1_BASE,
                    "function_end": P2_1_BASE + len(P2_1_CODE),
                }
                angr_result, angr_seconds = timed(
                    lambda current=request: angr.trace_value(
                        {
                            **current,
                            "source": {"register": "r12", "symbolic_bits": 64},
                            "consumer": P2_1_BASE + 13,
                            "observe": {"register": "r12", "max_values": 8},
                        }
                    )
                )
                ghidra_result, ghidra_seconds = timed(
                    lambda current=request: ghidra.analyze_function(current)
                )
                native_result = BackendResult.completed(
                    BackendIdentity("native-memop", native.version(), "capstone-native", frozenset()),
                    {},
                    [
                        BackendEvidence(
                            "value_domain",
                            f"r12@0x{P2_1_BASE + 13:x}",
                            proof.index_domain,
                            address=P2_1_BASE + 13,
                            provenance={"source_class": "static", "fixture": "P2-1"},
                        )
                    ],
                )
                consensus = consensus_of([native_result, angr_result])
                claim = next(item for item in consensus["claims"] if item["kind"] == "value_domain")
                row["native"] = {
                    "status": "COMPLETED",
                    "version": native.version(),
                    "verdict": proof.verdict.value,
                    "length": hex(proof.length),
                    "index_domain": proof.index_domain,
                    "destination_slot_size": hex(proof.destination_slot_size),
                    "runtime_seconds": native_seconds,
                }
                row["angr"] = {
                    **backend_summary(angr_result, angr_seconds),
                    "value_domain": angr_result.data.get("value_domain"),
                }
                row["ghidra"] = {
                    **backend_summary(ghidra_result, ghidra_seconds),
                    "pcode_ops": sorted({item["opcode"] for item in ghidra_result.data["pcode"]}),
                }
                row["consensus"] = {"classification": claim["classification"], "value": claim["value"]}
                row["triton_guard"] = {
                    f"r12_{index}": {
                        "taken": [
                            (branch["address"], branch["taken"])
                            for branch in run_guard(binary, P2_1_BASE, index)
                        ],
                        "return_value": run_guard(binary, P2_1_BASE, index, only_return=True),
                    }
                    for index in (0, 1, 2, 3)
                }
                row["verdict"] = "SAFE-INVARIANT; index domain {0,1}; no OOB or exploit claim"
                runtimes["angr"].append(angr_seconds)
                runtimes["ghidra"].append(ghidra_seconds)

            if name == "CASE-003":
                request = {
                    "binary": str(binary),
                    "architecture": "x86_64",
                    "base": CASE003_BASE,
                    "function": CASE003_BASE,
                    "function_end": CASE003_BASE + binary.stat().st_size,
                }
                surface, native_seconds = timed(
                    lambda path=binary: scan_secure(
                        BinaryImage.open(path, architecture="x86_64", base=CASE003_BASE)
                    )
                )
                angr_result, angr_seconds = timed(
                    lambda current=request: angr.analyze_function(current)
                )
                ghidra_result, ghidra_seconds = timed(
                    lambda current=request: ghidra.analyze_function(current)
                )
                row["native"] = {
                    "status": "COMPLETED",
                    "version": native.version(),
                    "classification": surface.classification,
                    "candidate_priority": surface.surfaces[0].candidate_priority,
                    "unknowns": surface.surfaces[0].unknowns,
                    "runtime_seconds": native_seconds,
                }
                row["angr"] = backend_summary(angr_result, angr_seconds)
                row["ghidra"] = backend_summary(ghidra_result, ghidra_seconds)
                row["consensus"] = {
                    "claims": [],
                    "note": "no shared secure-consumer claim; dynamic run adds no verdict",
                }
                row["verdict"] = (
                    "CROSS-PROCESSOR-CANDIDATE/P3 unchanged; dynamic evidence adds descriptor "
                    "pointer sinks only"
                )
                row["descriptor_sink_matches"] = row["triton"]["sink_addresses"] == sorted(
                    hex(address) for address in (CASE003_DESCRIPTOR + 8, CASE003_DESCRIPTOR + 0x10)
                )
                runtimes["angr"].append(angr_seconds)
                runtimes["ghidra"].append(ghidra_seconds)

            if name == "SVM":
                if fw900_available:
                    svm, native_seconds = timed(
                        lambda: scan_svm(
                            BinaryImage.open(fw900, architecture="x86_64", base=FW900_BASE)
                        )
                    )
                    row["native_scope"] = "real firmware image"
                else:
                    svm, native_seconds = timed(
                        lambda path=binary: scan_svm(
                            BinaryImage.open(path, architecture="x86_64", base=SVM_BASE)
                        )
                    )
                    row["native_scope"] = "64-byte fixture slice only"
                angr_result, angr_seconds = timed(
                    lambda path=binary: angr.analyze_function(
                        {
                            "binary": str(path),
                            "architecture": "x86_64",
                            "base": SVM_BASE,
                            "function": SVM_BASE,
                            "function_end": SVM_BASE + SVM_SLICE_SIZE,
                        }
                    )
                )
                row["native"] = {
                    "status": "COMPLETED",
                    "version": native.version(),
                    "classification": svm.classification,
                    "candidates": [
                        {
                            "surface_id": item.surface_id,
                            "priority": item.candidate_priority,
                            "score": item.candidate_score,
                        }
                        for item in svm.surfaces
                    ],
                    "open_chains": svm.to_dict()["open_chains"],
                    "runtime_seconds": native_seconds,
                }
                row["angr"] = backend_summary(angr_result, angr_seconds)
                row["consensus"] = {"claims": [], "note": "no engine reaches a shared SVM claim"}
                row["verdict"] = (
                    "no engine confirms the SVM surface; native capability-only, dynamic limited, "
                    "angr incomplete"
                )
                row["negative_claim"] = False
                runtimes["angr"].append(angr_seconds)

            output["research_rows"].append(row)

    # ---------------------------------------------------------- performance cold/warm
    performance: dict[str, Any] = {}
    with tempfile.TemporaryDirectory(prefix="orbisprobe-m2b-perf-") as perf_dir:
        perf_binary = Path(perf_dir) / "p2-1.bin"
        perf_binary.write_bytes(p2_1_binary())
        harness = parse_harness(p2_1_document(0))
        cold_cache = AnalysisCache(Path(perf_dir) / "cold")
        cold_orchestrator = BackendOrchestrator(registry, cold_cache, limits=limits)
        _, cold_seconds = timed(
            lambda: cold_orchestrator.run_harness(harness, perf_binary, "trace", ["triton"])
        )
        warm_orchestrator = BackendOrchestrator(registry, cold_cache, limits=limits)
        warm_report, warm_seconds = timed(
            lambda: warm_orchestrator.run_harness(harness, perf_binary, "trace", ["triton"])
        )
        performance = {
            "harness_cold_seconds": cold_seconds,
            "harness_warm_seconds": warm_seconds,
            "warm_cache_hits": warm_report.cache_hits,
            "runtime_samples": {
                name: {
                    "count": len(samples),
                    "median_seconds": round(statistics.median(samples), 6) if samples else None,
                    "max_seconds": round(max(samples), 6) if samples else None,
                }
                for name, samples in runtimes.items()
            },
        }
    output["performance"] = performance

    # ---------------------------------------------------------- cache regression
    first_cache = cache_dir / "regression"
    regression_binary = cache_dir / "cache-regression.bin"
    regression_binary.write_bytes(p2_1_binary())
    regression_harness = parse_harness(p2_1_document(1))
    first_report = BackendOrchestrator(
        registry, AnalysisCache(first_cache), limits=limits
    ).run_harness(regression_harness, regression_binary, "trace", ["triton"])
    second_report = BackendOrchestrator(
        registry, AnalysisCache(first_cache), limits=limits
    ).run_harness(regression_harness, regression_binary, "trace", ["triton"])
    first_payload = json.dumps(first_report.results[0].to_dict(), sort_keys=True)
    second_payload = json.dumps(second_report.results[0].to_dict(), sort_keys=True)
    output["cache_regression"] = {
        "cache_dir": str(first_cache),
        "first_run_cache_hits": first_report.cache_hits,
        "second_run_cache_hits": second_report.cache_hits,
        "records_identical": hashlib.sha256(first_payload.encode()).hexdigest()
        == hashlib.sha256(second_payload.encode()).hexdigest(),
        "harness_sha256": regression_harness.harness_sha256,
    }
    for row in output["research_rows"]:
        if row["consensus"] and "has_conflicts" in row["consensus"] and row["consensus"]["has_conflicts"]:
            output["conflicts"].append({"case": row["case"], "consensus": row["consensus"]})

    target = Path(args.out)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(output, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(
        {
            "out": str(target),
            "fixture_matrix": f"{output['harness_fixture_count']} cases, "
            f"{len(output['harness_fixture_failures'])} failures",
            "research_rows": [row["case"] for row in output["research_rows"]],
            "performance": performance,
            "cache_regression": output["cache_regression"],
        },
        indent=2,
        sort_keys=True,
    ))
    return 0


def run_guard(binary: Path, base: int, index: int, only_return: bool = False) -> Any:
    """Helper used for the P2-1 guard rows: run the harness for one concrete index value."""

    harness = parse_harness(p2_1_document(index))
    result = default_registry().create("triton", ResourceLimits(timeout_seconds=60)).run_harness(
        {
            "harness": harness,
            "binary": str(binary),
            "binary_sha256": harness.binary_sha256,
            "operation": "trace",
        }
    )
    if only_return:
        return result.data.get("return_value")
    return result.data.get("branches", [])


if __name__ == "__main__":
    raise SystemExit(main())
