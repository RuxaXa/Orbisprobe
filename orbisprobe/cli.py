from __future__ import annotations

import argparse
import importlib.util
import json
import shlex
import sys
from collections.abc import Sequence
from pathlib import Path

from .analysis.binary import BinaryImage, UnsupportedArchitecture
from .analyzers.memop_scan import scan_raw_x86_64
from .backends.base import BackendStatus, ResourceLimits
from .backends.cache import AnalysisCache
from .backends.orchestrator import BackendOrchestrator, default_registry
from .evidence import EvidenceLog
from .leads.cli import add_leads_parser, run_leads_command
from .policy import Policy
from .report import markdown_report
from .runner import ExitClassification, Runner
from .schema import Experiment, RiskClass, experiment_sha256
from .surfaces.privilege import TRACK_ORDER, scan_privilege_surface
from .targets.command_adapter import CommandAdapter
from .targets.offline import OfflineTarget

EXIT_BY_CLASSIFICATION = {
    ExitClassification.COMPLETED.value: 0,
    ExitClassification.BLOCKED.value: 2,
    ExitClassification.RUNTIME_FAILURE.value: 3,
    ExitClassification.RESTORE_FAILURE.value: 4,
}

AUTO_BACKENDS = ["native", "angr", "ghidra"]


def _backend_names(value: str) -> list[str]:
    if value == "auto":
        return list(AUTO_BACKENDS)
    names = [item.strip() for item in value.split(",") if item.strip()]
    if not names:
        raise ValueError("at least one backend is required")
    return names


def _limits(args) -> ResourceLimits:
    return ResourceLimits(
        timeout_seconds=args.timeout,
        memory_mb=args.memory_mb,
        state_ceiling=args.state_ceiling,
        maximum_function_count=args.max_functions,
        maximum_graph_size=args.max_graph_size,
        maximum_steps=args.max_steps,
    )


def _add_backend_options(command) -> None:
    command.add_argument("--backend", default="auto")
    command.add_argument("--cache-dir", default="~/.cache/orbisprobe/analysis")
    command.add_argument("--timeout", type=int, default=60)
    command.add_argument("--memory-mb", type=int, default=2048)
    command.add_argument("--state-ceiling", type=int, default=128)
    command.add_argument("--max-functions", type=int, default=4096)
    command.add_argument("--max-graph-size", type=int, default=100000)
    command.add_argument("--max-steps", type=int, default=100000)


def _orchestrator(args) -> BackendOrchestrator:
    return BackendOrchestrator(
        default_registry(),
        AnalysisCache(Path(args.cache_dir).expanduser()),
        limits=_limits(args),
    )


def _multi_backend_exit(payload: dict) -> int:
    usable = {
        BackendStatus.COMPLETED.value,
        BackendStatus.PARTIAL.value,
        BackendStatus.ANALYSIS_INCOMPLETE.value,
    }
    return 0 if any(item["status"] in usable for item in payload["results"]) else 3


def validated_plan(exp: Experiment, policy: Policy) -> dict:
    errors = policy.validate(exp)
    return {
        "ok": not errors,
        "errors": errors,
        "plan_sha256": experiment_sha256(exp),
        "policy": policy.to_dict(),
        "experiment": exp.to_dict(),
    }


def _load_experiment(path: str) -> tuple[Experiment | None, str | None]:
    try:
        return Experiment.from_json(path), None
    except (OSError, ValueError, TypeError, KeyError) as exc:
        return None, f"invalid experiment plan: {type(exc).__name__}: {exc}"


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="orbisprobe")
    sub = parser.add_subparsers(dest="cmd", required=True)
    add_leads_parser(sub)

    command = sub.add_parser("validate")
    command.add_argument("experiment")
    command.add_argument("--max-risk", default="read_only", choices=[item.value for item in RiskClass])

    command = sub.add_parser("run")
    command.add_argument("experiment")
    command.add_argument("--max-risk", default="read_only", choices=[item.value for item in RiskClass])
    command.add_argument("--adapter", help="external JSON stdin/stdout adapter command")
    command.add_argument("--evidence", default="evidence.jsonl")
    command.add_argument("--plan-sha256", required=True)
    command.add_argument("--dry-run", action="store_true")

    command = sub.add_parser("scan-memops")
    command.add_argument("binary")
    command.add_argument("--base", default="0", type=lambda value: int(value, 0))
    command.add_argument("--start", default="0", type=lambda value: int(value, 0))
    command.add_argument("--length", type=lambda value: int(value, 0))

    command = sub.add_parser("report")
    command.add_argument("evidence")
    command.add_argument("--out")

    command = sub.add_parser("backends")
    command.add_argument("--json", action="store_true")
    command.add_argument("--timeout", type=int, default=30)
    command.add_argument("--memory-mb", type=int, default=2048)
    command.add_argument("--state-ceiling", type=int, default=128)
    command.add_argument("--max-functions", type=int, default=4096)
    command.add_argument("--max-graph-size", type=int, default=100000)
    command.add_argument("--max-steps", type=int, default=100000)

    command = sub.add_parser("analyze-dataflow")
    command.add_argument("binary")
    command.add_argument("--base", required=True, type=lambda value: int(value, 0))
    command.add_argument("--function", required=True, type=lambda value: int(value, 0))
    command.add_argument("--function-end", type=lambda value: int(value, 0))
    command.add_argument("--architecture", default="x86_64")
    command.add_argument("--source-register")
    command.add_argument("--source-memory-base")
    command.add_argument("--source-memory-offset", type=lambda value: int(value, 0))
    command.add_argument("--consumer", type=lambda value: int(value, 0))
    command.add_argument("--json", action="store_true")
    command.add_argument("--out")
    _add_backend_options(command)

    command = sub.add_parser("prove-path")
    command.add_argument("binary")
    command.add_argument("--base", required=True, type=lambda value: int(value, 0))
    command.add_argument("--function", required=True, type=lambda value: int(value, 0))
    command.add_argument("--function-end", type=lambda value: int(value, 0))
    command.add_argument("--from", dest="from_address", required=True, type=lambda value: int(value, 0))
    command.add_argument("--to", dest="to_address", required=True, type=lambda value: int(value, 0))
    command.add_argument("--symbolic-register", action="append", default=[])
    command.add_argument("--architecture", default="x86_64")
    command.add_argument("--json", action="store_true")
    command.add_argument("--out")
    _add_backend_options(command)

    privilege = sub.add_parser("privilege-surface")
    privilege_sub = privilege.add_subparsers(dest="surface_mode", required=True)
    for mode in (*TRACK_ORDER, "all"):
        command = privilege_sub.add_parser(mode)
        command.add_argument("binary")
        command.add_argument("--base", default=0, type=lambda value: int(value, 0))
        command.add_argument("--architecture", default="x86_64")
        command.add_argument("--json", action="store_true")
        command.add_argument("--out")
        command.add_argument("--backend")
        command.add_argument("--cache-dir", default="~/.cache/orbisprobe/analysis")
        command.add_argument("--timeout", type=int, default=60)
        command.add_argument("--memory-mb", type=int, default=2048)
        command.add_argument("--state-ceiling", type=int, default=128)
        command.add_argument("--max-functions", type=int, default=4096)
        command.add_argument("--max-graph-size", type=int, default=100000)
        command.add_argument("--max-steps", type=int, default=100000)

    args = parser.parse_args(argv)
    if args.cmd == "leads":
        return run_leads_command(args)
    if args.cmd == "validate":
        exp, error = _load_experiment(args.experiment)
        if error is not None or exp is None:
            print(json.dumps({"ok": False, "errors": [error]}, indent=2))
            return 2
        result = validated_plan(exp, Policy(max_risk=RiskClass(args.max_risk)))
        print(json.dumps(result, indent=2))
        return 0 if result["ok"] else 2

    if args.cmd == "run":
        exp, error = _load_experiment(args.experiment)
        if error is not None or exp is None:
            print(json.dumps({"ok": False, "exit_classification": "blocked", "errors": [error]}, indent=2))
            return 2
        target = CommandAdapter(shlex.split(args.adapter)) if args.adapter else OfflineTarget()
        try:
            result = Runner(
                target,
                Policy(max_risk=RiskClass(args.max_risk)),
                EvidenceLog(args.evidence),
            ).run(
                exp,
                dry_run=args.dry_run,
                expected_plan_sha256=args.plan_sha256,
            )
        except Exception as exc:  # noqa: BLE001 - CLI must classify unexpected runtime failures
            print(
                json.dumps(
                    {
                        "ok": False,
                        "blocked": False,
                        "exit_classification": ExitClassification.RUNTIME_FAILURE.value,
                        "error": f"unexpected runtime failure: {type(exc).__name__}: {exc}",
                    },
                    indent=2,
                )
            )
            return 3
        print(json.dumps(result, indent=2))
        return EXIT_BY_CLASSIFICATION[result["exit_classification"]]

    if args.cmd == "backends":
        try:
            registry = default_registry()
            limits = _limits(args)
            payload = {
                name: registry.status(name, limits).to_dict()
                for name in AUTO_BACKENDS
            }
            binaryninja_present = importlib.util.find_spec("binaryninja") is not None
            payload["binaryninja"] = {
                "backend": {
                    "name": "binaryninja",
                    "version": "detected" if binaryninja_present else "unknown",
                    "independence_family": "binaryninja-mlil",
                    "capabilities": ["CFG", "SSA", "DATAFLOW", "CALLGRAPH", "DECOMPILER"],
                    "implementation": "optional",
                },
                "status": "BACKEND_UNAVAILABLE",
                "data": {"available": False},
                "evidence": [],
                "errors": [
                    "Binary Ninja installation/license not available"
                    if not binaryninja_present
                    else "Binary Ninja backend is not enabled until license validation"
                ],
                "unknowns": [],
                "partial": False,
                "metrics": {},
            }
            text = json.dumps(payload, indent=2, sort_keys=True)
            print(text)
            return 0
        except (OSError, ValueError) as exc:
            print(f"orbisprobe: backend detection failed: {exc}", file=sys.stderr)
            return 1

    if args.cmd == "analyze-dataflow":
        try:
            request = {
                "binary": args.binary,
                "architecture": args.architecture,
                "base": args.base,
                "function": args.function,
            }
            if args.function_end is not None:
                request["function_end"] = args.function_end
            source = {}
            if args.source_register:
                source["register"] = args.source_register
                source["symbolic_bits"] = 64
            if args.source_memory_base:
                source["memory_base"] = args.source_memory_base
                source["memory_displacement"] = args.source_memory_offset or 0
            if source:
                request["source"] = source
            if args.consumer is not None:
                request["consumer"] = args.consumer
            if args.source_register:
                request["observe"] = {"register": args.source_register, "max_values": 64}
            operation = "trace_value" if source and args.consumer is not None else "analyze_function"
            report = _orchestrator(args).run(operation, request, _backend_names(args.backend))
            payload = report.to_dict()
            text = json.dumps(payload, indent=2, sort_keys=True)
            if args.out:
                Path(args.out).write_text(text + "\n", encoding="utf-8")
            else:
                print(text)
            return _multi_backend_exit(payload)
        except (OSError, ValueError, RuntimeError) as exc:
            print(f"orbisprobe: analyze-dataflow failed: {exc}", file=sys.stderr)
            return 1

    if args.cmd == "prove-path":
        try:
            request = {
                "binary": args.binary,
                "architecture": args.architecture,
                "base": args.base,
                "function": args.function,
                "from": args.from_address,
                "to": args.to_address,
                "symbolic_registers": args.symbolic_register,
            }
            if args.function_end is not None:
                request["function_end"] = args.function_end
            report = _orchestrator(args).run(
                "evaluate_branch_constraints",
                request,
                _backend_names(args.backend),
            )
            payload = report.to_dict()
            text = json.dumps(payload, indent=2, sort_keys=True)
            if args.out:
                Path(args.out).write_text(text + "\n", encoding="utf-8")
            else:
                print(text)
            return _multi_backend_exit(payload)
        except (OSError, ValueError, RuntimeError) as exc:
            print(f"orbisprobe: prove-path failed: {exc}", file=sys.stderr)
            return 1

    if args.cmd == "privilege-surface":
        try:
            image = BinaryImage.open(
                args.binary,
                architecture=args.architecture,
                base=args.base,
            )
            result = scan_privilege_surface(args.surface_mode, image)
            payload = result.to_dict()
            if args.backend:
                analyses = []
                orchestrator = _orchestrator(args)
                names = _backend_names(args.backend)
                for surface in result.surfaces:
                    if surface.address is None:
                        continue
                    function = surface.address
                    if surface.function and surface.function.startswith("sub_"):
                        try:
                            function = int(surface.function[4:], 16)
                        except ValueError:
                            function = surface.address
                    function_end = min(image.base + image.size, function + 0x1000)
                    if function_end <= function:
                        continue
                    request = {
                        "binary": str(image.path),
                        "architecture": image.architecture,
                        "base": image.base,
                        "function": function,
                        "function_end": function_end,
                    }
                    backend_report = orchestrator.run("analyze_function", request, names)
                    item = backend_report.to_dict()
                    item["surface_id"] = surface.surface_id
                    analyses.append(item)
                payload["backend_analysis"] = analyses
            text = (
                json.dumps(payload, indent=2, sort_keys=True)
                if args.json or args.backend
                else result.to_text()
            )
            if args.out:
                Path(args.out).write_text(text + "\n", encoding="utf-8")
            else:
                print(text)
            return 0
        except (OSError, ValueError, RuntimeError, UnsupportedArchitecture) as exc:
            print(f"orbisprobe: privilege-surface failed: {exc}", file=sys.stderr)
            return 1

    if args.cmd == "scan-memops":
        try:
            result = scan_raw_x86_64(args.binary, args.base, args.start, args.length)
        except (OSError, ValueError, RuntimeError) as exc:
            print(f"orbisprobe: scan failed: {exc}", file=sys.stderr)
            return 1
        print(json.dumps(result, indent=2))
        return 0

    if args.cmd == "report":
        try:
            text = markdown_report(EvidenceLog(args.evidence))
            if args.out:
                Path(args.out).write_text(text, encoding="utf-8")
            else:
                print(text)
        except (OSError, ValueError) as exc:
            print(f"orbisprobe: report failed: {exc}", file=sys.stderr)
            return 1
        return 0

    return 1


if __name__ == "__main__":
    raise SystemExit(main())
