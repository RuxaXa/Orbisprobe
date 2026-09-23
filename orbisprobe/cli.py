from __future__ import annotations

import argparse
import json
import shlex
import sys
from collections.abc import Sequence
from pathlib import Path

from .analyzers.memop_scan import scan_raw_x86_64
from .evidence import EvidenceLog
from .policy import Policy
from .report import markdown_report
from .runner import ExitClassification, Runner
from .schema import Experiment, RiskClass, experiment_sha256
from .targets.command_adapter import CommandAdapter
from .targets.offline import OfflineTarget

EXIT_BY_CLASSIFICATION = {
    ExitClassification.COMPLETED.value: 0,
    ExitClassification.BLOCKED.value: 2,
    ExitClassification.RUNTIME_FAILURE.value: 3,
    ExitClassification.RESTORE_FAILURE.value: 4,
}


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

    args = parser.parse_args(argv)
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
