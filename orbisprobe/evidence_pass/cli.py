from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from orbisprobe.leads.store import LeadStore

from .builder import build_pass
from .journal import ActionJournal
from .manifest import manifest_sha256, verify_manifest
from .model import ClaimTrace, ReviewMode, canonical_json
from .plan import ActionPlan
from .rebuild import load_copy_events, replay_executor
from .remediation import RemediationRequest, plan_remediation
from .review import (
    build_review_bundle,
    classify_delayed_result,
    persist_review_result,
    review_failure_policy,
)
from .runner import run_plan
from .verify import verify_package

EXIT_CODES = {
    "PASS": 0,
    "MANIFEST_OK": 0,
    "EVIDENCE_PASS_BUILT": 0,
    "REMEDIATION_READY": 0,
    "CHANGES_REQUIRED": 2,
    "MANIFEST_INCOMPLETE": 2,
    "UNKNOWN_UNVERIFIED": 3,
    "STALE_REVIEW": 4,
    "STALE_RESULT": 4,
}


def _print(payload: object) -> None:
    sys.stdout.write(canonical_json(payload))


def _exit_for(status: str) -> int:
    return EXIT_CODES.get(status, 1)
def _evidence_inputs(values: list[str]) -> dict[str, str]:
    inputs: dict[str, str] = {}
    for item in values:
        name, _, path = item.partition("=")
        if not name or not path:
            raise ValueError(f"--evidence expects NAME=PATH, got {item!r}")
        inputs[name] = path
    return inputs


def add_evidence_pass_parser(subparsers: argparse._SubParsersAction) -> None:
    pass_block = subparsers.add_parser("evidence-pass", help="run one exact-once evidence pass")
    sub = pass_block.add_subparsers(dest="evidence_pass_cmd", required=True)

    command = sub.add_parser("build", help="execute the plan exactly once and freeze the package")
    command.add_argument("--plan", required=True)
    command.add_argument("--out", required=True)
    command.add_argument("--results", required=True, help="recorded execution results (JSON)")
    command.add_argument("--journal", help="existing journal to continue (exact-once)")
    command.add_argument("--leads-before", help="lead store before the pass (default: baseline package)")
    command.add_argument("--leads-final", help="lead store after the pass (default: --leads-before)")
    command.add_argument("--evidence", action="append", default=[], metavar="NAME=PATH")
    command.add_argument("--claims", help="claim traceability file (JSON)")
    command.add_argument("--copy-events", help="copy-direction claim record (JSON)")

    command = sub.add_parser("verify", help="verify a frozen package")
    command.add_argument("--package", required=True)
    command.add_argument("--expected-sha256", help="exact expected SHA256SUMS sha256")
    command.add_argument("--baseline", help="baseline package for unchanged-lead checks")
    command.add_argument("--expected-action-count", type=int)
    command.add_argument("--unchanged-lead", action="append", default=[])
    command.add_argument("--no-rebuild", action="store_true")
    command.add_argument("--no-strict", action="store_true")
    command.add_argument("--result-out")

    command = sub.add_parser("review-plan", help="emit the exact-hash review bundle")
    command.add_argument("--package", required=True)
    command.add_argument("--mode", default=ReviewMode.STANDARD.value, choices=[mode.value for mode in ReviewMode])
    command.add_argument("--reviewer", default="independent")

    command = sub.add_parser("review-record", help="bind a review result to the exact package hash")
    command.add_argument("--package", required=True)
    command.add_argument("--result", required=True)

    command = sub.add_parser("remediate", help="audit a remediation against the previous freeze")
    command.add_argument("--request", required=True)
    command.add_argument("--current", required=True)

    command = sub.add_parser("recover", help="mark in-flight journal entries UNKNOWN_UNVERIFIED")
    command.add_argument("--journal", required=True)


FAIL_CLOSED_ERRORS = (ValueError, TypeError, KeyError, OSError)


def run_evidence_pass_command(args: argparse.Namespace) -> int:
    """Dispatch one evidence-pass command.

    Predictable bad input (missing leads, stale remediation request, incomplete package, invalid
    plan) yields a canonical fail-closed result and exit code instead of a bare traceback.
    """

    try:
        return _dispatch(args)
    except FAIL_CLOSED_ERRORS as exc:
        status = "STALE_REVIEW" if "stale remediation request" in str(exc) else "CHANGES_REQUIRED"
        _print(
            {
                "schema": "orbisprobe-evidence-pass-cli-error-v1",
                "status": status,
                "error": f"{type(exc).__name__}: {exc}",
            }
        )
        return _exit_for(status)


def _dispatch(args: argparse.Namespace) -> int:
    command = args.evidence_pass_cmd

    if command == "build":
        plan = ActionPlan.load(args.plan)
        journal = (
            ActionJournal.from_dict(json.loads(Path(args.journal).read_text(encoding="utf-8")))
            if args.journal
            else None
        )
        report = run_plan(plan, replay_executor(Path(args.results)), journal)
        copy_events = load_copy_events(args.copy_events)
        before = (
            LeadStore.load(args.leads_before)
            if args.leads_before
            else LeadStore.load(Path(plan.baseline_package) / "leads-final.json")
        )
        final = LeadStore.load(args.leads_final) if args.leads_final else before
        claims_payload = (
            json.loads(Path(args.claims).read_text(encoding="utf-8")) if args.claims else {"claims": []}
        )
        claims = tuple(ClaimTrace.from_dict(item) for item in claims_payload.get("claims", []))
        result = build_pass(
            plan=plan,
            journal=report.journal,
            leads_before=before,
            leads_final=final,
            out_dir=args.out,
            evidence=_evidence_inputs(args.evidence),
            claims=claims,
            copy_events=copy_events,
            shared_records=report.shared_records,
        )
        _print(result.to_dict())
        return 0

    if command == "verify":
        result = verify_package(
            args.package,
            baseline_package=args.baseline,
            expected_sha256sums_sha256=args.expected_sha256,
            strict=not args.no_strict,
            rebuild=not args.no_rebuild,
            expected_action_count=args.expected_action_count,
            expected_unchanged_leads=tuple(args.unchanged_lead),
            result_out=args.result_out,
        )
        _print(result)
        return _exit_for(result["status"])

    if command == "review-plan":
        request = build_review_bundle(args.package, mode=ReviewMode(args.mode), reviewer=args.reviewer)
        _print({**request, "manifest": verify_manifest(args.package, strict=True).to_dict()})
        return 0

    if command == "review-record":
        payload = json.loads(Path(args.result).read_text(encoding="utf-8"))
        # Persist first: a verdict that is not frozen into the annex cannot stop anything.
        outcome = persist_review_result(args.package, payload)
        report = {
            **outcome.to_dict(),
            "policy": review_failure_policy(outcome),
            # Freshness is judged against the *current* freeze, not the hash the result names.
            "freshness": classify_delayed_result(manifest_sha256(args.package), payload).value,
        }
        _print(report)
        return _exit_for(report["state"])

    if command == "remediate":
        request = RemediationRequest.from_dict(json.loads(Path(args.request).read_text(encoding="utf-8")))
        report = plan_remediation(request=request, current_package=args.current)
        _print(report)
        return _exit_for(report["status"])

    if command == "recover":
        journal = ActionJournal.from_dict(json.loads(Path(args.journal).read_text(encoding="utf-8")))
        recovered = journal.recover_interrupted()
        _print({"recovered": list(recovered), "journal": journal.to_dict()})
        return 0

    raise ValueError(f"unknown evidence-pass command: {command}")
