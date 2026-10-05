from __future__ import annotations

import contextlib
import json
import os
import stat
import subprocess
import sys
import tempfile
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from orbisprobe.leads.model import EdgeDistance, LeadStatus
from orbisprobe.leads.safe_io import (
    capture_protected_sources,
    safe_atomic_write_text,
    validate_output_root,
)
from orbisprobe.leads.scoring import is_active
from orbisprobe.leads.store import LeadStore

from .journal import ActionJournal
from .manifest import (
    artifact_paths,
    manifest_sha256,
    verify_manifest,
)
from .metrics import compute_metrics, portfolio_snapshot
from .model import (
    DISPOSITION_SAFE_CLOSING_RESULTS,
    PACKAGE_REBUILD_ENTRYPOINT,
    PACKAGE_RESULT_NAME,
    PACKAGE_REVIEW_RESULT,
    ActionResult,
    ActionStatus,
    ClaimTrace,
    LeadDisposition,
    ReviewState,
    canonical_json,
    sha256_file,
)
from .plan import ActionPlan

PASS, FAIL, UNVERIFIED = "PASS", "FAIL", "UNVERIFIED"


@dataclass(frozen=True)
class Check:
    name: str
    status: str
    details: dict[str, Any]

    @property
    def ok(self) -> bool:
        return self.status == PASS

    def to_dict(self) -> dict[str, Any]:
        return {"check": self.name, "status": self.status, "details": self.details}


def _check(name: str, condition: bool, **details: Any) -> Check:
    return Check(name, PASS if condition else FAIL, details)


def _fail(name: str, **details: Any) -> Check:
    return Check(name, FAIL, details)


def _unverified(name: str, **details: Any) -> Check:
    return Check(name, UNVERIFIED, details)


def _load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _rebuild_parent(protected: Sequence[Any]) -> Path:
    """Pick a rebuild parent that the safe-I/O overlap guard accepts."""

    for base in (Path.home(), Path(tempfile.gettempdir()), Path("/var/tmp")):
        try:
            validate_output_root(base, protected)
        except ValueError:
            continue
        if base.is_dir():
            return base
    raise ValueError("no rebuild parent directory outside the protected source tree")


def _tree(root: Path) -> dict[str, str]:
    return {relative: sha256_file(root / relative) for relative in artifact_paths(root)}


@contextlib.contextmanager
def _package_read_barrier(root: Path):
    """Deny reads of the frozen package while a rebuild runs.

    The rebuild must derive its artifacts from its declared external inputs. Denying package
    reads (privilege-free, restored in ``finally``) makes an entry point that copies the package
    -- by ``__file__`` or by an embedded absolute path -- fail instead of passing itself off as a
    rebuild.
    """

    original_mode = stat.S_IMODE(root.stat().st_mode)
    os.chmod(root, 0o000)
    try:
        yield
    finally:
        os.chmod(root, original_mode)


def _rebuild_determinism(root: Path, protected: Sequence[Any]) -> Check:
    """Rebuild twice from a scratch copy of the entry point and require exact set equality.

    The entry point is copied outside the package before it is executed, so a
    ``__file__``-relative self-copy cannot present itself as a rebuild. The rebuilt artifact
    set must equal the package's artifact set exactly -- only the documented entry point may
    be package-only -- and a rebuild that emits nothing is a failure, never vacuous success.
    """

    entrypoint = root / PACKAGE_REBUILD_ENTRYPOINT
    if not entrypoint.is_file():
        return _unverified(
            "rebuild_determinism",
            reason=f"no {PACKAGE_REBUILD_ENTRYPOINT} entry point in the package",
            entrypoint=PACKAGE_REBUILD_ENTRYPOINT,
        )
    parent = _rebuild_parent(protected)
    package = _tree(root)
    with tempfile.TemporaryDirectory(prefix="evidence-pass-rebuild-a-", dir=parent) as first_tmp, \
            tempfile.TemporaryDirectory(prefix="evidence-pass-rebuild-b-", dir=parent) as second_tmp:
        outputs = []
        for temp in (first_tmp, second_tmp):
            scratch = Path(temp) / "entrypoint"
            scratch.mkdir()
            copied_entrypoint = scratch / "rebuild-pass.py"
            copied_entrypoint.write_bytes(entrypoint.read_bytes())
            target = Path(temp) / "out"
            with _package_read_barrier(root):
                completed = subprocess.run(
                    [sys.executable, str(copied_entrypoint), "--out", str(target)],
                    cwd=temp,
                    capture_output=True,
                    text=True,
                    check=False,
                )
            if completed.returncode != 0:
                return _fail(
                    "rebuild_determinism",
                    reason=(
                        "rebuild entry point failed (package reads are denied during the rebuild; "
                        "the entry point must use its declared external inputs)"
                    ),
                    exit_code=completed.returncode,
                    stderr=completed.stderr[-2000:],
                )
            outputs.append(target)
        first, second = _tree(outputs[0]), _tree(outputs[1])
        if first != second:
            differing = sorted({key for key in set(first) | set(second) if first.get(key) != second.get(key)})
            return _fail("rebuild_determinism", reason="rebuilds are not byte-identical", differing=differing)

        package_only = sorted(set(package) - set(first))
        not_reproduced = sorted(key for key in package_only if key != PACKAGE_REBUILD_ENTRYPOINT)
        rebuilt_only = sorted(set(first) - set(package))
        mismatched = sorted(key for key in first if package.get(key) != first[key])
        problems: list[str] = []
        if not first:
            problems.append("rebuild emitted no artifacts (vacuous reproducibility)")
        problems.extend(f"package artifact not reproduced by the rebuild: {key}" for key in not_reproduced)
        problems.extend(f"rebuilt artifact does not match the package: {key}" for key in mismatched)
        problems.extend(f"rebuilt artifact is absent from the package: {key}" for key in rebuilt_only)
        return _check(
            "rebuild_determinism",
            not problems,
            builds_compared=2,
            files_compared=len(first),
            package_artifacts=len(package),
            entrypoint_executed_from_scratch_copy=True,
            package_reads_denied_during_rebuild=True,
            rebuilt_bytes_identical=True,
            rebuilt_equals_package=not problems,
            mismatched=mismatched,
            rebuilt_only=rebuilt_only,
            package_only=package_only,
            problems=problems,
        )


def verify_package(
    package_dir: str | Path,
    *,
    baseline_package: str | Path | None = None,
    expected_sha256sums_sha256: str | None = None,
    strict: bool = True,
    rebuild: bool = True,
    expected_action_count: int | None = None,
    expected_unchanged_leads: Sequence[str] = (),
    result_out: str | Path | None = None,
) -> dict[str, Any]:
    """Verify one evidence-pass package. No check is a static flag; PASS is derived."""

    root = Path(package_dir).resolve()
    checks: list[Check] = []
    before_manifest = manifest_sha256(root)

    manifest_report = verify_manifest(root, strict=strict)
    checks.append(_check("manifest_integrity", manifest_report.ok, **manifest_report.to_dict()))

    if expected_sha256sums_sha256 is None:
        checks.append(
            _check(
                "package_hash_binding",
                True,
                recorded=before_manifest,
                expected=None,
                note="no external hash supplied; binding is enforced by the review gate",
            )
        )
    else:
        checks.append(
            _check(
                "package_hash_binding",
                before_manifest == expected_sha256sums_sha256,
                recorded=before_manifest,
                expected=expected_sha256sums_sha256,
            )
        )

    try:
        plan = ActionPlan.from_dict(_load_json(root / "action-plan.json"))
        journal = ActionJournal.from_dict(_load_json(root / "action-journal.json"))
        leads_before = LeadStore.load(root / "leads-before.json")
        leads_final = LeadStore.load(root / "leads-final.json")
        metrics_recorded = _load_json(root / "metrics.json")
        summary = _load_json(root / "campaign-summary.json")
        source_manifest = _load_json(root / "source-manifest.json")
        claims_payload = _load_json(root / "claims.json")
    except (OSError, ValueError, TypeError, KeyError) as exc:
        checks.append(_fail("package_readable", error=f"{type(exc).__name__}: {exc}"))
        result = _finalize(root, checks, before_manifest, None)
        _write_result(root, result, result_out, protected=())
        return result

    expected = expected_action_count if expected_action_count is not None else plan.expected_action_count
    journalled = sorted(record.action_id for record in journal.records())
    checks.append(
        _check(
            "action_count_and_plan_binding",
            journalled == sorted(plan.action_ids) and len(journalled) == expected,
            declared=sorted(plan.action_ids),
            journalled=journalled,
            expected_action_count=expected,
        )
    )

    counts = journal.execution_counts()
    started = sorted(record.action_id for record in journal.records() if record.status is ActionStatus.STARTED)
    completions_without_outcome = sorted(
        record.action_id
        for record in journal.records()
        if record.status is ActionStatus.COMPLETED and record.outcome is None
    )
    checks.append(
        _check(
            "exact_once",
            all(value <= 1 for value in counts.values())
            and len(counts) == len(journal.records())
            and not started
            and not completions_without_outcome,
            attempts=counts,
            in_flight=started,
            completions_without_outcome=completions_without_outcome,
            recovered_unknown=sum(
                1 for record in journal.records() if record.status is ActionStatus.UNKNOWN_UNVERIFIED
            ),
        )
    )

    leads_by_id = {lead.lead_id: lead for lead in leads_final.leads}
    before_by_id = {lead.lead_id: lead for lead in leads_before.leads}
    problems: list[str] = []
    for record in journal.records():
        outcome = record.outcome
        if outcome is None:
            continue
        lead = leads_by_id.get(outcome.lead_id)
        if lead is None:
            problems.append(
                f"{record.action_id}: outcome references lead {outcome.lead_id}, "
                "which is absent from leads-final.json"
            )
            continue
        if outcome.disposition is LeadDisposition.SAFE_CLOSED:
            if outcome.result not in DISPOSITION_SAFE_CLOSING_RESULTS:
                problems.append(
                    f"{record.action_id}: SAFE_CLOSED requires a safe-closing action result, got {outcome.result.value}"
                )
            if (
                lead.status is not LeadStatus.SAFE_INVARIANT
                or lead.edge_distance is not EdgeDistance.EDGE_0
                or lead.unknown_edges
            ):
                problems.append(
                    f"{record.action_id}: action result {outcome.result.value} must not be promoted to whole-lead "
                    f"closure (lead {lead.lead_id} is {lead.status.value}/{lead.edge_distance.value})"
                )
            if is_active(lead):
                problems.append(f"{record.action_id}: lead {lead.lead_id} is still active but recorded as SAFE_CLOSED")
            if not outcome.evidence:
                problems.append(f"{record.action_id}: SAFE_CLOSED requires at least one evidence reference")

    # A lead that is closed in the final store must be explained by the action / shared-evidence
    # history: an unchanged action must not silently carry a lead into a terminal disposition.
    closure_advancing = {ActionResult.RESOLVED_SAFE, ActionResult.EDGE_REDUCED}
    raw_shared = summary.get("shared_evidence") if isinstance(summary, dict) else None
    recorded_shared = raw_shared if isinstance(raw_shared, list) else []
    for lead in leads_final.leads:
        closed_now = (
            lead.status is LeadStatus.SAFE_INVARIANT
            and lead.edge_distance is EdgeDistance.EDGE_0
            and not lead.unknown_edges
        )
        if not closed_now:
            continue
        previous = before_by_id.get(lead.lead_id)
        if (
            previous is not None
            and previous.status is LeadStatus.SAFE_INVARIANT
            and previous.edge_distance is EdgeDistance.EDGE_0
        ):
            continue  # already closed before the pass: no new closure is being claimed
        explained = any(
            record.status is ActionStatus.COMPLETED
            and record.outcome is not None
            and record.outcome.lead_id == lead.lead_id
            and record.outcome.result in closure_advancing
            for record in journal.records()
        )
        if not explained:
            for entry in recorded_shared:
                if lead.lead_id not in entry.get("recipients", []):
                    continue
                source_id = entry.get("source_action_id")
                if source_id not in counts:
                    continue
                source = journal.record(source_id)
                if (
                    source.status is ActionStatus.COMPLETED
                    and source.outcome is not None
                    and source.outcome.result in closure_advancing
                    and entry.get("edges_changed")
                ):
                    explained = True
                    break
        if not explained:
            problems.append(
                f"lead {lead.lead_id}: terminal state {lead.edge_distance.value}/{lead.status.value} is not explained "
                "by any closure-advancing action result or shared-evidence propagation"
            )
    checks.append(
        _check("result_disposition_separation", not problems, problems=problems)
    )

    trace_problems: list[str] = []
    claim_records: list[ClaimTrace] = []
    raw_claims = claims_payload.get("claims") if isinstance(claims_payload, dict) else None
    if not isinstance(raw_claims, list):
        trace_problems.append("claims.json must contain a list of claims")
    else:
        for item in raw_claims:
            try:
                claim_records.append(ClaimTrace.from_dict(item))
            except (ValueError, TypeError) as exc:
                trace_problems.append(f"untraceable claim: {exc}")
    for claim in claim_records:
        target = root / claim.slice_path
        if not target.is_file():
            trace_problems.append(f"claim slice missing: {claim.slice_path}")
        elif sha256_file(target) != claim.slice_sha256:
            trace_problems.append(f"claim slice hash mismatch: {claim.slice_path}")
    for record in journal.records():
        outcome = record.outcome
        if outcome is None:
            continue
        for reference in outcome.evidence:
            if not (root / reference).is_file():
                trace_problems.append(f"{record.action_id}: evidence reference does not resolve: {reference}")
    checks.append(
        _check(
            "claim_traceability",
            not trace_problems,
            claims=len(claim_records),
            problems=trace_problems,
        )
    )

    copy_events_path = root / "copy-events.json"
    if not copy_events_path.is_file():
        checks.append(
            _fail(
                "copy_direction_claims",
                problems=["package does not contain its copy-event record"],
            )
        )
    else:
        from .direction import check_copy_events

        direction_problems, checked = check_copy_events(_load_json(copy_events_path))
        checks.append(
            _check(
                "copy_direction_claims",
                not direction_problems,
                copies_checked=checked,
                problems=direction_problems,
            )
        )

    unchanged_problems: list[str] = []
    if baseline_package is not None and expected_unchanged_leads:
        baseline = LeadStore.load(Path(baseline_package) / "leads-final.json")
        baseline_by_id = {lead.lead_id: lead for lead in baseline.leads}
        for lead_id in expected_unchanged_leads:
            before = baseline_by_id.get(lead_id)
            after = leads_by_id.get(lead_id)
            if before is None:
                unchanged_problems.append(f"expected unchanged lead is absent from the baseline: {lead_id}")
            elif after is None:
                unchanged_problems.append(f"expected unchanged lead is absent from leads-final.json: {lead_id}")
            elif before.to_dict() != after.to_dict():
                unchanged_problems.append(f"lead must stay byte-identical: {lead_id}")
    checks.append(
        _check(
            "expected_unchanged_leads",
            not unchanged_problems,
            checked=list(expected_unchanged_leads),
            problems=unchanged_problems,
        )
    )

    portfolio = portfolio_snapshot(leads_final)
    expected_portfolio = {key: value for key, value in plan.expected_portfolio}
    portfolio_problems = [
        f"{key}: expected {value}, observed {portfolio.get(key)}"
        for key, value in sorted(expected_portfolio.items())
        if portfolio.get(key) != value
    ]
    checks.append(
        _check(
            "portfolio_constraints",
            not portfolio_problems,
            observed=portfolio,
            expected=expected_portfolio,
            problems=portfolio_problems,
        )
    )

    protected = capture_protected_sources(plan.protected_sources)
    recorded_sources = source_manifest.get("sources") if isinstance(source_manifest, dict) else None
    source_problems: list[str] = []
    if not isinstance(recorded_sources, list) or len(recorded_sources) != len(protected):
        source_problems.append("source-manifest does not match the protected source set")
    else:
        for source, recorded in zip(sorted(protected, key=lambda item: str(item.resolved_path)), sorted(
            recorded_sources, key=lambda item: item["path"]
        ), strict=False):
            if str(source.resolved_path) != recorded.get("path"):
                source_problems.append(f"source path changed: {source.resolved_path}")
            if (source.device, source.inode) != (recorded.get("device"), recorded.get("inode")):
                source_problems.append(f"source identity changed: {source.resolved_path}")
            if source.sha256 != recorded.get("sha256"):
                source_problems.append(f"source hash changed: {source.resolved_path}")
    checks.append(
        _check(
            "source_immutability",
            not source_problems,
            sources=len(protected),
            problems=source_problems,
        )
    )

    recomputed = compute_metrics(
        plan=plan,
        journal=journal,
        leads_before=leads_before,
        leads_final=leads_final,
        source_integrity=not source_problems,
    ).to_dict()
    metrics_problems = [
        f"{key}: recorded {metrics_recorded.get(key)}, recomputed {value}"
        for key, value in sorted(recomputed.items())
        if metrics_recorded.get(key) != value
    ]
    summary_actions = summary.get("action_results") if isinstance(summary, dict) else None
    if not isinstance(summary_actions, list) or len(summary_actions) != len(journal.records()):
        metrics_problems.append("campaign-summary action_results do not match the journal")
    checks.append(
        _check(
            "metrics_recomputation",
            not metrics_problems,
            recorded=metrics_recorded,
            recomputed=recomputed,
            problems=metrics_problems,
        )
    )

    # The declared policy must actually constrain the recorded work: the metrics are recomputed
    # from the package, so this cannot be satisfied by editing a flag.
    policy = plan.safety_policy
    policy_problems: list[str] = []
    if not policy.runtime_actions_allowed and recomputed["runtime_actions"]:
        policy_problems.append(
            f"policy forbids runtime actions but {recomputed['runtime_actions']} were executed"
        )
    if not policy.proof_actions_allowed and recomputed["proof_actions"]:
        policy_problems.append(
            f"policy forbids proof actions but {recomputed['proof_actions']} were executed"
        )
    for action in plan.actions:
        if action.risk.value not in policy.allowed_risks:
            policy_problems.append(
                f"action {action.action_id} risk {action.risk.value} is outside the policy's allowed set"
            )
    checks.append(
        _check(
            "policy_enforcement",
            not policy_problems,
            runtime_actions_allowed=policy.runtime_actions_allowed,
            proof_actions_allowed=policy.proof_actions_allowed,
            allowed_risks=list(policy.allowed_risks),
            observed={"runtime_actions": recomputed["runtime_actions"], "proof_actions": recomputed["proof_actions"]},
            problems=policy_problems,
        )
    )

    shared_problems: list[str] = []
    recorded_shared = summary.get("shared_evidence") if isinstance(summary, dict) else None
    if not isinstance(recorded_shared, list):
        recorded_shared = []
    for shared in plan.shared_evidence:
        matches = [item for item in recorded_shared if item.get("source_action_id") == shared.source_action_id]
        if not matches:
            shared_problems.append(f"shared evidence not recorded: {shared.source_action_id}")
            continue
        entry = matches[0]
        if sorted(entry.get("recipients", [])) != sorted(shared.recipients):
            shared_problems.append(f"shared recipients mismatch: {shared.source_action_id}")
        source_record = journal.record(shared.source_action_id)
        if source_record.status is not ActionStatus.COMPLETED:
            shared_problems.append(f"shared source action is not COMPLETED: {shared.source_action_id}")
        for recipient in shared.recipients:
            record = journal.record(recipient) if recipient in counts else None
            if record is not None and record.attempts > 0:
                shared_problems.append(f"shared recipient was executed again: {recipient}")
    checks.append(
        _check(
            "shared_evidence",
            not shared_problems,
            shared_actions=sorted(plan.shared_action_ids()),
            problems=shared_problems,
        )
    )

    if rebuild:
        checks.append(_rebuild_determinism(root, protected))
    else:
        checks.append(_unverified("rebuild_determinism", reason="rebuild verification disabled by the caller"))

    review_state: str | None = None
    review_path = root / PACKAGE_REVIEW_RESULT
    if review_path.is_file():
        from .review import evaluate_review_result

        outcome = evaluate_review_result(root, _load_json(review_path))
        review_state = outcome.state.value
        # Only a hash-bound PASS may allow final verification: CHANGES_REQUIRED stops the pass.
        checks.append(
            _check(
                "review_annex_binding",
                outcome.state is ReviewState.PASS,
                state=outcome.state.value,
                reason=outcome.reason,
                findings=list(outcome.findings),
                problems=[] if outcome.state is ReviewState.PASS
                else [f"the frozen review annex is not PASS: {outcome.state.value} ({outcome.reason})"],
            )
        )
        checks.append(
            _check(
                "review_failure_policy",
                outcome.state is ReviewState.PASS,
                stop=outcome.state is not ReviewState.PASS,
                auto_remediation=False,
                requires=None if outcome.state is ReviewState.PASS
                else "separate REMEDIATION_PASS with explicit allowed paths",
            )
        )

    checks.append(
        _check(
            "frozen_set_unchanged",
            manifest_sha256(root) == before_manifest,
            before=before_manifest,
            after=manifest_sha256(root),
        )
    )

    result = _finalize(root, checks, before_manifest, review_state)
    _write_result(root, result, result_out, protected=protected)
    return result


def _write_result(
    root: Path,
    result: dict[str, Any],
    result_out: str | Path | None,
    *,
    protected: Sequence[Any],
) -> None:
    """Freeze the verification result as a package annex (outside the manifest)."""

    target = Path(result_out) if result_out is not None else root / PACKAGE_RESULT_NAME
    safe_atomic_write_text(
        target,
        canonical_json(result),
        output_root=target.parent,
        protected_sources=protected,
    )


def _finalize(
    root: Path,
    checks: Sequence[Check],
    manifest_hash: str,
    review_state: str | None,
) -> dict[str, Any]:
    if any(check.status == FAIL for check in checks):
        status = "CHANGES_REQUIRED"
    elif any(check.status == UNVERIFIED for check in checks):
        status = "UNKNOWN_UNVERIFIED"
    else:
        status = "PASS"
    by_name = {check.name: check for check in checks}
    return {
        "schema": "orbisprobe-evidence-pass-verification-v1",
        "status": status,
        "package": str(root),
        "package_sha256sums_sha256": manifest_hash,
        "checks": [check.to_dict() for check in checks],
        "manifest": dict(by_name["manifest_integrity"].details) if "manifest_integrity" in by_name else {},
        "actions_expected": by_name.get("action_count_and_plan_binding", Check("", UNVERIFIED, {})).details.get(
            "expected_action_count"
        ),
        "exactly_once": bool(by_name.get("exact_once", Check("", UNVERIFIED, {})).details.get("attempts"))
        and not by_name.get("exact_once", Check("", UNVERIFIED, {})).details.get("in_flight"),
        "rebuild_files_compared": by_name.get("rebuild_determinism", Check("", UNVERIFIED, {})).details.get(
            "files_compared"
        ),
        "frozen_set_unchanged": bool(
            by_name.get("frozen_set_unchanged", Check("", UNVERIFIED, {})).ok
        ),
        "review_state": review_state,
    }
