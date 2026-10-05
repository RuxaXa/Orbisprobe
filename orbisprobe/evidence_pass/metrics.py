from __future__ import annotations

from orbisprobe.leads.model import ActionKind, EdgeDistance, LeadStatus, ResearchLead
from orbisprobe.leads.scoring import is_active
from orbisprobe.leads.store import LeadStore

from .journal import ActionJournal
from .model import ActionResult, LeadDisposition, Metrics
from .plan import OFFLINE_RISKS, ActionPlan

EDGE_INDEX = {
    EdgeDistance.EDGE_0: 0,
    EdgeDistance.EDGE_1: 1,
    EdgeDistance.EDGE_2: 2,
    EdgeDistance.EDGE_3PLUS: 3,
    EdgeDistance.ARTIFACT_BLOCKED: 4,
}


def _by_id(store: LeadStore) -> dict[str, ResearchLead]:
    return {lead.lead_id: lead for lead in store.leads}


def lead_diff(before: LeadStore, after: LeadStore) -> tuple[tuple[str, ...], tuple[str, ...]]:
    """Return (changed_ids, unchanged_ids) using canonical serialization."""

    before_map = _by_id(before)
    after_map = _by_id(after)
    changed: list[str] = []
    unchanged: list[str] = []
    for lead_id in sorted(set(before_map) | set(after_map)):
        left = before_map.get(lead_id)
        right = after_map.get(lead_id)
        if left is None or right is None or left.to_dict() != right.to_dict():
            changed.append(lead_id)
        else:
            unchanged.append(lead_id)
    return tuple(changed), tuple(unchanged)


def compute_metrics(
    *,
    plan: ActionPlan,
    journal: ActionJournal,
    leads_before: LeadStore,
    leads_final: LeadStore,
    source_integrity: bool,
) -> Metrics:
    """Derive every metric from the package contents; no static or caller-supplied flags."""

    projection = journal.metrics_projection()
    changed, unchanged = lead_diff(leads_before, leads_final)
    before_map = _by_id(leads_before)
    after_map = _by_id(leads_final)

    score_movement = 0
    edge_movement = 0
    for lead_id in sorted(set(before_map) & set(after_map)):
        left = before_map[lead_id]
        right = after_map[lead_id]
        score_movement += int(getattr(right, "lead_score", 0)) - int(getattr(left, "lead_score", 0))
        edge_movement += EDGE_INDEX[right.edge_distance] - EDGE_INDEX[left.edge_distance]

    runtime_actions = sum(1 for action in plan.actions if action.risk.value not in OFFLINE_RISKS)
    proof_actions = sum(1 for action in plan.actions if action.kind is ActionKind.EXPLOIT_TEST)
    recipients = sum(len(entry.recipients) for entry in plan.shared_evidence)

    return Metrics(
        actions_expected=plan.expected_action_count,
        actions_executed=sum(1 for value in journal.execution_counts().values() if value > 0),
        exactly_once=bool(projection["exactly_once"]),
        shared_actions=len(plan.shared_action_ids()),
        shared_evidence_recipients=recipients,
        leads_changed=len(changed),
        leads_unchanged=len(unchanged),
        score_movement=score_movement,
        edge_movement=edge_movement,
        safe_closures=sum(
            1
            for record in journal.records()
            if record.outcome is not None and record.outcome.disposition is LeadDisposition.SAFE_CLOSED
        ),
        downgrades=sum(
            1
            for record in journal.records()
            if record.outcome is not None and record.outcome.disposition is LeadDisposition.DOWNGRADED
        ),
        blocked_leads=sum(
            1
            for record in journal.records()
            if record.outcome is not None
            and record.outcome.disposition in (LeadDisposition.ARTIFACT_BLOCKED, LeadDisposition.PARKED)
        ),
        evidence_conflicts=sum(
            1
            for record in journal.records()
            if record.outcome is not None and record.outcome.result is ActionResult.EVIDENCE_CONFLICT
        ),
        runtime_actions=runtime_actions,
        proof_actions=proof_actions,
        source_integrity=source_integrity,
    )


def portfolio_snapshot(store: LeadStore) -> dict[str, int]:
    """Portfolio constraints derived from the final lead store."""

    leads = list(store.leads)
    return {
        "active_leads": sum(1 for lead in leads if is_active(lead)),
        "vulnerability_candidates": sum(
            1 for lead in leads if lead.status is LeadStatus.VULNERABILITY_CANDIDATE
        ),
        "safe_invariant": sum(1 for lead in leads if lead.status is LeadStatus.SAFE_INVARIANT),
        "blocked": sum(
            1
            for lead in leads
            if lead.status in (LeadStatus.ARTIFACT_BLOCKED, LeadStatus.PARKED)
        ),
    }
