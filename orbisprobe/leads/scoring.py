from __future__ import annotations

from dataclasses import replace

from .model import ClosureCost, EdgeDistance, LeadStatus, OperationMode, ResearchLead

EDGE_PENALTY = {
    EdgeDistance.EDGE_0: 0,
    EdgeDistance.EDGE_1: 2,
    EdgeDistance.EDGE_2: 6,
    EdgeDistance.EDGE_3PLUS: 12,
    EdgeDistance.ARTIFACT_BLOCKED: 20,
}

EDGE_ORDER = {
    EdgeDistance.EDGE_0: 0,
    EdgeDistance.EDGE_1: 1,
    EdgeDistance.EDGE_2: 2,
    EdgeDistance.EDGE_3PLUS: 3,
    EdgeDistance.ARTIFACT_BLOCKED: 4,
}

COST_PENALTY = {
    ClosureCost.COST_1: 1,
    ClosureCost.COST_2: 3,
    ClosureCost.COST_3: 6,
    ClosureCost.COST_4: 10,
    ClosureCost.COST_5: 15,
    ClosureCost.COST_BLOCKED: 20,
}

ACTIVE_STATUSES = frozenset(
    {
        LeadStatus.DISCOVERED,
        LeadStatus.SCORED,
        LeadStatus.EDGE_ANALYZED,
        LeadStatus.CLOSURE_PENDING,
        LeadStatus.EVIDENCE_PROBE_READY,
        LeadStatus.PROOF_MODE,
    }
)

TERMINAL_STATUSES = frozenset(
    {
        LeadStatus.VULNERABILITY_CANDIDATE,
        LeadStatus.SAFE_INVARIANT,
        LeadStatus.DOWNGRADED,
        LeadStatus.ARTIFACT_BLOCKED,
        LeadStatus.DISPROVED,
    }
)

EDGE2_ACTIVE_MIN_SCORE = 35
EDGE2_ACTIVE_COSTS = frozenset(
    {ClosureCost.COST_1, ClosureCost.COST_2, ClosureCost.COST_3}
)


def compute_lead_score(lead: ResearchLead) -> int:
    """Research-priority score; never a security severity score."""
    return (
        lead.control_score * 3
        + lead.sink_score * 4
        + lead.gap_score * 4
        + lead.evidence_value * 2
        - EDGE_PENALTY[lead.edge_distance]
        - COST_PENALTY[lead.closure_cost]
    )


def activation_status(lead: ResearchLead) -> LeadStatus:
    if lead.status in TERMINAL_STATUSES:
        return lead.status
    if (
        lead.edge_distance is EdgeDistance.ARTIFACT_BLOCKED
        or lead.closure_cost is ClosureCost.COST_BLOCKED
    ):
        return LeadStatus.ARTIFACT_BLOCKED
    if lead.edge_distance is EdgeDistance.EDGE_3PLUS:
        return LeadStatus.PARKED
    if lead.edge_distance is EdgeDistance.EDGE_2:
        if (
            lead.lead_score >= EDGE2_ACTIVE_MIN_SCORE
            and lead.closure_cost in EDGE2_ACTIVE_COSTS
        ):
            return LeadStatus.CLOSURE_PENDING
        return LeadStatus.PARKED
    if lead.edge_distance is EdgeDistance.EDGE_1:
        return LeadStatus.CLOSURE_PENDING
    return LeadStatus.PROOF_MODE


def score_lead(lead: ResearchLead) -> ResearchLead:
    scored = replace(lead, lead_score=compute_lead_score(lead))
    status = activation_status(scored)
    if status in {LeadStatus.PROOF_MODE, LeadStatus.VULNERABILITY_CANDIDATE}:
        mode = OperationMode.PROOF_MODE
    elif status in ACTIVE_STATUSES:
        mode = OperationMode.DISCOVERY_MODE
    else:
        mode = scored.mode
    return replace(scored, status=status, mode=mode)


def is_active(lead: ResearchLead) -> bool:
    scored = replace(lead, lead_score=compute_lead_score(lead))
    status = activation_status(scored)
    return (
        status in ACTIVE_STATUSES
        and lead.edge_distance is not EdgeDistance.ARTIFACT_BLOCKED
        and lead.closure_cost is not ClosureCost.COST_BLOCKED
    )


def rank_leads(
    leads: list[ResearchLead] | tuple[ResearchLead, ...],
    *,
    include_inactive: bool = False,
) -> list[ResearchLead]:
    scored = [score_lead(lead) for lead in leads]
    if not include_inactive:
        scored = [lead for lead in scored if is_active(lead)]
    return sorted(
        scored,
        key=lambda lead: (
            -lead.lead_score,
            EDGE_ORDER[lead.edge_distance],
            COST_PENALTY[lead.closure_cost],
            lead.lead_id,
        ),
    )
