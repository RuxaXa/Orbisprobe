from __future__ import annotations

from dataclasses import dataclass, replace

from orbisprobe.schema import RiskClass

from .gates import evaluate_action_gate
from .model import (
    ActionKind,
    ClosureCost,
    EdgeDistance,
    EvidenceAction,
    LeadBudget,
    LeadStatus,
    OperationMode,
    ResearchLead,
)
from .scoring import COST_PENALTY, EDGE_ORDER, rank_leads, score_lead

COST_UNITS = {
    ClosureCost.COST_1: 1,
    ClosureCost.COST_2: 2,
    ClosureCost.COST_3: 3,
    ClosureCost.COST_4: 4,
    ClosureCost.COST_5: 5,
    ClosureCost.COST_BLOCKED: 1000,
}

RISK_PENALTY = {
    RiskClass.OFFLINE: 0.0,
    RiskClass.READ_ONLY: 0.5,
    RiskClass.VOLATILE_USER: 1.5,
    RiskClass.VOLATILE_SHARED: 2.0,
    RiskClass.REVERSIBLE_KERNEL_RAM: 4.0,
    RiskClass.ACTIVE_REQUEST: 5.0,
    RiskClass.PERSISTENT: 1000.0,
}


@dataclass(frozen=True)
class CampaignDecision:
    stop: bool
    reason: str


def default_budget(edge: EdgeDistance) -> LeadBudget:
    return {
        EdgeDistance.EDGE_0: LeadBudget(1, 0, 12),
        EdgeDistance.EDGE_1: LeadBudget(2, 10, 10),
        EdgeDistance.EDGE_2: LeadBudget(2, 5, 4),
        EdgeDistance.EDGE_3PLUS: LeadBudget(1, 1, 0),
        EdgeDistance.ARTIFACT_BLOCKED: LeadBudget(0, 0, 0),
    }[edge]


def action_priority(action: EvidenceAction) -> float:
    denominator = COST_UNITS[action.cost] + RISK_PENALTY[action.risk]
    return action.expected_information_gain / denominator


def edge_from_unknown_count(count: int) -> EdgeDistance:
    if count == 0:
        return EdgeDistance.EDGE_0
    if count == 1:
        return EdgeDistance.EDGE_1
    if count == 2:
        return EdgeDistance.EDGE_2
    return EdgeDistance.EDGE_3PLUS


def mode_budget(lead: ResearchLead) -> int:
    if lead.status in {LeadStatus.PROOF_MODE, LeadStatus.VULNERABILITY_CANDIDATE}:
        return lead.budget.proof
    if lead.status in {LeadStatus.CLOSURE_PENDING, LeadStatus.EVIDENCE_PROBE_READY}:
        return lead.budget.closure
    return lead.budget.discovery


def campaign_decision(
    leads: list[ResearchLead] | tuple[ResearchLead, ...],
    *,
    hard_safety_boundary: bool = False,
    integrity_fault: bool = False,
) -> CampaignDecision:
    if integrity_fault:
        return CampaignDecision(True, "INTEGRITY_FAULT")
    if hard_safety_boundary:
        return CampaignDecision(True, "HARD_SAFETY_BOUNDARY")
    if any(lead.status is LeadStatus.VULNERABILITY_CANDIDATE for lead in leads):
        return CampaignDecision(True, "VULNERABILITY_CANDIDATE")
    ranked = rank_leads(leads)
    if ranked:
        if any(mode_budget(lead) > 0 for lead in ranked):
            return CampaignDecision(False, "CONTINUE")
        return CampaignDecision(True, "TOP_K_BUDGET_EXHAUSTED")
    if leads and all(lead.status is LeadStatus.ARTIFACT_BLOCKED for lead in leads):
        return CampaignDecision(True, "ALL_HIGH_VALUE_ARTIFACT_BLOCKED")
    return CampaignDecision(True, "TOP_K_EXHAUSTED")


class ResearchScheduler:
    def __init__(self, leads: list[ResearchLead] | tuple[ResearchLead, ...]):
        self._leads = {lead.lead_id: lead for lead in leads}
        if len(self._leads) != len(leads):
            raise ValueError("lead IDs must be unique")

    @property
    def leads(self) -> tuple[ResearchLead, ...]:
        return tuple(self._leads[key] for key in sorted(self._leads))

    @property
    def active_closure_budget(self) -> int:
        return sum(lead.budget.closure for lead in rank_leads(self.leads))

    def ranked_active(self) -> list[ResearchLead]:
        scored = [lead for lead in rank_leads(self.leads) if mode_budget(lead) > 0]

        def key(lead: ResearchLead) -> tuple:
            action = self.next_action(lead)
            return (
                -lead.lead_score,
                EDGE_ORDER[lead.edge_distance],
                COST_PENALTY[lead.closure_cost],
                -(action.expected_information_gain if action else 0),
                RISK_PENALTY[action.risk] if action else 1000.0,
                lead.lead_id,
            )

        return sorted(scored, key=key)

    def next_lead(self) -> ResearchLead | None:
        ranked = self.ranked_active()
        return ranked[0] if ranked else None

    def funnel(self) -> dict[str, int | list[str]]:
        ranked = self.ranked_active()
        top20 = [lead.lead_id for lead in ranked[:20]]
        top8 = top20[:8]
        return {
            "raw_count": len(self._leads),
            "active_count": len(ranked),
            "top20": top20,
            "top8": top8,
            "top3": top8[:3],
        }

    def next_action(self, lead: ResearchLead | str) -> EvidenceAction | None:
        item = self._leads[lead] if isinstance(lead, str) else lead
        normalized = score_lead(item)
        if mode_budget(normalized) <= 0:
            return None
        actions = [
            action
            for action in item.evidence_actions
            if evaluate_action_gate(action).allowed
            and (
                action.kind is not ActionKind.EXPLOIT_TEST
                or (
                    normalized.mode is OperationMode.PROOF_MODE
                    and normalized.status
                    in {LeadStatus.PROOF_MODE, LeadStatus.VULNERABILITY_CANDIDATE}
                )
            )
            and (
                not action.required_artifact
                or item.edge_distance is not EdgeDistance.ARTIFACT_BLOCKED
            )
        ]
        if not actions:
            return None
        return min(
            actions,
            key=lambda action: (
                -action_priority(action),
                COST_UNITS[action.cost],
                RISK_PENALTY[action.risk],
                action.action_id,
            ),
        )

    def rehydrate(
        self,
        lead_id: str,
        resolved_edges: tuple[str, ...],
        *,
        artifact_available: bool = False,
    ) -> ResearchLead:
        if type(artifact_available) is not bool:
            raise TypeError("artifact_available must be a bool")
        lead = self._leads[lead_id]
        if lead.status not in {LeadStatus.PARKED, LeadStatus.ARTIFACT_BLOCKED}:
            return lead
        if lead.status is LeadStatus.ARTIFACT_BLOCKED and not artifact_available:
            return lead
        matched = set(lead.unknown_edges).intersection(resolved_edges)
        if not matched and not artifact_available:
            return lead
        remaining = tuple(edge for edge in lead.unknown_edges if edge not in matched)
        edge = edge_from_unknown_count(len(remaining))
        actions = tuple(
            replace(action, cost=ClosureCost.COST_2)
            if artifact_available and action.cost is ClosureCost.COST_BLOCKED
            else action
            for action in lead.evidence_actions
        )
        updated = score_lead(replace(
            lead,
            unknown_edges=remaining,
            known_edges=lead.known_edges + tuple(sorted(matched)),
            edge_distance=edge,
            closure_cost=(ClosureCost.COST_2 if lead.closure_cost is ClosureCost.COST_BLOCKED else lead.closure_cost),
            status=LeadStatus.EDGE_ANALYZED,
            budget=default_budget(edge),
            evidence_actions=actions,
        ))
        self._leads[lead_id] = updated
        return updated
