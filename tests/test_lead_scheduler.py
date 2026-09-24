from __future__ import annotations

from dataclasses import replace

import pytest

from orbisprobe.analysis import HardwareSinkClass, UserInfluence
from orbisprobe.leads.migration import current_reference_leads
from orbisprobe.leads.model import (
    ActionKind,
    ClosureCost,
    EdgeDistance,
    EvidenceAction,
    LeadBudget,
    LeadStatus,
    OperationMode,
    ResearchLead,
)
from orbisprobe.leads.scheduler import (
    ResearchScheduler,
    campaign_decision,
    default_budget,
)
from orbisprobe.schema import RiskClass


def _lead(
    lead_id: str,
    *,
    status: LeadStatus = LeadStatus.CLOSURE_PENDING,
    edge: EdgeDistance = EdgeDistance.EDGE_1,
    unknown: tuple[str, ...] | None = None,
    actions: tuple[EvidenceAction, ...] = (),
) -> ResearchLead:
    if unknown is None:
        unknown = {
            EdgeDistance.EDGE_0: (),
            EdgeDistance.EDGE_1: ("missing",),
            EdgeDistance.EDGE_2: ("missing-a", "missing-b"),
            EdgeDistance.EDGE_3PLUS: ("missing-a", "missing-b", "missing-c"),
            EdgeDistance.ARTIFACT_BLOCKED: ("missing-artifact",),
        }[edge]
    return ResearchLead(
        lead_id=lead_id,
        origin="test",
        root="root",
        source="source",
        sink="sink",
        hardware_class=HardwareSinkClass.DEVICE_COMMAND,
        user_influence=UserInfluence.USER_CONTROLLED,
        candidate_invariant="invariant",
        known_edges=("known",),
        unknown_edges=unknown,
        evidence=("evidence",),
        observable="observable",
        persistence_risk="NONE",
        runtime_requirements=(),
        risk_class=RiskClass.OFFLINE,
        status=status,
        control_score=5,
        sink_score=5,
        gap_score=4,
        edge_distance=edge,
        closure_cost=ClosureCost.COST_2,
        evidence_value=4,
        lead_score=0,
        evidence_actions=actions,
        budget=default_budget(edge),
    )


def _action(action_id: str, cost: ClosureCost, gain: int, risk: RiskClass) -> EvidenceAction:
    return EvidenceAction(
        action_id=action_id,
        action=action_id,
        target_edge="missing",
        kind=ActionKind.EVIDENCE_PROBE,
        expected_information_gain=gain,
        cost=cost,
        risk=risk,
        exact_question="Does this edge exist?",
        ownership_known=True,
        target_identity_known=True,
        bounded_scope=True,
        stop_condition="one bounded action",
    )


def test_scheduler_prefers_cheap_high_value_evidence_before_runtime():
    cheap = _action("offline-xref", ClosureCost.COST_1, 3, RiskClass.OFFLINE)
    runtime = _action("runtime-read", ClosureCost.COST_3, 4, RiskClass.READ_ONLY)
    lead = _lead("LEAD", actions=(runtime, cheap))

    selected = ResearchScheduler([lead]).next_action(lead)

    assert selected is not None
    assert selected.action_id == "offline-xref"


def test_artifact_blocked_and_safe_invariant_consume_no_active_budget():
    blocked = replace(
        _lead("BLOCKED"),
        status=LeadStatus.ARTIFACT_BLOCKED,
        edge_distance=EdgeDistance.ARTIFACT_BLOCKED,
        closure_cost=ClosureCost.COST_BLOCKED,
        budget=LeadBudget(0, 0, 0),
    )
    safe = _lead("SAFE", status=LeadStatus.SAFE_INVARIANT)
    scheduler = ResearchScheduler([blocked, safe])

    assert default_budget(EdgeDistance.ARTIFACT_BLOCKED) == LeadBudget(0, 0, 0)
    assert scheduler.next_lead() is None
    assert scheduler.active_closure_budget == 0


def test_parked_candidate_rehydrates_only_on_matching_new_edge_evidence():
    parked = _lead(
        "PARKED",
        status=LeadStatus.PARKED,
        edge=EdgeDistance.EDGE_3PLUS,
        unknown=("user-binding", "writer", "consumer"),
    )
    scheduler = ResearchScheduler([parked])

    unchanged = scheduler.rehydrate("PARKED", ("unrelated",))
    rehydrated = scheduler.rehydrate("PARKED", ("writer",))

    assert unchanged.status is LeadStatus.PARKED
    assert rehydrated.status is LeadStatus.CLOSURE_PENDING
    assert rehydrated.edge_distance is EdgeDistance.EDGE_2
    assert rehydrated.unknown_edges == ("consumer", "user-binding")


def test_scheduler_next_is_deterministic_and_edge1_precedes_edge2():
    edge2 = _lead("EDGE2", edge=EdgeDistance.EDGE_2, unknown=("a", "b"))
    edge1 = replace(_lead("EDGE1"), lead_score=1)

    first = ResearchScheduler([edge2, edge1]).next_lead()
    second = ResearchScheduler([edge1, edge2]).next_lead()

    assert first is not None and second is not None
    assert first.lead_id == second.lead_id == "EDGE1"


def test_campaign_stops_only_for_defined_terminal_conditions():
    ordinary_blocker = _lead(
        "PARKED",
        status=LeadStatus.PARKED,
        edge=EdgeDistance.EDGE_3PLUS,
        unknown=("a", "b", "c"),
    )
    candidate = _lead("VULN", status=LeadStatus.VULNERABILITY_CANDIDATE, edge=EdgeDistance.EDGE_0)
    artifact = replace(
        _lead("ARTIFACT"),
        status=LeadStatus.ARTIFACT_BLOCKED,
        edge_distance=EdgeDistance.ARTIFACT_BLOCKED,
        closure_cost=ClosureCost.COST_BLOCKED,
        budget=LeadBudget(0, 0, 0),
    )

    assert campaign_decision([ordinary_blocker]).reason == "TOP_K_EXHAUSTED"
    assert campaign_decision([candidate]).reason == "VULNERABILITY_CANDIDATE"
    assert campaign_decision([artifact]).reason == "ALL_HIGH_VALUE_ARTIFACT_BLOCKED"
    assert campaign_decision([_lead("ACTIVE")]).stop is False
    assert campaign_decision([_lead("ACTIVE")], hard_safety_boundary=True).reason == "HARD_SAFETY_BOUNDARY"
    assert campaign_decision([_lead("ACTIVE")], integrity_fault=True).reason == "INTEGRITY_FAULT"


def test_top_k_funnel_is_bounded_20_to_8_to_3():
    leads = [
        _lead(
            f"LEAD-{index:02d}",
            edge=EdgeDistance.EDGE_1 if index < 5 else EdgeDistance.EDGE_2,
        )
        for index in range(25)
    ]

    funnel = ResearchScheduler(leads).funnel()

    assert funnel["raw_count"] == 25
    assert len(funnel["top20"]) == 20
    assert len(funnel["top8"]) == 8
    assert len(funnel["top3"]) == 3
    assert funnel["top3"] == funnel["top8"][:3]


def test_strong_user_controlled_device_edge2_outranks_weak_generic_edge1():
    weak_edge1 = replace(
        _lead("GENERIC-EDGE1", edge=EdgeDistance.EDGE_1),
        hardware_class=HardwareSinkClass.HOST_ONLY,
        user_influence=UserInfluence.KERNEL_POLICY_SELECTED,
        control_score=1,
        sink_score=1,
        gap_score=1,
        evidence_value=2,
        closure_cost=ClosureCost.COST_2,
    )
    strong_edge2 = replace(
        _lead("DEVICE-EDGE2", edge=EdgeDistance.EDGE_2, unknown=("extent", "lifetime")),
        hardware_class=HardwareSinkClass.IOMMU_VISIBLE,
        user_influence=UserInfluence.USER_CONTROLLED,
        control_score=5,
        sink_score=5,
        gap_score=4,
        evidence_value=4,
        closure_cost=ClosureCost.COST_1,
    )

    ranked = ResearchScheduler([weak_edge1, strong_edge2]).ranked_active()

    assert [lead.lead_id for lead in ranked] == ["DEVICE-EDGE2", "GENERIC-EDGE1"]
    assert ranked[0].lead_score > ranked[1].lead_score


def test_equal_value_leads_use_information_gain_then_risk_deterministically():
    low_gain = _lead(
        "A-LOW-GAIN",
        actions=(_action("low", ClosureCost.COST_1, 2, RiskClass.OFFLINE),),
    )
    high_gain_read = _lead(
        "B-HIGH-GAIN-READ",
        actions=(_action("read", ClosureCost.COST_1, 5, RiskClass.READ_ONLY),),
    )
    high_gain_offline = _lead(
        "Z-HIGH-GAIN-OFFLINE",
        actions=(_action("offline", ClosureCost.COST_1, 5, RiskClass.OFFLINE),),
    )

    ranked = ResearchScheduler(
        [low_gain, high_gain_read, high_gain_offline]
    ).ranked_active()

    assert [lead.lead_id for lead in ranked] == [
        "Z-HIGH-GAIN-OFFLINE",
        "B-HIGH-GAIN-READ",
        "A-LOW-GAIN",
    ]


def test_discovery_mode_never_selects_exploit_action():
    exploit = EvidenceAction(
        action_id="exploit",
        action="bounded impact test",
        target_edge="effect",
        kind=ActionKind.EXPLOIT_TEST,
        expected_information_gain=5,
        cost=ClosureCost.COST_4,
        risk=RiskClass.VOLATILE_USER,
        exact_question="Does the complete candidate produce the bounded effect?",
        ownership_known=True,
        target_identity_known=True,
        bounded_scope=True,
        stop_condition="one attempt",
        controlled_input=True,
        concrete_gap=True,
        known_consumer=True,
        bounded_observable=True,
        lifecycle_closed=True,
        recovery_defined=True,
        controls_defined=True,
    )
    discovery = _lead("DISCOVERY", actions=(exploit,))
    proof = replace(
        discovery,
        lead_id="PROOF",
        mode=OperationMode.PROOF_MODE,
        status=LeadStatus.PROOF_MODE,
        edge_distance=EdgeDistance.EDGE_0,
        unknown_edges=(),
        budget=LeadBudget(0, 0, 1),
    )

    assert ResearchScheduler([discovery]).next_action(discovery) is None
    assert ResearchScheduler([proof]).next_action(proof) == exploit


def test_zero_mode_budget_removes_lead_action_and_stops_campaign():
    exhausted = replace(_lead("EXHAUSTED"), budget=LeadBudget(0, 0, 0))
    scheduler = ResearchScheduler([exhausted])

    assert scheduler.next_lead() is None
    assert scheduler.next_action(exhausted) is None
    assert campaign_decision([exhausted]).reason == "TOP_K_BUDGET_EXHAUSTED"


def test_artifact_rehydration_unblocks_a_selectable_action():
    secure = next(
        lead for lead in current_reference_leads() if lead.lead_id == "SEC-TAG1-TAG9"
    )
    scheduler = ResearchScheduler([secure])

    updated = scheduler.rehydrate(secure.lead_id, (), artifact_available=True)
    action = scheduler.next_action(updated)

    assert updated.status is LeadStatus.CLOSURE_PENDING
    assert updated.edge_distance is EdgeDistance.EDGE_2
    assert updated.closure_cost is ClosureCost.COST_2
    assert action is not None
    assert action.cost is ClosureCost.COST_2
    assert scheduler.next_lead() is not None
    assert campaign_decision(scheduler.leads).reason == "CONTINUE"
    for malformed in (1, 0, "false", [], {}):
        with pytest.raises(TypeError, match="artifact_available"):
            ResearchScheduler([secure]).rehydrate(
                secure.lead_id, (), artifact_available=malformed
            )
