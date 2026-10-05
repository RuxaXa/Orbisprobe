from __future__ import annotations

from dataclasses import replace

from orbisprobe.analysis import HardwareSinkClass, UserInfluence
from orbisprobe.leads.model import (
    ClosureCost,
    EdgeDistance,
    LeadBudget,
    LeadStatus,
    ResearchLead,
)
from orbisprobe.leads.scoring import (
    activation_status,
    compute_lead_score,
    is_active,
    rank_leads,
    score_lead,
)
from orbisprobe.schema import RiskClass


def _lead(
    lead_id: str,
    *,
    control: int,
    sink: int,
    gap: int,
    edge: EdgeDistance,
    cost: ClosureCost,
    status: LeadStatus = LeadStatus.DISCOVERED,
    hardware_class: HardwareSinkClass = HardwareSinkClass.DEVICE_COMMAND,
) -> ResearchLead:
    unknown = {
        EdgeDistance.EDGE_0: (),
        EdgeDistance.EDGE_1: ("unknown",),
        EdgeDistance.EDGE_2: ("unknown-a", "unknown-b"),
        EdgeDistance.EDGE_3PLUS: ("unknown-a", "unknown-b", "unknown-c"),
        EdgeDistance.ARTIFACT_BLOCKED: ("missing-artifact",),
    }[edge]
    return ResearchLead(
        lead_id=lead_id,
        origin="regression",
        root="root",
        source="source",
        sink="sink",
        hardware_class=hardware_class,
        user_influence=UserInfluence.USER_CONTROLLED,
        candidate_invariant="candidate invariant",
        known_edges=("known",),
        unknown_edges=unknown,
        evidence=("evidence",),
        observable="observable",
        persistence_risk="NONE",
        runtime_requirements=(),
        risk_class=RiskClass.OFFLINE,
        status=status,
        control_score=control,
        sink_score=sink,
        gap_score=gap,
        edge_distance=edge,
        closure_cost=cost,
        evidence_value=4,
        lead_score=0,
        budget=LeadBudget(1, 1, 1),
    )


def test_gc_reference_ranks_above_rc001_and_edge3plus():
    gc = _lead(
        "GC-A-REGRESSION",
        control=5,
        sink=5,
        gap=4,
        edge=EdgeDistance.EDGE_1,
        cost=ClosureCost.COST_2,
    )
    rc001 = _lead(
        "RC-001",
        control=3,
        sink=3,
        gap=3,
        edge=EdgeDistance.EDGE_3PLUS,
        cost=ClosureCost.COST_4,
        status=LeadStatus.PARKED,
    )

    ranked = rank_leads([rc001, gc], include_inactive=True)

    assert ranked[0].lead_id == "GC-A-REGRESSION"
    assert ranked[0].lead_score > ranked[1].lead_score


def test_high_hardware_sink_outranks_generic_kernel_sink():
    hardware = _lead(
        "HW",
        control=4,
        sink=5,
        gap=3,
        edge=EdgeDistance.EDGE_2,
        cost=ClosureCost.COST_2,
    )
    generic = replace(
        hardware,
        lead_id="GENERIC",
        sink_score=2,
        hardware_class=HardwareSinkClass.HOST_ONLY,
    )

    assert compute_lead_score(hardware) > compute_lead_score(generic)


def test_scoring_formula_and_ranking_are_deterministic():
    lead = _lead(
        "DETERMINISTIC",
        control=5,
        sink=5,
        gap=4,
        edge=EdgeDistance.EDGE_1,
        cost=ClosureCost.COST_2,
    )

    first = score_lead(lead)
    second = score_lead(lead)

    assert first.lead_score == 54
    assert first == second
    assert rank_leads([lead, lead], include_inactive=True) == rank_leads(
        [lead, lead], include_inactive=True
    )


def test_activation_policy_is_canonical_for_edges_and_value():
    edge3 = _lead(
        "EDGE3",
        control=5,
        sink=5,
        gap=5,
        edge=EdgeDistance.EDGE_3PLUS,
        cost=ClosureCost.COST_1,
        status=LeadStatus.DISCOVERED,
    )
    weak_edge2 = _lead(
        "WEAK-EDGE2",
        control=1,
        sink=1,
        gap=1,
        edge=EdgeDistance.EDGE_2,
        cost=ClosureCost.COST_3,
    )
    strong_edge2 = _lead(
        "STRONG-EDGE2",
        control=5,
        sink=5,
        gap=4,
        edge=EdgeDistance.EDGE_2,
        cost=ClosureCost.COST_1,
    )

    assert activation_status(score_lead(edge3)) is LeadStatus.PARKED
    assert is_active(score_lead(edge3)) is False
    assert activation_status(score_lead(weak_edge2)) is LeadStatus.PARKED
    assert activation_status(score_lead(strong_edge2)) is LeadStatus.CLOSURE_PENDING
