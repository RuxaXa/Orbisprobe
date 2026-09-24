from __future__ import annotations

import json
import math
from dataclasses import replace

import pytest

from orbisprobe.analysis import HardwareSinkClass, UserInfluence
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
from orbisprobe.schema import RiskClass


def test_research_lead_roundtrip_is_canonical_and_complete():
    action = EvidenceAction(
        action_id="act-xref",
        action="resolve direct callers",
        target_edge="dispatcher->consumer",
        kind=ActionKind.EVIDENCE_PROBE,
        expected_information_gain=4,
        cost=ClosureCost.COST_1,
        risk=RiskClass.OFFLINE,
        required_artifact="kernel.bin",
        exact_question="Which direct caller reaches the sink?",
        ownership_known=True,
        target_identity_known=True,
        bounded_scope=True,
        stop_condition="one bounded xref pass",
    )
    lead = ResearchLead(
        lead_id="LEAD-GC",
        origin="M3-SOC2",
        root="/dev/gc",
        source="ioctl 0xc00c8110",
        sink="fixed GPU register",
        hardware_class=HardwareSinkClass.DEVICE_COMMAND,
        user_influence=UserInfluence.USER_CONTROLLED,
        candidate_invariant="authorization before shared hardware state",
        known_edges=("user->ioctl", "ioctl->register"),
        unknown_edges=("register->cross-context effect",),
        evidence=("gc-command-contracts.json",),
        observable="GPU availability",
        persistence_risk="NONE",
        runtime_requirements=("read-only register observer",),
        risk_class=RiskClass.READ_ONLY,
        status=LeadStatus.EDGE_ANALYZED,
        control_score=5,
        sink_score=5,
        gap_score=4,
        edge_distance=EdgeDistance.EDGE_1,
        closure_cost=ClosureCost.COST_3,
        evidence_value=4,
        lead_score=0,
        evidence_actions=(action,),
        budget=LeadBudget(discovery=1, closure=8, proof=12),
        legacy_status="PARKED",
    )

    encoded = lead.to_json()
    restored = ResearchLead.from_dict(json.loads(encoded))

    assert restored == lead
    assert restored.mode is OperationMode.DISCOVERY_MODE
    assert json.loads(encoded) == lead.to_dict()
    assert lead.unknown_edges == ("register->cross-context effect",)
    assert action.evidence_probe_ready is True
    assert restored.legacy_status == "PARKED"

    try:
        replace(lead, lead_score=math.nan)
    except ValueError as exc:
        assert "finite" in str(exc)
    else:
        raise AssertionError("non-finite lead scores must be rejected")

    try:
        replace(lead, lead_id="bad\ud800id")
    except ValueError as exc:
        assert "UTF-8" in str(exc)
    else:
        raise AssertionError("non-UTF-8 identifiers must be rejected")

    try:
        replace(
            lead,
            edge_distance=EdgeDistance.EDGE_3PLUS,
            status=LeadStatus.CLOSURE_PENDING,
        )
    except ValueError as exc:
        assert "EDGE-3PLUS" in str(exc)
    else:
        raise AssertionError("EDGE-3PLUS cannot carry an active status")


def test_edge_distance_must_match_decisive_unknown_edge_count():
    base = ResearchLead(
        lead_id="EDGE-CHECK",
        origin="test",
        root="root",
        source="source",
        sink="sink",
        hardware_class=HardwareSinkClass.HOST_ONLY,
        user_influence=UserInfluence.UNKNOWN,
        candidate_invariant="invariant",
        known_edges=("known",),
        unknown_edges=(),
        evidence=("evidence",),
        observable="unknown",
        persistence_risk="NONE",
        runtime_requirements=(),
        risk_class=RiskClass.OFFLINE,
        status=LeadStatus.DISCOVERED,
        control_score=2,
        sink_score=1,
        gap_score=1,
        edge_distance=EdgeDistance.EDGE_0,
        closure_cost=ClosureCost.COST_1,
        evidence_value=1,
        lead_score=0,
    )
    valid = (
        (EdgeDistance.EDGE_0, ()),
        (EdgeDistance.EDGE_1, ("a",)),
        (EdgeDistance.EDGE_2, ("a", "b")),
        (EdgeDistance.EDGE_3PLUS, ("a", "b", "c")),
    )
    for edge, unknown in valid:
        assert replace(base, edge_distance=edge, unknown_edges=unknown)
    invalid = (
        (EdgeDistance.EDGE_0, ("a",)),
        (EdgeDistance.EDGE_1, ()),
        (EdgeDistance.EDGE_2, ("a",)),
        (EdgeDistance.EDGE_3PLUS, ("a", "b")),
    )
    for edge, unknown in invalid:
        with pytest.raises(ValueError, match="unknown_edges"):
            replace(base, edge_distance=edge, unknown_edges=unknown)
    for edge, unknown in (
        (EdgeDistance.EDGE_2, ("same", "same")),
        (EdgeDistance.EDGE_3PLUS, ("same", "same", "other")),
    ):
        with pytest.raises(ValueError, match="duplicate"):
            replace(base, edge_distance=edge, unknown_edges=unknown)


def _serialized_action() -> dict:
    return EvidenceAction(
        action_id="closed-schema",
        action="bounded offline probe",
        target_edge="one edge",
        kind=ActionKind.EVIDENCE_PROBE,
        expected_information_gain=2,
        cost=ClosureCost.COST_1,
        risk=RiskClass.OFFLINE,
        exact_question="Can the edge be closed?",
        ownership_known=True,
        target_identity_known=True,
        bounded_scope=True,
        stop_condition="one pass",
    ).to_dict()


@pytest.mark.parametrize(
    "unknown_key",
    (
        "kernel_wirte",
        "kernel_writess",
        "destructive_mmioo",
        "persistent_statee",
        "arbitrary_unknown_field",
    ),
)
def test_evidence_action_rejects_unknown_safety_fields(unknown_key: str):
    data = _serialized_action()
    data[unknown_key] = True

    with pytest.raises(ValueError, match=unknown_key):
        EvidenceAction.from_dict(data)


def test_evidence_action_accepts_known_kernel_write_field():
    data = _serialized_action()
    data["kernel_write"] = True

    restored = EvidenceAction.from_dict(data)

    assert restored.kernel_write is True


def test_research_lead_and_nested_budget_reject_unknown_fields():
    lead = ResearchLead(
        lead_id="CLOSED-SCHEMA",
        origin="test",
        root="root",
        source="source",
        sink="sink",
        hardware_class=HardwareSinkClass.HOST_ONLY,
        user_influence=UserInfluence.UNKNOWN,
        candidate_invariant="invariant",
        known_edges=("known",),
        unknown_edges=("unknown",),
        evidence=("evidence",),
        observable="observable",
        persistence_risk="NONE",
        runtime_requirements=(),
        risk_class=RiskClass.OFFLINE,
        status=LeadStatus.DISCOVERED,
        control_score=1,
        sink_score=1,
        gap_score=1,
        edge_distance=EdgeDistance.EDGE_1,
        closure_cost=ClosureCost.COST_1,
        evidence_value=1,
        lead_score=0,
    )
    unknown_lead = {**lead.to_dict(), "unknown_nested_field": True}
    with pytest.raises(ValueError, match="unknown_nested_field"):
        ResearchLead.from_dict(unknown_lead)

    unknown_budget = lead.to_dict()
    unknown_budget["budget"] = {**unknown_budget["budget"], "proofs": 1}
    with pytest.raises(ValueError, match="proofs"):
        ResearchLead.from_dict(unknown_budget)
