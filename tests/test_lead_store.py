from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path

import pytest

from orbisprobe.analysis import HardwareSinkClass, UserInfluence
from orbisprobe.leads.model import (
    ClosureCost,
    EdgeDistance,
    LeadBudget,
    LeadStatus,
    OperationMode,
    ResearchLead,
)
from orbisprobe.leads.store import LeadStore
from orbisprobe.schema import RiskClass


def _lead(lead_id: str, edge: EdgeDistance, status: LeadStatus) -> ResearchLead:
    unknown = {
        EdgeDistance.EDGE_0: (),
        EdgeDistance.EDGE_1: ("unknown",),
        EdgeDistance.EDGE_2: ("unknown-a", "unknown-b"),
        EdgeDistance.EDGE_3PLUS: ("unknown-a", "unknown-b", "unknown-c"),
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
        budget=LeadBudget(1, 2, 3),
    )


def test_lead_store_roundtrip_scores_and_preserves_schema(tmp_path: Path):
    path = tmp_path / "leads.json"
    store = LeadStore((_lead("A", EdgeDistance.EDGE_1, LeadStatus.DISCOVERED),))

    scored = store.score_all()
    scored.save(path)
    restored = LeadStore.load(path)

    assert restored.schema == "orbisprobe-research-leads-v1"
    assert restored.leads[0].status is LeadStatus.CLOSURE_PENDING
    assert restored.leads[0].lead_score == 54
    assert restored.to_dict() == scored.to_dict()


def test_canonical_store_rejects_status_that_conflicts_with_activation_policy():
    weak = replace(
        _lead("WEAK", EdgeDistance.EDGE_2, LeadStatus.CLOSURE_PENDING),
        control_score=1,
        sink_score=1,
        gap_score=1,
        evidence_value=1,
        closure_cost=ClosureCost.COST_3,
    )

    with pytest.raises(ValueError, match="activation policy"):
        LeadStore((weak,))

    closure_in_proof = replace(
        _lead("MODE", EdgeDistance.EDGE_1, LeadStatus.CLOSURE_PENDING),
        mode=OperationMode.PROOF_MODE,
    )
    with pytest.raises(ValueError, match="activation policy"):
        LeadStore((closure_in_proof,))

    with pytest.raises(ValueError, match="COST-BLOCKED"):
        replace(
            _lead("COST", EdgeDistance.EDGE_1, LeadStatus.DISCOVERED),
            closure_cost=ClosureCost.COST_BLOCKED,
        )


def test_lead_store_rejects_unknown_top_level_fields(tmp_path: Path):
    path = tmp_path / "leads.json"
    value = LeadStore((_lead("A", EdgeDistance.EDGE_1, LeadStatus.DISCOVERED),)).to_dict()
    value["unexpected"] = True
    path.write_text(json.dumps(value), encoding="utf-8")

    with pytest.raises(ValueError, match="unexpected"):
        LeadStore.load(path)
