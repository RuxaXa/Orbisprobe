from __future__ import annotations

import json
from pathlib import Path

from orbisprobe.analysis import HardwareSinkClass, UserInfluence
from orbisprobe.cli import main
from orbisprobe.leads.migration import current_reference_leads
from orbisprobe.leads.model import (
    ActionKind,
    ClosureCost,
    EdgeDistance,
    EvidenceAction,
    LeadBudget,
    LeadStatus,
    ResearchLead,
)
from orbisprobe.leads.store import LeadStore
from orbisprobe.schema import RiskClass


def _lead(lead_id: str, edge: EdgeDistance, status: LeadStatus) -> ResearchLead:
    unknown = {
        EdgeDistance.EDGE_0: (),
        EdgeDistance.EDGE_1: ("missing",),
        EdgeDistance.EDGE_2: ("missing-a", "missing-b"),
        EdgeDistance.EDGE_3PLUS: ("missing-a", "missing-b", "missing-c"),
        EdgeDistance.ARTIFACT_BLOCKED: ("missing-artifact",),
    }[edge]
    action = EvidenceAction(
        action_id=f"{lead_id}-action",
        action="resolve edge",
        target_edge="missing",
        kind=ActionKind.EVIDENCE_PROBE,
        expected_information_gain=4,
        cost=ClosureCost.COST_1,
        risk=RiskClass.OFFLINE,
        exact_question="Does the edge exist?",
        ownership_known=True,
        target_identity_known=True,
        bounded_scope=True,
        stop_condition="one pass",
    )
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
        evidence_actions=(action,),
        budget=LeadBudget(1, 4, 6),
    )


def test_leads_rank_next_show_and_action_cli(tmp_path: Path, capsys):
    store_path = tmp_path / "leads.json"
    LeadStore(
        (
            _lead("EDGE2", EdgeDistance.EDGE_2, LeadStatus.CLOSURE_PENDING),
            _lead("EDGE1", EdgeDistance.EDGE_1, LeadStatus.CLOSURE_PENDING),
        )
    ).save(store_path)

    assert main(["leads", "rank", str(store_path), "--top", "2", "--json"]) == 0
    ranking = json.loads(capsys.readouterr().out)
    assert [row["lead"] for row in ranking] == ["EDGE1", "EDGE2"]
    assert set(ranking[0]) >= {
        "rank",
        "lead",
        "control",
        "sink",
        "gap",
        "edge",
        "cost",
        "information_gain",
        "score",
        "next_action",
    }

    assert main(["leads", "next", str(store_path), "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["lead_id"] == "EDGE1"

    assert main(["leads", "show", str(store_path), "EDGE2", "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["lead_id"] == "EDGE2"

    assert main(["leads", "action", str(store_path), "EDGE1", "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["action_id"] == "EDGE1-action"


def test_leads_scan_score_and_rehydrate_cli(tmp_path: Path, capsys):
    parked = _lead("PARKED", EdgeDistance.EDGE_3PLUS, LeadStatus.PARKED)
    parked = ResearchLead.from_dict(
        {
            **parked.to_dict(),
            "unknown_edges": ["user-binding", "writer", "consumer"],
        }
    )
    raw = tmp_path / "raw.json"
    canonical = tmp_path / "canonical.json"
    scored = tmp_path / "scored.json"
    evidence = tmp_path / "evidence.json"
    rehydrated = tmp_path / "rehydrated.json"
    LeadStore((parked,)).save(raw)

    assert main(["leads", "scan", str(raw), "--out", str(canonical)]) == 0
    capsys.readouterr()
    assert main(["leads", "score", str(canonical), "--out", str(scored)]) == 0
    capsys.readouterr()
    assert LeadStore.load(scored).leads[0].lead_score != 0

    evidence.write_text(
        json.dumps({"lead_id": "PARKED", "resolved_edges": ["writer"]}),
        encoding="utf-8",
    )
    assert (
        main(
            [
                "leads",
                "rehydrate",
                str(scored),
                str(evidence),
                "--out",
                str(rehydrated),
            ]
        )
        == 0
    )
    capsys.readouterr()
    lead = LeadStore.load(rehydrated).get("PARKED")
    assert lead.status is LeadStatus.CLOSURE_PENDING
    assert lead.edge_distance is EdgeDistance.EDGE_2


def test_rehydrate_cli_rejects_truthy_non_boolean_artifact_availability(
    tmp_path: Path, capsys
):
    store_path = tmp_path / "leads.json"
    evidence = tmp_path / "evidence.json"
    out = tmp_path / "out.json"
    LeadStore(current_reference_leads()).score_all().save(store_path)

    for malformed in ("false", 0, 1, [], {}):
        evidence.write_text(
            json.dumps(
                {
                    "lead_id": "SEC-TAG1-TAG9",
                    "resolved_edges": [],
                    "artifact_available": malformed,
                }
            ),
            encoding="utf-8",
        )
        assert (
            main(
                [
                    "leads",
                    "rehydrate",
                    str(store_path),
                    str(evidence),
                    "--out",
                    str(out),
                ]
            )
            == 1
        )
        assert "artifact_available" in capsys.readouterr().err


def test_rehydrate_cli_rejects_unknown_evidence_fields(tmp_path: Path, capsys):
    store_path = tmp_path / "leads.json"
    evidence = tmp_path / "evidence.json"
    out = tmp_path / "out.json"
    LeadStore(current_reference_leads()).score_all().save(store_path)
    evidence.write_text(
        json.dumps(
            {
                "lead_id": "SEC-TAG1-TAG9",
                "resolved_edges": [],
                "artifact_available": False,
                "artifact_availabl": True,
            }
        ),
        encoding="utf-8",
    )

    assert main(
        [
            "leads",
            "rehydrate",
            str(store_path),
            str(evidence),
            "--out",
            str(out),
        ]
    ) == 1
    assert "artifact_availabl" in capsys.readouterr().err
