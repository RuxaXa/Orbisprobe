from __future__ import annotations

from typing import Any

from .model import EdgeDistance, LeadStatus, ResearchLead
from .scheduler import ResearchScheduler
from .scoring import is_active, rank_leads

INACTIVE_CLOSED = {
    LeadStatus.SAFE_INVARIANT,
    LeadStatus.DISPROVED,
    LeadStatus.DOWNGRADED,
}


def legacy_audit(leads: tuple[ResearchLead, ...] | list[ResearchLead]) -> dict[str, Any]:
    records = []
    for lead in sorted(leads, key=lambda item: item.lead_id):
        action = ResearchScheduler([lead]).next_action(lead)
        records.append(
            {
                "lead": lead.lead_id,
                "legacy_status": lead.legacy_status,
                "v0.3_edge": lead.edge_distance.value,
                "v0.3_cost": lead.closure_cost.value,
                "v0.3_status": lead.status.value,
                "active": is_active(lead),
                "reason": lead.candidate_invariant,
                "control_score": lead.control_score,
                "sink_score": lead.sink_score,
                "gap_score": lead.gap_score,
                "decisive_unknown_edges": list(lead.unknown_edges),
                "cheapest_closure_action": action.action if action else "NONE",
                "expected_information_gain": (
                    action.expected_information_gain if action else 0
                ),
                "hardware_relevance": lead.hardware_class.value,
                "artifact_requirements": list(lead.runtime_requirements),
            }
        )

    active_edges = [lead.edge_distance for lead in leads if lead.status not in INACTIVE_CLOSED]
    summary = {
        "legacy_parked_total": len(leads),
        "edge_0": active_edges.count(EdgeDistance.EDGE_0),
        "edge_1": active_edges.count(EdgeDistance.EDGE_1),
        "edge_2": active_edges.count(EdgeDistance.EDGE_2),
        "edge_3plus": active_edges.count(EdgeDistance.EDGE_3PLUS),
        "artifact_blocked": active_edges.count(EdgeDistance.ARTIFACT_BLOCKED),
        "safe_disproved": sum(
            lead.status in {LeadStatus.SAFE_INVARIANT, LeadStatus.DISPROVED}
            for lead in leads
        ),
        "downgraded": sum(lead.status is LeadStatus.DOWNGRADED for lead in leads),
        "active": sum(is_active(lead) for lead in leads),
    }
    return {
        "schema": "orbisprobe-v03-legacy-parked-audit-v1",
        "summary": summary,
        "records": records,
        "completion_marker": "LEGACY_PARKED_AUDIT_COMPLETE",
    }


def legacy_audit_markdown(audit: dict[str, Any]) -> str:
    summary = audit["summary"]
    lines = [
        "# Legacy PARKED → v0.3 migration audit",
        "",
        f"Legacy PARKED total: {summary['legacy_parked_total']}",
        f"EDGE-0: {summary['edge_0']}",
        f"EDGE-1: {summary['edge_1']}",
        f"EDGE-2: {summary['edge_2']}",
        f"EDGE-3PLUS: {summary['edge_3plus']}",
        f"ARTIFACT_BLOCKED: {summary['artifact_blocked']}",
        f"SAFE/DISPROVED: {summary['safe_disproved']}",
        f"DOWNGRADED: {summary['downgraded']}",
        f"Active: {summary['active']}",
        "",
        "| lead | legacy_status | v0.3_edge | v0.3_cost | v0.3_status | active? | reason |",
        "|---|---|---|---|---|---|---|",
    ]
    for row in audit["records"]:
        reason = row["reason"].replace("|", "\\|").replace("\n", " ")
        lines.append(
            f"| {row['lead']} | {row['legacy_status']} | {row['v0.3_edge']} | "
            f"{row['v0.3_cost']} | {row['v0.3_status']} | "
            f"{str(row['active']).lower()} | {reason} |"
        )
    return "\n".join(lines) + "\n"


def historical_replay(
    legacy: tuple[ResearchLead, ...] | list[ResearchLead],
    current: tuple[ResearchLead, ...] | list[ResearchLead],
    regressions: tuple[ResearchLead, ...] | list[ResearchLead],
) -> dict[str, Any]:
    regression_ranking = rank_leads(regressions, include_inactive=True)
    current_ranking = rank_leads(current)
    rc = next(lead for lead in legacy if lead.lead_id == "RC-001")
    gc_closed = next(lead for lead in current if lead.lead_id == "GC-RING-SIZES")
    earlier_than_rc = [
        lead.lead_id
        for lead in rank_leads(tuple(current) + tuple(legacy))
        if lead.lead_score > rank_leads([rc], include_inactive=True)[0].lead_score
    ]
    return {
        "schema": "orbisprobe-v03-historical-replay-v1",
        "legacy_total": len(legacy),
        "legacy_immediate_edge3plus": sum(
            lead.edge_distance is EdgeDistance.EDGE_3PLUS for lead in legacy
        ),
        "legacy_received_closure_budget": sum(is_active(lead) for lead in legacy),
        "legacy_activated": [lead.lead_id for lead in rank_leads(legacy)],
        "active_current_ranking": [lead.lead_id for lead in current_ranking],
        "leads_scoring_above_rc001": earlier_than_rc,
        "gc_preclosure_ranked_above_rc001": (
            regression_ranking[0].lead_id == "GC-A-PRE-CLOSURE"
            and regression_ranking[1].lead_id == "RC-001-REGRESSION"
        ),
        "gc_preclosure_score": next(
            lead.lead_score
            for lead in regression_ranking
            if lead.lead_id == "GC-A-PRE-CLOSURE"
        ),
        "rc001_regression_score": next(
            lead.lead_score
            for lead in regression_ranking
            if lead.lead_id == "RC-001-REGRESSION"
        ),
        "gc_after_soc3_status": gc_closed.status.value,
        "gc_after_soc3_active": is_active(gc_closed),
        "conclusion": (
            "GC-A pre-closure receives early budget; SOC3 evidence converts it to "
            "DOWNGRADED and removes it from the active queue."
        ),
        "completion_marker": "HISTORICAL_REPLAY_COMPLETE",
    }
