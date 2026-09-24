from __future__ import annotations

from collections import Counter

from orbisprobe.leads.audit import (
    historical_replay,
    legacy_audit,
    legacy_audit_markdown,
)
from orbisprobe.leads.migration import (
    current_reference_leads,
    regression_reference_leads,
)
from orbisprobe.leads.model import LeadStatus
from orbisprobe.leads.scoring import is_active


def test_legacy_audit_covers_all_104_with_required_fields():
    from orbisprobe.leads.migration import migrate_v5_parked

    base = "/home/hermes/audits/ps4b-soc-workbench/campaign-20260923/restart-v5"
    leads = migrate_v5_parked(f"{base}/AGGREGATE.json", f"{base}/p2-rest.json")

    audit = legacy_audit(leads)

    assert audit["summary"] == {
        "legacy_parked_total": 104,
        "edge_0": 0,
        "edge_1": 1,
        "edge_2": 1,
        "edge_3plus": 101,
        "artifact_blocked": 0,
        "safe_disproved": 0,
        "downgraded": 1,
        "active": 2,
    }
    assert len(audit["records"]) == 104
    required = {
        "lead",
        "legacy_status",
        "v0.3_edge",
        "v0.3_cost",
        "v0.3_status",
        "active",
        "reason",
        "control_score",
        "sink_score",
        "gap_score",
        "decisive_unknown_edges",
        "cheapest_closure_action",
        "expected_information_gain",
        "hardware_relevance",
        "artifact_requirements",
    }
    assert all(required <= set(row) for row in audit["records"])
    assert all(row["legacy_status"] == "PARKED" for row in audit["records"])
    assert Counter(row["active"] for row in audit["records"]) == {False: 102, True: 2}
    markdown = legacy_audit_markdown(audit)
    for expected in (
        "EDGE-1: 1",
        "EDGE-2: 1",
        "EDGE-3PLUS: 101",
        "DOWNGRADED: 1",
        "Active: 2",
    ):
        assert expected in markdown


def test_historical_replay_records_gc_promotion_then_soc3_removal():
    from orbisprobe.leads.migration import migrate_v5_parked

    base = "/home/hermes/audits/ps4b-soc-workbench/campaign-20260923/restart-v5"
    legacy = migrate_v5_parked(f"{base}/AGGREGATE.json", f"{base}/p2-rest.json")
    current = current_reference_leads()
    regressions = regression_reference_leads()

    replay = historical_replay(legacy, current, regressions)

    assert replay["legacy_immediate_edge3plus"] == 101
    assert replay["legacy_received_closure_budget"] == 2
    assert replay["gc_preclosure_ranked_above_rc001"] is True
    assert replay["gc_after_soc3_status"] == LeadStatus.DOWNGRADED.value
    assert "GC-RING-SIZES" not in replay["leads_scoring_above_rc001"]
    gc_closed = next(lead for lead in current if lead.lead_id == "GC-RING-SIZES")
    assert is_active(gc_closed) is False
