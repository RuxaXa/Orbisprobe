from __future__ import annotations

import hashlib
import os
from collections import Counter
from pathlib import Path

import pytest

from orbisprobe.leads import migration as migration_module
from orbisprobe.leads.migration import (
    current_reference_leads,
    migrate_v5_parked,
    regression_reference_leads,
)
from orbisprobe.leads.model import ClosureCost, EdgeDistance, LeadStatus
from orbisprobe.leads.safe_io import (
    capture_protected_sources,
    preflight_output_targets,
    prepare_output_directory,
    safe_atomic_write_text,
    verify_protected_sources,
)
from orbisprobe.leads.scheduler import ResearchScheduler
from orbisprobe.leads.scoring import rank_leads

V5 = Path("/home/hermes/audits/ps4b-soc-workbench/campaign-20260923/restart-v5")


def test_v5_migration_creates_exactly_104_metadata_only_parked_records():
    leads = migrate_v5_parked(V5 / "AGGREGATE.json", V5 / "p2-rest.json")

    assert len(leads) == 104
    assert all(lead.legacy_status == "PARKED" for lead in leads)

    distribution = Counter(
        (
            "INACTIVE"
            if lead.status in {LeadStatus.DOWNGRADED, LeadStatus.DISPROVED, LeadStatus.SAFE_INVARIANT}
            else lead.edge_distance.value
        )
        for lead in leads
    )
    assert distribution == {
        "EDGE-1": 1,
        "EDGE-2": 1,
        "EDGE-3PLUS": 101,
        "INACTIVE": 1,
    }

    active = {lead.root: lead for lead in leads if lead.status is LeadStatus.CLOSURE_PENDING}
    assert set(active) == {"0xffffffffd016efa0", "0xffffffffd0568e10"}
    assert active["0xffffffffd016efa0"].edge_distance is EdgeDistance.EDGE_2
    assert active["0xffffffffd016efa0"].closure_cost is ClosureCost.COST_2
    assert active["0xffffffffd0568e10"].edge_distance is EdgeDistance.EDGE_1
    assert active["0xffffffffd0568e10"].closure_cost is ClosureCost.COST_2
    inactive = next(lead for lead in leads if lead.status is LeadStatus.DOWNGRADED)
    assert inactive.budget.discovery == inactive.budget.closure == inactive.budget.proof == 0

    rc001 = next(lead for lead in leads if lead.lead_id == "RC-001")
    assert rc001.edge_distance is EdgeDistance.EDGE_3PLUS
    assert set(rc001.unknown_edges) >= {
        "user-binding",
        "writer-source",
        "dispatch-closure",
    }


def test_current_reference_leads_keep_sec_artifact_blocked_and_address_lead_separate():
    leads = {lead.lead_id: lead for lead in current_reference_leads()}

    assert leads["SEC-TAG1-TAG9"].status is LeadStatus.ARTIFACT_BLOCKED
    assert leads["SEC-TAG1-TAG9"].edge_distance is EdgeDistance.ARTIFACT_BLOCKED
    assert leads["SEC-TAG1-TAG9"].budget.closure == 0
    assert leads["GC-ADDRESS-LEAD"].status is LeadStatus.CLOSURE_PENDING
    assert leads["GC-ADDRESS-LEAD"].edge_distance is EdgeDistance.EDGE_2
    assert leads["GC-RING-SIZES"].status is LeadStatus.DOWNGRADED
    assert leads["GC-RING-SIZES"].budget.proof == 0


def test_gc_preclosure_regression_ranks_above_rc001_reference():
    gc, rc001 = regression_reference_leads()
    ranked = rank_leads([rc001, gc], include_inactive=True)

    assert ranked[0].lead_id == "GC-A-PRE-CLOSURE"
    assert ranked[1].lead_id == "RC-001-REGRESSION"


def test_final_active_ranking_includes_reclassified_legacy_leads():
    legacy = migrate_v5_parked(V5 / "AGGREGATE.json", V5 / "p2-rest.json")
    ranked = ResearchScheduler(legacy + current_reference_leads()).ranked_active()

    assert [lead.lead_id for lead in ranked] == [
        "GC-ADDRESS-LEAD",
        "GC-HQD-EXTENT-OWNERSHIP",
        "GC-PM4-IB-OWNERSHIP",
        "GPUVM-PARTIAL-MAP-GENERIC",
        "V5-P1-0393feccbbfc",
        "V5-P1-f46436a63b78",
    ]
    assert all(lead.lead_id != "RC-001" for lead in ranked)
    assert all(lead.lead_id != "SEC-TAG1-TAG9" for lead in ranked)
    assert all(lead.lead_id != "GC-RING-SIZES" for lead in ranked)


def test_legacy_detail_paths_cannot_escape_evidence_directory(tmp_path: Path):
    outside = tmp_path / "outside.json"
    outside.write_text('{"records": []}', encoding="utf-8")
    base = tmp_path / "evidence"
    base.mkdir()

    with pytest.raises(ValueError, match="escapes evidence directory"):
        migration_module._load_p1_details(
            base,
            [{"source_file": "../outside.json"}],
        )


def test_migration_output_must_be_separate_from_source_evidence(tmp_path: Path):
    source_dir = tmp_path / "evidence"
    source_dir.mkdir()
    source = source_dir / "AGGREGATE.json"
    source.write_text("{}", encoding="utf-8")
    alias = tmp_path / "alias"
    alias.symlink_to(source_dir, target_is_directory=True)

    for unsafe in (source_dir, source_dir / "generated", alias / "generated"):
        with pytest.raises(ValueError, match="overlaps source evidence"):
            migration_module.validate_output_separation(unsafe, (source,))

    safe = tmp_path / "separate-output"
    assert migration_module.validate_output_separation(safe, (source,)) == safe.resolve()


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_output_leaf_symlink_is_rejected_before_source_modification(tmp_path: Path):
    source_dir = tmp_path / "source"
    source_dir.mkdir()
    source = source_dir / "AGGREGATE.json"
    source.write_text("source evidence", encoding="utf-8")
    before = _sha256(source)
    protected = capture_protected_sources((source,))
    output = prepare_output_directory(tmp_path / "out", protected)
    (output / "leads.json").symlink_to(source)

    with pytest.raises(ValueError, match="symlink"):
        preflight_output_targets(output, ("leads.json",), protected)

    assert _sha256(source) == before
    verify_protected_sources(protected)


def test_output_directory_symlink_to_source_is_rejected(tmp_path: Path):
    source_dir = tmp_path / "source"
    source_dir.mkdir()
    source = source_dir / "AGGREGATE.json"
    source.write_text("source evidence", encoding="utf-8")
    before = _sha256(source)
    protected = capture_protected_sources((source,))
    alias = tmp_path / "out"
    alias.symlink_to(source_dir, target_is_directory=True)

    with pytest.raises(ValueError, match="symlink|overlaps source evidence"):
        prepare_output_directory(alias, protected)

    assert _sha256(source) == before
    verify_protected_sources(protected)


def test_nested_output_path_through_symlink_parent_is_rejected(tmp_path: Path):
    source_dir = tmp_path / "source"
    source_dir.mkdir()
    source = source_dir / "AGGREGATE.json"
    source.write_text("source evidence", encoding="utf-8")
    before = _sha256(source)
    protected = capture_protected_sources((source,))
    output = prepare_output_directory(tmp_path / "out", protected)
    (output / "nested").symlink_to(source_dir, target_is_directory=True)

    with pytest.raises(ValueError, match="symlink"):
        preflight_output_targets(output, ("nested/leads.json",), protected)

    assert _sha256(source) == before
    verify_protected_sources(protected)


def test_hardlink_output_leaf_to_source_is_rejected(tmp_path: Path):
    source_dir = tmp_path / "source"
    source_dir.mkdir()
    source = source_dir / "AGGREGATE.json"
    source.write_text("source evidence", encoding="utf-8")
    before = _sha256(source)
    protected = capture_protected_sources((source,))
    output = prepare_output_directory(tmp_path / "out", protected)
    try:
        os.link(source, output / "leads.json")
    except OSError as exc:
        pytest.skip(f"hardlinks unsupported: {exc}")

    with pytest.raises(ValueError, match="source evidence"):
        preflight_output_targets(output, ("leads.json",), protected)

    assert _sha256(source) == before
    verify_protected_sources(protected)


def test_safe_atomic_write_succeeds_in_clean_output_directory(tmp_path: Path):
    source_dir = tmp_path / "source"
    source_dir.mkdir()
    source = source_dir / "source.json"
    source.write_text("source evidence", encoding="utf-8")
    protected = capture_protected_sources((source,))
    output = prepare_output_directory(tmp_path / "out", protected)
    preflight_output_targets(output, ("leads.json",), protected)

    safe_atomic_write_text(
        output / "leads.json",
        "new metadata\n",
        output_root=output,
        protected_sources=protected,
    )

    assert (output / "leads.json").read_text(encoding="utf-8") == "new metadata\n"
    verify_protected_sources(protected)


def test_safe_atomic_write_replaces_existing_ordinary_file(tmp_path: Path):
    source_dir = tmp_path / "source"
    source_dir.mkdir()
    source = source_dir / "source.json"
    source.write_text("source evidence", encoding="utf-8")
    protected = capture_protected_sources((source,))
    output = prepare_output_directory(tmp_path / "out", protected)
    target = output / "leads.json"
    target.write_text("old metadata", encoding="utf-8")
    old_inode = target.stat().st_ino
    preflight_output_targets(output, ("leads.json",), protected)

    safe_atomic_write_text(
        target,
        "replacement metadata\n",
        output_root=output,
        protected_sources=protected,
    )

    assert target.read_text(encoding="utf-8") == "replacement metadata\n"
    assert target.stat().st_ino != old_inode
    verify_protected_sources(protected)
