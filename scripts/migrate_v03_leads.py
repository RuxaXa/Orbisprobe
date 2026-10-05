#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from orbisprobe.leads.audit import (
    historical_replay,
    legacy_audit,
    legacy_audit_markdown,
)
from orbisprobe.leads.migration import (
    current_reference_leads,
    migrate_v5_parked,
    regression_reference_leads,
)
from orbisprobe.leads.safe_io import (
    capture_protected_sources,
    preflight_output_targets,
    prepare_output_directory,
    safe_atomic_write_text,
    verify_protected_sources,
)
from orbisprobe.leads.scheduler import ResearchScheduler
from orbisprobe.leads.scoring import rank_leads
from orbisprobe.leads.store import LeadStore


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def rows(leads, *, include_inactive: bool, top: int) -> list[dict]:
    scheduler = ResearchScheduler(tuple(leads))
    ranked = (
        rank_leads(tuple(leads), include_inactive=True)
        if include_inactive
        else scheduler.ranked_active()
    )[:top]
    output = []
    for index, lead in enumerate(ranked, 1):
        action = scheduler.next_action(lead)
        output.append(
            {
                "rank": index,
                "lead": lead.lead_id,
                "status": lead.status.value,
                "control": lead.control_score,
                "sink": lead.sink_score,
                "gap": lead.gap_score,
                "edge": lead.edge_distance.value,
                "cost": lead.closure_cost.value,
                "information_gain": action.expected_information_gain if action else 0,
                "score": lead.lead_score,
                "next_action": action.action if action else "NONE",
            }
        )
    return output


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--p1", required=True)
    parser.add_argument("--p2", required=True)
    parser.add_argument("--out-dir", required=True)
    args = parser.parse_args()

    p1 = Path(args.p1)
    p2 = Path(args.p2)
    source_paths = tuple(
        sorted({p1.resolve(), p2.resolve(), *(path.resolve() for path in p1.parent.glob("p1-result-*.json"))})
    )
    protected_sources = capture_protected_sources(source_paths)
    source_hashes_before = {
        str(source.resolved_path): source.sha256 for source in protected_sources
    }
    output_names = (
        "leads.json",
        "v5-parked-metadata.json",
        "current-reference-leads.json",
        "regression-reference-leads.json",
        "ranked-active-top20.json",
        "ranked-portfolio-top20.json",
        "regression-ranking.json",
        "top-k-funnel.json",
        "legacy-parked-audit.json",
        "legacy-parked-audit.md",
        "historical-replay.json",
        "migration-manifest.json",
    )
    out = prepare_output_directory(args.out_dir, protected_sources)
    preflight_output_targets(out, output_names, protected_sources)

    parked = migrate_v5_parked(p1, p2)
    current = current_reference_leads()
    regression = regression_reference_leads()
    all_store = LeadStore(parked + current).score_all()
    parked_store = LeadStore(parked).score_all()
    current_store = LeadStore(current).score_all()
    regression_store = LeadStore(regression).score_all()

    all_store.save(
        out / "leads.json", output_root=out, protected_sources=protected_sources
    )
    parked_store.save(
        out / "v5-parked-metadata.json",
        output_root=out,
        protected_sources=protected_sources,
    )
    current_store.save(
        out / "current-reference-leads.json",
        output_root=out,
        protected_sources=protected_sources,
    )
    regression_store.save(
        out / "regression-reference-leads.json",
        output_root=out,
        protected_sources=protected_sources,
    )

    safe_atomic_write_text(
        out / "ranked-active-top20.json",
        json.dumps(rows(all_store.leads, include_inactive=False, top=20), indent=2) + "\n",
        output_root=out,
        protected_sources=protected_sources,
    )
    safe_atomic_write_text(
        out / "ranked-portfolio-top20.json",
        json.dumps(rows(all_store.leads, include_inactive=True, top=20), indent=2) + "\n",
        output_root=out,
        protected_sources=protected_sources,
    )
    regression_rows = rows(regression_store.leads, include_inactive=True, top=20)
    safe_atomic_write_text(
        out / "regression-ranking.json",
        json.dumps(regression_rows, indent=2) + "\n",
        output_root=out,
        protected_sources=protected_sources,
    )
    funnel = ResearchScheduler(all_store.leads).funnel()
    safe_atomic_write_text(
        out / "top-k-funnel.json",
        json.dumps(funnel, indent=2, sort_keys=True) + "\n",
        output_root=out,
        protected_sources=protected_sources,
    )
    audit = legacy_audit(parked_store.leads)
    safe_atomic_write_text(
        out / "legacy-parked-audit.json",
        json.dumps(audit, indent=2, sort_keys=True) + "\n",
        output_root=out,
        protected_sources=protected_sources,
    )
    safe_atomic_write_text(
        out / "legacy-parked-audit.md",
        legacy_audit_markdown(audit),
        output_root=out,
        protected_sources=protected_sources,
    )

    replay = historical_replay(
        parked_store.leads, current_store.leads, regression_store.leads
    )
    safe_atomic_write_text(
        out / "historical-replay.json",
        json.dumps(replay, indent=2, sort_keys=True) + "\n",
        output_root=out,
        protected_sources=protected_sources,
    )

    verify_protected_sources(protected_sources)
    source_hashes_after = {str(path): sha256(path) for path in source_paths}
    sources_unchanged = source_hashes_before == source_hashes_after
    if not sources_unchanged:
        raise RuntimeError("source evidence changed during migration")

    manifest = {
        "schema": "orbisprobe-v03-migration-v1",
        "sources": source_hashes_before,
        "counts": {
            "v5_parked": len(parked),
            "current_reference": len(current),
            "total": len(all_store.leads),
            "active": len(rank_leads(all_store.leads)),
            "regression": len(regression),
        },
        "funnel": funnel,
        "legacy_audit": audit["summary"],
        "historical_replay": replay,
        "integrity": {
            "old_evidence_modified": not sources_unchanged,
            "metadata_only_for_v5": sources_unchanged,
            "backward_compatible_source_files": sources_unchanged,
        },
        "regressions": {
            "gc_above_rc001": regression_rows[0]["lead"] == "GC-A-PRE-CLOSURE",
            "rc001_edge": next(row["edge"] for row in regression_rows if row["lead"] == "RC-001-REGRESSION"),
            "sec_artifact_blocked": next(lead.edge_distance.value for lead in current if lead.lead_id == "SEC-TAG1-TAG9"),
        },
        "completion_marker": "ORBISPROBE_V03_MIGRATION_COMPLETE",
    }
    safe_atomic_write_text(
        out / "migration-manifest.json",
        json.dumps(manifest, indent=2, sort_keys=True) + "\n",
        output_root=out,
        protected_sources=protected_sources,
    )
    print(json.dumps(manifest, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
