from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from orbisprobe.leads.safe_io import (
    capture_protected_sources,
    preflight_output_targets,
    prepare_output_directory,
    safe_atomic_write_bytes,
    safe_atomic_write_text,
    verify_protected_sources,
)
from orbisprobe.leads.store import LeadStore

from .journal import ActionJournal
from .manifest import build_manifest, manifest_sha256, render_manifest
from .metrics import compute_metrics, portfolio_snapshot
from .model import ClaimTrace, Metrics, canonical_json, sha256_file
from .plan import ActionPlan

SCHEMA = "orbisprobe-evidence-pass-v1"


@dataclass(frozen=True)
class BuildResult:
    package_dir: str
    sha256sums_sha256: str
    artifacts: int
    metrics: Metrics
    portfolio: dict[str, int]
    source_integrity: bool
    shared_records: tuple[dict[str, Any], ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": SCHEMA,
            "status": "EVIDENCE_PASS_BUILT",
            "package": self.package_dir,
            "sha256sums_sha256": self.sha256sums_sha256,
            "artifacts": self.artifacts,
            "metrics": self.metrics.to_dict(),
            "portfolio": dict(self.portfolio),
            "source_integrity": self.source_integrity,
            "shared_evidence": [dict(item) for item in self.shared_records],
        }


def _source_manifest(protected: Sequence[Any]) -> dict[str, Any]:
    return {
        "sources": [
            {
                "path": str(source.resolved_path),
                "device": source.device,
                "inode": source.inode,
                "sha256": source.sha256,
            }
            for source in protected
        ]
    }


def build_pass(
    *,
    plan: ActionPlan,
    journal: ActionJournal,
    leads_before: LeadStore,
    leads_final: LeadStore,
    out_dir: str | Path | None = None,
    evidence: Mapping[str, str | Path] | None = None,
    claims: Sequence[ClaimTrace] = (),
    copy_events: Sequence[Mapping[str, Any]] = (),
    shared_records: Sequence[Mapping[str, Any]] = (),
) -> BuildResult:
    """Write a deterministic pass package.

    Every write goes through the hardened v0.3 safe-I/O primitives: the output root is
    refused when it overlaps source evidence or traverses a symlink, and each leaf is
    written via temp file -> exclusive/no-follow -> fsync -> revalidate -> atomic replace.
    """

    evidence_inputs = {name: Path(path) for name, path in (evidence or {}).items()}
    protected = capture_protected_sources([*plan.protected_sources, *evidence_inputs.values()])
    root = prepare_output_directory(out_dir or plan.output_dir, protected)
    for subdirectory in ("action-results", "evidence"):
        prepare_output_directory(root / subdirectory, protected)

    targets = [
        "action-plan.json",
        "action-journal.json",
        "leads-before.json",
        "leads-final.json",
        "source-manifest.json",
        "claims.json",
        "copy-events.json",
        "metrics.json",
        "campaign-summary.json",
        "SHA256SUMS",
    ]
    targets += [f"action-results/{action_id}.json" for action_id in plan.action_ids]
    targets += [f"evidence/{name}" for name in sorted(evidence_inputs)]
    preflight_output_targets(root, targets, protected)

    def write_json(relative: str, value: object) -> None:
        safe_atomic_write_text(root / relative, canonical_json(value), output_root=root, protected_sources=protected)

    write_json("action-plan.json", plan.to_dict())
    write_json("action-journal.json", journal.to_dict())

    for record in journal.records():
        write_json(f"action-results/{record.action_id}.json", record.to_dict())

    safe_atomic_write_text(root / "leads-before.json", leads_before.to_json(), output_root=root, protected_sources=protected)
    safe_atomic_write_text(root / "leads-final.json", leads_final.to_json(), output_root=root, protected_sources=protected)
    write_json("source-manifest.json", _source_manifest(protected))
    write_json("claims.json", {"claims": [claim.to_dict() for claim in claims]})
    write_json("copy-events.json", {"copies": [dict(item) for item in copy_events]})

    for name, source_path in sorted(evidence_inputs.items()):
        safe_atomic_write_bytes(
            root / "evidence" / name,
            source_path.read_bytes(),
            output_root=root,
            protected_sources=protected,
        )

    # Source evidence must be provably unchanged before the pass is declared built.
    verify_protected_sources(protected)
    portfolio = portfolio_snapshot(leads_final)
    metrics = compute_metrics(
        plan=plan,
        journal=journal,
        leads_before=leads_before,
        leads_final=leads_final,
        source_integrity=True,
    )

    write_json("metrics.json", metrics.to_dict())
    write_json(
        "campaign-summary.json",
        {
            "schema": SCHEMA,
            "plan_id": plan.plan_id,
            "status": "EVIDENCE_PASS_BUILT",
            "actions_expected": plan.expected_action_count,
            "actions_executed": metrics.actions_executed,
            "action_results": [
                {
                    "action_id": record.action_id,
                    "lead_id": record.lead_id,
                    "status": record.status.value,
                    "result": record.outcome.result.value if record.outcome else None,
                    "disposition": record.outcome.disposition.value if record.outcome else None,
                    "evidence": list(record.outcome.evidence) if record.outcome else [],
                }
                for record in journal.records()
            ],
            "portfolio": portfolio,
            "expected_portfolio": {key: value for key, value in plan.expected_portfolio},
            "expected_unchanged_leads": list(plan.expected_unchanged_leads),
            "shared_evidence": [dict(item) for item in shared_records],
            "metrics": metrics.to_dict(),
            "review_mode": plan.review_mode.value,
            "stop": True,
        },
    )

    entries = build_manifest(root)
    safe_atomic_write_text(
        root / "SHA256SUMS",
        render_manifest(entries),
        output_root=root,
        protected_sources=protected,
    )
    verify_protected_sources(protected)
    assert manifest_sha256(root)
    return BuildResult(
        package_dir=str(root),
        sha256sums_sha256=manifest_sha256(root),
        artifacts=len(entries),
        metrics=metrics,
        portfolio=portfolio,
        source_integrity=True,
        shared_records=tuple(dict(item) for item in shared_records),
    )


def package_digest(path: str | Path) -> str:
    return sha256_file(Path(path))
