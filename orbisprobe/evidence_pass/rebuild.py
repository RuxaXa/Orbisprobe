"""Deterministic rebuild entry points.

A pass package carries a frozen ``rebuild-pass.py`` that reconstructs every generated
artifact from inputs *outside* the package. The verifier only executes it and compares bytes,
so verification stays independent of builder logic.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from orbisprobe.leads.store import LeadStore

from .builder import BuildResult, build_pass
from .journal import ActionJournal
from .model import ActionResult, ClaimTrace, LeadDisposition
from .plan import ActionPlan
from .runner import ActionExecution, ActionFailure, run_plan


def replay_executor(results_path: str | Path):
    """Offline executor that replays recorded action results through the exact-once runner."""

    payload = json.loads(Path(results_path).read_text(encoding="utf-8"))
    records = payload.get("results") if isinstance(payload, dict) else payload
    if not isinstance(records, list):
        raise TypeError('results file must be a list or {"results": [...]}')
    table: dict[str, dict[str, Any]] = {}
    for item in records:
        if not isinstance(item, dict) or "action_id" not in item:
            raise ValueError("each result entry needs an action_id")
        if item["action_id"] in table:
            raise ValueError(f"duplicate execution result for {item['action_id']}")
        table[item["action_id"]] = item

    def executor(action, context):
        item = table.get(action.action_id)
        if item is None:
            raise ActionFailure(f"no recorded execution result for {action.action_id}")
        return ActionExecution(
            result=ActionResult(item["result"]),
            disposition=LeadDisposition(item["disposition"]),
            evidence=tuple(item.get("evidence", ())),
            notes=tuple(item.get("notes", ())),
        )

    return executor


def load_claims(path: str | Path | None) -> tuple[ClaimTrace, ...]:
    if path is None:
        return ()
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    return tuple(ClaimTrace.from_dict(item) for item in payload.get("claims", []))


def load_copy_events(path: str | Path | None) -> tuple[dict[str, Any], ...]:
    if path is None:
        return ()
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    copies = payload.get("copies", []) if isinstance(payload, dict) else payload
    return tuple(dict(item) for item in copies)


def build_from_inputs(
    *,
    plan_path: str | Path,
    results_path: str | Path,
    leads_before_path: str | Path,
    out_dir: str | Path,
    leads_final_path: str | Path | None = None,
    evidence: Mapping[str, str | Path] | None = None,
    claims_path: str | Path | None = None,
    copy_events_path: str | Path | None = None,
    journal_path: str | Path | None = None,
) -> BuildResult:
    """Rebuild a pass package from its recorded inputs (single source of truth for build+rebuild)."""

    plan = ActionPlan.load(plan_path)
    journal = (
        ActionJournal.from_dict(json.loads(Path(journal_path).read_text(encoding="utf-8")))
        if journal_path is not None
        else None
    )
    report = run_plan(plan, replay_executor(results_path), journal)
    before = LeadStore.load(leads_before_path)
    final = LeadStore.load(leads_final_path) if leads_final_path is not None else before
    return build_pass(
        plan=plan,
        journal=report.journal,
        leads_before=before,
        leads_final=final,
        out_dir=out_dir,
        evidence=evidence,
        claims=load_claims(claims_path),
        copy_events=load_copy_events(copy_events_path),
        shared_records=report.shared_records,
    )
