from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .gates import evaluate_action_gate
from .scheduler import ResearchScheduler, action_priority
from .scoring import rank_leads
from .store import LeadStore


def add_leads_parser(subparsers: argparse._SubParsersAction) -> None:
    leads = subparsers.add_parser("leads")
    sub = leads.add_subparsers(dest="leads_cmd", required=True)

    command = sub.add_parser("scan")
    command.add_argument("input")
    command.add_argument("--out", required=True)

    command = sub.add_parser("score")
    command.add_argument("store")
    command.add_argument("--out", required=True)

    command = sub.add_parser("rank")
    command.add_argument("store")
    command.add_argument("--top", type=int, default=20)
    command.add_argument("--json", action="store_true")
    command.add_argument("--all", action="store_true", help="include inactive/parked leads")

    command = sub.add_parser("show")
    command.add_argument("store")
    command.add_argument("lead_id")
    command.add_argument("--json", action="store_true")

    command = sub.add_parser("next")
    command.add_argument("store")
    command.add_argument("--json", action="store_true")

    command = sub.add_parser("rehydrate")
    command.add_argument("store")
    command.add_argument("evidence")
    command.add_argument("--out", required=True)

    command = sub.add_parser("action")
    command.add_argument("store")
    command.add_argument("lead_id")
    command.add_argument("--json", action="store_true")


def _rank_rows(store: LeadStore, *, include_inactive: bool, top: int) -> list[dict]:
    scheduler = ResearchScheduler(store.leads)
    ranked = (
        rank_leads(store.leads, include_inactive=True)
        if include_inactive
        else scheduler.ranked_active()
    )[:top]
    rows = []
    for rank, lead in enumerate(ranked, 1):
        action = scheduler.next_action(lead)
        rows.append(
            {
                "rank": rank,
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
    return rows


def _print_rows(rows: list[dict]) -> None:
    columns = ("rank", "lead", "control", "sink", "gap", "edge", "cost", "information_gain", "score", "next_action")
    print("\t".join(columns))
    for row in rows:
        print("\t".join(str(row[column]) for column in columns))


def run_leads_command(args: argparse.Namespace) -> int:
    try:
        if args.leads_cmd == "scan":
            store = LeadStore.load(args.input)
            store.save(args.out)
            print(json.dumps({"ok": True, "count": len(store.leads), "out": args.out}, sort_keys=True))
            return 0
        if args.leads_cmd == "score":
            store = LeadStore.load(args.store).score_all()
            store.save(args.out)
            print(json.dumps({"ok": True, "count": len(store.leads), "out": args.out}, sort_keys=True))
            return 0

        store = LeadStore.load(args.store)
        if args.leads_cmd == "rank":
            rows = _rank_rows(store, include_inactive=args.all, top=args.top)
            if args.json:
                print(json.dumps(rows, indent=2, sort_keys=True))
            else:
                _print_rows(rows)
            return 0
        if args.leads_cmd == "show":
            lead = store.get(args.lead_id)
            print(json.dumps(lead.to_dict(), indent=2, sort_keys=True))
            return 0
        if args.leads_cmd == "next":
            lead = ResearchScheduler(store.leads).next_lead()
            if lead is None:
                print(json.dumps({"lead": None, "reason": "no active lead"}, sort_keys=True))
                return 2
            print(json.dumps(lead.to_dict(), indent=2, sort_keys=True))
            return 0
        if args.leads_cmd == "action":
            scheduler = ResearchScheduler(store.leads)
            action = scheduler.next_action(args.lead_id)
            if action is None:
                print(json.dumps({"action": None, "reason": "no gate-ready action"}, sort_keys=True))
                return 2
            payload = action.to_dict()
            payload["priority"] = action_priority(action)
            payload["gate"] = evaluate_action_gate(action).gate
            print(json.dumps(payload, indent=2, sort_keys=True))
            return 0
        if args.leads_cmd == "rehydrate":
            evidence = json.loads(Path(args.evidence).read_text(encoding="utf-8"))
            if not isinstance(evidence, dict):
                raise TypeError("rehydration evidence must be an object")
            unknown = set(evidence) - {
                "lead_id",
                "resolved_edges",
                "artifact_available",
            }
            if unknown:
                raise ValueError(
                    "rehydration evidence has unknown fields: "
                    + ", ".join(sorted(unknown))
                )
            artifact_available = evidence.get("artifact_available", False)
            if type(artifact_available) is not bool:
                raise TypeError("artifact_available must be a bool")
            scheduler = ResearchScheduler(store.leads)
            updated = scheduler.rehydrate(
                evidence["lead_id"],
                tuple(evidence.get("resolved_edges", ())),
                artifact_available=artifact_available,
            )
            LeadStore(scheduler.leads).score_all().save(args.out)
            print(json.dumps({"ok": True, "lead": updated.lead_id, "status": updated.status.value, "out": args.out}, sort_keys=True))
            return 0
    except (OSError, ValueError, TypeError, KeyError, json.JSONDecodeError) as exc:
        print(f"orbisprobe: leads failed: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1
    return 1
