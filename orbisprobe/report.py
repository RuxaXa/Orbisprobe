from __future__ import annotations

from collections import Counter

from .evidence import EvidenceLog


def markdown_report(log: EvidenceLog) -> str:
    events = log.read()
    kinds = Counter(x["kind"] for x in events)
    lines = ["# OrbisProbe evidence report", "", f"Events: {len(events)}", ""]
    for k, n in sorted(kinds.items()):
        lines.append(f"- {k}: {n}")
    lines += ["", "## Runs", ""]
    by_run: dict[str, list[dict]] = {}
    for e in events:
        by_run.setdefault(e["run_id"], []).append(e)
    for run, xs in by_run.items():
        lines.append(f"### {run}")
        lines.append(f"Experiment: `{xs[0]['experiment_id']}`")
        lines.append(f"Events: {len(xs)}")
        lines.append("")
    return "\n".join(lines)
