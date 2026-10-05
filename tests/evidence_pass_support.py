"""Shared harness that turns the regression fixtures (cases A-J) into real pass packages."""

from __future__ import annotations

import json
import shutil
from dataclasses import dataclass, replace
from pathlib import Path

from orbisprobe.analysis import HardwareSinkClass, UserInfluence
from orbisprobe.evidence_pass.builder import build_pass
from orbisprobe.evidence_pass.journal import ActionJournal
from orbisprobe.evidence_pass.manifest import manifest_sha256, verify_manifest
from orbisprobe.evidence_pass.model import canonical_json, sha256_file
from orbisprobe.evidence_pass.plan import (
    ActionAssignment,
    ActionPlan,
    SafetyPolicy,
    SharedEvidence,
)
from orbisprobe.evidence_pass.rebuild import replay_executor
from orbisprobe.evidence_pass.review import ReviewMode
from orbisprobe.evidence_pass.runner import run_plan
from orbisprobe.evidence_pass.verify import verify_package
from orbisprobe.leads.model import (
    ActionKind,
    ClosureCost,
    EdgeDistance,
    EvidenceAction,
    LeadBudget,
    LeadStatus,
    OperationMode,
    ResearchLead,
)
from orbisprobe.leads.store import LeadStore
from orbisprobe.schema import RiskClass

FIXTURE_DIR = Path(__file__).parent / "fixtures" / "evidence_pass"
REPO_ROOT = Path(__file__).resolve().parents[1]
LEAD_ID = "EP-LEAD-01"
RECIPIENT_ID = "EP-LEAD-02"
UNCHANGED_LEAD_ID = "EP-LEAD-03"
ACTION_ID = "ep-action-01"
SHARED_ACTION_ID = "ep-action-02"

UNKNOWN_BY_EDGE = {
    EdgeDistance.EDGE_0: (),
    EdgeDistance.EDGE_1: ("the decisive length pair for one object",),
    EdgeDistance.EDGE_2: ("first decisive edge", "second decisive edge"),
}


def load_case(case: str) -> dict:
    return json.loads((FIXTURE_DIR / f"case_{case}.json").read_text(encoding="utf-8"))


def probe_action(action_id: str = ACTION_ID, **overrides) -> EvidenceAction:
    base = EvidenceAction(
        action_id=action_id,
        action="bind the recorded length pair of one object",
        target_edge="edge:length->allocation",
        kind=ActionKind.EVIDENCE_PROBE,
        expected_information_gain=4,
        cost=ClosureCost.COST_1,
        risk=RiskClass.OFFLINE,
        required_artifact="pinned image and frozen evidence",
        exact_question="Can the reuse length exceed the original allocation for one object?",
        ownership_known=True,
        target_identity_known=True,
        bounded_scope=True,
        stop_condition="one bounded offline dataflow action",
    )
    return replace(base, **overrides) if overrides else base


def make_lead(
    lead_id: str,
    *,
    edge: EdgeDistance = EdgeDistance.EDGE_1,
    status: LeadStatus | None = None,
    actions: tuple[EvidenceAction, ...] = (),
    unknown: tuple[str, ...] | None = None,
) -> ResearchLead:
    resolved_status = status or (
        LeadStatus.SAFE_INVARIANT if edge is EdgeDistance.EDGE_0 else LeadStatus.CLOSURE_PENDING
    )
    return ResearchLead(
        lead_id=lead_id,
        origin="regression-fixture",
        root="ep-pass",
        source="synthetic fixture source",
        sink="synthetic fixture sink",
        hardware_class=HardwareSinkClass.DMA_VISIBLE,
        user_influence=UserInfluence.KERNEL_FIXED,
        candidate_invariant="every reuse length fits the original allocation",
        known_edges=("the object is bound to exactly one buffer",),
        unknown_edges=UNKNOWN_BY_EDGE[edge] if unknown is None else unknown,
        evidence=("evidence/pinned-slice.json",),
        observable="copy length observed at the recorded site",
        persistence_risk="none",
        runtime_requirements=(),
        risk_class=RiskClass.OFFLINE,
        status=resolved_status,
        control_score=2,
        sink_score=1,
        gap_score=2,
        edge_distance=edge,
        closure_cost=ClosureCost.COST_1,
        evidence_value=3,
        lead_score=0.0,
        evidence_actions=tuple(actions),
        budget=LeadBudget(closure=1, discovery=0, proof=0),
        mode=OperationMode.DISCOVERY_MODE,
    )


def lead_store(leads: list[ResearchLead]) -> LeadStore:
    return LeadStore(tuple(leads))


def write_evidence_inputs(inputs_dir: Path) -> dict[str, Path]:
    inputs_dir.mkdir(parents=True, exist_ok=True)
    pinned = inputs_dir / "pinned-slice.json"
    pinned.write_text(canonical_json({"slice": "copy-site", "bytes": "488b43 50"}), encoding="utf-8")
    return {"pinned-slice.json": pinned}


def direction_record(label: str, *, swap_names: bool = False) -> dict:
    """Real pinned bytes from the Scratch initiation handler, with a swappable label.

    ``swap_names`` reproduces the reviewer's probe: inverting the recorded field-name table
    together with the label, which must still be rejected because the operand roles are
    derived from the bytes.
    """

    record = {
        "name": "initiation_bound_buffer_copy",
        "function": "0xffffffffd016efa0",
        "callsite": "0xffffffffd016f077",
        "pinned_bytes": "4989f64889fb488b4350498b5608498b7618488b7818",
        "helper_bytes": "4887f7f348a5",
        "binder_bytes": "4989f64889fb",
        "argument_names": {"arg1": "indirdep", "arg2": "bp"},
        "field_names": {
            "*(indirdep+0x50)+0x18": "indirdep+0x50 bound-buffer data",
            "bp+0x18": "bp->b_data",
            "bp+0x8": "bp->b_bcount",
        },
        "label": label,
    }
    if swap_names:
        names = dict(record["field_names"])
        names["*(indirdep+0x50)+0x18"], names["bp+0x18"] = names["bp+0x18"], names["*(indirdep+0x50)+0x18"]
        record["field_names"] = names
    return record


NOOP_REBUILD_SCRIPT = """#!/usr/bin/env python3
import argparse

parser = argparse.ArgumentParser()
parser.add_argument("--out", required=True)
args = parser.parse_args()
print("noop rebuild")
"""

SELF_COPY_REBUILD_SCRIPT = """#!/usr/bin/env python3
import argparse
import shutil
from pathlib import Path

parser = argparse.ArgumentParser()
parser.add_argument("--out", required=True)
args = parser.parse_args()
shutil.copytree(Path(__file__).resolve().parent, Path(args.out))
"""

PARTIAL_REBUILD_SCRIPT = """#!/usr/bin/env python3
import argparse
from pathlib import Path

parser = argparse.ArgumentParser()
parser.add_argument("--out", required=True)
args = parser.parse_args()
target = Path(args.out)
target.mkdir(parents=True, exist_ok=True)
# Emits a single synthetic artifact: no package reads, so only the set-equality rule can catch it.
(target / "action-plan.json").write_text("{}\\n", encoding="utf-8")
"""

PACKAGE_READING_REBUILD_SCRIPT = """#!/usr/bin/env python3
import argparse
from pathlib import Path

PACKAGE = Path({package!r})
parser = argparse.ArgumentParser()
parser.add_argument("--out", required=True)
args = parser.parse_args()
target = Path(args.out)
target.mkdir(parents=True, exist_ok=True)
(target / "action-plan.json").write_bytes((PACKAGE / "action-plan.json").read_bytes())
"""

ABSOLUTE_PACKAGE_COPY_SCRIPT = """#!/usr/bin/env python3
import argparse
import shutil
from pathlib import Path

PACKAGE = Path({package!r})
parser = argparse.ArgumentParser()
parser.add_argument("--out", required=True)
args = parser.parse_args()
shutil.copytree(PACKAGE, Path(args.out))
"""


def set_rebuild_script(package: Path, script: str) -> None:
    """Replace the frozen rebuild entry point and re-freeze the manifest honestly."""

    (package / "rebuild-pass.py").write_text(script, encoding="utf-8")
    rewrite_manifest(package)


CORRECT_LABEL = "bcopy(indirdep+0x50 bound-buffer data -> bp->b_data, bp->b_bcount)"
PRE_F3_LABEL = "bcopy(bp->b_data -> indirdep+0x50 bound-buffer data, bp->b_bcount)"


def claim(case_dir: Path) -> dict:
    slice_path = case_dir / "evidence" / "pinned-slice.json"
    return {
        "claim": "every reuse length equals the bound buffer's length field",
        "function": "0xffffffffd016efa0",
        "address": "0xffffffffd016f077",
        "field": "bp+8 (b_bcount)",
        "callsite": "0xffffffffd016f077",
        "slice_path": "evidence/pinned-slice.json",
        "slice_sha256": sha256_file(slice_path),
    }


def write_rebuild_entrypoint(package: Path, recipe: dict) -> None:
    script = (
        "#!/usr/bin/env python3\n"
        '"""Deterministic rebuild entry point (frozen artifact)."""\n'
        "import argparse\n"
        "import json\n"
        "import sys\n"
        "from pathlib import Path\n\n"
        f"RECIPE = json.loads({json.dumps(json.dumps(recipe, sort_keys=True))})\n"
        'sys.path.insert(0, RECIPE["repo"])\n'
        "from orbisprobe.evidence_pass.rebuild import build_from_inputs\n\n"
        "parser = argparse.ArgumentParser()\n"
        'parser.add_argument("--out", required=True)\n'
        "args = parser.parse_args()\n"
        "result = build_from_inputs(\n"
        '    plan_path=RECIPE["plan"],\n'
        '    results_path=RECIPE["results"],\n'
        '    leads_before_path=RECIPE["leads_before"],\n'
        '    leads_final_path=RECIPE["leads_final"],\n'
        '    evidence=RECIPE["evidence"],\n'
        '    claims_path=RECIPE["claims"],\n'
        '    copy_events_path=RECIPE["copy_events"],\n'
        '    out_dir=args.out,\n'
        ")\n"
        "print(json.dumps(result.to_dict(), sort_keys=True))\n"
    )
    (package / "rebuild-pass.py").write_text(script, encoding="utf-8")
    (package / "rebuild-pass.py").chmod(0o755)


@dataclass
class Scenario:
    package: Path
    inputs: Path
    plan: ActionPlan
    journal: ActionJournal
    case: dict


def build_scenario(
    tmp_path: Path,
    case: str,
    *,
    result_kind: str = "RESOLVED_SAFE",
    disposition: str = "SAFE_CLOSED",
    lead_after_edge: EdgeDistance = EdgeDistance.EDGE_0,
    lead_after_status: LeadStatus | None = None,
    shared: bool = False,
    claims: tuple[dict, ...] = (),
    label: str = CORRECT_LABEL,
    swap_field_names: bool = False,
    extra_plan_fields: dict | None = None,
) -> Scenario:
    """Materialise one complete pass package (plus its external inputs) from fixture data."""

    inputs = tmp_path / "inputs"
    package = tmp_path / "package"
    inputs.mkdir(parents=True, exist_ok=True)
    evidence = write_evidence_inputs(inputs)

    before_lead = make_lead(LEAD_ID, edge=EdgeDistance.EDGE_1, actions=(probe_action(),))
    final_leads = [
        make_lead(
            LEAD_ID,
            edge=lead_after_edge,
            status=lead_after_status,
            actions=(),
            unknown=() if lead_after_edge is EdgeDistance.EDGE_0 else None,
        )
    ]
    recipients = []
    if shared:
        final_leads.append(
            make_lead(RECIPIENT_ID, edge=EdgeDistance.EDGE_0, status=LeadStatus.SAFE_INVARIANT, actions=())
        )
        recipients = [RECIPIENT_ID]
    before_leads = [
        before_lead,
        # An unrelated terminal lead that the pass must leave byte-identical.
        make_lead(UNCHANGED_LEAD_ID, edge=EdgeDistance.EDGE_0, status=LeadStatus.SAFE_INVARIANT, actions=()),
    ]
    if shared:
        before_leads.append(make_lead(RECIPIENT_ID, edge=EdgeDistance.EDGE_1, actions=()))
    store_before = LeadStore(tuple(before_leads))
    store_final = LeadStore(
        (
            *final_leads,
            make_lead(
                UNCHANGED_LEAD_ID,
                edge=EdgeDistance.EDGE_0,
                status=LeadStatus.SAFE_INVARIANT,
                actions=(),
            ),
        )
    )

    assignment = ActionAssignment(lead_id=LEAD_ID, action_id=ACTION_ID)
    plan_payload = {
        "plan_id": f"ep-pass-{case.lower()}",
        "lead_ids": [LEAD_ID, *recipients] if shared else [LEAD_ID],
        "action_ids": [ACTION_ID],
        "assignments": [assignment.to_dict()],
        "baseline_package": str(inputs),
        "baseline_sha256sums_sha256": sha256_file(evidence["pinned-slice.json"]),
        "expected_action_count": 1,
        "protected_sources": [str(evidence["pinned-slice.json"])],
        "output_dir": str(package),
        "safety_policy": SafetyPolicy(
            allowed_operation_mode=OperationMode.DISCOVERY_MODE.value, allowed_risks=("offline", "read_only")
        ).to_dict(),
        "review_mode": ReviewMode.STANDARD.value,
        "actions": [probe_action().to_dict()],
        "shared_evidence": [
            SharedEvidence(
                source_action_id=ACTION_ID,
                recipients=(RECIPIENT_ID,),
                edges_changed=("edge:length->allocation",),
            ).to_dict()
        ]
        if shared
        else [],
        "expected_unchanged_leads": [UNCHANGED_LEAD_ID],
        "expected_portfolio": [["active_leads", 0], ["vulnerability_candidates", 0]],
        **(extra_plan_fields or {}),
    }
    plan_path = inputs / "plan.json"
    plan_path.write_text(canonical_json(plan_payload), encoding="utf-8")
    plan = ActionPlan.load(plan_path)

    results_path = inputs / "results.json"
    results_path.write_text(
        canonical_json(
            {
                "results": [
                    {
                        "action_id": ACTION_ID,
                        "result": result_kind,
                        "disposition": disposition,
                        "evidence": ["evidence/pinned-slice.json"],
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    leads_before_path = inputs / "leads-before.json"
    leads_before_path.write_text(store_before.to_json(), encoding="utf-8")
    leads_final_path = inputs / "leads-final.json"
    leads_final_path.write_text(store_final.to_json(), encoding="utf-8")
    with (inputs / "evidence-paths.json").open("w", encoding="utf-8") as handle:
        handle.write(canonical_json({name: str(path) for name, path in evidence.items()}))

    journal = ActionJournal.from_plan(plan)
    report = run_plan(plan, replay_executor(results_path), journal)

    case_dir = package
    claims_path = None
    if claims:
        claims_path = inputs / "claims.json"
        claims_path.write_text(canonical_json({"claims": list(claims)}), encoding="utf-8")

    copy_events_path = inputs / "copy-events.json"
    copy_events_path.write_text(
        canonical_json({"copies": [direction_record(label, swap_names=swap_field_names)]}), encoding="utf-8"
    )

    from orbisprobe.evidence_pass.model import ClaimTrace

    resolved_claims: tuple[ClaimTrace, ...] = ()
    if claims:
        resolved_claims = tuple(ClaimTrace.from_dict(item) for item in claims)
    result = build_pass(
        plan=plan,
        journal=report.journal,
        leads_before=store_before,
        leads_final=store_final,
        out_dir=case_dir,
        evidence=evidence,
        claims=resolved_claims,
        copy_events=(direction_record(label, swap_names=swap_field_names),),
        shared_records=report.shared_records,
    )
    assert result.source_integrity
    write_rebuild_entrypoint(
        case_dir,
        {
            "repo": str(REPO_ROOT),
            "plan": str(plan_path),
            "results": str(results_path),
            "leads_before": str(leads_before_path),
            "leads_final": str(leads_final_path),
            "evidence": {name: str(path) for name, path in evidence.items()},
            "claims": str(claims_path) if claims_path else None,
            "copy_events": str(copy_events_path),
        },
    )
    # The rebuild entry point is itself a frozen artifact: re-freeze the manifest last.
    rewrite_manifest(case_dir)
    return Scenario(package=case_dir, inputs=inputs, plan=plan, journal=report.journal, case=case)


def verify(scenario: Scenario, **kwargs) -> dict:
    defaults = {
        "baseline_package": str(scenario.inputs),
        "expected_unchanged_leads": list(scenario.plan.expected_unchanged_leads),
    }
    defaults.update(kwargs)
    return verify_package(str(scenario.package), **defaults)


def rewrite_manifest(package: Path) -> str:
    """Regenerate the manifest after a deliberate package mutation (keeps the audited hash honest)."""

    entries = {}
    for path in sorted(package.rglob("*")):
        if not path.is_file():
            continue
        relative = str(path.relative_to(package))
        if relative == "SHA256SUMS" or relative == "verification-result.json" or relative.startswith("review/"):
            continue
        entries[relative] = sha256_file(path)
    from orbisprobe.evidence_pass.manifest import render_manifest

    (package / "SHA256SUMS").write_text(render_manifest(entries), encoding="utf-8")
    return manifest_sha256(package)


def copy_package(scenario: Scenario, target: Path) -> Path:
    shutil.copytree(scenario.package, target)
    return target


def manifest_status(package: Path, *, strict: bool = True) -> str:
    return verify_manifest(package, strict=strict).status


def package_tree(package: Path) -> dict[str, str]:
    """Map every frozen artifact of a package to its sha256."""

    from orbisprobe.evidence_pass.manifest import artifact_paths
    from orbisprobe.evidence_pass.model import sha256_file

    return {relative: sha256_file(package / relative) for relative in artifact_paths(package)}


def run_cli(*args: str) -> tuple[int, dict]:
    """Run the real CLI entry point and parse its canonical JSON output."""

    import os
    import subprocess
    import sys

    environment = dict(os.environ)
    environment["PYTHONPATH"] = str(REPO_ROOT)
    completed = subprocess.run(
        [sys.executable, "-m", "orbisprobe.cli", *args],
        capture_output=True,
        text=True,
        check=False,
        cwd=str(REPO_ROOT),
        env=environment,
    )
    stdout = completed.stdout.strip()
    payload: dict = {}
    if stdout:
        try:
            payload = json.loads(stdout)
        except json.JSONDecodeError:
            payload = {"raw_stdout": stdout[-2000:]}
    if completed.returncode != 0 and not payload:
        payload = {"raw_stderr": completed.stderr[-2000:]}
    return completed.returncode, payload
