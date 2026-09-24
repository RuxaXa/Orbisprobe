from __future__ import annotations

import hashlib
import json
from pathlib import Path

from orbisprobe.analysis import HardwareSinkClass, UserInfluence
from orbisprobe.schema import RiskClass

from .model import (
    ActionKind,
    ClosureCost,
    EdgeDistance,
    EvidenceAction,
    LeadBudget,
    LeadStatus,
    OperationMode,
    ResearchLead,
)
from .safe_io import capture_protected_sources, validate_output_root
from .scheduler import default_budget


def _identifier(prefix: str, key: str) -> str:
    digest = hashlib.sha256(key.encode()).hexdigest()[:12]
    return f"{prefix}-{digest}"


def validate_output_separation(
    output_dir: str | Path, source_paths: tuple[Path, ...]
) -> Path:
    protected = capture_protected_sources(source_paths)
    return validate_output_root(output_dir, protected)


def _lead(
    *,
    lead_id: str,
    origin: str,
    root: str,
    source: str,
    sink: str,
    hardware_class: HardwareSinkClass,
    user_influence: UserInfluence,
    invariant: str,
    known: tuple[str, ...],
    unknown: tuple[str, ...],
    evidence: tuple[str, ...],
    observable: str,
    status: LeadStatus,
    control: int,
    sink_score: int,
    gap: int,
    edge: EdgeDistance,
    cost: ClosureCost,
    evidence_value: int,
    actions: tuple[EvidenceAction, ...] = (),
    mode: OperationMode = OperationMode.DISCOVERY_MODE,
    legacy_status: str | None = None,
) -> ResearchLead:
    budget = (
        LeadBudget(0, 0, 0)
        if status
        in {
            LeadStatus.SAFE_INVARIANT,
            LeadStatus.DOWNGRADED,
            LeadStatus.DISPROVED,
            LeadStatus.ARTIFACT_BLOCKED,
        }
        else default_budget(edge)
    )
    return ResearchLead(
        lead_id=lead_id,
        origin=origin,
        root=root,
        source=source,
        sink=sink,
        hardware_class=hardware_class,
        user_influence=user_influence,
        candidate_invariant=invariant,
        known_edges=known,
        unknown_edges=unknown,
        evidence=evidence,
        observable=observable,
        persistence_risk="NONE",
        runtime_requirements=tuple(action.required_artifact for action in actions if action.required_artifact),
        risk_class=RiskClass.OFFLINE,
        status=status,
        control_score=control,
        sink_score=sink_score,
        gap_score=gap,
        edge_distance=edge,
        closure_cost=cost,
        evidence_value=evidence_value,
        lead_score=0,
        evidence_actions=actions,
        budget=budget,
        mode=mode,
        legacy_status=legacy_status,
    )


def _offline_action(action_id: str, action: str, edge: str, gain: int = 4) -> EvidenceAction:
    return EvidenceAction(
        action_id=action_id,
        action=action,
        target_edge=edge,
        kind=ActionKind.EVIDENCE_PROBE,
        expected_information_gain=gain,
        cost=ClosureCost.COST_2,
        risk=RiskClass.OFFLINE,
        required_artifact="FW13.52 kernel/Ghidra corpus",
        exact_question=f"Can offline evidence close {edge}?",
        ownership_known=True,
        target_identity_known=True,
        bounded_scope=True,
        stop_condition="one bounded target-specific analysis pass",
    )


def _legacy_action(
    key: str,
    action: str,
    target_edge: str,
    *,
    cost: ClosureCost,
    gain: int,
) -> EvidenceAction:
    return EvidenceAction(
        action_id=_identifier("legacy-action", key),
        action=action,
        target_edge=target_edge,
        kind=ActionKind.EVIDENCE_PROBE,
        expected_information_gain=gain,
        cost=cost,
        risk=RiskClass.OFFLINE,
        required_artifact="existing FW13.52 native/Ghidra corpus",
        exact_question=f"Can existing evidence close {target_edge}?",
        ownership_known=True,
        target_identity_known=True,
        bounded_scope=True,
        stop_condition="one bounded record-specific offline pass",
    )


P1_UNKNOWNS: dict[str, tuple[str, ...]] = {
    "PARKED_RESOURCE_POINTER_LIFECYCLE_AND_LOCK_DOMAIN_UNPROVEN": (
        "owner-field-lifecycle", "lock-domain", "user-binding"
    ),
    "PARKED_RING_POINTER_STABILITY_AND_USER_BINDING_UNPROVEN": (
        "user-binding", "writer-source", "dispatch-closure"
    ),
    "PARKED_SUBOBJECT_LIFECYCLE_AND_LOCK_DOMAIN_UNPROVEN": (
        "object-lifecycle", "lock-domain", "writer-source", "user-binding"
    ),
    "PARKED_VM_CLEANUP_OBJECT_LIFECYCLE_UNPROVEN": (
        "object-identity", "ownership-lifecycle", "writer-source", "user-binding"
    ),
    "PARKED_EXACT_FIELD_USER_AND_OBSERVABLE_UNPROVEN": (
        "field-semantic-binding", "user-binding", "bounded-observable"
    ),
    "PARKED_ROUTE_CALLBACK_USER_OBSERVABLE_AND_LOCK_DOMAIN_UNPROVEN": (
        "user-binding", "lock-domain", "bounded-observable"
    ),
    "PARKED_OWNER_FIELD_STABILITY_AND_LIFECYCLE_UNPROVEN": (
        "owner-type", "writer-stability", "user-binding"
    ),
    "PARKED_VM_OBJECT_POINTER_STABILITY_AND_USER_BINDING_UNPROVEN": (
        "owner-type", "writer-lifecycle", "lock-domain", "user-binding"
    ),
    "PARKED_DESTINATION_POINTER_LIFECYCLE_AND_MUTABILITY_UNPROVEN": (
        "owner-type", "writer-lifecycle", "user-binding"
    ),
    "PARKED_USB_FIFO_FIELD_LIFECYCLE_AND_DEEP_CONSUMER_UNPROVEN": (
        "writer-lifetime", "deep-consumer-effect", "user-binding"
    ),
    "PARKED_VM_OBJECT_POINTER_STABILITY_OUTER_MAP_LOCK_UNPROVEN": (
        "writer-set", "outer-map-lock-contract", "user-binding"
    ),
    "PARKED_SYNC_MANAGER_POINTER_LIFECYCLE_AND_LOCK_CONTRACT_UNPROVEN": (
        "writer-lifetime", "lock-ownership-contract", "user-binding"
    ),
    "PARKED_MUTABLE_WINDOW_AND_USER_BINDING_UNPROVEN": (
        "owner-field-stability", "user-binding", "security-observable"
    ),
    "PARKED_OBJECT_TYPE_AND_LIFECYCLE_UNPROVEN": (
        "owner-type", "writer-lifecycle", "user-binding", "deep-consumer-effect"
    ),
}


def _load_p1_details(base: Path, records: list[dict]) -> dict[str, dict]:
    details: dict[str, dict] = {}
    evidence_root = base.resolve()
    for name in sorted({record["source_file"] for record in records}):
        path = (evidence_root / name).resolve()
        if not path.is_relative_to(evidence_root):
            raise ValueError(f"source_file escapes evidence directory: {name}")
        if not path.exists():
            continue
        value = json.loads(path.read_text(encoding="utf-8"))
        rows = value if isinstance(value, list) else value.get("records", value.get("results", []))
        if not isinstance(rows, list):
            continue
        for row in rows:
            key = row.get("key")
            if key:
                details[key] = row
    return details


def _p1_migration_profile(record: dict, detail: dict) -> dict:
    candidate = record["candidate"]
    classification = record["classification"]
    key = f"{candidate}|{record['callsite']}|{record['field']}"
    consumer = record.get("consumer_class", "UNKNOWN")
    sink_score = 3 if consumer == "C3" else 2 if consumer == "C2" else 1
    hardware = (
        HardwareSinkClass.RING_STATE
        if candidate in {"0xffffffffd05ac8f0", "0xffffffffd0698e90"}
        else HardwareSinkClass.HOST_ONLY
    )

    if candidate == "0xffffffffd016efa0":
        unknown = ("capacity-across-reuse", "user/request-binding")
        return {
            "unknown": unknown,
            "edge": EdgeDistance.EDGE_2,
            "cost": ClosureCost.COST_2,
            "status": LeadStatus.CLOSURE_PENDING,
            "control": 2,
            "sink_score": 3,
            "gap": 5,
            "evidence_value": 5,
            "hardware": HardwareSinkClass.HOST_ONLY,
            "action": _legacy_action(
                key,
                "close scratch allocation capacity across all reuse callers",
                unknown[0],
                cost=ClosureCost.COST_2,
                gain=5,
            ),
            "reason": "allocation uses current length, reuse copies a later length without a local capacity check",
        }
    if candidate == "0xffffffffd0568e10":
        unknown = ("parent-pointer stability under vnode/tmpfs rename lock",)
        return {
            "unknown": unknown,
            "edge": EdgeDistance.EDGE_1,
            "cost": ClosureCost.COST_2,
            "status": LeadStatus.CLOSURE_PENDING,
            "control": 2,
            "sink_score": 3,
            "gap": 4,
            "evidence_value": 4,
            "hardware": HardwareSinkClass.HOST_ONLY,
            "action": _legacy_action(
                key,
                "resolve tmpfs parent-pointer stability under the rename-lock contract",
                unknown[0],
                cost=ClosureCost.COST_2,
                gain=4,
            ),
            "reason": "getdents-adjacent lock/unlock uses two parent-pointer reads; one lock-domain edge remains",
        }
    if candidate == "0xffffffffd048f350":
        return {
            "unknown": (),
            "edge": EdgeDistance.EDGE_0,
            "cost": ClosureCost.COST_1,
            "status": LeadStatus.DOWNGRADED,
            "control": 2,
            "sink_score": 1,
            "gap": 0,
            "evidence_value": 4,
            "hardware": HardwareSinkClass.HOST_ONLY,
            "action": None,
            "reason": "bounded read-only comparison with no privileged state effect",
        }

    unknown = P1_UNKNOWNS.get(
        classification,
        ("consumer-binding", "user-binding", "candidate-invariant"),
    )
    return {
        "unknown": unknown,
        "edge": EdgeDistance.EDGE_3PLUS,
        "cost": ClosureCost.COST_2,
        "status": LeadStatus.PARKED,
        "control": 2 if record.get("user_influence") != "KERNEL_CONTROLLED" else 1,
        "sink_score": sink_score,
        "gap": 3 if classification != "PARK" else 1,
        "evidence_value": 4 if detail else 2,
        "hardware": hardware,
        "action": _legacy_action(
            key,
            "resolve the cheapest decisive legacy edge from existing native/Ghidra evidence",
            unknown[0],
            cost=ClosureCost.COST_2,
            gain=2 if classification != "PARK" else 1,
        ),
        "reason": detail.get("blocker", classification),
    }


def migrate_v5_parked(aggregate_path: str | Path, p2_path: str | Path) -> tuple[ResearchLead, ...]:
    aggregate = Path(aggregate_path)
    p1 = json.loads(aggregate.read_text(encoding="utf-8"))["records"]
    p2 = json.loads(Path(p2_path).read_text(encoding="utf-8"))["records"]
    output: list[ResearchLead] = []

    p1_parked = [
        record
        for record in p1
        if record["classification"].startswith("PARK")
        and record["candidate"] != "0xffffffffd00d7f10"
    ]
    details = _load_p1_details(aggregate.parent, p1_parked)
    for record in p1_parked:
        key = f"{record['candidate']}|{record['callsite']}|{record['field']}"
        rc001 = record["candidate"] == "0xffffffffd05ac8f0"
        detail = details.get(key, {})
        profile = _p1_migration_profile(record, detail)
        action = profile["action"]
        output.append(
            _lead(
                lead_id="RC-001" if rc001 else _identifier("V5-P1", key),
                origin="V5-P1 legacy migration",
                root=record["candidate"],
                source=f"{record['callsite']} {record['field']}",
                sink=detail.get("consumer_semantics", record.get("consumer_class", "UNKNOWN")),
                hardware_class=profile["hardware"],
                user_influence=(
                    UserInfluence.KERNEL_POLICY_SELECTED
                    if record.get("user_influence") == "KERNEL_CONTROLLED"
                    else UserInfluence.UNKNOWN
                ),
                invariant=profile["reason"],
                known=("candidate-callsite-field identity", "legacy evidence reviewed under v0.3"),
                unknown=profile["unknown"],
                evidence=(record["source_file"], "AGGREGATE.json"),
                observable=record.get("observable", detail.get("observable", "UNKNOWN")),
                status=profile["status"],
                control=profile["control"],
                sink_score=profile["sink_score"],
                gap=profile["gap"],
                edge=profile["edge"],
                cost=profile["cost"],
                evidence_value=profile["evidence_value"],
                actions=((action,) if action is not None else ()),
                legacy_status="PARKED",
            )
        )

    for record in (item for item in p2 if item["disposition"] == "PARKED"):
        key = record["record_key"]
        bucket = record.get("native_bucket", "UNRESOLVED")
        if bucket == "C4":
            unknown = ("consumer-binding", "user-binding", "security-effect")
            sink_score = 1
            gap = 1
            cost = ClosureCost.COST_1
            gain = 1
            action_text = "resolve whether a concrete consumer exists before deeper analysis"
        elif bucket == "C2_C3_KERNEL_OWNED":
            unknown = ("user-binding", "ownership/lifecycle", "host-observable")
            sink_score = 3
            gap = 2
            cost = ClosureCost.COST_2
            gain = 2
            action_text = "bind a concrete user/request source and host observable"
        else:
            unknown = ("consumer-binding", "user-binding", "host-observable")
            sink_score = 2
            gap = 2
            cost = ClosureCost.COST_2
            gain = 2
            action_text = "resolve the independent consumer before source/lifecycle work"
        action = _legacy_action(
            key,
            action_text,
            unknown[0],
            cost=cost,
            gain=gain,
        )
        output.append(
            _lead(
                lead_id=_identifier("V5-P2", key),
                origin="V5-P2 legacy migration",
                root=record["candidate"],
                source=f"{record['callsite']} {record['field']}",
                sink=bucket,
                hardware_class=HardwareSinkClass.HOST_ONLY,
                user_influence=UserInfluence.UNKNOWN,
                invariant=record["classification"],
                known=("repeated-read record identity", "legacy evidence reviewed under v0.3"),
                unknown=unknown,
                evidence=("p2-rest.json", record.get("native_evidence") or "native window"),
                observable=record.get("host_observable", "NONE_BOUND"),
                status=LeadStatus.PARKED,
                control=2,
                sink_score=sink_score,
                gap=gap,
                edge=EdgeDistance.EDGE_3PLUS,
                cost=cost,
                evidence_value=2,
                actions=(action,),
                legacy_status="PARKED",
            )
        )
    if len(output) != 104:
        raise ValueError(f"expected 104 V5 parked records, found {len(output)}")
    return tuple(sorted(output, key=lambda lead: lead.lead_id))


def current_reference_leads() -> tuple[ResearchLead, ...]:
    gc_address = _lead(
        lead_id="GC-ADDRESS-LEAD",
        origin="M3-SOC3",
        root="/dev/gc ioctl 0xc0848119",
        source="USER GPUVA base and size",
        sink="CP_PRT_LOD_STATS address/control registers",
        hardware_class=HardwareSinkClass.DEVICE_COMMAND,
        user_influence=UserInfluence.USER_CONTROLLED,
        invariant="base+size must remain within an owned current-VMID mapping",
        known=("ordinary process reachability", "forced current VMID", "per-context restore"),
        unknown=("mapping-object extent binding", "cross-boundary security effect"),
        evidence=("M3-SOC3/secondary-register-leads.json",),
        observable="current-VMID hardware write/fault",
        status=LeadStatus.CLOSURE_PENDING,
        control=5,
        sink_score=5,
        gap=4,
        edge=EdgeDistance.EDGE_2,
        cost=ClosureCost.COST_2,
        evidence_value=4,
        actions=(
            _offline_action("gc-address-map", "bind base+size to mapping-object extents", "mapping-object extent binding"),
        ),
    )
    pm4 = _lead(
        lead_id="GC-PM4-IB-OWNERSHIP",
        origin="M3-SOC2",
        root="gc PM4 ioctl",
        source="USER GPUVA/IB descriptor",
        sink="GPU command fetch under forced VMID",
        hardware_class=HardwareSinkClass.DEVICE_COMMAND,
        user_influence=UserInfluence.USER_CONTROLLED,
        invariant="IB base+length must stay in a live owned mapping until completion",
        known=("packet whitelist", "forced context VMID"),
        unknown=("mapping extent binding", "mapping lifetime to completion"),
        evidence=("M3-SOC2/gc-pm4-hqd-contract.json",),
        observable="GPU command fetch/fault",
        status=LeadStatus.CLOSURE_PENDING,
        control=5,
        sink_score=5,
        gap=3,
        edge=EdgeDistance.EDGE_2,
        cost=ClosureCost.COST_2,
        evidence_value=4,
        actions=(_offline_action("pm4-extent", "resolve final IB mapping extent and lifetime", "mapping extent binding"),),
    )
    hqd = _lead(
        lead_id="GC-HQD-EXTENT-OWNERSHIP",
        origin="M3-SOC2",
        root="gc HQD ioctl",
        source="USER queue base/size",
        sink="HQD queue base and doorbell state",
        hardware_class=HardwareSinkClass.DEVICE_COMMAND,
        user_influence=UserInfluence.USER_CONTROLLED,
        invariant="queue extent and report pointers must remain within current-VMID owned mappings",
        known=("forced VMID", "kernel MQD", "kernel-derived doorbell"),
        unknown=("queue base+extent binding", "completion lifetime"),
        evidence=("M3-SOC2/gc-pm4-hqd-contract.json",),
        observable="queue fetch/fault",
        status=LeadStatus.CLOSURE_PENDING,
        control=5,
        sink_score=5,
        gap=3,
        edge=EdgeDistance.EDGE_2,
        cost=ClosureCost.COST_2,
        evidence_value=4,
        actions=(_offline_action("hqd-extent", "resolve HQD base+extent against current mappings", "queue base+extent binding"),),
    )
    partial = _lead(
        lead_id="GPUVM-PARTIAL-MAP-GENERIC",
        origin="M3-SOC2",
        root="multi-unit gpuvm_map callers",
        source="USER_INFLUENCED multi-run mappings",
        sink="GPUVM/GBase leaf mappings",
        hardware_class=HardwareSinkClass.GPUVM_VISIBLE,
        user_influence=UserInfluence.USER_INFLUENCED,
        invariant="failed multi-segment mapping must roll back earlier segments and allocation bits",
        known=("generic rollback gap", "0xc0284409 single segment disproved as trigger"),
        unknown=("reachable multi-segment caller", "deterministic lower-layer failure"),
        evidence=("M3-SOC2/partial-map-verification.json",),
        observable="stale GPU translation/allocation state",
        status=LeadStatus.CLOSURE_PENDING,
        control=4,
        sink_score=4,
        gap=4,
        edge=EdgeDistance.EDGE_2,
        cost=ClosureCost.COST_2,
        evidence_value=3,
        actions=(_offline_action("gpuvm-callers", "rank multi-unit gpuvm_map callers", "reachable multi-segment caller"),),
    )
    ring_closed = _lead(
        lead_id="GC-RING-SIZES",
        origin="M3-SOC3",
        root="sceGnmSetGsRingSizes / 0xc00c8110",
        source="ordinary game process ring-size values",
        sink="0x2232/0x2233 GS ring-size state",
        hardware_class=HardwareSinkClass.RING_STATE,
        user_influence=UserInfluence.USER_CONTROLLED,
        invariant="per-context save/restore prevents cross-context inheritance",
        known=("ordinary process reachability", "exact write", "Liverpool RLC restore", "software context restore"),
        unknown=(),
        evidence=("M3-SOC3/CHECKPOINT_CONTINUE_M3_SOC3.json",),
        observable="context-local GS ring sizing",
        status=LeadStatus.DOWNGRADED,
        control=5,
        sink_score=3,
        gap=0,
        edge=EdgeDistance.EDGE_0,
        cost=ClosureCost.COST_1,
        evidence_value=5,
        mode=OperationMode.PROOF_MODE,
    )
    secure = _lead(
        lead_id="SEC-TAG1-TAG9",
        origin="M3-SOC2",
        root="pup_update0 GPUVM/SAMU transport",
        source="USER_INFLUENCED Tag-1 descriptor",
        sink="SAMU/SBL secure consumer",
        hardware_class=HardwareSinkClass.DEVICE_COMMAND,
        user_influence=UserInfluence.USER_INFLUENCED,
        invariant="secure parser must validate address, length, VMID, session and snapshot semantics",
        known=("host Tag-1/Tag-9 transport", "VMID15 mapping"),
        unknown=("decoded Tag-9 dispatcher", "decoded Tag-1 consumer"),
        evidence=("M3-SOC2/secure-tag1-tag9.json",),
        observable="secure/hardware result",
        status=LeadStatus.ARTIFACT_BLOCKED,
        control=4,
        sink_score=5,
        gap=3,
        edge=EdgeDistance.ARTIFACT_BLOCKED,
        cost=ClosureCost.COST_BLOCKED,
        evidence_value=4,
        actions=(
            EvidenceAction(
                action_id="secure-decoded-artifact",
                action="analyze a genuinely decoded Tag-1/Tag-9 executable",
                target_edge="decoded Tag-9 dispatcher",
                kind=ActionKind.EVIDENCE_PROBE,
                expected_information_gain=5,
                cost=ClosureCost.COST_BLOCKED,
                risk=RiskClass.OFFLINE,
                required_artifact="decoded SAMU/SBL Tag-1/Tag-9 executable",
                exact_question="How does the secure parser validate and consume the descriptor?",
                ownership_known=True,
                target_identity_known=True,
                bounded_scope=True,
                stop_condition="stop if the executable is not decoded/provenanced",
            ),
        ),
    )
    return (gc_address, pm4, hqd, partial, ring_closed, secure)


def regression_reference_leads() -> tuple[ResearchLead, ResearchLead]:
    gc = _lead(
        lead_id="GC-A-PRE-CLOSURE",
        origin="M3-SOC2 historical regression only",
        root="/dev/gc 0xc00c8110",
        source="USER_CONTROLLED register values",
        sink="fixed security-relevant GPU register candidate",
        hardware_class=HardwareSinkClass.DEVICE_COMMAND,
        user_influence=UserInfluence.USER_CONTROLLED,
        invariant="authorization/globality contract",
        known=("user reachability", "exact register write"),
        unknown=("global/cross-context behavior",),
        evidence=("M3-SOC2 historical pre-closure snapshot",),
        observable="potential cross-context GPU availability",
        status=LeadStatus.CLOSURE_PENDING,
        control=5,
        sink_score=5,
        gap=4,
        edge=EdgeDistance.EDGE_1,
        cost=ClosureCost.COST_2,
        evidence_value=4,
    )
    rc = _lead(
        lead_id="RC-001-REGRESSION",
        origin="M3-SOC1 regression",
        root="d05ac8f0",
        source="context ring pointer",
        sink="GPU ring submit",
        hardware_class=HardwareSinkClass.RING_STATE,
        user_influence=UserInfluence.CONTEXT_SELECTED,
        invariant="writer/lifetime/user binding before dispatch",
        known=("ring consumer",),
        unknown=("user-binding", "writer-source", "dispatch-closure"),
        evidence=("M3-SOC1 parked RC-001",),
        observable="unknown",
        status=LeadStatus.PARKED,
        control=3,
        sink_score=3,
        gap=3,
        edge=EdgeDistance.EDGE_3PLUS,
        cost=ClosureCost.COST_4,
        evidence_value=3,
    )
    return gc, rc
