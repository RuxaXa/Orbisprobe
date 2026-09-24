from __future__ import annotations

import json
import math
from dataclasses import dataclass
from enum import Enum
from typing import Any

from orbisprobe.analysis import HardwareSinkClass, UserInfluence
from orbisprobe.schema import RiskClass


class OperationMode(str, Enum):
    DISCOVERY_MODE = "DISCOVERY_MODE"
    PROOF_MODE = "PROOF_MODE"


class LeadStatus(str, Enum):
    DISCOVERED = "DISCOVERED"
    SCORED = "SCORED"
    EDGE_ANALYZED = "EDGE_ANALYZED"
    CLOSURE_PENDING = "CLOSURE_PENDING"
    EVIDENCE_PROBE_READY = "EVIDENCE_PROBE_READY"
    PROOF_MODE = "PROOF_MODE"
    VULNERABILITY_CANDIDATE = "VULNERABILITY_CANDIDATE"
    SAFE_INVARIANT = "SAFE_INVARIANT"
    DOWNGRADED = "DOWNGRADED"
    PARKED = "PARKED"
    ARTIFACT_BLOCKED = "ARTIFACT_BLOCKED"
    DISPROVED = "DISPROVED"


class EdgeDistance(str, Enum):
    EDGE_0 = "EDGE-0"
    EDGE_1 = "EDGE-1"
    EDGE_2 = "EDGE-2"
    EDGE_3PLUS = "EDGE-3PLUS"
    ARTIFACT_BLOCKED = "ARTIFACT_BLOCKED"


class ClosureCost(str, Enum):
    COST_1 = "COST-1"
    COST_2 = "COST-2"
    COST_3 = "COST-3"
    COST_4 = "COST-4"
    COST_5 = "COST-5"
    COST_BLOCKED = "COST-BLOCKED"


class ActionKind(str, Enum):
    EVIDENCE_PROBE = "EVIDENCE_PROBE"
    EXPLOIT_TEST = "EXPLOIT_TEST"


def _text(name: str, value: str) -> None:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{name} must be non-empty text")
    try:
        value.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise ValueError(f"{name} must be valid UTF-8 text") from exc


def _tuple(name: str, value: tuple[str, ...]) -> None:
    if not isinstance(value, tuple) or any(not isinstance(item, str) or not item for item in value):
        raise TypeError(f"{name} must be a tuple of non-empty strings")
    for item in value:
        _text(name, item)


def _closed_schema(
    name: str, value: dict[str, Any], allowed: set[str]
) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise TypeError(f"{name} must be an object")
    unknown = set(value) - allowed
    if unknown:
        raise ValueError(f"{name} has unknown fields: {', '.join(sorted(unknown))}")
    return dict(value)


@dataclass(frozen=True)
class LeadBudget:
    discovery: int
    closure: int
    proof: int

    def __post_init__(self) -> None:
        for name, value in (("discovery", self.discovery), ("closure", self.closure), ("proof", self.proof)):
            if not isinstance(value, int) or isinstance(value, bool) or value < 0:
                raise ValueError(f"{name} budget must be a non-negative integer")

    def to_dict(self) -> dict[str, int]:
        return {"discovery": self.discovery, "closure": self.closure, "proof": self.proof}

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> LeadBudget:
        data = _closed_schema(
            "LeadBudget", value, {"discovery", "closure", "proof"}
        )
        return cls(**data)


@dataclass(frozen=True)
class EvidenceAction:
    action_id: str
    action: str
    target_edge: str
    kind: ActionKind
    expected_information_gain: int
    cost: ClosureCost
    risk: RiskClass
    required_artifact: str = ""
    exact_question: str = ""
    ownership_known: bool = False
    target_identity_known: bool = False
    bounded_scope: bool = False
    stop_condition: str = ""
    persistent_effect: bool = False
    unknown_mmio: bool = False
    invalid_pointer: bool = False
    kernel_code_mutation: bool = False
    kernel_write: bool = False
    arbitrary_address: bool = False
    destructive_mmio: bool = False
    persistent_state_target: bool = False
    secure_state_modification: bool = False
    controlled_input: bool = False
    concrete_gap: bool = False
    known_consumer: bool = False
    bounded_observable: bool = False
    lifecycle_closed: bool = False
    recovery_defined: bool = False
    controls_defined: bool = False

    def __post_init__(self) -> None:
        for name in ("action_id", "action", "target_edge"):
            _text(name, getattr(self, name))
        if not isinstance(self.kind, ActionKind):
            raise TypeError("kind must be an ActionKind")
        if not isinstance(self.cost, ClosureCost):
            raise TypeError("cost must be a ClosureCost")
        if not isinstance(self.risk, RiskClass):
            raise TypeError("risk must be a RiskClass")
        if (
            not isinstance(self.expected_information_gain, int)
            or isinstance(self.expected_information_gain, bool)
            or not 0 <= self.expected_information_gain <= 5
        ):
            raise ValueError("expected_information_gain must be in 0..5")
        for name in ("required_artifact", "exact_question", "stop_condition"):
            value = getattr(self, name)
            if not isinstance(value, str):
                raise TypeError(f"{name} must be text")
            if value:
                _text(name, value)
        boolean_fields = (
            "ownership_known",
            "target_identity_known",
            "bounded_scope",
            "persistent_effect",
            "unknown_mmio",
            "invalid_pointer",
            "kernel_code_mutation",
            "kernel_write",
            "arbitrary_address",
            "destructive_mmio",
            "persistent_state_target",
            "secure_state_modification",
            "controlled_input",
            "concrete_gap",
            "known_consumer",
            "bounded_observable",
            "lifecycle_closed",
            "recovery_defined",
            "controls_defined",
        )
        for name in boolean_fields:
            if type(getattr(self, name)) is not bool:
                raise TypeError(f"{name} must be a bool")

    @property
    def evidence_probe_ready(self) -> bool:
        return (
            self.kind is ActionKind.EVIDENCE_PROBE
            and bool(self.exact_question)
            and self.ownership_known
            and self.target_identity_known
            and self.bounded_scope
            and bool(self.stop_condition)
            and not self.persistent_effect
            and not self.unknown_mmio
            and not self.invalid_pointer
            and not self.kernel_code_mutation
            and not self.kernel_write
            and not self.arbitrary_address
            and not self.destructive_mmio
            and not self.persistent_state_target
            and not self.secure_state_modification
            and self.cost is not ClosureCost.COST_BLOCKED
            and self.risk is not RiskClass.PERSISTENT
        )

    @property
    def exploit_test_ready(self) -> bool:
        return (
            self.kind is ActionKind.EXPLOIT_TEST
            and bool(self.exact_question)
            and self.controlled_input
            and self.concrete_gap
            and self.known_consumer
            and self.bounded_observable
            and self.lifecycle_closed
            and self.recovery_defined
            and self.controls_defined
            and self.ownership_known
            and self.target_identity_known
            and self.bounded_scope
            and bool(self.stop_condition)
            and not self.persistent_effect
            and not self.unknown_mmio
            and not self.invalid_pointer
            and not self.kernel_code_mutation
            and not self.kernel_write
            and not self.arbitrary_address
            and not self.destructive_mmio
            and not self.persistent_state_target
            and not self.secure_state_modification
            and self.cost is not ClosureCost.COST_BLOCKED
            and self.risk is not RiskClass.PERSISTENT
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "action_id": self.action_id,
            "action": self.action,
            "target_edge": self.target_edge,
            "kind": self.kind.value,
            "expected_information_gain": self.expected_information_gain,
            "cost": self.cost.value,
            "risk": self.risk.value,
            "required_artifact": self.required_artifact,
            "exact_question": self.exact_question,
            "ownership_known": self.ownership_known,
            "target_identity_known": self.target_identity_known,
            "bounded_scope": self.bounded_scope,
            "stop_condition": self.stop_condition,
            "persistent_effect": self.persistent_effect,
            "unknown_mmio": self.unknown_mmio,
            "invalid_pointer": self.invalid_pointer,
            "kernel_code_mutation": self.kernel_code_mutation,
            "kernel_write": self.kernel_write,
            "arbitrary_address": self.arbitrary_address,
            "destructive_mmio": self.destructive_mmio,
            "persistent_state_target": self.persistent_state_target,
            "secure_state_modification": self.secure_state_modification,
            "controlled_input": self.controlled_input,
            "concrete_gap": self.concrete_gap,
            "known_consumer": self.known_consumer,
            "bounded_observable": self.bounded_observable,
            "lifecycle_closed": self.lifecycle_closed,
            "recovery_defined": self.recovery_defined,
            "controls_defined": self.controls_defined,
            "evidence_probe_ready": self.evidence_probe_ready,
            "exploit_test_ready": self.exploit_test_ready,
        }

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> EvidenceAction:
        fields = {field.name for field in cls.__dataclass_fields__.values()}
        derived = {"evidence_probe_ready", "exploit_test_ready"}
        data = _closed_schema("EvidenceAction", value, fields | derived)
        for name in derived:
            data.pop(name, None)
        data["kind"] = ActionKind(data["kind"])
        data["cost"] = ClosureCost(data["cost"])
        data["risk"] = RiskClass(data["risk"])
        return cls(**data)


@dataclass(frozen=True)
class ResearchLead:
    lead_id: str
    origin: str
    root: str
    source: str
    sink: str
    hardware_class: HardwareSinkClass
    user_influence: UserInfluence
    candidate_invariant: str
    known_edges: tuple[str, ...]
    unknown_edges: tuple[str, ...]
    evidence: tuple[str, ...]
    observable: str
    persistence_risk: str
    runtime_requirements: tuple[str, ...]
    risk_class: RiskClass
    status: LeadStatus
    control_score: int
    sink_score: int
    gap_score: int
    edge_distance: EdgeDistance
    closure_cost: ClosureCost
    evidence_value: int
    lead_score: float
    evidence_actions: tuple[EvidenceAction, ...] = ()
    budget: LeadBudget = LeadBudget(1, 1, 1)
    mode: OperationMode = OperationMode.DISCOVERY_MODE
    legacy_status: str | None = None

    def __post_init__(self) -> None:
        for name in ("lead_id", "origin", "root", "source", "sink", "candidate_invariant", "observable", "persistence_risk"):
            _text(name, getattr(self, name))
        if not isinstance(self.hardware_class, HardwareSinkClass):
            raise TypeError("hardware_class must be a HardwareSinkClass")
        if not isinstance(self.user_influence, UserInfluence):
            raise TypeError("user_influence must be a UserInfluence")
        for name in ("known_edges", "unknown_edges", "evidence", "runtime_requirements"):
            _tuple(name, getattr(self, name))
            object.__setattr__(self, name, tuple(sorted(getattr(self, name))))
        if len(set(self.unknown_edges)) != len(self.unknown_edges):
            raise ValueError("unknown_edges must not contain duplicate decisive edges")
        if not isinstance(self.risk_class, RiskClass):
            raise TypeError("risk_class must be a RiskClass")
        if not isinstance(self.status, LeadStatus):
            raise TypeError("status must be a LeadStatus")
        active_statuses = {
            LeadStatus.CLOSURE_PENDING,
            LeadStatus.EVIDENCE_PROBE_READY,
            LeadStatus.PROOF_MODE,
            LeadStatus.VULNERABILITY_CANDIDATE,
        }
        if self.edge_distance is EdgeDistance.EDGE_3PLUS and self.status in active_statuses:
            raise ValueError("EDGE-3PLUS cannot carry an active status")
        if self.edge_distance is EdgeDistance.ARTIFACT_BLOCKED and (
            self.status is not LeadStatus.ARTIFACT_BLOCKED
            or self.closure_cost is not ClosureCost.COST_BLOCKED
        ):
            raise ValueError(
                "ARTIFACT_BLOCKED requires ARTIFACT_BLOCKED status and COST-BLOCKED"
            )
        if self.status is LeadStatus.ARTIFACT_BLOCKED and (
            self.edge_distance is not EdgeDistance.ARTIFACT_BLOCKED
            or self.closure_cost is not ClosureCost.COST_BLOCKED
        ):
            raise ValueError(
                "ARTIFACT_BLOCKED status requires ARTIFACT_BLOCKED and COST-BLOCKED"
            )
        if self.closure_cost is ClosureCost.COST_BLOCKED and (
            self.edge_distance is not EdgeDistance.ARTIFACT_BLOCKED
            or self.status is not LeadStatus.ARTIFACT_BLOCKED
        ):
            raise ValueError(
                "COST-BLOCKED requires ARTIFACT_BLOCKED edge and status"
            )
        for name in ("control_score", "sink_score", "gap_score", "evidence_value"):
            value = getattr(self, name)
            if not isinstance(value, int) or isinstance(value, bool) or not 0 <= value <= 5:
                raise ValueError(f"{name} must be in 0..5")
        if not isinstance(self.edge_distance, EdgeDistance):
            raise TypeError("edge_distance must be an EdgeDistance")
        if self.edge_distance is not EdgeDistance.ARTIFACT_BLOCKED:
            unknown_count = len(self.unknown_edges)
            valid_count = {
                EdgeDistance.EDGE_0: unknown_count == 0,
                EdgeDistance.EDGE_1: unknown_count == 1,
                EdgeDistance.EDGE_2: unknown_count == 2,
                EdgeDistance.EDGE_3PLUS: unknown_count >= 3,
            }[self.edge_distance]
            if not valid_count:
                raise ValueError(
                    f"unknown_edges count {unknown_count} contradicts "
                    f"{self.edge_distance.value}"
                )
        if not isinstance(self.closure_cost, ClosureCost):
            raise TypeError("closure_cost must be a ClosureCost")
        if not isinstance(self.lead_score, (int, float)) or isinstance(self.lead_score, bool):
            raise TypeError("lead_score must be numeric")
        if not math.isfinite(self.lead_score):
            raise ValueError("lead_score must be finite")
        if not isinstance(self.evidence_actions, tuple) or any(not isinstance(item, EvidenceAction) for item in self.evidence_actions):
            raise TypeError("evidence_actions must be a tuple of EvidenceAction")
        object.__setattr__(
            self,
            "evidence_actions",
            tuple(sorted(self.evidence_actions, key=lambda item: item.action_id)),
        )
        if not isinstance(self.budget, LeadBudget):
            raise TypeError("budget must be a LeadBudget")
        if not isinstance(self.mode, OperationMode):
            raise TypeError("mode must be an OperationMode")
        if self.legacy_status is not None:
            _text("legacy_status", self.legacy_status)

    def to_dict(self) -> dict[str, Any]:
        return {
            "lead_id": self.lead_id,
            "origin": self.origin,
            "root": self.root,
            "source": self.source,
            "sink": self.sink,
            "hardware_class": self.hardware_class.value,
            "user_influence": self.user_influence.value,
            "candidate_invariant": self.candidate_invariant,
            "known_edges": sorted(self.known_edges),
            "unknown_edges": sorted(self.unknown_edges),
            "evidence": sorted(self.evidence),
            "observable": self.observable,
            "persistence_risk": self.persistence_risk,
            "runtime_requirements": sorted(self.runtime_requirements),
            "risk_class": self.risk_class.value,
            "status": self.status.value,
            "control_score": self.control_score,
            "sink_score": self.sink_score,
            "gap_score": self.gap_score,
            "edge_distance": self.edge_distance.value,
            "closure_cost": self.closure_cost.value,
            "evidence_value": self.evidence_value,
            "lead_score": self.lead_score,
            "evidence_actions": [item.to_dict() for item in sorted(self.evidence_actions, key=lambda item: item.action_id)],
            "budget": self.budget.to_dict(),
            "mode": self.mode.value,
            "legacy_status": self.legacy_status,
        }

    def to_json(self) -> str:
        return json.dumps(
            self.to_dict(), sort_keys=True, separators=(",", ":"), allow_nan=False
        )

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> ResearchLead:
        allowed = {field.name for field in cls.__dataclass_fields__.values()}
        data = _closed_schema("ResearchLead", value, allowed)
        data["hardware_class"] = HardwareSinkClass(data["hardware_class"])
        data["user_influence"] = UserInfluence(data["user_influence"])
        data["risk_class"] = RiskClass(data["risk_class"])
        data["status"] = LeadStatus(data["status"])
        data["edge_distance"] = EdgeDistance(data["edge_distance"])
        data["closure_cost"] = ClosureCost(data["closure_cost"])
        data["mode"] = OperationMode(data.get("mode", OperationMode.DISCOVERY_MODE.value))
        for name in ("known_edges", "unknown_edges", "evidence", "runtime_requirements"):
            data[name] = tuple(data.get(name, ()))
        data["evidence_actions"] = tuple(EvidenceAction.from_dict(item) for item in data.get("evidence_actions", ()))
        data["budget"] = LeadBudget.from_dict(
            data.get("budget", {"discovery": 1, "closure": 1, "proof": 1})
        )
        return cls(**data)
