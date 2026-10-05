"""Fail-closed records for sink-first firmware analysis.

The records in this module describe offline analysis evidence only.  They do not
make live-policy decisions or authorize interaction with a discovered sink.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from enum import Enum
from typing import Any

from orbisprobe.surfaces.model import Confidence

_SHA256 = re.compile(r"[0-9a-f]{64}")


def _require_text(name: str, value: str) -> None:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{name} must be non-empty")


def _require_sha256(name: str, value: str) -> None:
    if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
        raise ValueError(f"{name} must be a lowercase SHA-256 digest")


def _json(payload: dict[str, Any]) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), allow_nan=False)


class HardwareSinkClass(str, Enum):
    """Taxonomy of terminal hardware effects visible to firmware analysis."""

    HOST_ONLY = "host_only"
    RING_STATE = "ring_state"
    DMA_VISIBLE = "dma_visible"
    GPUVM_VISIBLE = "gpuvm_visible"
    IOMMU_VISIBLE = "iommu_visible"
    DEVICE_COMMAND = "device_command"
    MMIO_REGISTER = "mmio_register"
    PORT_IO = "port_io"
    DMA_DESCRIPTOR = "dma_descriptor"
    IOMMU_MAPPING = "iommu_mapping"
    INTERRUPT_CONTROLLER = "interrupt_controller"
    SECURE_MAILBOX = "secure_mailbox"
    NONVOLATILE_STORAGE = "nonvolatile_storage"
    UNKNOWN = "unknown"

    @property
    def persistent(self) -> bool:
        return self is HardwareSinkClass.NONVOLATILE_STORAGE


class SinkOperation(str, Enum):
    READ = "read"
    WRITE = "write"
    SUBMIT = "submit"
    MAP = "map"
    INVALIDATE = "invalidate"
    EXECUTE = "execute"
    UNKNOWN = "unknown"


class UserInfluence(str, Enum):
    USER_CONTROLLED = "USER_CONTROLLED"
    USER_INFLUENCED = "USER_INFLUENCED"
    HANDLE_SELECTED = "HANDLE_SELECTED"
    CONTEXT_SELECTED = "CONTEXT_SELECTED"
    KERNEL_POLICY_SELECTED = "KERNEL_POLICY_SELECTED"
    KERNEL_FIXED = "KERNEL_FIXED"
    UNKNOWN = "UNKNOWN"


@dataclass(frozen=True)
class HardwareSink:
    sink_id: str
    sink_class: HardwareSinkClass
    operation: SinkOperation
    firmware_id: str
    binary_sha256: str
    address: int
    device: str
    confidence: Confidence
    evidence: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        _require_text("sink_id", self.sink_id)
        _require_text("firmware_id", self.firmware_id)
        _require_text("device", self.device)
        _require_sha256("binary_sha256", self.binary_sha256)
        if not isinstance(self.address, int) or isinstance(self.address, bool) or self.address < 0:
            raise ValueError("address must be a non-negative integer")
        if not isinstance(self.sink_class, HardwareSinkClass):
            raise TypeError("sink_class must be a HardwareSinkClass")
        if not isinstance(self.operation, SinkOperation):
            raise TypeError("operation must be a SinkOperation")
        if not isinstance(self.confidence, Confidence):
            raise TypeError("confidence must be a Confidence")
        if any(not isinstance(item, str) or not item.strip() for item in self.evidence):
            raise ValueError("evidence entries must be non-empty strings")

    @property
    def persistent(self) -> bool:
        return self.sink_class.persistent

    def to_dict(self) -> dict[str, Any]:
        return {
            "sink_id": self.sink_id,
            "sink_class": self.sink_class.value,
            "operation": self.operation.value,
            "firmware_id": self.firmware_id,
            "binary_sha256": self.binary_sha256,
            "address": self.address,
            "device": self.device,
            "confidence": self.confidence.value,
            "evidence": list(self.evidence),
            "persistent": self.persistent,
        }

    def to_json(self) -> str:
        return _json(self.to_dict())


_CONFIDENCE_RANK = {
    Confidence.NONE: 0,
    Confidence.LOW: 1,
    Confidence.MEDIUM: 2,
    Confidence.HIGH: 3,
}


@dataclass(frozen=True)
class BackwardSliceStep:
    """One dependency node, ordered from a sink toward its possible sources."""

    step_id: str
    address: int
    expression: str
    depends_on: tuple[str, ...] = ()
    confidence: Confidence = Confidence.NONE
    evidence: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        _require_text("step_id", self.step_id)
        _require_text("expression", self.expression)
        if not isinstance(self.address, int) or isinstance(self.address, bool) or self.address < 0:
            raise ValueError("address must be a non-negative integer")
        if not isinstance(self.confidence, Confidence):
            raise TypeError("confidence must be a Confidence")
        if self.step_id in self.depends_on:
            raise ValueError(f"slice dependency cycle at {self.step_id}")
        for name, entries in (("depends_on", self.depends_on), ("evidence", self.evidence)):
            if not isinstance(entries, tuple) or any(
                not isinstance(item, str) or not item.strip() for item in entries
            ):
                raise ValueError(f"{name} must contain non-empty strings")
        if len(set(self.depends_on)) != len(self.depends_on):
            raise ValueError("depends_on contains duplicate step ids")

    def to_dict(self) -> dict[str, Any]:
        return {
            "step_id": self.step_id,
            "address": self.address,
            "expression": self.expression,
            "depends_on": list(self.depends_on),
            "confidence": self.confidence.value,
            "evidence": list(self.evidence),
        }


@dataclass(frozen=True)
class SinkBackwardSlice:
    """A validated dependency graph rooted at one hardware sink operation."""

    slice_id: str
    sink: HardwareSink
    sink_step: str
    steps: tuple[BackwardSliceStep, ...]
    unresolved: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        _require_text("slice_id", self.slice_id)
        _require_text("sink_step", self.sink_step)
        if not isinstance(self.sink, HardwareSink):
            raise TypeError("sink must be a HardwareSink")
        if not isinstance(self.steps, tuple) or not self.steps:
            raise ValueError("steps must be a non-empty tuple")
        if any(not isinstance(step, BackwardSliceStep) for step in self.steps):
            raise ValueError("steps must contain BackwardSliceStep records")
        if any(not isinstance(item, str) or not item.strip() for item in self.unresolved):
            raise ValueError("unresolved entries must be non-empty strings")

        by_id = {step.step_id: step for step in self.steps}
        if len(by_id) != len(self.steps):
            raise ValueError("slice step ids must be unique")
        if self.sink_step not in by_id:
            raise ValueError("sink_step is not present in steps")
        for step in self.steps:
            missing = set(step.depends_on) - set(by_id)
            if missing:
                raise ValueError(f"missing slice dependencies: {sorted(missing)}")

        visiting: set[str] = set()
        visited: set[str] = set()

        def visit(step_id: str) -> None:
            if step_id in visiting:
                raise ValueError(f"slice dependency cycle at {step_id}")
            if step_id in visited:
                return
            visiting.add(step_id)
            for dependency in by_id[step_id].depends_on:
                visit(dependency)
            visiting.remove(step_id)
            visited.add(step_id)

        visit(self.sink_step)
        if visited != set(by_id):
            raise ValueError(f"slice contains unreachable steps: {sorted(set(by_id) - visited)}")

    @property
    def complete(self) -> bool:
        return not self.unresolved and all(
            step.confidence is not Confidence.NONE for step in self.steps
        )

    @property
    def confidence(self) -> Confidence:
        return min(
            (step.confidence for step in self.steps),
            key=_CONFIDENCE_RANK.__getitem__,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "slice_id": self.slice_id,
            "sink": self.sink.to_dict(),
            "sink_step": self.sink_step,
            "steps": [step.to_dict() for step in self.steps],
            "unresolved": list(self.unresolved),
            "complete": self.complete,
            "confidence": self.confidence.value,
        }

    def to_json(self) -> str:
        return _json(self.to_dict())


class MappingState(str, Enum):
    ALLOCATED = "allocated"
    MAPPED = "mapped"
    ACTIVE = "active"
    INVALIDATED = "invalidated"
    UNMAPPED = "unmapped"
    RELEASED = "released"
    UNKNOWN = "unknown"


_ALLOWED_MAPPING_TRANSITIONS = {
    (MappingState.ALLOCATED, MappingState.MAPPED),
    (MappingState.ALLOCATED, MappingState.RELEASED),
    (MappingState.MAPPED, MappingState.ACTIVE),
    (MappingState.MAPPED, MappingState.INVALIDATED),
    (MappingState.MAPPED, MappingState.UNMAPPED),
    (MappingState.ACTIVE, MappingState.INVALIDATED),
    (MappingState.INVALIDATED, MappingState.MAPPED),
    (MappingState.INVALIDATED, MappingState.UNMAPPED),
    (MappingState.UNMAPPED, MappingState.MAPPED),
    (MappingState.UNMAPPED, MappingState.RELEASED),
}


@dataclass(frozen=True)
class MappingTransition:
    source: MappingState
    target: MappingState
    address: int
    confidence: Confidence
    evidence: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.source, MappingState) or not isinstance(self.target, MappingState):
            raise TypeError("mapping transition endpoints must be MappingState values")
        if (self.source, self.target) not in _ALLOWED_MAPPING_TRANSITIONS:
            raise ValueError(
                f"illegal mapping transition: {self.source.value} -> {self.target.value}"
            )
        if not isinstance(self.address, int) or isinstance(self.address, bool) or self.address < 0:
            raise ValueError("address must be a non-negative integer")
        if not isinstance(self.confidence, Confidence):
            raise TypeError("confidence must be a Confidence")
        if not isinstance(self.evidence, tuple) or any(
            not isinstance(item, str) or not item.strip() for item in self.evidence
        ):
            raise ValueError("evidence must contain non-empty strings")

    def to_dict(self) -> dict[str, Any]:
        return {
            "source": self.source.value,
            "target": self.target.value,
            "address": self.address,
            "confidence": self.confidence.value,
            "evidence": list(self.evidence),
        }


@dataclass(frozen=True)
class MappingLifecycleGraph:
    """An observed, ordered path through the validated mapping state graph."""

    mapping_id: str
    initial_state: MappingState
    transitions: tuple[MappingTransition, ...]

    def __post_init__(self) -> None:
        _require_text("mapping_id", self.mapping_id)
        if not isinstance(self.initial_state, MappingState):
            raise TypeError("initial_state must be a MappingState")
        if not isinstance(self.transitions, tuple):
            raise TypeError("transitions must be a tuple")
        if any(not isinstance(item, MappingTransition) for item in self.transitions):
            raise ValueError("transitions must contain MappingTransition records")
        expected = self.initial_state
        for transition in self.transitions:
            if transition.source is not expected:
                raise ValueError(
                    "mapping transition path is not contiguous: "
                    f"expected {expected.value}, got {transition.source.value}"
                )
            expected = transition.target

    @property
    def final_state(self) -> MappingState:
        if not self.transitions:
            return self.initial_state
        return self.transitions[-1].target

    @property
    def complete(self) -> bool:
        return (
            self.initial_state is MappingState.ALLOCATED
            and self.final_state is MappingState.RELEASED
            and bool(self.transitions)
            and all(item.confidence is not Confidence.NONE for item in self.transitions)
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "mapping_id": self.mapping_id,
            "initial_state": self.initial_state.value,
            "transitions": [transition.to_dict() for transition in self.transitions],
            "final_state": self.final_state.value,
            "complete": self.complete,
        }

    def to_json(self) -> str:
        return _json(self.to_dict())


@dataclass(frozen=True)
class ProvenanceEdge:
    source: str
    target: str
    relation: str
    confidence: Confidence
    evidence: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        _require_text("source", self.source)
        _require_text("target", self.target)
        _require_text("relation", self.relation)
        if self.source == self.target:
            raise ValueError("provenance edge cannot be a self-loop")
        if not isinstance(self.confidence, Confidence):
            raise TypeError("confidence must be a Confidence")
        if not isinstance(self.evidence, tuple) or any(
            not isinstance(item, str) or not item.strip() for item in self.evidence
        ):
            raise ValueError("evidence must contain non-empty strings")

    def to_dict(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "target": self.target,
            "relation": self.relation,
            "confidence": self.confidence.value,
            "evidence": list(self.evidence),
        }


@dataclass(frozen=True)
class UserSinkProvenancePath:
    """A single contiguous user-origin path ending at a concrete sink."""

    path_id: str
    user_source: str
    sink: HardwareSink
    edges: tuple[ProvenanceEdge, ...]
    unresolved: tuple[str, ...] = ()
    influence: UserInfluence = UserInfluence.UNKNOWN

    def __post_init__(self) -> None:
        _require_text("path_id", self.path_id)
        _require_text("user_source", self.user_source)
        if not self.user_source.startswith("user:"):
            raise ValueError("user_source must use the user: namespace")
        if not isinstance(self.sink, HardwareSink):
            raise TypeError("sink must be a HardwareSink")
        if not isinstance(self.edges, tuple) or not self.edges:
            raise ValueError("edges must be a non-empty tuple")
        if any(not isinstance(edge, ProvenanceEdge) for edge in self.edges):
            raise ValueError("edges must contain ProvenanceEdge records")
        if not isinstance(self.influence, UserInfluence):
            raise TypeError("influence must be a UserInfluence")
        if any(not isinstance(item, str) or not item.strip() for item in self.unresolved):
            raise ValueError("unresolved entries must be non-empty strings")
        expected = self.user_source
        nodes = [expected]
        for edge in self.edges:
            if edge.source != expected:
                raise ValueError(
                    "provenance path is not contiguous: "
                    f"expected {expected}, got {edge.source}"
                )
            expected = edge.target
            nodes.append(expected)
        if expected != self.sink.sink_id:
            raise ValueError(
                f"provenance path does not terminate at sink {self.sink.sink_id}"
            )
        if len(set(nodes)) != len(nodes):
            raise ValueError("provenance path contains a cycle")

    @property
    def confidence(self) -> Confidence:
        values = [self.sink.confidence, *(edge.confidence for edge in self.edges)]
        return min(values, key=_CONFIDENCE_RANK.__getitem__)

    @property
    def complete(self) -> bool:
        return not self.unresolved and self.confidence is not Confidence.NONE

    def to_dict(self) -> dict[str, Any]:
        return {
            "path_id": self.path_id,
            "user_source": self.user_source,
            "sink": self.sink.to_dict(),
            "edges": [edge.to_dict() for edge in self.edges],
            "unresolved": list(self.unresolved),
            "influence": self.influence.value,
            "confidence": self.confidence.value,
            "complete": self.complete,
        }

    def to_json(self) -> str:
        return _json(self.to_dict())


class FunctionRelation(str, Enum):
    EXACT = "exact"
    SIMILAR = "similar"
    CHANGED = "changed"
    MISSING = "missing"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class FirmwareFunction:
    firmware_id: str
    binary_sha256: str
    function_id: str
    address: int
    size: int
    normalized_sha256: str
    features: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        _require_text("firmware_id", self.firmware_id)
        _require_text("function_id", self.function_id)
        _require_sha256("binary_sha256", self.binary_sha256)
        _require_sha256("normalized_sha256", self.normalized_sha256)
        if not isinstance(self.address, int) or isinstance(self.address, bool) or self.address < 0:
            raise ValueError("address must be a non-negative integer")
        if not isinstance(self.size, int) or isinstance(self.size, bool) or self.size <= 0:
            raise ValueError("size must be a positive integer")
        if not isinstance(self.features, tuple) or any(
            not isinstance(item, str) or not item.strip() for item in self.features
        ):
            raise ValueError("features must contain non-empty strings")

    def to_dict(self) -> dict[str, Any]:
        return {
            "firmware_id": self.firmware_id,
            "binary_sha256": self.binary_sha256,
            "function_id": self.function_id,
            "address": self.address,
            "size": self.size,
            "normalized_sha256": self.normalized_sha256,
            "features": list(self.features),
        }


@dataclass(frozen=True)
class FunctionComparison:
    comparison_id: str
    baseline: FirmwareFunction
    candidate: FirmwareFunction | None
    relation: FunctionRelation
    confidence: Confidence
    evidence: tuple[str, ...] = ()
    unresolved: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        _require_text("comparison_id", self.comparison_id)
        if not isinstance(self.baseline, FirmwareFunction):
            raise TypeError("baseline must be a FirmwareFunction")
        if self.candidate is not None and not isinstance(self.candidate, FirmwareFunction):
            raise ValueError("candidate must be a FirmwareFunction or None")
        if not isinstance(self.relation, FunctionRelation):
            raise TypeError("relation must be a FunctionRelation")
        if not isinstance(self.confidence, Confidence):
            raise TypeError("confidence must be a Confidence")
        for name, entries in (("evidence", self.evidence), ("unresolved", self.unresolved)):
            if not isinstance(entries, tuple) or any(
                not isinstance(item, str) or not item.strip() for item in entries
            ):
                raise ValueError(f"{name} must contain non-empty strings")

        if self.relation is FunctionRelation.MISSING:
            if self.candidate is not None:
                raise ValueError("MISSING comparison cannot have a candidate")
            return
        if self.candidate is None:
            raise ValueError(f"{self.relation.name} comparison requires a candidate")
        if self.baseline.firmware_id == self.candidate.firmware_id:
            raise ValueError("cross-firmware comparison requires distinct firmware ids")
        hashes_equal = self.baseline.normalized_sha256 == self.candidate.normalized_sha256
        if self.relation is FunctionRelation.EXACT and not hashes_equal:
            raise ValueError("EXACT comparison requires equal normalized hashes")
        if self.relation is FunctionRelation.CHANGED and hashes_equal:
            raise ValueError("CHANGED comparison requires different normalized hashes")

    @property
    def complete(self) -> bool:
        return (
            self.confidence is not Confidence.NONE
            and self.relation is not FunctionRelation.UNKNOWN
            and bool(self.evidence)
            and not self.unresolved
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "comparison_id": self.comparison_id,
            "baseline": self.baseline.to_dict(),
            "candidate": self.candidate.to_dict() if self.candidate is not None else None,
            "relation": self.relation.value,
            "confidence": self.confidence.value,
            "evidence": list(self.evidence),
            "unresolved": list(self.unresolved),
            "complete": self.complete,
        }

    def to_json(self) -> str:
        return _json(self.to_dict())


@dataclass(frozen=True)
class CandidateBlocker:
    blocker_id: str
    reason: str
    required_evidence: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        _require_text("blocker_id", self.blocker_id)
        _require_text("reason", self.reason)
        if not isinstance(self.required_evidence, tuple) or any(
            not isinstance(item, str) or not item.strip() for item in self.required_evidence
        ):
            raise ValueError("required_evidence must contain non-empty strings")

    def to_dict(self) -> dict[str, Any]:
        return {
            "blocker_id": self.blocker_id,
            "reason": self.reason,
            "required_evidence": list(self.required_evidence),
        }


@dataclass(frozen=True)
class BlockerResolution:
    blocker_id: str
    confidence: Confidence
    evidence: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        _require_text("blocker_id", self.blocker_id)
        if not isinstance(self.confidence, Confidence):
            raise TypeError("confidence must be a Confidence")
        if not isinstance(self.evidence, tuple) or any(
            not isinstance(item, str) or not item.strip() for item in self.evidence
        ):
            raise ValueError("evidence must contain non-empty strings")

    @property
    def resolved(self) -> bool:
        return self.confidence is not Confidence.NONE and bool(self.evidence)

    def to_dict(self) -> dict[str, Any]:
        return {
            "blocker_id": self.blocker_id,
            "confidence": self.confidence.value,
            "evidence": list(self.evidence),
            "resolved": self.resolved,
        }


@dataclass(frozen=True)
class CandidateRehydration:
    candidate_id: str
    resolved: tuple[BlockerResolution, ...]
    remaining: tuple[CandidateBlocker, ...]

    @property
    def status(self) -> str:
        return "PARKED" if self.remaining else "READY"

    def to_dict(self) -> dict[str, Any]:
        return {
            "candidate_id": self.candidate_id,
            "status": self.status,
            "resolved": [item.to_dict() for item in self.resolved],
            "remaining": [item.to_dict() for item in self.remaining],
        }

    def to_json(self) -> str:
        return _json(self.to_dict())


@dataclass(frozen=True)
class ParkedCandidate:
    candidate_id: str
    blockers: tuple[CandidateBlocker, ...]

    def __post_init__(self) -> None:
        _require_text("candidate_id", self.candidate_id)
        if not isinstance(self.blockers, tuple) or not self.blockers:
            raise ValueError("blockers must be a non-empty tuple")
        if any(not isinstance(item, CandidateBlocker) for item in self.blockers):
            raise ValueError("blockers must contain CandidateBlocker records")
        ids = [item.blocker_id for item in self.blockers]
        if len(set(ids)) != len(ids):
            raise ValueError("blocker ids must be unique")

    def rehydrate(
        self, resolutions: tuple[BlockerResolution, ...]
    ) -> CandidateRehydration:
        if not isinstance(resolutions, tuple):
            raise TypeError("resolutions must be a tuple")
        if any(not isinstance(item, BlockerResolution) for item in resolutions):
            raise ValueError("resolutions must contain BlockerResolution records")
        resolution_ids = [item.blocker_id for item in resolutions]
        if len(set(resolution_ids)) != len(resolution_ids):
            raise ValueError("resolution blocker ids must be unique")
        blocker_ids = {item.blocker_id for item in self.blockers}
        unknown = set(resolution_ids) - blocker_ids
        if unknown:
            raise ValueError(f"unknown blocker ids: {sorted(unknown)}")

        by_id = {item.blocker_id: item for item in resolutions}
        resolved = tuple(
            by_id[blocker.blocker_id]
            for blocker in self.blockers
            if blocker.blocker_id in by_id and by_id[blocker.blocker_id].resolved
        )
        remaining = tuple(
            blocker
            for blocker in self.blockers
            if blocker.blocker_id not in by_id or not by_id[blocker.blocker_id].resolved
        )
        return CandidateRehydration(self.candidate_id, resolved, remaining)

    def to_dict(self) -> dict[str, Any]:
        return {
            "candidate_id": self.candidate_id,
            "status": "PARKED",
            "blockers": [item.to_dict() for item in self.blockers],
        }

    def to_json(self) -> str:
        return _json(self.to_dict())


class DeviceOpenClassification(str, Enum):
    """Evidence-backed classification of a device's open path."""

    UNPRIVILEGED_USER = "UNPRIVILEGED_USER"
    PRIVILEGED_USER = "PRIVILEGED_USER"
    SYSTEM_PROCESS_ONLY = "SYSTEM_PROCESS_ONLY"
    AUTHID_GATED = "AUTHID_GATED"
    SESSION_GATED = "SESSION_GATED"
    UNKNOWN = "UNKNOWN"


def _require_optional_bool(name: str, value: bool | None) -> None:
    if value is not None and not isinstance(value, bool):
        raise TypeError(f"{name} must be a bool or None")


def _require_string_tuple(
    name: str,
    entries: tuple[str, ...],
    *,
    nonempty: bool = False,
) -> None:
    if not isinstance(entries, tuple):
        raise TypeError(f"{name} must be a tuple")
    if nonempty and not entries:
        raise ValueError(f"{name} must be non-empty")
    if any(not isinstance(item, str) or not item.strip() for item in entries):
        raise ValueError(f"{name} must contain non-empty strings")
    if len(set(entries)) != len(entries):
        raise ValueError(f"{name} must not contain duplicates")


@dataclass(frozen=True)
class DeviceOpenContract:
    """Offline evidence describing who can reach a device open entrypoint."""

    contract_id: str
    device: str
    entrypoint: str
    user_reachable: bool | None
    privilege_required: bool | None
    confidence: Confidence
    authid_gated: bool | None = None
    session_gated: bool | None = None
    evidence: tuple[str, ...] = ()
    unresolved: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        _require_text("contract_id", self.contract_id)
        _require_text("device", self.device)
        _require_text("entrypoint", self.entrypoint)
        _require_optional_bool("user_reachable", self.user_reachable)
        _require_optional_bool("privilege_required", self.privilege_required)
        _require_optional_bool("authid_gated", self.authid_gated)
        _require_optional_bool("session_gated", self.session_gated)
        if not isinstance(self.confidence, Confidence):
            raise TypeError("confidence must be a Confidence")
        _require_string_tuple("evidence", self.evidence)
        _require_string_tuple("unresolved", self.unresolved)

    @property
    def classification(self) -> DeviceOpenClassification:
        if (
            self.user_reachable is None
            or self.privilege_required is None
            or self.authid_gated is None
            or self.session_gated is None
            or self.confidence is Confidence.NONE
            or not self.evidence
            or self.unresolved
        ):
            return DeviceOpenClassification.UNKNOWN
        if not self.user_reachable:
            return DeviceOpenClassification.SYSTEM_PROCESS_ONLY
        if self.privilege_required:
            return DeviceOpenClassification.PRIVILEGED_USER
        if self.authid_gated:
            return DeviceOpenClassification.AUTHID_GATED
        if self.session_gated:
            return DeviceOpenClassification.SESSION_GATED
        return DeviceOpenClassification.UNPRIVILEGED_USER

    @property
    def complete(self) -> bool:
        return self.classification is not DeviceOpenClassification.UNKNOWN

    def to_dict(self) -> dict[str, Any]:
        return {
            "contract_id": self.contract_id,
            "device": self.device,
            "entrypoint": self.entrypoint,
            "user_reachable": self.user_reachable,
            "privilege_required": self.privilege_required,
            "authid_gated": self.authid_gated,
            "session_gated": self.session_gated,
            "confidence": self.confidence.value,
            "evidence": sorted(self.evidence),
            "unresolved": sorted(self.unresolved),
            "classification": self.classification.value,
            "complete": self.complete,
        }

    def to_json(self) -> str:
        return _json(self.to_dict())


@dataclass(frozen=True)
class CommandAuthorizationContract:
    """Offline evidence for authorization checks on one device command."""

    contract_id: str
    device_open_contract_id: str
    command_id: int
    handler: str
    requires_authorization: bool | None
    authorization_checks: tuple[str, ...] = ()
    confidence: Confidence = Confidence.NONE
    evidence: tuple[str, ...] = ()
    unresolved: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        _require_text("contract_id", self.contract_id)
        _require_text("device_open_contract_id", self.device_open_contract_id)
        _require_text("handler", self.handler)
        if (
            not isinstance(self.command_id, int)
            or isinstance(self.command_id, bool)
            or self.command_id < 0
        ):
            raise ValueError("command_id must be a non-negative integer")
        _require_optional_bool("requires_authorization", self.requires_authorization)
        _require_string_tuple("authorization_checks", self.authorization_checks)
        _require_string_tuple("evidence", self.evidence)
        _require_string_tuple("unresolved", self.unresolved)
        if not isinstance(self.confidence, Confidence):
            raise TypeError("confidence must be a Confidence")
        if self.requires_authorization is True and not self.authorization_checks:
            raise ValueError(
                "authorization_checks are required when authorization is enforced"
            )
        if self.requires_authorization is not True and self.authorization_checks:
            raise ValueError("authorization_checks require requires_authorization=True")

    @property
    def classification(self) -> str:
        if (
            self.requires_authorization is None
            or self.confidence is Confidence.NONE
            or not self.evidence
            or self.unresolved
        ):
            return "unknown"
        if self.requires_authorization:
            return "authorization_enforced"
        return "authorization_absent"

    @property
    def complete(self) -> bool:
        return self.classification != "unknown"

    def to_dict(self) -> dict[str, Any]:
        return {
            "contract_id": self.contract_id,
            "device_open_contract_id": self.device_open_contract_id,
            "command_id": self.command_id,
            "handler": self.handler,
            "requires_authorization": self.requires_authorization,
            "authorization_checks": sorted(self.authorization_checks),
            "confidence": self.confidence.value,
            "evidence": sorted(self.evidence),
            "unresolved": sorted(self.unresolved),
            "classification": self.classification,
            "complete": self.complete,
        }

    def to_json(self) -> str:
        return _json(self.to_dict())


@dataclass(frozen=True)
class FieldContract:
    """Location, influence, and validation evidence for a structured field."""

    field_id: str
    offset: int
    width: int
    influence: UserInfluence
    validators: tuple[str, ...] = ()
    confidence: Confidence = Confidence.NONE
    evidence: tuple[str, ...] = ()
    unresolved: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        _require_text("field_id", self.field_id)
        if (
            not isinstance(self.offset, int)
            or isinstance(self.offset, bool)
            or self.offset < 0
        ):
            raise ValueError("offset must be a non-negative integer")
        if (
            not isinstance(self.width, int)
            or isinstance(self.width, bool)
            or self.width <= 0
        ):
            raise ValueError("width must be a positive integer")
        if not isinstance(self.influence, UserInfluence):
            raise TypeError("influence must be a UserInfluence")
        if not isinstance(self.confidence, Confidence):
            raise TypeError("confidence must be a Confidence")
        _require_string_tuple("validators", self.validators)
        _require_string_tuple("evidence", self.evidence)
        _require_string_tuple("unresolved", self.unresolved)

    @property
    def complete(self) -> bool:
        return (
            self.influence is not UserInfluence.UNKNOWN
            and self.confidence is not Confidence.NONE
            and bool(self.evidence)
            and not self.unresolved
        )

    @property
    def validated(self) -> bool:
        return self.complete and bool(self.validators)

    def to_dict(self) -> dict[str, Any]:
        return {
            "field_id": self.field_id,
            "offset": self.offset,
            "width": self.width,
            "influence": self.influence.value,
            "validators": sorted(self.validators),
            "confidence": self.confidence.value,
            "evidence": sorted(self.evidence),
            "unresolved": sorted(self.unresolved),
            "complete": self.complete,
            "validated": self.validated,
        }

    def to_json(self) -> str:
        return _json(self.to_dict())


class SnapshotSemantics(str, Enum):
    """How a consumer observes a field that may change across processors."""

    SNAPSHOT_SAFE = "SNAPSHOT_SAFE"
    REREAD_AFTER_VALIDATE = "REREAD_AFTER_VALIDATE"
    MIXED = "MIXED"
    UNKNOWN = "UNKNOWN"


@dataclass(frozen=True)
class CrossProcessorFieldContract:
    """Evidence for a field transferred between distinct processors."""

    contract_id: str
    field: FieldContract
    producer: str
    consumer: str
    snapshot_semantics: SnapshotSemantics
    confidence: Confidence
    evidence: tuple[str, ...] = ()
    unresolved: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        _require_text("contract_id", self.contract_id)
        if not isinstance(self.field, FieldContract):
            raise TypeError("field must be a FieldContract")
        _require_text("producer", self.producer)
        _require_text("consumer", self.consumer)
        if self.producer == self.consumer:
            raise ValueError("producer and consumer must be distinct")
        if not isinstance(self.snapshot_semantics, SnapshotSemantics):
            raise TypeError("snapshot_semantics must be a SnapshotSemantics")
        if not isinstance(self.confidence, Confidence):
            raise TypeError("confidence must be a Confidence")
        _require_string_tuple("evidence", self.evidence)
        _require_string_tuple("unresolved", self.unresolved)

    @property
    def complete(self) -> bool:
        return (
            self.field.complete
            and self.snapshot_semantics is not SnapshotSemantics.UNKNOWN
            and self.confidence is not Confidence.NONE
            and bool(self.evidence)
            and not self.unresolved
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "contract_id": self.contract_id,
            "field": self.field.to_dict(),
            "producer": self.producer,
            "consumer": self.consumer,
            "snapshot_semantics": self.snapshot_semantics.value,
            "confidence": self.confidence.value,
            "evidence": sorted(self.evidence),
            "unresolved": sorted(self.unresolved),
            "complete": self.complete,
        }

    def to_json(self) -> str:
        return _json(self.to_dict())


@dataclass(frozen=True)
class SessionBindingContract:
    """Evidence tying command handling state to one device-open session."""

    contract_id: str
    device_open_contract_id: str
    command_contract_ids: tuple[str, ...]
    binding_fields: tuple[str, ...]
    per_open_state: bool | None
    confidence: Confidence
    evidence: tuple[str, ...] = ()
    unresolved: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        _require_text("contract_id", self.contract_id)
        _require_text("device_open_contract_id", self.device_open_contract_id)
        _require_string_tuple(
            "command_contract_ids", self.command_contract_ids, nonempty=True
        )
        _require_string_tuple("binding_fields", self.binding_fields)
        _require_optional_bool("per_open_state", self.per_open_state)
        if not isinstance(self.confidence, Confidence):
            raise TypeError("confidence must be a Confidence")
        _require_string_tuple("evidence", self.evidence)
        _require_string_tuple("unresolved", self.unresolved)
        if self.per_open_state is True and not self.binding_fields:
            raise ValueError("binding_fields are required for per-open state")
        if self.per_open_state is not True and self.binding_fields:
            raise ValueError("binding_fields require per_open_state=True")

    @property
    def complete(self) -> bool:
        return (
            self.per_open_state is not None
            and self.confidence is not Confidence.NONE
            and bool(self.evidence)
            and not self.unresolved
        )

    @property
    def bound(self) -> bool:
        return self.complete and self.per_open_state is True

    def to_dict(self) -> dict[str, Any]:
        return {
            "contract_id": self.contract_id,
            "device_open_contract_id": self.device_open_contract_id,
            "command_contract_ids": sorted(self.command_contract_ids),
            "binding_fields": sorted(self.binding_fields),
            "per_open_state": self.per_open_state,
            "confidence": self.confidence.value,
            "evidence": sorted(self.evidence),
            "unresolved": sorted(self.unresolved),
            "complete": self.complete,
            "bound": self.bound,
        }

    def to_json(self) -> str:
        return _json(self.to_dict())


class RegisterSpaceClass(str, Enum):
    CONTEXT = "CONTEXT"
    UCONFIG = "UCONFIG"
    CONFIG = "CONFIG"
    PRIVILEGED = "PRIVILEGED"
    UNKNOWN = "UNKNOWN"


class ContextRestoreBehavior(str, Enum):
    PER_CONTEXT_RESTORED = "PER_CONTEXT_RESTORED"
    GLOBAL_PERSISTENT = "GLOBAL_PERSISTENT"
    GLOBAL_UNTIL_OVERWRITTEN = "GLOBAL_UNTIL_OVERWRITTEN"
    RESET_ON_SWITCH = "RESET_ON_SWITCH"
    UNKNOWN = "UNKNOWN"


@dataclass(frozen=True)
class RegisterPolicyContract:
    """Evidence-backed register-space, role, and context-lifetime contract."""

    contract_id: str
    register_index: int
    register_name: str
    register_role: str
    space_class: RegisterSpaceClass
    shadowed: bool | None
    restore_behavior: ContextRestoreBehavior
    register_name_confidence: Confidence = Confidence.NONE
    register_role_confidence: Confidence = Confidence.NONE
    globality_confidence: Confidence = Confidence.NONE
    context_restore_confidence: Confidence = Confidence.NONE
    evidence: tuple[str, ...] = ()
    unresolved: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        _require_text("contract_id", self.contract_id)
        _require_text("register_name", self.register_name)
        _require_text("register_role", self.register_role)
        if not isinstance(self.register_index, int) or isinstance(self.register_index, bool) or self.register_index < 0:
            raise ValueError("register_index must be a non-negative integer")
        if not isinstance(self.space_class, RegisterSpaceClass):
            raise TypeError("space_class must be a RegisterSpaceClass")
        _require_optional_bool("shadowed", self.shadowed)
        if not isinstance(self.restore_behavior, ContextRestoreBehavior):
            raise TypeError("restore_behavior must be a ContextRestoreBehavior")
        for name, value in (("register_name_confidence", self.register_name_confidence), ("register_role_confidence", self.register_role_confidence), ("globality_confidence", self.globality_confidence), ("context_restore_confidence", self.context_restore_confidence)):
            if not isinstance(value, Confidence):
                raise TypeError(f"{name} must be a Confidence")
        _require_string_tuple("evidence", self.evidence)
        _require_string_tuple("unresolved", self.unresolved)

    @property
    def complete(self) -> bool:
        return self.space_class is not RegisterSpaceClass.UNKNOWN and self.shadowed is not None and self.restore_behavior is not ContextRestoreBehavior.UNKNOWN and all(item is not Confidence.NONE for item in (self.register_name_confidence, self.register_role_confidence, self.globality_confidence, self.context_restore_confidence)) and bool(self.evidence) and not self.unresolved

    def to_dict(self) -> dict[str, Any]:
        return {"contract_id": self.contract_id, "register_index": self.register_index, "register_name": self.register_name, "register_role": self.register_role, "space_class": self.space_class.value, "shadowed": self.shadowed, "restore_behavior": self.restore_behavior.value, "register_name_confidence": self.register_name_confidence.value, "register_role_confidence": self.register_role_confidence.value, "globality_confidence": self.globality_confidence.value, "context_restore_confidence": self.context_restore_confidence.value, "evidence": sorted(self.evidence), "unresolved": sorted(self.unresolved), "complete": self.complete}

    def to_json(self) -> str:
        return _json(self.to_dict())


@dataclass(frozen=True)
class CrossContextImpactContract:
    """Whether a register write by one GPU context reaches another context."""

    contract_id: str
    register_policy: RegisterPolicyContract
    writer_context: str
    consumer_context: str
    affected_scope: str
    effects: tuple[str, ...]
    crosses_contexts: bool | None
    recovery: tuple[str, ...] = ()
    confidence: Confidence = Confidence.NONE
    evidence: tuple[str, ...] = ()
    unresolved: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        _require_text("contract_id", self.contract_id)
        if not isinstance(self.register_policy, RegisterPolicyContract):
            raise TypeError("register_policy must be a RegisterPolicyContract")
        _require_text("writer_context", self.writer_context)
        _require_text("consumer_context", self.consumer_context)
        _require_text("affected_scope", self.affected_scope)
        if self.writer_context == self.consumer_context:
            raise ValueError("writer_context and consumer_context must be distinct")
        _require_string_tuple("effects", self.effects, nonempty=True)
        _require_optional_bool("crosses_contexts", self.crosses_contexts)
        _require_string_tuple("recovery", self.recovery)
        if not isinstance(self.confidence, Confidence):
            raise TypeError("confidence must be a Confidence")
        _require_string_tuple("evidence", self.evidence)
        _require_string_tuple("unresolved", self.unresolved)

    @property
    def complete(self) -> bool:
        return self.register_policy.complete and self.crosses_contexts is not None and self.confidence is not Confidence.NONE and bool(self.evidence) and not self.unresolved

    @property
    def classification(self) -> str:
        if not self.complete:
            return "POTENTIAL_CROSS_CONTEXT"
        return "CONFIRMED_CROSS_CONTEXT" if self.crosses_contexts else "CONTAINED_PER_CONTEXT"

    def to_dict(self) -> dict[str, Any]:
        return {"contract_id": self.contract_id, "register_policy": self.register_policy.to_dict(), "writer_context": self.writer_context, "consumer_context": self.consumer_context, "affected_scope": self.affected_scope, "effects": sorted(self.effects), "crosses_contexts": self.crosses_contexts, "recovery": sorted(self.recovery), "confidence": self.confidence.value, "evidence": sorted(self.evidence), "unresolved": sorted(self.unresolved), "classification": self.classification, "complete": self.complete}

    def to_json(self) -> str:
        return _json(self.to_dict())
