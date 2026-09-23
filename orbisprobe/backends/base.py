from __future__ import annotations

import hashlib
import inspect
import json
import math
from abc import ABC, abstractmethod
from dataclasses import asdict, dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any


class BackendCapability(str, Enum):
    CFG = "CFG"
    SSA = "SSA"
    DATAFLOW = "DATAFLOW"
    SYMBOLIC = "SYMBOLIC"
    TAINT = "TAINT"
    EMULATION = "EMULATION"
    CALLGRAPH = "CALLGRAPH"
    MEMORY_MODEL = "MEMORY_MODEL"
    DECOMPILER = "DECOMPILER"
    HEADLESS = "HEADLESS"
    # M2-B dynamic-analysis capabilities
    DYNAMIC_SYMBOLIC = "DYNAMIC_SYMBOLIC"
    REGISTER_TRACE = "REGISTER_TRACE"
    MEMORY_TRACE = "MEMORY_TRACE"
    BRANCH_TRACE = "BRANCH_TRACE"
    CALL_STUBS = "CALL_STUBS"
    SNAPSHOT = "SNAPSHOT"
    CONCRETE_EXECUTION = "CONCRETE_EXECUTION"


class BackendStatus(str, Enum):
    COMPLETED = "COMPLETED"
    BACKEND_UNAVAILABLE = "BACKEND_UNAVAILABLE"
    ANALYSIS_INCOMPLETE = "ANALYSIS_INCOMPLETE"
    TIMEOUT = "TIMEOUT"
    RESOURCE_LIMIT = "RESOURCE_LIMIT"
    PARTIAL = "PARTIAL"
    ERROR = "ERROR"


#: Provenance classes, ordered from weakest to strongest evidence modality. A backend may only use
#: the offline classes; real-target runtime evidence is collected by OrbisProbe itself.
class EvidenceProvenance(str, Enum):
    STATIC = "STATIC"
    SYMBOLIC = "SYMBOLIC"
    EMULATED = "EMULATED"
    REAL_RUNTIME = "REAL_RUNTIME"


#: Source classes a backend may attach to its own evidence. `runtime_real` is deliberately absent:
#: it is reserved for OrbisProbe's own runtime-collection channel and can never be declared by
#: external backend output.
BACKEND_SOURCE_CLASSES = frozenset(
    {"static", "symbolic", "emulated", "inferred", "unattributed", "fixture"}
)
RUNTIME_SOURCE_CLASS = "runtime_real"
SOURCE_CLASS_BY_PROVENANCE = {
    EvidenceProvenance.STATIC: "static",
    EvidenceProvenance.SYMBOLIC: "symbolic",
    EvidenceProvenance.EMULATED: "emulated",
    EvidenceProvenance.REAL_RUNTIME: RUNTIME_SOURCE_CLASS,
}
OFFLINE_PROVENANCE = frozenset(
    {EvidenceProvenance.STATIC, EvidenceProvenance.SYMBOLIC, EvidenceProvenance.EMULATED}
)


def ensure_json_domain(value: Any, path: str = "value") -> None:
    """Reject values that are not representable in strict JSON.

    Backends are external and untrusted: NaN, Infinity, sets, and other non-JSON types must be
    rejected at the adapter boundary instead of breaking canonicalisation later (``allow_nan=False``
    sinks in the cache and consensus engine raise on them).
    """

    if value is None or isinstance(value, (str, bool, int)):
        return
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError(f"{path} must be a finite JSON number")
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise TypeError(f"{path} keys must be strings")
            ensure_json_domain(item, f"{path}.{key}")
        return
    if isinstance(value, (list, tuple)):
        for index, item in enumerate(value):
            ensure_json_domain(item, f"{path}[{index}]")
        return
    raise ValueError(f"{path} has unsupported type {type(value).__name__}")


@dataclass(frozen=True)
class ResourceLimits:
    timeout_seconds: int = 60
    memory_mb: int = 2048
    state_ceiling: int = 128
    maximum_function_count: int = 4096
    maximum_graph_size: int = 100_000
    maximum_steps: int = 100_000

    def __post_init__(self) -> None:
        for name, value in asdict(self).items():
            if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
                raise ValueError(f"{name} must be a positive integer")
        if self.timeout_seconds > 300:
            raise ValueError("timeout_seconds must not exceed 300")
        if self.memory_mb > 32_768:
            raise ValueError("memory_mb must not exceed 32768")

    def to_dict(self) -> dict[str, int]:
        return asdict(self)


@dataclass(frozen=True)
class BackendIdentity:
    name: str
    version: str
    independence_family: str
    capabilities: frozenset[BackendCapability]
    implementation: str | None = None

    def __post_init__(self) -> None:
        if not self.name or not self.version or not self.independence_family:
            raise ValueError("backend identity fields must not be empty")

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "version": self.version,
            "independence_family": self.independence_family,
            "capabilities": sorted(item.value for item in self.capabilities),
            "implementation": self.implementation,
        }

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> BackendIdentity:
        return cls(
            name=str(raw["name"]),
            version=str(raw["version"]),
            independence_family=str(raw["independence_family"]),
            capabilities=frozenset(BackendCapability(item) for item in raw.get("capabilities", [])),
            implementation=raw.get("implementation"),
        )


@dataclass(frozen=True)
class BackendEvidence:
    kind: str
    subject: str
    value: Any
    address: int | None = None
    confidence: str = "SUPPORTED"
    provenance: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        allowed = {"SUPPORTED", "INFERRED", "UNKNOWN", "DISPROVED"}
        if self.confidence not in allowed:
            raise ValueError(
                "backend evidence confidence must be atomic and cannot set final consensus status"
            )
        ensure_json_domain(self.value, "evidence.value")
        ensure_json_domain(self.provenance, "evidence.provenance")
        if self.address is not None and (
            not isinstance(self.address, int) or isinstance(self.address, bool)
        ):
            raise TypeError("evidence.address must be an integer or None")

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> BackendEvidence:
        if not isinstance(raw, dict):
            raise TypeError("backend evidence entry must be an object")
        address = raw.get("address")
        if address is not None and (
            not isinstance(address, int) or isinstance(address, bool)
        ):
            raise TypeError("backend evidence address must be an integer or null")
        provenance = dict(raw.get("provenance", {}))
        source_class = provenance.get("source_class", "static")
        if source_class not in BACKEND_SOURCE_CLASSES:
            raise ValueError(
                "backend evidence may not declare source_class "
                f"{source_class!r}; runtime evidence is collected by OrbisProbe itself"
            )
        return cls(
            kind=str(raw["kind"]),
            subject=str(raw["subject"]),
            value=raw.get("value"),
            address=address,
            confidence=str(raw.get("confidence", "SUPPORTED")),
            provenance=provenance,
        )


@dataclass
class BackendResult:
    identity: BackendIdentity
    status: BackendStatus
    data: dict[str, Any] = field(default_factory=dict)
    evidence: list[BackendEvidence] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    unknowns: list[str] = field(default_factory=list)
    partial: bool = False
    metrics: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def completed(
        cls,
        identity: BackendIdentity,
        data: dict[str, Any] | None = None,
        evidence: list[BackendEvidence] | None = None,
        metrics: dict[str, Any] | None = None,
    ) -> BackendResult:
        return cls(
            identity=identity,
            status=BackendStatus.COMPLETED,
            data=data or {},
            evidence=evidence or [],
            metrics=metrics or {},
        )

    @classmethod
    def unavailable(cls, identity: BackendIdentity, reason: str) -> BackendResult:
        return cls(identity=identity, status=BackendStatus.BACKEND_UNAVAILABLE, errors=[reason])

    @classmethod
    def incomplete(
        cls,
        identity: BackendIdentity,
        reason: str,
        data: dict[str, Any] | None = None,
    ) -> BackendResult:
        return cls(
            identity=identity,
            status=BackendStatus.ANALYSIS_INCOMPLETE,
            errors=[reason],
            data=data or {},
            partial=True,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "backend": self.identity.to_dict(),
            "status": self.status.value,
            "data": self.data,
            "evidence": [item.to_dict() for item in self.evidence],
            "errors": self.errors,
            "unknowns": self.unknowns,
            "partial": self.partial,
            "metrics": self.metrics,
        }

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> BackendResult:
        return cls(
            identity=BackendIdentity.from_dict(raw["backend"]),
            status=BackendStatus(raw["status"]),
            data=dict(raw.get("data", {})),
            evidence=[BackendEvidence.from_dict(item) for item in raw.get("evidence", [])],
            errors=[str(item) for item in raw.get("errors", [])],
            unknowns=[str(item) for item in raw.get("unknowns", [])],
            partial=bool(raw.get("partial", False)),
            metrics=dict(raw.get("metrics", {})),
        )


class AnalysisBackend(ABC):
    identity: BackendIdentity

    def __init__(self, limits: ResourceLimits | None = None) -> None:
        self.limits = limits or ResourceLimits()

    @abstractmethod
    def availability(self) -> BackendResult: ...

    @abstractmethod
    def version(self) -> str: ...

    @abstractmethod
    def analyze_function(self, request: dict[str, Any]) -> BackendResult: ...

    @abstractmethod
    def recover_cfg(self, request: dict[str, Any]) -> BackendResult: ...

    @abstractmethod
    def trace_value(self, request: dict[str, Any]) -> BackendResult: ...

    @abstractmethod
    def find_definitions(self, request: dict[str, Any]) -> BackendResult: ...

    @abstractmethod
    def find_consumers(self, request: dict[str, Any]) -> BackendResult: ...

    @abstractmethod
    def resolve_call_arguments(self, request: dict[str, Any]) -> BackendResult: ...

    @abstractmethod
    def evaluate_branch_constraints(self, request: dict[str, Any]) -> BackendResult: ...

    @abstractmethod
    def analyze_memory_access(self, request: dict[str, Any]) -> BackendResult: ...

    def run_harness(self, request: dict[str, Any]) -> BackendResult:
        """Execute a validated M2-B function harness.

        Static-analysis backends do not implement this; the default is a structured
        ``ANALYSIS_INCOMPLETE`` rather than an exception, so a mixed backend list still runs.
        """

        return BackendResult(
            identity=self.identity,
            status=BackendStatus.ANALYSIS_INCOMPLETE,
            errors=[f"backend {self.identity.name} does not implement harness execution"],
            partial=True,
        )

    def dynamic_evidence(
        self, harness: Any, binary_sha256: str, result: BackendResult
    ) -> Any | None:
        """Return a :class:`~orbisprobe.backends.dynamic.DynamicEvidence` record, if supported."""

        return None

    def export_evidence(self, result: BackendResult) -> str:
        return json.dumps(result.to_dict(), sort_keys=True, separators=(",", ":"))

    def cache_fingerprint(self) -> str:
        files = [Path(inspect.getfile(type(self)))]
        worker = getattr(self, "worker", None)
        if worker is not None:
            files.append(Path(worker))
        script_dir = getattr(self, "script_dir", None)
        if script_dir is not None and Path(script_dir).is_dir():
            files.extend(sorted(path for path in Path(script_dir).rglob("*") if path.is_file()))
        digest = hashlib.sha256()
        for path in files:
            digest.update(path.name.encode("utf-8"))
            digest.update(path.read_bytes())
        return digest.hexdigest()
