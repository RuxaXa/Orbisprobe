from __future__ import annotations

import hashlib
import inspect
import json
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


class BackendStatus(str, Enum):
    COMPLETED = "COMPLETED"
    BACKEND_UNAVAILABLE = "BACKEND_UNAVAILABLE"
    ANALYSIS_INCOMPLETE = "ANALYSIS_INCOMPLETE"
    TIMEOUT = "TIMEOUT"
    RESOURCE_LIMIT = "RESOURCE_LIMIT"
    PARTIAL = "PARTIAL"
    ERROR = "ERROR"


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

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> BackendEvidence:
        return cls(
            kind=str(raw["kind"]),
            subject=str(raw["subject"]),
            value=raw.get("value"),
            address=raw.get("address"),
            confidence=str(raw.get("confidence", "SUPPORTED")),
            provenance=dict(raw.get("provenance", {})),
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
