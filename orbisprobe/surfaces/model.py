from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any


class SurfaceType(str, Enum):
    SVM_HV = "SVM_HV"
    IOMMU_DMA = "IOMMU_DMA"
    SAMU_SECURE = "SAMU_SECURE"
    MEMORY_CONTROLLER = "MEMORY_CONTROLLER"
    SMM_SMI = "SMM_SMI"
    UNKNOWN_PRIVILEGED = "UNKNOWN_PRIVILEGED"


class SurfaceStatus(str, Enum):
    CONFIRMED = "CONFIRMED"
    SUPPORTED = "SUPPORTED"
    INFERRED = "INFERRED"
    UNKNOWN = "UNKNOWN"
    DISPROVED = "DISPROVED"
    REVIDIERT = "REVIDIERT"


class Confidence(str, Enum):
    NONE = "NONE"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


class BoundaryType(str, Enum):
    CPU_PRIVILEGE = "CPU_PRIVILEGE"
    DMA_TRANSLATION = "DMA_TRANSLATION"
    CROSS_PROCESSOR = "CROSS_PROCESSOR"
    MEMORY_MAP = "MEMORY_MAP"
    SMM = "SMM"
    UNKNOWN = "UNKNOWN"


@dataclass(frozen=True)
class Evidence:
    kind: str
    detail: str
    address: int | None = None
    function: str | None = None
    raw: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class SurfaceFinding:
    surface_id: str
    surface_type: SurfaceType
    binary: str
    binary_sha256: str
    architecture: str
    function: str | None
    address: int | None
    source: list[str]
    validation: list[str]
    boundary: BoundaryType
    consumer: list[str]
    observable: list[str]
    confidence: Confidence
    evidence: list[Evidence]
    unknowns: list[str]
    status: SurfaceStatus
    boundary_type: str = ""
    candidate_priority: str = "P4"
    candidate_score: float = 0.0
    open_chains: list[str] = field(default_factory=list)
    classification: str = ""

    @classmethod
    def create(
        cls,
        *,
        surface_type: SurfaceType,
        binary: str,
        binary_sha256: str,
        architecture: str,
        function: str | None,
        address: int | None,
        source: list[str],
        validation: list[str],
        boundary: BoundaryType,
        consumer: list[str],
        observable: list[str],
        confidence: Confidence,
        evidence: list[Evidence],
        unknowns: list[str],
        status: SurfaceStatus,
        boundary_type: str = "",
        candidate_priority: str = "P4",
        candidate_score: float = 0.0,
        open_chains: list[str] | None = None,
        classification: str = "",
    ) -> SurfaceFinding:
        identity = {
            "surface_type": surface_type.value,
            "binary_sha256": binary_sha256,
            "architecture": architecture,
            "function": function,
            "address": address,
            "evidence": [item.to_dict() for item in evidence],
        }
        digest = hashlib.sha256(
            json.dumps(identity, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()[:16]
        return cls(
            surface_id=f"SURF-{surface_type.value}-{digest}",
            surface_type=surface_type,
            binary=binary,
            binary_sha256=binary_sha256,
            architecture=architecture,
            function=function,
            address=address,
            source=list(source),
            validation=list(validation),
            boundary=boundary,
            consumer=list(consumer),
            observable=list(observable),
            confidence=confidence,
            evidence=list(evidence),
            unknowns=list(unknowns),
            status=status,
            boundary_type=boundary_type,
            candidate_priority=candidate_priority,
            candidate_score=float(candidate_score),
            open_chains=list(open_chains or []),
            classification=classification,
        )

    def creation_fields(self) -> dict[str, Any]:
        return {
            "surface_type": self.surface_type,
            "binary": self.binary,
            "binary_sha256": self.binary_sha256,
            "architecture": self.architecture,
            "function": self.function,
            "address": self.address,
            "source": list(self.source),
            "validation": list(self.validation),
            "boundary": self.boundary,
            "consumer": list(self.consumer),
            "observable": list(self.observable),
            "confidence": self.confidence,
            "evidence": list(self.evidence),
            "unknowns": list(self.unknowns),
            "status": self.status,
            "boundary_type": self.boundary_type,
            "candidate_priority": self.candidate_priority,
            "candidate_score": self.candidate_score,
            "open_chains": list(self.open_chains),
            "classification": self.classification,
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "surface_id": self.surface_id,
            "surface_type": self.surface_type.value,
            "binary": self.binary,
            "binary_sha256": self.binary_sha256,
            "architecture": self.architecture,
            "function": self.function,
            "address": self.address,
            "source": list(self.source),
            "validation": list(self.validation),
            "boundary": self.boundary.value,
            "consumer": list(self.consumer),
            "observable": list(self.observable),
            "confidence": self.confidence.value,
            "evidence": [item.to_dict() for item in self.evidence],
            "unknowns": list(self.unknowns),
            "status": self.status.value,
            "boundary_type": self.boundary_type,
            "candidate_priority": self.candidate_priority,
            "candidate_score": self.candidate_score,
            "open_chains": list(self.open_chains),
            "classification": self.classification,
        }
