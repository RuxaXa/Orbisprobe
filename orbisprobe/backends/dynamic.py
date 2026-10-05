"""M2-B dynamic evidence model.

A dynamic run produces a compact, hash-bound record instead of a full instruction trace. Large
traces stay outside the main evidence payload and are referenced by SHA-256, so consensus and
reports never have to carry (or trust) a multi-megabyte dump.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

from .base import BackendResult, EvidenceProvenance, ensure_json_domain

EXECUTION_STATUSES = frozenset(
    {
        "COMPLETED",
        "PARTIAL",
        "ANALYSIS_INCOMPLETE",
        "RESOURCE_LIMIT",
        "TIMEOUT",
        "ERROR",
    }
)

MAX_INLINE_TRACE_ENTRIES = 64


@dataclass(frozen=True)
class DynamicEvidence:
    backend: str
    backend_version: str
    binary_sha256: str
    harness_sha256: str
    function: int
    input_sha256: str
    execution_status: str
    instructions_executed: int
    branches: list[dict[str, Any]] = field(default_factory=list)
    calls: list[dict[str, Any]] = field(default_factory=list)
    stubs_used: list[dict[str, Any]] = field(default_factory=list)
    taint_flows: list[dict[str, Any]] = field(default_factory=list)
    memory_reads: list[dict[str, Any]] = field(default_factory=list)
    memory_writes: list[dict[str, Any]] = field(default_factory=list)
    memory_violations: list[dict[str, Any]] = field(default_factory=list)
    return_value: int | None = None
    stop_reason: str = "UNKNOWN"
    trace_sha256: str | None = None
    trace_entry_count: int = 0
    trace_truncated: bool = False
    symbolic_inputs: list[str] = field(default_factory=list)
    path_constraints: list[str] = field(default_factory=list)
    unknowns: list[str] = field(default_factory=list)
    provenance: str = EvidenceProvenance.EMULATED.value

    def __post_init__(self) -> None:
        if self.execution_status not in EXECUTION_STATUSES:
            raise ValueError(f"unknown execution status {self.execution_status!r}")
        if self.provenance not in {
            EvidenceProvenance.EMULATED.value,
            EvidenceProvenance.SYMBOLIC.value,
            EvidenceProvenance.STATIC.value,
        }:
            raise ValueError(
                "dynamic evidence may only claim an offline provenance class; real-target runtime "
                "evidence is collected by OrbisProbe itself"
            )
        for name in ("binary_sha256", "harness_sha256", "input_sha256"):
            value = getattr(self, name)
            if len(value) != 64 or any(ch not in "0123456789abcdef" for ch in value):
                raise ValueError(f"{name} must be 64 lowercase hexadecimal characters")
        ensure_json_domain(self.to_payload(), "dynamic_evidence")

    def to_payload(self) -> dict[str, Any]:
        payload = asdict(self)
        # Large traces are never inlined; the reference hash carries them.
        payload["branches"] = self.branches[:MAX_INLINE_TRACE_ENTRIES]
        payload["calls"] = self.calls[:MAX_INLINE_TRACE_ENTRIES]
        payload["memory_reads"] = self.memory_reads[:MAX_INLINE_TRACE_ENTRIES]
        payload["memory_writes"] = self.memory_writes[:MAX_INLINE_TRACE_ENTRIES]
        payload["taint_flows"] = self.taint_flows[:MAX_INLINE_TRACE_ENTRIES]
        payload["counts"] = {
            "branches": len(self.branches),
            "calls": len(self.calls),
            "memory_reads": len(self.memory_reads),
            "memory_writes": len(self.memory_writes),
            "taint_flows": len(self.taint_flows),
            "stubs_used": len(self.stubs_used),
        }
        return payload

    def to_dict(self) -> dict[str, Any]:
        return self.to_payload()

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> DynamicEvidence:
        if not isinstance(raw, dict):
            raise TypeError("dynamic evidence must be an object")
        payload = dict(raw)
        payload.pop("counts", None)
        known = {item.name for item in cls.__dataclass_fields__.values()}
        unknown_keys = set(payload) - known
        if unknown_keys:
            raise ValueError(f"dynamic evidence has unknown fields: {sorted(unknown_keys)}")
        return cls(**payload)


def evidence_from_result(result: BackendResult) -> list[dict[str, Any]]:
    """Atomic evidence rows a dynamic backend contributes to consensus."""

    return [item.to_dict() for item in result.evidence]
