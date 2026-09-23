from __future__ import annotations

import json
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from .base import BackendEvidence, BackendResult, BackendStatus


class ConsensusClassification(str, Enum):
    UNKNOWN = "UNKNOWN"
    SUPPORTED = "SUPPORTED"
    STRONGLY_SUPPORTED = "STRONGLY_SUPPORTED"
    CONFIRMED = "CONFIRMED"
    EVIDENCE_CONFLICT = "EVIDENCE_CONFLICT"
    DISPROVED = "DISPROVED"
    REVIDIERT = "REVIDIERT"


def _canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


@dataclass
class ConsensusClaim:
    kind: str
    subject: str
    value: Any
    classification: ConsensusClassification
    sources: list[dict[str, Any]] = field(default_factory=list)
    independent_families: list[str] = field(default_factory=list)
    conflicts: list[dict[str, Any]] = field(default_factory=list)
    unknowns: list[str] = field(default_factory=list)

    @property
    def independent_source_count(self) -> int:
        return len(self.independent_families)

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "subject": self.subject,
            "value": self.value,
            "classification": self.classification.value,
            "sources": self.sources,
            "independent_families": self.independent_families,
            "independent_source_count": self.independent_source_count,
            "conflicts": self.conflicts,
            "unknowns": self.unknowns,
        }


@dataclass
class ConsensusReport:
    claims: list[ConsensusClaim]
    backend_statuses: dict[str, str]

    def to_dict(self) -> dict[str, Any]:
        return {
            "claims": [claim.to_dict() for claim in self.claims],
            "backend_statuses": self.backend_statuses,
            "has_conflicts": any(
                claim.classification is ConsensusClassification.EVIDENCE_CONFLICT
                for claim in self.claims
            ),
        }


class ConsensusEngine:
    def __init__(self, register_cross_check_required: bool = True) -> None:
        self.register_cross_check_required = register_cross_check_required

    @staticmethod
    def _source(result: BackendResult, evidence: BackendEvidence) -> dict[str, Any]:
        return {
            "backend": result.identity.name,
            "backend_version": result.identity.version,
            "independence_family": result.identity.independence_family,
            "source_class": evidence.provenance.get("source_class", "static"),
            "confidence": evidence.confidence,
            "value": evidence.value,
            "address": evidence.address,
            "provenance": evidence.provenance,
        }

    def combine(
        self,
        results: list[BackendResult],
        available_families: set[str] | None = None,
    ) -> ConsensusReport:
        groups: dict[tuple[str, str], list[tuple[BackendResult, BackendEvidence]]] = {}
        statuses = {result.identity.name: result.status.value for result in results}
        for result in results:
            if result.status is not BackendStatus.COMPLETED:
                continue
            for evidence in result.evidence:
                groups.setdefault((evidence.kind, evidence.subject), []).append((result, evidence))

        claims: list[ConsensusClaim] = []
        for (kind, subject), entries in sorted(groups.items()):
            by_value: dict[str, list[tuple[BackendResult, BackendEvidence]]] = {}
            for result, evidence in entries:
                by_value.setdefault(_canonical(evidence.value), []).append((result, evidence))
            sources = [self._source(result, evidence) for result, evidence in entries]
            if len(by_value) > 1:
                conflicts = [
                    {
                        "value": evidence.value,
                        "backend": result.identity.name,
                        "independence_family": result.identity.independence_family,
                    }
                    for result, evidence in entries
                ]
                claims.append(
                    ConsensusClaim(
                        kind=kind,
                        subject=subject,
                        value=None,
                        classification=ConsensusClassification.EVIDENCE_CONFLICT,
                        sources=sources,
                        independent_families=sorted(
                            {result.identity.independence_family for result, _evidence in entries}
                        ),
                        conflicts=conflicts,
                        unknowns=["backend values disagree; claim cannot be promoted"],
                    )
                )
                continue

            value_entries = next(iter(by_value.values()))
            value = value_entries[0][1].value
            families = sorted(
                {result.identity.independence_family for result, _evidence in value_entries}
            )
            refutation_flags = {
                evidence.confidence == "DISPROVED" for _result, evidence in value_entries
            }
            if len(refutation_flags) > 1:
                claims.append(
                    ConsensusClaim(
                        kind=kind,
                        subject=subject,
                        value=None,
                        classification=ConsensusClassification.EVIDENCE_CONFLICT,
                        sources=sources,
                        independent_families=families,
                        conflicts=[
                            {
                                "value": evidence.value,
                                "outcome": evidence.confidence,
                                "backend": result.identity.name,
                                "independence_family": result.identity.independence_family,
                            }
                            for result, evidence in value_entries
                        ],
                        unknowns=["complete support/refutation contradiction; no majority vote"],
                    )
                )
                continue
            if refutation_flags == {True}:
                claims.append(
                    ConsensusClaim(
                        kind=kind,
                        subject=subject,
                        value=value,
                        classification=ConsensusClassification.DISPROVED,
                        sources=sources,
                        independent_families=families,
                    )
                )
                continue
            source_classes = {
                evidence.provenance.get("source_class", "static")
                for _result, evidence in value_entries
            }
            has_real_runtime = "runtime_real" in source_classes
            has_non_runtime_family = any(
                evidence.provenance.get("source_class", "static") != "runtime_real"
                for _result, evidence in value_entries
            )
            if has_real_runtime and has_non_runtime_family and len(families) >= 2:
                classification = ConsensusClassification.CONFIRMED
            elif len(families) >= 2:
                classification = ConsensusClassification.STRONGLY_SUPPORTED
            else:
                classification = ConsensusClassification.SUPPORTED

            unknowns: list[str] = []
            register_subject = subject.split("@", 1)[0].lower()
            if (
                self.register_cross_check_required
                and register_subject
                in {"rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp", "r12", "r13", "r14", "r15"}
                and len(families) < 2
                and available_families is not None
                and len(available_families) >= 2
            ):
                unknowns.append("second independent register-lifetime source required")

            claims.append(
                ConsensusClaim(
                    kind=kind,
                    subject=subject,
                    value=value,
                    classification=classification,
                    sources=sources,
                    independent_families=families,
                    unknowns=unknowns,
                )
            )
        return ConsensusReport(claims=claims, backend_statuses=statuses)
