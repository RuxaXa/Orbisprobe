from __future__ import annotations

import json
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from .base import (
    RUNTIME_SOURCE_CLASS,
    BackendEvidence,
    BackendResult,
    BackendStatus,
)

#: Adapter identities allowed to contribute real-target runtime evidence. Runtime evidence must come
#: from OrbisProbe's own runtime-collection channel; a claim of ``runtime_real`` from any other
#: adapter identity is ignored rather than promoted.
RUNTIME_CHANNELS = frozenset({"runtime-log", "runtime"})

#: Provenance families used to decide whether a claim is corroborated across evidence modalities.
STATIC_SOURCE_CLASSES = frozenset({"static", "inferred", "unattributed", "fixture"})
SYMBOLIC_SOURCE_CLASSES = frozenset({"symbolic"})
EMULATED_SOURCE_CLASSES = frozenset({"emulated"})


class ConsensusClassification(str, Enum):
    UNKNOWN = "UNKNOWN"
    SUPPORTED = "SUPPORTED"
    STRONGLY_SUPPORTED = "STRONGLY_SUPPORTED"
    MULTI_MODAL_STRONG_SUPPORT = "MULTI_MODAL_STRONG_SUPPORT"
    CONFIRMED = "CONFIRMED"
    EVIDENCE_CONFLICT = "EVIDENCE_CONFLICT"
    DISPROVED = "DISPROVED"
    REVIDIERT = "REVIDIERT"


def _canonical(value: Any) -> str | None:
    """Canonicalise a claim value, returning ``None`` when it is not strict-JSON representable.

    Non-representable values must never raise here: a single malformed backend value would abort
    the entire consensus step and discard the results of every other engine. They also must never
    vote, so they are excluded instead.
    """

    try:
        return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)
    except (TypeError, ValueError):
        return None


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
    excluded_evidence: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "claims": [claim.to_dict() for claim in self.claims],
            "backend_statuses": self.backend_statuses,
            "excluded_evidence": self.excluded_evidence,
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

    @staticmethod
    def _is_runtime_channel(result: BackendResult, evidence: BackendEvidence) -> bool:
        """Runtime evidence counts only from OrbisProbe's own runtime-collection adapters."""

        return (
            evidence.provenance.get("source_class") == RUNTIME_SOURCE_CLASS
            and result.identity.name in RUNTIME_CHANNELS
        )

    def combine(
        self,
        results: list[BackendResult],
        available_families: set[str] | None = None,
    ) -> ConsensusReport:
        groups: dict[tuple[str, str], list[tuple[BackendResult, BackendEvidence]]] = {}
        statuses = {result.identity.name: result.status.value for result in results}
        excluded: list[str] = []
        for result in results:
            if result.status is not BackendStatus.COMPLETED:
                continue
            for evidence in result.evidence:
                if _canonical(evidence.value) is None:
                    excluded.append(
                        f"{result.identity.name}:{evidence.kind}:{evidence.subject} "
                        "(value not strict-JSON representable; excluded from voting)"
                    )
                    continue
                groups.setdefault((evidence.kind, evidence.subject), []).append((result, evidence))

        claims: list[ConsensusClaim] = []
        for (kind, subject), entries in sorted(groups.items()):
            by_value: dict[str, list[tuple[BackendResult, BackendEvidence]]] = {}
            for result, evidence in entries:
                canonical = _canonical(evidence.value)
                if canonical is None:
                    excluded.append(
                        f"{result.identity.name}:{evidence.kind}:{evidence.subject} "
                        "(value not strict-JSON representable; excluded from voting)"
                    )
                    continue
                by_value.setdefault(canonical, []).append((result, evidence))
            if not by_value:
                continue
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
            runtime_flags = {
                self._is_runtime_channel(result, evidence)
                for result, evidence in value_entries
            }
            declares_untrusted_runtime = any(
                evidence.provenance.get("source_class") == RUNTIME_SOURCE_CLASS
                and not self._is_runtime_channel(result, evidence)
                for result, evidence in value_entries
            )
            if any(runtime_flags) and len(runtime_flags) > 1 and len(families) >= 2:
                classification = ConsensusClassification.CONFIRMED
            elif (
                len(families) >= 2
                and any(
                    evidence.provenance.get("source_class") in EMULATED_SOURCE_CLASSES
                    for _result, evidence in value_entries
                )
                and any(
                    evidence.provenance.get("source_class")
                    in (STATIC_SOURCE_CLASSES | SYMBOLIC_SOURCE_CLASSES)
                    for _result, evidence in value_entries
                )
            ):
                # Corroboration across an offline static/symbolic modality and an executed
                # emulation modality. Still explicitly not real-target runtime confirmation.
                classification = ConsensusClassification.MULTI_MODAL_STRONG_SUPPORT
            elif len(families) >= 2:
                classification = ConsensusClassification.STRONGLY_SUPPORTED
            else:
                classification = ConsensusClassification.SUPPORTED

            unknowns: list[str] = []
            if declares_untrusted_runtime:
                unknowns.append(
                    "runtime evidence from a non-runtime adapter was ignored for promotion"
                )
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
        return ConsensusReport(claims=claims, backend_statuses=statuses, excluded_evidence=excluded)
