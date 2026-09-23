"""M2-LIVE2.4 — object/entry/consumer closure outcomes (R24-A..E) and the honesty gates around them.

The classification exists to stop an unresolved candidate from drifting into a live test:

* R24-A only when root entry, user influence, mutability, a security-sensitive consumer and a volatile
  path are all closed.
* R24-B/C when the evidence disproves the race or the consumer is harmless.
* R24-D when the kernel write / persistence question stays open (PLAN_ONLY).
* R24-E when the artifact needed for closure is missing — the artifact must be named, not hinted at.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

R24_A = "R24-A"
R24_B = "R24-B"
R24_C = "R24-C"
R24_D = "R24-D"
R24_E = "R24-E"

#: scanner limitations that invalidate closure claims if not declared
REQUIRED_DISCLOSURES = ("scanner_truncation", "indirect_calls", "symbol_absence")


@dataclass
class ClosureEvidence:
    candidate_id: str
    object_register_provenance: str
    fields_resolved: list[str] = field(default_factory=list)
    constructor_found: bool = False
    field_writer_candidates: dict[str, int] = field(default_factory=dict)
    root_entry_closed: bool = False
    user_influence_proven: bool = False
    mutability: str = "UNKNOWN"
    consumer_class: str = "C4"
    consumer_closed: bool = False
    kernel_write_semantics_resolved: bool = False
    volatile_path_proven: bool = False
    missing_artifacts: list[str] = field(default_factory=list)
    disclosures: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def missing_disclosures(self) -> list[str]:
        return [name for name in REQUIRED_DISCLOSURES if name not in self.disclosures]


def classify(evidence: ClosureEvidence) -> tuple[str, str, list[str]]:
    """Return (outcome, reason, blockers). Blocker order is deliberate: safety first."""

    blockers: list[str] = []
    undisclosed = evidence.missing_disclosures()
    if undisclosed:
        blockers.append(f"undeclared scanner limitations: {', '.join(undisclosed)}")
    if not evidence.kernel_write_semantics_resolved or not evidence.volatile_path_proven:
        blockers.append("kernel write / non-persistence of the concrete path unresolved")
    if not evidence.user_influence_proven:
        blockers.append("no proven user influence on the field")
    if not evidence.consumer_closed or evidence.consumer_class == "C4":
        blockers.append("consumer not semantically closed (C4)")
    if not evidence.root_entry_closed:
        blockers.append("root entry/dispatch path not closed")
    if evidence.mutability in ("IMMUTABLE_AFTER_INIT", "KERNEL_CONTROLLED"):
        return R24_B, "field is kernel-controlled/immutable: race candidate disproved", blockers
    if evidence.consumer_class == "C1" and evidence.consumer_closed:
        return R24_C, "consumer is semantically harmless: candidate downgraded", blockers
    if undisclosed or (not evidence.constructor_found and evidence.missing_artifacts):
        return (R24_E,
                "closure requires an artifact that is not present: "
                + ("; ".join(evidence.missing_artifacts) or "; ".join(undisclosed)), blockers)
    if not (evidence.root_entry_closed and evidence.user_influence_proven and evidence.consumer_closed
            and evidence.volatile_path_proven and evidence.kernel_write_semantics_resolved):
        return R24_D, "kernel write/persistence remains unsafe or unresolved: PLAN_ONLY", blockers
    return R24_A, "root entry, user influence, mutable field, security-sensitive consumer and volatile path closed", []


def writer_status(family_correlation: int) -> str:
    """§4 writer acceptance: neighbouring-offset correlation gates the status."""

    if family_correlation >= 2:
        return "SUPPORTED"
    if family_correlation == 1:
        return "UNKNOWN"
    return "UNRELATED"
