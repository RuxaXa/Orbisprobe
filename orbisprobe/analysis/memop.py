from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class MemopVerdict(str, Enum):
    SAFE_INVARIANT = "SAFE-INVARIANT"
    OOB_READ_CANDIDATE = "OOB-READ-CANDIDATE"
    OOB_WRITE_CANDIDATE = "OOB-WRITE-CANDIDATE"
    INDEX_CANDIDATE = "INDEX-CANDIDATE"
    UNKNOWN = "UNKNOWN"


@dataclass
class MemopResult:
    verdict: MemopVerdict
    length: int | None
    index_domain: list[int]
    destination_slot_size: int | None
    remaining_extent: int | None
    evidence: list[str] = field(default_factory=list)
    unknowns: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "verdict": self.verdict.value,
            "length": self.length,
            "index_domain": list(self.index_domain),
            "destination_slot_size": self.destination_slot_size,
            "remaining_extent": self.remaining_extent,
            "evidence": list(self.evidence),
            "unknowns": list(self.unknowns),
        }


def analyze_memop_facts(facts: dict[str, Any]) -> MemopResult:
    length_values = facts.get("length_values")
    index_domain = facts.get("index_domain")
    slot_size = facts.get("destination_slot_size")
    slot_count = facts.get("destination_slot_count")
    if (
        not isinstance(length_values, list)
        or not all(isinstance(value, int) and not isinstance(value, bool) for value in length_values)
        or not isinstance(index_domain, list)
        or not all(isinstance(value, int) and not isinstance(value, bool) for value in index_domain)
        or not isinstance(slot_size, int)
        or not isinstance(slot_count, int)
    ):
        return MemopResult(
            verdict=MemopVerdict.UNKNOWN,
            length=None,
            index_domain=[],
            destination_slot_size=None,
            remaining_extent=None,
            unknowns=["malformed or incomplete memop facts"],
        )

    unique_lengths = sorted(set(length_values))
    if any(index < 0 or index >= slot_count for index in index_domain):
        return MemopResult(
            verdict=MemopVerdict.INDEX_CANDIDATE,
            length=unique_lengths[0] if len(unique_lengths) == 1 else None,
            index_domain=sorted(set(index_domain)),
            destination_slot_size=slot_size,
            remaining_extent=None,
            evidence=["index domain exceeds destination slot count"],
        )

    if len(unique_lengths) != 1 or facts.get("length_mutable") is not False:
        return MemopResult(
            verdict=MemopVerdict.UNKNOWN,
            length=unique_lengths[0] if len(unique_lengths) == 1 else None,
            index_domain=sorted(set(index_domain)),
            destination_slot_size=slot_size,
            remaining_extent=None,
            unknowns=["length is not a single immutable invariant"],
        )

    length = unique_lengths[0]
    if length < 0:
        return MemopResult(
            verdict=MemopVerdict.UNKNOWN,
            length=length,
            index_domain=sorted(set(index_domain)),
            destination_slot_size=slot_size,
            remaining_extent=None,
            unknowns=["negative length"],
        )
    if length > slot_size:
        operation = str(facts.get("operation", "")).lower()
        verdict = (
            MemopVerdict.OOB_READ_CANDIDATE
            if operation == "copyin"
            else MemopVerdict.OOB_WRITE_CANDIDATE
        )
        return MemopResult(
            verdict=verdict,
            length=length,
            index_domain=sorted(set(index_domain)),
            destination_slot_size=slot_size,
            remaining_extent=slot_size - length,
            evidence=["copy length exceeds destination slot extent"],
        )

    return MemopResult(
        verdict=MemopVerdict.SAFE_INVARIANT,
        length=length,
        index_domain=sorted(set(index_domain)),
        destination_slot_size=slot_size,
        remaining_extent=slot_size - length,
        evidence=[
            f"length invariant = 0x{length:x}",
            "index domain bounded to declared destination slots",
            f"destination slot size = 0x{slot_size:x}",
        ],
    )
