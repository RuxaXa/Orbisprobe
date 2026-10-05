"""LIVE1 candidate record and its pre-execution gate (§3, §4).

A LIVE1 experiment may only run when every condition below is *positively* satisfied: both A and B
individually valid, no reachable persistent sink, a known host-side consumer, a defined observable,
and a complete restore plan. Anything else is PLAN_ONLY — the record can still be written and
reviewed, but nothing is dispatched.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from typing import Any

from .policy import HARD_BLOCK_KEYWORDS, HARD_BLOCK_SINKS

REQUIRED_FIELDS = (
    "hypothesis",
    "controlled_field",
    "value_a",
    "value_b",
    "validation",
    "consumer",
    "expected_effect",
    "observable",
    "risk",
    "restore_plan",
)


@dataclass(frozen=True)
class CandidateRecord:
    candidate_id: str
    hypothesis: str
    controlled_field: str
    value_a: str
    value_b: str
    validation: dict[str, Any]
    consumer: str
    expected_effect: str
    observable: tuple[str, ...]
    risk: str
    persistent_sinks: tuple[str, ...]
    restore_plan: str
    notes: str = ""
    extra: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["observable"] = list(self.observable)
        payload["persistent_sinks"] = list(self.persistent_sinks)
        return payload

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True)

    def gate(self) -> tuple[bool, list[str]]:
        """Return (may_execute, blockers). Fail-closed: any doubt is a blocker."""

        blockers: list[str] = []
        for name in REQUIRED_FIELDS:
            value = getattr(self, name)
            if value in (None, "", (), {}, []):
                blockers.append(f"missing {name}")
        if self.value_a == self.value_b and not self.extra.get("identical_inputs_intended"):
            blockers.append("value_a equals value_b: no controlled difference")
        sinks = set(self.persistent_sinks)
        unknown = sinks - set(HARD_BLOCK_SINKS)
        if sinks - {"NONE"} and not sinks <= set(HARD_BLOCK_SINKS):
            blockers.append(f"undeclared sink class in {sorted(unknown)}")
        if sinks and sinks != {"NONE"}:
            blockers.append(f"persistent sink reachable: {sorted(sinks)}")
        haystack = f"{self.candidate_id} {self.consumer} {self.notes} {json.dumps(self.validation)}"
        for keyword in HARD_BLOCK_KEYWORDS:
            if keyword in haystack.lower():
                blockers.append(f"candidate references hard-blocked term {keyword!r}")
        for name in ("valid_a", "valid_b"):
            if not self.validation.get(name):
                blockers.append(f"{name} not proven")
        if not self.validation.get("same_shape"):
            blockers.append("A and B are not proven same-size/same-permission/same-ownership")
        if not self.observable:
            blockers.append("no observable defined")
        if not self.restore_plan:
            blockers.append("no restore plan")
        return (not blockers), blockers
