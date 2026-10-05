"""M2-LIVE2.5 — whole-image CFG closure: sweep-vs-CFG delta, consumer semantics, R25 outcomes.

The whole-image Ghidra project supplies what the linear sweep cannot: real function boundaries, basic
blocks, incoming-call references and decompiled C. This module turns that evidence into

* ``sweep_delta``      — which linear-sweep "functions" disappear under CFG recovery (false positives to
  keep as regression fixtures) and which real callsites the sweep had missed,
* ``consumer_semantics`` — C1/C2/C3/C4 derived from decompiled C plus the recorded field accesses,
* ``classify``         — R25-A..E with R25-A only when every closure is actually present.
"""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field
from typing import Any

R25_A = "R25-A"
R25_B = "R25-B"
R25_C = "R25-C"
R25_D = "R25-D"
R25_E = "R25-E"

C1, C2, C3, C4 = "C1", "C2", "C3", "C4"

#: decompiled-C markers, in increasing order of security relevance
_DEREF = re.compile(r"\*\(.*\)\s*\(?\s*\w+|\*\w+|\[\w+\]", )
_WRITE = re.compile(r"\*\s*\(?[\w\s\*]*\)?\s*\w+\s*=|\w+\[\w+\]\s*=|->\w+\s*=")
_CALL_WITH = re.compile(r"\w+\([^)]*\bhandle\b[^)]*\)")
_STORE_FIELD = re.compile(r"->\w+\s*=")


@dataclass
class SweepDelta:
    cfg_functions: int
    sweep_functions: int
    reproduced: list[str] = field(default_factory=list)
    sweep_only: list[str] = field(default_factory=list)
    cfg_only: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @property
    def false_positive_rate(self) -> float:
        total = len(self.reproduced) + len(self.sweep_only)
        return round(len(self.sweep_only) / total, 4) if total else 0.0


def sweep_delta(cfg_boundaries: dict[str, tuple[str, str]], sweep_functions: set[str]) -> SweepDelta:
    """Compare recovered CFG starts against the linear-sweep function map."""

    reproduced = sorted(name for name in cfg_boundaries if name in sweep_functions)
    sweep_only = sorted(name for name in sweep_functions if name not in cfg_boundaries)
    cfg_only = sorted(name for name in cfg_boundaries if name not in sweep_functions)
    return SweepDelta(cfg_functions=len(cfg_boundaries), sweep_functions=len(sweep_functions),
                      reproduced=reproduced, sweep_only=sweep_only, cfg_only=cfg_only)


def consumer_semantics(decompiled_c: str, pointer_variable: str = "handle") -> tuple[str, list[str]]:
    """Classify what the consumer does with the pointer it receives (§3).

    Rule: a write through the pointer (``h->f = x``, ``*(h+o) = x``) is C3, a plain dereference (``*h``,
    ``h->f`` read) is C2, a pointer that only reaches comparisons/branches is C1.
    """

    if not decompiled_c.strip():
        return C4, ["no decompiled C for the consumer"]
    reasons: list[str] = []
    body = decompiled_c
    writes = _WRITE.findall(body)
    derefs = _DEREF.findall(body)
    if writes:
        reasons.append(f"writes through/into a pointer at {len(writes)} site(s)")
        return C3, reasons
    if re.search(r"\*\s*\(" + re.escape(pointer_variable) + r"\s*\+", body) or re.search(
            re.escape(pointer_variable) + r"->", body):
        reasons.append("field of the received object is read or written")
        return C3, reasons
    if re.search(r"\b" + re.escape(pointer_variable) + r"\b", body) and derefs:
        reasons.append("pointer is used in a memory expression")
        return C2, reasons
    if re.search(r"\b" + re.escape(pointer_variable) + r"\b", body):
        reasons.append("pointer appears only in comparisons/branches")
        return C1, reasons
    reasons.append("pointer does not appear in the decompiled body")
    return C4, reasons


@dataclass
class R25Evidence:
    candidate_id: str
    cfg_boundaries: dict[str, tuple[str, str]] = field(default_factory=dict)
    sweep_functions: set[str] = field(default_factory=set)
    root_entry: str = ""
    root_class: str = "UNKNOWN"                 # SYSCALL / IOCTL / DEVICE_OP / SERVICE_HANDLER / ...
    root_edges: list[str] = field(default_factory=list)
    indirect_targets_resolved: bool = False
    object_fields: dict[str, dict[str, Any]] = field(default_factory=dict)
    constructor_found: bool = False
    destructor_found: bool = False
    field_writer_status: dict[str, int] = field(default_factory=dict)
    user_influence: str = "UNKNOWN"
    mutability: str = "UNKNOWN"
    consumer_class: str = C4
    consumer_closed: bool = False
    field_78_semantics: str = "UNRESOLVED"     # VOLATILE_SYNC_STATE / PERSISTENT / UNRESOLVED
    volatile_path_proven: bool = False
    missing_artifact: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def classify(evidence: R25Evidence) -> tuple[str, str, list[str]]:
    """§19: R25-A only when every closure is present; safety blockers always reported."""

    blockers: list[str] = []
    if evidence.mutability in ("IMMUTABLE_AFTER_INIT", "KERNEL_CONTROLLED"):
        return R25_B, "field_f8 is kernel-controlled/immutable: candidate disproved", blockers
    if evidence.consumer_closed and evidence.consumer_class == C1:
        return R25_C, "consumer is semantically harmless: candidate downgraded", blockers
    if evidence.field_78_semantics != "VOLATILE_SYNC_STATE" or not evidence.volatile_path_proven:
        blockers.append("field_78 write/poll semantics not closed as volatile sync state")
    if not evidence.root_entry:
        blockers.append("root entry not closed")
    if evidence.user_influence not in ("USER_CONTROLLED", "USER_INFLUENCED"):
        blockers.append(f"user influence not established ({evidence.user_influence})")
    if not evidence.consumer_closed or evidence.consumer_class == C4:
        blockers.append("consumer not semantically closed")
    if not evidence.indirect_targets_resolved:
        blockers.append("indirect call targets not resolved")
    if not evidence.constructor_found:
        blockers.append("constructor/allocator not identified")
    if blockers and evidence.missing_artifact:
        return R25_E, f"whole-image CFG still insufficient: {evidence.missing_artifact}", blockers
    if blockers:
        return R25_D, "field_78 path unsafe or unresolved: PLAN_ONLY", blockers
    return R25_A, "root, user influence, mutable field, C2/C3 consumer and volatile field_78 path closed", []
