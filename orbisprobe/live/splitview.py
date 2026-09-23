"""LIVE2 — bounded split-view / TOCTOU candidates and classification (§2, §3, §11, §16, §18).

Two candidates:

``CAND-2``  executable now: a payload-owned mutable field that one consumer run reads twice with a
            real intervening kernel call, while a bounded writer thread toggles it between two
            separately valid values. Every read carries a payload-side timestamp, so the witness is
            direct (§10 allows payload-side timestamped observations).

``CAND-3``  CASE-003 as a split-view candidate: static double-read chain of the host descriptor
            (``user+0x28``/``+0x30``/``+0x38`` read across two helper phases). PLAN_ONLY — executing
            it needs the secure/service path, which is not authorised, so the chain is documented and
            the secure consumer stays UNKNOWN.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any

from .policy import HARD_BLOCK_SINKS

#: Attempt budget (§11): start small, escalate only while the run stays clean.
PHASE1_MAX_ATTEMPTS = 100
PHASE2_MAX_ATTEMPTS = 100
ESCALATED_MAX_ATTEMPTS = 1000

R2_A = "R2-A"  # SPLIT_VIEW_CONFIRMED
R2_B = "R2-B"  # SPLIT_VIEW_SUPPORTED (inferred)
R2_C = "R2-C"  # RACE_WINDOW_REACHED / NO SPLIT VIEW
R2_D = "R2-D"  # NO_OBSERVATION
R2_E = "R2-E"  # FAULT / unexpected state -> STOP


@dataclass(frozen=True)
class SplitViewCandidate:
    candidate_id: str
    structure: str
    field_offsets: tuple[int, ...]
    read_set_1: str
    read_set_2: str
    intervening_calls: tuple[str, ...]
    value_a: str
    value_b: str
    consumer_1: str
    consumer_2: str
    observable: tuple[str, ...]
    risk: str
    persistent_sinks: tuple[str, ...]
    restore_plan: str
    executable: bool
    plan_only_reason: str = ""

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        for key in ("field_offsets", "intervening_calls", "observable", "persistent_sinks"):
            payload[key] = list(payload[key])
        return payload

    def gate(self) -> tuple[bool, list[str]]:
        """Chain closure (§2): multi-read, separated in time, with an intervening call, both valid."""

        blockers: list[str] = []
        for name in (
            "structure",
            "field_offsets",
            "read_set_1",
            "read_set_2",
            "intervening_calls",
            "value_a",
            "value_b",
            "consumer_1",
            "consumer_2",
            "observable",
            "restore_plan",
        ):
            if getattr(self, name) in (None, "", (), {}):
                blockers.append(f"missing {name}")
        if not self.executable:
            blockers.append(self.plan_only_reason or "candidate is PLAN_ONLY")
        if self.value_a == self.value_b:
            blockers.append("value_a equals value_b: no controlled difference")
        sinks = set(self.persistent_sinks)
        if sinks and sinks != {"NONE"}:
            blockers.append(f"sink must be NONE, got {sorted(sinks)}")
        unknown = sinks - set(HARD_BLOCK_SINKS) - {"NONE"}
        if unknown:
            blockers.append(f"undeclared sink class {sorted(unknown)}")
        return (not blockers), blockers


def cand2_executable() -> SplitViewCandidate:
    return SplitViewCandidate(
        candidate_id="CAND-2",
        structure="payload-owned mutable u64 field inside buffer A (LIVE1-validated allocation)",
        field_offsets=(0x100,),
        read_set_1="phase-1 user-space load of the field, timestamped payload-side",
        read_set_2="phase-2 user-space load of the same field, timestamped payload-side",
        intervening_calls=(
            "kernel copyout (get_memory_dump) of buffer B between the two loads",
            "writer-thread toggle of the same field",
        ),
        value_a="canary A (32-byte deterministic value derived from the run id)",
        value_b="canary B (32-byte deterministic value derived from the run id)",
        consumer_1="in-payload double-read consumer (DR command)",
        consumer_2="in-payload double-read consumer (same request, second phase)",
        observable=(
            "w1/w2 per request (direct read witness)",
            "phase timestamps t1/t2",
            "writer transition count and first/last transition timestamps",
            "DR other_rc",
        ),
        risk="low: user-owned allocation, two valid values, bounded writer, restore-bound",
        persistent_sinks=("NONE",),
        restore_plan="READ ORIGINAL → WRITE A/B → CONSUME → RESTORE ORIGINAL → READBACK VERIFY",
        executable=True,
    )


def cand3_case003() -> SplitViewCandidate:
    return SplitViewCandidate(
        candidate_id="CAND-3",
        structure="CASE-003 host descriptor (user-backed mutable structure)",
        field_offsets=(0x28, 0x30, 0x38),
        read_set_1="helper op=3 phase reads user+0x28 / user+0x30 / user+0x38",
        read_set_2="helper op=8 phase reads the same three fields",
        intervening_calls=(
            "helper dispatch between the two read phases",
            "no host-side revalidation of the pointer fields between phases (static evidence)",
        ),
        value_a="payload-owned structure instance A (all three fields valid)",
        value_b="payload-owned structure instance B (all three fields valid)",
        consumer_1="helper op=3",
        consumer_2="helper op=8",
        observable=("helper return codes per phase", "response bytes", "status structure"),
        risk="high: requires the secure/service path (not authorised)",
        persistent_sinks=("NONE",),
        restore_plan="READ ORIGINAL → WRITE A/B → SERVICE REQUEST → OBSERVE → RESTORE → VERIFY",
        executable=False,
        plan_only_reason=(
            "PLAN_ONLY: executing this candidate needs the secure/service request path, which is not "
            "authorised; the static double-read chain is documented, the secure consumer stays UNKNOWN"
        ),
    )


@dataclass
class AttemptRecord:
    attempt_id: str
    candidate_id: str
    target_identity: dict[str, Any]
    writer_start: int
    request_start: int
    writer_events: dict[str, Any]
    request_end: int
    ab_transitions: int
    observables: dict[str, Any]
    status: dict[str, Any]
    response_hash: str
    restore_result: str
    classification: str = ""
    read_phase_1_value: str = ""
    read_phase_2_value: str = ""
    witness_source: str = ""
    confidence: str = ""
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def classify_attempts(
    attempts: list[AttemptRecord],
    *,
    writer_overlap: bool,
    fault: str | None = None,
) -> tuple[str, str, dict[str, Any]]:
    """Return (classification, reason, detail). R2-B is not reachable with a same-field double read."""

    if fault:
        return R2_E, f"fault: {fault}", {"fault": fault}
    split = [
        a
        for a in attempts
        if a.read_phase_1_value
        and a.read_phase_2_value
        and a.read_phase_1_value != a.read_phase_2_value
    ]
    if split:
        first = split[0]
        return (
            R2_A,
            f"{len(split)}/{len(attempts)} requests observed two different valid values in one run",
            {
                "example": first.to_dict(),
                "direction": f"{first.read_phase_1_value} -> {first.read_phase_2_value}",
                "split_attempts": len(split),
            },
        )
    if writer_overlap:
        return (
            R2_C,
            (
                f"writer toggled within the request window in {len(attempts)} attempts but both "
                "reads always saw the same value"
            ),
            {"attempts": len(attempts)},
        )
    return R2_D, "no timing window with an overlapping writer transition was observed", {}


def bounded_iterations(clean: bool, escalated: bool = False) -> int:
    if escalated and clean:
        return ESCALATED_MAX_ATTEMPTS
    return PHASE2_MAX_ATTEMPTS
