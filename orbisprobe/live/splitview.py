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


# ---------------------------------------------------------------- LIVE2.1 (timing engine closure)

T2_A = "T2-A"  # OVERLAP_CONFIRMED
T2_B = "T2-B"  # NO_OVERLAP
T2_C = "T2-C"  # TIMING_UNKNOWN
T2_D = "T2-D"  # FAULT / RESTORE ANOMALY -> STOP

SPLIT_VIEW_CONFIRMED = "SPLIT_VIEW_CONFIRMED"
OVERLAP_NO_SPLIT = "OVERLAP_CONFIRMED / NO_SPLIT_VIEW_OBSERVED"
NO_OVERLAP = "NO_OVERLAP"

#: scheduling modes exercised (no delay fuzzing): tight toggle, yield between toggles, short fixed pause
SCHED_MODES: tuple[tuple[str, int], ...] = (("tight", 0), ("yield", 1), ("sleep", 2))
MAX_WRITER_MS = 100
MAX_TRANSITIONS = 100000
PHASE1_ATTEMPTS_PER_CONFIG = 20
MAX_ATTEMPTS_PER_CONFIG = 100
RELIABLE_OVERLAP_RATE = 0.5


def parse_trace(response: dict[str, Any]) -> list[dict[str, int]]:
    """Parse ``OK RTRACE … id:ts_us:old:new`` entries into records (empty when unparsable)."""

    entries: list[dict[str, int]] = []
    if response.get("trace"):
        body = str(response["trace"]).replace(",", " ")
    else:
        body = str(response.get("raw") or response.get("command", ""))
    for token in body.split():
        parts = token.split(":")
        if len(parts) != 4:
            continue
        try:
            entries.append({"transition_id": int(parts[0]), "timestamp_us": int(parts[1]),
                            "old_value": int(parts[2], 16), "new_value": int(parts[3], 16)})
        except ValueError:
            continue
    return entries


def transitions_inside(trace: list[dict[str, int]], t1_us: int, t2_us: int) -> list[dict[str, int]]:
    return [e for e in trace if t1_us and t2_us and t1_us <= e["timestamp_us"] <= t2_us]


def classify_overlap(
    *, t1_us: int, t2_us: int, trace: list[dict[str, int]], writer_ran: bool,
    fault: str | None = None,
) -> tuple[str, str, dict[str, Any]]:
    """T2 classification: only T2-A permits split-view evaluation (§5)."""

    if fault:
        return T2_D, f"fault: {fault}", {"fault": fault}
    if not writer_ran:
        return T2_C, "writer did not run: timing context unreliable", {}
    if not (t1_us and t2_us) or t1_us >= t2_us:
        return T2_C, f"request timestamps unusable (t1={t1_us}, t2={t2_us})", {}
    inside = transitions_inside(trace, t1_us, t2_us)
    if inside:
        return (T2_A, f"{len(inside)} writer transition(s) inside the request window",
                {"inside": inside[:8], "inside_count": len(inside), "window_us": t2_us - t1_us})
    return (T2_B, "writer ran but no transition fell inside the request window",
            {"trace_size": len(trace), "window_us": t2_us - t1_us})


def classify_split(w1: str, w2: str, overlap_class: str) -> tuple[str, str]:
    """Split-view evaluation — only meaningful once overlap is confirmed (§4, §6)."""

    if overlap_class != T2_A:
        return NO_OVERLAP, "not evaluated: no confirmed writer/request overlap"
    if w1 and w2 and w1 != w2:
        return SPLIT_VIEW_CONFIRMED, f"phase 1 saw {w1}, phase 2 saw {w2}"
    return OVERLAP_NO_SPLIT, "overlap confirmed but both reads observed the same value"


def negative_control_verdict(witnesses: list[tuple[str, str, bool]]) -> tuple[bool, str]:
    """A→A control: even under confirmed overlap every witness pair must be identical (§7)."""

    bad = [w for w in witnesses if w[0] != w[1]]
    if bad:
        return False, f"measurement model broken: {len(bad)} A→A attempts produced differing witnesses"
    return True, f"{len(witnesses)} A→A attempts produced identical witnesses"


def should_escalate(overlap_rate: float) -> bool:
    return overlap_rate >= RELIABLE_OVERLAP_RATE
