"""LIVE2.2.1 — writer lifecycle validation (state machine, generation binding, hand-over).

The payload implements the machine ``IDLE → STARTING → RUNNING → STOPPING → DONE → IDLE`` with a
per-attempt generation id. This module is the host-side checker: an attempt is only accepted when the
payload reports a DONE for *its own* generation, a completed thread join, a stable transition counter
after that join, and a return to IDLE. A late DONE from a previous generation, an unjoined thread or a
counter that keeps moving is a lifecycle violation, never a measurement.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

STATES = ("IDLE", "STARTING", "RUNNING", "STOPPING", "DONE")
HANDOVER_TIMEOUT = "WRITER_HANDOVER_TIMEOUT"


@dataclass
class LifecycleVerdict:
    ok: bool
    generation: int | None = None
    violations: list[str] = field(default_factory=list)
    evidence: dict[str, Any] = field(default_factory=dict)
    stopped: bool = False
    stop_reason: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def validate_attempt(response: dict[str, Any], *, previous_generation: int | None = None,
                     expected_generation: int | None = None) -> LifecycleVerdict:
    """Accept only a complete, generation-bound, joined and stable attempt (§2–§7)."""

    evidence = {key: response.get(key) for key in
                ("gen", "done_gen", "joined", "stable", "handover_us", "state", "trans")}
    if not response.get("ok"):
        message = str(response.get("msg", "") or response.get("error", ""))
        if HANDOVER_TIMEOUT in message:
            return LifecycleVerdict(ok=False, violations=[f"hand-over timeout: {message}"],
                                    evidence=evidence, stopped=True, stop_reason=HANDOVER_TIMEOUT)
        return LifecycleVerdict(ok=False, violations=[f"attempt refused: {message}"], evidence=evidence,
                                stopped=True, stop_reason=message or "refused")
    violations: list[str] = []
    try:
        generation = int(response.get("gen", 0))
        done_generation = int(response.get("done_gen", 0))
        joined = int(response.get("joined", 0))
        stable = int(response.get("stable", 0))
    except (TypeError, ValueError):
        return LifecycleVerdict(ok=False, violations=["lifecycle fields are not numeric"],
                                evidence=evidence, stopped=True, stop_reason="malformed lifecycle fields")
    if expected_generation is not None and generation != expected_generation:
        violations.append(f"generation mismatch: expected {expected_generation}, payload reported {generation}")
    if previous_generation is not None and generation <= previous_generation:
        violations.append(f"generation not monotonic: {generation} after {previous_generation}")
    if done_generation != generation:
        violations.append(f"stale DONE: done_gen {done_generation} does not belong to generation {generation}")
    if joined != 1:
        violations.append("writer thread was not joined")
    if stable != 1:
        violations.append("transition counter moved after the joined DONE (stale write)")
    if response.get("state") not in (None, "IDLE"):
        violations.append(f"payload did not return to IDLE (state={response.get('state')})")
    return LifecycleVerdict(ok=not violations, generation=generation, violations=violations,
                            evidence=evidence)


def stale_done_must_not_unlock(*, previous_done_generation: int, current_generation: int,
                               state: str) -> tuple[bool, str]:
    """§3: a DONE that belongs to an earlier generation must not admit a new attempt."""

    if previous_done_generation == current_generation:
        return True, "DONE belongs to the current generation"
    if state != "IDLE":
        return True, f"payload stays {state}: new attempt is refused while DONE is stale"
    return False, "stale DONE would admit a new attempt (generation binding broken)"


def refusal_is_safe(response: dict[str, Any]) -> tuple[bool, str]:
    """§6/F: a refused attempt must not have started a writer or touched the counters."""

    if response.get("ok"):
        return False, "not a refusal"
    if int(response.get("trans", 0) or 0) != 0:
        return False, "refusal reported writer transitions: a writer was started"
    if response.get("gen") not in (None, "", "0"):
        return False, "refusal advanced the generation"
    return True, "refusal left the state machine and the counters untouched"


def sequential_plan(count: int) -> list[int]:
    """§8/E: the generation sequence a clean run of ``count`` sequential attempts must produce."""

    return list(range(1, count + 1))


def summarize(verdicts: list[LifecycleVerdict]) -> dict[str, Any]:
    """Aggregate lifecycle evidence over all attempts of a run."""

    generations = [v.generation for v in verdicts if v.generation is not None]
    return {
        "attempts": len(verdicts),
        "violations": [violation for verdict in verdicts for violation in verdict.violations],
        "generations": generations,
        "generations_monotonic": generations == sorted(generations)
        and len(set(generations)) == len(generations),
        "all_joined": all(v.evidence.get("joined") in (1, "1") for v in verdicts) if verdicts else False,
        "all_stable": all(v.evidence.get("stable") in (1, "1") for v in verdicts) if verdicts else False,
        "max_handover_us": max((int(v.evidence.get("handover_us") or 0) for v in verdicts), default=0),
        "stopped": any(v.stopped for v in verdicts),
    }
