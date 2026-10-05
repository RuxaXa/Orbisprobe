"""LIVE2.2.1 writer-lifecycle regression tests A-G (§8). Offline only.

A normal attempt → DONE → next attempt accepted
B writer finishes slightly after the request → command waits → no BUSY
C stale DONE from a previous generation does not unlock the next attempt
D writer never finishes → HANDOVER_TIMEOUT → no new writer
E 20 sequential attempts → no BUSY, no leaked writer
F rapid back-to-back submission → refused safely (no writer started)
G transition counter does not change after the joined DONE
"""

from __future__ import annotations

from orbisprobe.live.lifecycle import (
    HANDOVER_TIMEOUT,
    refusal_is_safe,
    sequential_plan,
    stale_done_must_not_unlock,
    summarize,
    validate_attempt,
)


def _ok(gen: int, *, joined: int = 1, stable: int = 1, state: str = "IDLE", trans: int = 900,
        handover_us: int = 120) -> dict:
    return {"ok": 1, "gen": str(gen), "done_gen": str(gen), "joined": str(joined), "stable": str(stable),
            "state": state, "trans": str(trans), "handover_us": str(handover_us)}


def test_a_normal_attempt_then_next_is_accepted():
    first = validate_attempt(_ok(1), previous_generation=None)
    second = validate_attempt(_ok(2), previous_generation=first.generation)
    assert first.ok and second.ok
    assert first.generation == 1 and second.generation == 2
    assert not first.violations and not second.violations


def test_b_writer_finishing_after_the_request_does_not_yield_busy():
    # the payload waited 4 ms for its own DONE: that is a wait, not a refusal
    verdict = validate_attempt(_ok(3, handover_us=4000))
    assert verdict.ok and not verdict.stopped
    assert verdict.evidence["handover_us"] == "4000"
    assert verdict.violations == []


def test_c_stale_done_from_a_previous_generation_does_not_unlock():
    verdict = validate_attempt({"ok": 1, "gen": "8", "done_gen": "7", "joined": "1", "stable": "1",
                                "state": "IDLE", "trans": "10", "handover_us": "50"})
    assert not verdict.ok
    assert any("stale DONE" in v for v in verdict.violations)
    locked, reason = stale_done_must_not_unlock(previous_done_generation=7, current_generation=8,
                                               state="STOPPING")
    assert locked and "refused" in reason
    broken, reason_broken = stale_done_must_not_unlock(previous_done_generation=7, current_generation=8,
                                                      state="IDLE")
    assert not broken and "generation binding broken" in reason_broken


def test_d2_live_signature_generation_zero_is_rejected():
    """Live regression (22:20 run): the writer believed it was generation 0 -> gen=1/done_gen=0/timeout.

    The host must never accept such an attempt, and the payload fix (generation taken from
    g_writer_gen, STARTING waited out) is what makes the pair match again.
    """

    verdict = validate_attempt({"ok": 0, "msg": "WRITER_HANDOVER_TIMEOUT gen=1 done_gen=0 state=STOPPING "
                                               "handover_us=500053", "trans": "0", "gen": "1"},
                               previous_generation=None)
    assert not verdict.ok and verdict.stopped and verdict.stop_reason == HANDOVER_TIMEOUT
    assert "timeout" in verdict.violations[0]
    accepted = validate_attempt(_ok(1))          # after the fix the pair matches and is accepted
    assert accepted.ok and accepted.evidence["done_gen"] == "1"


def test_d_handover_timeout_is_a_stop_without_a_new_writer():
    verdict = validate_attempt({"ok": 0, "msg": f"{HANDOVER_TIMEOUT} gen=4 done_gen=3 state=STOPPING",
                                "trans": "0"})
    assert not verdict.ok and verdict.stopped and verdict.stop_reason == HANDOVER_TIMEOUT
    safe, _ = refusal_is_safe({"ok": 0, "trans": "0", "gen": ""})
    assert safe


def test_e_twenty_sequential_attempts_are_all_accepted_and_monotonic():
    verdicts, previous = [], None
    for generation in sequential_plan(20):
        verdict = validate_attempt(_ok(generation), previous_generation=previous)
        assert verdict.ok, verdict.violations
        previous = verdict.generation
        verdicts.append(verdict)
    summary = summarize(verdicts)
    assert summary["attempts"] == 20 and summary["generations_monotonic"]
    assert summary["all_joined"] and summary["all_stable"] and not summary["violations"]
    assert summary["generations"] == list(range(1, 21))


def test_f_rapid_back_to_back_submission_is_refused_safely():
    busy = {"ok": 0, "msg": "busy state=STOPPING gen=11 done_gen=11", "trans": "0", "gen": ""}
    verdict = validate_attempt(busy, previous_generation=10)
    assert not verdict.ok and verdict.stopped
    safe, reason = refusal_is_safe(busy)
    assert safe and "untouched" in reason
    unsafe, reason_unsafe = refusal_is_safe({"ok": 0, "trans": "5", "gen": "12"})
    assert not unsafe and "writer was started" in reason_unsafe


def test_g_counter_must_not_move_after_the_joined_done():
    verdict = validate_attempt(_ok(5, stable=0))
    assert not verdict.ok
    assert any("moved after the joined DONE" in v for v in verdict.violations)


def test_generation_regression_and_missing_join_are_violations():
    regression = validate_attempt(_ok(4), previous_generation=9)
    assert not regression.ok and any("not monotonic" in v for v in regression.violations)
    unjoined = validate_attempt(_ok(6, joined=0))
    assert not unjoined.ok and any("not joined" in v for v in unjoined.violations)


def test_non_idle_state_and_non_numeric_fields_are_violations():
    running = validate_attempt(_ok(7, state="RUNNING"))
    assert not running.ok and any("IDLE" in v for v in running.violations)
    malformed = validate_attempt({"ok": 1, "gen": "x", "done_gen": "y"})
    assert not malformed.ok and malformed.stopped


def test_summary_flags_a_stop():
    verdicts = [validate_attempt(_ok(1)), validate_attempt({"ok": 0, "msg": f"{HANDOVER_TIMEOUT}"})]
    summary = summarize(verdicts)
    assert summary["stopped"] and summary["violations"]
    assert summary["attempts"] == 2
