"""LIVE2 candidate-chain closure and split-view classification (§2, §11, §16). Offline only."""

from __future__ import annotations

from orbisprobe.live.splitview import (
    ESCALATED_MAX_ATTEMPTS,
    PHASE2_MAX_ATTEMPTS,
    R2_A,
    R2_C,
    R2_D,
    R2_E,
    AttemptRecord,
    bounded_iterations,
    cand2_executable,
    cand3_case003,
    classify_attempts,
)


def _attempt(attempt_id: str, w1: str, w2: str, overlap: bool = True) -> AttemptRecord:
    return AttemptRecord(
        attempt_id=attempt_id,
        candidate_id="CAND-2",
        target_identity={},
        writer_start=1,
        request_start=2,
        writer_events={"overlap": overlap, "transitions": 10},
        request_end=3,
        ab_transitions=10,
        observables={},
        status={"dr_ok": True},
        response_hash="h",
        restore_result="RESTORED_CONFIRMED",
        read_phase_1_value=w1,
        read_phase_2_value=w2,
        witness_source="direct",
    )


def test_cand2_chain_is_closed_and_executable():
    candidate = cand2_executable()
    allowed, blockers = candidate.gate()
    assert allowed and blockers == []
    assert candidate.intervening_calls, "the chain must have an intervening call"
    assert candidate.value_a != candidate.value_b
    assert candidate.persistent_sinks == ("NONE",)


def test_cand2_without_intervening_call_is_refused():
    from dataclasses import replace

    allowed, blockers = cand2_executable().gate() if False else (None, None)
    candidate = replace(cand2_executable(), intervening_calls=())
    allowed, blockers = candidate.gate()
    assert not allowed and any("intervening_calls" in b for b in blockers)


def test_cand3_case003_is_plan_only():
    candidate = cand3_case003()
    allowed, blockers = candidate.gate()
    assert not allowed
    assert any("PLAN_ONLY" in b for b in blockers)
    assert (0x28, 0x30, 0x38) == candidate.field_offsets
    assert "op=3" in candidate.consumer_1 and "op=8" in candidate.consumer_2


def test_candidate_rejects_identical_values():
    from dataclasses import replace

    allowed, blockers = replace(cand2_executable(), value_b=cand2_executable().value_a).gate()
    assert not allowed and any("no controlled difference" in b for b in blockers)


def test_classification_r2_a_split_confirmed():
    attempts = [_attempt("a1", "0x11", "0x11"), _attempt("a2", "0x11", "0x22")]
    classification, reason, detail = classify_attempts(attempts, writer_overlap=True)
    assert classification == R2_A and "different valid values" in reason
    assert detail["direction"] == "0x11 -> 0x22" and detail["split_attempts"] == 1


def test_classification_r2_c_window_reached_without_split():
    attempts = [_attempt("a1", "0x11", "0x11"), _attempt("a2", "0x11", "0x11")]
    classification, reason, _ = classify_attempts(attempts, writer_overlap=True)
    assert classification == R2_C and "same value" in reason


def test_classification_r2_d_no_observation():
    attempts = [_attempt("a1", "0x11", "0x11", overlap=False)]
    classification, reason, _ = classify_attempts(attempts, writer_overlap=False)
    assert classification == R2_D and "no timing window" in reason


def test_classification_r2_e_fault_wins():
    attempts = [_attempt("a1", "0x11", "0x22")]
    classification, reason, _ = classify_attempts(attempts, writer_overlap=True, fault="disconnect")
    assert classification == R2_E and "fault" in reason


def test_attempt_budget_is_bounded():
    assert bounded_iterations(clean=True) == PHASE2_MAX_ATTEMPTS
    assert bounded_iterations(clean=False, escalated=True) == PHASE2_MAX_ATTEMPTS
    assert bounded_iterations(clean=True, escalated=True) == ESCALATED_MAX_ATTEMPTS
    assert ESCALATED_MAX_ATTEMPTS == 1000


def test_restore_fault_is_treated_as_fault():
    attempts = [_attempt("a1", "0x11", "0x22")]
    classification, _, _ = classify_attempts(attempts, writer_overlap=True, fault="STATE_INTEGRITY_UNKNOWN")
    assert classification == R2_E
