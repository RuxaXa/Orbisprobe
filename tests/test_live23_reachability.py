"""LIVE2.3 reachability gates and RCR classification (§7-§13). Offline only."""

from __future__ import annotations

from dataclasses import replace

from orbisprobe.live.reachability import (
    C1,
    C2,
    C3,
    C4,
    RCR_A,
    RCR_B,
    RCR_C,
    RCR_D,
    ReachabilityEvidence,
    classify,
    classify_consumer,
)


def _evidence(**overrides) -> ReachabilityEvidence:
    base = ReachabilityEvidence(
        candidate_id="RC-001",
        function="0xffffffffd05ac8f0-0xffffffffd05ac9be",
        field="[r15+0xf8]",
        read_1="0xffffffffd05ac963 mov rdi, qword ptr [r15 + 0xf8]",
        read_2="0xffffffffd05ac974 mov rdi, qword ptr [r15 + 0xf8]",
        intervening_call="0xffffffffd05ac938 call 0xffffffffd057e7b0",
        consumer="0xffffffffd057e7b0 (rdi = field value)",
        consumer_security_class=C2,
        user_control="USER_CONTROLLED",
        mutability="MUTABLE",
        lock_between_reads=False,
        persistent_sink_proof="PROVEN_ABSENT",
    )
    return replace(base, **overrides)


def test_full_gate_closure_is_the_only_rcr_a():
    evidence = _evidence()
    allowed, blockers = evidence.gates()
    assert allowed and blockers == []
    verdict, reason, _ = classify(evidence)
    assert verdict == RCR_A and "non-persistent" in reason


def test_kernel_write_on_the_path_blocks_any_live_test():
    evidence = _evidence(kernel_writes_on_path=["0xffffffffd05ac91a mov qword ptr [rbx], 0"])
    allowed, blockers = evidence.gates()
    assert not allowed and any("writes kernel memory" in b for b in blockers)
    verdict, _, _ = classify(evidence)
    assert verdict == RCR_D


def test_unproven_non_persistence_is_plan_only():
    allowed, blockers = _evidence(persistent_sink_proof="NOT_PROVEN").gates()
    assert not allowed and any("non-persistence" in b for b in blockers)


def test_unknown_consumer_semantics_blocks_the_test():
    allowed, blockers = _evidence(consumer_security_class=C4).gates()
    assert not allowed and any("semantics unknown" in b for b in blockers)


def test_non_security_sensitive_consumer_downgrades():
    evidence = _evidence(consumer_security_class=C1)
    allowed, blockers = evidence.gates()
    assert not allowed and any("not security sensitive" in b for b in blockers)
    verdict, _, _ = classify(evidence)
    assert verdict == RCR_C


def test_kernel_controlled_or_immutable_field_disproves_the_candidate():
    assert classify(_evidence(user_control="KERNEL_CONTROLLED"))[0] == RCR_B
    assert classify(_evidence(mutability="LOCK_PROTECTED"))[0] == RCR_B
    allowed, blockers = _evidence(mutability="LOCK_PROTECTED").gates()
    assert not allowed and any("lock/refcount" in b or "not temporally mutable" in b for b in blockers)


def test_user_influence_requirement():
    allowed, blockers = _evidence(user_control="UNKNOWN").gates()
    assert not allowed and any("not user-controllable" in b for b in blockers)


def test_consumer_class_mapping():
    assert classify_consumer(derefs=0, calls=0, stores_via_pointer=0) == C1
    assert classify_consumer(derefs=3, calls=0, stores_via_pointer=0) == C2
    assert classify_consumer(derefs=2, calls=1, stores_via_pointer=0) == C3
    assert classify_consumer(derefs=1, calls=0, stores_via_pointer=1) == C3
    assert classify_consumer(derefs=0, calls=0, stores_via_pointer=0, known=False) == C4


def test_unresolved_items_are_reported_not_hidden():
    evidence = _evidence(unresolved=["indirect callers not followed"])
    allowed, blockers = evidence.gates()
    assert not allowed and any("indirect callers" in b for b in blockers)
