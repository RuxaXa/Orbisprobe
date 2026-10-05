"""LIVE2.5 sweep-vs-CFG delta, consumer semantics and R25 outcomes. Offline only."""

from __future__ import annotations

from dataclasses import replace

from orbisprobe.live.wholeimage import (
    C1,
    C2,
    C3,
    C4,
    R25_A,
    R25_B,
    R25_C,
    R25_D,
    R25_E,
    R25Evidence,
    classify,
    consumer_semantics,
    sweep_delta,
)


def _evidence(**overrides) -> R25Evidence:
    base = R25Evidence(
        candidate_id="RC-001",
        root_entry="0xffffffffd05ac8f0-root", root_class="KERNEL_INTERNAL", root_edges=["a -> b"],
        indirect_targets_resolved=True, constructor_found=True, destructor_found=True,
        user_influence="USER_INFLUENCED", mutability="KERNEL_MUTABLE", consumer_class=C3,
        consumer_closed=True, field_78_semantics="VOLATILE_SYNC_STATE", volatile_path_proven=True)
    return replace(base, **overrides)


def test_complete_closure_is_r25_a():
    outcome, reason, blockers = classify(_evidence())
    assert outcome == R25_A and blockers == [] and "volatile" in reason


def test_immutable_field_disproves_the_candidate():
    assert classify(_evidence(mutability="IMMUTABLE_AFTER_INIT"))[0] == R25_B


def test_harmless_consumer_downgrades():
    assert classify(_evidence(consumer_class=C1))[0] == R25_C


def test_unresolved_field_78_is_r25_d():
    outcome, _, blockers = classify(_evidence(field_78_semantics="PERSISTENT", volatile_path_proven=False))
    assert outcome == R25_D and any("field_78" in b for b in blockers)


def test_missing_artifact_wins_over_r25_d():
    evidence = _evidence(root_entry="", missing_artifact="decompiler failed on the dispatch table")
    outcome, reason, _ = classify(evidence)
    assert outcome == R25_E and "dispatch table" in reason


def test_consumer_semantics_from_decompiled_c():
    assert consumer_semantics("void f(long handle) { do_something(handle); }")[0] == C1
    assert consumer_semantics("void f(long *h) { if (h->flags == 1) { g(h); } }", "h")[0] == C3
    # a plain dereference is a pointer use (C2); a write through the pointer is C3
    assert consumer_semantics("void f(long *h) { long v = *h; use(v); }", "h")[0] == C2
    assert consumer_semantics("void f(long h) { }", "h")[0] == C1
    assert consumer_semantics("")[0] == C4


def test_sweep_delta_counts_false_positives():
    delta = sweep_delta({"0x1000": ("0x1000", "0x1100"), "0x2000": ("0x2000", "0x2100")},
                        {"0x1000", "0x2000", "0x3000"})
    assert delta.reproduced == ["0x1000", "0x2000"] and delta.sweep_only == ["0x3000"]
    assert delta.cfg_functions == 2 and abs(delta.false_positive_rate - round(1 / 3, 4)) < 1e-9


def test_user_influence_must_not_be_assumed_from_a_syscall_root():
    _, _, blockers = classify(_evidence(user_influence="UNKNOWN", root_class="SYSCALL"))
    assert any("user influence" in b for b in blockers)
