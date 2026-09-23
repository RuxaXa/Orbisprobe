"""LIVE2.4 closure outcomes and the required honesty disclosures. Offline only."""

from __future__ import annotations

from dataclasses import replace

from orbisprobe.live.objectclosure import (
    R24_A,
    R24_B,
    R24_C,
    R24_D,
    R24_E,
    ClosureEvidence,
    classify,
    writer_status,
)


def _evidence(**overrides) -> ClosureEvidence:
    base = ClosureEvidence(
        candidate_id="RC-001",
        object_register_provenance="0xffffffffd05ac90e mov r15, rdi (arg1 object)",
        fields_resolved=["field_78", "field_88", "field_f0", "field_f8"],
        constructor_found=True,
        field_writer_candidates={"SUPPORTED": 8, "UNKNOWN": 13, "UNRELATED": 22},
        root_entry_closed=True,
        user_influence_proven=True,
        mutability="KERNEL_MUTABLE",
        consumer_class="C2",
        consumer_closed=True,
        kernel_write_semantics_resolved=True,
        volatile_path_proven=True,
        disclosures={"scanner_truncation": "linear sweep stops at internal jumps",
                     "indirect_calls": "not followed",
                     "symbol_absence": "no symbol table in the dump"},
    )
    return replace(base, **overrides)


def test_complete_closure_is_r24_a():
    outcome, reason, blockers = classify(_evidence())
    assert outcome == R24_A and blockers == [] and "volatile" in reason


def test_unresolved_kernel_write_forces_r24_d():
    outcome, _reason, blockers = classify(_evidence(kernel_write_semantics_resolved=False))
    assert outcome == R24_D and "kernel write" in blockers[0]


def test_missing_artifact_is_named_r24_e():
    evidence = _evidence(constructor_found=False, missing_artifacts=["CFG-aware disassembly (Ghidra) for the callers"])
    outcome, reason, _ = classify(evidence)
    assert outcome == R24_E and "Ghidra" in reason


def test_undeclared_scanner_limitations_block_any_upgrade():
    evidence = _evidence(disclosures={})
    outcome, _, blockers = classify(evidence)
    assert outcome == R24_E
    assert any("undeclared scanner limitations" in b for b in blockers)


def test_kernel_controlled_field_disproves_the_candidate():
    outcome, _, _ = classify(_evidence(mutability="IMMUTABLE_AFTER_INIT"))
    assert outcome == R24_B


def test_harmless_consumer_downgrades():
    outcome, _, _ = classify(_evidence(consumer_class="C1"))
    assert outcome == R24_C


def test_user_influence_must_be_proven():
    _, _, blockers = classify(_evidence(user_influence_proven=False))
    assert any("user influence" in b for b in blockers)


def test_writer_status_thresholds():
    assert writer_status(3) == "SUPPORTED"
    assert writer_status(1) == "UNKNOWN"
    assert writer_status(0) == "UNRELATED"
