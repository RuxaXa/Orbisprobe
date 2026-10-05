"""LIVE2.6 dispatch fixtures, ambiguity handling and R26 outcomes (§19). Offline only."""

from __future__ import annotations

from dataclasses import replace

from orbisprobe.live.dispatch import (
    R26_A,
    R26_B,
    R26_C,
    R26_D,
    R26_E,
    DispatchSite,
    R26Evidence,
    classify,
    classify_dispatch_form,
    target_from_data_pointer,
)

TEXT_RANGE = ("0xffffffffd00d0000", "0xffffffffd0dcdc38")


def _site(**overrides) -> DispatchSite:
    base = DispatchSite(site="0xffffffffd057d0ea", form="CALL_MEM_OFFSET", source="RBX",
                        reaching_definition="table entry from handle lookup",
                        table_base="DAT_ffffffffd1b32cd0 (index), stride 8",
                        entry_stride=8, function_pointer_offset="+0x8",
                        possible_targets=["0xffffffffd057d060"], analysis_status="RESOLVED",
                        evidence_sources=["ghidra", "native"])
    return replace(base, **overrides)


def _evidence(**overrides) -> R26Evidence:
    base = R26Evidence(
        candidate_id="RC-001", root_entry="0xffffffffd05adbf0", root_class="IOCTL",
        dispatch_sites=[_site()], object_family="SUPPORTED",
        context_struct_offsets=["0x21810", "0x21820", "0x21830", "0x21840", "0x21850", "0x21870", "0x21890"],
        field_f8_writers=["0xffffffffd075afed"], user_influence="USER_INFLUENCED",
        user_influence_chain=["handle -> FUN_d0337b00 lookup -> context -> field_f8"],
        mutability="MUTABLE", synchronization_held=False, consumer_class="C3",
        consumer_target="RING_STATE", non_persistence="SUPPORTED", chain_link_ioctl_to_candidate=True)
    return replace(base, **overrides)


def test_dispatch_form_fixtures():
    assert classify_dispatch_form("CALL qword ptr [RBX + 0x8]") == "CALL_MEM_OFFSET"
    assert classify_dispatch_form("CALL qword ptr [RAX + 0x21850]") == "CALL_MEM_BIG"
    assert classify_dispatch_form("CALL RAX") == "CALL_REG"
    assert classify_dispatch_form("JMP RAX") == "JMP_REG"
    assert classify_dispatch_form("CALL 0xffffffffd057e7b0") == "NONE"


def test_possible_target_sets_and_ambiguity():
    resolved = _site()
    ambiguous = _site(possible_targets=["0xffffffffd057d060", "0xffffffffd0582950"], ambiguous=True,
                      analysis_status="AMBIGUOUS")
    assert resolved.is_resolved() and not ambiguous.is_resolved()
    incomplete = _site(possible_targets=[], analysis_status="INCOMPLETE")
    assert not incomplete.is_resolved(), "incomplete analysis is not a refutation and not a resolution"


def test_data_pointer_only_counts_inside_the_text_range():
    hits = ["0xffffffffd057d060", "0xffffffffd24c5d00", "0xdeadbeef"]
    assert target_from_data_pointer(hits, TEXT_RANGE) == ["0xffffffffd057d060"]


def test_complete_closure_is_r26_a():
    outcome, reason, blockers = classify(_evidence())
    assert outcome == R26_A and blockers == [] and "non-persistent" in reason


def test_immutable_field_disproves_the_candidate():
    assert classify(_evidence(mutability="IMMUTABLE_AFTER_INIT"))[0] == R26_B


def test_held_lock_disproves_the_race():
    assert classify(_evidence(synchronization_held=True))[0] == R26_C


def test_user_influence_unknown_is_r26_d():
    outcome, _, blockers = classify(_evidence(user_influence="UNKNOWN"))
    assert outcome == R26_D and any("user influence" in b for b in blockers)


def test_unresolved_indirect_target_is_r26_e():
    evidence = _evidence(dispatch_sites=[_site(possible_targets=[], analysis_status="INCOMPLETE")],
                         missing_artifact="possible-value set for the ops-table load in FUN_d057f200")
    outcome, reason, blockers = classify(evidence)
    assert outcome == R26_E and "possible-value" in reason
    assert any("indirect dispatch sites unresolved" in b for b in blockers)


def test_chain_link_must_be_proven_not_assumed():
    _, _, blockers = classify(_evidence(chain_link_ioctl_to_candidate=False))
    assert any("no proven path" in b for b in blockers)


def test_rc001_chain_regression_fixture():
    """The dispatch site that terminates the LIVE2.5 chain must stay classified as its real form."""

    site = DispatchSite(site="0xffffffffd057f8bc", form=classify_dispatch_form("CALL qword ptr [RAX + 0x21850]"),
                        source="RAX", function_pointer_offset="+0x21850", possible_targets=[],
                        analysis_status="INCOMPLETE")
    assert site.form == "CALL_MEM_BIG" and not site.is_resolved()
