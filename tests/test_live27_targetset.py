"""LIVE2.7 fixtures: index domains, target sets, callback slots, ioctl map, R27 outcomes (§20)."""

from __future__ import annotations

from dataclasses import replace

from orbisprobe.live.targetset import (
    CALLBACK_CONFIRMED,
    CONSTANT,
    DATA_FIELD,
    FUNCTION_POINTER,
    R27_A,
    R27_B,
    R27_C,
    R27_D,
    R27_E,
    RUNTIME_ENUM,
    SMALL_ENUM,
    USER_INFLUENCED,
    IndexDomain,
    R27Evidence,
    classify,
    classify_callback_slot,
    classify_user_influence,
    decode_ioctl,
    validate_targets,
)

TEXT = ("0xffffffffd00d0000", "0xffffffffd0dcdc38")
FUNCTIONS = {"0xffffffffd057d060", "0xffffffffd0582950"}


def _evidence(**overrides) -> R27Evidence:
    base = R27Evidence(
        candidate_id="RC-001", index_domain={"class": CONSTANT, "value": "0x12"},
        table_base_source="ctx->field_28 (runtime pointer)", table_init="RUNTIME",
        target_set=[], target_set_ambiguous=False, callback_field="ctx+0x21850",
        callback_class=CALLBACK_CONFIRMED, ioctl_codes=["0xc030811e", "0xc0048114"],
        handle_lookup="FUN_ffffffffd0337b00 = *(param_1 + 0x28)", root_to_candidate_link=False,
        field_f8_writer="", field_f8_source_class="UNKNOWN", user_influence="UNKNOWN",
        mutability="UNKNOWN", synchronization_held=None, non_persistence="SUPPORTED",
        missing_artifact="runtime-initialised ops table behind ctx->field_28 plus the callback value "
                         "written at 0xffffffffd0580aaf from R14")
    return replace(base, **overrides)


def test_index_domain_fixtures():
    assert IndexDomain("g", 0, 1124, 0x12).classify()[0] == CONSTANT
    assert IndexDomain("g", 2, 50, 1).classify()[0] == SMALL_ENUM
    assert IndexDomain("g", 40, 50, None).classify()[0] == RUNTIME_ENUM
    assert IndexDomain("g", 0, 0, None).classify()[0] == "UNKNOWN"


def test_target_validation_rejects_data_and_unknown_boundaries():
    accepted, rejected = validate_targets(
        ["0xffffffffd057d060", "0xffffffffd24c5d00", "0xffffffffd0aabbcc"], FUNCTIONS, TEXT)
    assert accepted == ["0xffffffffd057d060"]
    assert len(rejected) == 2 and any("outside the text range" in r for r in rejected)


def test_callback_slot_fixtures():
    assert classify_callback_slot(writes=1, reads=1, calls=1, clears=1)[0] == CALLBACK_CONFIRMED
    assert classify_callback_slot(writes=0, reads=1, calls=1, clears=0)[0] == FUNCTION_POINTER
    assert classify_callback_slot(writes=1, reads=2, calls=0, clears=0)[0] == DATA_FIELD


def test_ioctl_code_map_fixtures():
    decoded = decode_ioctl(0xC030811E)
    assert decoded["dir"] == "READ_WRITE" and decoded["size"] == 0x30 and decoded["nr"] == 0x1E
    assert decode_ioctl(0xC0048114)["size"] == 4
    assert decode_ioctl(0xC0048114)["type"] == "0x81"


def test_user_influence_handle_vs_direct():
    assert classify_user_influence(handle_from_ioctl_input=True, writer_from_handle_lookup=True,
                                   writer_kernel_internal=False)[0] == USER_INFLUENCED
    assert classify_user_influence(handle_from_ioctl_input=False, writer_from_handle_lookup=False,
                                   writer_kernel_internal=True)[0] == "KERNEL_CONTROLLED"
    assert classify_user_influence(handle_from_ioctl_input=True, writer_from_handle_lookup=False,
                                   writer_kernel_internal=False)[0] == "UNKNOWN"


def test_runtime_table_forces_r27_e_not_a_guess():
    outcome, reason, blockers = classify(_evidence())
    assert outcome == R27_E and "runtime-initialised ops table" in reason
    assert any("runtime-initialised" in b for b in blockers) and any("field_f8 writer" in b for b in blockers)


def test_full_closure_would_be_r27_a():
    evidence = _evidence(table_init="STATIC", target_set=["0xffffffffd057d060"], table_base_source="static arrays",
                         field_f8_writer="0xffffffffd075afed", field_f8_source_class="KERNEL_ALLOCATED_RING",
                         user_influence=USER_INFLUENCED, root_to_candidate_link=True, mutability="MUTABLE",
                         synchronization_held=False, non_persistence="SUPPORTED", missing_artifact="")
    outcome, reason, blockers = classify(evidence)
    assert outcome == R27_A and blockers == [] and "volatile" in reason


def test_init_only_field_disproves_init_only():
    assert classify(_evidence(mutability="IMMUTABLE_AFTER_INIT"))[0] == R27_B


def test_lock_across_reads_disproves_the_race():
    assert classify(_evidence(synchronization_held=True))[0] == R27_C


def test_ambiguous_target_set_is_kept_ambiguous():
    evidence = _evidence(target_set=["0xffffffffd057d060", "0xffffffffd0582950"], target_set_ambiguous=True,
                         missing_artifact="")
    outcome, _, blockers = classify(evidence)
    assert outcome == R27_D and any("ambiguous" in b for b in blockers)
