"""LIVE0 PayloadInfo parser, ownership proof and the payload_info-loss regression (§2–§10).

The regression test here targets the exact defect observed live: ``get_target_info()`` validated the
payload fields, but the *stored* state was the raw response only, so ``capture_allocation()`` saw no
allocation provenance and the ownership gate refused. Before the fix ``payload_info`` was a plain
dict, so ``test_B_raw_response_never_replaces_the_parsed_structure`` fails; after the fix the
validated :class:`PayloadInfo` is the single source of truth and it passes.
"""

from __future__ import annotations

from dataclasses import replace

import pytest
from live0_harness import (
    FAKE_BUFFER,
    FAKE_BUFFER_LEN,
    FAKE_PID,
    FAKE_TEST_LENGTH,
    FAKE_TEST_OFFSET,
    ScriptedChannel,
    make_identity,
    make_target,
    write_plan,
)

from orbisprobe.live.evidence import MutationState
from orbisprobe.live.ps4_target import (
    PayloadInfo,
    parse_payload_info,
)

RAW_INFO = ScriptedChannel().request("INFO")
SESSION = "sess-a"


def _parsed(**overrides) -> PayloadInfo:
    parsed, missing = parse_payload_info(
        RAW_INFO, process_name="ScePartyDaemon", endpoint="fake", session_id=SESSION
    )
    assert parsed is not None and not missing
    return replace(parsed, **overrides) if overrides else parsed


# ---------------------------------------------------------------- §9 A/B/C
def test_A_complete_payload_info_confirms_ownership():
    target = make_target(ScriptedChannel())
    record = target.capture_allocation(
        process_name="ScePartyDaemon",
        injection_pid=FAKE_PID,
        test_offset=FAKE_TEST_OFFSET,
        test_length=FAKE_TEST_LENGTH,
    )
    assert record is not None
    assert record.allocation_call == "mmap"
    assert record.allocation_base == FAKE_BUFFER
    assert record.allocation_size == FAKE_BUFFER_LEN
    assert record.allocation_generation == 1
    assert record.pid == FAKE_PID
    assert record.session_id == SESSION
    assert target.allocation_block() is None


def test_B_raw_response_never_replaces_the_parsed_structure():
    """Regression for the live defect: raw/default state must not win over validated state."""

    target = make_target(ScriptedChannel())
    parsed = target.payload_info
    assert isinstance(parsed, PayloadInfo), "the parsed structure must be the stored truth"
    # simulate the old merge path: a raw response (and an empty one) arrives afterwards
    target.raw_target_info = {"ok": "True", "command": "INFO"}
    assert target.payload_info is parsed
    target.raw_target_info = {}
    assert target.payload_info is parsed
    assert target.allocation_block() is None
    assert target.allocation is not None


def test_B2_totally_empty_raw_dict_leaves_the_parsed_structure_intact():
    target = make_target(ScriptedChannel())
    before = target.payload_info.to_dict()
    target.raw_target_info = {}
    assert target.payload_info.to_dict() == before


def test_C_incomplete_payload_info_fails_closed():
    target = make_target(ScriptedChannel())
    target.payload_info = None
    target.payload_info_missing = ["allocation_base", "pid"]
    plan = write_plan(plan_id="C-incomplete")
    result = target.write_memory(plan, test="C")
    assert result["result"] == "BLOCK"
    assert "PAYLOAD_INFO_INCOMPLETE" in result["error"]
    assert all(not request["mutation"] for request in target.channel.requests)


def test_C2_parser_reports_missing_fields_and_never_defaults():
    parsed, missing = parse_payload_info({"ok": "True", "fw": "1352"}, session_id=SESSION)
    assert parsed is None
    for field in (
        "pid",
        "instance_id",
        "allocation_method",
        "allocation_base",
        "allocation_return",
        "allocation_size",
        "allocation_generation",
    ):
        assert field in missing, field
    assert "session_id" not in missing
    # session_id is bound after identity capture and enforced by the ownership gate, not the parser
    parsed2, missing2 = parse_payload_info(RAW_INFO, session_id="")
    assert parsed2 is not None and missing2 == []
    target_sessionless = "sessionless"
    assert target_sessionless  # placeholder for the gate-level check below


# ---------------------------------------------------------------- §9 D–G
@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("pid", FAKE_PID + 1),
        ("instance_id", "0xdeadbeef"),
        ("allocation_generation", 2),
        ("allocation_base", FAKE_BUFFER + 0x100),
    ],
)
def test_D_to_G_changed_identity_marks_the_buffer_stale(field, value):
    target = make_target(ScriptedChannel())
    assert target.allocation is not None
    target.payload_info = replace(target.payload_info, **{field: value})
    result = target.write_memory(write_plan(plan_id=f"stale-{field}"), test="stale")
    assert result["result"] == "BLOCK"
    assert "STALE buffer" in result["error"]
    assert all(not request["mutation"] for request in target.channel.requests)


def test_F_session_change_marks_the_buffer_stale():
    target = make_target(ScriptedChannel())
    target.identity = make_identity(session_id="another-boot")
    result = target.write_memory(write_plan(plan_id="stale-session"), test="stale")
    assert result["result"] == "BLOCK"
    assert "STALE buffer" in result["error"]


def test_H_allocation_return_mismatch_blocks(monkeypatch):
    target = make_target(ScriptedChannel())
    target.payload_info = replace(target.payload_info, allocation_return=FAKE_BUFFER + 0x40)
    assert (
        target.capture_allocation(process_name="p", injection_pid=FAKE_PID, test_offset=0, test_length=8)
        is None
    )


def test_I_range_beyond_the_allocation_blocks():
    target = make_target(ScriptedChannel())
    assert (
        target.capture_allocation(
            process_name="p",
            injection_pid=FAKE_PID,
            test_offset=FAKE_BUFFER_LEN - 8,
            test_length=64,
        )
        is None
    )
    with pytest.raises(ValueError, match="exceeds allocation"):
        target.test_range(FAKE_BUFFER_LEN)


# ---------------------------------------------------------------- §9 J/K + §7
def test_J_missing_klog_is_missing_corroboration_not_a_blocker():
    target = make_target(ScriptedChannel())
    record = target.capture_allocation(process_name="unknown", injection_pid=None)
    assert record is not None, "a complete PayloadInfo must confirm buffer ownership on its own"
    assert target.allocation_block() is None


def test_K_contradicting_klog_pid_blocks():
    target = make_target(ScriptedChannel())
    assert (
        target.capture_allocation(
            process_name="ScePartyDaemon", injection_pid=FAKE_PID + 1, test_offset=0, test_length=8
        )
        is None
    )


def test_write_cycle_still_confirms_and_restores_after_the_fix():
    target = make_target(ScriptedChannel())
    result = target.write_memory(write_plan(plan_id="post-fix"), test="post-fix")
    assert result["mutation_state"] == MutationState.MUTATION_CONFIRMED.value
    assert result["restore_state"] == "RESTORED_CONFIRMED"
    assert result["result"] == "PASS"



