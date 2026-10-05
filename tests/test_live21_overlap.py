"""LIVE2.1 overlap/timing-engine classification (§4-§9). Offline only."""

from __future__ import annotations

from orbisprobe.live.splitview import (
    MAX_TRANSITIONS,
    MAX_WRITER_MS,
    NO_OVERLAP,
    OVERLAP_NO_SPLIT,
    SCHED_MODES,
    SPLIT_VIEW_CONFIRMED,
    T2_A,
    T2_B,
    T2_C,
    T2_D,
    classify_overlap,
    classify_split,
    negative_control_verdict,
    parse_trace,
    should_escalate,
    transitions_inside,
)


def _trace(*stamps: int) -> list[dict[str, int]]:
    return [{"transition_id": i, "timestamp_us": ts, "old_value": 0x11, "new_value": 0x22}
            for i, ts in enumerate(stamps, start=1)]


def test_parse_trace_reads_the_trace_field():
    response = {"ok": True, "command": "DRW", "avail": "3",
                "trace": "1:100:aa:bb,2:200:bb:aa,3:300:aa:bb"}
    entries = parse_trace(response)
    assert [e["timestamp_us"] for e in entries] == [100, 200, 300]
    assert entries[0]["old_value"] == 0xAA and entries[0]["new_value"] == 0xBB
    assert parse_trace({"ok": True, "command": "DRW", "trace": ""}) == []
    # bare space-separated tokens are dropped by the frame parser, so the fallback must not invent data
    assert parse_trace({"command": "RTRACE"}) == []


def test_transitions_inside_is_inclusive_on_the_request_window():
    trace = _trace(90, 100, 150, 200, 260)
    inside = transitions_inside(trace, 100, 200)
    assert [e["timestamp_us"] for e in inside] == [100, 150, 200]


def test_t2_a_requires_a_transition_inside_the_window():
    classification, reason, detail = classify_overlap(t1_us=100, t2_us=200, trace=_trace(150),
                                                      writer_ran=True)
    assert classification == T2_A and detail["inside_count"] == 1 and "inside the request window" in reason


def test_t2_b_writer_ran_without_inside_transition():
    classification, reason, _ = classify_overlap(t1_us=100, t2_us=200, trace=_trace(10, 300),
                                                 writer_ran=True)
    assert classification == T2_B and "no transition fell inside" in reason


def test_t2_c_unusable_timestamps_or_dead_writer():
    assert classify_overlap(t1_us=0, t2_us=0, trace=[], writer_ran=True)[0] == T2_C
    assert classify_overlap(t1_us=200, t2_us=100, trace=[], writer_ran=True)[0] == T2_C
    assert classify_overlap(t1_us=100, t2_us=200, trace=[], writer_ran=False)[0] == T2_C


def test_t2_d_fault_wins_over_everything():
    classification, reason, _ = classify_overlap(t1_us=100, t2_us=200, trace=_trace(150),
                                                 writer_ran=True, fault="disconnect")
    assert classification == T2_D and "fault" in reason


def test_split_only_evaluated_after_overlap():
    assert classify_split("0x11", "0x22", T2_B)[0] == NO_OVERLAP
    assert classify_split("0x11", "0x22", T2_A)[0] == SPLIT_VIEW_CONFIRMED
    assert classify_split("0x11", "0x11", T2_A)[0] == OVERLAP_NO_SPLIT
    assert classify_split("0x11", "0x11", T2_A)[1].startswith("overlap confirmed")


def test_negative_control_must_hold_under_overlap():
    ok, reason = negative_control_verdict([("0x11", "0x11", True), ("0x11", "0x11", True)])
    assert ok and "identical witnesses" in reason
    bad, reason_bad = negative_control_verdict([("0x11", "0x11", True), ("0x11", "0x22", True)])
    assert not bad and "measurement model broken" in reason_bad


def test_scheduling_modes_and_limits_are_fixed_not_fuzzed():
    assert [mode for _, mode in SCHED_MODES] == [0, 1, 2]
    assert MAX_WRITER_MS == 100 and MAX_TRANSITIONS == 100000
    assert should_escalate(0.5) and not should_escalate(0.49)
