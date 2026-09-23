"""LIVE0 adapter behaviour and failure-taxonomy tests (LIVE0 §7, §12, §13, §14, §21).

Every scenario here runs against a scripted channel: no console, no real mutation. The point is to
prove that the *host* side of the adapter cannot mis-report a mutation or a restore.
"""

from __future__ import annotations

import pytest
from live0_harness import (
    FAKE_BUFFER,
    FAKE_BUFFER_LEN,
    FAKE_KBASE,
    FAKE_PID,
    FAKE_TEST_LENGTH,
    FAKE_TEST_OFFSET,
    ScriptedChannel,
    make_identity,
    make_target,
    write_plan,
)

from orbisprobe.live.evidence import EvidenceWriter, MutationState, RestoreState
from orbisprobe.live.ps4_target import Ps4LiveTarget
from orbisprobe.live.transport import WorkerConfig


def _mutations(channel) -> list:
    """Only state-changing requests count; INFO/READ are legitimate non-mutating setup."""

    return [request for request in channel.requests if request["mutation"]]


# ------------------------------------------------------------------ happy path
def test_successful_write_cycle_confirms_mutation_and_restore():
    channel = ScriptedChannel()
    target = make_target(channel)
    result = target.write_memory(write_plan(plan_id="U-ok"), test="U2")
    assert result["result"] == "PASS"
    assert result["mutation_state"] == MutationState.MUTATION_CONFIRMED.value
    assert result["restore_state"] == RestoreState.CONFIRMED.value
    assert target.state_integrity_unknown is False
    # baseline read, write, readback, restore, restore-readback
    commands = [request["command"] for request in channel.requests]
    assert commands == ["INFO", "VERIFY", "WRITE", "VERIFY", "WRITE", "VERIFY"]


def test_canary_equal_to_baseline_aborts_before_dispatch():
    # the payload buffer starts filled with 0x5a; a canary of the same bytes is not a mutation
    channel = ScriptedChannel()
    target = make_target(channel)
    plan = write_plan(plan_id="U-same", canary=b"\x5a" * 16)
    result = target.write_memory(plan, test="U-same")
    assert result["result"] == "ABORT"
    assert result["error_type"] == "canary_equals_baseline"
    assert all(not request["mutation"] for request in channel.requests)


def test_baseline_failure_aborts_before_dispatch():
    channel = ScriptedChannel(fail_on={"READ": "read_fault"})
    target = make_target(channel)
    result = target.write_memory(write_plan(plan_id="U-nobase"), test="U-nobase")
    assert result["result"] == "ABORT"
    assert result["error_type"] == "baseline_failed"
    assert all(not request["mutation"] for request in channel.requests)


# ------------------------------------------------------------------ §14 dry run
def test_dry_run_never_dispatches_and_reports_the_plan():
    channel = ScriptedChannel()
    target = make_target(channel, dry_run=True)
    result = target.write_memory(write_plan(plan_id="U-dry"), test="U-dry")
    assert result["result"] == "DRY_RUN"
    # a dry run may still read (it must report the original hash) but must never dispatch a write
    assert all(not request["mutation"] for request in channel.requests)
    assert [request["command"] for request in channel.requests] == ["INFO", "VERIFY"]
    assert target.state_integrity_unknown is False


# ------------------------------------------------------------------ §21 failures
def test_timeout_before_write_is_not_a_mutation():
    channel = ScriptedChannel(fail_on={"READ": "timeout_before_write"})
    target = make_target(channel)
    result = target.write_memory(write_plan(plan_id="F1"), test="F1")
    assert result["result"] == "ABORT"
    assert result["error_type"] == "baseline_failed"
    assert target.state_integrity_unknown is False


def test_timeout_after_write_dispatch_is_attempted_and_latches_when_unverified():
    channel = ScriptedChannel(fail_on={"WRITE": "timeout_after_write"})
    target = make_target(channel)
    result = target.write_memory(write_plan(plan_id="F2"), test="F2")
    assert result["mutation_state"] in {
        MutationState.MUTATION_ATTEMPTED.value,
        MutationState.RESTORE_ATTEMPTED.value,
    }
    assert result["restore_state"] == RestoreState.UNKNOWN.value
    assert result["result"] == "FAIL"
    assert target.state_integrity_unknown is True
    assert "timeout_after_write" in (result["error"] or "")


def test_disconnect_before_restore_latches_state_integrity_unknown():
    channel = ScriptedChannel(fail_on={"WRITE": "disconnect_before_restore"})
    target = make_target(channel)
    result = target.write_memory(write_plan(plan_id="F3"), test="F3")
    assert result["mutation_state"] == MutationState.MUTATION_ATTEMPTED.value
    assert result["restore_state"] == RestoreState.UNKNOWN.value
    assert target.state_integrity_unknown is True


def test_malformed_and_partial_responses_are_structured_errors():
    for fault, expected in (
        ("malformed_response", "malformed_response"),
        ("partial_response", "partial_response"),
    ):
        channel = ScriptedChannel(fail_on={"READ": fault})
        target = make_target(channel)
        result = target.read_memory(FAKE_KBASE, 16, test="F4")
        assert result["ok"] is False
        assert result["error_type"] == expected


def test_readback_mismatch_is_detected_and_still_restores():
    # baseline comes from the channel's own buffer, then the write is accepted, so the readback
    # equals the canary; here we force a mismatch by making the write a no-op with a fresh buffer
    channel2 = ScriptedChannel()
    target2 = make_target(channel2)
    result = target2.write_memory(write_plan(plan_id="F5"), test="F5")
    assert result["mutation_state"] == MutationState.MUTATION_CONFIRMED.value

    # now a channel whose writes never land -> mutation cannot be confirmed, restore is still run
    class NoOpWrites(ScriptedChannel):
        def request(self, command, *, timeout=None, mutation=False, expect=None, **fields):
            if command == "WRITE":
                self.requests.append({"command": command, "fields": fields, "mutation": mutation})
                return {"ok": True, "command": "WRITE", "rc": "0"}
            if command in {"READ", "VERIFY"}:
                self.requests.append({"command": command, "fields": fields, "mutation": False})
                length = int(fields["len"])
                return {"ok": True, "command": command, "rc": "0", "hex": "5a" * length}
            return super().request(
                command, timeout=timeout, mutation=mutation, expect=expect, **fields
            )

    target3 = make_target(NoOpWrites())
    result3 = target3.write_memory(write_plan(plan_id="F5b"), test="F5b")
    assert result3["mutation_state"] == MutationState.MUTATION_FAILED.value
    assert result3["restore_state"] == RestoreState.CONFIRMED.value
    assert result3["result"] == "FAIL"
    commands = [request["command"] for request in target3.channel.requests]
    assert commands == ["INFO", "VERIFY", "WRITE", "VERIFY", "WRITE", "VERIFY"]


def test_restore_mismatch_is_a_restore_failure_and_latches():
    channel = ScriptedChannel(fail_on={"READ": "restore_readback_mismatch"})
    target = make_target(channel)
    result = target.write_memory(write_plan(plan_id="F6"), test="F6")
    # the mutation was dispatched, so it can never be reported as "nothing happened"
    assert result["mutation_state"] in {
        MutationState.MUTATION_ATTEMPTED.value,
        MutationState.MUTATION_FAILED.value,
    }
    assert result["mutation_state"] != MutationState.NONE.value
    assert result["restore_state"] == RestoreState.UNKNOWN.value
    assert target.state_integrity_unknown is True


def test_latched_target_refuses_further_mutations():
    channel = ScriptedChannel()
    target = make_target(channel, state_integrity_unknown=True)
    result = target.write_memory(write_plan(plan_id="F7"), test="F7")
    assert result["result"] == "BLOCK"
    assert _mutations(channel) == []


# ------------------------------------------------------------------ §13 truth boundary
def test_write_success_claim_requires_independent_readback():
    """Adapter 'ok' from the payload alone must not be accepted as the mutation proof."""

    class LyingChannel(ScriptedChannel):
        def request(self, command, *, timeout=None, mutation=False, expect=None, **fields):
            response = super().request(
                command, timeout=timeout, mutation=mutation, expect=expect, **fields
            )
            if command == "WRITE":
                return response  # payload claims success
            if command in {"READ", "VERIFY"}:
                length = int(fields["len"])
                return {"ok": True, "command": command, "rc": "0", "hex": "5a" * length}
            return response

    target = make_target(LyingChannel())
    result = target.write_memory(write_plan(plan_id="T1"), test="T1")
    assert result["mutation_state"] == MutationState.MUTATION_FAILED.value
    assert result["result"] != "PASS"


def test_write_memory_without_plan_is_refused():
    channel = ScriptedChannel()
    target = make_target(channel)
    result = target.execute("write_memory", {"address": FAKE_BUFFER, "data_hex": "aa" * 16})
    assert result["result"] == "BLOCK"
    assert result["error_type"] == "plan_required"
    assert _mutations(channel) == []


def test_unsupported_operation_is_reported_not_executed():
    target = make_target(ScriptedChannel())
    result = target.execute("shell", {"cmd": "id"})
    assert result["ok"] is False
    assert result["error_type"] == "unsupported_operation"


# ------------------------------------------------------------------ §5 protocol
def test_protocol_frames_roundtrip():
    from orbisprobe.live.channel import encode_frame, parse_response

    frame = encode_frame(b"OK PING payload=live0-1 uptime_ms=7")
    assert frame[:1] == b"#"
    assert int(frame[1:9], 16) == len(frame) - 9
    parsed = parse_response(b"OK READ kaddr=0x10 len=0x4 rc=0 hex=deadbeef")
    assert parsed["ok"] is True
    assert parsed["command"] == "READ"
    assert parsed["hex"] == "deadbeef"
    err = parse_response(b"ERR READ code=6 msg=read_fault")
    assert err["ok"] is False
    assert err["code"] == "6"


# ------------------------------------------------------------------ evidence
def test_evidence_rows_are_written_for_a_cycle(tmp_path):
    writer = EvidenceWriter(tmp_path, "run1")
    channel = ScriptedChannel()
    target = make_target(channel, evidence=writer)
    target.write_memory(write_plan(plan_id="E1"), test="U2")
    rows = writer.records
    assert rows, "no evidence recorded"
    mutation_rows = [row for row in rows if row.operation == "write_memory"]
    assert len(mutation_rows) == 1
    row = mutation_rows[0]
    assert row.mutation_state == MutationState.MUTATION_CONFIRMED.value
    assert row.restore_state == RestoreState.CONFIRMED.value
    assert row.target_name == "ps4b-cuh2116a"
    assert row.session_id == "sess-a"
    assert row.sha256 and len(row.sha256) == 64
    assert (tmp_path / "run1.jsonl").is_file()


def test_worker_config_defaults_match_the_established_infrastructure():
    config = WorkerConfig()
    assert config.ssh_target == "neo@192.168.1.148"
    assert config.console_ip == "192.168.1.141"
    assert config.payload_port == 9090
    assert config.bridge_payload_port == 9025


def test_adapter_has_no_shell_primitive():
    target = Ps4LiveTarget.__dict__
    public = {name for name in target if not name.startswith("_")}
    assert "shell" not in public
    assert "exec" not in public
    # the interface is exactly the documented primitive set
    for kind in (
        "ping",
        "get_target_info",
        "get_kbase",
        "read_memory",
        "write_memory",
        "readback",
        "snapshot_state",
        "get_klog",
        "get_process_info",
    ):
        assert kind in public


def test_buffer_bounds_are_enforced_by_the_host_too():
    channel = ScriptedChannel()
    target = make_target(channel)
    # a USER-class address outside the owned buffer is refused before any I/O
    outside = 0x0000000040000000
    result = target.read_memory(outside, 16, test="B1")
    assert result["result"] == "BLOCK"
    assert _mutations(channel) == []


def test_read_limits_are_enforced_on_the_primitive():
    channel = ScriptedChannel()
    target = make_target(channel)
    result = target.read_memory(FAKE_BUFFER, FAKE_BUFFER_LEN + 0x1000, test="B2")
    assert result["result"] == "BLOCK"
    assert _mutations(channel) == []


@pytest.mark.parametrize("level", ["LIVE0-R", "LIVE0-U", "LIVE0-S"])
def test_policy_level_binding(level):
    channel = ScriptedChannel()
    target = make_target(channel, level=level)
    plan = write_plan(address=FAKE_BUFFER, length=16, plan_id=f"L-{level}", level=level)
    if level == "LIVE0-R":
        assert target.write_memory(plan, test="L")["result"] == "BLOCK"
    else:
        assert target.write_memory(plan, test="L")["result"] == "PASS"


# ------------------------------------------------------------------ ownership gate
def _bare_target(channel, **payload_overrides):
    """A target whose parsed PayloadInfo comes from the real INFO pipeline."""

    from dataclasses import replace

    from orbisprobe.live.classification import (
        AddressClass,
        KernelImageLayout,
        region_of,
    )
    from orbisprobe.live.policy import LivePolicy
    from orbisprobe.live.ps4_target import AdapterConfig, Ps4LiveTarget

    policy = LivePolicy(level="LIVE0-U")
    policy.image = KernelImageLayout(base=FAKE_KBASE)
    policy.owned_regions = (
        region_of("live0-test-buffer", FAKE_BUFFER, FAKE_BUFFER_LEN, AddressClass.USER),
    )
    target = Ps4LiveTarget(
        channel,
        policy=policy,
        evidence=None,
        dry_run=False,
        identity=make_identity(),
        config=AdapterConfig(console_endpoint="fake"),
    )
    target.injection_context = {"process_name": "ScePartyDaemon", "pid": FAKE_PID}
    info = target.get_target_info()
    assert info.get("ok"), info
    if payload_overrides:
        assert target.payload_info is not None
        target.payload_info = replace(target.payload_info, **payload_overrides)
    return target


def test_ownership_gate_requires_a_captured_allocation():
    channel = ScriptedChannel()
    target = _bare_target(channel)
    result = target.write_memory(write_plan(plan_id="OWN-none"), test="OWN-none")
    assert result["result"] == "BLOCK"
    assert "no allocation record" in result["error"]
    assert _mutations(channel) == []


def test_ownership_gate_rejects_provenance_that_is_not_an_allocation_call():
    channel = ScriptedChannel()
    target = _bare_target(channel, allocation_method="pattern_search")
    assert target.capture_allocation(process_name="p", injection_pid=FAKE_PID) is None
    assert target.write_memory(write_plan(plan_id="OWN-call"), test="OWN-call")["result"] == "BLOCK"


def test_ownership_gate_rejects_buffer_that_is_not_the_allocation_result():
    channel = ScriptedChannel()
    target = _bare_target(channel, allocation_base=FAKE_BUFFER + 0x40)
    assert target.capture_allocation(process_name="p", injection_pid=FAKE_PID) is None


def test_ownership_gate_rejects_pid_mismatch_with_the_loader():
    channel = ScriptedChannel()
    target = _bare_target(channel)
    assert target.capture_allocation(process_name="p", injection_pid=FAKE_PID + 1) is None


def test_ownership_gate_accepts_the_payloads_own_allocation():
    channel = ScriptedChannel()
    target = _bare_target(channel)
    record = target.capture_allocation(
        process_name="ScePartyDaemon",
        injection_pid=FAKE_PID,
        test_offset=FAKE_TEST_OFFSET,
        test_length=FAKE_TEST_LENGTH,
    )
    assert record is not None
    assert record.allocation_base == FAKE_BUFFER
    assert record.test_base == FAKE_BUFFER + FAKE_TEST_OFFSET
    assert record.pid == FAKE_PID
    assert record.process_name == "ScePartyDaemon"
    assert record.allocation_generation == 1


def test_stale_allocation_is_refused_after_a_reload():
    channel = ScriptedChannel()
    target = make_target(channel)
    assert target.allocation is not None
    from dataclasses import replace as _replace

    target.payload_info = _replace(target.payload_info, instance_id="0xdeadbeef")
    result = target.write_memory(write_plan(plan_id="OWN-stale"), test="OWN-stale")
    assert result["result"] == "BLOCK"
    assert "STALE buffer" in result["error"]
    assert _mutations(channel) == []


def test_stale_allocation_is_refused_when_the_session_changes():
    channel = ScriptedChannel()
    target = make_target(channel)
    target.identity = make_identity(session_id="new-boot-session")
    result = target.write_memory(write_plan(plan_id="OWN-session"), test="OWN-session")
    assert result["result"] == "BLOCK"
    assert "STALE buffer" in result["error"]


def test_test_range_is_bounded_by_the_allocation():
    channel = ScriptedChannel()
    target = make_target(channel)
    base, length = target.test_range(FAKE_TEST_LENGTH)
    assert base == FAKE_BUFFER + FAKE_TEST_OFFSET
    assert length == FAKE_TEST_LENGTH
    assert FAKE_TEST_OFFSET + FAKE_TEST_LENGTH <= FAKE_BUFFER_LEN
    with pytest.raises(ValueError, match="exceeds allocation"):
        target.test_range(FAKE_BUFFER_LEN)


def test_plan_address_outside_the_allocation_is_refused():
    channel = ScriptedChannel()
    target = make_target(channel)
    plan = write_plan(address=FAKE_BUFFER - 0x10, length=16, plan_id="OWN-outside")
    result = target.write_memory(plan, test="OWN-outside")
    assert result["result"] == "BLOCK"
    assert _mutations(channel) == []


def test_dry_run_reports_every_required_field():
    channel = ScriptedChannel()
    target = make_target(channel, dry_run=True)
    plan = write_plan(
        address=FAKE_BUFFER + FAKE_TEST_OFFSET, length=FAKE_TEST_LENGTH, plan_id="U-dry-report"
    )
    result = target.write_memory(plan, test="U-dry")
    assert result["result"] == "DRY_RUN"
    report = result["dry_run"]
    for key in (
        "target_identity",
        "pid",
        "process_name",
        "allocation",
        "address_class",
        "address",
        "length",
        "original_sha256",
        "write_sha256",
        "restore_sha256",
        "persistent_sinks",
        "mutations",
        "restore_steps",
    ):
        assert key in report, key
    assert report["address_class"] == "USER"
    assert report["mutations"] == 1
    assert report["persistent_sink_touched"] is False
    assert all(report["restore_steps"].values())
    assert report["original_sha256"] == report["restore_sha256"]
    assert [request["command"] for request in channel.requests] == ["INFO", "VERIFY"]


def test_kbase_is_read_from_the_payload_and_not_cached_across_boots():
    channel = ScriptedChannel()
    target = make_target(channel)
    target.kernel_base = None
    info = target.get_target_info()
    assert info["ok"] is True
    assert int(info["kbase"], 16) == FAKE_KBASE
    assert target.kernel_base == FAKE_KBASE
    identity = make_identity(kernel_base=0xFFFFFFFF90000000)
    assert identity.check_staleness(target.kernel_base) is not None





