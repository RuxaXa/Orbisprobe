"""LIVE1 candidate gate, A/B classification, noise masking and two-buffer ownership (§4, §11–§13,
§21–§23). All offline: no console, no mutation.
"""

from __future__ import annotations

from dataclasses import replace

import pytest
from live0_harness import (
    FAKE_BUFFER,
    FAKE_BUFFER_B,
    FAKE_KBASE,
    FAKE_PID,
    FAKE_TEST_LENGTH,
    FAKE_TEST_OFFSET,
    ScriptedChannel,
    make_identity,
)

from orbisprobe.live.abexperiment import (
    ABClass,
    ExperimentRecord,
    byte_differences,
    classify_pair,
    mask_noise,
    noise_fields,
)
from orbisprobe.live.candidate import CandidateRecord
from orbisprobe.live.classification import AddressClass, KernelImageLayout
from orbisprobe.live.plan import ExperimentPlan, RestoreSteps, WriteOp
from orbisprobe.live.policy import LivePolicy
from orbisprobe.live.ps4_target import AdapterConfig, Ps4LiveTarget


def _candidate(**overrides) -> CandidateRecord:
    base = {
        "candidate_id": "CAND-T",
        "hypothesis": "h",
        "controlled_field": "which buffer is consumed",
        "value_a": "A",
        "value_b": "B",
        "validation": {"valid_a": True, "valid_b": True, "same_shape": True},
        "consumer": "kernel copyout",
        "expected_effect": "consumed bytes follow the selected buffer",
        "observable": ("consumed_buffer_sha256",),
        "risk": "low",
        "persistent_sinks": ("NONE",),
        "restore_plan": "READ/WRITE/READBACK/CONSUME/RESTORE/VERIFY",
    }
    base.update(overrides)
    return CandidateRecord(**base)


# ------------------------------------------------------------------ §4 candidate gate
def test_complete_candidate_is_executable():
    allowed, blockers = _candidate().gate()
    assert allowed and blockers == []


@pytest.mark.parametrize(
    "overrides",
    [
        {"observable": ()},
        {"restore_plan": ""},
        {"value_b": "A"},
        {"validation": {"valid_a": True, "valid_b": False, "same_shape": True}},
        {"validation": {"valid_a": True, "valid_b": True}},  # same_shape unproven
        {"persistent_sinks": ("SNVS_WRITE",)},
        {"notes": "reaches sflash0"},
    ],
)
def test_incomplete_or_unsafe_candidate_is_plan_only(overrides):
    allowed, blockers = _candidate(**overrides).gate()
    assert not allowed and blockers


def test_identical_inputs_require_explicit_intent():
    assert not _candidate(value_a="X", value_b="X").gate()[0]
    allowed, _ = _candidate(
        value_a="X", value_b="X", extra={"identical_inputs_intended": True}
    ).gate()
    assert allowed


# ------------------------------------------------------------------ §22/§23 noise
def test_noise_fields_and_masking():
    a = bytes([1, 2, 3, 4])
    b = bytes([1, 9, 3, 4])
    assert noise_fields(a, a) == []
    assert noise_fields(a, b) == [1]
    assert mask_noise(a, [1]) == bytes([1, 0, 3, 4])
    assert byte_differences(a, b)["count"] == 1


# ------------------------------------------------------------------ §11 classification
def _record(exp: str, consumed: str, rc: str = "0", err=None, restore="RESTORED_CONFIRMED"):
    return ExperimentRecord(
        experiment_id=exp,
        candidate_id="CAND-T",
        target_identity={},
        input_variant=exp,
        allocation={},
        controlled_field="which buffer is consumed",
        before_hash="b",
        write_hash="w",
        readback_hash="r",
        observable_hashes={"consumed_buffer_sha256": consumed, "other_buffer_sha256": "same"},
        return_status={"rc": rc},
        restore_hash="r",
        restore_state=restore,
        error=err,
        extra={"pair_id": "P1"},
    )


def test_ab_a_deterministic_sensitivity():
    pair = classify_pair(
        a=_record("A1", "hash-a"),
        b=_record("B1", "hash-b"),
        noise_offsets=[],
        expected_region=(0, 32),
    )
    assert pair.classification == ABClass.A


def test_ab_c_no_sensitivity():
    pair = classify_pair(
        a=_record("A1", "same"), b=_record("B1", "same"), noise_offsets=[], expected_region=(0, 32)
    )
    assert pair.classification == ABClass.C


def test_ab_d_one_input_rejected():
    pair = classify_pair(
        a=_record("A1", "hash-a"),
        b=_record("B1", "hash-b", rc="rejected"),
        noise_offsets=[],
        expected_region=(0, 32),
    )
    assert pair.classification == ABClass.D


def test_ab_e_fault_stops():
    pair = classify_pair(
        a=_record("A1", "hash-a", err="timeout_after_write", restore="STATE_INTEGRITY_UNKNOWN"),
        b=_record("B1", "hash-b"),
        noise_offsets=[],
        expected_region=(0, 32),
    )
    assert pair.classification == ABClass.E


def test_ab_b_unclear_attribution():
    other = _record("A1", "hash-a")
    other.observable_hashes["other_buffer_sha256"] = "changed"
    pair = classify_pair(a=other, b=_record("B1", "hash-b"), noise_offsets=[], expected_region=(0, 32))
    assert pair.classification == ABClass.B


# ------------------------------------------------------------------ §5 per-buffer ownership
def _buffer_target(**info_overrides):
    channel = ScriptedChannel(buffers=True)
    policy = LivePolicy(level="LIVE0-U")
    policy.image = KernelImageLayout(base=FAKE_KBASE)
    target = Ps4LiveTarget(
        channel,
        policy=policy,
        evidence=None,
        dry_run=False,
        identity=make_identity(),
        config=AdapterConfig(console_endpoint="fake"),
    )
    target.injection_context = {"process_name": "ScePartyDaemon", "pid": FAKE_PID}
    assert target.get_target_info()["ok"]
    info = target.payload_info
    target.payload_info = replace(info, **info_overrides) if info_overrides else info
    return target


def test_two_buffers_get_separate_ownership_records():
    target = _buffer_target()
    records, problems = target.capture_buffer_allocations(
        process_name="ScePartyDaemon", injection_pid=FAKE_PID,
        test_offset=FAKE_TEST_OFFSET, test_length=FAKE_TEST_LENGTH,
    )
    assert set(records) == {"A", "B"}
    assert problems["A"] == [] and problems["B"] == []
    assert records["A"].allocation_base == FAKE_BUFFER
    assert records["B"].allocation_base == FAKE_BUFFER_B
    assert records["A"].allocation_generation == 1
    assert records["B"].allocation_generation == 2
    assert records["A"].allocation_base != records["B"].allocation_base
    # both regions are classified USER and covered by the policy
    assert target.policy.classify(FAKE_BUFFER) is AddressClass.USER
    assert target.policy.classify(FAKE_BUFFER_B) is AddressClass.USER
    assert target.buffer_block("A") is None and target.buffer_block("B") is None


def test_shared_allocation_base_blocks_both():
    target = _buffer_target()
    from orbisprobe.live.ps4_target import BufferAllocation

    info = target.payload_info
    duplicated = tuple(
        BufferAllocation(
            name=b.name, allocation_method=b.allocation_method,
            allocation_base=FAKE_BUFFER, allocation_return=FAKE_BUFFER,
            allocation_size=b.allocation_size, generation=b.generation,
        )
        for b in info.buffers
    )
    target.payload_info = replace(info, buffers=duplicated)
    records, problems = target.capture_buffer_allocations(test_offset=0, test_length=8)
    assert records == {}
    assert any("share one allocation base" in reason for r in problems.values() for reason in r)


def test_zero_generation_blocks():
    target = _buffer_target()
    target.payload_info = replace(target.payload_info, buffers=())
    records, problems = target.capture_buffer_allocations(test_offset=0, test_length=8)
    assert records == {} and "*" in problems


def test_stale_buffer_after_instance_change():
    target = _buffer_target()
    target.capture_buffer_allocations(test_offset=0, test_length=8)
    target.payload_info = replace(target.payload_info, instance_id="0xdeadbeef")
    assert "STALE buffer A" in (target.buffer_block("A") or "")


def test_two_buffer_parsing_is_optional_for_live0():
    single = ScriptedChannel()  # buffers=False
    policy = LivePolicy(level="LIVE0-U")
    target = Ps4LiveTarget(single, policy=policy, identity=make_identity(),
                           config=AdapterConfig(console_endpoint="fake"))
    assert target.get_target_info()["ok"]
    assert target.payload_info.buffers == ()
    records, problems = target.capture_buffer_allocations()
    assert records == {} and "*" in problems


def test_exactly_one_mutation_still_enforced_for_ab_plans():

    with pytest.raises(ValueError, match="at most one mutation"):
        ExperimentPlan(
            plan_id="ab-two-writes",
            level="LIVE0-U",
            writes=(
                WriteOp(address=FAKE_BUFFER + FAKE_TEST_OFFSET, data=b"\x01", address_class="USER"),
                WriteOp(address=FAKE_BUFFER_B + FAKE_TEST_OFFSET, data=b"\x02", address_class="USER"),
            ),
            expected={"canary": "01"},
            restore_steps=RestoreSteps(True, True, True, True),
        )
