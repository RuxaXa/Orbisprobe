"""LIVE0 policy, classification and plan-validation tests (LIVE0 §4, §15, §16, §20).

These are the negative tests A–G from the live checklist. They must all pass without a console and
must never dispatch a mutation.
"""

from __future__ import annotations

import pytest
from live0_harness import (
    FAKE_BUFFER,
    FAKE_KBASE,
    RecordingOnlyChannel,
    make_identity,
    make_policy,
    make_target,
    write_plan,
)

from orbisprobe.live.classification import (
    AddressClass,
    KernelImageLayout,
    classify,
    is_canonical,
)
from orbisprobe.live.plan import (
    ExperimentPlan,
    ReadOp,
    RestoreSteps,
    WriteOp,
    canary_for,
)
from orbisprobe.live.policy import HARD_BLOCK_SINKS, LivePolicy, PersistentSink


# ------------------------------------------------------------------ classification
def test_classification_ranges_are_explicit():
    image = KernelImageLayout(base=FAKE_KBASE)
    assert classify(FAKE_KBASE + 0x1000, image=image) is AddressClass.KERNEL_TEXT
    assert classify(FAKE_KBASE + 0x1200000, image=image) is AddressClass.KERNEL_DATA
    assert classify(0xFFFF82DA44230000, image=image) is AddressClass.KERNEL_HEAP
    assert classify(0xFFFFFF8100000000, image=image) is AddressClass.DIRECT_MAP
    assert classify(0x00000000E4800000, image=image) is AddressClass.MMIO
    assert classify(0x00000000F8000000, image=image) is AddressClass.MMIO
    assert classify(0xDEADBEEF, image=image) is AddressClass.UNKNOWN


def test_owned_region_is_the_only_user_class():
    policy = make_policy("LIVE0-U")
    assert policy.classify(FAKE_BUFFER) is AddressClass.USER
    # a plausible user address that we do not own is not USER
    assert policy.classify(0x0000000040000000) is AddressClass.UNKNOWN


def test_non_canonical_addresses_are_unknown():
    assert not is_canonical(-1)
    assert not is_canonical(0x0000800000000000_0)
    # 0x0000800000000000 itself is still canonical, but it is not a class we own
    assert is_canonical(0x0000800000000000)
    assert is_canonical(0xFFFF800000000000)
    assert classify(0x0000800000000000) is AddressClass.UNKNOWN


def test_mmio_read_is_blocked_by_default():
    policy = make_policy("LIVE0-R")
    plan = ExperimentPlan(
        plan_id="mmio",
        level="LIVE0-R",
        reads=(ReadOp(address=0xF8000000, length=16, address_class="UNKNOWN"),),
    )
    decision = policy.evaluate(plan, make_identity())
    assert not decision.allowed
    assert any("MMIO" in block for block in decision.blocks)


# ------------------------------------------------------------------ §20 negatives
def test_negative_A_write_to_kernel_text_is_blocked():
    policy = make_policy("LIVE0-U")
    plan = write_plan(address=FAKE_KBASE + 0x1000, length=16, plan_id="negA")
    decision = policy.evaluate(plan, make_identity())
    assert not decision.allowed
    assert any("KERNEL_TEXT" in block for block in decision.blocks)


def test_negative_B_write_to_unknown_is_blocked():
    policy = make_policy("LIVE0-U")
    plan = write_plan(address=0xDEADBEEF, length=16, plan_id="negB")
    decision = policy.evaluate(plan, make_identity())
    assert not decision.allowed
    assert any("UNKNOWN" in block for block in decision.blocks)


def test_negative_C_write_without_restore_steps_cannot_even_be_built():
    # The plan model refuses to exist, which is strictly stronger than a policy block.
    with pytest.raises(ValueError, match="complete restore steps"):
        write_plan(address=FAKE_BUFFER, length=16, plan_id="negC", complete_restore=False)
    # and a plan whose restore steps are stripped *after* construction is re-checked by policy
    plan = write_plan(address=FAKE_BUFFER, length=16, plan_id="negC-forced")
    plan.restore_steps = RestoreSteps()
    decision = make_policy("LIVE0-U").evaluate(plan, make_identity())
    assert not decision.allowed
    assert any("restore steps" in block for block in decision.blocks)


@pytest.mark.parametrize("sink", sorted(HARD_BLOCK_SINKS))
def test_negative_D_persistent_sinks_are_hard_blocked(sink):
    policy = make_policy("LIVE0-U")
    plan = write_plan(address=FAKE_BUFFER, length=16, plan_id="negD", declared_sink=sink)
    decision = policy.evaluate(plan, make_identity())
    assert not decision.allowed
    assert any("persistent hard block" in block for block in decision.blocks)


@pytest.mark.parametrize(
    "note",
    ["write via sflash0", "pup_update ioctl", "SNVS record append", "syscon state", "elf_sign_check"],
)
def test_negative_D_keywords_in_notes_are_hard_blocked(note):
    policy = make_policy("LIVE0-U")
    plan = write_plan(address=FAKE_BUFFER, length=16, plan_id="negD-note", notes=note)
    decision = policy.evaluate(plan, make_identity())
    assert not decision.allowed


def test_negative_E_oversized_write_is_blocked():
    policy = make_policy("LIVE0-U")
    canary = bytes(0x1800)  # above LIVE0 max_write; cannot come from canary_for
    plan = ExperimentPlan(
        plan_id="negE",
        level="LIVE0-U",
        writes=(WriteOp(address=FAKE_BUFFER, data=canary, address_class="USER"),),
        expected={"canary": canary.hex()},
        restore_steps=RestoreSteps(True, True, True, True),
    )
    decision = policy.evaluate(plan, make_identity())
    assert not decision.allowed
    assert any("max_write" in block for block in decision.blocks)


def test_negative_E_oversized_read_is_blocked():
    policy = make_policy("LIVE0-R")
    plan = ExperimentPlan(
        plan_id="negE-read",
        level="LIVE0-R",
        reads=(ReadOp(address=FAKE_KBASE, length=0x2000, address_class="UNKNOWN"),),
    )
    decision = policy.evaluate(plan, make_identity())
    assert not decision.allowed
    assert any("max_read" in block for block in decision.blocks)


def test_negative_F_wrong_target_identity_is_blocked():
    policy = make_policy("LIVE0-U")
    identity = make_identity()
    plan = write_plan(address=FAKE_BUFFER, length=16, plan_id="negF")
    plan.expected["session_id"] = "some-other-session"
    plan.expected["target_name"] = "ps4a-dead"
    decision = policy.evaluate(plan, identity)
    assert not decision.allowed
    assert any("identity mismatch" in block for block in decision.blocks)
    assert any("target mismatch" in block for block in decision.blocks)


def test_negative_G_stale_kernel_base_is_blocked():
    policy = make_policy("LIVE0-U")
    identity = make_identity(kernel_base=0xFFFFFFFF90000000)
    plan = write_plan(address=FAKE_BUFFER, length=16, plan_id="negG")
    decision = policy.evaluate(plan, identity, live_kernel_base=FAKE_KBASE)
    assert not decision.allowed
    assert any("stale identity" in block for block in decision.blocks)

    plan2 = write_plan(address=FAKE_BUFFER, length=16, plan_id="negG2")
    plan2.expected["kernel_base"] = 0xFFFFFFFF90000000
    decision2 = policy.evaluate(plan2, make_identity(), live_kernel_base=FAKE_KBASE)
    assert not decision2.allowed
    assert any("stale kernel base in plan" in block for block in decision2.blocks)


def test_mutating_plan_is_refused_in_read_only_level():
    policy = make_policy("LIVE0-R")
    plan = write_plan(address=FAKE_BUFFER, length=16, plan_id="ro", level="LIVE0-R")
    decision = policy.evaluate(plan, make_identity())
    assert not decision.allowed
    assert any("read-only" in block for block in decision.blocks)


def test_negative_tests_dispatch_no_mutation():
    """A blocked state-changing request must never reach the wire."""

    channel = RecordingOnlyChannel()
    target = make_target(channel, level="LIVE0-U")
    plan = write_plan(address=FAKE_KBASE + 0x1000, length=16, plan_id="negA-live")
    result = target.write_memory(plan, test="negA")
    assert result["result"] == "BLOCK"
    assert [r for r in channel.requests if r["mutation"]] == []
    assert target.state_integrity_unknown is False


# ------------------------------------------------------------------ plan model
def test_plan_allows_at_most_one_mutation():
    with pytest.raises(ValueError, match="at most one mutation"):
        ExperimentPlan(
            plan_id="two-writes",
            level="LIVE0-U",
            writes=(
                WriteOp(address=FAKE_BUFFER, data=b"\x01", address_class="USER"),
                WriteOp(address=FAKE_BUFFER + 8, data=b"\x02", address_class="USER"),
            ),
            expected={"canary": "01"},
            restore_steps=RestoreSteps(True, True, True, True),
        )


def test_canary_is_deterministic_and_experiment_scoped():
    a1 = canary_for("exp-1", 32)
    a2 = canary_for("exp-1", 32)
    b1 = canary_for("exp-2", 32)
    assert a1 == a2
    assert a1 != b1
    assert len(a1) == 32


def test_persistent_sink_enum_matches_policy_table():
    assert set(HARD_BLOCK_SINKS) == {item.value for item in PersistentSink}


def test_policy_serialisation_lists_the_hard_blocks():
    payload = LivePolicy().to_dict()
    assert "SNVS_WRITE" in payload["hard_block_sinks"]
    assert payload["allowed_write_classes"] == ["USER"]
    assert payload["max_read"] == 0x1000

