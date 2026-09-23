from pathlib import Path

from orbisprobe.evidence import EvidenceLog
from orbisprobe.policy import DEFAULT_BLOCKED_SINKS, Policy
from orbisprobe.runner import (
    ExitClassification,
    MutationLifecycle,
    RestoreState,
    Runner,
)
from orbisprobe.schema import Experiment, RiskClass, Step, experiment_sha256
from orbisprobe.targets.base import Target


class RecordingTarget(Target):
    def __init__(self, replies):
        self.replies = list(replies)
        self.calls = []

    def execute(self, kind, args):
        self.calls.append((kind, args))
        return self.replies.pop(0)


def experiment():
    return Experiment(
        id="resolved-restore",
        title="resolved restore",
        hypothesis="RAM byte is restored",
        risk=RiskClass.REVERSIBLE_KERNEL_RAM,
        controlled_input="00",
        validation="control channel ready",
        consumer="named consumer",
        expected_effect="one volatile byte",
        observable="post-write and restore readbacks",
        experiment="read, write, read, restore, verify",
        preconditions=["ready"],
        forbidden_sinks=sorted(DEFAULT_BLOCKED_SINKS),
        validation_steps=[Step("check_precondition", {"name": "ready"})],
        steps=[
            Step("read_memory", {"address": "0x1000", "length": 1}),
            Step("write_memory", {"address": "0x1000", "data_hex": "00"}),
            Step("read_memory", {"address": "0x1000", "length": 1}),
        ],
        restore_steps=[
            Step("write_saved_original", {"from_step": 0}),
            Step("verify_restored", {"from_step": 0}),
        ],
        metadata={"live_target": True},
    )


def run(target, exp, path: Path):
    return Runner(
        target,
        Policy(max_risk=RiskClass.REVERSIBLE_KERNEL_RAM),
        EvidenceLog(path),
    ).run(exp, expected_plan_sha256=experiment_sha256(exp))


def test_runner_resolves_saved_original_and_verifies_readback(tmp_path: Path):
    target = RecordingTarget([
        {"ok": True, "satisfied": True},
        {"ok": True, "address": "0x1000", "data_hex": "aa"},
        {"ok": True},
        {"ok": True, "address": "0x1000", "data_hex": "00"},
        {"ok": True},
        {"ok": True, "address": "0x1000", "data_hex": "aa"},
    ])
    exp = experiment()
    result = run(target, exp, tmp_path / "evidence.jsonl")
    assert result["exit_classification"] == ExitClassification.COMPLETED.value
    assert result["mutation_state"] == MutationLifecycle.MUTATED_CONFIRMED.value
    assert result["restore_state"] == RestoreState.RESTORED_CONFIRMED.value
    assert target.calls[4] == (
        "write_memory",
        {"address": "0x1000", "data_hex": "aa"},
    )
    assert target.calls[5] == (
        "read_memory",
        {"address": "0x1000", "length": 1},
    )


def test_restore_readback_mismatch_is_exit_4(tmp_path: Path):
    target = RecordingTarget([
        {"ok": True, "satisfied": True},
        {"ok": True, "address": "0x1000", "data_hex": "aa"},
        {"ok": True},
        {"ok": True, "address": "0x1000", "data_hex": "00"},
        {"ok": True},
        {"ok": True, "address": "0x1000", "data_hex": "bb", "restored": True},
    ])
    result = run(target, experiment(), tmp_path / "evidence.jsonl")
    assert result["exit_classification"] == ExitClassification.RESTORE_FAILURE.value
    assert result["restore_state"] == RestoreState.RESTORE_FAILED.value


def test_post_write_mismatch_is_exit_3_after_successful_restore(tmp_path: Path):
    target = RecordingTarget([
        {"ok": True, "satisfied": True},
        {"ok": True, "address": "0x1000", "data_hex": "aa"},
        {"ok": True},
        {"ok": True, "address": "0x1000", "data_hex": "bb"},
        {"ok": True},
        {"ok": True, "address": "0x1000", "data_hex": "aa"},
    ])
    result = run(target, experiment(), tmp_path / "evidence.jsonl")
    assert result["exit_classification"] == ExitClassification.RUNTIME_FAILURE.value
    assert result["restore_state"] == RestoreState.RESTORED_CONFIRMED.value
    assert result["lifecycle_state"] == MutationLifecycle.RESTORED_CONFIRMED.value
