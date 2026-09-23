import json
import sys
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
from orbisprobe.targets.command_adapter import CommandAdapter


class RecordingTarget(Target):
    def __init__(self, replies):
        self.replies = list(replies)
        self.calls = []

    def execute(self, kind, args):
        self.calls.append((kind, args))
        reply = self.replies.pop(0)
        if isinstance(reply, BaseException):
            raise reply
        return reply


class FailingEvidence(EvidenceLog):
    def __init__(self, path: Path, fail_from_call: int):
        super().__init__(path)
        self.calls = 0
        self.fail_from_call = fail_from_call

    def append(self, run_id, experiment_id, kind, data):
        self.calls += 1
        if self.calls >= self.fail_from_call:
            raise OSError("simulated evidence storage failure")
        return super().append(run_id, experiment_id, kind, data)


def reversible_experiment(*, steps=None, restore_steps=None, metadata=None) -> Experiment:
    return Experiment(
        id="reversible",
        title="reversible",
        hypothesis="a bounded RAM write has a bounded effect",
        risk=RiskClass.REVERSIBLE_KERNEL_RAM,
        controlled_input="one byte",
        validation="check control channel and pre-image",
        consumer="named kernel RAM consumer",
        expected_effect="bounded volatile effect",
        observable="write and restore readback",
        experiment="write, observe, restore, verify",
        preconditions=["control_channel_ready"],
        forbidden_sinks=sorted(DEFAULT_BLOCKED_SINKS),
        validation_steps=[Step("check_precondition", {"name": "control_channel_ready"})],
        steps=steps or [
            Step("read_memory", {"address": "0x1000", "length": 1}),
            Step("write_memory", {"address": "0x1000", "data_hex": "00"}),
            Step("read_memory", {"address": "0x1000", "length": 1}),
        ],
        restore_steps=restore_steps or [
            Step("write_saved_original", {"from_step": 0}),
            Step("verify_restored", {"from_step": 0}),
        ],
        metadata={"live_target": True, **(metadata or {})},
    )


def run_with_hash(runner: Runner, exp: Experiment):
    return runner.run(exp, expected_plan_sha256=experiment_sha256(exp))


def summaries(path: Path) -> list[dict]:
    return [event for event in EvidenceLog(path).read() if event["kind"] == "summary"]


def test_validation_failure_executes_no_experiment_steps(tmp_path: Path):
    target = RecordingTarget([{"ok": True, "satisfied": False}])
    exp = reversible_experiment()
    evidence = tmp_path / "evidence.jsonl"
    result = run_with_hash(
        Runner(target, Policy(max_risk=RiskClass.REVERSIBLE_KERNEL_RAM), EvidenceLog(evidence)),
        exp,
    )
    assert result["exit_classification"] == ExitClassification.BLOCKED.value
    assert result["executed_steps"] == 0
    assert target.calls == [("check_precondition", {"name": "control_channel_ready"})]
    assert summaries(evidence)[-1]["data"]["executed_steps"] == 0


def test_runtime_failure_before_mutation_does_not_restore(tmp_path: Path):
    target = RecordingTarget([
        {"ok": True, "satisfied": True},
        {"ok": False, "error": "read failed"},
    ])
    exp = reversible_experiment(
        steps=[
            Step("read_memory", {"address": "0x1000", "length": 1}),
            Step("write_memory", {"address": "0x1000", "data_hex": "00"}),
            Step("read_memory", {"address": "0x1000", "length": 1}),
        ]
    )
    result = run_with_hash(
        Runner(target, Policy(max_risk=RiskClass.REVERSIBLE_KERNEL_RAM), EvidenceLog(tmp_path / "e.jsonl")),
        exp,
    )
    assert result["exit_classification"] == ExitClassification.RUNTIME_FAILURE.value
    assert result["mutation_state"] == MutationLifecycle.NOT_MUTATED.value
    assert result["restore_state"] == RestoreState.NOT_ATTEMPTED.value
    assert result["restore_steps_executed"] == 0
    assert [kind for kind, _ in target.calls] == ["check_precondition", "read_memory"]


def test_partial_write_failure_attempts_restore(tmp_path: Path):
    target = RecordingTarget([
        {"ok": True, "satisfied": True},
        {"ok": True, "data_hex": "aa"},
        {"ok": False, "error": "timeout after dispatch", "error_type": "adapter_timeout"},
        {"ok": True},
        {"ok": True, "data_hex": "aa"},
    ])
    exp = reversible_experiment()
    result = run_with_hash(
        Runner(target, Policy(max_risk=RiskClass.REVERSIBLE_KERNEL_RAM), EvidenceLog(tmp_path / "e.jsonl")),
        exp,
    )
    assert result["exit_classification"] == ExitClassification.RUNTIME_FAILURE.value
    assert result["mutation_state"] == MutationLifecycle.MUTATION_ATTEMPTED.value
    assert result["restore_state"] == RestoreState.RESTORED_CONFIRMED.value
    assert result["lifecycle_state"] == MutationLifecycle.RESTORED_CONFIRMED.value
    assert [kind for kind, _ in target.calls] == [
        "check_precondition", "read_memory", "write_memory",
        "write_memory", "read_memory"
    ]


def test_successful_reversible_write_restores_and_completes(tmp_path: Path):
    target = RecordingTarget([
        {"ok": True, "satisfied": True},
        {"ok": True, "data_hex": "aa"},
        {"ok": True, "mutated_confirmed": True},
        {"ok": True, "data_hex": "00"},
        {"ok": True},
        {"ok": True, "data_hex": "aa"},
    ])
    exp = reversible_experiment()
    result = run_with_hash(
        Runner(target, Policy(max_risk=RiskClass.REVERSIBLE_KERNEL_RAM), EvidenceLog(tmp_path / "e.jsonl")),
        exp,
    )
    assert result["exit_classification"] == ExitClassification.COMPLETED.value
    assert result["mutation_state"] == MutationLifecycle.MUTATED_CONFIRMED.value
    assert result["restore_state"] == RestoreState.RESTORED_CONFIRMED.value


def test_restore_failure_latches_runner_against_future_mutation(tmp_path: Path):
    target = RecordingTarget([
        {"ok": True, "satisfied": True},
        {"ok": True, "data_hex": "aa"},
        {"ok": True, "mutated_confirmed": True},
        {"ok": True, "data_hex": "00"},
        {"ok": False, "error": "restore failed"},
        {"ok": False, "error": "restore readback failed"},
    ])
    exp = reversible_experiment()
    runner = Runner(
        target,
        Policy(max_risk=RiskClass.REVERSIBLE_KERNEL_RAM),
        EvidenceLog(tmp_path / "e.jsonl"),
    )
    first = run_with_hash(runner, exp)
    calls_after_first = list(target.calls)
    second = run_with_hash(runner, exp)
    assert first["exit_classification"] == ExitClassification.RESTORE_FAILURE.value
    assert first["restore_state"] == RestoreState.RESTORE_FAILED.value
    assert second["exit_classification"] == ExitClassification.RESTORE_FAILURE.value
    assert second["executed_steps"] == 0
    assert target.calls == calls_after_first


def test_malformed_adapter_response_is_runtime_failure(tmp_path: Path):
    target = RecordingTarget([
        {"ok": True, "satisfied": True},
        ["not", "an", "object"],
    ])
    exp = reversible_experiment()
    result = run_with_hash(
        Runner(target, Policy(max_risk=RiskClass.REVERSIBLE_KERNEL_RAM), EvidenceLog(tmp_path / "e.jsonl")),
        exp,
    )
    assert result["exit_classification"] == ExitClassification.RUNTIME_FAILURE.value
    assert "malformed adapter response" in result["error"]
    assert result["restore_steps_executed"] == 0


def test_evidence_summary_contains_required_contract_fields(tmp_path: Path):
    target = RecordingTarget([
        {"ok": True, "satisfied": True},
        {"ok": True, "data_hex": "aa"},
        {"ok": True, "mutated_confirmed": True},
        {"ok": True, "data_hex": "00"},
        {"ok": True},
        {"ok": True, "data_hex": "aa"},
    ])
    exp = reversible_experiment()
    evidence = tmp_path / "evidence.jsonl"
    result = run_with_hash(
        Runner(target, Policy(max_risk=RiskClass.REVERSIBLE_KERNEL_RAM), EvidenceLog(evidence)),
        exp,
    )
    summary = summaries(evidence)[-1]["data"]
    assert summary["plan_sha256"] == experiment_sha256(exp)
    assert summary["policy"]["max_risk"] == "reversible_kernel_ram"
    assert summary["exit_classification"] == "completed"
    assert summary["executed_steps"] == 3
    assert summary["mutation_state"] == "MUTATED_CONFIRMED"
    assert summary["restore_state"] == "RESTORED_CONFIRMED"
    assert summary["stop_reason"] is None
    assert summary["adapter_errors"] == []
    assert summary["oracle_results"] == []
    assert result["ok"] is True


def test_evidence_sanitizes_secrets_and_large_hex(tmp_path: Path):
    evidence = EvidenceLog(tmp_path / "evidence.jsonl")
    secret = "super-secret-token"
    full_hex = "ab" * 1024
    evidence.append(
        "run",
        "exp",
        "step",
        {"token": secret, "data_hex": full_hex},
    )
    raw = (tmp_path / "evidence.jsonl").read_text(encoding="utf-8")
    event = json.loads(raw)
    assert secret not in raw
    assert full_hex not in raw
    assert event["data"]["token"] == "[REDACTED]"
    assert event["data"]["data_hex_bytes"] == 1024
    assert len(event["data"]["data_hex_sha256"]) == 64


def test_adapter_exit_failure_is_structured():
    adapter = CommandAdapter([sys.executable, "-c", "raise SystemExit(7)"])
    result = adapter.execute("read_memory", {})
    assert result["ok"] is False
    assert result["error_type"] == "adapter_exit_failure"
    assert result["returncode"] == 7


def test_malformed_adapter_json_is_structured():
    adapter = CommandAdapter([sys.executable, "-c", "print('not-json')"])
    result = adapter.execute("read_memory", {})
    assert result["ok"] is False
    assert result["error_type"] == "malformed_adapter_response"


def test_evidence_failure_after_write_does_not_skip_restore(tmp_path: Path):
    target = RecordingTarget([
        {"ok": True, "satisfied": True},
        {"ok": True, "data_hex": "aa"},
        {"ok": True},
        {"ok": True},
        {"ok": True, "data_hex": "aa"},
    ])
    exp = reversible_experiment()
    runner = Runner(
        target,
        Policy(max_risk=RiskClass.REVERSIBLE_KERNEL_RAM),
        FailingEvidence(tmp_path / "evidence.jsonl", fail_from_call=4),
    )
    result = runner.run(exp, expected_plan_sha256=experiment_sha256(exp))
    assert [kind for kind, _ in target.calls] == [
        "check_precondition", "read_memory", "write_memory", "write_memory", "read_memory"
    ]
    assert result["exit_classification"] == ExitClassification.RESTORE_FAILURE.value
    assert result["restore_state"] == RestoreState.RESTORE_FAILED.value


def test_programmatic_invalid_plan_is_blocked_before_target(tmp_path: Path):
    target = RecordingTarget([])
    exp = reversible_experiment(metadata={"invalid": object()})
    exp.metadata = None
    result = Runner(
        target,
        Policy(max_risk=RiskClass.REVERSIBLE_KERNEL_RAM),
        EvidenceLog(tmp_path / "evidence.jsonl"),
    ).run(exp, expected_plan_sha256="0" * 64)
    assert result["exit_classification"] == ExitClassification.BLOCKED.value
    assert result["executed_steps"] == 0
    assert target.calls == []


def test_programmatic_invalid_risk_is_blocked_before_target(tmp_path: Path):
    for index, invalid_risk in enumerate(("offline", None)):
        target = RecordingTarget([])
        exp = reversible_experiment()
        exp.risk = invalid_risk
        result = Runner(
            target,
            Policy(max_risk=RiskClass.REVERSIBLE_KERNEL_RAM),
            EvidenceLog(tmp_path / f"evidence-{index}.jsonl"),
        ).run(exp, expected_plan_sha256="0" * 64)
        assert result["exit_classification"] == ExitClassification.BLOCKED.value
        assert result["executed_steps"] == 0
        assert target.calls == []


def test_evidence_failure_between_restore_steps_is_exit_4_and_verification_runs(tmp_path: Path):
    target = RecordingTarget([
        {"ok": True, "satisfied": True},
        {"ok": True, "data_hex": "aa"},
        {"ok": True},
        {"ok": True, "data_hex": "00"},
        {"ok": True},
        {"ok": True, "data_hex": "aa"},
    ])
    exp = reversible_experiment()
    result = Runner(
        target,
        Policy(max_risk=RiskClass.REVERSIBLE_KERNEL_RAM),
        FailingEvidence(tmp_path / "evidence.jsonl", fail_from_call=7),
    ).run(exp, expected_plan_sha256=experiment_sha256(exp))
    assert [kind for kind, _ in target.calls] == [
        "check_precondition", "read_memory", "write_memory", "read_memory",
        "write_memory", "read_memory"
    ]
    assert result["exit_classification"] == ExitClassification.RESTORE_FAILURE.value
    assert result["restore_state"] == RestoreState.RESTORE_FAILED.value
