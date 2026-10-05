import hashlib
import json
import sys
from pathlib import Path

from orbisprobe.evidence import EvidenceLog
from orbisprobe.policy import DEFAULT_BLOCKED_SINKS, Policy
from orbisprobe.runner import RestoreState, Runner
from orbisprobe.schema import Experiment, RiskClass, Step, experiment_sha256
from orbisprobe.targets.base import Target
from orbisprobe.targets.command_adapter import CommandAdapter


def complete_live_experiment(**overrides):
    values = {
        "id": "live-1",
        "title": "live",
        "hypothesis": "H",
        "controlled_input": "one bounded input",
        "validation": "prove all named preconditions before execution",
        "consumer": "named consumer",
        "expected_effect": "bounded effect",
        "observable": "named raw observable",
        "experiment": "A/B comparison",
        "risk": RiskClass.ACTIVE_REQUEST,
        "preconditions": ["control_channel_ready"],
        "forbidden_sinks": sorted(DEFAULT_BLOCKED_SINKS),
        "validation_steps": [Step("check_precondition", {"name": "control_channel_ready"})],
        "steps": [Step("execute_named_case", {"case": "A"})],
        "metadata": {"live_target": True},
    }
    values.update(overrides)
    return Experiment(**values)


def test_live_plan_requires_complete_research_chain():
    exp = complete_live_experiment(consumer="")
    errors = Policy(max_risk=RiskClass.ACTIVE_REQUEST).validate(exp)
    assert "missing research field: consumer" in errors


def test_forbidden_sinks_are_guardrails_but_reachable_sinks_block():
    allowed = complete_live_experiment()
    assert Policy(max_risk=RiskClass.ACTIVE_REQUEST).validate(allowed) == []

    blocked = complete_live_experiment(reachable_sinks=["flash_write"])
    errors = Policy(max_risk=RiskClass.ACTIVE_REQUEST).validate(blocked)
    assert "experiment declares reachable blocked sinks: flash_write" in errors


def test_validated_plan_is_hash_bound_to_canonical_experiment():
    from orbisprobe.cli import validated_plan

    exp = complete_live_experiment()
    result = validated_plan(exp, Policy(max_risk=RiskClass.ACTIVE_REQUEST))
    canonical = json.dumps(exp.to_dict(), sort_keys=True, separators=(",", ":")).encode()
    assert result["ok"] is True
    assert result["plan_sha256"] == hashlib.sha256(canonical).hexdigest()
    assert result["experiment"] == exp.to_dict()


def test_template_only_plan_is_not_executable():
    exp = complete_live_experiment(metadata={"live_target": True, "template_only": True})
    errors = Policy(max_risk=RiskClass.ACTIVE_REQUEST).validate(exp)
    assert "template-only experiment cannot execute" in errors


def test_validate_cli_exits_nonzero_for_blocked_plan(tmp_path: Path, monkeypatch):
    from orbisprobe.cli import main

    plan = tmp_path / "blocked.json"
    plan.write_text(
        json.dumps(
            complete_live_experiment(metadata={"live_target": True, "template_only": True}).to_dict()
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(
        sys,
        "argv",
        ["orbisprobe", "validate", str(plan), "--max-risk", "active_request"],
    )
    assert main() == 2


def test_run_cli_exits_nonzero_for_blocked_plan(tmp_path: Path, monkeypatch):
    from orbisprobe.cli import main

    exp = complete_live_experiment(metadata={"live_target": True, "template_only": True})
    plan = tmp_path / "blocked.json"
    plan.write_text(json.dumps(exp.to_dict()), encoding="utf-8")
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "orbisprobe", "run", str(plan), "--max-risk", "active_request",
            "--plan-sha256", experiment_sha256(exp),
            "--evidence", str(tmp_path / "evidence.jsonl"),
        ],
    )
    assert main() == 2


def test_security_relevant_x86_dataflow_requires_all_four_stages():
    exp = complete_live_experiment(
        metadata={
            "live_target": True,
            "security_relevant_x86_64_dataflow": True,
            "x86_64_dataflow": {
                "definition": "mov rdx, [descriptor.length]",
                "overwrite_history": "no later definition observed",
                "call_clobber_analysis": "",
                "consumer": "copy primitive",
            },
        }
    )
    errors = Policy(max_risk=RiskClass.ACTIVE_REQUEST).validate(exp)
    assert "missing x86_64_dataflow field: call_clobber_analysis" in errors


class RecordingTarget(Target):
    def __init__(self, replies):
        self.replies = list(replies)
        self.calls = []

    def execute(self, kind, args):
        self.calls.append((kind, args))
        return self.replies.pop(0)


def test_command_adapter_times_out_fail_closed():
    adapter = CommandAdapter(
        [sys.executable, "-c", "import time; time.sleep(1)"],
        timeout_seconds=0.01,
    )
    result = adapter.execute("read_memory", {"address": "0x1000", "length": 1})
    assert result["ok"] is False
    assert result["error"] == "adapter timeout"


def test_failed_precondition_blocks_experiment_steps(tmp_path: Path):
    target = RecordingTarget([{"ok": True, "satisfied": False}])
    exp = complete_live_experiment()
    result = Runner(
        target,
        Policy(max_risk=RiskClass.ACTIVE_REQUEST),
        EvidenceLog(tmp_path / "evidence.jsonl"),
    ).run(exp, expected_plan_sha256=experiment_sha256(exp))
    assert result["ok"] is False
    assert result["blocked"] is True
    assert target.calls == [("check_precondition", {"name": "control_channel_ready"})]


def test_stop_condition_aborts_remaining_steps(tmp_path: Path):
    target = RecordingTarget([
        {"ok": True, "satisfied": True},
        {"ok": True, "fault": True},
    ])
    exp = complete_live_experiment(
        steps=[
            Step("execute_named_case", {"case": "A"}),
            Step("execute_named_case", {"case": "B"}),
        ]
    )
    result = Runner(
        target,
        Policy(max_risk=RiskClass.ACTIVE_REQUEST),
        EvidenceLog(tmp_path / "evidence.jsonl"),
    ).run(exp, expected_plan_sha256=experiment_sha256(exp))
    assert result["ok"] is False
    assert result["stop_reason"] == "fault"
    assert [kind for kind, _ in target.calls] == ["check_precondition", "execute_named_case"]


def test_validation_steps_cannot_mutate_target():
    exp = complete_live_experiment(
        validation_steps=[Step("write_memory", {"address": "0x1000", "data_hex": "00"})]
    )
    errors = Policy(max_risk=RiskClass.ACTIVE_REQUEST).validate(exp)
    assert "validation step cannot mutate target: write_memory" in errors


def test_blocked_sink_step_cannot_bypass_reachable_sink_declaration():
    exp = complete_live_experiment(steps=[Step("flash_write", {"offset": 0})])
    errors = Policy(max_risk=RiskClass.ACTIVE_REQUEST).validate(exp)
    assert "blocked sink step is never executable: flash_write" in errors


def test_restore_write_obeys_max_write_bytes():
    exp = complete_live_experiment(
        risk=RiskClass.REVERSIBLE_KERNEL_RAM,
        steps=[
            Step("read_memory", {"address": "0x1000", "length": 1}),
            Step("write_memory", {"address": "0x1000", "data_hex": "00"}),
            Step("read_memory", {"address": "0x1000", "length": 1}),
        ],
        restore_steps=[
            Step("write_memory", {"address": "0x1000", "data_hex": "00" * 5}),
            Step("verify_restored", {"from_step": 0}),
        ],
    )
    errors = Policy(
        max_risk=RiskClass.REVERSIBLE_KERNEL_RAM,
        max_write_bytes=4,
    ).validate(exp)
    assert "write exceeds max_write_bytes" in errors


def test_malformed_write_hex_is_a_validation_error():
    exp = complete_live_experiment(
        risk=RiskClass.REVERSIBLE_KERNEL_RAM,
        steps=[
            Step("read_memory", {"address": "0x1000", "length": 1}),
            Step("write_memory", {"address": "0x1000", "data_hex": "NOT-HEX"}),
            Step("read_memory", {"address": "0x1000", "length": 1}),
        ],
        restore_steps=[
            Step("write_saved_original", {"from_step": 0}),
            Step("verify_restored", {"from_step": 0}),
        ],
    )
    errors = Policy(max_risk=RiskClass.REVERSIBLE_KERNEL_RAM).validate(exp)
    assert "write_memory data_hex is not valid hex" in errors


def test_reversible_kernel_write_restores_after_failed_step(tmp_path: Path):
    target = RecordingTarget([
        {"ok": True, "satisfied": True},
        {"ok": True, "data_hex": "aa"},
        {"ok": False, "error": "write failed after partial mutation"},
        {"ok": True},
        {"ok": True, "data_hex": "aa"},
    ])
    exp = complete_live_experiment(
        risk=RiskClass.REVERSIBLE_KERNEL_RAM,
        steps=[
            Step("read_memory", {"address": "0x1000", "length": 1}),
            Step("write_memory", {"address": "0x1000", "data_hex": "00"}),
            Step("read_memory", {"address": "0x1000", "length": 1}),
        ],
        restore_steps=[
            Step("restore_saved_original", {"address": "0x1000", "from_step": 0}),
            Step("verify_restored", {"from_step": 0}),
        ],
    )
    result = Runner(
        target,
        Policy(max_risk=RiskClass.REVERSIBLE_KERNEL_RAM),
        EvidenceLog(tmp_path / "evidence.jsonl"),
    ).run(exp, expected_plan_sha256=experiment_sha256(exp))
    assert result["ok"] is False
    assert result["restore_state"] == RestoreState.RESTORED_CONFIRMED.value
    assert [kind for kind, _ in target.calls] == [
        "check_precondition", "read_memory", "write_memory",
        "write_memory", "read_memory"
    ]
