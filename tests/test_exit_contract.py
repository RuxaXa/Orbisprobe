import hashlib
import json
import sys
from pathlib import Path

from orbisprobe.cli import main
from orbisprobe.policy import DEFAULT_BLOCKED_SINKS
from orbisprobe.schema import Experiment, Oracle, RiskClass, Step
from orbisprobe.targets.base import Target


def plan_hash(exp: Experiment) -> str:
    canonical = json.dumps(
        exp.to_dict(), sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def write_plan(path: Path, exp: Experiment) -> Path:
    path.write_text(json.dumps(exp.to_dict()), encoding="utf-8")
    return path


def offline_experiment(path: Path, *, oracle_expected: str | None = None) -> Experiment:
    oracles = []
    if oracle_expected is not None:
        oracles = [
            Oracle(
                "field_equals",
                {"step": 0, "field": "sha256", "expected": oracle_expected},
            )
        ]
    return Experiment(
        id="offline",
        title="offline",
        hypothesis="hash an offline fixture",
        risk=RiskClass.OFFLINE,
        controlled_input=str(path),
        validation="fixture exists",
        consumer="OfflineTarget.hash_file",
        expected_effect="hash is observed",
        observable="sha256",
        experiment="one offline hash",
        steps=[Step("hash_file", {"path": str(path)})],
        oracles=oracles,
    )


def live_experiment(**overrides) -> Experiment:
    values = {
        "id": "live",
        "title": "live",
        "hypothesis": "bounded input reaches a named consumer",
        "risk": RiskClass.ACTIVE_REQUEST,
        "controlled_input": "case A",
        "validation": "check the control channel",
        "consumer": "named consumer",
        "expected_effect": "bounded response",
        "observable": "adapter result",
        "experiment": "single bounded request",
        "preconditions": ["control_channel_ready"],
        "forbidden_sinks": sorted(DEFAULT_BLOCKED_SINKS),
        "validation_steps": [Step("check_precondition", {"name": "control_channel_ready"})],
        "steps": [Step("execute_named_case", {"case": "A"})],
        "metadata": {"live_target": True},
    }
    values.update(overrides)
    return Experiment(**values)


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


def invoke(monkeypatch, argv: list[str]) -> int:
    monkeypatch.setattr(sys, "argv", ["orbisprobe", *argv])
    return main()


def test_validate_cli_exits_0_for_valid_plan(tmp_path: Path, monkeypatch):
    fixture = tmp_path / "fixture.bin"
    fixture.write_bytes(b"abc")
    exp = offline_experiment(fixture)
    plan = write_plan(tmp_path / "plan.json", exp)
    assert invoke(monkeypatch, ["validate", str(plan), "--max-risk", "offline"]) == 0


def test_validate_cli_exits_2_for_invalid_plan(tmp_path: Path, monkeypatch):
    exp = live_experiment(metadata={"live_target": True, "template_only": True})
    plan = write_plan(tmp_path / "plan.json", exp)
    assert invoke(monkeypatch, ["validate", str(plan), "--max-risk", "active_request"]) == 2


def test_run_cli_exits_0_for_completed_plan(tmp_path: Path, monkeypatch):
    fixture = tmp_path / "fixture.bin"
    fixture.write_bytes(b"abc")
    # A negative oracle is a completed experiment, not a CLI failure.
    exp = offline_experiment(fixture, oracle_expected="0" * 64)
    plan = write_plan(tmp_path / "plan.json", exp)
    code = invoke(
        monkeypatch,
        [
            "run", str(plan), "--max-risk", "offline",
            "--plan-sha256", plan_hash(exp),
            "--evidence", str(tmp_path / "evidence.jsonl"),
        ],
    )
    assert code == 0


def test_run_cli_exits_2_for_blocked_plan(tmp_path: Path, monkeypatch):
    from orbisprobe import cli

    target = RecordingTarget([])
    monkeypatch.setattr(cli, "CommandAdapter", lambda _argv: target)
    exp = live_experiment(metadata={"live_target": True, "template_only": True})
    plan = write_plan(tmp_path / "plan.json", exp)
    code = invoke(
        monkeypatch,
        [
            "run", str(plan), "--max-risk", "active_request", "--adapter", "ignored",
            "--plan-sha256", plan_hash(exp),
            "--evidence", str(tmp_path / "evidence.jsonl"),
        ],
    )
    assert code == 2
    assert target.calls == []


def test_run_cli_exits_3_for_runtime_failure(tmp_path: Path, monkeypatch):
    from orbisprobe import cli

    target = RecordingTarget([
        {"ok": True, "satisfied": True},
        {"ok": False, "error": "adapter failed"},
    ])
    monkeypatch.setattr(cli, "CommandAdapter", lambda _argv: target)
    exp = live_experiment()
    plan = write_plan(tmp_path / "plan.json", exp)
    code = invoke(
        monkeypatch,
        [
            "run", str(plan), "--max-risk", "active_request", "--adapter", "ignored",
            "--plan-sha256", plan_hash(exp),
            "--evidence", str(tmp_path / "evidence.jsonl"),
        ],
    )
    assert code == 3


def test_run_cli_exits_4_for_restore_failure(tmp_path: Path, monkeypatch):
    from orbisprobe import cli

    target = RecordingTarget([
        {"ok": True, "satisfied": True},
        {"ok": True, "data_hex": "aa"},
        {"ok": True, "mutated_confirmed": True},
        {"ok": True, "data_hex": "00"},
        {"ok": False, "error": "restore write failed"},
        {"ok": False, "error": "restore readback failed"},
    ])
    monkeypatch.setattr(cli, "CommandAdapter", lambda _argv: target)
    exp = live_experiment(
        risk=RiskClass.REVERSIBLE_KERNEL_RAM,
        steps=[
            Step("read_memory", {"address": "0x1000", "length": 1}),
            Step("write_memory", {"address": "0x1000", "data_hex": "00"}),
            Step("read_memory", {"address": "0x1000", "length": 1}),
        ],
        restore_steps=[
            Step("write_saved_original", {"from_step": 0}),
            Step("verify_restored", {"from_step": 0}),
        ],
    )
    plan = write_plan(tmp_path / "plan.json", exp)
    code = invoke(
        monkeypatch,
        [
            "run", str(plan), "--max-risk", "reversible_kernel_ram", "--adapter", "ignored",
            "--plan-sha256", plan_hash(exp),
            "--evidence", str(tmp_path / "evidence.jsonl"),
        ],
    )
    assert code == 4


def test_run_blocks_when_plan_changed_after_validation(tmp_path: Path, monkeypatch):
    from orbisprobe import cli

    target = RecordingTarget([])
    monkeypatch.setattr(cli, "CommandAdapter", lambda _argv: target)
    original = live_experiment()
    expected_hash = plan_hash(original)
    changed = live_experiment(controlled_input="case B")
    plan = write_plan(tmp_path / "plan.json", changed)
    code = invoke(
        monkeypatch,
        [
            "run", str(plan), "--max-risk", "active_request", "--adapter", "ignored",
            "--plan-sha256", expected_hash,
            "--evidence", str(tmp_path / "evidence.jsonl"),
        ],
    )
    assert code == 2
    assert target.calls == []


def test_evidence_open_failure_is_exit_3_before_target_calls(tmp_path: Path, monkeypatch):
    from orbisprobe import cli

    target = RecordingTarget([])
    monkeypatch.setattr(cli, "CommandAdapter", lambda _argv: target)
    exp = live_experiment()
    plan = write_plan(tmp_path / "plan.json", exp)
    evidence_directory = tmp_path / "evidence-directory"
    evidence_directory.mkdir()
    code = invoke(
        monkeypatch,
        [
            "run", str(plan), "--max-risk", "active_request", "--adapter", "ignored",
            "--plan-sha256", plan_hash(exp),
            "--evidence", str(evidence_directory),
        ],
    )
    assert code == 3
    assert target.calls == []


def test_invalid_metadata_type_is_exit_2(tmp_path: Path, monkeypatch):
    exp = offline_experiment(tmp_path / "fixture.bin")
    raw = exp.to_dict()
    raw["metadata"] = None
    plan = tmp_path / "invalid-metadata.json"
    plan.write_text(json.dumps(raw), encoding="utf-8")
    assert invoke(monkeypatch, ["validate", str(plan), "--max-risk", "offline"]) == 2


def test_nonfinite_plan_value_is_exit_2(tmp_path: Path, monkeypatch):
    exp = offline_experiment(tmp_path / "fixture.bin")
    raw = exp.to_dict()
    raw["metadata"] = {"invalid": float("nan")}
    plan = tmp_path / "nonfinite.json"
    plan.write_text(json.dumps(raw), encoding="utf-8")
    assert invoke(monkeypatch, ["validate", str(plan), "--max-risk", "offline"]) == 2


def test_null_step_args_is_exit_2_for_validate_and_run(tmp_path: Path, monkeypatch):
    raw = offline_experiment(tmp_path / "fixture.bin").to_dict()
    raw["steps"][0]["args"] = None
    plan = tmp_path / "null-args.json"
    plan.write_text(json.dumps(raw), encoding="utf-8")
    assert invoke(monkeypatch, ["validate", str(plan), "--max-risk", "offline"]) == 2
    assert invoke(
        monkeypatch,
        [
            "run", str(plan), "--max-risk", "offline",
            "--plan-sha256", "0" * 64,
            "--evidence", str(tmp_path / "evidence.jsonl"),
        ],
    ) == 2
