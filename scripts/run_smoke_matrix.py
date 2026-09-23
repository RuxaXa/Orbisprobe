#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
import tempfile
from pathlib import Path
from typing import Any

from orbisprobe.evidence import EvidenceLog
from orbisprobe.policy import DEFAULT_BLOCKED_SINKS, Policy
from orbisprobe.runner import ExitClassification, RestoreState, Runner
from orbisprobe.schema import Experiment, RiskClass, Step, experiment_sha256
from orbisprobe.targets.base import Target
from orbisprobe.targets.command_adapter import CommandAdapter
from orbisprobe.targets.offline import OfflineTarget


class FakeTarget(Target):
    def __init__(self, replies: list[Any]):
        self.replies = list(replies)
        self.calls: list[tuple[str, dict[str, Any]]] = []

    def execute(self, kind: str, args: dict[str, Any]) -> dict[str, Any]:
        self.calls.append((kind, args))
        reply = self.replies.pop(0)
        if isinstance(reply, BaseException):
            raise reply
        return reply


def live_experiment(**overrides: Any) -> Experiment:
    values: dict[str, Any] = {
        "id": "smoke-live",
        "title": "smoke live",
        "hypothesis": "bounded smoke input reaches the adapter",
        "risk": RiskClass.ACTIVE_REQUEST,
        "controlled_input": "smoke-case-A",
        "validation": "control channel precondition",
        "consumer": "fake adapter",
        "expected_effect": "one bounded response",
        "observable": "adapter JSON",
        "experiment": "one request",
        "preconditions": ["control_channel_ready"],
        "forbidden_sinks": sorted(DEFAULT_BLOCKED_SINKS),
        "validation_steps": [Step("check_precondition", {"name": "control_channel_ready"})],
        "steps": [Step("execute_named_case", {"case": "A"})],
        "metadata": {"live_target": True},
    }
    values.update(overrides)
    return Experiment(**values)


def reversible_experiment() -> Experiment:
    return live_experiment(
        id="smoke-reversible",
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


def run_case(
    name: str,
    exp: Experiment,
    target: Target,
    policy: Policy,
    evidence_path: Path,
) -> dict[str, Any]:
    result = Runner(target, policy, EvidenceLog(evidence_path)).run(
        exp,
        expected_plan_sha256=experiment_sha256(exp),
    )
    return {
        "name": name,
        "classification": result["exit_classification"],
        "executed_steps": result["executed_steps"],
        "restore_state": result["restore_state"],
        "result": result,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", type=Path)
    args = parser.parse_args()
    cases: list[dict[str, Any]] = []

    with tempfile.TemporaryDirectory(prefix="orbisprobe-smoke-") as temporary:
        root = Path(temporary)

        fixture = root / "fixture.bin"
        fixture.write_bytes(b"orbisprobe-smoke\n")
        offline = Experiment(
            id="smoke-offline",
            title="offline smoke",
            hypothesis="fixture hash is observable",
            risk=RiskClass.OFFLINE,
            controlled_input=str(fixture),
            validation="fixture exists",
            consumer="OfflineTarget.hash_file",
            expected_effect="hash returned",
            observable="sha256",
            experiment="one offline hash",
            steps=[Step("hash_file", {"path": str(fixture)})],
        )
        result = run_case(
            "offline_success",
            offline,
            OfflineTarget(),
            Policy(max_risk=RiskClass.OFFLINE),
            root / "offline.jsonl",
        )
        result["passed"] = result["classification"] == ExitClassification.COMPLETED.value
        cases.append(result)

        blocked_target = FakeTarget([])
        blocked = live_experiment(metadata={"live_target": True, "template_only": True})
        result = run_case(
            "policy_blocked",
            blocked,
            blocked_target,
            Policy(max_risk=RiskClass.ACTIVE_REQUEST),
            root / "blocked.jsonl",
        )
        result["target_calls"] = len(blocked_target.calls)
        result["passed"] = (
            result["classification"] == ExitClassification.BLOCKED.value
            and result["target_calls"] == 0
        )
        cases.append(result)

        result = run_case(
            "adapter_exit_failure",
            live_experiment(id="smoke-adapter-exit"),
            CommandAdapter([sys.executable, "-c", "raise SystemExit(7)"]),
            Policy(max_risk=RiskClass.ACTIVE_REQUEST),
            root / "adapter-exit.jsonl",
        )
        result["passed"] = result["classification"] == ExitClassification.RUNTIME_FAILURE.value
        cases.append(result)

        result = run_case(
            "adapter_timeout",
            live_experiment(id="smoke-adapter-timeout"),
            CommandAdapter(
                [sys.executable, "-c", "import time; time.sleep(1)"],
                timeout_seconds=0.01,
            ),
            Policy(max_risk=RiskClass.ACTIVE_REQUEST),
            root / "adapter-timeout.jsonl",
        )
        result["passed"] = result["classification"] == ExitClassification.RUNTIME_FAILURE.value
        cases.append(result)

        reversible = reversible_experiment()
        success_target = FakeTarget([
            {"ok": True, "satisfied": True},
            {"ok": True, "data_hex": "aa"},
            {"ok": True, "mutated_confirmed": True},
            {"ok": True, "data_hex": "00"},
            {"ok": True},
            {"ok": True, "data_hex": "aa"},
        ])
        result = run_case(
            "reversible_success_restore",
            reversible,
            success_target,
            Policy(max_risk=RiskClass.REVERSIBLE_KERNEL_RAM),
            root / "reversible-success.jsonl",
        )
        result["target_calls"] = len(success_target.calls)
        result["passed"] = (
            result["classification"] == ExitClassification.COMPLETED.value
            and result["restore_state"] == RestoreState.RESTORED_CONFIRMED.value
        )
        cases.append(result)

        partial_target = FakeTarget([
            {"ok": True, "satisfied": True},
            {"ok": True, "data_hex": "aa"},
            {"ok": False, "error_type": "adapter_timeout", "error": "timeout after dispatch"},
            {"ok": True},
            {"ok": True, "data_hex": "aa"},
        ])
        result = run_case(
            "partial_write_failure_restore_success",
            reversible,
            partial_target,
            Policy(max_risk=RiskClass.REVERSIBLE_KERNEL_RAM),
            root / "partial-write.jsonl",
        )
        result["target_calls"] = len(partial_target.calls)
        result["passed"] = (
            result["classification"] == ExitClassification.RUNTIME_FAILURE.value
            and result["restore_state"] == RestoreState.RESTORED_CONFIRMED.value
        )
        cases.append(result)

        restore_failure_target = FakeTarget([
            {"ok": True, "satisfied": True},
            {"ok": True, "data_hex": "aa"},
            {"ok": True, "mutated_confirmed": True},
            {"ok": True, "data_hex": "00"},
            {"ok": False, "error": "restore request failed"},
            {"ok": False, "error": "restore readback failed"},
        ])
        result = run_case(
            "restore_failure",
            reversible,
            restore_failure_target,
            Policy(max_risk=RiskClass.REVERSIBLE_KERNEL_RAM),
            root / "restore-failure.jsonl",
        )
        result["target_calls"] = len(restore_failure_target.calls)
        result["passed"] = (
            result["classification"] == ExitClassification.RESTORE_FAILURE.value
            and result["restore_state"] == RestoreState.RESTORE_FAILED.value
        )
        cases.append(result)

    concise_cases = [
        {
            "name": case["name"],
            "passed": case["passed"],
            "classification": case["classification"],
            "executed_steps": case["executed_steps"],
            "restore_state": case["restore_state"],
            **({"target_calls": case["target_calls"]} if "target_calls" in case else {}),
        }
        for case in cases
    ]
    report = {
        "all_passed": all(case["passed"] for case in cases),
        "count": len(cases),
        "cases": concise_cases,
    }
    text = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(text, encoding="utf-8")
    print(text, end="")
    return 0 if report["all_passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
