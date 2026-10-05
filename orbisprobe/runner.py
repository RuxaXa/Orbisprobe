from __future__ import annotations

import re
import uuid
from enum import Enum
from typing import Any

from .evidence import EvidenceLog
from .policy import Policy
from .schema import Experiment, Oracle, RiskClass, Step, experiment_sha256
from .targets.base import Target


class ExitClassification(str, Enum):
    COMPLETED = "completed"
    BLOCKED = "blocked"
    RUNTIME_FAILURE = "runtime_failure"
    RESTORE_FAILURE = "restore_failure"


class MutationLifecycle(str, Enum):
    NOT_MUTATED = "NOT_MUTATED"
    MUTATION_ATTEMPTED = "MUTATION_ATTEMPTED"
    MUTATED_CONFIRMED = "MUTATED_CONFIRMED"
    RESTORE_ATTEMPTED = "RESTORE_ATTEMPTED"
    RESTORED_CONFIRMED = "RESTORED_CONFIRMED"
    RESTORE_FAILED = "RESTORE_FAILED"


class RestoreState(str, Enum):
    NOT_ATTEMPTED = "NOT_ATTEMPTED"
    RESTORE_ATTEMPTED = "RESTORE_ATTEMPTED"
    RESTORED_CONFIRMED = "RESTORED_CONFIRMED"
    RESTORE_FAILED = "RESTORE_FAILED"


class Runner:
    def __init__(self, target: Target, policy: Policy, evidence: EvidenceLog):
        self.target = target
        self.policy = policy
        self.evidence = evidence
        self._state_integrity_latched = False

    def run(
        self,
        exp: Experiment,
        dry_run: bool = False,
        expected_plan_sha256: str | None = None,
    ) -> dict[str, Any]:
        run_id = uuid.uuid4().hex[:12]
        errors: list[str] = []
        actual_plan_sha256: str | None = None
        try:
            exp.assert_valid_structure()
            actual_plan_sha256 = experiment_sha256(exp)
        except (TypeError, ValueError) as exc:
            errors.append(f"invalid experiment plan: {type(exc).__name__}: {exc}")
        if not errors:
            errors.extend(self.policy.validate(exp))
            if expected_plan_sha256 is None:
                errors.append("run requires validated plan SHA-256")
            elif not re.fullmatch(r"[0-9a-f]{64}", expected_plan_sha256):
                errors.append("validated plan SHA-256 has invalid format")
            elif expected_plan_sha256 != actual_plan_sha256:
                errors.append("validated plan SHA-256 does not match execution plan")

        context: dict[str, Any] = {
            "run_id": run_id,
            "experiment_id": str(exp.id),
            "plan_sha256": actual_plan_sha256,
            "expected_plan_sha256": expected_plan_sha256,
            "policy": self.policy.to_dict(),
            "executed_steps": 0,
            "validation_steps_executed": 0,
            "restore_steps_executed": 0,
            "mutation_state": MutationLifecycle.NOT_MUTATED.value,
            "restore_state": RestoreState.NOT_ATTEMPTED.value,
            "lifecycle_state": MutationLifecycle.NOT_MUTATED.value,
            "stop_reason": None,
            "adapter_errors": [],
            "evidence_errors": [],
            "validation_results": [],
            "results": [],
            "oracles": [],
            "restore_results": [],
        }
        plan_evidence_ok = self._append_evidence(
            context,
            "plan",
            {
                "plan_sha256": actual_plan_sha256,
                "expected_plan_sha256": expected_plan_sha256,
                "policy": self.policy.to_dict(),
                "policy_errors": errors,
                "risk": exp.risk.value if isinstance(exp.risk, RiskClass) else repr(exp.risk),
            },
        )
        if not plan_evidence_ok:
            return self._finish(
                context,
                ExitClassification.RUNTIME_FAILURE,
                error="evidence storage unavailable before execution",
            )

        if errors:
            return self._finish(
                context,
                ExitClassification.BLOCKED,
                errors=errors,
                blocked=True,
            )

        mutating_plan = any(self._is_mutating_step(step) for step in exp.steps)
        if self._state_integrity_latched and mutating_plan:
            context["restore_state"] = RestoreState.RESTORE_FAILED.value
            context["lifecycle_state"] = MutationLifecycle.RESTORE_FAILED.value
            return self._finish(
                context,
                ExitClassification.RESTORE_FAILURE,
                error="runner state-integrity latch is set",
                blocked=True,
            )

        if dry_run:
            return self._finish(
                context,
                ExitClassification.COMPLETED,
                dry_run=True,
                steps=[step.kind for step in exp.steps],
            )

        validation_outcome = self._run_validations(exp, context)
        if validation_outcome is not None:
            classification, message = validation_outcome
            return self._finish(
                context,
                classification,
                errors=[message] if classification == ExitClassification.BLOCKED else None,
                error=message if classification != ExitClassification.BLOCKED else None,
                blocked=classification == ExitClassification.BLOCKED,
            )

        runtime_error: str | None = None
        mutation_state = MutationLifecycle.NOT_MUTATED
        pending_write: dict[str, str] | None = None
        try:
            for index, step in enumerate(exp.steps):
                mutating = self._is_mutating_step(step)
                if mutating:
                    mutation_state = MutationLifecycle.MUTATION_ATTEMPTED
                    context["mutation_state"] = mutation_state.value
                    context["lifecycle_state"] = mutation_state.value
                result = self._execute(step)
                context["executed_steps"] += 1
                context["results"].append(result)
                step_evidence_ok = self._append_evidence(
                    context,
                    "step",
                    {
                        "index": index,
                        "kind": step.kind,
                        "args": step.args,
                        "result": result,
                        "mutation_state": context["mutation_state"],
                    },
                )
                if not step_evidence_ok:
                    raise OSError("evidence storage failed after target step")
                if not result.get("ok", False):
                    self._record_adapter_error(context, "step", index, result)
                    raise RuntimeError(f"target step {index} failed: {result.get('error', 'unknown error')}")
                if step.kind == "write_memory":
                    pending_write = {
                        "address": str(step.args.get("address")),
                        "data_hex": self._normalize_hex(str(step.args.get("data_hex", ""))),
                    }
                elif step.kind == "read_memory" and pending_write is not None:
                    readback = result.get("data_hex")
                    readback_matches = (
                        str(step.args.get("address")) == pending_write["address"]
                        and isinstance(readback, str)
                        and self._normalize_hex(readback) == pending_write["data_hex"]
                    )
                    if not readback_matches:
                        raise RuntimeError("post-write readback mismatch")
                    mutation_state = MutationLifecycle.MUTATED_CONFIRMED
                    context["mutation_state"] = mutation_state.value
                    context["lifecycle_state"] = mutation_state.value
                for condition in exp.stop_on:
                    if result.get(condition) is True or result.get("event") == condition:
                        context["stop_reason"] = condition
                        raise RuntimeError(f"stop condition triggered: {condition}")

            context["oracles"] = [self._oracle(oracle, context["results"]) for oracle in exp.oracles]
            if not self._append_evidence(
                context,
                "oracles",
                {"results": context["oracles"]},
            ):
                raise OSError("evidence storage failed after oracle evaluation")
        except Exception as exc:  # noqa: BLE001 - target/oracle failures become evidence
            runtime_error = str(exc)
            if not context["adapter_errors"]:
                context["adapter_errors"].append(
                    {"phase": "execution", "type": type(exc).__name__, "error": str(exc)}
                )
            self._append_evidence(
                context,
                "exception",
                {"type": type(exc).__name__, "message": str(exc)},
            )

        restore_failed = False
        if exp.risk == RiskClass.REVERSIBLE_KERNEL_RAM and mutation_state != MutationLifecycle.NOT_MUTATED:
            restore_failed = not self._restore(exp, context)

        if restore_failed:
            self._state_integrity_latched = True
            return self._finish(
                context,
                ExitClassification.RESTORE_FAILURE,
                error="restore/state-integrity confirmation failed",
            )
        if runtime_error is not None:
            return self._finish(
                context,
                ExitClassification.RUNTIME_FAILURE,
                error=runtime_error,
            )
        return self._finish(context, ExitClassification.COMPLETED)

    def _run_validations(
        self,
        exp: Experiment,
        context: dict[str, Any],
    ) -> tuple[ExitClassification, str] | None:
        for index, step in enumerate(exp.validation_steps):
            try:
                result = self._execute(step)
            except Exception as exc:  # noqa: BLE001 - adapter boundary must fail closed
                error = f"validation adapter failure at step {index}: {exc}"
                context["adapter_errors"].append(
                    {"phase": "validation", "index": index, "type": type(exc).__name__, "error": str(exc)}
                )
                return ExitClassification.RUNTIME_FAILURE, error
            context["validation_steps_executed"] += 1
            context["validation_results"].append(result)
            if not self._append_evidence(
                context,
                "validation",
                {"index": index, "kind": step.kind, "args": step.args, "result": result},
            ):
                return ExitClassification.RUNTIME_FAILURE, "evidence storage failed during validation"
            if not result.get("ok", False):
                self._record_adapter_error(context, "validation", index, result)
                return (
                    ExitClassification.RUNTIME_FAILURE,
                    f"validation adapter failure at step {index}: {result.get('error', 'unknown error')}",
                )
            if result.get("satisfied") is not True:
                return ExitClassification.BLOCKED, f"precondition validation failed at step {index}"
        return None

    def _restore(self, exp: Experiment, context: dict[str, Any]) -> bool:
        context["restore_state"] = RestoreState.RESTORE_ATTEMPTED.value
        context["lifecycle_state"] = MutationLifecycle.RESTORE_ATTEMPTED.value
        all_steps_ok = True
        for index, planned_step in enumerate(exp.restore_steps):
            try:
                executed_step, expected_hex = self._resolve_restore_step(exp, context, planned_step)
                result = self._execute(executed_step)
                if expected_hex is not None:
                    result = dict(result)
                    readback = result.get("data_hex")
                    result["state_integrity_confirmed"] = (
                        result.get("ok") is True
                        and isinstance(readback, str)
                        and self._normalize_hex(readback) == expected_hex
                    )
                    if not result["state_integrity_confirmed"]:
                        result.setdefault("error", "restore readback mismatch")
                        result.setdefault("error_type", "restore_readback_mismatch")
            except Exception as exc:  # noqa: BLE001 - all remaining restore steps must still be attempted
                executed_step = planned_step
                result = {"ok": False, "error": str(exc), "error_type": type(exc).__name__}
            context["restore_steps_executed"] += 1
            context["restore_results"].append(result)
            restore_evidence_ok = self._append_evidence(
                context,
                "restore",
                {
                    "index": index,
                    "planned_kind": planned_step.kind,
                    "planned_args": planned_step.args,
                    "executed_kind": executed_step.kind,
                    "executed_args": executed_step.args,
                    "result": result,
                },
            )
            if not restore_evidence_ok:
                all_steps_ok = False
                self._record_adapter_error(
                    context,
                    "restore",
                    index,
                    {"error_type": "evidence_storage_failure", "error": "restore evidence was not persisted"},
                )
            if not result.get("ok", False) or result.get("state_integrity_confirmed") is False:
                all_steps_ok = False
                self._record_adapter_error(context, "restore", index, result)

        final_result = context["restore_results"][-1] if context["restore_results"] else {}
        restored_confirmed = final_result.get("state_integrity_confirmed") is True
        if all_steps_ok and restored_confirmed:
            context["restore_state"] = RestoreState.RESTORED_CONFIRMED.value
            context["lifecycle_state"] = MutationLifecycle.RESTORED_CONFIRMED.value
            return True
        context["restore_state"] = RestoreState.RESTORE_FAILED.value
        context["lifecycle_state"] = MutationLifecycle.RESTORE_FAILED.value
        return False

    def _resolve_restore_step(
        self,
        exp: Experiment,
        context: dict[str, Any],
        step: Step,
    ) -> tuple[Step, str | None]:
        if step.kind in {"write_saved_original", "restore_saved_original"}:
            address, original_hex, _length = self._original_from_step(exp, context, step)
            return Step("write_memory", {"address": address, "data_hex": original_hex}), None
        if step.kind in {"verify_restored", "restore_readback"}:
            address, original_hex, length = self._original_from_step(exp, context, step)
            return Step("read_memory", {"address": address, "length": length}), original_hex
        return step, None

    def _original_from_step(
        self,
        exp: Experiment,
        context: dict[str, Any],
        restore_step: Step,
    ) -> tuple[Any, str, int]:
        source_index = restore_step.args.get("from_step")
        if not isinstance(source_index, int) or isinstance(source_index, bool):
            raise TypeError("restore from_step must be an integer")
        if source_index < 0 or source_index >= len(context["results"]):
            raise ValueError("restore from_step is outside executed results")
        source_result = context["results"][source_index]
        original_hex = source_result.get("data_hex")
        if not isinstance(original_hex, str):
            raise TypeError("original-byte result has no data_hex")
        try:
            original_bytes = bytes.fromhex(original_hex)
        except ValueError as exc:
            raise ValueError("original-byte result contains invalid data_hex") from exc
        source_step = exp.steps[source_index]
        address = source_step.args.get("address", source_result.get("address"))
        if address is None:
            raise ValueError("restore address cannot be resolved")
        return address, original_bytes.hex(), len(original_bytes)

    def _finish(
        self,
        context: dict[str, Any],
        classification: ExitClassification,
        *,
        error: str | None = None,
        errors: list[str] | None = None,
        blocked: bool = False,
        **extra: Any,
    ) -> dict[str, Any]:
        summary_ok = self._append_evidence(
            context,
            "summary",
            {
                "exit_classification": classification.value,
                "plan_sha256": context["plan_sha256"],
                "policy": context["policy"],
                "executed_steps": context["executed_steps"],
                "validation_steps_executed": context["validation_steps_executed"],
                "restore_steps_executed": context["restore_steps_executed"],
                "mutation_state": context["mutation_state"],
                "restore_state": context["restore_state"],
                "lifecycle_state": context["lifecycle_state"],
                "stop_reason": context["stop_reason"],
                "adapter_errors": context["adapter_errors"],
                "evidence_errors": context["evidence_errors"],
                "oracle_results": context["oracles"],
                "state_integrity_latched": self._state_integrity_latched,
                "error": error,
                "errors": errors,
            },
        )
        if not summary_ok and classification not in {
            ExitClassification.RUNTIME_FAILURE,
            ExitClassification.RESTORE_FAILURE,
        }:
            classification = ExitClassification.RUNTIME_FAILURE
            error = error or "final evidence summary was not persisted"
            blocked = False
        result = {
            "ok": classification == ExitClassification.COMPLETED,
            "blocked": blocked,
            "exit_classification": classification.value,
            **context,
        }
        if error is not None:
            result["error"] = error
        if errors is not None:
            result["errors"] = errors
        result.update(extra)
        return result

    def _append_evidence(
        self,
        context: dict[str, Any],
        kind: str,
        data: dict[str, Any],
    ) -> bool:
        try:
            self.evidence.append(
                context["run_id"],
                context["experiment_id"],
                kind,
                data,
            )
        except Exception as exc:  # noqa: BLE001 - evidence failure must not bypass restore
            context["evidence_errors"].append(
                {"kind": kind, "type": type(exc).__name__, "error": str(exc)}
            )
            return False
        return True

    def _execute(self, step: Step) -> dict[str, Any]:
        result = self.target.execute(step.kind, step.args)
        if not isinstance(result, dict):
            raise TypeError("malformed adapter response: expected JSON object")
        return result

    @staticmethod
    def _normalize_hex(value: str) -> str:
        try:
            return bytes.fromhex(value).hex()
        except ValueError:
            return value.lower()

    @staticmethod
    def _is_mutating_step(step: Step) -> bool:
        return (
            step.kind == "write_memory"
            or step.kind.startswith("write_")
            or step.args.get("mutating") is True
        )

    @staticmethod
    def _record_adapter_error(
        context: dict[str, Any],
        phase: str,
        index: int,
        result: dict[str, Any],
    ) -> None:
        context["adapter_errors"].append(
            {
                "phase": phase,
                "index": index,
                "error_type": result.get("error_type"),
                "error": result.get("error", "unknown error"),
                "returncode": result.get("returncode"),
            }
        )

    def _oracle(self, oracle: Oracle, results: list[dict[str, Any]]) -> dict[str, Any]:
        if oracle.kind == "changed":
            a, b = int(oracle.args["a"]), int(oracle.args["b"])
            return {"kind": "changed", "value": results[a] != results[b]}
        if oracle.kind == "sha256_equal":
            a, b = int(oracle.args["a"]), int(oracle.args["b"])
            return {
                "kind": "sha256_equal",
                "value": results[a].get("sha256") == results[b].get("sha256"),
            }
        if oracle.kind == "field_equals":
            index = int(oracle.args["step"])
            key = oracle.args["field"]
            expected = oracle.args["expected"]
            return {
                "kind": "field_equals",
                "value": results[index].get(key) == expected,
                "actual": results[index].get(key),
            }
        return {"kind": oracle.kind, "value": None, "unsupported": True}
