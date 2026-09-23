from __future__ import annotations

from dataclasses import dataclass, field

from .schema import Experiment, RiskClass

DEFAULT_BLOCKED_SINKS = {
    "flash_write", "nor_write", "fsl_write", "snvs_write", "syscon_write",
    "nvs_write", "nvram_write", "key_provision", "firmware_commit",
    "update_install", "bootloader_write", "code_page_write", "page_table_write",
    "efuse", "otp", "persistent_state",
}


def _is_nonnegative_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0

@dataclass
class Policy:
    max_risk: RiskClass = RiskClass.READ_ONLY
    blocked_sinks: set[str] = field(default_factory=lambda: set(DEFAULT_BLOCKED_SINKS))
    require_restore_for_kernel_write: bool = True
    max_read_bytes: int = 0x10000
    max_write_bytes: int = 0x1000
    max_iterations: int = 10000

    def to_dict(self) -> dict:
        effective_blocked_sinks = set(DEFAULT_BLOCKED_SINKS) | set(self.blocked_sinks)
        return {
            "max_risk": self.max_risk.value,
            "blocked_sinks": sorted(effective_blocked_sinks),
            "require_restore_for_kernel_write": self.require_restore_for_kernel_write,
            "max_read_bytes": self.max_read_bytes,
            "max_write_bytes": self.max_write_bytes,
            "max_iterations": self.max_iterations,
        }

    def _rank(self, r: RiskClass) -> int:
        order = [
            RiskClass.OFFLINE, RiskClass.READ_ONLY, RiskClass.VOLATILE_USER,
            RiskClass.VOLATILE_SHARED, RiskClass.REVERSIBLE_KERNEL_RAM,
            RiskClass.ACTIVE_REQUEST, RiskClass.PERSISTENT,
        ]
        return order.index(r)

    def validate(self, exp: Experiment) -> list[str]:
        errors: list[str] = []
        effective_blocked_sinks = set(DEFAULT_BLOCKED_SINKS) | set(self.blocked_sinks)
        if self._rank(exp.risk) > self._rank(self.max_risk):
            errors.append(f"risk {exp.risk.value} exceeds policy max {self.max_risk.value}")
        bad = effective_blocked_sinks.intersection(exp.reachable_sinks)
        if bad:
            errors.append("experiment declares reachable blocked sinks: " + ", ".join(sorted(bad)))
        if exp.risk == RiskClass.PERSISTENT:
            errors.append("persistent experiments are never executable")
        if exp.metadata.get("template_only"):
            errors.append("template-only experiment cannot execute")
        if exp.risk == RiskClass.REVERSIBLE_KERNEL_RAM and self.require_restore_for_kernel_write:
            if not exp.restore_steps:
                errors.append("reversible kernel write requires explicit restore_steps")
            mutation_indexes = [
                index
                for index, step in enumerate(exp.steps)
                if step.kind == "write_memory"
                or step.kind.startswith("write_")
                or step.args.get("mutating") is True
            ]
            if not mutation_indexes:
                errors.append("reversible kernel experiment requires a mutating step")
            else:
                first_mutation = mutation_indexes[0]
                last_mutation = mutation_indexes[-1]
                if len(mutation_indexes) != 1:
                    errors.append("reversible kernel experiment requires exactly one mutating step")
                write_step = exp.steps[first_mutation]
                try:
                    write_length = len(bytes.fromhex(write_step.args.get("data_hex", "")))
                except (TypeError, ValueError):
                    write_length = None
                write_address = write_step.args.get("address")
                original_indexes = [
                    index
                    for index, step in enumerate(exp.steps[:first_mutation])
                    if step.kind == "read_memory"
                    and step.args.get("address") == write_address
                    and step.args.get("length") == write_length
                ]
                post_write_indexes = [
                    index
                    for index, step in enumerate(exp.steps[last_mutation + 1 :], start=last_mutation + 1)
                    if step.kind == "read_memory"
                    and step.args.get("address") == write_address
                    and step.args.get("length") == write_length
                ]
                if not any(
                    step.kind in {"read_memory", "read_original", "snapshot_original"}
                    for step in exp.steps[:first_mutation]
                ):
                    errors.append("reversible write requires original-byte read before mutation")
                elif not original_indexes:
                    errors.append("original-byte read must match write address and length")
                if not any(
                    step.kind in {"read_memory", "post_write_readback", "verify_write"}
                    for step in exp.steps[last_mutation + 1 :]
                ):
                    errors.append("reversible write requires post-write readback")
                elif not post_write_indexes:
                    errors.append("post-write readback must match write address and length")
                if original_indexes:
                    original_index = original_indexes[-1]
                    original_address = exp.steps[original_index].args.get("address")
                    for restore_step in exp.restore_steps:
                        if restore_step.kind in {
                            "write_saved_original",
                            "restore_saved_original",
                            "verify_restored",
                            "restore_readback",
                        } and restore_step.args.get("from_step") != original_index:
                            errors.append("restore from_step must reference the original-byte read")
                        if (
                            restore_step.kind in {
                                "write_saved_original",
                                "restore_saved_original",
                                "verify_restored",
                                "restore_readback",
                            }
                            and "address" in restore_step.args
                            and restore_step.args["address"] != original_address
                        ):
                            errors.append("restore address override must match original-byte read")
            if exp.restore_steps:
                has_restore_request = any(
                    step.kind.startswith(("write_", "restore_"))
                    and step.kind not in {"restore_readback"}
                    for step in exp.restore_steps
                )
                if not has_restore_request:
                    errors.append("reversible write requires explicit restore request")
                if not any(
                    step.kind in {"verify_restored", "restore_readback"}
                    or step.args.get("state_integrity_check") is True
                    for step in exp.restore_steps
                ):
                    errors.append("reversible write requires explicit restore readback")
        is_live = bool(exp.metadata.get("live_target")) or self._rank(exp.risk) >= self._rank(RiskClass.VOLATILE_USER)
        research_fields = (
            "hypothesis", "controlled_input", "validation", "consumer",
            "expected_effect", "observable", "experiment",
        )
        if is_live:
            for name in research_fields:
                if not str(getattr(exp, name, "")).strip():
                    errors.append(f"missing research field: {name}")
            if not exp.forbidden_sinks:
                errors.append("live experiment requires explicit forbidden_sinks")
            elif not effective_blocked_sinks.issubset(set(exp.forbidden_sinks)):
                errors.append("live experiment must forbid every policy-blocked sink")
            if not exp.preconditions:
                errors.append("live experiment requires explicit preconditions")
            validation_names = {
                str(step.args.get("name", ""))
                for step in exp.validation_steps
                if step.kind == "check_precondition"
            }
            for name in exp.preconditions:
                if name not in validation_names:
                    errors.append(f"precondition lacks validation step: {name}")
        dataflow = exp.metadata.get("x86_64_dataflow")
        if exp.metadata.get("security_relevant_x86_64_dataflow") or dataflow is not None:
            required = ("definition", "overwrite_history", "call_clobber_analysis", "consumer")
            if not isinstance(dataflow, dict):
                errors.append("x86_64_dataflow must be an object")
            else:
                for name in required:
                    if not str(dataflow.get(name, "")).strip():
                        errors.append(f"missing x86_64_dataflow field: {name}")
        for s in exp.validation_steps:
            if (
                s.kind.startswith(("write", "execute", "restore"))
                or s.kind in effective_blocked_sinks
                or s.args.get("mutating") is True
            ):
                errors.append(f"validation step cannot mutate target: {s.kind}")
        for s in (*exp.validation_steps, *exp.steps, *exp.restore_steps):
            if s.kind in effective_blocked_sinks:
                errors.append(f"blocked sink step is never executable: {s.kind}")
            if s.kind in exp.forbidden_sinks:
                errors.append(f"plan-forbidden sink step is not executable: {s.kind}")
        if exp.risk != RiskClass.REVERSIBLE_KERNEL_RAM and any(
            step.kind == "write_memory" for step in exp.steps
        ):
            errors.append("write_memory requires reversible_kernel_ram risk")
        for s in (*exp.validation_steps, *exp.steps, *exp.restore_steps):
            if s.kind == "read_memory":
                length = s.args.get("length")
                if not _is_nonnegative_int(length):
                    errors.append("read_memory length must be a non-negative integer")
                elif length > self.max_read_bytes:
                    errors.append(f"read exceeds max_read_bytes: {length}")
            if s.kind == "write_memory":
                try:
                    write_length = len(bytes.fromhex(s.args.get("data_hex", "")))
                except (TypeError, ValueError):
                    errors.append("write_memory data_hex is not valid hex")
                else:
                    if write_length > self.max_write_bytes:
                        errors.append("write exceeds max_write_bytes")
            if "iterations" in s.args:
                iterations = s.args["iterations"]
                if not _is_nonnegative_int(iterations):
                    errors.append("iterations must be a non-negative integer")
                elif iterations > self.max_iterations:
                    errors.append("iterations exceed policy max")
        return errors
