from __future__ import annotations

from dataclasses import dataclass

from orbisprobe.schema import RiskClass

from .model import ActionKind, ClosureCost, EvidenceAction


@dataclass(frozen=True)
class ActionGateDecision:
    allowed: bool
    gate: str
    blocks: tuple[str, ...]


HARD_SAFETY_CHECKS = (
    ("persistent_effect", "persistent effect is forbidden"),
    ("unknown_mmio", "unknown MMIO access is forbidden"),
    ("invalid_pointer", "invalid or unvalidated pointer is forbidden"),
    ("kernel_code_mutation", "kernel code mutation is forbidden"),
    ("kernel_write", "kernel writes are forbidden"),
    ("arbitrary_address", "arbitrary addresses are forbidden"),
    ("destructive_mmio", "destructive MMIO is forbidden"),
    ("persistent_state_target", "persistent-state targets are forbidden"),
    ("secure_state_modification", "secure-state modification is forbidden"),
)


def evaluate_action_gate(action: EvidenceAction) -> ActionGateDecision:
    blocks: list[str] = []
    gate = (
        "EVIDENCE_PROBE_GATE"
        if action.kind is ActionKind.EVIDENCE_PROBE
        else "EXPLOIT_TEST_GATE"
    )

    for field, reason in HARD_SAFETY_CHECKS:
        if getattr(action, field):
            blocks.append(reason)
    if action.risk is RiskClass.PERSISTENT:
        blocks.append("persistent risk class is forbidden")
    if action.cost is ClosureCost.COST_BLOCKED:
        blocks.append("required evidence is artifact-blocked")
    if not action.exact_question:
        blocks.append("exact research question is required")
    if not action.ownership_known:
        blocks.append("ownership is not known")
    if not action.target_identity_known:
        blocks.append("target identity is not known")
    if not action.bounded_scope:
        blocks.append("scope is not bounded")
    if not action.stop_condition:
        blocks.append("explicit stop condition is required")

    if action.kind is ActionKind.EXPLOIT_TEST:
        if not action.controlled_input:
            blocks.append("controlled input is not established")
        if not action.concrete_gap:
            blocks.append("concrete security gap is not established")
        if not action.known_consumer:
            blocks.append("privileged or hardware consumer is not known")
        if not action.bounded_observable:
            blocks.append("observable is not bounded")
        if not action.lifecycle_closed:
            blocks.append("lifecycle is not closed")
        if not action.recovery_defined:
            blocks.append("restore or recovery is not defined")
        if not action.controls_defined:
            blocks.append("positive and negative controls are not defined")

    return ActionGateDecision(not blocks, gate, tuple(blocks))
