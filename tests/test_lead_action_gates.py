from __future__ import annotations

from dataclasses import replace

import pytest

from orbisprobe.leads.gates import evaluate_action_gate
from orbisprobe.leads.model import ActionKind, ClosureCost, EvidenceAction
from orbisprobe.schema import RiskClass


def _probe() -> EvidenceAction:
    return EvidenceAction(
        action_id="probe",
        action="read owned status",
        target_edge="state->consumer",
        kind=ActionKind.EVIDENCE_PROBE,
        expected_information_gain=4,
        cost=ClosureCost.COST_3,
        risk=RiskClass.READ_ONLY,
        exact_question="Does the consumer observe the same object?",
        ownership_known=True,
        target_identity_known=True,
        bounded_scope=True,
        stop_condition="one read then stop",
    )


def test_evidence_probe_reduced_gate_does_not_require_complete_vulnerability_graph():
    decision = evaluate_action_gate(_probe())

    assert decision.allowed is True
    assert decision.gate == "EVIDENCE_PROBE_GATE"
    assert decision.blocks == ()


def test_evidence_probe_still_blocks_hard_safety_violations():
    for unsafe in (
        replace(_probe(), persistent_effect=True),
        replace(_probe(), unknown_mmio=True),
        replace(_probe(), invalid_pointer=True),
        replace(_probe(), kernel_code_mutation=True),
        replace(_probe(), kernel_write=True),
        replace(_probe(), arbitrary_address=True),
        replace(_probe(), destructive_mmio=True),
        replace(_probe(), persistent_state_target=True),
        replace(_probe(), secure_state_modification=True),
        replace(_probe(), risk=RiskClass.PERSISTENT),
    ):
        decision = evaluate_action_gate(unsafe)
        assert decision.allowed is False
        assert decision.blocks


def test_exploit_test_requires_strict_complete_gate():
    incomplete = replace(
        _probe(),
        kind=ActionKind.EXPLOIT_TEST,
        risk=RiskClass.VOLATILE_USER,
        controlled_input=True,
        known_consumer=True,
        bounded_observable=True,
        lifecycle_closed=True,
        recovery_defined=True,
        controls_defined=True,
        concrete_gap=False,
    )
    complete = replace(incomplete, concrete_gap=True)

    blocked = evaluate_action_gate(incomplete)
    allowed = evaluate_action_gate(complete)

    assert blocked.allowed is False
    assert "concrete security gap is not established" in blocked.blocks
    assert allowed.allowed is True
    assert allowed.gate == "EXPLOIT_TEST_GATE"
    no_question = replace(complete, exact_question="")
    assert no_question.exploit_test_ready is False
    assert evaluate_action_gate(no_question).allowed is False


def test_action_gate_fields_are_strictly_typed_and_utf8_safe():
    action = _probe()
    boolean_fields = (
        "ownership_known",
        "target_identity_known",
        "bounded_scope",
        "persistent_effect",
        "unknown_mmio",
        "invalid_pointer",
        "kernel_code_mutation",
        "kernel_write",
        "arbitrary_address",
        "destructive_mmio",
        "persistent_state_target",
        "secure_state_modification",
        "controlled_input",
        "concrete_gap",
        "known_consumer",
        "bounded_observable",
        "lifecycle_closed",
        "recovery_defined",
        "controls_defined",
    )
    for field in boolean_fields:
        for malformed in (1, 0, "true", [], {}):
            with pytest.raises(TypeError, match=field):
                replace(action, **{field: malformed})
    with pytest.raises(ValueError, match="expected_information_gain"):
        replace(action, expected_information_gain=True)
    with pytest.raises(ValueError, match="UTF-8"):
        replace(action, required_artifact="bad\ud800artifact")
