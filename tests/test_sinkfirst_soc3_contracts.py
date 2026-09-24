from __future__ import annotations

import json

import pytest

from orbisprobe.analysis import (
    ContextRestoreBehavior,
    CrossContextImpactContract,
    RegisterPolicyContract,
    RegisterSpaceClass,
)
from orbisprobe.surfaces.model import Confidence


def _complete_register_policy() -> RegisterPolicyContract:
    return RegisterPolicyContract(
        contract_id="register-policy:test-global-control",
        register_index=0x1234,
        register_name="TEST_GLOBAL_CONTROL",
        register_role="synthetic global control used by the unit test",
        space_class=RegisterSpaceClass.CONFIG,
        shadowed=False,
        restore_behavior=ContextRestoreBehavior.GLOBAL_UNTIL_OVERWRITTEN,
        register_name_confidence=Confidence.HIGH,
        register_role_confidence=Confidence.MEDIUM,
        globality_confidence=Confidence.MEDIUM,
        context_restore_confidence=Confidence.MEDIUM,
        evidence=("fixture:save-list-absent", "fixture:mmio-write"),
    )


def test_soc3_enums_preserve_requested_labels():
    assert [item.value for item in RegisterSpaceClass] == [
        "CONTEXT",
        "UCONFIG",
        "CONFIG",
        "PRIVILEGED",
        "UNKNOWN",
    ]
    assert [item.value for item in ContextRestoreBehavior] == [
        "PER_CONTEXT_RESTORED",
        "GLOBAL_PERSISTENT",
        "GLOBAL_UNTIL_OVERWRITTEN",
        "RESET_ON_SWITCH",
        "UNKNOWN",
    ]


def test_register_policy_contract_is_fail_closed_and_deterministic():
    policy = _complete_register_policy()
    reordered = RegisterPolicyContract(
        contract_id=policy.contract_id,
        register_index=policy.register_index,
        register_name=policy.register_name,
        register_role=policy.register_role,
        space_class=policy.space_class,
        shadowed=policy.shadowed,
        restore_behavior=policy.restore_behavior,
        register_name_confidence=policy.register_name_confidence,
        register_role_confidence=policy.register_role_confidence,
        globality_confidence=policy.globality_confidence,
        context_restore_confidence=policy.context_restore_confidence,
        evidence=tuple(reversed(policy.evidence)),
    )

    assert policy.complete is True
    assert policy.to_json() == reordered.to_json()
    assert json.loads(policy.to_json()) == policy.to_dict()
    assert policy.to_dict()["register_index"] == 0x1234
    assert policy.to_dict()["restore_behavior"] == "GLOBAL_UNTIL_OVERWRITTEN"

    unknown = RegisterPolicyContract(
        contract_id="register-policy:unknown",
        register_index=0x2233,
        register_name="UNKNOWN",
        register_role="UNKNOWN",
        space_class=RegisterSpaceClass.UNKNOWN,
        shadowed=None,
        restore_behavior=ContextRestoreBehavior.UNKNOWN,
    )
    assert unknown.complete is False

    with pytest.raises(TypeError, match="shadowed"):
        RegisterPolicyContract(
            contract_id="register-policy:bad",
            register_index=0x1234,
            register_name="TEST_GLOBAL_CONTROL",
            register_role="control",
            space_class=RegisterSpaceClass.CONFIG,
            shadowed=1,  # type: ignore[arg-type]
            restore_behavior=ContextRestoreBehavior.UNKNOWN,
        )


def test_cross_context_impact_requires_complete_evidence_backed_policy():
    policy = _complete_register_policy()
    impact = CrossContextImpactContract(
        contract_id="cross-context:vgt-reset-debug",
        register_policy=policy,
        writer_context="process-a:graphics",
        consumer_context="process-b:graphics",
        affected_scope="graphics pipe",
        effects=("synthetic-effect-a", "synthetic-effect-b"),
        crosses_contexts=True,
        recovery=("gpu-reset", "explicit-write"),
        confidence=Confidence.MEDIUM,
        evidence=("scheduler-save-list:absent", "global-mmio-path"),
    )
    reordered = CrossContextImpactContract(
        contract_id=impact.contract_id,
        register_policy=policy,
        writer_context=impact.writer_context,
        consumer_context=impact.consumer_context,
        affected_scope=impact.affected_scope,
        effects=tuple(reversed(impact.effects)),
        crosses_contexts=impact.crosses_contexts,
        recovery=tuple(reversed(impact.recovery)),
        confidence=impact.confidence,
        evidence=tuple(reversed(impact.evidence)),
    )

    assert impact.complete is True
    assert impact.classification == "CONFIRMED_CROSS_CONTEXT"
    assert impact.to_json() == reordered.to_json()
    assert json.loads(impact.to_json())["register_policy"]["register_index"] == 0x1234


def test_cross_context_impact_remains_potential_when_unresolved():
    policy = _complete_register_policy()
    impact = CrossContextImpactContract(
        contract_id="cross-context:unknown",
        register_policy=policy,
        writer_context="process-a:graphics",
        consumer_context="process-b:graphics",
        affected_scope="unknown",
        effects=("synthetic-effect",),
        crosses_contexts=None,
        confidence=Confidence.NONE,
        unresolved=("consumer inheritance not statically proven",),
    )

    assert impact.complete is False
    assert impact.classification == "POTENTIAL_CROSS_CONTEXT"

    with pytest.raises(ValueError, match="distinct"):
        CrossContextImpactContract(
            contract_id="cross-context:bad",
            register_policy=policy,
            writer_context="process-a:graphics",
            consumer_context="process-a:graphics",
            affected_scope="graphics pipe",
            effects=("synthetic-effect",),
            crosses_contexts=None,
        )
