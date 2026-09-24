from __future__ import annotations

import json

import pytest

from orbisprobe.analysis import (
    CommandAuthorizationContract,
    CrossProcessorFieldContract,
    DeviceOpenClassification,
    DeviceOpenContract,
    FieldContract,
    SessionBindingContract,
    SnapshotSemantics,
    UserInfluence,
)
from orbisprobe.surfaces.model import Confidence


def test_device_open_contract_classifies_only_evidence_backed_observations():
    contract = DeviceOpenContract(
        contract_id="open:gpu",
        device="/dev/gpu",
        entrypoint="gpu_open",
        user_reachable=True,
        privilege_required=False,
        confidence=Confidence.HIGH,
        authid_gated=False,
        session_gated=False,
        evidence=("mode:0666", "cdevsw:gpu_open"),
    )

    assert contract.classification is DeviceOpenClassification.UNPRIVILEGED_USER
    assert contract.complete is True
    assert json.loads(contract.to_json()) == contract.to_dict()

    session = DeviceOpenContract(
        contract_id="open:gc",
        device="/dev/gc",
        entrypoint="gc_open",
        user_reachable=True,
        privilege_required=False,
        confidence=Confidence.HIGH,
        authid_gated=False,
        session_gated=True,
        evidence=("mode:0666", "cdevpriv:set/get"),
    )
    assert session.classification is DeviceOpenClassification.SESSION_GATED

    authid = DeviceOpenContract(
        contract_id="open:authid",
        device="/dev/special",
        entrypoint="special_open",
        user_reachable=True,
        privilege_required=False,
        confidence=Confidence.HIGH,
        authid_gated=True,
        session_gated=True,
        evidence=("authid allowlist",),
    )
    assert authid.classification is DeviceOpenClassification.AUTHID_GATED

    unresolved = DeviceOpenContract(
        contract_id="open:unknown",
        device="/dev/unknown",
        entrypoint="unknown_open",
        user_reachable=None,
        privilege_required=None,
        confidence=Confidence.NONE,
    )
    assert unresolved.classification is DeviceOpenClassification.UNKNOWN
    assert unresolved.complete is False

    with pytest.raises(TypeError, match="user_reachable"):
        DeviceOpenContract(
            "open:bad",
            "/dev/bad",
            "bad_open",
            user_reachable=1,  # type: ignore[arg-type]
            privilege_required=False,
            confidence=Confidence.HIGH,
            authid_gated=False,
            session_gated=False,
            evidence=("observation",),
        )


def test_command_authorization_contract_distinguishes_absent_from_unknown():
    guarded = CommandAuthorizationContract(
        contract_id="auth:gpu-submit",
        device_open_contract_id="open:gpu",
        command_id=0xC0204701,
        handler="gpu_submit",
        requires_authorization=True,
        authorization_checks=("session-owner", "privilege:gpu-submit"),
        confidence=Confidence.HIGH,
        evidence=("branch@0x401000",),
    )
    absent = CommandAuthorizationContract(
        contract_id="auth:gpu-query",
        device_open_contract_id="open:gpu",
        command_id=0xC0204702,
        handler="gpu_query",
        requires_authorization=False,
        confidence=Confidence.HIGH,
        evidence=("full-handler-cfg",),
    )
    unknown = CommandAuthorizationContract(
        contract_id="auth:gpu-unknown",
        device_open_contract_id="open:gpu",
        command_id=0xC0204703,
        handler="gpu_unknown",
        requires_authorization=None,
        confidence=Confidence.NONE,
    )

    assert guarded.classification == "authorization_enforced"
    assert absent.classification == "authorization_absent"
    assert unknown.classification == "unknown"
    assert guarded.complete is True
    assert absent.complete is True
    assert unknown.complete is False

    with pytest.raises(ValueError, match="authorization_checks"):
        CommandAuthorizationContract(
            "auth:bad",
            "open:gpu",
            1,
            "bad_handler",
            True,
            confidence=Confidence.HIGH,
            evidence=("branch",),
        )


def test_field_contract_is_fail_closed_and_serializes_set_like_evidence_canonically():
    left = FieldContract(
        field_id="field:request.length",
        offset=0x18,
        width=4,
        influence=UserInfluence.USER_CONTROLLED,
        validators=("max:0x400", "type:u32"),
        confidence=Confidence.HIGH,
        evidence=("load@0x2000", "copyin@0x1000"),
    )
    reordered = FieldContract(
        field_id="field:request.length",
        offset=0x18,
        width=4,
        influence=UserInfluence.USER_CONTROLLED,
        validators=("type:u32", "max:0x400"),
        confidence=Confidence.HIGH,
        evidence=("copyin@0x1000", "load@0x2000"),
    )

    assert left.complete is True
    assert left.validated is True
    assert left.to_json() == reordered.to_json()

    unknown = FieldContract(
        field_id="field:request.pointer",
        offset=0x20,
        width=8,
        influence=UserInfluence.UNKNOWN,
        confidence=Confidence.NONE,
    )
    assert unknown.complete is False
    assert unknown.validated is False

    with pytest.raises(ValueError, match="width"):
        FieldContract(
            "field:bad",
            0,
            0,
            UserInfluence.UNKNOWN,
            confidence=Confidence.NONE,
        )


def test_cross_processor_field_contract_requires_known_snapshot_semantics():
    field = FieldContract(
        field_id="field:gpu.command",
        offset=8,
        width=8,
        influence=UserInfluence.USER_INFLUENCED,
        validators=("command-allowlist",),
        confidence=Confidence.HIGH,
        evidence=("host-write@0x1000",),
    )
    contract = CrossProcessorFieldContract(
        contract_id="xproc:gpu-command",
        field=field,
        producer="host-kernel",
        consumer="gpu-firmware",
        snapshot_semantics=SnapshotSemantics.REREAD_AFTER_VALIDATE,
        confidence=Confidence.MEDIUM,
        evidence=("firmware-read@0x3000",),
    )

    assert contract.complete is True
    assert contract.to_dict()["snapshot_semantics"] == "REREAD_AFTER_VALIDATE"
    assert contract.to_dict()["field"]["field_id"] == field.field_id

    unknown = CrossProcessorFieldContract(
        contract_id="xproc:unknown",
        field=field,
        producer="host-kernel",
        consumer="gpu-firmware",
        snapshot_semantics=SnapshotSemantics.UNKNOWN,
        confidence=Confidence.HIGH,
        evidence=("single observed read",),
    )
    assert unknown.complete is False

    with pytest.raises(ValueError, match="distinct"):
        CrossProcessorFieldContract(
            "xproc:loop",
            field,
            "host-kernel",
            "host-kernel",
            SnapshotSemantics.SNAPSHOT_SAFE,
            Confidence.HIGH,
            ("observation",),
        )


def test_session_binding_contract_requires_explicit_per_open_binding():
    bound = SessionBindingContract(
        contract_id="session:gpu",
        device_open_contract_id="open:gpu",
        command_contract_ids=("auth:gpu-submit", "auth:gpu-query"),
        binding_fields=("field:session.owner", "field:session.token"),
        per_open_state=True,
        confidence=Confidence.HIGH,
        evidence=("lookup-by-file-private",),
    )
    unbound = SessionBindingContract(
        contract_id="session:global",
        device_open_contract_id="open:gpu",
        command_contract_ids=("auth:gpu-global",),
        binding_fields=(),
        per_open_state=False,
        confidence=Confidence.HIGH,
        evidence=("global-state-reference",),
    )

    assert bound.bound is True
    assert bound.complete is True
    assert unbound.bound is False
    assert unbound.complete is True
    assert json.loads(bound.to_json())["command_contract_ids"] == [
        "auth:gpu-query",
        "auth:gpu-submit",
    ]

    with pytest.raises(ValueError, match="binding_fields"):
        SessionBindingContract(
            "session:bad",
            "open:gpu",
            ("auth:gpu-submit",),
            (),
            True,
            Confidence.HIGH,
            ("observation",),
        )
