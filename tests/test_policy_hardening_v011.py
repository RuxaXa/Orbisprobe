import pytest

from orbisprobe.policy import DEFAULT_BLOCKED_SINKS, Policy
from orbisprobe.schema import Experiment, RiskClass, Step


def live_plan(**overrides):
    values = {
        "id": "policy-hardening",
        "title": "policy hardening",
        "hypothesis": "bounded plan",
        "risk": RiskClass.ACTIVE_REQUEST,
        "controlled_input": "one input",
        "validation": "one precondition",
        "consumer": "named consumer",
        "expected_effect": "bounded effect",
        "observable": "result",
        "experiment": "one step",
        "preconditions": ["ready"],
        "forbidden_sinks": sorted(DEFAULT_BLOCKED_SINKS),
        "validation_steps": [Step("check_precondition", {"name": "ready"})],
        "steps": [Step("execute_named_case", {"case": "A"})],
        "metadata": {"live_target": True},
    }
    values.update(overrides)
    return Experiment(**values)


@pytest.mark.parametrize("value", [None, "", "nope", [], {}, -1, True, 1.5])
def test_invalid_read_length_is_plan_error_not_exception(value):
    exp = Experiment(
        "invalid-length",
        "invalid length",
        "reject invalid length",
        RiskClass.OFFLINE,
        steps=[Step("read_memory", {"length": value})],
    )
    errors = Policy(max_risk=RiskClass.OFFLINE).validate(exp)
    assert "read_memory length must be a non-negative integer" in errors


@pytest.mark.parametrize("value", [None, "", "nope", [], {}, -1, True, 1.5])
def test_invalid_iterations_is_plan_error_not_exception(value):
    exp = Experiment(
        "invalid-iterations",
        "invalid iterations",
        "reject invalid iterations",
        RiskClass.OFFLINE,
        steps=[Step("hash_file", {"path": "x", "iterations": value})],
    )
    errors = Policy(max_risk=RiskClass.OFFLINE).validate(exp)
    assert "iterations must be a non-negative integer" in errors


def test_validation_mutating_flag_is_blocked():
    exp = live_plan(
        validation_steps=[Step("check_precondition", {"name": "ready", "mutating": True})]
    )
    errors = Policy(max_risk=RiskClass.ACTIVE_REQUEST).validate(exp)
    assert "validation step cannot mutate target: check_precondition" in errors


def test_plan_specific_forbidden_sink_step_is_blocked():
    exp = live_plan(
        forbidden_sinks=sorted(DEFAULT_BLOCKED_SINKS | {"network_send"}),
        steps=[Step("network_send", {})],
    )
    errors = Policy(max_risk=RiskClass.ACTIVE_REQUEST).validate(exp)
    assert "plan-forbidden sink step is not executable: network_send" in errors


def test_write_memory_requires_reversible_kernel_risk():
    exp = live_plan(
        steps=[Step("write_memory", {"address": "0x1000", "data_hex": "00"})]
    )
    errors = Policy(max_risk=RiskClass.ACTIVE_REQUEST).validate(exp)
    assert "write_memory requires reversible_kernel_ram risk" in errors


def test_persistent_sink_cannot_be_disabled_by_policy_override():
    exp = Experiment(
        "persistent-hard-block",
        "persistent hard block",
        "persistent sink stays blocked",
        RiskClass.OFFLINE,
        steps=[Step("flash_write", {})],
    )
    errors = Policy(max_risk=RiskClass.OFFLINE, blocked_sinks=set()).validate(exp)
    assert "blocked sink step is never executable: flash_write" in errors
