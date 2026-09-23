from orbisprobe.policy import DEFAULT_BLOCKED_SINKS, Policy
from orbisprobe.schema import Experiment, RiskClass, Step


def reversible_plan(**overrides):
    values = {
        "id": "restore-sequence",
        "title": "restore sequence",
        "hypothesis": "bounded write",
        "risk": RiskClass.REVERSIBLE_KERNEL_RAM,
        "controlled_input": "one byte",
        "validation": "preconditions",
        "consumer": "named consumer",
        "expected_effect": "bounded effect",
        "observable": "readbacks",
        "experiment": "read, write, read, restore, verify",
        "preconditions": ["ready"],
        "forbidden_sinks": sorted(DEFAULT_BLOCKED_SINKS),
        "validation_steps": [Step("check_precondition", {"name": "ready"})],
        "steps": [
            Step("read_memory", {"address": "0x1000", "length": 1}),
            Step("write_memory", {"address": "0x1000", "data_hex": "00"}),
            Step("read_memory", {"address": "0x1000", "length": 1}),
        ],
        "restore_steps": [
            Step("write_saved_original", {"from_step": 0}),
            Step("verify_restored", {"from_step": 0}),
        ],
        "metadata": {"live_target": True},
    }
    values.update(overrides)
    return Experiment(**values)


def errors(exp):
    return Policy(max_risk=RiskClass.REVERSIBLE_KERNEL_RAM).validate(exp)


def test_complete_reversible_sequence_is_valid():
    assert errors(reversible_plan()) == []


def test_reversible_sequence_requires_original_read():
    exp = reversible_plan(
        steps=[
            Step("write_memory", {"address": "0x1000", "data_hex": "00"}),
            Step("read_memory", {"address": "0x1000", "length": 1}),
        ]
    )
    assert "reversible write requires original-byte read before mutation" in errors(exp)


def test_reversible_sequence_requires_post_write_readback():
    exp = reversible_plan(
        steps=[
            Step("read_memory", {"address": "0x1000", "length": 1}),
            Step("write_memory", {"address": "0x1000", "data_hex": "00"}),
        ]
    )
    assert "reversible write requires post-write readback" in errors(exp)


def test_reversible_sequence_requires_restore_readback():
    exp = reversible_plan(
        restore_steps=[Step("write_saved_original", {"from_step": 0})]
    )
    assert "reversible write requires explicit restore readback" in errors(exp)


def test_reversible_sequence_reads_same_address_and_length():
    exp = reversible_plan(
        steps=[
            Step("read_memory", {"address": "0x2000", "length": 1}),
            Step("write_memory", {"address": "0x1000", "data_hex": "00"}),
            Step("read_memory", {"address": "0x1000", "length": 2}),
        ]
    )
    plan_errors = errors(exp)
    assert "original-byte read must match write address and length" in plan_errors
    assert "post-write readback must match write address and length" in plan_errors


def test_restore_steps_require_valid_original_from_step():
    exp = reversible_plan(
        restore_steps=[
            Step("write_saved_original", {}),
            Step("verify_restored", {"from_step": 99}),
        ]
    )
    plan_errors = errors(exp)
    assert "restore from_step must reference the original-byte read" in plan_errors


def test_restore_alias_cannot_override_original_address():
    exp = reversible_plan(
        restore_steps=[
            Step("write_saved_original", {"from_step": 0, "address": "0x2000"}),
            Step("verify_restored", {"from_step": 0, "address": "0x2000"}),
        ]
    )
    assert "restore address override must match original-byte read" in errors(exp)
