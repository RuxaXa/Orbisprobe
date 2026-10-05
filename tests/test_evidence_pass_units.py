"""Focused unit tests: fail-closed states, determinism, hash binding, gates, direction decoder."""

from __future__ import annotations

import json
from dataclasses import replace

import pytest
from evidence_pass_support import (
    CORRECT_LABEL,
    PRE_F3_LABEL,
    build_scenario,
    copy_package,
    direction_record,
    probe_action,
    rewrite_manifest,
)

from orbisprobe.evidence_pass.direction import (
    argument_bindings,
    check_copy_events,
    derive_copy_direction,
    helper_first_argument_is_source,
)
from orbisprobe.evidence_pass.manifest import (
    build_manifest,
    render_manifest,
    verify_manifest,
)
from orbisprobe.evidence_pass.model import ReviewState, canonical_json, ensure_finite
from orbisprobe.evidence_pass.plan import ActionPlan
from orbisprobe.evidence_pass.review import (
    ReviewMode,
    ReviewOutcome,
    evaluate_review_result,
    review_failure_policy,
    review_questions,
)
from orbisprobe.evidence_pass.verify import verify_package
from orbisprobe.leads.gates import evaluate_action_gate
from orbisprobe.leads.model import ActionKind


def test_canonical_json_is_deterministic_and_fail_closed():
    payload = {"b": [2, 1], "a": {"d": 1.5, "c": "text"}}

    assert canonical_json(payload) == canonical_json({"a": {"c": "text", "d": 1.5}, "b": [2, 1]})
    assert canonical_json(payload).endswith("\n")

    for bad in (float("nan"), float("inf"), {"x": float("-inf")}):
        with pytest.raises(ValueError):
            canonical_json(bad)
    with pytest.raises(ValueError):
        canonical_json({"key": "\ud800"})
    with pytest.raises(TypeError):
        ensure_finite("value", {"key": object()})


def test_manifest_detects_duplicates_missing_and_unexpected(tmp_path):
    root = tmp_path / "pkg"
    root.mkdir()
    (root / "a.json").write_text("{}\n", encoding="utf-8")
    (root / "b.json").write_text("{}\n", encoding="utf-8")
    entries = build_manifest(root)

    (root / "SHA256SUMS").write_text(
        render_manifest(entries) + f"{entries['a.json']}  ./a.json\n", encoding="utf-8"
    )
    report = verify_manifest(root)
    assert report.duplicates == ("a.json",)
    assert report.status == "MANIFEST_INCOMPLETE"

    (root / "SHA256SUMS").write_text(render_manifest(entries), encoding="utf-8")
    assert verify_manifest(root, strict=True).status == "MANIFEST_OK"

    (root / "extra.json").write_text("{}\n", encoding="utf-8")
    assert verify_manifest(root, strict=True).unexpected == ("extra.json",)
    assert verify_manifest(root, strict=True).status == "MANIFEST_INCOMPLETE"
    assert verify_manifest(root, strict=False).status == "MANIFEST_OK"

    (root / "extra.json").unlink()
    (root / "b.json").unlink()
    assert verify_manifest(root).missing == ("b.json",)


def test_metrics_are_recomputed_and_tampering_is_rejected(tmp_path):
    scenario = build_scenario(tmp_path, "A")
    tampered = copy_package(scenario, tmp_path / "tampered")
    payload = json.loads((tampered / "metrics.json").read_text(encoding="utf-8"))
    payload["actions_executed"] = 5
    (tampered / "metrics.json").write_text(canonical_json(payload), encoding="utf-8")
    rewrite_manifest(tampered)

    result = verify_package(str(tampered))

    assert result["status"] == "CHANGES_REQUIRED"
    check = next(item for item in result["checks"] if item["check"] == "metrics_recomputation")
    assert check["status"] == "FAIL"
    assert "actions_executed" in json.dumps(check["details"])


def test_direction_decoder_matches_the_pinned_scratch_bytes():
    record = direction_record(CORRECT_LABEL)

    assert helper_first_argument_is_source(record["helper_bytes"]) is True
    assert helper_first_argument_is_source("90" * 8) is False
    assert argument_bindings(record["binder_bytes"]) == {"r14": "arg2", "rbx": "arg1"}
    assert derive_copy_direction(record) == ("*(indirdep+0x50)+0x18", "bp+0x18", "bp+0x8")

    problems, checked = check_copy_events({"copies": [record]})
    assert checked == 1 and problems == []

    problems, checked = check_copy_events({"copies": [direction_record(PRE_F3_LABEL)]})
    assert checked == 1
    assert problems and "contradicts the pinned bytes" in problems[0]

    # Inverted direction with a consistently inverted field-name table must still fail.
    problems, checked = check_copy_events({"copies": [direction_record(PRE_F3_LABEL, swap_names=True)]})
    assert checked == 1
    assert any("operand role" in problem for problem in problems)

    problems, checked = check_copy_events({"copies": [{"name": "incomplete"}]})
    assert checked == 0 and problems


def test_review_states_never_allow_implicit_success(tmp_path):
    scenario = build_scenario(tmp_path, "A")
    from orbisprobe.evidence_pass.manifest import manifest_sha256

    base = {
        "schema": "orbisprobe-evidence-pass-review-request-v1",
        "package_sha256sums_sha256": manifest_sha256(scenario.package),
    }

    assert evaluate_review_result(scenario.package, base).state is ReviewState.UNKNOWN_UNVERIFIED
    assert evaluate_review_result(scenario.package, {**base, "state": "PASS"}).state is ReviewState.PASS
    assert (
        evaluate_review_result(scenario.package, {**base, "state": "PASS", "findings": ["x"]}).state
        is ReviewState.UNKNOWN_UNVERIFIED
    )
    assert (
        evaluate_review_result(scenario.package, {**base, "state": "CHANGES_REQUIRED"}).state
        is ReviewState.UNKNOWN_UNVERIFIED
    )
    assert (
        evaluate_review_result(scenario.package, {**base, "state": "NOT_A_STATE"}).state
        is ReviewState.UNKNOWN_UNVERIFIED
    )
    stale = evaluate_review_result(
        scenario.package, {**base, "package_sha256sums_sha256": "0" * 64, "state": "PASS"}
    )
    assert stale.state is ReviewState.STALE_REVIEW

    adversarial = review_questions(ReviewMode.ADVERSARIAL)
    assert len(adversarial) > len(review_questions(ReviewMode.STANDARD))
    assert any("counterexample" in question for question in adversarial)


def test_review_failure_policy_stops_without_auto_remediation():
    failed = review_failure_policy(ReviewOutcome(ReviewState.CHANGES_REQUIRED, "findings present", ("F3",)))

    assert failed["stop"] is True
    assert failed["auto_remediation"] is False
    assert failed["findings"] == ["F3"]
    assert "REMEDIATION_PASS" in failed["requires"]

    clean = review_failure_policy(ReviewOutcome(ReviewState.PASS, "clean"))
    assert clean["stop"] is False
    assert clean["auto_remediation"] is False


def test_safety_integration_reuses_the_existing_gates(tmp_path):
    scenario = build_scenario(tmp_path, "A")
    payload = json.loads((scenario.inputs / "plan.json").read_text(encoding="utf-8"))
    action = payload["actions"][0]

    action["kind"] = ActionKind.EXPLOIT_TEST.value
    action.update(
        {
            "controlled_input": True,
            "concrete_gap": True,
            "known_consumer": True,
            "bounded_observable": True,
            "lifecycle_closed": True,
            "recovery_defined": True,
            "controls_defined": True,
        }
    )
    with pytest.raises(ValueError, match="EXPLOIT_TEST|proof/exploit"):
        ActionPlan.from_dict(payload)

    action["kind"] = ActionKind.EVIDENCE_PROBE.value
    action["kernel_write"] = True
    with pytest.raises(ValueError, match="EVIDENCE_PROBE_GATE"):
        ActionPlan.from_dict(payload)
    decision = evaluate_action_gate(replace(probe_action(), kernel_write=True))
    assert decision.allowed is False
    assert decision.gate == "EVIDENCE_PROBE_GATE"
    assert "kernel writes are forbidden" in decision.blocks
