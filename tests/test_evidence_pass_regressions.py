"""Regression fixtures A-J for the exact-once evidence-pass workflow."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from evidence_pass_support import (
    ABSOLUTE_PACKAGE_COPY_SCRIPT,
    ACTION_ID,
    CORRECT_LABEL,
    LEAD_ID,
    NOOP_REBUILD_SCRIPT,
    PACKAGE_READING_REBUILD_SCRIPT,
    PARTIAL_REBUILD_SCRIPT,
    PRE_F3_LABEL,
    RECIPIENT_ID,
    SELF_COPY_REBUILD_SCRIPT,
    build_scenario,
    copy_package,
    load_case,
    manifest_status,
    package_tree,
    rewrite_manifest,
    run_cli,
    set_rebuild_script,
    verify,
)

from orbisprobe.evidence_pass.journal import ActionJournal, ExactOnceViolation
from orbisprobe.evidence_pass.manifest import manifest_sha256
from orbisprobe.evidence_pass.model import (
    ActionResult,
    ActionStatus,
    LeadDisposition,
    ResultFreshness,
    ReviewMode,
    ReviewState,
    canonical_json,
)
from orbisprobe.evidence_pass.plan import ActionPlan
from orbisprobe.evidence_pass.remediation import RemediationRequest, plan_remediation
from orbisprobe.evidence_pass.review import (
    build_review_bundle,
    classify_delayed_result,
    evaluate_review_result,
    persist_review_result,
    review_failure_policy,
)
from orbisprobe.evidence_pass.runner import ActionExecution, ActionFailure, run_plan
from orbisprobe.evidence_pass.verify import verify_package
from orbisprobe.leads.model import EdgeDistance
from orbisprobe.leads.safe_io import (
    capture_protected_sources,
    prepare_output_directory,
    safe_atomic_write_text,
)

FIXTURE_CASES = ["A", "B", "C", "D", "E", "F", "G", "H", "I", "J"]


def _check(result: dict, name: str) -> dict:
    return next(check for check in result["checks"] if check["check"] == name)


def test_fixture_catalogue_is_complete():
    for case in FIXTURE_CASES:
        payload = load_case(case)
        assert payload["case"] == case
        assert payload["expect"]


def test_case_a_ordinary_pass_is_manifest_ok_and_verifies(tmp_path):
    case = load_case("A")
    scenario = build_scenario(tmp_path, "A")

    assert manifest_status(scenario.package) == "MANIFEST_OK"
    result = verify(scenario)

    assert result["status"] == case["expect"]["verifier"] == "PASS"
    assert result["exactly_once"] is True
    assert _check(result, "rebuild_determinism")["details"]["files_compared"] > 0
    assert result["frozen_set_unchanged"] is True
    summary = json.loads((scenario.package / "campaign-summary.json").read_text(encoding="utf-8"))
    assert summary["metrics"]["actions_executed"] == case["expect"]["actions_executed"]
    assert summary["portfolio"]["active_leads"] == case["expect"]["active_leads"]


def test_case_a_without_rebuild_is_unknown_not_pass(tmp_path):
    scenario = build_scenario(tmp_path, "A")

    result = verify(scenario, rebuild=False)

    assert result["status"] == "UNKNOWN_UNVERIFIED"
    assert _check(result, "rebuild_determinism")["status"] == "UNVERIFIED"


def test_case_b_shared_evidence_is_propagated_without_reexecution(tmp_path):
    case = load_case("B")
    scenario = build_scenario(tmp_path, "B", result_kind="EDGE_REDUCED", shared=True)

    result = verify(scenario)

    assert result["status"] == case["expect"]["verifier"] == "PASS"
    summary = json.loads((scenario.package / "campaign-summary.json").read_text(encoding="utf-8"))
    shared = summary["shared_evidence"]
    assert len(shared) == case["expect"]["shared_actions"]
    assert shared[0]["recipients"] == case["expect"]["recipients"] == [RECIPIENT_ID]
    assert shared[0]["reexecuted"] is False
    assert set(scenario.journal.execution_counts()) == {ACTION_ID}
    assert scenario.journal.record(ACTION_ID).attempts == 1
    unchanged = _check(result, "expected_unchanged_leads")
    assert unchanged["status"] == "PASS"
    assert unchanged["details"]["checked"] == case["expect"]["unchanged_leads"]


def test_case_c_resolved_safe_must_not_close_a_still_active_lead(tmp_path):
    case = load_case("C")
    scenario = build_scenario(
        tmp_path,
        "C",
        result_kind="RESOLVED_SAFE",
        disposition="SAFE_CLOSED",
        lead_after_edge=EdgeDistance.EDGE_1,
    )

    result = verify(scenario)

    assert result["status"] == case["expect"]["verifier"] == "CHANGES_REQUIRED"
    check = _check(result, case["expect"]["check"])
    assert check["status"] == "FAIL"
    assert any("must not be promoted" in problem for problem in check["details"]["problems"])


def test_case_d_result_bound_to_a_previous_hash_is_stale(tmp_path):
    case = load_case("D")
    scenario = build_scenario(tmp_path, "A")
    stale_payload = {
        "schema": "orbisprobe-evidence-pass-review-request-v1",
        "package_sha256sums_sha256": "f7ac4e1878a8890bfdcfabeae92fb268401cec2483fd0f05ad4b05ea7fefb5af",
        "state": "PASS",
    }

    outcome = evaluate_review_result(scenario.package, stale_payload)
    policy = review_failure_policy(outcome)

    assert outcome.state is ReviewState.STALE_REVIEW
    assert outcome.state.value == case["expect"]["review_state"]
    assert classify_delayed_result(manifest_sha256(scenario.package), stale_payload) is ResultFreshness.STALE_RESULT
    assert policy["stop"] is True and policy["auto_remediation"] is False
    assert "REMEDIATION_PASS" in policy["requires"]


def test_case_e_untraceable_claim_requires_changes(tmp_path):
    case = load_case("E")
    scenario = build_scenario(tmp_path, "A")
    mutated = copy_package(scenario, tmp_path / "mutated")
    (mutated / "claims.json").write_text(
        canonical_json({"claims": case["injected_claims"]}), encoding="utf-8"
    )
    rewrite_manifest(mutated)

    result = verify_package(str(mutated))

    assert result["status"] == case["expect"]["verifier"] == "CHANGES_REQUIRED"
    check = _check(result, case["expect"]["check"])
    assert check["status"] == "FAIL"
    assert any("untraceable claim" in problem for problem in check["details"]["problems"])


def test_case_f_copy_direction_label_must_match_the_pinned_bytes(tmp_path):
    case = load_case("F")
    inverted = build_scenario(tmp_path / "inverted", "F", label=PRE_F3_LABEL)

    inverted_result = verify(inverted)

    assert inverted_result["status"] == case["expect"]["verifier"] == "CHANGES_REQUIRED"
    check = _check(inverted_result, case["expect"]["check"])
    assert check["status"] == "FAIL"
    assert any("contradicts the pinned bytes" in problem for problem in check["details"]["problems"])
    assert case["pre_f3_label"] in json.dumps(check["details"])

    corrected = build_scenario(tmp_path / "corrected", "F", label=CORRECT_LABEL)
    corrected_result = verify(corrected)
    assert corrected_result["status"] == "PASS"
    assert _check(corrected_result, "copy_direction_claims")["details"]["copies_checked"] == 1

    # Inverting the field-name table together with the label must still be rejected: the
    # operand roles come from the pinned bytes, not from the author's naming.
    swapped = build_scenario(tmp_path / "swapped", "F", label=PRE_F3_LABEL, swap_field_names=True)
    swapped_result = verify(swapped)
    assert swapped_result["status"] == "CHANGES_REQUIRED"
    swapped_check = _check(swapped_result, case["expect"]["check"])
    assert swapped_check["status"] == "FAIL"
    assert any("operand role" in problem for problem in swapped_check["details"]["problems"])


def test_case_g_remediation_requires_a_new_freeze_and_stays_in_scope(tmp_path):
    case = load_case("G")
    scenario = build_scenario(tmp_path, "A")
    previous_hash = manifest_sha256(scenario.package)

    current = copy_package(scenario, tmp_path / "current")
    payload = json.loads((current / "action-plan.json").read_text(encoding="utf-8"))
    payload["plan_id"] = payload["plan_id"] + "-remediated"
    (current / "action-plan.json").write_text(canonical_json(payload), encoding="utf-8")
    rewrite_manifest(current)

    report = plan_remediation(
        request=RemediationRequest(
            previous_package=str(scenario.package),
            previous_package_sha256sums_sha256=previous_hash,
            findings=("F3: initiation copy direction labelled inverted",),
            allowed_paths=tuple(case["allowed_paths"]),
        ),
        current_package=current,
    )

    assert report["status"] == case["expect"]["status"]
    assert report["changed"] == ["action-plan.json"]
    assert report["out_of_scope"] == []
    assert report["current_sha256sums_sha256"] != previous_hash
    assert report["previous_package_preserved"] is True
    assert report["requires_review_of"] == manifest_sha256(current)
    assert report["auto_remediation"] is False
    assert manifest_sha256(scenario.package) == previous_hash

    out_of_scope = copy_package(scenario, tmp_path / "out-of-scope")
    leads = json.loads((out_of_scope / "leads-final.json").read_text(encoding="utf-8"))
    leads["count"] = leads["count"] + 1
    (out_of_scope / "leads-final.json").write_text(canonical_json(leads), encoding="utf-8")
    rewrite_manifest(out_of_scope)

    blocked = plan_remediation(
        request=RemediationRequest(
            previous_package=str(scenario.package),
            previous_package_sha256sums_sha256=previous_hash,
            findings=("out of scope edit",),
            allowed_paths=("action-plan.json",),
        ),
        current_package=out_of_scope,
    )
    assert blocked["status"] == "CHANGES_REQUIRED"
    assert blocked["out_of_scope"] == [case["out_of_scope_paths"][0]]


def test_case_h_symlink_overlap_and_alias_attacks_fail_closed(tmp_path):
    case = load_case("H")
    scenario = build_scenario(tmp_path, "A")
    source = scenario.plan.protected_sources[0]
    protected = capture_protected_sources([source])

    real = tmp_path / "real"
    real.mkdir()
    linked = tmp_path / "linked"
    linked.symlink_to(real)
    with pytest.raises(ValueError) as symlink_error:
        prepare_output_directory(linked, protected)
    assert "symlink" in str(symlink_error.value)

    with pytest.raises(ValueError) as overlap_error:
        prepare_output_directory(Path(source).parent, protected)
    assert "overlaps source evidence" in str(overlap_error.value)

    aliased_root = tmp_path / "alias-root"
    aliased_root.mkdir()
    aliased = aliased_root / "aliased.json"
    import os

    os.link(source, aliased)
    with pytest.raises(ValueError) as alias_error:
        safe_atomic_write_text(aliased, "{}\n", output_root=aliased_root, protected_sources=protected)
    assert "aliases source evidence" in str(alias_error.value)
    assert case["expect"]["errors"]


def test_case_i_unknown_safety_field_fails_closed(tmp_path):
    case = load_case("I")
    scenario = build_scenario(tmp_path, "A")
    payload = json.loads((scenario.inputs / "plan.json").read_text(encoding="utf-8"))

    payload["safety_policy"]["allow_destructive_actions"] = True
    from orbisprobe.evidence_pass.plan import ActionPlan

    with pytest.raises(ValueError) as policy_error:
        ActionPlan.from_dict(payload)
    assert case["expect"]["error"] in str(policy_error.value)

    payload["safety_policy"].pop("allow_destructive_actions")
    payload["unknown_top_level_field"] = 1
    with pytest.raises(ValueError) as plan_error:
        ActionPlan.from_dict(payload)
    assert case["expect"]["error"] in str(plan_error.value)


def test_case_j_interrupted_worker_is_unknown_never_success(tmp_path):
    case = load_case("J")
    scenario = build_scenario(tmp_path, "A")
    journal = ActionJournal.from_plan(scenario.plan)

    def interrupted(action, context):
        raise KeyboardInterrupt("gateway interruption")

    with pytest.raises(KeyboardInterrupt):
        run_plan(scenario.plan, interrupted, journal)

    record = journal.record(ACTION_ID)
    assert record.status is ActionStatus.UNKNOWN_UNVERIFIED
    assert record.outcome is None
    assert record.status.value == case["expect"]["status"]
    # UNKNOWN_UNVERIFIED is a terminal state, not an open one.
    assert record.terminal is case["expect"]["terminal"] is True

    started = ActionJournal.from_dict(
        {"records": [{"action_id": ACTION_ID, "lead_id": LEAD_ID, "status": "STARTED", "attempts": 1}]}
    )
    assert started.recover_interrupted() == (ACTION_ID,)
    assert started.record(ACTION_ID).status is ActionStatus.UNKNOWN_UNVERIFIED
    assert started.record(ACTION_ID).status.value == case["expect"]["recovered_in_flight"]
    assert started.record(ACTION_ID).outcome is None

    def succeed(action, context):
        return ActionExecution(
            result=ActionResult.RESOLVED_SAFE,
            disposition=LeadDisposition.SAFE_CLOSED,
            evidence=("evidence/pinned-slice.json",),
        )

    retry = started.request_retry(ACTION_ID, justification="explicit retry after recovery")
    assert retry.status is ActionStatus.NOT_STARTED
    run_plan(scenario.plan, succeed, started)
    assert started.record(ACTION_ID).attempts == case["expect"]["retry_attempts"]


def test_review_bundle_binds_the_exact_package_hash(tmp_path):
    scenario = build_scenario(tmp_path, "A")

    request = build_review_bundle(scenario.package, mode=ReviewMode.ADVERSARIAL, reviewer="fresh-independent")

    assert request["package_sha256sums_sha256"] == manifest_sha256(scenario.package)
    assert request["review_mode"] == ReviewMode.ADVERSARIAL.value
    assert (scenario.package / "review" / "REVIEW-REQUEST.json").is_file()
    assert (scenario.package / "review" / "REVIEW-INSTRUCTIONS.md").is_file()
    assert any("counterexample" in question for question in request["questions"])
    assert "no automatic remediation after CHANGES_REQUIRED" in request["prohibited"]
    assert (
        evaluate_review_result(
            scenario.package,
            {
                "schema": "orbisprobe-evidence-pass-review-request-v1",
                "package_sha256sums_sha256": request["package_sha256sums_sha256"],
            },
        ).state
        is ReviewState.UNKNOWN_UNVERIFIED
    )
    assert manifest_status(scenario.package) == "MANIFEST_OK"


def test_exact_once_completed_actions_are_never_rerun(tmp_path):
    scenario = build_scenario(tmp_path, "A")
    journal = ActionJournal.from_plan(scenario.plan)
    calls: list[str] = []

    def executor(action, context):
        calls.append(action.action_id)
        raise ActionFailure("declared failure")

    first = run_plan(scenario.plan, executor, journal)
    assert first.executed == ()
    assert journal.record(ACTION_ID).status is ActionStatus.FAILED

    completed = ActionJournal.from_plan(scenario.plan)

    def succeed(action, context):
        return ActionExecution(
            result=ActionResult.RESOLVED_SAFE,
            disposition=LeadDisposition.SAFE_CLOSED,
            evidence=("evidence/pinned-slice.json",),
        )

    run_plan(scenario.plan, succeed, completed)
    assert completed.record(ACTION_ID).status is ActionStatus.COMPLETED

    with pytest.raises(ExactOnceViolation):
        completed.start(ACTION_ID)
    with pytest.raises(ExactOnceViolation):
        completed.complete(
            ACTION_ID,
            __import__("orbisprobe.evidence_pass.model", fromlist=["ActionOutcome"]).ActionOutcome(
                action_id=ACTION_ID,
                lead_id=LEAD_ID,
                result=ActionResult.RESOLVED_SAFE,
                disposition=LeadDisposition.SAFE_CLOSED,
            ),
        )
    with pytest.raises(ExactOnceViolation):
        completed.request_retry(ACTION_ID, justification="should be refused")
    rerun = run_plan(scenario.plan, executor, completed)
    assert rerun.skipped_completed == (ACTION_ID,)
    assert calls == [ACTION_ID]


# ---------------------------------------------------------------------------
# Remediation regressions (review findings F1-F6 of the 20260925 review)
# ---------------------------------------------------------------------------


def test_rebuild_must_reproduce_the_full_package(tmp_path):
    """F1: a vacuous, partial or self-copying rebuild must never be reported as reproducible."""

    healthy = build_scenario(tmp_path / "healthy", "A")
    control = verify(healthy)
    rebuild = _check(control, "rebuild_determinism")
    assert rebuild["status"] == "PASS"
    assert rebuild["details"]["files_compared"] == rebuild["details"]["package_artifacts"] - 1
    assert rebuild["details"]["files_compared"] > 0

    noop = build_scenario(tmp_path / "noop", "A")
    set_rebuild_script(noop.package, NOOP_REBUILD_SCRIPT)
    noop_result = verify(noop)
    assert noop_result["status"] == "CHANGES_REQUIRED"
    assert _check(noop_result, "rebuild_determinism")["status"] == "FAIL"
    assert any(
        "vacuous" in problem
        for problem in _check(noop_result, "rebuild_determinism")["details"]["problems"]
    )

    partial = build_scenario(tmp_path / "partial", "A")
    set_rebuild_script(partial.package, PARTIAL_REBUILD_SCRIPT)
    partial_result = verify(partial)
    assert partial_result["status"] == "CHANGES_REQUIRED"
    partial_check = _check(partial_result, "rebuild_determinism")
    assert partial_check["status"] == "FAIL"
    assert partial_check["details"]["files_compared"] == 1
    assert any("not reproduced" in problem for problem in partial_check["details"]["problems"])

    reading = build_scenario(tmp_path / "reading", "A")
    set_rebuild_script(
        reading.package, PACKAGE_READING_REBUILD_SCRIPT.format(package=str(reading.package))
    )
    reading_result = verify(reading)
    assert reading_result["status"] == "CHANGES_REQUIRED"
    reading_check = _check(reading_result, "rebuild_determinism")
    assert reading_check["status"] == "FAIL"
    assert "package reads are denied" in reading_check["details"]["reason"]

    self_copy = build_scenario(tmp_path / "selfcopy", "A")
    set_rebuild_script(self_copy.package, SELF_COPY_REBUILD_SCRIPT)
    self_copy_result = verify(self_copy)
    assert self_copy_result["status"] == "CHANGES_REQUIRED"
    details = _check(self_copy_result, "rebuild_determinism")
    assert details["status"] == "FAIL"
    assert any(
        "not reproduced" in problem or "absent from the package" in problem
        for problem in details["details"]["problems"]
    )
    assert details["details"]["entrypoint_executed_from_scratch_copy"] is True

    # A package copy that embeds the package path absolutely must fail too: package reads are
    # denied while the rebuild runs, so the copy cannot succeed.
    absolute_copy = build_scenario(tmp_path / "abs-copy", "A")
    set_rebuild_script(
        absolute_copy.package,
        ABSOLUTE_PACKAGE_COPY_SCRIPT.format(package=str(absolute_copy.package)),
    )
    absolute_result = verify(absolute_copy)
    assert absolute_result["status"] == "CHANGES_REQUIRED"
    absolute_check = _check(absolute_result, "rebuild_determinism")
    assert absolute_check["status"] == "FAIL"
    assert "package reads are denied" in absolute_check["details"]["reason"]


def test_review_changes_required_stops_final_verification(tmp_path):
    """F2: only a hash-bound PASS may allow final verification."""

    scenario = build_scenario(tmp_path, "A")
    current = manifest_sha256(scenario.package)

    pass_annex = persist_review_result(
        scenario.package,
        {
            "schema": "orbisprobe-evidence-pass-review-request-v1",
            "package_sha256sums_sha256": current,
            "state": "PASS",
            "reviewer": "fixture",
        },
    )
    assert pass_annex.state is ReviewState.PASS
    assert (scenario.package / "review" / "REVIEW-RESULT.json").is_file()
    assert verify(scenario)["status"] == "PASS"

    changes = persist_review_result(
        scenario.package,
        {
            "schema": "orbisprobe-evidence-pass-review-request-v1",
            "package_sha256sums_sha256": current,
            "state": "CHANGES_REQUIRED",
            "findings": ["F3: initiation copy direction labelled inverted"],
        },
    )
    assert changes.state is ReviewState.CHANGES_REQUIRED

    blocked = verify(scenario)
    assert blocked["status"] == "CHANGES_REQUIRED"
    assert blocked["review_state"] == "CHANGES_REQUIRED"
    annex = _check(blocked, "review_annex_binding")
    assert annex["status"] == "FAIL"
    assert "not PASS" in annex["details"]["problems"][0]
    policy = _check(blocked, "review_failure_policy")
    assert policy["status"] == "FAIL"
    assert policy["details"]["stop"] is True
    assert policy["details"]["auto_remediation"] is False
    assert manifest_status(scenario.package) == "MANIFEST_OK"


def test_review_record_persists_the_verdict(tmp_path):
    """F2: the verdict must survive in the package annex, so it can stop the next verify."""

    scenario = build_scenario(tmp_path, "A")
    current = manifest_sha256(scenario.package)
    verdict = tmp_path / "verdict.json"
    verdict.write_text(
        canonical_json(
            {
                "schema": "orbisprobe-evidence-pass-review-request-v1",
                "package_sha256sums_sha256": current,
                "state": "CHANGES_REQUIRED",
                "findings": ["F1: rebuild determinism was vacuous"],
            }
        ),
        encoding="utf-8",
    )

    code, payload = run_cli("evidence-pass", "review-record", "--package", str(scenario.package), "--result", str(verdict))
    assert code == 2
    assert payload["state"] == "CHANGES_REQUIRED"
    annex = json.loads((scenario.package / "review" / "REVIEW-RESULT.json").read_text(encoding="utf-8"))
    assert annex["state"] == "CHANGES_REQUIRED"
    assert annex["findings"] == ["F1: rebuild determinism was vacuous"]

    code, blocked = run_cli("evidence-pass", "verify", "--package", str(scenario.package))
    assert code == 2
    assert blocked["status"] == "CHANGES_REQUIRED"


def test_runtime_policy_is_enforced_not_just_serialized(tmp_path):
    """F3: runtime_actions_allowed must constrain plans and be re-checked by the verifier."""

    scenario = build_scenario(tmp_path, "A")
    payload = json.loads((scenario.inputs / "plan.json").read_text(encoding="utf-8"))
    payload["safety_policy"]["allowed_risks"] = ["offline", "read_only", "active_request"]
    payload["actions"][0]["risk"] = "active_request"
    with pytest.raises(ValueError, match="runtime"):
        ActionPlan.from_dict(payload)

    payload["safety_policy"]["runtime_actions_allowed"] = True
    allowed = ActionPlan.from_dict(payload)
    assert allowed.safety_policy.runtime_actions_allowed is True
    assert allowed.safety_policy.allows(allowed.actions[0]) == ()

    # A package whose *policy* forbids the runtime work its actions declare must be rejected
    # at the contract boundary, and verification must return a canonical failure (no traceback).
    tampered = copy_package(scenario, tmp_path / "tampered")
    plan_payload = json.loads((tampered / "action-plan.json").read_text(encoding="utf-8"))
    plan_payload["safety_policy"]["allowed_risks"] = ["offline", "read_only", "active_request"]
    plan_payload["actions"][0]["risk"] = "active_request"
    (tampered / "action-plan.json").write_text(canonical_json(plan_payload), encoding="utf-8")
    rewrite_manifest(tampered)

    result = verify_package(str(tampered), rebuild=False)
    assert result["status"] == "CHANGES_REQUIRED"
    readable = _check(result, "package_readable")
    assert readable["status"] == "FAIL"
    assert "runtime" in readable["details"]["error"]

    code, cli_payload = run_cli("evidence-pass", "verify", "--package", str(tampered), "--no-rebuild")
    assert code == 2
    assert cli_payload["status"] == "CHANGES_REQUIRED"


def test_closure_requires_explaining_evidence(tmp_path):
    """F6: an unchanged action must not carry a lead into a terminal state."""

    scenario = build_scenario(
        tmp_path,
        "F6",
        result_kind="EDGE_UNCHANGED",
        disposition="PARKED",
        lead_after_edge=EdgeDistance.EDGE_0,
    )

    result = verify(scenario)

    assert result["status"] == "CHANGES_REQUIRED"
    separation = _check(result, "result_disposition_separation")
    assert separation["status"] == "FAIL"
    assert any("not explained" in problem for problem in separation["details"]["problems"])


def test_bad_inputs_yield_closed_results_and_exit_codes(tmp_path):
    """F4: expected bad input must produce canonical fail-closed results, never a traceback."""

    scenario = build_scenario(tmp_path, "A")

    # missing lead in leads-final.json
    missing = copy_package(scenario, tmp_path / "missing-lead")
    store = json.loads((missing / "leads-final.json").read_text(encoding="utf-8"))
    kept = [lead for lead in store["leads"] if lead["lead_id"] != LEAD_ID]
    store["leads"] = kept
    store["count"] = len(kept)
    (missing / "leads-final.json").write_text(canonical_json(store), encoding="utf-8")
    rewrite_manifest(missing)
    code, payload = run_cli("evidence-pass", "verify", "--package", str(missing))
    assert code == 2
    assert payload["status"] == "CHANGES_REQUIRED"
    separation = _check(payload, "result_disposition_separation")
    assert any("absent from leads-final.json" in problem for problem in separation["details"]["problems"])
    assert "Traceback" not in payload.get("raw_stderr", "")

    # stale remediation request
    request = tmp_path / "remediation.json"
    request.write_text(
        canonical_json(
            {
                "previous_package": str(scenario.package),
                "previous_package_sha256sums_sha256": "0" * 64,
                "findings": ["F1"],
                "allowed_paths": ["action-plan.json"],
            }
        ),
        encoding="utf-8",
    )
    code, payload = run_cli("evidence-pass", "remediate", "--request", str(request), "--current", str(scenario.package))
    assert code == 4
    assert payload["status"] == "STALE_REVIEW"

    # review bundle for an incomplete package
    broken = copy_package(scenario, tmp_path / "incomplete")
    (broken / "evidence" / "pinned-slice.json").unlink()
    code, payload = run_cli("evidence-pass", "review-plan", "--package", str(broken))
    assert code == 2
    assert payload["status"] == "CHANGES_REQUIRED"

    # invalid plan
    bad_plan = tmp_path / "bad-plan.json"
    bad_plan.write_text(
        canonical_json({"plan_id": "bad", "unknown_safety_field": True}), encoding="utf-8"
    )
    code, payload = run_cli(
        "evidence-pass",
        "build",
        "--plan",
        str(bad_plan),
        "--results",
        str(scenario.inputs / "results.json"),
        "--out",
        str(tmp_path / "never-built"),
    )
    assert code == 2
    assert payload["status"] == "CHANGES_REQUIRED"
    assert "unknown fields" in payload["error"]


def test_case_f_generated_artifacts_are_path_independent(tmp_path):
    """F7: the fixture must not depend on historical absolute hashes or on the build path."""

    case = load_case("F")
    first = build_scenario(tmp_path / "one", "F")
    second = build_scenario(tmp_path / "two", "F")
    # The contract, the source manifest and the rebuild entry point legitimately carry absolute
    # paths; every content-derived artifact must be path independent.
    path_carrying = {"action-plan.json", "source-manifest.json", "rebuild-pass.py"}

    def stable(package: Path) -> dict[str, str]:
        return {
            relative: digest
            for relative, digest in package_tree(package).items()
            if relative not in path_carrying
        }

    stable_first, stable_second = stable(first.package), stable(second.package)
    assert stable_first and stable_first == stable_second
    assert len(stable_first) >= 8
    assert "history" in case and "never asserted" in case["history"]["note"]
    assert case["history"]["pre_f3_package_sha256sums_sha256"] != case["history"][
        "corrected_package_sha256sums_sha256"
    ]
