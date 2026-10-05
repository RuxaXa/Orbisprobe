from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from orbisprobe.leads.safe_io import safe_atomic_write_text

from .manifest import manifest_sha256, verify_manifest
from .model import (
    PACKAGE_REVIEW_INSTRUCTIONS,
    PACKAGE_REVIEW_REQUEST,
    PACKAGE_REVIEW_RESULT,
    ResultFreshness,
    ReviewMode,
    ReviewState,
    canonical_json,
    closed_schema,
    require_hex_digest,
    require_text,
)

ADVERSARIAL_TARGETS: tuple[str, ...] = (
    "alternative caller: find another dispatcher that reaches the same site with a different argument role",
    "alternate object identity: show the object can be keyed by a second identity and rebound",
    "hidden writer: show a further site writes the same field/buffer without the recorded length",
    "source/destination inversion: derive each copy direction from the pinned bytes and look for an inverted label",
    "lifecycle exception: show a free/reallocate path that lets a longer length meet a smaller allocation",
    "counterexample request pair: state the exact pair (LA, LB) that would falsify the invariant and where it would occur",
)

STANDARD_QUESTIONS: tuple[str, ...] = (
    "does every decisive claim resolve to a frozen artifact with a matching hash?",
    "do the recorded action results and lead dispositions stay separated (no promotion from RESOLVED_SAFE to closure)?",
    "is the frozen set byte-identical to its manifest and unchanged by the verification run?",
)

REQUIRED_STATES: tuple[str, ...] = tuple(state.value for state in ReviewState)


@dataclass(frozen=True)
class ReviewOutcome:
    state: ReviewState
    reason: str
    findings: tuple[str, ...] = ()
    package_sha256sums_sha256: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "state": self.state.value,
            "reason": self.reason,
            "findings": list(self.findings),
            "package_sha256sums_sha256": self.package_sha256sums_sha256,
        }


def review_questions(mode: ReviewMode) -> tuple[str, ...]:
    if mode is ReviewMode.ADVERSARIAL:
        return STANDARD_QUESTIONS + ADVERSARIAL_TARGETS
    return STANDARD_QUESTIONS


def persist_review_result(package_dir: str | Path, payload: object) -> ReviewOutcome:
    """Freeze the reviewer's verdict into the package annex, then bind it to the package hash.

    Persisting is what makes a failed review actually stop the pass: without the annex the
    verdict is invisible to later verification runs.
    """

    root = Path(package_dir).resolve()
    data = closed_schema(
        "ReviewResult",
        payload,
        {"schema", "package_sha256sums_sha256", "state"},
        {"findings", "notes", "reviewer", "review_mode"},
    )
    target = root / PACKAGE_REVIEW_RESULT
    target.parent.mkdir(parents=True, exist_ok=True)
    safe_atomic_write_text(target, canonical_json(data), output_root=root, protected_sources=())
    return evaluate_review_result(root, data)


def build_review_bundle(
    package_dir: str | Path,
    *,
    mode: ReviewMode | None = None,
    reviewer: str = "independent",
) -> dict[str, Any]:
    """Emit the exact-hash review request; never executes a reviewer."""

    root = Path(package_dir).resolve()
    report = verify_manifest(root, strict=True)
    if not report.ok:
        raise ValueError(f"cannot build a review bundle for an incomplete package: {report.status}")
    package_hash = manifest_sha256(root)
    resolved_mode = mode or ReviewMode.STANDARD
    request = {
        "schema": "orbisprobe-evidence-pass-review-request-v1",
        "package": str(root),
        "package_sha256sums_sha256": package_hash,
        "review_mode": resolved_mode.value,
        "reviewer": require_text("reviewer", reviewer),
        "required_states": list(REQUIRED_STATES),
        "questions": list(review_questions(resolved_mode)),
        "prohibited": [
            "no automatic remediation after CHANGES_REQUIRED",
            "no acceptance of a result bound to another package hash",
            "no implicit success when a verdict is missing",
        ],
        "result_file": str(Path(PACKAGE_REVIEW_RESULT)),
    }
    request_path = root / PACKAGE_REVIEW_REQUEST
    request_path.parent.mkdir(parents=True, exist_ok=True)
    safe_atomic_write_text(request_path, canonical_json(request), output_root=root, protected_sources=())
    instructions = [
        "# Evidence pass review",
        "",
        f"Package: {root}",
        f"Package SHA256SUMS sha256 (exact-hash binding): {package_hash}",
        f"Review mode: {resolved_mode.value}",
        "",
        "Return one state from: " + ", ".join(REQUIRED_STATES) + ".",
        "A missing verdict is UNKNOWN_UNVERIFIED, never success.",
        "A result bound to a different package hash is STALE_REVIEW.",
        "",
        "## Questions",
        "",
    ]
    instructions += [f"- {question}" for question in review_questions(resolved_mode)]
    instructions += [
        "",
        "## Rules",
        "",
        "- CHANGES_REQUIRED stops the pass: no automatic remediation, a separate REMEDIATION_PASS is required.",
        "- Do not edit the package while reviewing.",
        "",
    ]
    safe_atomic_write_text(
        root / PACKAGE_REVIEW_INSTRUCTIONS,
        "\n".join(instructions),
        output_root=root,
        protected_sources=(),
    )
    return request


def evaluate_review_result(package_dir: str | Path, payload: object) -> ReviewOutcome:
    """Bind a review result to the exact current package hash and canonical states."""

    root = Path(package_dir).resolve()
    current = manifest_sha256(root)
    try:
        data = closed_schema(
            "ReviewResult",
            payload,
            {"schema", "package_sha256sums_sha256", "state"},
            {"findings", "notes", "reviewer", "review_mode"},
        )
    except (TypeError, ValueError) as exc:
        return ReviewOutcome(ReviewState.UNKNOWN_UNVERIFIED, f"unreadable review result: {exc}")

    reported = data["package_sha256sums_sha256"]
    try:
        require_hex_digest("ReviewResult.package_sha256sums_sha256", reported)
    except ValueError as exc:
        return ReviewOutcome(ReviewState.UNKNOWN_UNVERIFIED, str(exc))
    state_value = require_text("ReviewResult.state", data["state"])
    if state_value not in REQUIRED_STATES:
        return ReviewOutcome(
            ReviewState.UNKNOWN_UNVERIFIED, f"unknown review state: {state_value}", package_sha256sums_sha256=reported
        )
    findings = tuple(str(item) for item in data.get("findings", ()))

    if reported != current:
        return ReviewOutcome(
            ReviewState.STALE_REVIEW,
            f"review is bound to {reported}, current package is {current}",
            findings,
            reported,
        )
    if state_value == ReviewState.PASS.value and findings:
        return ReviewOutcome(
            ReviewState.UNKNOWN_UNVERIFIED,
            "PASS with material findings is ambiguous and is not treated as success",
            findings,
            reported,
        )
    if state_value == ReviewState.CHANGES_REQUIRED.value and not findings:
        return ReviewOutcome(
            ReviewState.UNKNOWN_UNVERIFIED,
            "CHANGES_REQUIRED without findings cannot be acted on",
            findings,
            reported,
        )
    return ReviewOutcome(ReviewState(state_value), "exact-hash bound verdict", findings, reported)


def review_failure_policy(outcome: ReviewOutcome) -> dict[str, Any]:
    """Review failure policy: a failed review stops the pass and never self-remediates."""

    return {
        "state": outcome.state.value,
        "stop": outcome.state is not ReviewState.PASS,
        "auto_remediation": False,
        "requires": None
        if outcome.state is ReviewState.PASS
        else "separate REMEDIATION_PASS with explicit allowed paths",
        "findings": list(outcome.findings),
    }


def classify_delayed_result(package_sha256sums_sha256: str, payload: object) -> ResultFreshness:
    """A delayed worker/verifier result that names an older package hash is stale."""

    if isinstance(payload, dict) and payload.get("package_sha256sums_sha256") == package_sha256sums_sha256:
        return ResultFreshness.CURRENT
    return ResultFreshness.STALE_RESULT


__all__ = [
    "ADVERSARIAL_TARGETS",
    "REQUIRED_STATES",
    "STANDARD_QUESTIONS",
    "ReviewOutcome",
    "build_review_bundle",
    "classify_delayed_result",
    "evaluate_review_result",
    "persist_review_result",
    "review_failure_policy",
    "review_questions",
]
