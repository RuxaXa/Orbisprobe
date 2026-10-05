"""Reusable, exact-once evidence-pass workflow (build -> verify -> review -> remediate).

The module standardises the sequence proven by the OrbisProbe evidence campaign:

    EvidenceAction specification -> exact-once execution -> deterministic builder ->
    isolated rebuilds -> source immutability -> manifest -> external verifier ->
    exact package hash -> independent exact-hash review -> frozen result

It is tooling only: no discovery, no live target access, and it never weakens the
existing OrbisProbe gates (``orbisprobe.leads.gates`` and the hard safety policy).
"""

from .builder import BuildResult, build_pass
from .journal import ActionJournal, ActionRecord, ExactOnceViolation
from .manifest import ManifestReport, manifest_sha256, verify_manifest
from .metrics import compute_metrics, lead_diff, portfolio_snapshot
from .model import (
    DISPOSITION_SAFE_CLOSING_RESULTS,
    TERMINAL_STATUSES,
    ActionOutcome,
    ActionResult,
    ActionStatus,
    ClaimTrace,
    EvidenceReference,
    LeadDisposition,
    Metrics,
    ResultFreshness,
    ReviewMode,
    ReviewState,
    canonical_json,
    sha256_file,
)
from .plan import ActionAssignment, ActionPlan, SafetyPolicy, SharedEvidence
from .remediation import RemediationRequest, plan_remediation
from .review import (
    ADVERSARIAL_TARGETS,
    ReviewOutcome,
    build_review_bundle,
    classify_delayed_result,
    evaluate_review_result,
    review_failure_policy,
    review_questions,
)
from .runner import (
    ActionContext,
    ActionExecution,
    ActionFailure,
    RunReport,
    propagate_shared_evidence,
    run_plan,
)
from .verify import verify_package

__all__ = [
    "ADVERSARIAL_TARGETS",
    "DISPOSITION_SAFE_CLOSING_RESULTS",
    "TERMINAL_STATUSES",
    "ActionAssignment",
    "ActionContext",
    "ActionExecution",
    "ActionFailure",
    "ActionJournal",
    "ActionOutcome",
    "ActionPlan",
    "ActionRecord",
    "ActionResult",
    "ActionStatus",
    "BuildResult",
    "ClaimTrace",
    "EvidenceReference",
    "ExactOnceViolation",
    "LeadDisposition",
    "ManifestReport",
    "Metrics",
    "RemediationRequest",
    "ResultFreshness",
    "ReviewMode",
    "ReviewOutcome",
    "ReviewState",
    "RunReport",
    "SafetyPolicy",
    "SharedEvidence",
    "build_pass",
    "build_review_bundle",
    "canonical_json",
    "classify_delayed_result",
    "compute_metrics",
    "evaluate_review_result",
    "lead_diff",
    "manifest_sha256",
    "plan_remediation",
    "portfolio_snapshot",
    "propagate_shared_evidence",
    "review_failure_policy",
    "review_questions",
    "run_plan",
    "sha256_file",
    "verify_manifest",
    "verify_package",
]
