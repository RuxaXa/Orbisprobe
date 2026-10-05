from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from orbisprobe.leads.gates import evaluate_action_gate
from orbisprobe.leads.model import ActionKind, EvidenceAction, OperationMode

from .model import (
    ReviewMode,
    closed_schema,
    require_bool,
    require_hex_digest,
    require_int,
    require_text,
    require_tuple,
)

ALLOWED_REVIEW_MODES = tuple(mode.value for mode in ReviewMode)
OFFLINE_RISKS = ("offline", "read_only")
# Risks that require touching a live target / runtime state; they need runtime_actions_allowed.
RUNTIME_RISKS = ("volatile_user", "volatile_shared", "reversible_kernel_ram", "active_request", "persistent")


@dataclass(frozen=True)
class SafetyPolicy:
    """Policy gate for a pass. Unknown or weakened fields fail closed."""

    allowed_operation_mode: str
    allowed_risks: tuple[str, ...]
    runtime_actions_allowed: bool = False
    proof_actions_allowed: bool = False
    destructive_actions_allowed: bool = False
    allow_source_overlap: bool = False

    def __post_init__(self) -> None:
        if self.allowed_operation_mode not in tuple(mode.value for mode in OperationMode):
            raise ValueError(f"unknown allowed_operation_mode: {self.allowed_operation_mode}")
        if not self.allowed_risks:
            raise ValueError("allowed_risks must not be empty")
        for name, value in (
            ("runtime_actions_allowed", self.runtime_actions_allowed),
            ("proof_actions_allowed", self.proof_actions_allowed),
            ("destructive_actions_allowed", self.destructive_actions_allowed),
            ("allow_source_overlap", self.allow_source_overlap),
        ):
            require_bool(f"SafetyPolicy.{name}", value)
        if self.allow_source_overlap:
            raise ValueError("allow_source_overlap must stay false: output/source overlap is forbidden")
        if self.destructive_actions_allowed:
            raise ValueError("destructive_actions_allowed must stay false: hard safety policy is not weakenable")

    def allows(self, action: EvidenceAction) -> tuple[str, ...]:
        """Reasons the policy refuses an action; empty tuple means allowed."""

        reasons: list[str] = []
        if action.risk.value not in self.allowed_risks:
            reasons.append(f"risk {action.risk.value} is not in the allowed set")
        if action.risk.value in RUNTIME_RISKS and not self.runtime_actions_allowed:
            reasons.append(
                f"runtime risk {action.risk.value} requires runtime_actions_allowed=true"
            )
        if action.kind is ActionKind.EXPLOIT_TEST and not self.proof_actions_allowed:
            reasons.append("proof/exploit actions are not allowed by this policy")
        if self.allowed_operation_mode == OperationMode.DISCOVERY_MODE.value and action.kind is ActionKind.EXPLOIT_TEST:
            reasons.append("DISCOVERY_MODE forbids EXPLOIT_TEST actions")
        return tuple(reasons)

    def to_dict(self) -> dict[str, Any]:
        return {
            "allowed_operation_mode": self.allowed_operation_mode,
            "allowed_risks": list(self.allowed_risks),
            "runtime_actions_allowed": self.runtime_actions_allowed,
            "proof_actions_allowed": self.proof_actions_allowed,
            "destructive_actions_allowed": self.destructive_actions_allowed,
            "allow_source_overlap": self.allow_source_overlap,
        }

    @classmethod
    def from_dict(cls, value: object) -> SafetyPolicy:
        data = closed_schema(
            "SafetyPolicy",
            value,
            {"allowed_operation_mode", "allowed_risks"},
            {
                "runtime_actions_allowed",
                "proof_actions_allowed",
                "destructive_actions_allowed",
                "allow_source_overlap",
            },
        )
        return cls(
            allowed_operation_mode=data["allowed_operation_mode"],
            allowed_risks=require_tuple("SafetyPolicy.allowed_risks", data["allowed_risks"]),
            runtime_actions_allowed=data.get("runtime_actions_allowed", False),
            proof_actions_allowed=data.get("proof_actions_allowed", False),
            destructive_actions_allowed=data.get("destructive_actions_allowed", False),
            allow_source_overlap=data.get("allow_source_overlap", False),
        )


@dataclass(frozen=True)
class ActionAssignment:
    """Binds one EvidenceAction to exactly one lead (a lead may own several actions)."""

    lead_id: str
    action_id: str

    def __post_init__(self) -> None:
        require_text("ActionAssignment.lead_id", self.lead_id)
        require_text("ActionAssignment.action_id", self.action_id)

    def to_dict(self) -> dict[str, str]:
        return {"lead_id": self.lead_id, "action_id": self.action_id}

    @classmethod
    def from_dict(cls, value: object) -> ActionAssignment:
        data = closed_schema("ActionAssignment", value, {"lead_id", "action_id"})
        return cls(lead_id=data["lead_id"], action_id=data["action_id"])


@dataclass(frozen=True)
class SharedEvidence:
    """One EvidenceAction whose evidence is propagated to further leads without re-execution."""

    source_action_id: str
    recipients: tuple[str, ...]
    edges_changed: tuple[str, ...]

    def __post_init__(self) -> None:
        require_text("SharedEvidence.source_action_id", self.source_action_id)
        object.__setattr__(self, "recipients", require_tuple("SharedEvidence.recipients", self.recipients))
        object.__setattr__(self, "edges_changed", require_tuple("SharedEvidence.edges_changed", self.edges_changed))
        if not self.recipients:
            raise ValueError("shared evidence requires at least one recipient lead")
        if self.source_action_id in self.recipients:
            raise ValueError("shared evidence source must not be its own recipient")

    def to_dict(self) -> dict[str, Any]:
        return {
            "source_action_id": self.source_action_id,
            "recipients": list(self.recipients),
            "edges_changed": list(self.edges_changed),
        }

    @classmethod
    def from_dict(cls, value: object) -> SharedEvidence:
        data = closed_schema(
            "SharedEvidence", value, {"source_action_id", "recipients", "edges_changed"}
        )
        return cls(
            source_action_id=data["source_action_id"],
            recipients=tuple(data["recipients"]),
            edges_changed=tuple(data["edges_changed"]),
        )


@dataclass(frozen=True)
class ActionPlan:
    """Versioned input contract for one evidence pass."""

    plan_id: str
    lead_ids: tuple[str, ...]
    action_ids: tuple[str, ...]
    assignments: tuple[ActionAssignment, ...]
    baseline_package: str
    baseline_sha256sums_sha256: str
    expected_action_count: int
    protected_sources: tuple[str, ...]
    output_dir: str
    safety_policy: SafetyPolicy
    review_mode: ReviewMode
    actions: tuple[EvidenceAction, ...]
    shared_evidence: tuple[SharedEvidence, ...] = ()
    adversarial_review: bool = False
    expected_unchanged_leads: tuple[str, ...] = ()
    expected_portfolio: tuple[tuple[str, int], ...] = ()

    def __post_init__(self) -> None:
        require_text("ActionPlan.plan_id", self.plan_id)
        object.__setattr__(self, "lead_ids", require_tuple("ActionPlan.lead_ids", self.lead_ids))
        object.__setattr__(self, "action_ids", require_tuple("ActionPlan.action_ids", self.action_ids))
        require_text("ActionPlan.baseline_package", self.baseline_package)
        require_hex_digest("ActionPlan.baseline_sha256sums_sha256", self.baseline_sha256sums_sha256)
        require_int("ActionPlan.expected_action_count", self.expected_action_count, minimum=1)
        object.__setattr__(
            self, "protected_sources", require_tuple("ActionPlan.protected_sources", self.protected_sources)
        )
        if not self.protected_sources:
            raise ValueError("a pass requires at least one protected source")
        require_text("ActionPlan.output_dir", self.output_dir)
        if not isinstance(self.safety_policy, SafetyPolicy):
            raise TypeError("ActionPlan.safety_policy must be a SafetyPolicy")
        if not isinstance(self.review_mode, ReviewMode):
            raise TypeError("ActionPlan.review_mode must be a ReviewMode")
        require_bool("ActionPlan.adversarial_review", self.adversarial_review)
        object.__setattr__(
            self,
            "expected_unchanged_leads",
            require_tuple("ActionPlan.expected_unchanged_leads", self.expected_unchanged_leads),
        )
        if not isinstance(self.actions, tuple) or any(
            not isinstance(item, EvidenceAction) for item in self.actions
        ):
            raise TypeError("ActionPlan.actions must be a tuple of EvidenceAction")
        declared = {item.action_id for item in self.actions}
        if len(declared) != len(self.actions):
            raise ValueError("action IDs must be unique")
        if declared != set(self.action_ids):
            raise ValueError("action_ids must match the declared actions exactly")
        if len(self.actions) != self.expected_action_count:
            raise ValueError(
                f"expected_action_count {self.expected_action_count} does not match {len(self.actions)} actions"
            )
        assigned = {item.action_id for item in self.assignments}
        if assigned != declared:
            raise ValueError("every action must be assigned to exactly one lead")
        assigned_leads = {item.lead_id for item in self.assignments}
        # Declared leads may include shared-evidence recipients that own no action themselves.
        if not assigned_leads <= set(self.lead_ids):
            raise ValueError("assignments must reference declared leads only")
        if len(self.assignments) != len(self.actions):
            raise ValueError("each action must have exactly one assignment")
        for shared in self.shared_evidence:
            if shared.source_action_id not in declared:
                raise ValueError(f"shared evidence source is not a declared action: {shared.source_action_id}")
        for action in self.actions:
            decision = evaluate_action_gate(action)
            if not decision.allowed:
                raise ValueError(
                    f"action {action.action_id} is blocked by {decision.gate}: {', '.join(decision.blocks)}"
                )
            reasons = self.safety_policy.allows(action)
            if reasons:
                raise ValueError(f"action {action.action_id} violates the pass safety policy: {', '.join(reasons)}")

    def action(self, action_id: str) -> EvidenceAction:
        for item in self.actions:
            if item.action_id == action_id:
                return item
        raise KeyError(action_id)

    def lead_for_action(self, action_id: str) -> str:
        for item in self.assignments:
            if item.action_id == action_id:
                return item.lead_id
        raise KeyError(action_id)

    def actions_for_lead(self, lead_id: str) -> tuple[str, ...]:
        return tuple(sorted(item.action_id for item in self.assignments if item.lead_id == lead_id))

    def shared_recipients(self, action_id: str) -> tuple[str, ...]:
        recipients: list[str] = []
        for shared in self.shared_evidence:
            if shared.source_action_id == action_id:
                recipients.extend(shared.recipients)
        return tuple(sorted(set(recipients)))

    def shared_action_ids(self) -> tuple[str, ...]:
        return tuple(sorted({item.source_action_id for item in self.shared_evidence}))

    def to_dict(self) -> dict[str, Any]:
        return {
            "plan_id": self.plan_id,
            "lead_ids": list(self.lead_ids),
            "action_ids": list(self.action_ids),
            "assignments": [item.to_dict() for item in self.assignments],
            "baseline_package": self.baseline_package,
            "baseline_sha256sums_sha256": self.baseline_sha256sums_sha256,
            "expected_action_count": self.expected_action_count,
            "protected_sources": list(self.protected_sources),
            "output_dir": self.output_dir,
            "safety_policy": self.safety_policy.to_dict(),
            "review_mode": self.review_mode.value,
            "actions": [item.to_dict() for item in self.actions],
            "shared_evidence": [item.to_dict() for item in self.shared_evidence],
            "adversarial_review": self.adversarial_review,
            "expected_unchanged_leads": list(self.expected_unchanged_leads),
            "expected_portfolio": [[key, value] for key, value in self.expected_portfolio],
        }

    @classmethod
    def from_dict(cls, value: object) -> ActionPlan:
        data = closed_schema(
            "ActionPlan",
            value,
            {
                "plan_id",
                "lead_ids",
                "action_ids",
                "assignments",
                "baseline_package",
                "baseline_sha256sums_sha256",
                "expected_action_count",
                "protected_sources",
                "output_dir",
                "safety_policy",
                "review_mode",
                "actions",
            },
            {"shared_evidence", "adversarial_review", "expected_unchanged_leads", "expected_portfolio"},
        )
        mode = require_text("ActionPlan.review_mode", data["review_mode"])
        if mode not in ALLOWED_REVIEW_MODES:
            raise ValueError(f"unknown review_mode: {mode}")
        portfolio: list[tuple[str, int]] = []
        for entry in data.get("expected_portfolio", []):
            if not isinstance(entry, (list, tuple)) or len(entry) != 2:
                raise TypeError("expected_portfolio entries must be [name, value] pairs")
            name = require_text("expected_portfolio name", entry[0])
            portfolio.append((name, require_int(f"expected_portfolio.{name}", entry[1])))
        assignments_value = data["assignments"]
        actions_value = data["actions"]
        if not isinstance(assignments_value, list) or not isinstance(actions_value, list):
            raise TypeError("ActionPlan.assignments and ActionPlan.actions must be lists")
        return cls(
            plan_id=data["plan_id"],
            lead_ids=tuple(data["lead_ids"]),
            action_ids=tuple(data["action_ids"]),
            assignments=tuple(ActionAssignment.from_dict(item) for item in assignments_value),
            baseline_package=data["baseline_package"],
            baseline_sha256sums_sha256=data["baseline_sha256sums_sha256"],
            expected_action_count=data["expected_action_count"],
            protected_sources=tuple(data["protected_sources"]),
            output_dir=data["output_dir"],
            safety_policy=SafetyPolicy.from_dict(data["safety_policy"]),
            review_mode=ReviewMode(mode),
            actions=tuple(EvidenceAction.from_dict(item) for item in actions_value),
            shared_evidence=tuple(
                SharedEvidence.from_dict(item) for item in data.get("shared_evidence", [])
            ),
            adversarial_review=data.get("adversarial_review", False),
            expected_unchanged_leads=tuple(data.get("expected_unchanged_leads", [])),
            expected_portfolio=tuple(portfolio),
        )

    @classmethod
    def load(cls, path: str | Path) -> ActionPlan:
        try:
            value = json.loads(Path(path).read_text(encoding="utf-8"))
        except UnicodeDecodeError as exc:
            raise ValueError("plan must be valid UTF-8") from exc
        return cls.from_dict(value)
