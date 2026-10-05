from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from orbisprobe.leads.model import EvidenceAction

from .journal import ActionJournal
from .model import ActionOutcome, ActionResult, LeadDisposition
from .plan import ActionPlan


class ActionFailure(RuntimeError):
    """A declared, clean failure: recorded as FAILED, never as success."""


@dataclass(frozen=True)
class ActionExecution:
    """Raw executor result before it is journalled."""

    result: ActionResult
    disposition: LeadDisposition
    evidence: tuple[str, ...] = ()
    notes: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.result, ActionResult) or not isinstance(self.disposition, LeadDisposition):
            raise TypeError("ActionExecution result/disposition must use the canonical enums")
        if not isinstance(self.evidence, tuple) or any(not isinstance(item, str) for item in self.evidence):
            raise TypeError("ActionExecution.evidence must be a tuple of strings")


@dataclass(frozen=True)
class ActionContext:
    """Read-only context handed to an executor."""

    plan_id: str
    action_index: int
    shared_recipients: tuple[str, ...]


Executor = Callable[[EvidenceAction, ActionContext], ActionExecution]


@dataclass(frozen=True)
class RunReport:
    journal: ActionJournal
    executed: tuple[str, ...]
    skipped_completed: tuple[str, ...]
    shared_records: tuple[dict[str, Any], ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "executed": list(self.executed),
            "skipped_completed": list(self.skipped_completed),
            "shared_records": [dict(item) for item in self.shared_records],
        }


def run_plan(plan: ActionPlan, executor: Executor, journal: ActionJournal | None = None) -> RunReport:
    """Execute the plan exactly once.

    ``COMPLETED`` actions are never rerun. A journal recovered from a crashed run has its
    in-flight entries marked ``UNKNOWN_UNVERIFIED`` first, so no earlier attempt can be
    mistaken for success. Any unexpected interruption of the current run is recorded as
    ``UNKNOWN_UNVERIFIED`` before the exception propagates.
    """

    active = journal if journal is not None else ActionJournal.from_plan(plan)
    active.recover_interrupted()
    executed: list[str] = []
    skipped: list[str] = []

    for index, assignment in enumerate(sorted(plan.assignments, key=lambda item: item.action_id)):
        action_id = assignment.action_id
        if active.record(action_id).status.value == "COMPLETED":
            skipped.append(action_id)
            continue
        action = plan.action(action_id)
        active.start(action_id)
        context = ActionContext(
            plan_id=plan.plan_id,
            action_index=index,
            shared_recipients=plan.shared_recipients(action_id),
        )
        try:
            execution = executor(action, context)
        except ActionFailure as exc:
            active.fail(action_id, notes=(str(exc),))
            continue
        except BaseException:
            active.interrupt(action_id)
            raise
        if not isinstance(execution, ActionExecution):
            active.fail(action_id, notes=("executor returned a non-ActionExecution value",))
            continue
        active.complete(
            action_id,
            ActionOutcome(
                action_id=action_id,
                lead_id=assignment.lead_id,
                result=execution.result,
                disposition=execution.disposition,
                evidence=execution.evidence,
                notes=execution.notes,
            ),
        )
        executed.append(action_id)

    return RunReport(
        journal=active,
        executed=tuple(executed),
        skipped_completed=tuple(skipped),
        shared_records=propagate_shared_evidence(plan, active),
    )


def propagate_shared_evidence(plan: ActionPlan, journal: ActionJournal) -> tuple[dict[str, Any], ...]:
    """Record one action's evidence reaching further leads -- without re-executing anything."""

    records: list[dict[str, Any]] = []
    for shared in plan.shared_evidence:
        record = journal.record(shared.source_action_id)
        if record.status.value != "COMPLETED":
            raise ActionFailure(
                f"shared evidence requires a COMPLETED source action: {shared.source_action_id}"
            )
        source = record.outcome
        if source is None:
            raise ActionFailure(f"shared evidence source has no outcome: {shared.source_action_id}")
        records.append(
            {
                "source_action_id": shared.source_action_id,
                "source_lead_id": source.lead_id,
                "recipients": list(shared.recipients),
                "edges_changed": list(shared.edges_changed),
                "evidence": list(source.evidence),
                "reexecuted": False,
            }
        )
    return tuple(records)
