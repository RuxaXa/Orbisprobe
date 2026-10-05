from __future__ import annotations

from dataclasses import dataclass, replace
from typing import Any

from .model import (
    TERMINAL_STATUSES,
    ActionOutcome,
    ActionResult,
    ActionStatus,
    LeadDisposition,
    closed_schema,
    require_int,
    require_text,
    require_tuple,
)
from .plan import ActionPlan


@dataclass(frozen=True)
class ActionRecord:
    """Journal entry: the exact-once life of one action, with no implicit success."""

    action_id: str
    lead_id: str
    status: ActionStatus = ActionStatus.NOT_STARTED
    attempts: int = 0
    outcome: ActionOutcome | None = None
    notes: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        require_text("ActionRecord.action_id", self.action_id)
        require_text("ActionRecord.lead_id", self.lead_id)
        if not isinstance(self.status, ActionStatus):
            raise TypeError("ActionRecord.status must be an ActionStatus")
        require_int("ActionRecord.attempts", self.attempts)
        object.__setattr__(self, "notes", require_tuple("ActionRecord.notes", self.notes))
        if self.status is ActionStatus.COMPLETED and self.outcome is None:
            raise ValueError("a COMPLETED action requires a recorded outcome")
        if self.status in (ActionStatus.NOT_STARTED, ActionStatus.STARTED) and self.outcome is not None:
            raise ValueError("only terminal statuses may carry an outcome")

    @property
    def terminal(self) -> bool:
        return self.status in TERMINAL_STATUSES

    def to_dict(self) -> dict[str, Any]:
        return {
            "action_id": self.action_id,
            "lead_id": self.lead_id,
            "status": self.status.value,
            "attempts": self.attempts,
            "outcome": self.outcome.to_dict() if self.outcome is not None else None,
            "notes": list(self.notes),
        }

    @classmethod
    def from_dict(cls, value: object) -> ActionRecord:
        data = closed_schema(
            "ActionRecord", value, {"action_id", "lead_id", "status", "attempts"}, {"outcome", "notes"}
        )
        outcome = data.get("outcome")
        return cls(
            action_id=data["action_id"],
            lead_id=data["lead_id"],
            status=ActionStatus(data["status"]),
            attempts=data["attempts"],
            outcome=ActionOutcome.from_dict(outcome) if outcome is not None else None,
            notes=tuple(data.get("notes", ())),
        )


class ExactOnceViolation(RuntimeError):
    """Raised when a caller tries to execute an action a second time."""


class ActionJournal:
    """Exact-once execution journal.

    ``COMPLETED`` is final: it is never rerun automatically. An action interrupted after
    ``STARTED`` but before terminal evidence becomes ``UNKNOWN_UNVERIFIED`` -- never success.
    """

    def __init__(self, records: dict[str, ActionRecord]) -> None:
        self._records = dict(records)

    @classmethod
    def from_plan(cls, plan: ActionPlan) -> ActionJournal:
        return cls(
            {
                assignment.action_id: ActionRecord(
                    action_id=assignment.action_id, lead_id=assignment.lead_id
                )
                for assignment in plan.assignments
            }
        )

    @classmethod
    def from_dict(cls, value: object) -> ActionJournal:
        data = closed_schema("ActionJournal", value, {"records"})
        records = data["records"]
        if not isinstance(records, list):
            raise TypeError("ActionJournal.records must be a list")
        rebuilt: dict[str, ActionRecord] = {}
        for item in records:
            record = ActionRecord.from_dict(item)
            if record.action_id in rebuilt:
                raise ValueError(f"duplicate journal entry: {record.action_id}")
            rebuilt[record.action_id] = record
        return cls(rebuilt)

    def to_dict(self) -> dict[str, Any]:
        return {"records": [self._records[key].to_dict() for key in sorted(self._records)]}

    def record(self, action_id: str) -> ActionRecord:
        try:
            return self._records[action_id]
        except KeyError as exc:
            raise KeyError(f"unknown action in journal: {action_id}") from exc

    def records(self) -> tuple[ActionRecord, ...]:
        return tuple(self._records[key] for key in sorted(self._records))

    def start(self, action_id: str) -> ActionRecord:
        record = self.record(action_id)
        if record.status is ActionStatus.COMPLETED:
            raise ExactOnceViolation(
                f"exact-once violation: action {action_id} is already COMPLETED and must not be rerun"
            )
        if record.status is ActionStatus.STARTED:
            raise ExactOnceViolation(f"action {action_id} is already in flight")
        updated = replace(record, status=ActionStatus.STARTED, attempts=record.attempts + 1)
        self._records[action_id] = updated
        return updated

    def complete(self, action_id: str, outcome: ActionOutcome) -> ActionRecord:
        record = self.record(action_id)
        if record.status is ActionStatus.COMPLETED:
            raise ExactOnceViolation(f"exact-once violation: action {action_id} already has a terminal outcome")
        if record.status is not ActionStatus.STARTED:
            raise ExactOnceViolation(f"action {action_id} cannot complete from {record.status.value}")
        if outcome.action_id != action_id:
            raise ValueError("outcome action_id does not match the journal entry")
        updated = replace(record, status=ActionStatus.COMPLETED, outcome=outcome)
        self._records[action_id] = updated
        return updated

    def fail(self, action_id: str, *, notes: tuple[str, ...]) -> ActionRecord:
        record = self.record(action_id)
        if record.status is ActionStatus.COMPLETED:
            raise ExactOnceViolation(f"exact-once violation: action {action_id} is already COMPLETED")
        updated = replace(record, status=ActionStatus.FAILED, notes=record.notes + tuple(notes))
        self._records[action_id] = updated
        return updated

    def interrupt(self, action_id: str, *, notes: tuple[str, ...] = ()) -> ActionRecord:
        """Gateway/worker interruption: an in-flight action never becomes success."""

        record = self.record(action_id)
        if record.status is ActionStatus.COMPLETED:
            raise ExactOnceViolation(f"exact-once violation: action {action_id} is already COMPLETED")
        updated = replace(
            record,
            status=ActionStatus.UNKNOWN_UNVERIFIED,
            notes=record.notes + tuple(notes) + ("interrupted before terminal evidence",),
        )
        self._records[action_id] = updated
        return updated

    def recover_interrupted(self) -> tuple[str, ...]:
        """Convert every still-``STARTED`` entry (e.g. after a hard kill) to UNKNOWN_UNVERIFIED."""

        recovered: list[str] = []
        for action_id, record in sorted(self._records.items()):
            if record.status is ActionStatus.STARTED:
                self._records[action_id] = replace(
                    record,
                    status=ActionStatus.UNKNOWN_UNVERIFIED,
                    notes=record.notes + ("recovered without terminal evidence",),
                )
                recovered.append(action_id)
        return tuple(recovered)

    def request_retry(self, action_id: str, *, justification: str) -> ActionRecord:
        """Explicit, recorded retry of a non-successful action; never available for COMPLETED."""

        require_text("justification", justification)
        record = self.record(action_id)
        if record.status is ActionStatus.COMPLETED:
            raise ExactOnceViolation(f"exact-once violation: action {action_id} is COMPLETED")
        if record.status in (ActionStatus.NOT_STARTED, ActionStatus.STARTED):
            raise ExactOnceViolation(f"action {action_id} cannot be retried from {record.status.value}")
        updated = replace(
            record,
            status=ActionStatus.NOT_STARTED,
            notes=record.notes + (f"explicit retry: {justification}",),
        )
        self._records[action_id] = updated
        return updated

    def execution_counts(self) -> dict[str, int]:
        """Attempts per action; used to prove exact-once execution."""

        return {action_id: record.attempts for action_id, record in sorted(self._records.items())}

    def metrics_projection(self) -> dict[str, Any]:
        records = self.records()
        completed = [record for record in records if record.status is ActionStatus.COMPLETED]
        results = [record.outcome.result for record in completed if record.outcome is not None]
        dispositions = [record.outcome.disposition for record in completed if record.outcome is not None]
        return {
            "records": len(records),
            "completed": len(completed),
            "terminal": sum(1 for record in records if record.terminal),
            "attempts_total": sum(record.attempts for record in records),
            "exactly_once": all(record.attempts <= 1 for record in records)
            and len({record.action_id for record in records}) == len(records),
            "resolved_safe": sum(1 for result in results if result is ActionResult.RESOLVED_SAFE),
            "safe_closed": sum(1 for item in dispositions if item is LeadDisposition.SAFE_CLOSED),
            "downgraded": sum(1 for item in dispositions if item is LeadDisposition.DOWNGRADED),
            "artifact_blocked": sum(
                1
                for item in dispositions
                if item in (LeadDisposition.ARTIFACT_BLOCKED, LeadDisposition.PARKED)
            ),
            "evidence_conflicts": sum(
                1 for result in results if result is ActionResult.EVIDENCE_CONFLICT
            ),
            "unknown_unverified": sum(
                1 for record in records if record.status is ActionStatus.UNKNOWN_UNVERIFIED
            ),
        }
