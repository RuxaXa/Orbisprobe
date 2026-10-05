from __future__ import annotations

import hashlib
import json
import math
from collections.abc import Iterable
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any


class ActionStatus(str, Enum):
    """Exact-once lifecycle of a single EvidenceAction."""

    NOT_STARTED = "NOT_STARTED"
    STARTED = "STARTED"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    UNKNOWN_UNVERIFIED = "UNKNOWN_UNVERIFIED"


class ActionResult(str, Enum):
    RESOLVED_SAFE = "RESOLVED_SAFE"
    RESOLVED_GAP = "RESOLVED_GAP"
    EDGE_REDUCED = "EDGE_REDUCED"
    EDGE_UNCHANGED = "EDGE_UNCHANGED"
    DOWNGRADED = "DOWNGRADED"
    ARTIFACT_BLOCKED = "ARTIFACT_BLOCKED"
    EVIDENCE_CONFLICT = "EVIDENCE_CONFLICT"


class LeadDisposition(str, Enum):
    PROOF_MODE_READY = "PROOF_MODE_READY"
    CLOSURE_PENDING = "CLOSURE_PENDING"
    VULNERABILITY_CANDIDATE = "VULNERABILITY_CANDIDATE"
    SAFE_CLOSED = "SAFE_CLOSED"
    DOWNGRADED = "DOWNGRADED"
    PARKED = "PARKED"
    ARTIFACT_BLOCKED = "ARTIFACT_BLOCKED"
    EVIDENCE_CONFLICT = "EVIDENCE_CONFLICT"


class ReviewState(str, Enum):
    PASS = "PASS"
    CHANGES_REQUIRED = "CHANGES_REQUIRED"
    UNKNOWN_UNVERIFIED = "UNKNOWN_UNVERIFIED"
    STALE_REVIEW = "STALE_REVIEW"


class ResultFreshness(str, Enum):
    CURRENT = "CURRENT"
    STALE_RESULT = "STALE_RESULT"


class ReviewMode(str, Enum):
    STANDARD = "standard"
    ADVERSARIAL = "adversarial"


TERMINAL_STATUSES: tuple[ActionStatus, ...] = (
    ActionStatus.COMPLETED,
    ActionStatus.FAILED,
    ActionStatus.UNKNOWN_UNVERIFIED,
)

# Package layout conventions (documented in the skill so rebuild entry points stay stable).
PACKAGE_REBUILD_ENTRYPOINT = "rebuild-pass.py"
PACKAGE_RESULT_NAME = "verification-result.json"
PACKAGE_REVIEW_DIR = "review"
PACKAGE_REVIEW_REQUEST = "review/REVIEW-REQUEST.json"
PACKAGE_REVIEW_INSTRUCTIONS = "review/REVIEW-INSTRUCTIONS.md"
PACKAGE_REVIEW_RESULT = "review/REVIEW-RESULT.json"

# Action results explicitly keep their own vocabulary; a RESOLVED_SAFE action result is
# never on its own sufficient evidence for closing a whole lead. Closure requires the lead
# itself to be closed (terminal, EDGE-0, no unknown edges, evidence present), and the action
# must at least have advanced closure.
DISPOSITION_SAFE_CLOSING_RESULTS: tuple[ActionResult, ...] = (
    ActionResult.RESOLVED_SAFE,
    ActionResult.EDGE_REDUCED,
)


def _require_text(name: str, value: object) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{name} must be non-empty text")
    try:
        value.encode("utf-8")
    except UnicodeEncodeError as exc:  # lone surrogates are not valid evidence text
        raise ValueError(f"{name} must be valid UTF-8 text") from exc
    return value


def require_text(name: str, value: object) -> str:
    return _require_text(name, value)


def require_hex_digest(name: str, value: object) -> str:
    text = _require_text(name, value)
    if len(text) != 64 or any(character not in "0123456789abcdef" for character in text):
        raise ValueError(f"{name} must be a lowercase sha256 hex digest")
    return text


def require_hex_bytes(name: str, value: object) -> str:
    """Validate an even-length hexadecimal byte string (instruction pins, not digests)."""

    text = _require_text(name, value)
    if len(text) % 2 or any(character not in "0123456789abcdefABCDEF" for character in text):
        raise ValueError(f"{name} must be an even-length hexadecimal byte string")
    return text


def require_address(name: str, value: object) -> str:
    text = _require_text(name, value)
    body = text.removeprefix("0x")
    if not body or any(character not in "0123456789abcdefABCDEF" for character in body):
        raise ValueError(f"{name} must be a hexadecimal address")
    return text


def require_int(name: str, value: object, *, minimum: int = 0) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < minimum:
        raise ValueError(f"{name} must be an integer >= {minimum}")
    return value


def require_bool(name: str, value: object) -> bool:
    if not isinstance(value, bool):
        raise TypeError(f"{name} must be a boolean")
    return value


def require_tuple(name: str, value: object) -> tuple[str, ...]:
    if not isinstance(value, (list, tuple)):
        raise TypeError(f"{name} must be a list of non-empty strings")
    items = tuple(_require_text(f"{name}[]", item) for item in value)
    if len(set(items)) != len(items):
        raise ValueError(f"{name} must not contain duplicates")
    return items


def closed_schema(
    name: str,
    value: object,
    required: set[str],
    optional: Iterable[str] = frozenset(),
) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise TypeError(f"{name} must be an object")
    keys = set(value)
    unknown = keys - required - set(optional)
    if unknown:
        raise ValueError(f"{name} has unknown fields: {', '.join(sorted(unknown))}")
    missing = required - keys
    if missing:
        raise ValueError(f"{name} is missing required fields: {', '.join(sorted(missing))}")
    for key in value:
        _require_text(f"{name} key", key)
    return dict(value)


def _require_utf8(name: str, value: str) -> None:
    """Reject text that cannot be encoded as UTF-8 (for example lone surrogates)."""

    try:
        value.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise ValueError(f"{name} must be valid UTF-8 text") from exc


def ensure_finite(name: str, value: object) -> None:
    """Fail closed on values that cannot be serialized canonically."""

    if isinstance(value, bool):
        return
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError(f"{name} must be a finite number")
        return
    if value is None or isinstance(value, int):
        return
    if isinstance(value, str):
        _require_utf8(name, value)
        return
    if isinstance(value, (list, tuple)):
        for item in value:
            ensure_finite(f"{name}[]", item)
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise TypeError(f"{name} keys must be strings")
            _require_utf8(f"{name} key", key)
            ensure_finite(f"{name}.{key}", item)
        return
    raise TypeError(f"{name} must be JSON-serializable")


def canonical_json(value: object) -> str:
    """Canonical, UTF-8-fail-closed JSON with stable key ordering and no timestamps."""

    ensure_finite("value", value)
    text = json.dumps(value, indent=2, sort_keys=True, allow_nan=False, ensure_ascii=False)
    return text + "\n"


def canonical_bytes(value: object) -> bytes:
    try:
        return canonical_json(value).encode("utf-8")
    except UnicodeEncodeError as exc:
        raise ValueError("value is not valid UTF-8") from exc


def sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def sha256_file(path: str | Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


@dataclass(frozen=True)
class EvidenceReference:
    """A frozen artifact inside the pass package that backs a decision."""

    path: str
    sha256: str

    def __post_init__(self) -> None:
        relative = Path(_require_text("EvidenceReference.path", self.path))
        if relative.is_absolute() or ".." in relative.parts:
            raise ValueError(f"evidence reference must be package-relative: {self.path}")
        require_hex_digest("EvidenceReference.sha256", self.sha256)

    def to_dict(self) -> dict[str, str]:
        return {"path": self.path, "sha256": self.sha256}

    @classmethod
    def from_dict(cls, value: object) -> EvidenceReference:
        data = closed_schema("EvidenceReference", value, {"path", "sha256"})
        return cls(path=data["path"], sha256=data["sha256"])


@dataclass(frozen=True)
class ClaimTrace:
    """Traceable coordinates for a decisive claim (function/address/field/callsite/slice)."""

    claim: str
    function: str
    address: str
    field: str
    callsite: str
    slice_path: str
    slice_sha256: str

    def __post_init__(self) -> None:
        _require_text("ClaimTrace.claim", self.claim)
        _require_text("ClaimTrace.function", self.function)
        require_address("ClaimTrace.address", self.address)
        _require_text("ClaimTrace.field", self.field)
        _require_text("ClaimTrace.callsite", self.callsite)
        relative = Path(_require_text("ClaimTrace.slice_path", self.slice_path))
        if relative.is_absolute() or ".." in relative.parts:
            raise ValueError(f"claim slice must be package-relative: {self.slice_path}")
        require_hex_digest("ClaimTrace.slice_sha256", self.slice_sha256)

    def to_dict(self) -> dict[str, str]:
        return {
            "claim": self.claim,
            "function": self.function,
            "address": self.address,
            "field": self.field,
            "callsite": self.callsite,
            "slice_path": self.slice_path,
            "slice_sha256": self.slice_sha256,
        }

    @classmethod
    def from_dict(cls, value: object) -> ClaimTrace:
        data = closed_schema(
            "ClaimTrace",
            value,
            {"claim", "function", "address", "field", "callsite", "slice_path", "slice_sha256"},
        )
        return cls(**data)


@dataclass(frozen=True)
class ActionOutcome:
    """What a single executed action produced, kept separate from the lead disposition."""

    action_id: str
    lead_id: str
    result: ActionResult
    disposition: LeadDisposition
    evidence: tuple[str, ...] = ()
    notes: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        _require_text("ActionOutcome.action_id", self.action_id)
        _require_text("ActionOutcome.lead_id", self.lead_id)
        if not isinstance(self.result, ActionResult) or not isinstance(self.disposition, LeadDisposition):
            raise TypeError("ActionOutcome result/disposition must use the canonical enums")
        object.__setattr__(self, "evidence", require_tuple("ActionOutcome.evidence", self.evidence))
        object.__setattr__(self, "notes", require_tuple("ActionOutcome.notes", self.notes))

    def to_dict(self) -> dict[str, Any]:
        return {
            "action_id": self.action_id,
            "lead_id": self.lead_id,
            "result": self.result.value,
            "disposition": self.disposition.value,
            "evidence": list(self.evidence),
            "notes": list(self.notes),
        }

    @classmethod
    def from_dict(cls, value: object) -> ActionOutcome:
        data = closed_schema(
            "ActionOutcome",
            value,
            {"action_id", "lead_id", "result", "disposition"},
            {"evidence", "notes"},
        )
        return cls(
            action_id=data["action_id"],
            lead_id=data["lead_id"],
            result=ActionResult(data["result"]),
            disposition=LeadDisposition(data["disposition"]),
            evidence=tuple(data.get("evidence", ())),
            notes=tuple(data.get("notes", ())),
        )


@dataclass(frozen=True)
class Metrics:
    """Required pass metrics; every field derives from the package, never from a static flag."""

    actions_expected: int
    actions_executed: int
    exactly_once: bool
    shared_actions: int
    leads_changed: int
    leads_unchanged: int
    score_movement: int
    edge_movement: int
    safe_closures: int
    downgrades: int
    blocked_leads: int
    evidence_conflicts: int
    runtime_actions: int
    proof_actions: int
    source_integrity: bool
    shared_evidence_recipients: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "actions_expected": self.actions_expected,
            "actions_executed": self.actions_executed,
            "exactly_once": self.exactly_once,
            "shared_actions": self.shared_actions,
            "shared_evidence_recipients": self.shared_evidence_recipients,
            "leads_changed": self.leads_changed,
            "leads_unchanged": self.leads_unchanged,
            "score_movement": self.score_movement,
            "edge_movement": self.edge_movement,
            "safe_closures": self.safe_closures,
            "downgrades": self.downgrades,
            "blocked_leads": self.blocked_leads,
            "evidence_conflicts": self.evidence_conflicts,
            "runtime_actions": self.runtime_actions,
            "proof_actions": self.proof_actions,
            "source_integrity": self.source_integrity,
        }
