"""Experiment plans for live runs.

A plan is the only thing that may authorise a live operation, and it carries its own bounds: the
exact addresses, the exact bytes, the expectation, and — for every mutation — the restore steps.
LIVE0 allows at most one mutation per plan (§11), and a mutating plan without complete restore
steps is structurally invalid before it ever reaches the policy layer.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Any

CANARY_DOMAIN = b"orbisprobe-live0-canary-v1"


def canary_for(experiment_id: str, length: int) -> bytes:
    """Deterministic canary bytes derived from the experiment id (no randomness needed)."""

    if length <= 0 or length > 0x1000:
        raise ValueError("canary length out of range")
    out = bytearray()
    counter = 0
    while len(out) < length:
        out += hashlib.sha256(
            CANARY_DOMAIN + experiment_id.encode("utf-8") + counter.to_bytes(4, "little")
        ).digest()
        counter += 1
    return bytes(out[:length])


@dataclass(frozen=True)
class ReadOp:
    address: int
    length: int
    address_class: str = "UNKNOWN"
    label: str = ""

    def __post_init__(self) -> None:
        if self.length <= 0:
            raise ValueError("read length must be positive")
        if self.address < 0:
            raise ValueError("read address must be non-negative")


@dataclass(frozen=True)
class WriteOp:
    address: int
    data: bytes
    address_class: str = "UNKNOWN"
    label: str = ""

    def __post_init__(self) -> None:
        if not self.data:
            raise ValueError("write data must not be empty")
        if self.address < 0:
            raise ValueError("write address must be non-negative")

    @property
    def length(self) -> int:
        return len(self.data)


@dataclass(frozen=True)
class RestoreSteps:
    """The complete, ordered repair path a mutating plan must declare."""

    baseline_read: bool = False
    restore_write: bool = False
    restore_readback: bool = False
    verify_equality: bool = False

    @property
    def complete(self) -> bool:
        return (
            self.baseline_read
            and self.restore_write
            and self.restore_readback
            and self.verify_equality
        )

    def missing(self) -> list[str]:
        missing = []
        if not self.baseline_read:
            missing.append("baseline_read")
        if not self.restore_write:
            missing.append("restore_write")
        if not self.restore_readback:
            missing.append("restore_readback")
        if not self.verify_equality:
            missing.append("verify_equality")
        return missing


@dataclass
class ExperimentPlan:
    plan_id: str
    level: str
    reads: tuple[ReadOp, ...] = ()
    writes: tuple[WriteOp, ...] = ()
    expected: dict[str, Any] = field(default_factory=dict)
    restore_steps: RestoreSteps = field(default_factory=RestoreSteps)
    declared_sink: str = "USER_MEMORY"
    notes: str = ""
    dry_run: bool = False

    def __post_init__(self) -> None:
        if self.level not in {"LIVE0-R", "LIVE0-U", "LIVE0-S", "LIVE0-K"}:
            raise ValueError(f"unknown live level {self.level!r}")
        if len(self.writes) > 1:
            # §11: exactly one bounded mutation per plan.
            raise ValueError("a plan may contain at most one mutation")
        if self.writes and not self.restore_steps.complete:
            raise ValueError(
                "a mutating plan must declare complete restore steps; missing: "
                + ", ".join(self.restore_steps.missing())
            )
        if self.writes and not self.expected.get("canary"):
            raise ValueError("a mutating plan must declare its expected canary")

    @property
    def mutating(self) -> bool:
        return bool(self.writes)

    def to_dict(self) -> dict[str, Any]:
        return {
            "plan_id": self.plan_id,
            "level": self.level,
            "reads": [
                {
                    "address": f"0x{op.address:x}",
                    "length": op.length,
                    "address_class": op.address_class,
                }
                for op in self.reads
            ],
            "writes": [
                {
                    "address": f"0x{op.address:x}",
                    "length": op.length,
                    "address_class": op.address_class,
                    "data_sha256": hashlib.sha256(op.data).hexdigest(),
                }
                for op in self.writes
            ],
            "expected": self.expected,
            "restore_steps": {
                "baseline_read": self.restore_steps.baseline_read,
                "restore_write": self.restore_steps.restore_write,
                "restore_readback": self.restore_steps.restore_readback,
                "verify_equality": self.restore_steps.verify_equality,
            },
            "declared_sink": self.declared_sink,
            "dry_run": self.dry_run,
        }
