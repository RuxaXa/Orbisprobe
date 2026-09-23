"""LIVE0 — PS4 live-transport components.

Kept deliberately separate from the offline analyzer: nothing in this package is imported by the
M1/M2-A/M2-B1 analysis paths, and it contains no analysis logic. It owns exactly three concerns:

* ``classification`` — fail-closed address classification for every live access
* ``policy``         — what may be read, what may be written, what is hard-blocked
* ``channel``/``ps4_target`` — the console transport and the adapter primitives behind
  :class:`orbisprobe.targets.base.Target`

Scope reminder (M2-LIVE0): read-only kernel access, user-space mutation with verified restore, no
kernel writes, no persistent state, no service requests.
"""

from __future__ import annotations

from .classification import AddressClass, classify, is_canonical
from .evidence import (
    EvidenceRecord,
    EvidenceWriter,
    MutationState,
    RestoreState,
)
from .plan import ExperimentPlan, ReadOp, WriteOp, canary_for
from .policy import (
    HARD_BLOCK_SINKS,
    LIVE0_MAX_READ,
    LivePolicy,
    PolicyDecision,
)

__all__ = [
    "HARD_BLOCK_SINKS",
    "LIVE0_MAX_READ",
    "AddressClass",
    "EvidenceRecord",
    "EvidenceWriter",
    "ExperimentPlan",
    "LivePolicy",
    "MutationState",
    "PolicyDecision",
    "ReadOp",
    "RestoreState",
    "WriteOp",
    "canary_for",
    "classify",
    "is_canonical",
]
