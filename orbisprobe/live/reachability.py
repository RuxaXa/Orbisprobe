"""M2-LIVE2.3 — real-candidate reachability classification and safety gates (§7-§13).

Separates what the static evidence actually proves from what it merely suggests:

* ``SecurityClass``  C1/C2/C3/C4 — only a dereferencing/selecting consumer (C2/C3) is interesting,
  C4 (semantics unknown) forbids a live test.
* ``gates()``        the hard pre-live gates: no kernel write on the path, no persistent sink, the field
  must be user-controllable *and* temporally mutable, the consumer must be closed.
* ``classify()``     RCR-A (safe live candidate) / RCR-B (disproved) / RCR-C (downgrade) / RCR-D (PLAN_ONLY).

A candidate that writes kernel memory inside its own body can never become RCR-A: driving it would be a
kernel write, which the milestone rules out.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

RCR_A = "RCR-A"  # safe live candidate
RCR_B = "RCR-B"  # real path closed, but field kernel-controlled/immutable -> candidate disproved
RCR_C = "RCR-C"  # consumer not security-sensitive -> downgrade
RCR_D = "RCR-D"  # reachability/ownership unresolved -> PLAN_ONLY

C1 = "C1"  # consumer only compares/logs the value
C2 = "C2"  # consumer dereferences the pointer / selects an object
C3 = "C3"  # consumer copies/reads/writes memory based on the value
C4 = "C4"  # consumer semantics unknown

#: mnemonics that write memory (kernel state) when the destination is a memory operand
MEMORY_WRITE_MNEMONICS = ("mov", "movzx", "movsx", "movsxd", "and", "or", "xor", "add", "sub", "inc",
                          "dec", "not", "neg", "shl", "shr", "sar", "stosb", "stosd", "stosq", "rep")

PERSISTENT_SINKS = ("snvs", "syscon", "flash", "nor", "fsl", "nvram", "firmware", "update", "keys",
                    "key_provisioning", "filesystem", "mount", "vnode", "ufs")


@dataclass
class ReachabilityEvidence:
    """Everything the static closure produced for one candidate."""

    candidate_id: str
    function: str
    field: str
    read_1: str
    read_2: str
    intervening_call: str
    consumer: str
    consumer_security_class: str
    field_writers_in_body: list[str] = field(default_factory=list)
    kernel_writes_on_path: list[str] = field(default_factory=list)
    user_control: str = "UNKNOWN"           # USER_CONTROLLED / USER_INFLUENCED / KERNEL_CONTROLLED / UNKNOWN
    mutability: str = "UNKNOWN"             # MUTABLE / LOCK_PROTECTED / IMMUTABLE / UNKNOWN
    lock_between_reads: bool | None = None
    persistent_sink_proof: str = "NOT_PROVEN"
    callers: list[str] = field(default_factory=list)
    unresolved: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def gates(self) -> tuple[bool, list[str]]:
        blockers: list[str] = []
        if self.kernel_writes_on_path:
            blockers.append("the candidate itself writes kernel memory: "
                            f"{self.kernel_writes_on_path[0]} (kernel write is out of scope)")
        if self.persistent_sink_proof != "PROVEN_ABSENT":
            blockers.append("non-persistence of the concrete input path is not proven")
        if self.consumer_security_class == C4:
            blockers.append("consumer semantics unknown (C4): no live test")
        if self.consumer_security_class == C1:
            blockers.append("consumer only compares/logs (C1): not security sensitive")
        if self.user_control not in ("USER_CONTROLLED", "USER_INFLUENCED"):
            blockers.append(f"field is not user-controllable ({self.user_control})")
        if self.mutability != "MUTABLE":
            blockers.append(f"field is not temporally mutable ({self.mutability})")
        if self.mutability == "MUTABLE" and self.lock_between_reads:
            blockers.append("a lock/refcount pins the field between the reads")
        if self.unresolved:
            blockers.append(f"unresolved: {self.unresolved[0]}")
        return (not blockers), blockers


def classify(evidence: ReachabilityEvidence) -> tuple[str, str, list[str]]:
    """§13: RCR-A only when every gate is closed."""

    allowed, blockers = evidence.gates()
    if allowed:
        return RCR_A, "real entry path closed, user-influenced mutable field, closed host consumer, non-persistent", []
    if evidence.mutability in ("IMMUTABLE", "LOCK_PROTECTED") or evidence.user_control == "KERNEL_CONTROLLED":
        return RCR_B, "real path closed but the field is kernel-controlled/immutable: candidate disproved", blockers
    if evidence.consumer_security_class == C1:
        return RCR_C, "consumer is not security sensitive: candidate downgraded", blockers
    return RCR_D, "reachability/ownership/consumer semantics unresolved: PLAN_ONLY", blockers


def classify_consumer(derefs: int, calls: int, stores_via_pointer: int, known: bool = True) -> str:
    """§7 mapping from measured consumer behaviour to the security class."""

    if not known:
        return C4
    if stores_via_pointer > 0 or (derefs > 0 and calls > 0):
        return C3
    if derefs > 0:
        return C2
    return C1
