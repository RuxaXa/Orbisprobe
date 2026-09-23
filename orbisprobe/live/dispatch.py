"""M2-LIVE2.6 — indirect dispatch resolution, user-influence and R26 outcomes.

The dispatch forms found in the image and what each one means:

``CALL [RBX + 0x8]``   ops/vtable dispatch: the base comes from a handle/object lookup, the function
                       pointer sits at a fixed offset inside a table entry (stride 8 here)
``CALL [RAX + 0x21850]`` a function pointer inside a large per-context structure (neighbouring fields
                       0x21810/20/30/40/70/90 belong to the same struct)
``JMP RAX``            tail call / thunk — never treated as dispatch without a reaching definition

A dispatch site is only "resolved" when its possible target set is non-empty **and** unambiguous, or when
ambiguity is explicitly carried (multi-target sets must never be collapsed to one observed value).
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

R26_A = "R26-A"
R26_B = "R26-B"
R26_C = "R26-C"
R26_D = "R26-D"
R26_E = "R26-E"

ROOT_CLASSES = ("SYSCALL", "IOCTL", "DEVICE_OP", "SERVICE_HANDLER", "SOCKET", "WORKQUEUE",
                "GPU_DRM_ENTRY", "CALLBACK", "KERNEL_INTERNAL", "UNKNOWN")
CONSUMER_TARGETS = ("HOST_STATE", "RING_STATE", "DMA_VISIBLE", "DEVICE_COMMAND", "UNKNOWN")


@dataclass
class DispatchSite:
    site: str
    form: str                                  # CALL_MEM_OFFSET / JMP_REG / CALL_REG / CALL_MEM_BIG
    source: str = ""                           # register/memory the target comes from
    reaching_definition: str = ""
    table_base: str = ""
    entry_stride: int | None = None
    function_pointer_offset: str = ""
    possible_targets: list[str] = field(default_factory=list)
    ambiguous: bool = False
    analysis_status: str = "UNRESOLVED"        # RESOLVED / AMBIGUOUS / INCOMPLETE / UNRESOLVED
    evidence_sources: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def is_resolved(self) -> bool:
        return self.analysis_status == "RESOLVED" and bool(self.possible_targets) and not self.ambiguous


def classify_dispatch_form(instruction: str) -> str:
    """Map an instruction to the dispatch form (fixtures: ops-table, big offset, register call/jump)."""

    import re

    text = instruction.upper()
    if re.search(r"CALL\s+(QWORD PTR\s+)?\[R\w+\s*\+\s*0X218[0-9A-F]{2}\]", text):
        return "CALL_MEM_BIG"
    if re.search(r"CALL\s+(QWORD PTR\s+)?\[R\w+\s*\+\s*0X[0-9A-F]+\]", text):
        return "CALL_MEM_OFFSET"
    if re.search(r"CALL\s+R\w+", text):
        return "CALL_REG"
    if re.search(r"JMP\s+R\w+", text):
        return "JMP_REG"
    return "NONE"


def target_from_data_pointer(data_hits: list[str], known_text_range: tuple[str, str]) -> list[str]:
    """§19: a value found in data is only a dispatch target when it lies inside the executable range."""

    low, high = (int(bound, 16) for bound in known_text_range)
    return sorted({hit for hit in data_hits if low <= int(hit, 16) < high})


@dataclass
class R26Evidence:
    candidate_id: str
    root_entry: str = ""
    root_class: str = "UNKNOWN"
    dispatch_sites: list[DispatchSite] = field(default_factory=list)
    object_family: str = "UNKNOWN"             # OBJECT_FAMILY_CONFIRMED / SUPPORTED / UNKNOWN
    context_struct_offsets: list[str] = field(default_factory=list)
    field_f8_writers: list[str] = field(default_factory=list)
    user_influence: str = "UNKNOWN"
    user_influence_chain: list[str] = field(default_factory=list)
    mutability: str = "UNKNOWN"
    synchronization_held: bool | None = None
    consumer_class: str = "C4"
    consumer_target: str = "UNKNOWN"           # HOST_STATE / RING_STATE / DMA_VISIBLE / DEVICE_COMMAND
    non_persistence: str = "UNPROVEN"          # CONFIRMED / SUPPORTED / UNPROVEN
    chain_link_ioctl_to_candidate: bool = False
    missing_artifact: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def unresolved_sites(self) -> list[str]:
        return [site.site for site in self.dispatch_sites if not site.is_resolved()]


def classify(evidence: R26Evidence) -> tuple[str, str, list[str]]:
    """§17 outcomes; safety blockers first, and R26-A only on complete closure."""

    blockers: list[str] = []
    if evidence.mutability in ("IMMUTABLE_AFTER_INIT", "KERNEL_CONTROLLED"):
        return R26_B, "field_f8 is kernel-controlled/immutable: candidate disproved", blockers
    if evidence.synchronization_held is True:
        return R26_C, "a lock/refcount is held across both reads: split disproved for this path", blockers
    if evidence.user_influence not in ("USER_CONTROLLED", "USER_INFLUENCED"):
        blockers.append(f"user influence not established ({evidence.user_influence})")
    if not evidence.chain_link_ioctl_to_candidate:
        blockers.append("no proven path from the root entry to the candidate")
    if evidence.unresolved_sites():
        blockers.append(f"indirect dispatch sites unresolved: {', '.join(evidence.unresolved_sites()[:3])}")
    if evidence.consumer_class != "C3":
        blockers.append(f"consumer class {evidence.consumer_class} is not C3")
    if evidence.non_persistence == "UNPROVEN":
        blockers.append("non-persistence of the fixed path unproven")
    if evidence.missing_artifact:
        return R26_E, f"indirect targets still unresolved: {evidence.missing_artifact}", blockers
    if blockers:
        return R26_D, "dispatch/root resolved but user influence still unknown: PLAN_ONLY", blockers
    return R26_A, "root, user influence, mutable field, unprotected double read, C3 consumer, non-persistent", []
