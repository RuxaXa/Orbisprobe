"""M2-LIVE2.7 — target-set / field-writer / user-influence closure (R27).

Three questions decide whether RC-001 can ever be a live candidate:

* **index domain** — a table index with no write reference in the image is a compile-time constant; a
  value a user can pick would look completely different (writes from request handlers).
* **target set** — an entry's function pointer is only a target if it resolves to an executable address
  that is a known function boundary. Data pointers never become targets.
* **callback/ops field** — a field that is written once, NULL-checked before the call and cleared on
  teardown is a registered callback; that is a different (and much narrower) thing than a table.

The outcomes keep an unresolved runtime table unresolved: it needs runtime data, not more static guessing.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

R27_A = "R27-A"
R27_B = "R27-B"
R27_C = "R27-C"
R27_D = "R27-D"
R27_E = "R27-E"

CONSTANT = "CONSTANT"
SMALL_ENUM = "SMALL_ENUM"
RUNTIME_ENUM = "RUNTIME_ENUM"
USER_INFLUENCED = "USER_INFLUENCED"
UNKNOWN = "UNKNOWN"

FUNCTION_POINTER = "FUNCTION_POINTER"
CALLBACK_CONFIRMED = "CALLBACK_CONFIRMED"
DATA_FIELD = "DATA_FIELD"
FIELD_UNKNOWN = "FIELD_UNKNOWN"

#: ioctl direction bits (Linux/BSD _IOC encoding, four bits at 30..29)
IOC_DIRS = {0: "NONE", 1: "WRITE", 2: "READ", 3: "READ_WRITE"}


def decode_ioctl(code: int) -> dict[str, Any]:
    """Decode a 0xc0xxxxxx style ioctl number into direction/size/type/number."""

    return {"code": f"0x{code:08x}", "dir": IOC_DIRS.get((code >> 30) & 0b11, "?"),
            "size": (code >> 16) & 0x3FFF, "type": f"0x{(code >> 8) & 0xFF:02x}",
            "nr": code & 0xFF, "user_data": ((code >> 30) & 0b11) != 0}


@dataclass
class IndexDomain:
    symbol: str
    write_references: int
    read_references: int
    static_value: int | None = None

    def classify(self) -> tuple[str, str]:
        if self.write_references == 0 and self.static_value is not None:
            return CONSTANT, f"no write reference in the image; static value {self.static_value:#x}"
        if self.write_references == 0:
            return UNKNOWN, "no write reference and no static value"
        if self.write_references <= 4 and self.static_value is not None:
            return SMALL_ENUM, f"{self.write_references} writer(s): small enum"
        return RUNTIME_ENUM, f"{self.write_references} writers: runtime selected"


def validate_targets(hits: list[str], function_entries: set[str], text_range: tuple[str, str]
                     ) -> tuple[list[str], list[str]]:
    """§4: a target must be inside the text range, executable and a known function boundary."""

    low, high = (int(bound, 16) for bound in text_range)
    accepted, rejected = [], []
    for hit in hits:
        value = int(hit, 16)
        if not (low <= value < high):
            rejected.append(f"{hit}: outside the text range")
        elif hit not in function_entries:
            rejected.append(f"{hit}: no function boundary at this address")
        else:
            accepted.append(hit)
    return sorted(accepted), rejected


def classify_callback_slot(*, writes: int, reads: int, calls: int, clears: int) -> tuple[str, str]:
    """§6: call + write + clear pattern means a registered callback, not a data field."""

    if calls and writes:
        return CALLBACK_CONFIRMED, f"written {writes}x, called {calls}x, cleared {clears}x"
    if calls:
        return FUNCTION_POINTER, "called but never written in the image (externally initialised)"
    if writes or reads:
        return DATA_FIELD, "accessed, but never called: no function pointer evidence"
    return FIELD_UNKNOWN, "no access found"


def classify_user_influence(*, handle_from_ioctl_input: bool, writer_from_handle_lookup: bool,
                            writer_kernel_internal: bool) -> tuple[str, str]:
    """§14: direct value control is a different claim from indirect selection through a handle."""

    if handle_from_ioctl_input and writer_from_handle_lookup:
        return "USER_INFLUENCED", "the handle comes from ioctl input and the kernel resolves the object"
    if writer_kernel_internal and not handle_from_ioctl_input:
        return "KERNEL_CONTROLLED", "no user-visible selector reaches the writer"
    return "UNKNOWN", "the chain from user input to the writer is not proven"


@dataclass
class R27Evidence:
    candidate_id: str
    index_domain: dict[str, Any] = field(default_factory=dict)
    table_base_source: str = ""
    table_init: str = "UNKNOWN"                 # STATIC / RUNTIME / UNKNOWN
    target_set: list[str] = field(default_factory=list)
    target_set_ambiguous: bool = False
    callback_field: str = ""
    callback_class: str = FIELD_UNKNOWN
    ioctl_codes: list[str] = field(default_factory=list)
    handle_lookup: str = ""
    root_to_candidate_link: bool = False
    field_f8_writer: str = ""
    field_f8_source_class: str = "UNKNOWN"      # STATIC_RING / KERNEL_ALLOCATED_RING / HANDLE_SELECTED_RING / USER_POINTER / UNKNOWN
    user_influence: str = "UNKNOWN"
    mutability: str = "UNKNOWN"
    synchronization_held: bool | None = None
    non_persistence: str = "UNPROVEN"
    missing_artifact: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def classify(evidence: R27Evidence) -> tuple[str, str, list[str]]:
    """§18: R27-A only when the writer, the user influence, the target set and the path all hold."""

    blockers: list[str] = []
    if evidence.mutability in ("IMMUTABLE_AFTER_INIT", "KERNEL_CONTROLLED"):
        return R27_B, "field_f8 is init-only/immutable: candidate disproved", blockers
    if evidence.synchronization_held is True:
        return R27_C, "synchronization prevents mutation between the reads: race disproved", blockers
    if evidence.table_init == "RUNTIME":
        blockers.append("the ops table is runtime-initialised: its target set is not statically enumerable")
    if evidence.target_set_ambiguous:
        blockers.append(f"the target set is ambiguous ({len(evidence.target_set)} candidates): never collapsed to one")
    if not evidence.field_f8_writer:
        blockers.append("no field_f8 writer identified in the object family")
    if evidence.user_influence not in ("USER_CONTROLLED", "USER_INFLUENCED"):
        blockers.append(f"user influence not established ({evidence.user_influence})")
    if not evidence.root_to_candidate_link:
        blockers.append("no proven path from the gc_ioctl root to the candidate")
    if evidence.non_persistence == "UNPROVEN":
        blockers.append("non-persistence of the fixed path unproven")
    if evidence.missing_artifact:
        return R27_E, f"target sets remain unresolved: {evidence.missing_artifact}", blockers
    if blockers:
        return R27_D, "target set resolved but user influence still unknown: PLAN_ONLY", blockers
    return R27_A, "ioctl root, user influence, real writer, unprotected mutable field, C3 consumer, volatile path", []
