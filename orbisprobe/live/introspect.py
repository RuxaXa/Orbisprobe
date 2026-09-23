"""M2-LIVE2.8 - read-only runtime introspection: address classes, pointer sanity, target validation.

Everything here exists to make a *read* decision, never an action decision:

* every address is classified before it is dereferenced; MMIO and unknown classes are hard blocks
* pointers are only followed when canonical, aligned and inside a class we are allowed to read
* a pointer from a previous boot is rejected: the kernel is rebased per boot, so an address derived from
  a stale KBASE must never be dereferenced
* a function-pointer target is only accepted when it lies inside the kernel text range and on a known
  function boundary; data addresses are never promoted to targets
* reads are bounded (default 0x100 bytes); there is no heap or kernel-wide dump
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

KERNEL_TEXT = "KERNEL_TEXT"
KERNEL_DATA = "KERNEL_DATA"
KERNEL_HEAP = "KERNEL_HEAP"
DIRECT_MAP = "DIRECT_MAP"
USER = "USER"
MMIO = "MMIO"
UNKNOWN = "UNKNOWN"

READABLE = (KERNEL_TEXT, KERNEL_DATA, KERNEL_HEAP, DIRECT_MAP)

CALLBACK_TARGET_CONFIRMED = "CALLBACK_TARGET_CONFIRMED"
CALLBACK_TARGET_SUPPORTED = "CALLBACK_TARGET_SUPPORTED"
INVALID_POINTER = "INVALID_POINTER"
TARGET_UNKNOWN = "UNKNOWN"

R28_A = "R28-A"
R28_B = "R28-B"
R28_C = "R28-C"
R28_D = "R28-D"

MMIO_RANGE = (0x00000000C0000000, 0x0000010000000000)
DIRECT_MAP_RANGE = (0xFFFFFF8000000000, 0xFFFFFFC000000000)
USER_MAX = 0x0000800000000000
MAX_READ = 0x100


def is_canonical(address: int) -> bool:
    high = address >> 48
    return high in (0x0000, 0xFFFF)


def classify_address(address: int, *, kernel_base: int, kernel_text_end: int, kernel_image_end: int) -> str:
    if not is_canonical(address) or address == 0:
        return UNKNOWN
    if MMIO_RANGE[0] <= address < MMIO_RANGE[1]:
        return MMIO
    if address < USER_MAX:
        return USER
    if DIRECT_MAP_RANGE[0] <= address < DIRECT_MAP_RANGE[1]:
        return DIRECT_MAP
    if kernel_base <= address < kernel_image_end:
        return KERNEL_TEXT if address < kernel_text_end else KERNEL_DATA
    return UNKNOWN


def rebound_object_address(object_static_va: int, *, dump_base: int, live_base: int) -> int:
    return object_static_va + (live_base - dump_base)


def pointer_sanity(value: int, *, kernel_base: int, kernel_text_end: int, kernel_image_end: int,
                   expected_class: str | None = None) -> tuple[bool, str, str]:
    if value == 0:
        return False, "null pointer", UNKNOWN
    if not is_canonical(value):
        return False, "not canonical", UNKNOWN
    if value % 8 != 0:
        return False, "not 8-byte aligned", UNKNOWN
    klass = classify_address(value, kernel_base=kernel_base, kernel_text_end=kernel_text_end,
                             kernel_image_end=kernel_image_end)
    if klass in (MMIO, UNKNOWN):
        return False, f"class {klass} is blocked", klass
    if expected_class == KERNEL_TEXT:
        if klass != KERNEL_TEXT:
            return False, f"expected {KERNEL_TEXT}, got {klass}", klass
        return True, "executable kernel text", klass
    if klass == USER:
        return False, "user address rejected for kernel introspection", klass
    return True, f"readable class {klass}", klass


def stale_boot_rejection(address: int, *, pointer_boot_base: int, current_boot_base: int) -> tuple[bool, str]:
    if pointer_boot_base != current_boot_base:
        return False, (f"pointer belongs to boot base 0x{pointer_boot_base:x}, current boot is "
                       f"0x{current_boot_base:x}: stale boot pointer refused")
    return True, "pointer matches the current boot base"


def bounded_read_length(requested: int, limit: int = MAX_READ) -> tuple[int, bool]:
    if requested <= 0:
        raise ValueError("read length must be positive")
    return (requested, False) if requested <= limit else (limit, True)


def validate_function_target(address: int, *, kernel_base: int, kernel_text_end: int,
                             function_starts: set[int], thunks: set[int] | None = None) -> tuple[str, str]:
    if not is_canonical(address):
        return INVALID_POINTER, "not canonical"
    if not (kernel_base <= address < kernel_text_end):
        return INVALID_POINTER, "outside the kernel text range"
    if address in function_starts:
        return CALLBACK_TARGET_CONFIRMED, "exact Ghidra function start"
    if thunks and address in thunks:
        return CALLBACK_TARGET_SUPPORTED, "documented thunk"
    return TARGET_UNKNOWN, "inside text but not a known function boundary"


def entry_model_check(static_expression: str, runtime_expression: str) -> tuple[bool, str]:
    if static_expression.replace(" ", "") == runtime_expression.replace(" ", ""):
        return True, "entry arithmetic consistent"
    return False, (f"entry arithmetic differs: static {static_expression!r} vs runtime "
                   f"{runtime_expression!r} -> model revision required")


@dataclass
class ReadRecord:
    address: str
    length: int
    klass: str
    sha256: str
    preview: str
    parsed: dict[str, Any] = field(default_factory=dict)
    timestamp: str = ""


@dataclass
class R28Evidence:
    candidate_id: str = "RC-001"
    boot_base: int = 0
    anchor_address: str = ""
    anchor_value: str = ""
    context_readable: bool = False
    context_window: dict[str, str] = field(default_factory=dict)
    callback_target: str = ""
    callback_class: str = TARGET_UNKNOWN
    table_pointer: str = ""
    entry_0x12_target: str = ""
    entry_target_class: str = TARGET_UNKNOWN
    neighbor_entries: dict[str, str] = field(default_factory=dict)
    rc001_object: str = ""
    rc001_fields: dict[str, str] = field(default_factory=dict)
    snapshots: int = 0
    changed_between_snapshots: list[str] = field(default_factory=list)
    model_consistent: bool = True
    blocker: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def classify(evidence: R28Evidence) -> tuple[str, str, list[str]]:
    notes: list[str] = []
    if not evidence.context_readable:
        return R28_D, f"runtime pointers unavailable/unreadable: {evidence.blocker or 'context not readable'}", notes
    if not evidence.model_consistent:
        return R28_B, "runtime values contradict the static model: revision required", notes
    if evidence.entry_target_class == CALLBACK_TARGET_CONFIRMED and evidence.rc001_object:
        return R28_A, "runtime table entry and the RC-001 object chain resolved", notes
    if evidence.rc001_object:
        return R28_C, "runtime object resolved but user influence still unknown: continue offline", notes
    if not evidence.entry_target_class or evidence.entry_target_class == TARGET_UNKNOWN:
        notes.append("table entry target not resolved to a function boundary")
    return R28_C, "runtime context resolved but the object chain is incomplete", notes
