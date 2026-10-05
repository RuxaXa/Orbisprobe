"""M2-LIVE2.9 — runtime layout reclassification: target tiers, string-pointer detection, R29.

Correction that drives this module: on x86-64 a code pointer does **not** have to be 8-byte aligned, so
alignment alone must never decide a target's class. The decision is made from evidence:

* membership in the set of known instruction boundaries (mid-instruction addresses are invalid)
* membership in the set of known function starts (strict tier) or basic-block starts (block tier)
* whether the bytes behind the target are *data* (printable string content) rather than code

Security-relevant claims must therefore always name the tier they rely on.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

FUNCTION_ENTRY_CONFIRMED = "FUNCTION_ENTRY_CONFIRMED"
EXECUTABLE_CODE_TARGET = "EXECUTABLE_CODE_TARGET"
INTERNAL_BLOCK_TARGET = "INTERNAL_BLOCK_TARGET"
THUNK_TARGET = "THUNK_TARGET"
MID_INSTRUCTION_INVALID = "MID_INSTRUCTION_INVALID"
DATA_NOT_CODE = "DATA_NOT_CODE"
TARGET_UNKNOWN = "TARGET_UNKNOWN"

#: the two validator levels (§4)
STRICT_FUNCTION_TARGET = "STRICT_FUNCTION_TARGET"
VALID_EXECUTABLE_TARGET = "VALID_EXECUTABLE_TARGET"
NOT_A_TARGET = "NOT_A_TARGET"

R29_A = "R29-A"
R29_B = "R29-B"
R29_C = "R29-C"
R29_D = "R29-D"
R29_E = "R29-E"

PRINTABLE_MIN = 0x20
PRINTABLE_MAX = 0x7E


def looks_like_string(data: bytes, minimum_ratio: float = 0.85) -> tuple[bool, str]:
    """§2/§3: bytes that are printable ASCII (optionally NUL-terminated) are data, not code."""

    if not data:
        return False, "no bytes"
    sample = data.split(b"\x00", 1)[0] or data[:8]
    printable = sum(1 for byte in sample if PRINTABLE_MIN <= byte <= PRINTABLE_MAX)
    ratio = printable / max(1, len(sample))
    text = sample.decode("latin-1")
    if ratio >= minimum_ratio and printable >= 4:
        return True, f"printable ASCII {text!r} (ratio {ratio:.2f})"
    return False, f"not printable (ratio {ratio:.2f})"


def classify_target(address: int, *, kernel_base: int, kernel_text_end: int,
                    instruction_boundaries: set[int], function_starts: set[int],
                    block_starts: set[int] | None = None, thunks: set[int] | None = None,
                    target_bytes: bytes = b"") -> tuple[str, str, str]:
    """Return (tier, tier_level, reason). Alignment is deliberately not consulted."""

    if not kernel_base <= address < kernel_text_end:
        return TARGET_UNKNOWN, NOT_A_TARGET, "outside the kernel text range"
    is_string, why = looks_like_string(target_bytes)
    if is_string and address not in function_starts:
        return DATA_NOT_CODE, NOT_A_TARGET, f"target bytes are data: {why}"
    if instruction_boundaries and address not in instruction_boundaries:
        return MID_INSTRUCTION_INVALID, NOT_A_TARGET, "address is inside an instruction"
    if address in function_starts:
        return FUNCTION_ENTRY_CONFIRMED, STRICT_FUNCTION_TARGET, "known function entry"
    if thunks and address in thunks:
        return THUNK_TARGET, VALID_EXECUTABLE_TARGET, "documented thunk"
    if block_starts and address in block_starts:
        return INTERNAL_BLOCK_TARGET, VALID_EXECUTABLE_TARGET, "known basic-block/label entry"
    if address in instruction_boundaries or not instruction_boundaries:
        return EXECUTABLE_CODE_TARGET, VALID_EXECUTABLE_TARGET, "valid instruction boundary in executable code"
    return TARGET_UNKNOWN, NOT_A_TARGET, "no boundary evidence"


def reinterpret_window(raw: bytes, *, base_offset: int, kernel_base: int, kernel_text_end: int,
                       dump_base: int, live_base: int) -> list[dict[str, Any]]:
    """§11: reinterpret a raw runtime window byte-wise and as rebased pointers."""

    rows: list[dict[str, Any]] = []
    for index in range(0, len(raw) - (len(raw) % 8), 8):
        chunk = raw[index:index + 8]
        value = int.from_bytes(chunk, "little")
        is_string, why = looks_like_string(chunk)
        row: dict[str, Any] = {
            "offset": f"0x{base_offset + index:x}", "raw": chunk.hex(),
            "u64": f"0x{value:x}", "u32": f"0x{int.from_bytes(chunk[:4], 'little'):x}",
            "string_in_field": is_string, "string_reason": why,
        }
        if kernel_base <= value < kernel_text_end or value > 0xFFFF800000000000:
            dump_va = value - (live_base - dump_base)
            row["rebased_to_dump"] = f"0x{dump_va:x}"
            row["target_hint"] = ("data" if is_string else "kernel address")
        rows.append(row)
    return rows


def derive_access_width(instruction: str) -> int | None:
    """§5: the field width comes from the instruction's operand size, not from an assumed raster."""

    lowered = instruction.lower()
    for needle, width in (("qword ptr", 8), ("dword ptr", 4), ("word ptr", 2), ("byte ptr", 1)):
        if needle in lowered:
            return width
    if " mov " in f" {lowered} " or lowered.startswith("mov "):
        return 8   # register-to-register form: 64-bit default on this target
    return None


def access_matrix(entries: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    """Group recorded static accesses per offset with widths and access kinds."""

    matrix: dict[str, dict[str, Any]] = {}
    for entry in entries:
        offset = entry.get("offset") or ""
        matrix.setdefault(offset, {"accesses": 0, "widths": set(), "read": 0, "write": 0,
                                  "call_jmp": 0, "compare": 0, "examples": []})
        cell = matrix[offset]
        cell["accesses"] += 1
        instruction = str(entry.get("instruction", ""))
        width = derive_access_width(instruction)
        if width:
            cell["widths"].add(width)
        upper = instruction.upper()
        if "CALL" in upper or "JMP" in upper:
            cell["call_jmp"] += 1
        elif "CMP" in upper or "TEST" in upper:
            cell["compare"] += 1
        elif "," in instruction and instruction.split(",", 1)[0].strip().upper().startswith(("MOV", "LEA")):
            cell["write"] += 1 if "[" in instruction.split(",", 1)[0] else 0
            cell["read"] += 0 if "[" in instruction.split(",", 1)[0] else 1
        if len(cell["examples"]) < 3:
            cell["examples"].append(instruction)
    for cell in matrix.values():
        cell["widths"] = sorted(cell["widths"])
    return matrix


@dataclass
class R29Evidence:
    candidate_id: str = "RC-001"
    callback_layout_disproved: bool = False
    callback_registration_state: str = "UNKNOWN"     # BOOT_OPTIONAL / DEVICE_INIT / CONTEXT_INIT /
                                                     # TASKLET_REGISTRATION / REQUEST_DEPENDENT / UNKNOWN
    neighbour_target_classes: dict[str, str] = field(default_factory=dict)
    neighbour_values_are_data: bool = False
    mixed_struct: bool = False
    window_from_expected_struct: bool = True
    alignment_rule_retracted: bool = True

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def classify(evidence: R29Evidence) -> tuple[str, str, list[str]]:
    """§12 outcomes for the reclassification."""

    notes: list[str] = []
    if evidence.callback_layout_disproved:
        return R29_B, "the static field boundary for +0x21850 was shown to be wrong", notes
    if not evidence.window_from_expected_struct:
        return R29_D, "the runtime window does not come from the modelled structure", notes
    data_neighbours = evidence.neighbour_values_are_data or any(
        value == DATA_NOT_CODE for value in evidence.neighbour_target_classes.values())
    if evidence.mixed_struct and data_neighbours:
        notes.append("the neighbouring fields are data pointers (name strings), the callback slot is a code pointer")
        notes.append(f"callback registration state: {evidence.callback_registration_state}")
        if evidence.alignment_rule_retracted:
            notes.append("the alignment-only rejection from LIVE2.8 is retracted")
        return R29_C, ("the 0x218xx area is a mixed structure: data pointers to name strings next to a "
                       "callback code-pointer slot and scalars; the +0x21850 layout stands, the runtime "
                       "snapshot merely shows it unregistered"), notes
    if data_neighbours and not evidence.mixed_struct:
        return R29_A, "the callback layout is confirmed; the runtime values were simply unregistered/neighbouring data", notes
    return R29_E, "still unresolved with the available evidence", notes
