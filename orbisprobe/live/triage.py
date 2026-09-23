"""Candidate triage with structured consumer resolution (campaign v2).

Consumer evidence is taken from the disassembly reference model (Ghidra ``direct_calls`` / call flows), never
from regular expressions over decompiled C -- that method was retracted as unsound (it matched the candidate's
own symbol and produced false positives).
"""

from __future__ import annotations

import dataclasses
import re

CALL_REGISTERS = {"rdi": 1, "rsi": 2, "rdx": 3, "rcx": 4, "r8": 5, "r9": 6}
PARAMETERS = ("param_1", "param_2", "param_3", "param_4", "param_5", "param_6")
CONSUMER_CLASSES = ("C1", "C2", "C3", "C4")
STAGES = ("A", "B", "C", "D", "E")
_STORE = re.compile(r"^0x[0-9a-f]+ mov (?:qword|dword|word|byte) ptr \[")
_STORE_DEST = re.compile(r"\[(\w+)\s*(?:[+\-]\s*0x[0-9a-f]+)?\],")
_STORE_SRC = re.compile(r"\[(\w+)")


def field_is_reread(read_1: str, read_2: str, field: str) -> bool:
    """True when the same struct field offset is named by both recorded reads."""
    if not field:
        return False
    needle = field.replace(" ", "")
    return needle in (read_1 or "").replace(" ", "") and needle in (read_2 or "").replace(" ", "")


def consumer_kind(record: dict) -> str:
    """call-direct | call-indirect | store | unknown -- derived from structured evidence only."""
    if record.get("callee"):
        return "call-direct"
    if record.get("indirect_callsite"):
        return "call-indirect"
    if _STORE.match(record.get("consumer_instruction") or ""):
        return "store"
    return "unknown"


def store_consumer_class(record: dict) -> tuple[str, list[str]]:
    """A store into a different object is a memory/state consumer (C3); otherwise unresolved (C4)."""
    src = _STORE_SRC.search(record.get("read_1") or "")
    dest = _STORE_DEST.search(record.get("consumer_instruction") or "")
    if src and dest and src.group(1) != dest.group(1):
        return "C3", [f"field value is stored into another object (dest base {dest.group(1)} != source base {src.group(1)})"]
    if dest and dest.group(1) in ("rax", "rcx", "r8", "r9", "r10", "r11"):
        return "C3", ["field value written through a call-clobbered destination register"]
    return "C4", ["store consumer without a resolved destination object"]


def resolve_consumer(record: dict, calls: dict[str, str]) -> tuple[str, int, str, bool]:
    """Return (callsite, callee_target, argument_register, is_indirect) for the consumer instruction."""
    text = record.get("consumer_instruction") or ""
    site = text.split()[0] if text.startswith("0x") else ""
    target = int(calls[site], 16) if site and site in (calls or {}) else 0
    register = ""
    match = re.search(r"call with (\w+) =", text)
    if match:
        register = match.group(1)
    indirect = bool(site) and site in (record.get("indirect_call_sites") or [])
    return site, target, register, indirect


def classify_consumer(callee_c: str, register: str, classifier) -> tuple[str, list[str]]:
    """Classify the consumer body for the register/parameter that received the field value."""
    if not callee_c:
        return "C4", ["callee body unavailable"]
    order = ([PARAMETERS[CALL_REGISTERS[register] - 1]] if register in CALL_REGISTERS else []) + list(PARAMETERS)
    for name in order:
        klass, reasons = classifier(callee_c, name)
        if klass != "C4":
            return klass, [f"{name}: {reason}" for reason in reasons][:3]
    return "C4", ["no semantic use of the argument parameter in the callee body"]


@dataclasses.dataclass
class GateResult:
    stage: str
    gate: str
    status: str
    blocker: str

    @property
    def survivor(self) -> bool:
        return self.gate == "SURVIVOR"


def funnel(record: dict) -> GateResult:
    """Stages A-E of the campaign funnel; only C2/C3 consumers survive."""
    if not record.get("cfg_confirmed"):
        return GateResult("A", "DOWNGRADE", "DISPROVED", "not a CFG-confirmed function")
    if not field_is_reread(record.get("read_1", ""), record.get("read_2", ""), record.get("field", "")):
        return GateResult("B", "DOWNGRADE", "DISPROVED", "same mutable field not corroborated across the reads")
    if not record.get("validation"):
        return GateResult("C", "DOWNGRADE", "DISPROVED", "no validation between the reads")
    if consumer_kind(record) == "unknown":
        return GateResult("D", "DOWNGRADE", "PARKED", "no structured consumer evidence (neither call nor store)")
    if record.get("consumer_class") not in ("C2", "C3"):
        return GateResult("D", "DOWNGRADE", "PARKED",
                          f"consumer class {record.get('consumer_class')} (log/compare only)")
    return GateResult("E", "SURVIVOR", "TRIAGE", "")
