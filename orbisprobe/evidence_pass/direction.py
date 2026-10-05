"""Byte-level derivation of copy directions.

The Scratch finding class was a *labelling* error: a copy event was described with the source
and destination swapped while the pinned bytes said otherwise. Verifying such a claim by
string-pinning the corrected sentence does not close the class, so this module derives the
direction from the pinned bytes and compares the derived expression with the recorded label.

It decodes only the small instruction subset used by the recorded pins:

* ``REX.W 8B /r`` with a memory operand  -> ``mov reg, [base+disp]`` (argument/field loads)
* ``REX.W 89 /r`` with mod=11            -> ``mov reg, reg``        (argument binders)

The helper's own convention is derived from its body (``xchg rdi, rsi`` followed by a
``rep movsq rdi, rsi`` means the first argument is read and the second is written).
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from .model import closed_schema, require_hex_bytes, require_text

REGISTER_NAMES = {
    0: "rax",
    1: "rcx",
    2: "rdx",
    3: "rbx",
    4: "rsp",
    5: "rbp",
    6: "rsi",
    7: "rdi",
    8: "r8",
    9: "r9",
    10: "r10",
    11: "r11",
    12: "r12",
    13: "r13",
    14: "r14",
    15: "r15",
}
ARGUMENT_REGISTERS = {"arg1": "rdi", "arg2": "rsi", "arg3": "rdx"}
FIRST_ARGUMENT_IS_SOURCE_BYTES = "4887f7"  # xchg rdi, rsi
COPY_LOOP_BYTES = "f348a5"  # rep movsq rdi, rsi


@dataclass(frozen=True)
class Load:
    """``mov register, [base+disp]`` or a register move recorded during decoding."""

    register: str
    base: str | None
    disp: int
    kind: str  # "load" | "move"

    @property
    def expression(self) -> str:
        if self.kind == "move":
            return f"={self.base}"
        if self.base is None:
            return f"[{self.disp:#x}]"
        return f"{self.base}+{self.disp:#x}"


def _decode(payload: bytes) -> tuple[Load, ...]:
    decoded: list[Load] = []
    index = 0
    while index + 2 < len(payload):
        rex = payload[index]
        if rex & 0xF8 != 0x48 or not rex & 0x08:  # require REX.W
            index += 1
            continue
        opcode = payload[index + 1]
        if opcode not in (0x8B, 0x89):
            index += 1
            continue
        modrm = payload[index + 2]
        mod = modrm >> 6
        reg = REGISTER_NAMES[((modrm >> 3) & 7) | ((rex & 4) << 1)]
        rm_index = (modrm & 7) | ((rex & 1) << 3)
        if mod == 3:
            if opcode == 0x8B:  # mov r64, r/m64: destination is the reg field
                destination, source = reg, REGISTER_NAMES[rm_index]
            else:  # mov r/m64, r64: destination is the r/m field
                destination, source = REGISTER_NAMES[rm_index], reg
            decoded.append(Load(register=destination, base=source, disp=0, kind="move"))
            index += 3
            continue
        if mod == 0 and (modrm & 7) == 5:  # rip-relative, not used by the recorded pins
            index += 7
            continue
        if mod == 1:
            disp = int.from_bytes(payload[index + 3 : index + 4], "little", signed=True)
            length = 4
        elif mod == 2:
            disp = int.from_bytes(payload[index + 3 : index + 7], "little", signed=True)
            length = 7
        else:
            disp = 0
            length = 3
        if opcode == 0x8B:
            decoded.append(Load(register=reg, base=REGISTER_NAMES[rm_index], disp=disp, kind="load"))
        else:
            decoded.append(Load(register=REGISTER_NAMES[rm_index], base=reg, disp=disp, kind="load"))
        index += length
    return tuple(decoded)


def helper_first_argument_is_source(helper_bytes: str) -> bool:
    """Derive the helper convention from its body, never from documentation."""

    payload = bytes.fromhex(helper_bytes)
    return FIRST_ARGUMENT_IS_SOURCE_BYTES in payload.hex() and COPY_LOOP_BYTES in payload.hex()


def argument_bindings(binder_bytes: str) -> dict[str, str]:
    """Map registers to handler arguments, e.g. ``49 89 f6`` -> ``{"r14": "arg2"}``."""

    bindings: dict[str, str] = {}
    for load in _decode(bytes.fromhex(binder_bytes)):
        if load.kind != "move" or load.base not in ARGUMENT_REGISTERS.values():
            continue
        for argument, register in ARGUMENT_REGISTERS.items():
            if load.base == register:
                bindings[load.register] = argument
    return bindings


def _value_expressions(payload: bytes, roles: dict[str, str]) -> dict[str, str]:
    """Resolve register values to machine expressions using derived argument roles."""

    expressions = dict(roles)
    for _ in range(4):  # small fixed-point iteration: loads may reference earlier loads
        for load in _decode(payload):
            if load.kind != "load" or load.base is None:
                continue
            if load.register in roles or load.base not in expressions:
                continue
            base_expression = expressions[load.base]
            if load.base in roles:
                expression = f"{base_expression}+{load.disp:#x}"
            else:
                expression = f"*({base_expression})+{load.disp:#x}"
            expressions[load.register] = expression
    return expressions


def derive_copy_direction(entry: dict[str, Any]) -> tuple[str, str, str]:
    """Derive (source, destination, length) expressions for one recorded copy event."""

    helper_bytes = require_text("helper_bytes", entry["helper_bytes"])
    pin_bytes = require_text("pinned_bytes", entry["pinned_bytes"])
    if not helper_first_argument_is_source(helper_bytes):
        raise ValueError("helper body does not show the first argument being read")
    roles = argument_bindings(require_text("binder_bytes", entry["binder_bytes"]))
    argument_names = entry["argument_names"]
    if not isinstance(argument_names, dict) or not argument_names:
        raise TypeError("CopyEvent.argument_names must be a non-empty object")
    resolved = {register: argument_names[argument] for register, argument in roles.items()}
    values = _value_expressions(bytes.fromhex(pin_bytes), resolved)
    source = values.get(ARGUMENT_REGISTERS["arg1"])
    destination = values.get(ARGUMENT_REGISTERS["arg2"])
    length = values.get(ARGUMENT_REGISTERS["arg3"])
    if source is None or destination is None or length is None:
        raise ValueError("pinned bytes do not load the helper's three argument registers")
    return source, destination, length


IDENTIFIER_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
OFFSET_RE = re.compile(r"[+-]0x[0-9a-fA-F]+")


def _expression_roles(expression: str) -> set[str]:
    """Operand role identifiers of a machine expression, ignoring its offset fragments."""

    return set(IDENTIFIER_RE.findall(OFFSET_RE.sub("", expression)))


def _name_role_problems(expression: str, name: str, roles: set[str]) -> list[str]:
    """A field name may only describe the operand role the pinned bytes proved."""

    required = _expression_roles(expression)
    problems: list[str] = []
    if not required:
        problems.append(f"cannot derive an operand role from the pinned expression {expression!r}")
    missing = sorted(token for token in required if token not in name)
    if missing:
        problems.append(
            f"field name {name!r} does not name the operand role(s) {missing} of {expression!r}"
        )
    foreign = sorted(token for token in roles - required if token in name)
    if foreign:
        problems.append(
            f"field name {name!r} names unrelated operand role(s) {foreign} for {expression!r}"
        )
    return problems


def check_copy_events(payload: object) -> tuple[list[str], int]:
    """Return (problems, checked_count) for the package's recorded copy-direction claims."""

    problems: list[str] = []
    checked = 0
    try:
        data = closed_schema("CopyEvents", payload, {"copies"})
        copies = data["copies"]
        if not isinstance(copies, list):
            raise TypeError("CopyEvents.copies must be a list")
    except (TypeError, ValueError) as exc:
        return [f"unreadable copy-event record: {exc}"], 0

    for index, entry in enumerate(copies):
        try:
            record = closed_schema(
                "CopyEvent",
                entry,
                {
                    "name",
                    "function",
                    "callsite",
                    "label",
                    "pinned_bytes",
                    "helper_bytes",
                    "binder_bytes",
                    "argument_names",
                    "field_names",
                },
            )
            for key in ("pinned_bytes", "helper_bytes", "binder_bytes"):
                require_hex_bytes(f"CopyEvent.{key}", record[key])
            field_names = record["field_names"]
            if not isinstance(field_names, dict) or not field_names:
                raise TypeError("CopyEvent.field_names must be a non-empty object")
            argument_names = record["argument_names"]
            if not isinstance(argument_names, dict) or not argument_names:
                raise TypeError("CopyEvent.argument_names must be a non-empty object")
            source, destination, length = derive_copy_direction(record)
        except (KeyError, TypeError, ValueError) as exc:
            problems.append(f"copy event {index}: {exc}")
            continue

        roles = {require_text("CopyEvent.argument_names value", role) for role in argument_names.values()}
        try:
            source_name = require_text("field_names", field_names[source])
            destination_name = require_text("field_names", field_names[destination])
            length_name = require_text("field_names", field_names[length])
        except KeyError as exc:
            problems.append(f"copy event {record['name']}: no field name recorded for {exc}")
            continue

        # The bytes decide which operand is read and which is written; the recorded names may
        # only describe that proven operand, never redefine it (a consistently inverted record
        # must fail here even when label and names agree with each other).
        for expression, name in (
            (source, source_name),
            (destination, destination_name),
            (length, length_name),
        ):
            problems.extend(
                f"copy event {record['name']}: {problem}"
                for problem in _name_role_problems(expression, name, roles)
            )
        if len({source_name, destination_name, length_name}) != 3:
            problems.append(f"copy event {record['name']}: operand field names must be distinct")

        expected = f"bcopy({source_name} -> {destination_name}, {length_name})"
        label = require_text("CopyEvent.label", record["label"])
        checked += 1
        if expected not in label:
            problems.append(
                f"copy event {record['name']}: label {label!r} contradicts the pinned bytes "
                f"(expected {expected!r} from {source!r} -> {destination!r})"
            )
    return problems, checked
