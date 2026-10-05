"""Serializable function-harness model and validation.

The harness is the central M2-B artifact: it fully describes one bounded offline function
execution. It is validated before anything is executed, it is hash-bound so a run can never be
re-attributed to a different harness, and it never carries executable code — callee behaviour is a
name resolved against :mod:`orbisprobe.harness.registry`.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

from .registry import resolve_stub

CALLING_CONVENTIONS = ("sysv-amd64",)
SUPPORTED_SCHEMA_VERSION = "m2b-harness-v1"
HARNESS_KEYS = frozenset(
    {
        "schema_version",
        "harness_id",
        "binary_sha256",
        "architecture",
        "base",
        "function_entry",
        "function_end",
        "calling_convention",
        "initial_registers",
        "stack_base",
        "stack_size",
        "memory_regions",
        "input_regions",
        "output_regions",
        "taint_sources",
        "expected_sinks",
        "callee_stubs",
        "stop_conditions",
        "instruction_limit",
        "branch_limit",
        "max_symbolic_expressions",
        "max_trace_entries",
        "max_call_depth",
        "max_internal_calls",
        "timeout_seconds",
        "notes",
    }
)
MEMORY_REGION_KEYS = frozenset(
    {"name", "base", "size", "permissions", "source", "initial_data"}
)
ADDRESSED_REGION_KEYS = frozenset({"name", "address", "size"})
INPUT_REGION_KEYS = ADDRESSED_REGION_KEYS | {"concrete_value", "symbolic", "tainted", "symbolic_name"}
TAINT_SOURCE_KEYS = frozenset({"kind", "label", "register", "address", "size"})
EXPECTED_SINK_KEYS = frozenset({"sink_type", "label", "address", "size", "register"})
CALLEE_STUB_KEYS = frozenset(
    {"target", "name", "behavior", "return_value", "register_effects", "memory_effects"}
)
MEMORY_EFFECT_KEYS = frozenset({"kind", "address", "size"})
STOP_CONDITION_KEYS = frozenset({"kind", "address"})
GENERAL_REGISTERS = (
    "rax",
    "rbx",
    "rcx",
    "rdx",
    "rsi",
    "rdi",
    "rbp",
    "rsp",
    "r8",
    "r9",
    "r10",
    "r11",
    "r12",
    "r13",
    "r14",
    "r15",
    "rip",
)
STOP_KINDS = ("ADDRESS", "INSTRUCTION_LIMIT", "BRANCH_LIMIT", "RETURN", "UNMAPPED", "STUB_REQUIRED")
MEMORY_EFFECT_KINDS = ("WRITE", "READ", "NONE")
SOURCE_KINDS = ("register", "memory")
MAX_TIMEOUT_SECONDS = 300


#: Stable error code for any harness that fails schema or semantic validation.
HARNESS_INVALID = "HARNESS_INVALID"


class HarnessError(ValueError):
    code = HARNESS_INVALID

    def __init__(self, errors: list[str]) -> None:
        super().__init__("; ".join(errors))
        self.errors = errors

    def to_dict(self) -> dict[str, Any]:
        return {"code": self.code, "errors": list(self.errors)}


class SinkType(str, Enum):
    MEMORY_ADDRESS = "MEMORY_ADDRESS"
    MEMORY_LENGTH = "MEMORY_LENGTH"
    ARRAY_INDEX = "ARRAY_INDEX"
    BRANCH_CONDITION = "BRANCH_CONDITION"
    DESCRIPTOR_FIELD = "DESCRIPTOR_FIELD"
    DMA_ADDRESS = "DMA_ADDRESS"
    SERVICE_SELECTOR = "SERVICE_SELECTOR"
    RETURN_VALUE = "RETURN_VALUE"
    UNKNOWN = "UNKNOWN"


@dataclass(frozen=True)
class MemoryRegion:
    name: str
    base: int
    size: int
    permissions: str
    source: str = "literal"
    initial_data: str | None = None

    @property
    def end(self) -> int:
        return self.base + self.size


@dataclass(frozen=True)
class InputRegion:
    name: str
    address: int
    size: int
    concrete_value: str | None = None
    symbolic: bool = False
    tainted: bool = False
    symbolic_name: str | None = None


@dataclass(frozen=True)
class OutputRegion:
    name: str
    address: int
    size: int


@dataclass(frozen=True)
class TaintSource:
    kind: str
    label: str
    register: str | None = None
    address: int | None = None
    size: int | None = None


@dataclass(frozen=True)
class CalleeStub:
    target: int
    name: str
    behavior: str
    return_value: int | None = None
    register_effects: dict[str, int] = field(default_factory=dict)
    memory_effects: list[dict[str, Any]] = field(default_factory=list)


@dataclass(frozen=True)
class StopCondition:
    kind: str
    address: int | None = None


@dataclass(frozen=True)
class Harness:
    harness_id: str
    binary_sha256: str
    architecture: str
    base: int
    function_entry: int
    function_end: int
    calling_convention: str
    memory_regions: tuple[MemoryRegion, ...]
    input_regions: tuple[InputRegion, ...] = ()
    output_regions: tuple[OutputRegion, ...] = ()
    taint_sources: tuple[TaintSource, ...] = ()
    expected_sinks: tuple[dict[str, Any], ...] = ()
    callee_stubs: tuple[CalleeStub, ...] = ()
    stop_conditions: tuple[StopCondition, ...] = ()
    initial_registers: dict[str, int] = field(default_factory=dict)
    stack_base: int | None = None
    stack_size: int = 0
    instruction_limit: int = 4096
    branch_limit: int = 256
    max_symbolic_expressions: int = 8192
    max_trace_entries: int = 4096
    max_call_depth: int = 8
    max_internal_calls: int = 256
    timeout_seconds: int = 60
    notes: str | None = None

    def normalized(self) -> dict[str, Any]:
        """Canonical document used for hashing and for the cache key."""

        return {
            "harness_id": self.harness_id,
            "binary_sha256": self.binary_sha256,
            "architecture": self.architecture,
            "base": self.base,
            "function_entry": self.function_entry,
            "function_end": self.function_end,
            "calling_convention": self.calling_convention,
            "initial_registers": dict(sorted(self.initial_registers.items())),
            "stack_base": self.stack_base,
            "stack_size": self.stack_size,
            "memory_regions": [asdict(item) for item in self.memory_regions],
            "input_regions": [asdict(item) for item in self.input_regions],
            "output_regions": [asdict(item) for item in self.output_regions],
            "taint_sources": [asdict(item) for item in self.taint_sources],
            "expected_sinks": [dict(sorted(item.items())) for item in self.expected_sinks],
            "callee_stubs": [asdict(item) for item in self.callee_stubs],
            "stop_conditions": [asdict(item) for item in self.stop_conditions],
            "instruction_limit": self.instruction_limit,
            "branch_limit": self.branch_limit,
            "max_symbolic_expressions": self.max_symbolic_expressions,
            "max_trace_entries": self.max_trace_entries,
            "max_call_depth": self.max_call_depth,
            "max_internal_calls": self.max_internal_calls,
            "timeout_seconds": self.timeout_seconds,
            "notes": self.notes,
        }

    @property
    def harness_sha256(self) -> str:
        raw = json.dumps(
            self.normalized(), sort_keys=True, separators=(",", ":"), allow_nan=False
        ).encode("utf-8")
        return hashlib.sha256(raw).hexdigest()

    def to_dict(self) -> dict[str, Any]:
        return {**self.normalized(), "harness_sha256": self.harness_sha256}


def _is_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _reject_unknown_keys(
    raw: dict[str, Any],
    allowed: frozenset[str],
    path: str,
    errors: list[str],
) -> None:
    """Fail closed on any key the frozen B1 schema does not define.

    A misspelled key would otherwise be silently ignored, leaving the harness weaker than its
    author intended (for example a typo in ``taint_sources`` or ``callee_stubs``).
    """

    unknown = sorted(set(raw) - allowed)
    if unknown:
        errors.append(f"{path} has unknown keys: {unknown}")


def _parse_int(value: Any, path: str, errors: list[str], minimum: int = 0) -> int | None:
    if not _is_int(value) or value < minimum:
        errors.append(f"{path} must be an integer >= {minimum}")
        return None
    if value > 0xFFFFFFFFFFFFFFFF:
        errors.append(f"{path} exceeds the 64-bit address domain")
        return None
    return value


def _parse_hex(value: Any, path: str, errors: list[str], expected_size: int | None = None) -> str | None:
    if not isinstance(value, str):
        errors.append(f"{path} must be a hexadecimal string")
        return None
    cleaned = value.replace(" ", "").replace("_", "").lower()
    if len(cleaned) % 2 or any(ch not in "0123456789abcdef" for ch in cleaned):
        errors.append(f"{path} must be an even-length hexadecimal string")
        return None
    if expected_size is not None and len(cleaned) != expected_size * 2:
        errors.append(f"{path} must be exactly {expected_size} bytes")
        return None
    return cleaned


def parse_harness(document: Any) -> Harness:
    """Validate and normalize a harness document. Raises :class:`HarnessError` on any problem."""

    errors: list[str] = []
    if not isinstance(document, dict):
        raise HarnessError(["harness document must be a JSON object"])
    _reject_unknown_keys(document, HARNESS_KEYS, "harness", errors)

    schema_version = document.get("schema_version", SUPPORTED_SCHEMA_VERSION)
    if schema_version != SUPPORTED_SCHEMA_VERSION:
        errors.append(
            f"unsupported schema_version {schema_version!r}; this build accepts "
            f"{SUPPORTED_SCHEMA_VERSION!r}"
        )

    harness_id = document.get("harness_id")
    if not isinstance(harness_id, str) or not harness_id.strip():
        errors.append("harness_id must be a non-empty string")
    binary_sha256 = document.get("binary_sha256")
    if not isinstance(binary_sha256, str) or len(binary_sha256) != 64 or any(
        ch not in "0123456789abcdef" for ch in binary_sha256.lower()
    ):
        errors.append("binary_sha256 must be 64 lowercase hexadecimal characters")
    architecture = document.get("architecture", "x86_64")
    if architecture != "x86_64":
        errors.append("architecture must be x86_64")
    base = _parse_int(document.get("base"), "base", errors)
    entry = _parse_int(document.get("function_entry"), "function_entry", errors)
    end = _parse_int(document.get("function_end"), "function_end", errors)
    if entry is not None and end is not None and end <= entry:
        errors.append("function_end must be greater than function_entry")
    convention = document.get("calling_convention", "sysv-amd64")
    if convention not in CALLING_CONVENTIONS:
        errors.append(f"calling_convention must be one of {list(CALLING_CONVENTIONS)}")

    memory_regions: list[MemoryRegion] = []
    raw_regions = document.get("memory_regions")
    if not isinstance(raw_regions, list) or not raw_regions:
        errors.append("memory_regions must be a non-empty list")
        raw_regions = []
    seen_names: set[str] = set()
    for index, raw in enumerate(raw_regions):
        path = f"memory_regions[{index}]"
        if not isinstance(raw, dict):
            errors.append(f"{path} must be an object")
            continue
        _reject_unknown_keys(raw, MEMORY_REGION_KEYS, path, errors)
        name = raw.get("name")
        if not isinstance(name, str) or not name.strip():
            errors.append(f"{path}.name must be a non-empty string")
            name = f"region{index}"
        if name in seen_names:
            errors.append(f"{path}.name {name!r} is duplicated")
        seen_names.add(name)
        region_base = _parse_int(raw.get("base"), f"{path}.base", errors)
        region_size = _parse_int(raw.get("size"), f"{path}.size", errors, minimum=1)
        permissions = raw.get("permissions")
        if not isinstance(permissions, str) or not permissions:
            errors.append(f"{path}.permissions must be a non-empty string")
            permissions = ""
        if any(ch not in "rwx" for ch in permissions):
            errors.append(f"{path}.permissions may only contain r, w, x")
        if "w" in permissions and "x" in permissions:
            errors.append(
                f"{path} declares writable and executable permissions on the same region "
                "(executable writable confusion)"
            )
        source = raw.get("source", "literal")
        if source not in {"literal", "binary", "zero"}:
            errors.append(f"{path}.source must be one of literal, binary, zero")
        initial_data = raw.get("initial_data")
        if source == "literal":
            if initial_data is None:
                errors.append(f"{path}.initial_data is required when source is literal")
            else:
                initial_data = _parse_hex(initial_data, f"{path}.initial_data", errors, region_size)
        elif initial_data is not None:
            errors.append(f"{path}.initial_data must be null when source is {source}")
            initial_data = None
        if region_base is None or region_size is None:
            continue
        memory_regions.append(
            MemoryRegion(
                name=name,
                base=region_base,
                size=region_size,
                permissions=permissions,
                source=source,
                initial_data=initial_data,
            )
        )

    for index, region in enumerate(memory_regions):
        for other in memory_regions[index + 1 :]:
            if region.base < other.end and other.base < region.end:
                errors.append(
                    f"memory_regions {region.name!r} and {other.name!r} overlap"
                )

    def containing_region(address: int, size: int) -> MemoryRegion | None:
        for region in memory_regions:
            if region.base <= address and address + size <= region.end:
                return region
        return None

    def parse_addressed_list(
        key: str, minimum_size: int = 1, allowed: frozenset[str] = ADDRESSED_REGION_KEYS
    ) -> list[dict[str, Any]]:
        raw_items = document.get(key, [])
        if raw_items is None:
            raw_items = []
        if not isinstance(raw_items, list):
            errors.append(f"{key} must be a list")
            return []
        parsed: list[dict[str, Any]] = []
        for index, raw in enumerate(raw_items):
            path = f"{key}[{index}]"
            if not isinstance(raw, dict):
                errors.append(f"{path} must be an object")
                continue
            _reject_unknown_keys(raw, allowed, path, errors)
            if not isinstance(raw.get("name"), str) or not raw["name"].strip():
                errors.append(f"{path}.name must be a non-empty string")
            address = _parse_int(raw.get("address"), f"{path}.address", errors)
            size = _parse_int(raw.get("size"), f"{path}.size", errors, minimum=minimum_size)
            parsed.append({**raw, "address": address, "size": size})
        return parsed

    input_regions: list[InputRegion] = []
    output_regions: list[OutputRegion] = []
    for raw in parse_addressed_list("input_regions", allowed=INPUT_REGION_KEYS):
        address, size = raw["address"], raw["size"]
        if address is None or size is None:
            continue
        region = containing_region(address, size)
        if region is None:
            errors.append(f"input region {raw.get('name')!r} is not fully inside a mapped region")
        elif "r" not in region.permissions:
            errors.append(f"input region {raw.get('name')!r} lies in a non-readable region")
        concrete = raw.get("concrete_value")
        if concrete is not None:
            concrete = _parse_hex(concrete, f"input_regions[{raw.get('name')}].concrete_value", errors, size)
        symbolic_name = raw.get("symbolic_name")
        if symbolic_name is not None and not isinstance(symbolic_name, str):
            errors.append(f"input region {raw.get('name')!r} symbolic_name must be a string")
        input_regions.append(
            InputRegion(
                name=str(raw.get("name")),
                address=address,
                size=size,
                concrete_value=concrete,
                symbolic=bool(raw.get("symbolic", False)),
                tainted=bool(raw.get("tainted", False)),
                symbolic_name=symbolic_name if isinstance(symbolic_name, str) else None,
            )
        )
    for raw in parse_addressed_list("output_regions"):
        address, size = raw["address"], raw["size"]
        if address is None or size is None:
            continue
        region = containing_region(address, size)
        if region is None:
            errors.append(f"output region {raw.get('name')!r} is not fully inside a mapped region")
        elif "w" not in region.permissions:
            errors.append(f"output region {raw.get('name')!r} lies in a non-writable region")
        output_regions.append(OutputRegion(name=str(raw.get("name")), address=address, size=size))

    taint_sources: list[TaintSource] = []
    raw_sources = document.get("taint_sources", [])
    if raw_sources is None:
        raw_sources = []
    if not isinstance(raw_sources, list):
        errors.append("taint_sources must be a list")
        raw_sources = []
    for index, raw in enumerate(raw_sources):
        path = f"taint_sources[{index}]"
        if not isinstance(raw, dict):
            errors.append(f"{path} must be an object")
            continue
        _reject_unknown_keys(raw, TAINT_SOURCE_KEYS, path, errors)
        kind = raw.get("kind")
        if kind not in SOURCE_KINDS:
            errors.append(f"{path}.kind must be one of {list(SOURCE_KINDS)}")
            continue
        label = raw.get("label", f"{kind}{index}")
        if not isinstance(label, str) or not label.strip():
            errors.append(f"{path}.label must be a non-empty string")
            label = f"{kind}{index}"
        if kind == "register":
            register = raw.get("register")
            if register not in GENERAL_REGISTERS:
                errors.append(f"{path}.register must be a general-purpose register name")
                continue
            taint_sources.append(TaintSource(kind=kind, label=label, register=register))
        else:
            address = _parse_int(raw.get("address"), f"{path}.address", errors)
            size = _parse_int(raw.get("size"), f"{path}.size", errors, minimum=1)
            if address is None or size is None:
                continue
            region = containing_region(address, size)
            if region is None:
                errors.append(f"{path} is not fully inside a mapped region")
            elif "r" not in region.permissions:
                errors.append(f"{path} lies in a non-readable region")
            taint_sources.append(
                TaintSource(kind=kind, label=label, address=address, size=size)
            )

    expected_sinks: list[dict[str, Any]] = []
    raw_sinks = document.get("expected_sinks", [])
    if raw_sinks is None:
        raw_sinks = []
    if not isinstance(raw_sinks, list):
        errors.append("expected_sinks must be a list")
        raw_sinks = []
    sink_values = {item.value for item in SinkType}
    for index, raw in enumerate(raw_sinks):
        path = f"expected_sinks[{index}]"
        if not isinstance(raw, dict):
            errors.append(f"{path} must be an object")
            continue
        _reject_unknown_keys(raw, EXPECTED_SINK_KEYS, path, errors)
        sink_type = raw.get("sink_type")
        if sink_type not in sink_values:
            errors.append(f"{path}.sink_type must be one of {sorted(sink_values)}")
            continue
        normalized_sink: dict[str, Any] = {"sink_type": sink_type}
        if "label" in raw:
            if not isinstance(raw["label"], str):
                errors.append(f"{path}.label must be a string")
            else:
                normalized_sink["label"] = raw["label"]
        for key in ("address", "size"):
            if key in raw:
                value = _parse_int(raw[key], f"{path}.{key}", errors)
                if value is not None:
                    normalized_sink[key] = value
        if normalized_sink.get("address") is not None and not containing_region(
            normalized_sink["address"], normalized_sink.get("size", 1)
        ):
            errors.append(f"{path}.address is not inside a mapped region")
        if "register" in raw:
            if raw["register"] not in GENERAL_REGISTERS:
                errors.append(f"{path}.register must be a general-purpose register name")
            else:
                normalized_sink["register"] = raw["register"]
        expected_sinks.append(normalized_sink)

    callee_stubs: list[CalleeStub] = []
    raw_stubs = document.get("callee_stubs", [])
    if raw_stubs is None:
        raw_stubs = []
    if not isinstance(raw_stubs, list):
        errors.append("callee_stubs must be a list")
        raw_stubs = []
    stub_targets: set[int] = set()
    for index, raw in enumerate(raw_stubs):
        path = f"callee_stubs[{index}]"
        if not isinstance(raw, dict):
            errors.append(f"{path} must be an object")
            continue
        _reject_unknown_keys(raw, CALLEE_STUB_KEYS, path, errors)
        target = _parse_int(raw.get("target"), f"{path}.target", errors)
        if target is not None:
            if target in stub_targets:
                errors.append(f"{path}.target is declared twice")
            stub_targets.add(target)
        name = raw.get("name")
        if not isinstance(name, str) or not name.strip():
            errors.append(f"{path}.name must be a non-empty string")
            name = f"stub{index}"
        behavior = raw.get("behavior", name)
        if not isinstance(behavior, str):
            errors.append(f"{path}.behavior must be a string")
            continue
        spec = resolve_stub(behavior)
        if spec is None:
            errors.append(
                f"{path}.behavior {behavior!r} is not in the stub registry "
                "(unknown calls must stop the run as STUB_REQUIRED, never be wildcarded)"
            )
            continue
        return_value = raw.get("return_value")
        if return_value is not None:
            return_value = _parse_int(return_value, f"{path}.return_value", errors)
        if behavior in {"alloc_region", "status_ok"} and return_value is None:
            errors.append(f"{path}.return_value is required for the {behavior} stub")
        register_effects: dict[str, int] = {}
        raw_effects = raw.get("register_effects", {})
        if raw_effects is None:
            raw_effects = {}
        if not isinstance(raw_effects, dict):
            errors.append(f"{path}.register_effects must be an object")
        else:
            for register, value in raw_effects.items():
                if register not in GENERAL_REGISTERS:
                    errors.append(f"{path}.register_effects has an unknown register {register!r}")
                    continue
                if register in spec.preserves:
                    errors.append(
                        f"{path}.register_effects contradicts the {behavior} ABI: "
                        f"{register} is callee-saved and must be preserved"
                    )
                    continue
                parsed_value = _parse_int(value, f"{path}.register_effects.{register}", errors)
                if parsed_value is not None:
                    register_effects[register] = parsed_value
        memory_effects: list[dict[str, Any]] = []
        raw_memory = raw.get("memory_effects", [])
        if raw_memory is None:
            raw_memory = []
        if not isinstance(raw_memory, list):
            errors.append(f"{path}.memory_effects must be a list")
        else:
            for effect_index, effect in enumerate(raw_memory):
                effect_path = f"{path}.memory_effects[{effect_index}]"
                if not isinstance(effect, dict):
                    errors.append(f"{effect_path} must be an object")
                    continue
                _reject_unknown_keys(effect, MEMORY_EFFECT_KEYS, effect_path, errors)
                kind = effect.get("kind", "NONE")
                if kind not in MEMORY_EFFECT_KINDS:
                    errors.append(f"{effect_path}.kind must be one of {list(MEMORY_EFFECT_KINDS)}")
                    continue
                normalized_effect: dict[str, Any] = {"kind": kind}
                for key in ("address", "size"):
                    if key in effect:
                        value = _parse_int(effect[key], f"{effect_path}.{key}", errors)
                        if value is not None:
                            normalized_effect[key] = value
                memory_effects.append(normalized_effect)
                if behavior in {"memcpy", "memmove"} and kind == "NONE":
                    errors.append(
                        f"{effect_path} contradicts the {behavior} stub, which always writes memory"
                    )
        callee_stubs.append(
            CalleeStub(
                target=target if target is not None else 0,
                name=name,
                behavior=behavior,
                return_value=return_value,
                register_effects=register_effects,
                memory_effects=memory_effects,
            )
        )

    stop_conditions: list[StopCondition] = []
    raw_stops = document.get("stop_conditions", [])
    if raw_stops is None:
        raw_stops = []
    if not isinstance(raw_stops, list):
        errors.append("stop_conditions must be a list")
        raw_stops = []
    for index, raw in enumerate(raw_stops):
        path = f"stop_conditions[{index}]"
        if not isinstance(raw, dict):
            errors.append(f"{path} must be an object")
            continue
        _reject_unknown_keys(raw, STOP_CONDITION_KEYS, path, errors)
        kind = raw.get("kind")
        if kind not in STOP_KINDS:
            errors.append(f"{path}.kind must be one of {list(STOP_KINDS)}")
            continue
        address = raw.get("address")
        if kind == "ADDRESS":
            address = _parse_int(address, f"{path}.address", errors)
            if address is None:
                continue
        elif address is not None:
            errors.append(f"{path}.address is only allowed for the ADDRESS stop kind")
            address = None
        stop_conditions.append(StopCondition(kind=kind, address=address))

    initial_registers: dict[str, int] = {}
    raw_initial = document.get("initial_registers", {})
    if raw_initial is None:
        raw_initial = {}
    if not isinstance(raw_initial, dict):
        errors.append("initial_registers must be an object")
    else:
        for register, value in raw_initial.items():
            if register not in GENERAL_REGISTERS:
                errors.append(f"initial_registers has an unknown register {register!r}")
                continue
            parsed_value = _parse_int(value, f"initial_registers.{register}", errors)
            if parsed_value is not None:
                initial_registers[register] = parsed_value

    stack_base = document.get("stack_base")
    if stack_base is not None:
        stack_base = _parse_int(stack_base, "stack_base", errors)
    parsed_stack_size = _parse_int(document.get("stack_size", 0), "stack_size", errors)
    stack_size = parsed_stack_size if parsed_stack_size is not None else 0
    if stack_base is not None and stack_size and not containing_region(stack_base, stack_size):
        errors.append("stack_base/stack_size is not fully inside a mapped region")

    def parse_limit(key: str, default: int, maximum: int | None = None) -> int:
        value = document.get(key, default)
        parsed = _parse_int(value, key, errors, minimum=1)
        if parsed is None:
            return default
        if maximum is not None and parsed > maximum:
            errors.append(f"{key} must not exceed {maximum}")
            return default
        return parsed

    instruction_limit = parse_limit("instruction_limit", 4096, 1_000_000)
    branch_limit = parse_limit("branch_limit", 256, 100_000)
    max_symbolic_expressions = parse_limit("max_symbolic_expressions", 8192, 1_000_000)
    max_trace_entries = parse_limit("max_trace_entries", 4096, 1_000_000)
    max_call_depth = parse_limit("max_call_depth", 8, 1024)
    max_internal_calls = parse_limit("max_internal_calls", 256, 1_000_000)
    timeout_seconds = parse_limit("timeout_seconds", 60, MAX_TIMEOUT_SECONDS)

    notes = document.get("notes")
    if notes is not None and not isinstance(notes, str):
        errors.append("notes must be a string")

    if errors:
        raise HarnessError(errors)

    assert base is not None and entry is not None and end is not None
    return Harness(
        harness_id=str(harness_id),
        binary_sha256=str(binary_sha256).lower(),
        architecture=str(architecture),
        base=base,
        function_entry=entry,
        function_end=end,
        calling_convention=convention,
        memory_regions=tuple(memory_regions),
        input_regions=tuple(input_regions),
        output_regions=tuple(output_regions),
        taint_sources=tuple(taint_sources),
        expected_sinks=tuple(expected_sinks),
        callee_stubs=tuple(callee_stubs),
        stop_conditions=tuple(stop_conditions),
        initial_registers=initial_registers,
        stack_base=stack_base,
        stack_size=stack_size,
        instruction_limit=instruction_limit,
        branch_limit=branch_limit,
        max_symbolic_expressions=max_symbolic_expressions,
        max_trace_entries=max_trace_entries,
        max_call_depth=max_call_depth,
        max_internal_calls=max_internal_calls,
        timeout_seconds=timeout_seconds,
        notes=notes,
    )


def load_harness(path: str | Path) -> Harness:
    try:
        document = json.loads(Path(path).read_text(encoding="utf-8"))
    except OSError as exc:
        raise HarnessError([f"harness file cannot be read: {exc}"]) from exc
    except json.JSONDecodeError as exc:
        raise HarnessError([f"harness file is not valid JSON: {exc}"]) from exc
    return parse_harness(document)


def validate_harness(document: Any) -> list[str]:
    """Return validation errors for a candidate harness document (empty list means valid)."""

    try:
        parse_harness(document)
    except HarnessError as exc:
        return list(exc.errors)
    return []


def executable_regions(harness: Harness) -> list[MemoryRegion]:
    return [region for region in harness.memory_regions if "x" in region.permissions]
