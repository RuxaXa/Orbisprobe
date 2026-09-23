"""Triton worker: bounded offline execution of a single validated function harness.

Contract: JSON request on stdin, one JSON response on stdout. Nothing is imported from the
OrbisProbe core, nothing is executed from the guest but the harness-described function bytes, and
no guest syscall, host file access, network access, or subprocess is ever performed.

Instruction semantics come from Triton (`triton-library`); instruction boundaries come from
Capstone, so the worker never guesses where an instruction ends. Stub behaviour is resolved from the
fixed allowlist in ``orbisprobe.harness.registry`` shipped alongside this worker.
"""

from __future__ import annotations

import hashlib
import json
import sys
import time
from pathlib import Path
from typing import Any

# The worker is executed with a dedicated Triton interpreter as a script, so Python's
# default sys.path starts at ``orbisprobe/backends/workers`` rather than the package
# parent. Add the package parent deterministically so the shared harness registry is
# importable both from a source checkout and from an installed wheel.
_PACKAGE_PARENT = Path(__file__).resolve().parents[3]
if str(_PACKAGE_PARENT) not in sys.path:
    sys.path.insert(0, str(_PACKAGE_PARENT))

STOP_RETURN = "RETURN"
STOP_ADDRESS = "ADDRESS"
STOP_FUNCTION_END = "FUNCTION_END"
STOP_UNMAPPED = "UNMAPPED"
STOP_STUB_REQUIRED = "STUB_REQUIRED"
STOP_INDIRECT_CALL_UNRESOLVED = "INDIRECT_CALL_UNRESOLVED"
STOP_INVALID_INSTRUCTION = "INVALID_INSTRUCTION"
STOP_INSTRUCTION_LIMIT = "INSTRUCTION_LIMIT"
STOP_BRANCH_LIMIT = "BRANCH_LIMIT"
STOP_SYMBOLIC_LIMIT = "SYMBOLIC_EXPRESSION_LIMIT"
STOP_TIMEOUT = "TIMEOUT"
STOP_ERROR = "ERROR"

VIOLATION_READ_UNMAPPED = "READ_UNMAPPED"
VIOLATION_WRITE_UNMAPPED = "WRITE_UNMAPPED"
VIOLATION_READ_OOB = "READ_OOB_REGION"
VIOLATION_WRITE_OOB = "WRITE_OOB_REGION"
VIOLATION_EXECUTE_UNMAPPED = "EXECUTE_UNMAPPED"
VIOLATION_STUB_LENGTH_OUT_OF_RANGE = "STUB_LENGTH_OUT_OF_RANGE"
#: A guest access into a region that is mapped but lacks the required permission bit.
VIOLATION_READ_PERMISSION = "READ_PERMISSION_DENIED"
VIOLATION_WRITE_PERMISSION = "WRITE_PERMISSION_DENIED"
#: Control-flow integrity outcomes for call/return handling.
VIOLATION_RETURN_TO_UNMAPPED = "RETURN_TO_UNMAPPED"
VIOLATION_RETURN_TO_NON_EXECUTABLE = "RETURN_TO_NON_EXECUTABLE"
VIOLATION_CORRUPTED_STACK_RETURN = "CORRUPTED_STACK_RETURN"
VIOLATION_CALL_TARGET_NOT_EXECUTABLE = "CALL_TARGET_NOT_EXECUTABLE"
VIOLATION_CALL_DEPTH_EXCEEDED = "CALL_DEPTH_EXCEEDED"
#: Repair-scope additions (M2-B1 CALL/RET).
VIOLATION_INVALID_CALL_TARGET = "INVALID_CALL_TARGET"
VIOLATION_INVALID_RETURN_TARGET = "INVALID_RETURN_TARGET"
VIOLATION_EARLY_SENTINEL_RETURN = "EARLY_SENTINEL_RETURN"
VIOLATION_CALL_STACK_UNDERFLOW = "CALL_STACK_UNDERFLOW"
VIOLATION_CONTROL_FLOW_CONFLICT = "CONTROL_FLOW_CONFLICT"
VIOLATION_UNSUPPORTED_RETURN_FORM = "UNSUPPORTED_RETURN_FORM"
#: The harness is entered as if called by an unknown caller: this sentinel return address is pushed
#: once, before execution, and the first RET that pops it ends the harness invocation. Every other
#: RET is an ordinary return from an internal callee.
SENTINEL_RETURN_ADDRESS = 0x4F52424953454E54  # "ORBISENT"
#: CALL classification outcomes.
CALL_INTERNAL = "INTERNAL"
CALL_REGISTERED_STUB = "REGISTERED_STUB"
CALL_EXTERNAL_UNKNOWN = "EXTERNAL_UNKNOWN"
CALL_INDIRECT_UNRESOLVED = "INDIRECT_CALL_UNRESOLVED"
#: Largest byte count a memory stub will materialise. Anything larger is an anomaly, not a copy.
MAX_STUB_LENGTH = 1 << 20

STUBS: dict[str, dict[str, Any]] = {}


def load_stub_specs() -> None:
    """Import the shared stub registry without importing the OrbisProbe core."""

    from orbisprobe.harness.registry import STUBS as registry_stubs

    for name, spec in registry_stubs.items():
        STUBS[name] = spec.to_dict()


def emit(payload: dict[str, Any]) -> None:
    sys.stdout.write(json.dumps(payload, sort_keys=True, allow_nan=False))
    sys.stdout.write("\n")


class MemoryModel:
    """Flat region model with permissions, used for access validation and stub effects."""

    def __init__(self, regions: list[dict[str, Any]]) -> None:
        self.regions = regions

    def region_of(self, address: int, size: int = 1) -> dict[str, Any] | None:
        for region in self.regions:
            if region["base"] <= address and address + size <= region["base"] + region["size"]:
                return region
        return None

    def covering(self, address: int, size: int = 1) -> dict[str, Any] | None:
        """Return a region that merely contains the start address."""

        for region in self.regions:
            if region["base"] <= address < region["base"] + region["size"]:
                return region
        return None

    def permissions(self, address: int) -> str:
        region = self.covering(address)
        return region["permissions"] if region else ""

    def read(self, address: int, size: int) -> bytes | None:
        data = bytearray()
        for offset in range(size):
            region = self.covering(address + offset)
            if region is None:
                return None
            data.append(region["data"][address + offset - region["base"]])
        return bytes(data)

    def write(self, address: int, payload: bytes) -> bool:
        for offset, value in enumerate(payload):
            region = self.covering(address + offset)
            if region is None or "w" not in region["permissions"]:
                return False
            region["data"][address + offset - region["base"]] = value
        return True

    def seed(self, address: int, payload: bytes) -> bool:
        """Write harness-setup data into a region, ignoring guest permissions.

        Seeding an input region is harness setup, not emulated behaviour: the harness declares the
        bytes that are already in memory when the function is entered. Guest writes still have to
        respect the region's permission bits through :meth:`write`.
        """

        for offset, value in enumerate(payload):
            region = self.covering(address + offset)
            if region is None:
                return False
            region["data"][address + offset - region["base"]] = value
        return True

    def access_violation(self, address: int, size: int, access: str) -> str | None:
        """Classify a *guest* access. Returns None when the access is legal.

        Precedence: unmapped, then out-of-region, then missing permission. Setup-time seeding never
        goes through here - the harness may pre-fill a region that is later mapped read-only, but
        once execution has started the declared permission bits apply to every emulated access.
        """

        if access not in {"read", "write"}:
            raise ValueError(f"unsupported access kind {access!r}")
        kind_unmapped = VIOLATION_READ_UNMAPPED if access == "read" else VIOLATION_WRITE_UNMAPPED
        kind_oob = VIOLATION_READ_OOB if access == "read" else VIOLATION_WRITE_OOB
        kind_permission = (
            VIOLATION_READ_PERMISSION if access == "read" else VIOLATION_WRITE_PERMISSION
        )
        required = "r" if access == "read" else "w"
        region = self.region_of(address, size)
        if region is not None:
            return None if required in region["permissions"] else kind_permission
        if self.covering(address) is None:
            return kind_unmapped
        return kind_oob

    def total_size(self) -> int:
        return sum(region["size"] for region in self.regions)


def build_memory(harness: dict[str, Any], binary: bytes, max_mapped_bytes: int) -> MemoryModel:
    base = harness["base"]
    regions: list[dict[str, Any]] = []
    for raw in harness["memory_regions"]:
        size = int(raw["size"])
        source = raw.get("source", "literal")
        if source == "literal":
            data = bytearray(bytes.fromhex(raw["initial_data"]))
        elif source == "zero":
            data = bytearray(size)
        else:
            offset = int(raw["base"]) - base
            if offset < 0 or offset + size > len(binary):
                raise ValueError(
                    f"region {raw['name']!r} (source=binary) is not fully inside the analyzed binary"
                )
            data = bytearray(binary[offset : offset + size])
        if len(data) != size:
            raise ValueError(f"region {raw['name']!r} initial data does not match its size")
        regions.append(
            {
                "name": raw["name"],
                "base": int(raw["base"]),
                "size": size,
                "permissions": raw["permissions"],
                "data": data,
            }
        )
    model = MemoryModel(regions)
    if model.total_size() > max_mapped_bytes:
        raise MemoryLimitExceeded(
            f"mapped memory {model.total_size()} exceeds the limit {max_mapped_bytes}"
        )
    return model


class MemoryLimitExceeded(Exception):
    pass


def register_names(context: Any, entries: list[Any]) -> list[str]:
    """Extract parent register names from Triton's ``(Register, AstNode)`` tuples.

    Triton 1.0 rc returns access/read/write lists as tuples; older releases return bare registers.
    Both shapes are accepted so the worker does not depend on one exact revision.
    """

    names = set()
    for entry in entries:
        register = entry[0] if isinstance(entry, tuple) else entry
        if not hasattr(register, "getName"):
            continue
        parent = None
        try:
            parent = context.getParentRegister(register)
        except TypeError:
            parent = None
        target = parent if parent is not None else register
        names.add(target.getName())
    return sorted(names)


def describe_constraint(constraint: Any) -> str:
    """Render a Triton path constraint as readable text instead of an object repr."""

    parts: list[str] = []
    for getter in ("getTakenPredicate", "getTakenPredicateAst"):
        function = getattr(constraint, getter, None)
        if callable(function):
            try:
                predicate = function()
            except Exception:  # noqa: BLE001, S112 - rendering must never fail the run
                continue
            if predicate is not None:
                parts.append(str(predicate))
                break
    getter = getattr(constraint, "getBranchConstraints", None)
    if callable(getter):
        try:
            for branch in getter():
                try:
                    parts.append(
                        f"0x{int(branch.getAddress()):x}:"
                        f"{'taken' if branch.isTaken() else 'not-taken'}:{branch.getConstraint()}"
                    )
                except Exception:  # noqa: BLE001, S112 - a malformed constraint must not abort
                    continue
        except Exception:  # noqa: BLE001, S110 - rendering is best effort
            pass
    return " | ".join(parts) if parts else "<constraint unavailable>"


def apply_stub(
    context: Any,
    model: MemoryModel,
    stub: dict[str, Any],
    spec: dict[str, Any],
    flow_recorder: FlowRecorder,
    call_site: int | None = None,
) -> dict[str, Any]:
    """Apply deterministic stub behaviour. Returns an event describing what happened."""

    behavior = stub["behavior"]
    event: dict[str, Any] = {
        "target": stub["target"],
        "name": stub["name"],
        "behavior": behavior,
        "memory_effect": spec["memory_effect"],
        "taint_semantics": spec["taint_semantics"],
    }
    violations: list[dict[str, Any]] = []
    clobbered = sorted(set(spec["clobbers"]) | set(stub.get("register_effects", {})))

    # The stub returns a fixed result, so the return register is redefined and must lose any taint it
    # carried into the call. Taint is only re-established where a stub explicitly propagates it
    # (pure_identity) or copies tainted bytes (memcpy/memmove).
    context.untaintRegister(context.registers.rax)

    def reg(name: str) -> int:
        return context.getConcreteRegisterValue(getattr(context.registers, name))

    def set_reg(name: str, value: int) -> None:
        context.setConcreteRegisterValue(getattr(context.registers, name), value & 0xFFFFFFFFFFFFFFFF)

    if behavior in {"memcpy", "memmove", "memset"}:
        destination = reg("rdi")
        length = reg("rdx")
        if length > MAX_STUB_LENGTH:
            # A stub must never try to materialise an unbounded byte string: report the anomaly and
            # perform no memory effect instead of aborting the whole run.
            violations.append(
                {
                    "kind": VIOLATION_STUB_LENGTH_OUT_OF_RANGE,
                    "address": destination,
                    "size": length,
                    "stub": stub["name"],
                }
            )
            return {
                **event,
                "destination": destination,
                "length": length,
                "bytes_copied": 0,
                "clobbered": [],
                "preserved": sorted(spec["preserves"]),
                "violations": violations,
            }
        source_address: int | None = None
        source_violation: str | None = None
        fill = 0
        if behavior == "memset":
            fill = reg("esi") & 0xFF
        else:
            source_address = reg("rsi")
            source_violation = model.access_violation(source_address, length, "read")
        destination_violation = model.access_violation(destination, length, "write")
        if source_violation:
            violations.append(
                {
                    "kind": source_violation,
                    "address": source_address,
                    "size": length,
                    "stub": stub["name"],
                }
            )
        if destination_violation:
            violations.append(
                {
                    "kind": destination_violation,
                    "address": destination,
                    "size": length,
                    "stub": stub["name"],
                }
            )
        if not source_violation and not destination_violation:
            if behavior == "memset":
                payload = bytes([fill]) * length
            else:
                payload = (
                    bytes(context.getConcreteMemoryAreaValue(source_address, length))
                    if source_address is not None
                    else None
                )
            if payload is not None:
                # Keep the worker's permission/object model and Triton's architectural memory in
                # lock-step. Later guest code must observe stub writes, and later stubs must observe
                # writes performed by real guest instructions.
                model.write(destination, payload)
                context.setConcreteMemoryAreaValue(destination, payload)
        event.update(
            {
                "destination": destination,
                "length": length,
                "source": source_address,
                "bytes_copied": 0 if (source_violation or destination_violation) else length,
            }
        )
        if behavior == "memset":
            flow_recorder.record_stub_copy(
                stub=stub["name"],
                destination=destination,
                length=length,
                source_tainted=False,
                source_label=None,
                call_site=call_site,
            )
        else:
            tainted, labels = flow_recorder.memory_band_tainted(context, source_address, length)
            if tainted:
                destination_tainted = model.read(destination, length)
                if destination_tainted is not None:
                    flow_recorder.mark_memory_tainted(context, destination, length, labels)
                flow_recorder.record_stub_copy(
                    stub=stub["name"],
                    destination=destination,
                    length=length,
                    source_tainted=True,
                    source_label=",".join(sorted(labels)),
                    call_site=call_site,
                )
        set_reg("rax", destination)
    elif behavior == "alloc_region" or behavior == "status_ok":
        set_reg("rax", int(stub["return_value"]))
        event["return_value"] = int(stub["return_value"])
    elif behavior == "pure_identity":
        value = reg("rdi")
        set_reg("rax", value)
        if flow_recorder.register_is_tainted(context, "rdi"):
            flow_recorder.mark_register_tainted(context, "rax", flow_recorder.labels_of(context, "rdi"))
            event["taint_propagated"] = True
        event["return_value"] = value
    elif behavior == "pure_zero":
        set_reg("rax", 0)
        event["return_value"] = 0
    else:  # pragma: no cover - validation prevents this
        raise ValueError(f"unsupported stub behaviour {behavior!r}")

    for name in clobbered:
        if name == "rax":
            continue
        context.untaintRegister(getattr(context.registers, name))
        if name not in stub.get("register_effects", {}):
            set_reg(name, 0)
    for name, value in stub.get("register_effects", {}).items():
        set_reg(name, int(value))
    event["clobbered"] = [name for name in clobbered if name != "rax"]
    event["preserved"] = sorted(spec["preserves"])
    event["violations"] = violations
    return event


class FlowRecorder:
    """Reconstructs source -> transformation -> sink taint flows without full traces."""

    def __init__(self, sources: list[dict[str, Any]]) -> None:
        self.flows: dict[str, dict[str, Any]] = {}
        self.memory_ranges: list[tuple[int, int, str]] = []
        #: Set by the caller so the recorder can ask the engine to taint/write memory without
        #: importing the engine here.
        self.memory_taint_hook: Any = None
        for source in sources:
            label = source["label"]
            self.flows[label] = {
                "source": label,
                "source_kind": source["kind"],
                "register": source.get("register"),
                "address": source.get("address"),
                "size": source.get("size"),
                "transformations": [],
                "sink": None,
                "sinks": [],
                "first_instruction": None,
                "last_instruction": None,
            }
            if source["kind"] == "memory" and source.get("address") is not None:
                start = int(source["address"])
                self.memory_ranges.append((start, start + int(source["size"]), label))
        self._labels_by_register: dict[str, set[str]] = {}

    # -- taint helpers ----------------------------------------------------------------
    def register_is_tainted(self, context: Any, register: str) -> bool:
        return bool(context.isRegisterTainted(getattr(context.registers, register)))

    def labels_of(self, context: Any, register: str) -> set[str]:
        if register not in self._labels_by_register:
            return {label for label in self.flows}
        return set(self._labels_by_register[register])

    def labels_of_registers(self, registers: list[str]) -> set[str]:
        labels: set[str] = set()
        for register in registers:
            labels |= self.labels_of(None, register)
        return labels

    def mark_register_tainted(self, context: Any, register: str, labels: set[str]) -> None:
        context.taintRegister(getattr(context.registers, register))
        self._labels_by_register[register] = labels

    def mark_memory_tainted(self, context: Any, address: int, size: int, labels: set[str]) -> None:
        if self.memory_taint_hook is not None:
            try:
                self.memory_taint_hook(address, size)
            except Exception:  # noqa: BLE001, S110 - best effort, recorded as a range label
                pass
        self.memory_ranges.append((address, address + size, ",".join(sorted(labels)) or "tainted"))

    def memory_band_tainted(self, context: Any, address: int | None, size: int) -> tuple[bool, set[str]]:
        if address is None:
            return False, set()
        labels = self._range_labels(address, size)
        if labels:
            return True, labels
        try:
            if context.isMemoryTainted(address):
                return True, {"triton.tainted_memory"}
        except Exception:  # noqa: BLE001, S110 - optional engine-side confirmation
            pass
        return False, set()

    def _range_labels(self, address: int, size: int) -> set[str]:
        end = address + max(size, 1)
        labels: set[str] = set()
        for start, stop, label in self.memory_ranges:
            if address < stop and start < end:
                labels.add(label)
        return labels

    # -- flow recording ---------------------------------------------------------------
    def record_transformation(
        self,
        *,
        address: int,
        instruction: str,
        inputs: list[str],
        output: str,
        output_kind: str,
    ) -> None:
        for flow in self.flows.values():
            flow["transformations"].append(
                {
                    "instruction": address,
                    "disassembly": instruction,
                    "input": inputs,
                    "output": output,
                    "output_kind": output_kind,
                }
            )
            if flow["first_instruction"] is None:
                flow["first_instruction"] = address
            flow["last_instruction"] = address

    def record_sink(
        self,
        *,
        sink_type: str,
        address: int | None,
        instruction: int,
        detail: str,
        labels: set[str] | None = None,
    ) -> None:
        """Attribute a sink to the flows that actually supplied the value.

        When ``labels`` is given, only those flows are updated. Without it the sink is attributed to
        every flow that has not yet been attributed, which is the conservative fallback.
        """

        for label, flow in self.flows.items():
            if labels is not None and label not in labels:
                continue
            flow["sinks"].append(
                {
                    "sink": sink_type,
                    "address": address,
                    "instruction": instruction,
                    "detail": detail,
                }
            )
            if flow["sink"] is None:
                flow.update(
                    {
                        "sink": sink_type,
                        "sink_address": address,
                        "sink_instruction": instruction,
                        "sink_detail": detail,
                        "last_instruction": instruction,
                    }
                )

    def record_stub_copy(
        self,
        *,
        stub: str,
        destination: int,
        length: int,
        source_tainted: bool,
        source_label: str | None,
        call_site: int | None = None,
    ) -> None:
        if not source_tainted:
            return
        # Attach the copy step only to the flows that actually supplied the copied bytes. A tainted
        # *length* value controls how much is copied but does not become the copied data, so it must
        # never inherit this destination as its sink.
        labels = {item for item in (source_label or "").split(",") if item}
        for label, flow in self.flows.items():
            if label not in labels:
                continue
            flow["transformations"].append(
                {
                    "instruction": call_site,
                    "disassembly": f"{stub} length={length:#x}",
                    "input": sorted(labels),
                    "output": f"memory[0x{destination:x}]",
                    "output_kind": "memory",
                }
            )
            if call_site is not None:
                if flow["first_instruction"] is None:
                    flow["first_instruction"] = call_site
                flow["last_instruction"] = call_site
            if flow["sink"] is None:
                flow.update(
                    {
                        "sink": "MEMORY_WRITE_FROM_TAINTED_SOURCE",
                        "sink_address": destination,
                        "sink_detail": f"{stub} copied tainted bytes to 0x{destination:x}",
                    }
                )

    def document(self) -> list[dict[str, Any]]:
        flows = []
        for flow in self.flows.values():
            if not flow["transformations"] and flow["sink"] is None:
                continue
            flows.append({**flow, "reproducible": True, "deterministic": True})
        return sorted(flows, key=lambda item: item["source"])


def main() -> int:
    started = time.monotonic()
    try:
        request = json.load(sys.stdin)
    except json.JSONDecodeError as exc:
        emit({"status": "ERROR", "version": "unknown", "errors": [f"request is not valid JSON: {exc}"]})
        return 0
    try:
        load_stub_specs()
    except Exception as exc:  # noqa: BLE001
        emit({"status": "ERROR", "version": "unknown", "errors": [f"stub registry unavailable: {exc}"]})
        return 0

    harness = request["harness"]
    harness_hash = request.get("harness_sha256")
    recomputed = hashlib.sha256(
        json.dumps(harness, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")
    ).hexdigest()
    if harness_hash and harness_hash != recomputed:
        emit(
            {
                "status": "ERROR",
                "version": "unknown",
                "errors": [f"harness hash mismatch: declared {harness_hash}, recomputed {recomputed}"],
            }
        )
        return 0

    limits = request.get("limits", {})
    instruction_limit = int(limits.get("instruction_limit", harness.get("instruction_limit", 4096)))
    branch_limit = int(limits.get("branch_limit", harness.get("branch_limit", 256)))
    symbolic_limit = int(
        limits.get("max_symbolic_expressions", harness.get("max_symbolic_expressions", 8192))
    )
    trace_limit = int(limits.get("max_trace_entries", harness.get("max_trace_entries", 4096)))
    timeout_seconds = float(limits.get("timeout_seconds", harness.get("timeout_seconds", 60)))
    max_mapped_bytes = int(limits.get("max_mapped_bytes", 16 * 1024 * 1024))
    max_call_depth_limit = int(limits.get("max_call_depth", harness.get("max_call_depth", 8)))
    max_internal_calls_limit = int(
        limits.get("max_internal_calls", harness.get("max_internal_calls", 256))
    )
    operation = request.get("operation", "emulate")

    binary = request["binary"]
    try:
        binary_bytes = Path(binary).read_bytes()
    except OSError as exc:
        emit({"status": "ERROR", "version": "unknown", "errors": [f"binary cannot be read: {exc}"]})
        return 0
    binary_sha256 = hashlib.sha256(binary_bytes).hexdigest()
    if binary_sha256 != harness["binary_sha256"]:
        emit(
            {
                "status": "ERROR",
                "version": "unknown",
                "errors": [
                    f"binary hash mismatch: harness expects {harness['binary_sha256']}, got {binary_sha256}"
                ],
            }
        )
        return 0

    try:
        model = build_memory(harness, binary_bytes, max_mapped_bytes)
    except MemoryLimitExceeded as exc:
        emit(
            {
                "status": "RESOURCE_LIMIT",
                "version": "unknown",
                "errors": [str(exc)],
                "data": {"stop_reason": "MAPPED_MEMORY_LIMIT"},
            }
        )
        return 0
    except (OSError, ValueError, KeyError) as exc:
        emit({"status": "ERROR", "version": "unknown", "errors": [f"harness memory build failed: {exc}"]})
        return 0

    unknown_stubs = [stub["behavior"] for stub in harness["callee_stubs"] if stub["behavior"] not in STUBS]
    if unknown_stubs:
        emit(
            {
                "status": "ERROR",
                "version": "unknown",
                "errors": [f"harness declares unregistered stub behaviour: {sorted(set(unknown_stubs))}"],
            }
        )
        return 0

    # Apply concrete input payloads before execution.
    for region in harness["input_regions"]:
        if region.get("concrete_value"):
            model.seed(int(region["address"]), bytes.fromhex(region["concrete_value"]))

    try:
        import triton
        from capstone import (
            CS_ARCH_X86,
            CS_GRP_JUMP,
            CS_GRP_RET,
            CS_MODE_64,
            CS_OP_IMM,
            CS_OP_MEM,
            CS_OP_REG,
            Cs,
        )
        from triton import ARCH, TritonContext
        from triton import Instruction as TritonInstruction
        from triton import MemoryAccess as TritonMemoryAccess
    except Exception as exc:  # noqa: BLE001
        emit({"status": "ERROR", "version": "unknown", "errors": [f"analysis engines unavailable: {exc}"]})
        return 0

    version = "unknown"
    try:
        from importlib import metadata

        version = metadata.version("triton-library")
    except Exception:  # noqa: BLE001
        version = getattr(triton, "__version__", "unknown")

    context = TritonContext()
    context.setArchitecture(ARCH.X86_64)
    for region in model.regions:
        if region["size"]:
            context.setConcreteMemoryAreaValue(region["base"], bytes(region["data"]))

    registers = harness.get("initial_registers", {})
    for name, value in registers.items():
        context.setConcreteRegisterValue(getattr(context.registers, name), int(value))
    context.setConcreteRegisterValue(context.registers.rip, int(harness["function_entry"]))
    stack_base = harness.get("stack_base")
    stack_size = int(harness.get("stack_size") or 0)
    if stack_base and stack_size:
        # Keep the initial stack pointer 16-byte aligned but strictly inside the mapped stack
        # region, so the first push/return-address read cannot fall off its end.
        stack_top = (int(stack_base) + stack_size - 0x10) & ~0xF
        context.setConcreteRegisterValue(context.registers.rsp, stack_top)

    unknowns: list[str] = []
    # Triton 1.0.0rc4 only accepts MemoryAccess widths from a small aligned set. Harness
    # regions, however, are arbitrary byte ranges (a 0x80-byte descriptor is a common case).
    # Split ranges into the largest legal, naturally aligned chunks so taint/symbolic setup never
    # crashes merely because a declared range is not one Triton MemoryAccess object.
    triton_memory_widths = (64, 32, 16, 8, 4, 2, 1)

    def triton_memory_chunks(address: int, size: int):
        cursor = int(address)
        remaining = int(size)
        if remaining < 0:
            raise ValueError("memory range size must not be negative")
        while remaining:
            width = next(
                item
                for item in triton_memory_widths
                if item <= remaining and cursor % item == 0
            )
            yield TritonMemoryAccess(cursor, width)
            cursor += width
            remaining -= width

    symbolic_applied: list[str] = []
    for region in harness["input_regions"]:
        if not region.get("symbolic"):
            continue
        label = region.get("symbolic_name") or f"input_{region['name']}"
        chunks = list(triton_memory_chunks(int(region["address"]), int(region["size"])))
        created = bool(chunks)
        for index, access in enumerate(chunks):
            chunk_label = label if len(chunks) == 1 else f"{label}.chunk{index}"
            try:
                context.symbolizeMemory(access, chunk_label)
            except TypeError:
                try:
                    context.symbolizeMemory(access)
                except Exception as exc:  # noqa: BLE001
                    unknowns.append(
                        f"symbolic memory for {chunk_label} could not be created: "
                        f"{type(exc).__name__}"
                    )
                    created = False
                    break
            except Exception as exc:  # noqa: BLE001
                unknowns.append(
                    f"symbolic memory for {chunk_label} could not be created: "
                    f"{type(exc).__name__}"
                )
                created = False
                break
        if created:
            symbolic_applied.append(label)

    recorder = FlowRecorder(list(harness["taint_sources"]))
    function_entry = int(harness["function_entry"])
    call_depth = 0
    max_call_depth_reached = 0
    internal_calls = 0
    call_events: list[dict[str, Any]] = []
    return_events: list[dict[str, Any]] = []
    stub_call_sites: dict[int, dict[str, int]] = {}
    # Known instruction boundaries inside the harness range: a call target must land on one of
    # them, otherwise execution would start in the middle of an instruction.
    instruction_starts: set[int] = set()
    boundary_decoder = Cs(CS_ARCH_X86, CS_MODE_64)
    boundary_check = function_entry
    while boundary_check < int(harness["function_end"]):
        raw_window = model.read(boundary_check, 16)
        if raw_window is None:
            break
        decoded_boundary = next(boundary_decoder.disasm(raw_window, boundary_check, count=1), None)
        if decoded_boundary is None:
            break
        instruction_starts.add(boundary_check)
        boundary_check += decoded_boundary.size
    rsp_start = context.getConcreteRegisterValue(context.registers.rsp)
    sentinel_slot = rsp_start - 8
    sentinel_installed = False
    if model.access_violation(sentinel_slot, 8, "write") is None:
        sentinel_bytes = SENTINEL_RETURN_ADDRESS.to_bytes(8, "little")
        model.write(sentinel_slot, sentinel_bytes)
        context.setConcreteMemoryAreaValue(sentinel_slot, sentinel_bytes)
        context.setConcreteRegisterValue(context.registers.rsp, sentinel_slot)
        sentinel_installed = True
    else:
        unknowns.append(
            "no writable stack slot for the outer-return sentinel; the harness return is detected "
            "by comparing RSP with its start value instead"
        )
    def taint_memory_range(address: int, size: int) -> None:
        for access in triton_memory_chunks(int(address), int(size)):
            context.taintMemory(access)

    recorder.memory_taint_hook = taint_memory_range
    for source in harness["taint_sources"]:
        if source["kind"] == "register" and source.get("register"):
            context.taintRegister(getattr(context.registers, source["register"]))
            recorder._labels_by_register[source["register"]] = {source["label"]}
        elif source["kind"] == "memory" and source.get("address"):
            recorder.memory_taint_hook(int(source["address"]), int(source["size"]))
    if not harness["taint_sources"]:
        unknowns.append("harness declares no taint source; no taint flow can be observed")

    disassembler = Cs(CS_ARCH_X86, CS_MODE_64)
    disassembler.detail = True
    stubs_by_target = {int(stub["target"]): stub for stub in harness["callee_stubs"]}
    stop_addresses = {
        int(item["address"]) for item in harness["stop_conditions"] if item["kind"] == "ADDRESS"
    }
    stop_kinds = {item["kind"] for item in harness["stop_conditions"]}

    trace: list[dict[str, Any]] = []
    memory_reads: list[dict[str, Any]] = []
    memory_writes: list[dict[str, Any]] = []
    violations: list[dict[str, Any]] = []
    branches: list[dict[str, Any]] = []
    calls: list[dict[str, Any]] = []
    stubs_used: list[dict[str, Any]] = []
    executed = 0
    stop_reason = STOP_ERROR
    return_value: int | None = None
    status = "COMPLETED"
    function_end = int(harness["function_end"])
    output_regions = harness.get("output_regions", [])

    def output_region_of(address: int) -> dict[str, Any] | None:
        for region in output_regions:
            if int(region["address"]) <= address < int(region["address"]) + int(region["size"]):
                return region
        return None

    try:
        while True:
            if time.monotonic() - started > timeout_seconds:
                stop_reason = STOP_TIMEOUT
                status = "TIMEOUT"
                break
            if executed >= instruction_limit:
                stop_reason = STOP_INSTRUCTION_LIMIT
                status = "RESOURCE_LIMIT"
                break
            if len(context.getSymbolicExpressions()) > symbolic_limit:
                stop_reason = STOP_SYMBOLIC_LIMIT
                status = "RESOURCE_LIMIT"
                break
            rip = context.getConcreteRegisterValue(context.registers.rip)
            if "EXECUTE_UNMAPPED" in stop_kinds and not model.permissions(rip).count("x"):
                violations.append(
                    {"kind": VIOLATION_EXECUTE_UNMAPPED, "address": rip, "size": 1, "instruction": executed}
                )
                stop_reason = STOP_UNMAPPED
                status = "ANALYSIS_INCOMPLETE"
                break
            if rip in stubs_by_target:
                # A registered stub is entered only after Triton has executed the real CALL. The
                # architectural stack is authoritative: the return address must be present at RSP
                # and must match the call-site metadata captured immediately after CALL.
                stub = stubs_by_target[rip]
                spec = STUBS[stub["behavior"]]
                call_meta = stub_call_sites.get(rip)
                if call_meta is None or call_depth <= 0:
                    violations.append(
                        {
                            "kind": VIOLATION_CALL_STACK_UNDERFLOW,
                            "address": rip,
                            "size": 8,
                            "stub": stub["name"],
                        }
                    )
                    stop_reason = STOP_UNMAPPED
                    status = "ANALYSIS_INCOMPLETE"
                    break
                stack_pointer = context.getConcreteRegisterValue(context.registers.rsp)
                try:
                    raw_return = bytes(context.getConcreteMemoryAreaValue(stack_pointer, 8))
                except Exception:  # noqa: BLE001 - structured worker failure, never escape
                    raw_return = b""
                if len(raw_return) != 8:
                    violations.append(
                        {
                            "kind": VIOLATION_CORRUPTED_STACK_RETURN,
                            "address": stack_pointer,
                            "size": 8,
                            "stub": stub["name"],
                        }
                    )
                    stop_reason = STOP_UNMAPPED
                    status = "ANALYSIS_INCOMPLETE"
                    break
                stub_return_target = int.from_bytes(raw_return, "little")
                if (
                    stack_pointer != call_meta["rsp_after"]
                    or stub_return_target != call_meta["return_address"]
                ):
                    violations.append(
                        {
                            "kind": VIOLATION_CORRUPTED_STACK_RETURN,
                            "address": stack_pointer,
                            "size": 8,
                            "stub": stub["name"],
                            "expected_return_address": call_meta["return_address"],
                            "observed_return_address": stub_return_target,
                        }
                    )
                    stop_reason = STOP_UNMAPPED
                    status = "ANALYSIS_INCOMPLETE"
                    break
                length_tainted = recorder.register_is_tainted(context, "rdx")
                event = apply_stub(
                    context,
                    model,
                    stub,
                    spec,
                    recorder,
                    call_site=call_meta["call_site"],
                )
                if length_tainted:
                    recorder.record_sink(
                        sink_type="MEMORY_LENGTH",
                        address=event.get("destination"),
                        instruction=call_meta["call_site"],
                        detail=f"tainted length reached {stub['behavior']}",
                        labels=recorder.labels_of_registers(["rdx"]),
                    )
                stubs_used.append(event)
                violations.extend(event["violations"])
                if event["violations"]:
                    stop_reason = STOP_UNMAPPED
                    status = "ANALYSIS_INCOMPLETE"
                    break
                # There is no real RET instruction in a stub, so this is the one place where the
                # worker performs a synthetic architectural return.
                rsp_before_return = stack_pointer
                context.setConcreteRegisterValue(context.registers.rsp, stack_pointer + 8)
                context.setConcreteRegisterValue(context.registers.rip, stub_return_target)
                depth_before = call_depth
                call_depth -= 1
                return_events.append(
                    {
                        "ret_instruction": None,
                        "stack_slot": stack_pointer,
                        "popped": stub_return_target,
                        "target": stub_return_target,
                        "rsp_before": rsp_before_return,
                        "rsp_after": stack_pointer + 8,
                        "depth_before": depth_before,
                        "depth_after": call_depth,
                        "classification": "STUB_RETURN",
                        "stub": stub["name"],
                    }
                )
                if len(trace) < trace_limit:
                    trace.append(
                        {
                            "index": executed,
                            "address": rip,
                            "instruction": f"<stub {stub['name']}>",
                            "reads": list(spec["arguments"]),
                            "writes": sorted({"rax", *spec["clobbers"]}),
                            "tainted_inputs": [
                                name
                                for name in spec["arguments"]
                                if recorder.register_is_tainted(context, name)
                            ],
                            "tainted_outputs": [],
                            "memory_reads": [],
                            "memory_writes": [],
                            "symbolic_expressions": 0,
                            "path_constraints": 0,
                            "tainted": False,
                            "event": "STUB_RETURN",
                            "target": stub_return_target,
                            "call_depth": call_depth,
                        }
                    )
                executed += 1
                continue
            if rip >= function_end:
                stop_reason = STOP_FUNCTION_END
                break
            if rip in stop_addresses:
                stop_reason = STOP_ADDRESS
                break
            if not model.permissions(rip).count("x"):
                violations.append(
                    {"kind": VIOLATION_EXECUTE_UNMAPPED, "address": rip, "size": 1, "instruction": executed}
                )
                stop_reason = STOP_UNMAPPED
                status = "ANALYSIS_INCOMPLETE"
                break
            code = model.read(rip, 16)
            if code is None:
                violations.append(
                    {"kind": VIOLATION_EXECUTE_UNMAPPED, "address": rip, "size": 1, "instruction": executed}
                )
                stop_reason = STOP_UNMAPPED
                status = "ANALYSIS_INCOMPLETE"
                break
            decoded = None
            for candidate in disassembler.disasm(code, rip, count=1):
                decoded = candidate
            if decoded is None:
                stop_reason = STOP_INVALID_INSTRUCTION
                status = "ANALYSIS_INCOMPLETE"
                break

            instruction = TritonInstruction(rip, code[: decoded.size])
            context.disassembly(instruction)
            constraints_before = len(context.getPathConstraints())
            expressions_before = len(context.getSymbolicExpressions())
            # Triton only populates the register read/write lists once an instruction has been
            # processed, so the taint state has to be snapshotted up front and the read set
            # interpreted against that snapshot afterwards.
            tainted_registers_before = set(
                register_names(context, list(context.getTaintedRegisters()))
            )

            # Far returns / interrupt returns have control-flow semantics outside the bounded B1
            # harness model. Stop before executing them so partially changed architectural state is
            # never mistaken for a supported near return.
            return_mnemonic = decoded.mnemonic.lower()
            if return_mnemonic in {"retf", "retfq", "iret", "iretd", "iretq"}:
                violations.append(
                    {
                        "kind": VIOLATION_UNSUPPORTED_RETURN_FORM,
                        "address": rip,
                        "size": decoded.size,
                        "ret_instruction": rip,
                        "mnemonic": decoded.mnemonic,
                    }
                )
                stop_reason = VIOLATION_UNSUPPORTED_RETURN_FORM
                status = "ANALYSIS_INCOMPLETE"
                break

            is_near_return = return_mnemonic in {"ret", "retn"} or bool(
                decoded.groups and CS_GRP_RET in decoded.groups
            )
            return_pre_state: dict[str, int] | None = None
            if is_near_return:
                stack_pointer = context.getConcreteRegisterValue(context.registers.rsp)
                access_kind = model.access_violation(stack_pointer, 8, "read")
                if access_kind is not None:
                    violations.append(
                        {
                            "kind": access_kind,
                            "address": stack_pointer,
                            "size": 8,
                            "ret_instruction": rip,
                        }
                    )
                    stop_reason = STOP_UNMAPPED
                    status = "ANALYSIS_INCOMPLETE"
                    break
                try:
                    raw_return = bytes(context.getConcreteMemoryAreaValue(stack_pointer, 8))
                except Exception:  # noqa: BLE001 - malformed guest state becomes evidence
                    raw_return = b""
                if len(raw_return) != 8:
                    violations.append(
                        {
                            "kind": VIOLATION_CORRUPTED_STACK_RETURN,
                            "address": stack_pointer,
                            "size": 8,
                            "ret_instruction": rip,
                        }
                    )
                    stop_reason = STOP_UNMAPPED
                    status = "ANALYSIS_INCOMPLETE"
                    break
                cleanup = 0
                if decoded.operands and decoded.operands[0].type == CS_OP_IMM:
                    cleanup = int(decoded.operands[0].imm) & 0xFFFF
                return_pre_state = {
                    "stack_pointer": stack_pointer,
                    "target": int.from_bytes(raw_return, "little"),
                    "cleanup": cleanup,
                    "depth_before": call_depth,
                }

            if decoded.mnemonic == "call":
                call_spec = stubs_by_target.get(
                    int(decoded.operands[0].imm) if (decoded.operands and decoded.operands[0].type == CS_OP_IMM) else -1
                )
                call_arguments = (
                    call_spec and STUBS[call_spec["behavior"]]["arguments"] or []
                )
                reads = [name for name in call_arguments if name in tainted_registers_before]
                tainted_inputs = list(reads)
                operand = decoded.operands[0] if decoded.operands else None
                target: int | None = None
                indirect = operand is not None and operand.type != CS_OP_IMM
                if operand is not None and operand.type == CS_OP_IMM:
                    target = int(operand.imm)
                elif operand is not None and operand.type == CS_OP_REG:
                    target = context.getConcreteRegisterValue(
                        getattr(context.registers, decoded.reg_name(operand.reg))
                    )
                elif operand is not None and operand.type == CS_OP_MEM:
                    # Indirect call through memory: only the concrete pointer stored at the operand
                    # address is used. Nothing is guessed.
                    base = (
                        context.getConcreteRegisterValue(
                            getattr(context.registers, decoded.reg_name(operand.mem.base))
                        )
                        if operand.mem.base
                        else 0
                    )
                    index = 0
                    if operand.mem.index:
                        index = context.getConcreteRegisterValue(
                            getattr(context.registers, decoded.reg_name(operand.mem.index))
                        ) * max(operand.mem.scale, 1)
                    pointer = model.read(base + index + operand.mem.disp, 8)
                    target = int.from_bytes(pointer, "little") if pointer else None

                if target is not None and function_entry <= target < function_end:
                    classification = CALL_INTERNAL
                elif target is not None and target in stubs_by_target:
                    classification = CALL_REGISTERED_STUB
                elif indirect and target is None:
                    classification = CALL_INDIRECT_UNRESOLVED
                else:
                    classification = CALL_EXTERNAL_UNKNOWN

                if classification == CALL_INTERNAL:
                    # A real callee runs its own instructions. No abstract ABI clobber is applied:
                    # only the instructions that actually execute change register state.
                    return_address = rip + decoded.size
                    if call_depth + 1 > max_call_depth_limit:
                        violations.append(
                            {
                                "kind": VIOLATION_CALL_DEPTH_EXCEEDED,
                                "address": rip,
                                "size": 8,
                                "target": target,
                                "call_depth": call_depth + 1,
                            }
                        )
                        stop_reason = VIOLATION_CALL_DEPTH_EXCEEDED
                        status = "RESOURCE_LIMIT"
                        break
                    if internal_calls + 1 > max_internal_calls_limit:
                        violations.append(
                            {
                                "kind": "INTERNAL_CALL_LIMIT",
                                "address": rip,
                                "size": 8,
                                "internal_calls": internal_calls + 1,
                            }
                        )
                        stop_reason = "INTERNAL_CALL_LIMIT"
                        status = "RESOURCE_LIMIT"
                        break
                    if target not in instruction_starts:
                        violations.append(
                            {
                                "kind": VIOLATION_INVALID_CALL_TARGET,
                                "address": target,
                                "size": decoded.size,
                                "call_from": rip,
                            }
                        )
                        stop_reason = STOP_UNMAPPED
                        status = "ANALYSIS_INCOMPLETE"
                        break
                    if not model.permissions(target).count("x"):
                        violations.append(
                            {
                                "kind": VIOLATION_CALL_TARGET_NOT_EXECUTABLE,
                                "address": target,
                                "size": decoded.size,
                            }
                        )
                        stop_reason = STOP_UNMAPPED
                        status = "ANALYSIS_INCOMPLETE"
                        break
                    # Triton is authoritative for the architectural CALL effect (RSP -= 8,
                    # [RSP] = return address, RIP = target): verified by
                    # scripts/probe_triton_call_ret.py. The worker verifies the effect and never
                    # pushes a second return address.
                    rsp_before = context.getConcreteRegisterValue(context.registers.rsp)
                    stack_slot = rsp_before - 8
                    stack_violation = model.access_violation(stack_slot, 8, "write")
                    if stack_violation is not None:
                        violations.append(
                            {
                                "kind": stack_violation,
                                "address": stack_slot,
                                "size": 8,
                                "call_from": rip,
                            }
                        )
                        stop_reason = STOP_UNMAPPED
                        status = "ANALYSIS_INCOMPLETE"
                        break
                    context.processing(instruction)
                    rip_after = context.getConcreteRegisterValue(context.registers.rip)
                    rsp_after = context.getConcreteRegisterValue(context.registers.rsp)
                    slot_bytes = bytes(context.getConcreteMemoryAreaValue(rsp_after, 8))
                    model.write(rsp_after, slot_bytes)
                    conflict = (
                        rip_after != target
                        or rsp_after != rsp_before - 8
                        or int.from_bytes(slot_bytes, "little") != return_address
                    )
                    if conflict:
                        violations.append(
                            {
                                "kind": VIOLATION_CONTROL_FLOW_CONFLICT,
                                "address": rip,
                                "size": decoded.size,
                                "expected_target": target,
                                "target_after": rip_after,
                                "expected_return_address": return_address,
                            }
                        )
                        stop_reason = STOP_UNMAPPED
                        status = "ANALYSIS_INCOMPLETE"
                        break
                    call_depth += 1
                    internal_calls += 1
                    max_call_depth_reached = max(max_call_depth_reached, call_depth)
                    call_events.append(
                        {
                            "caller": rip,
                            "call_instruction": f"{decoded.mnemonic} {decoded.op_str}".strip(),
                            "target": target,
                            "classification": classification,
                            "return_address": return_address,
                            "rsp_before": rsp_before,
                            "rsp_after": rsp_after,
                            "depth_before": call_depth - 1,
                            "depth_after": call_depth,
                        }
                    )
                    if len(trace) < trace_limit:
                        trace.append(
                            {
                                "index": executed,
                                "address": rip,
                                "instruction": f"{decoded.mnemonic} {decoded.op_str}".strip(),
                                "reads": reads,
                                "writes": ["rip", "rsp"],
                                "tainted_inputs": tainted_inputs,
                                "tainted_outputs": [],
                                "memory_reads": [],
                                "memory_writes": [{"instruction": rip, "address": rsp_after, "size": 8}],
                                "symbolic_expressions": 0,
                                "path_constraints": 0,
                                "tainted": bool(tainted_inputs),
                                "event": "INTERNAL_CALL",
                                "target": target,
                                "call_depth": call_depth,
                            }
                        )
                    executed += 1
                    continue

                if classification != CALL_REGISTERED_STUB:
                    reason = (
                        "indirect call target did not resolve to one concrete executable value"
                        if classification == CALL_INDIRECT_UNRESOLVED
                        else "no callee stub declared for this target"
                    )
                    calls.append(
                        {
                            "address": rip,
                            "target": target,
                            "resolved": False,
                            "classification": classification,
                            "reason": reason,
                        }
                    )
                    if len(trace) < trace_limit:
                        trace.append(
                            {
                                "index": executed,
                                "address": rip,
                                "instruction": f"{decoded.mnemonic} {decoded.op_str}".strip(),
                                "reads": reads,
                                "writes": [],
                                "tainted_inputs": tainted_inputs,
                                "tainted_outputs": [],
                                "memory_reads": [],
                                "memory_writes": [],
                                "symbolic_expressions": 0,
                                "path_constraints": 0,
                                "tainted": bool(tainted_inputs),
                                "event": "STUB_REQUIRED",
                                "target": target,
                            }
                        )
                    stop_reason = (
                        STOP_INDIRECT_CALL_UNRESOLVED
                        if classification == CALL_INDIRECT_UNRESOLVED
                        else STOP_STUB_REQUIRED
                    )
                    status = "ANALYSIS_INCOMPLETE"
                    break
                # Registered stubs still receive a real CALL. Triton performs the architectural
                # push and transfers RIP to the stub target; the next loop iteration intercepts the
                # target and applies the deterministic stub semantics.
                stub = stubs_by_target[target]
                return_address = rip + decoded.size
                if call_depth + 1 > max_call_depth_limit:
                    violations.append(
                        {
                            "kind": VIOLATION_CALL_DEPTH_EXCEEDED,
                            "address": rip,
                            "size": 8,
                            "target": target,
                            "call_depth": call_depth + 1,
                        }
                    )
                    stop_reason = VIOLATION_CALL_DEPTH_EXCEEDED
                    status = "RESOURCE_LIMIT"
                    break
                rsp_before = context.getConcreteRegisterValue(context.registers.rsp)
                stack_slot = rsp_before - 8
                stack_violation = model.access_violation(stack_slot, 8, "write")
                if stack_violation is not None:
                    violations.append(
                        {
                            "kind": stack_violation,
                            "address": stack_slot,
                            "size": 8,
                            "call_from": rip,
                        }
                    )
                    stop_reason = STOP_UNMAPPED
                    status = "ANALYSIS_INCOMPLETE"
                    break
                context.processing(instruction)
                rip_after = context.getConcreteRegisterValue(context.registers.rip)
                rsp_after = context.getConcreteRegisterValue(context.registers.rsp)
                slot_bytes = bytes(context.getConcreteMemoryAreaValue(rsp_after, 8))
                if model.access_violation(rsp_after, 8, "write") is None:
                    model.write(rsp_after, slot_bytes)
                conflict = (
                    rip_after != target
                    or rsp_after != rsp_before - 8
                    or int.from_bytes(slot_bytes, "little") != return_address
                )
                if conflict:
                    violations.append(
                        {
                            "kind": VIOLATION_CONTROL_FLOW_CONFLICT,
                            "address": rip,
                            "size": decoded.size,
                            "expected_target": target,
                            "target_after": rip_after,
                            "expected_return_address": return_address,
                        }
                    )
                    stop_reason = STOP_UNMAPPED
                    status = "ANALYSIS_INCOMPLETE"
                    break
                call_depth += 1
                max_call_depth_reached = max(max_call_depth_reached, call_depth)
                stub_call_sites[target] = {
                    "call_site": rip,
                    "return_address": return_address,
                    "rsp_after": rsp_after,
                }
                call_events.append(
                    {
                        "caller": rip,
                        "call_instruction": f"{decoded.mnemonic} {decoded.op_str}".strip(),
                        "target": target,
                        "classification": CALL_REGISTERED_STUB,
                        "return_address": return_address,
                        "rsp_before": rsp_before,
                        "rsp_after": rsp_after,
                        "depth_before": call_depth - 1,
                        "depth_after": call_depth,
                    }
                )
                calls.append(
                    {
                        "address": rip,
                        "target": target,
                        "resolved": True,
                        "classification": CALL_REGISTERED_STUB,
                        "stub": stub["name"],
                        "behavior": stub["behavior"],
                    }
                )
                if len(trace) < trace_limit:
                    trace.append(
                        {
                            "index": executed,
                            "address": rip,
                            "instruction": f"{decoded.mnemonic} {decoded.op_str}".strip(),
                            "reads": reads,
                            "writes": ["rip", "rsp"],
                            "tainted_inputs": tainted_inputs,
                            "tainted_outputs": [],
                            "memory_reads": [],
                            "memory_writes": [
                                {"instruction": rip, "address": rsp_after, "size": 8}
                            ],
                            "symbolic_expressions": 0,
                            "path_constraints": 0,
                            "tainted": bool(tainted_inputs),
                            "event": "STUB_CALL",
                            "stub": stub["name"],
                            "target": target,
                            "call_depth": call_depth,
                        }
                    )
                executed += 1
                continue

            # Triton reports 0 from processing() when an instruction produced no symbolic
            # expression (a plain concrete move, for example). Instruction validity is decided by
            # Capstone decoding above, so this return value is not a failure signal.
            context.processing(instruction)
            executed += 1

            reads = register_names(context, list(instruction.getReadRegisters()))
            writes = register_names(context, list(instruction.getWrittenRegisters()))
            tainted_inputs = sorted(
                name for name in reads if name in tainted_registers_before
            )
            index_registers: set[str] = set()
            base_registers: set[str] = set()
            for operand in decoded.operands if decoded.operands else []:
                if operand.type == CS_OP_MEM:
                    if operand.mem.index:
                        index_registers.add(decoded.reg_name(operand.mem.index))
                    if operand.mem.base:
                        base_registers.add(decoded.reg_name(operand.mem.base))
            tainted_index = sorted(
                name for name in index_registers if recorder.register_is_tainted(context, name)
            )
            tainted_base = sorted(
                name for name in base_registers if recorder.register_is_tainted(context, name)
            )
            loads = []
            for access, _ast in instruction.getLoadAccess():
                address, size = int(access.getAddress()), int(access.getSize())
                entry = {"instruction": rip, "address": address, "size": size}
                memory_reads.append(entry)
                kind = model.access_violation(address, size, "read")
                if kind is not None:
                    violations.append({**entry, "kind": kind})
                loads.append(entry)
            stores = []
            for access, _ast in instruction.getStoreAccess():
                address, size = int(access.getAddress()), int(access.getSize())
                entry = {"instruction": rip, "address": address, "size": size}
                memory_writes.append(entry)
                kind = model.access_violation(address, size, "write")
                if kind is not None:
                    violations.append({**entry, "kind": kind})
                else:
                    # Triton has already executed the store. Mirror the resulting concrete bytes
                    # into MemoryModel so stubbed callees and control-flow checks see architectural
                    # guest state rather than stale setup bytes.
                    concrete_store = bytes(context.getConcreteMemoryAreaValue(address, size))
                    model.write(address, concrete_store)
                stores.append(entry)
                if output_region_of(address) is not None and tainted_inputs:
                    recorder.record_sink(
                        sink_type="DESCRIPTOR_FIELD",
                        address=address,
                        instruction=rip,
                        detail=f"{decoded.mnemonic} stored a tainted value into an output region",
                        labels=recorder.labels_of_registers(tainted_inputs),
                    )
            access_address = next(
                (item["address"] for item in (*loads, *stores)),
                None,
            )
            if tainted_index:
                recorder.record_sink(
                    sink_type="ARRAY_INDEX",
                    address=access_address,
                    instruction=rip,
                    detail="tainted register used as a memory index",
                    labels=recorder.labels_of_registers(tainted_index),
                )
            elif tainted_base:
                recorder.record_sink(
                    sink_type="MEMORY_ADDRESS",
                    address=access_address,
                    instruction=rip,
                    detail="tainted register used as a memory base address",
                    labels=recorder.labels_of_registers(tainted_base),
                )
            if violations and any(
                item["instruction"] == rip for item in violations if "instruction" in item
            ):
                stop_reason = STOP_UNMAPPED
                status = "ANALYSIS_INCOMPLETE"

            newly_tainted = [
                name for name in writes if recorder.register_is_tainted(context, name)
            ]
            memory_labelled = set()
            for entry in loads:
                memory_labelled |= recorder._range_labels(entry["address"], entry["size"])
            propagated = recorder.labels_of_registers(tainted_inputs) | memory_labelled
            if newly_tainted and propagated:
                for name in newly_tainted:
                    recorder.mark_register_tainted(context, name, propagated)
                    recorder.record_transformation(
                        address=rip,
                        instruction=f"{decoded.mnemonic} {decoded.op_str}".strip(),
                        inputs=tainted_inputs,
                        output=name,
                        output_kind="register",
                    )
            for name in writes:
                if name not in newly_tainted:
                    # A register that was redefined without receiving taint loses its old labels:
                    # an overwrite must clear stale taint instead of inheriting it.
                    recorder._labels_by_register.pop(name, None)
            if decoded.groups and CS_GRP_JUMP in decoded.groups and decoded.mnemonic != "jmp":
                constraints_after = context.getPathConstraints()
                new_constraints = constraints_after[constraints_before:]
                condition_tainted = bool(tainted_inputs)
                # Triton has already applied the concrete branch semantics. A conditional branch
                # is taken exactly when the post-instruction RIP differs from the architectural
                # fall-through address. Do not infer this from the existence of a path constraint:
                # concrete/non-symbolic branches may legitimately have no new constraint.
                rip_after_branch = context.getConcreteRegisterValue(context.registers.rip)
                fallthrough = rip + decoded.size
                branch_evidence: dict[str, Any] = {
                    "address": rip,
                    "instruction": f"{decoded.mnemonic} {decoded.op_str}".strip(),
                    "taken": rip_after_branch != fallthrough,
                    "next_rip": rip_after_branch,
                    "fallthrough": fallthrough,
                    "tainted_condition": condition_tainted,
                    "constraints": [describe_constraint(item) for item in new_constraints],
                }
                if condition_tainted:
                    recorder.record_sink(
                        sink_type="BRANCH_CONDITION",
                        address=rip,
                        instruction=rip,
                        detail="branch condition depends on tainted input",
                        labels=recorder.labels_of_registers(tainted_inputs),
                    )
                branches.append(branch_evidence)
                if len(branches) >= branch_limit:
                    stop_reason = STOP_BRANCH_LIMIT
                    status = "RESOURCE_LIMIT"
                    break

            if len(trace) < trace_limit:
                trace.append(
                    {
                        "index": executed - 1,
                        "address": rip,
                        "instruction": f"{decoded.mnemonic} {decoded.op_str}".strip(),
                        "reads": reads,
                        "writes": writes,
                        "tainted_inputs": tainted_inputs,
                        "tainted_outputs": newly_tainted,
                        "memory_reads": loads,
                        "memory_writes": stores,
                        "symbolic_expressions": len(context.getSymbolicExpressions())
                        - expressions_before,
                        "path_constraints": len(context.getPathConstraints()) - constraints_before,
                        "tainted": bool(tainted_inputs or newly_tainted),
                    }
                )
            if violations and any(
                item["instruction"] == rip for item in violations if "instruction" in item
            ):
                break
            if is_near_return:
                # Triton executed this near RET exactly once. The pre-state was captured before
                # processing, so the worker only verifies the architectural effect afterwards.
                assert return_pre_state is not None
                stack_pointer = return_pre_state["stack_pointer"]
                return_target = return_pre_state["target"]
                cleanup = return_pre_state["cleanup"]
                rip_after = context.getConcreteRegisterValue(context.registers.rip)
                rsp_after = context.getConcreteRegisterValue(context.registers.rsp)
                expected_rsp_after = stack_pointer + 8 + cleanup
                if rip_after != return_target or rsp_after != expected_rsp_after:
                    violations.append(
                        {
                            "kind": VIOLATION_CONTROL_FLOW_CONFLICT,
                            "address": rip,
                            "size": decoded.size,
                            "expected_return_target": return_target,
                            "target_after": rip_after,
                            "expected_rsp_after": expected_rsp_after,
                            "rsp_after": rsp_after,
                        }
                    )
                    stop_reason = STOP_UNMAPPED
                    status = "ANALYSIS_INCOMPLETE"
                    break

                depth_before = call_depth
                event_base = {
                    "ret_instruction": rip,
                    "stack_slot": stack_pointer,
                    "popped": return_target,
                    "target": return_target,
                    "rsp_before": stack_pointer,
                    "rsp_after": rsp_after,
                    "depth_before": depth_before,
                }

                # The sentinel is a real qword in the outer caller's stack frame. Reaching the
                # sentinel is a successful harness return only when *all* outer-frame invariants
                # agree; this prevents a corrupted/nested stack from producing a false success.
                if return_target == SENTINEL_RETURN_ADDRESS:
                    if depth_before > 0:
                        violations.append(
                            {
                                "kind": VIOLATION_EARLY_SENTINEL_RETURN,
                                "address": return_target,
                                "size": 8,
                                "ret_instruction": rip,
                                "depth_before": depth_before,
                            }
                        )
                        return_events.append(
                            {
                                **event_base,
                                "depth_after": depth_before,
                                "classification": "EARLY_SENTINEL_RETURN",
                            }
                        )
                        stop_reason = STOP_UNMAPPED
                        status = "ANALYSIS_INCOMPLETE"
                        break
                    if not sentinel_installed or stack_pointer != sentinel_slot:
                        violations.append(
                            {
                                "kind": VIOLATION_CORRUPTED_STACK_RETURN,
                                "address": stack_pointer,
                                "size": 8,
                                "ret_instruction": rip,
                                "expected_outer_return_slot": sentinel_slot,
                            }
                        )
                        return_events.append(
                            {
                                **event_base,
                                "depth_after": depth_before,
                                "classification": "CORRUPTED_RETURN",
                            }
                        )
                        stop_reason = STOP_UNMAPPED
                        status = "ANALYSIS_INCOMPLETE"
                        break
                    return_events.append(
                        {
                            **event_base,
                            "depth_after": 0,
                            "classification": "HARNESS_RETURN",
                        }
                    )
                    stop_reason = STOP_RETURN
                    break

                if depth_before == 0:
                    # An outer RET that does not pop the installed sentinel means the guest stack
                    # was changed. Do not reinterpret it as an internal return.
                    violations.append(
                        {
                            "kind": VIOLATION_CORRUPTED_STACK_RETURN,
                            "address": stack_pointer,
                            "size": 8,
                            "ret_instruction": rip,
                            "observed_return_target": return_target,
                            "expected_outer_return_slot": sentinel_slot,
                            "expected_sentinel": SENTINEL_RETURN_ADDRESS,
                        }
                    )
                    return_events.append(
                        {
                            **event_base,
                            "depth_after": 0,
                            "classification": "CORRUPTED_RETURN",
                        }
                    )
                    stop_reason = STOP_UNMAPPED
                    status = "ANALYSIS_INCOMPLETE"
                    break

                permissions = model.permissions(return_target)
                if not permissions:
                    violations.append(
                        {
                            "kind": VIOLATION_RETURN_TO_UNMAPPED,
                            "address": return_target,
                            "size": 8,
                            "ret_instruction": rip,
                        }
                    )
                    stop_reason = STOP_UNMAPPED
                    status = "ANALYSIS_INCOMPLETE"
                    break
                if "x" not in permissions:
                    violations.append(
                        {
                            "kind": VIOLATION_RETURN_TO_NON_EXECUTABLE,
                            "address": return_target,
                            "size": 8,
                            "ret_instruction": rip,
                        }
                    )
                    stop_reason = STOP_UNMAPPED
                    status = "ANALYSIS_INCOMPLETE"
                    break
                if return_target not in instruction_starts:
                    violations.append(
                        {
                            "kind": VIOLATION_INVALID_RETURN_TARGET,
                            "address": return_target,
                            "size": 8,
                            "ret_instruction": rip,
                        }
                    )
                    stop_reason = STOP_UNMAPPED
                    status = "ANALYSIS_INCOMPLETE"
                    break
                call_depth -= 1
                if call_depth < 0:
                    violations.append(
                        {
                            "kind": VIOLATION_CALL_STACK_UNDERFLOW,
                            "address": rip,
                            "size": decoded.size,
                        }
                    )
                    stop_reason = STOP_UNMAPPED
                    status = "ANALYSIS_INCOMPLETE"
                    break
                return_events.append(
                    {
                        **event_base,
                        "depth_after": call_depth,
                        "classification": "INTERNAL_RETURN",
                    }
                )
                # RIP/RSP were already set by Triton's RET semantics. The generic instruction trace
                # above contains the memory read; append only the control-flow classification.
                if len(trace) < trace_limit:
                    trace.append(
                        {
                            "index": executed - 1,
                            "address": rip,
                            "instruction": f"{decoded.mnemonic} {decoded.op_str}".strip(),
                            "reads": reads,
                            "writes": writes,
                            "tainted_inputs": tainted_inputs,
                            "tainted_outputs": newly_tainted,
                            "memory_reads": [
                                {"instruction": rip, "address": stack_pointer, "size": 8}
                            ],
                            "memory_writes": [],
                            "symbolic_expressions": 0,
                            "path_constraints": 0,
                            "tainted": bool(tainted_inputs),
                            "event": "INTERNAL_RETURN",
                            "target": return_target,
                            "call_depth": call_depth,
                        }
                    )
                continue
    except Exception as exc:  # noqa: BLE001 - worker must never crash the core
        import traceback

        emit(
            {
                "status": "ERROR",
                "version": version,
                "errors": [
                    f"triton worker failed: {type(exc).__name__}: {exc}",
                    traceback.format_exc()[-600:],
                ],
                "data": {"instructions_executed": executed, "stop_reason": STOP_ERROR},
            }
        )
        return 0

    if stop_reason in {STOP_RETURN, STOP_ADDRESS, STOP_FUNCTION_END} and not violations:
        status = "COMPLETED"
    elif stop_reason in {STOP_INSTRUCTION_LIMIT, STOP_BRANCH_LIMIT, STOP_SYMBOLIC_LIMIT}:
        status = "RESOURCE_LIMIT"
    elif stop_reason == STOP_TIMEOUT:
        status = "TIMEOUT"
    elif status == "COMPLETED":
        status = "ANALYSIS_INCOMPLETE"

    return_value = context.getConcreteRegisterValue(context.registers.rax)
    if recorder.register_is_tainted(context, "rax"):
        recorder.record_sink(
            sink_type="RETURN_VALUE",
            address=None,
            instruction=executed,
            detail="tainted value reached the return register",
            labels=recorder.labels_of_registers(["rax"]),
        )
    unknowns.append("B1 explores a single primary concrete path; alternate branches are not explored")

    full_trace_hash = hashlib.sha256(
        json.dumps(trace, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    data = {
        "execution_status": status,
        "stop_reason": stop_reason,
        "instructions_executed": executed,
        "call_depth": call_depth,
        "max_call_depth": max_call_depth_reached,
        "internal_calls": internal_calls,
        "call_events": call_events,
        "return_events": return_events,
        "sentinel_return_installed": sentinel_installed,
        "branches": branches,
        "calls": calls,
        "stubs_used": stubs_used,
        "taint_flows": recorder.document(),
        "memory_reads": memory_reads,
        "memory_writes": memory_writes,
        "memory_violations": violations,
        "return_value": return_value,
        "symbolic_inputs": symbolic_applied,
        "symbolic_expressions": len(context.getSymbolicExpressions()),
        "path_constraints": [str(item) for item in context.getPathConstraints()],
        "trace": trace,
        "trace_sha256": full_trace_hash,
        "trace_entry_count": len(trace),
        "trace_truncated": len(trace) >= trace_limit,
        "register_trace_enabled": True,
        "memory_trace_enabled": True,
        "branch_trace_enabled": True,
        "unknowns": sorted(set(unknowns)),
        "operation": operation,
        "elapsed_seconds": round(time.monotonic() - started, 6),
        "stub_registry_used": sorted({stub["behavior"] for stub in stubs_used}),
        "engine": {"name": "triton", "version": version},
    }
    emit({"status": status, "version": version, "data": data, "errors": [], "unknowns": sorted(set(unknowns))})
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
