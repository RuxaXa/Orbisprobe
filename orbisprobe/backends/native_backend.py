from __future__ import annotations

import hashlib
from importlib.metadata import PackageNotFoundError
from importlib.metadata import version as distribution_version
from pathlib import Path
from typing import Any

from orbisprobe.analysis.binary import BinaryImage
from orbisprobe.analysis.dataflow import (
    DataflowAnalyzer,
    SourceSpec,
    normalize_register,
)

from .base import (
    AnalysisBackend,
    BackendCapability,
    BackendEvidence,
    BackendIdentity,
    BackendResult,
    BackendStatus,
    ResourceLimits,
)

CAPABILITIES = frozenset(
    {
        BackendCapability.CFG,
        BackendCapability.DATAFLOW,
        BackendCapability.CALLGRAPH,
        BackendCapability.MEMORY_MODEL,
    }
)


class NativeBackend(AnalysisBackend):
    identity = BackendIdentity(
        name="native",
        version="unknown",
        independence_family="capstone-native",
        capabilities=CAPABILITIES,
        implementation="orbisprobe-capstone",
    )

    def __init__(self, limits: ResourceLimits | None = None) -> None:
        super().__init__(limits)
        self.identity = BackendIdentity(
            name="native",
            version=self.version(),
            independence_family="capstone-native",
            capabilities=CAPABILITIES,
            implementation="orbisprobe-capstone",
        )

    def version(self) -> str:
        try:
            import capstone  # noqa: F401 - import verifies the runtime module is usable

            return distribution_version("capstone")
        except (ImportError, PackageNotFoundError):
            return "unavailable"

    def availability(self) -> BackendResult:
        if self.version() == "unavailable":
            return BackendResult.unavailable(self.identity, "capstone is not installed")
        return BackendResult.completed(self.identity, {"available": True})

    @staticmethod
    def _image(request: dict[str, Any]) -> BinaryImage:
        path = Path(request["binary"]).expanduser().resolve()
        if not path.is_file():
            raise ValueError(f"binary is not a regular file: {path}")
        return BinaryImage.open(
            path,
            architecture=request.get("architecture", "x86_64"),
            base=int(request["base"]),
        )

    @staticmethod
    def _range(request: dict[str, Any], image: BinaryImage) -> tuple[int, int]:
        start = int(request["function"])
        end = int(request.get("function_end", min(image.base + image.size, start + 0x1000)))
        image.file_offset(start)
        if end < image.base or end > image.base + image.size:
            raise ValueError("function_end outside binary")
        if end <= start:
            raise ValueError("function_end must be greater than function")
        return start, end

    def _error(self, exc: Exception) -> BackendResult:
        return BackendResult(self.identity, BackendStatus.ERROR, errors=[f"{type(exc).__name__}: {exc}"])

    def analyze_function(self, request: dict[str, Any]) -> BackendResult:
        try:
            image = self._image(request)
            start, end = self._range(request, image)
            instructions = [
                {
                    "address": item.address,
                    "size": item.size,
                    "mnemonic": item.mnemonic,
                    "op_str": item.op_str,
                }
                for item in image.disassemble(start=start, end=end)
                if item.mnemonic != ".byte"
            ]
            return BackendResult.completed(
                self.identity,
                {
                    "binary_sha256": hashlib.sha256(image.data).hexdigest(),
                    "function": start,
                    "end": end,
                    "instructions": instructions,
                },
            )
        except (OSError, ValueError, RuntimeError, KeyError) as exc:
            return self._error(exc)

    def recover_cfg(self, request: dict[str, Any]) -> BackendResult:
        result = self.analyze_function(request)
        if result.status is not BackendStatus.COMPLETED:
            return result
        blocks = []
        calls = []
        for item in result.data["instructions"]:
            if not blocks or item["mnemonic"].startswith("j"):
                blocks.append({"address": item["address"]})
            if item["mnemonic"] == "call":
                calls.append({"address": item["address"], "op_str": item["op_str"]})
        result.data = {"function": result.data["function"], "blocks": blocks, "calls": calls}
        return result

    @staticmethod
    def _source(raw: dict[str, Any]) -> SourceSpec:
        return SourceSpec(
            register=raw.get("register"),
            definition_address=raw.get("definition_address"),
            memory_base=raw.get("memory_base", raw.get("base_register")),
            memory_displacement=raw.get("memory_displacement", raw.get("offset")),
        )

    def trace_value(self, request: dict[str, Any]) -> BackendResult:
        try:
            image = self._image(request)
            start, end = self._range(request, image)
            analysis = DataflowAnalyzer(image).analyze(
                function=start,
                end=end,
                source=self._source(dict(request.get("source", {}))),
                consumer=request.get("consumer"),
            )
            data = analysis.to_dict()
            events = [
                {
                    "address": item["address"],
                    "instruction": item["instruction"],
                    "kind": item["event"],
                    "register": item["register"],
                    "detail": item["detail"],
                }
                for item in data["events"]
            ]
            data["events"] = events
            evidence = [
                BackendEvidence(
                    kind=item["kind"],
                    subject=f"{item['register']}@0x{item['address']:x}",
                    value=item["detail"],
                    address=item["address"],
                    provenance={"source_class": "static", "engine": "native-capstone"},
                )
                for item in events
                if item["register"] is not None
            ]
            observe = (request.get("observe") or {}).get("register")
            consumer = request.get("consumer")
            if observe and consumer is not None:
                normalized = normalize_register(observe)
                reaches = any(
                    item["kind"] == "consumer"
                    and item["address"] == consumer
                    and item["register"] == normalized
                    for item in events
                )
                evidence.append(
                    BackendEvidence(
                        kind="register_lifetime",
                        subject=f"{normalized}@0x{consumer:x}",
                        value=reaches,
                        address=consumer,
                        provenance={"source_class": "static", "engine": "native-capstone"},
                    )
                )
            return BackendResult(
                identity=self.identity,
                status=BackendStatus.COMPLETED,
                data=data,
                evidence=evidence,
                unknowns=list(analysis.unknowns),
                partial=not analysis.proof_complete,
            )
        except (OSError, ValueError, RuntimeError, KeyError, TypeError) as exc:
            return self._error(exc)

    def find_definitions(self, request: dict[str, Any]) -> BackendResult:
        result = self.trace_value(request)
        result.data = {"definitions": [item for item in result.data.get("events", []) if item["kind"] == "definition"]}
        return result

    def find_consumers(self, request: dict[str, Any]) -> BackendResult:
        result = self.trace_value(request)
        result.data = {"consumers": [item for item in result.data.get("events", []) if item["kind"] in {"consumer", "use"}]}
        return result

    def resolve_call_arguments(self, request: dict[str, Any]) -> BackendResult:
        result = self.trace_value(request)
        result.status = BackendStatus.ANALYSIS_INCOMPLETE if result.status is BackendStatus.COMPLETED else result.status
        result.unknowns.append("native backend does not recover complete call arguments")
        return result

    def evaluate_branch_constraints(self, request: dict[str, Any]) -> BackendResult:
        result = self.recover_cfg(request)
        if result.status is BackendStatus.COMPLETED:
            result.status = BackendStatus.ANALYSIS_INCOMPLETE
            result.unknowns.append("native backend does not solve branch constraints")
        return result

    def analyze_memory_access(self, request: dict[str, Any]) -> BackendResult:
        try:
            from capstone import CS_OP_MEM

            image = self._image(request)
            start, end = self._range(request, image)
            accesses = []
            for instruction in image.disassemble(start=start, end=end):
                for operand in instruction.operands:
                    if operand.type != CS_OP_MEM:
                        continue
                    accesses.append(
                        {
                            "address": instruction.address,
                            "instruction": f"{instruction.mnemonic} {instruction.op_str}".strip(),
                            "base": instruction.reg_name(operand.mem.base) if operand.mem.base else None,
                            "index": instruction.reg_name(operand.mem.index) if operand.mem.index else None,
                            "scale": operand.mem.scale,
                            "displacement": operand.mem.disp,
                            "access": operand.access,
                        }
                    )
            return BackendResult.completed(self.identity, {"memory_accesses": accesses})
        except (ImportError, OSError, ValueError, RuntimeError, KeyError) as exc:
            return self._error(exc)
