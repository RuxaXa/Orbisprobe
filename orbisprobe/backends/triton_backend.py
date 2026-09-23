"""Triton dynamic-analysis backend (M2-B priority 1).

Runs one validated function harness in an isolated worker process. The core never imports Triton:
the backend only speaks JSON over stdio to a fixed worker script inside a pinned interpreter.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import resource
import subprocess
from pathlib import Path
from typing import Any

from orbisprobe.harness import STUB_REGISTRY_VERSION, Harness

from .base import (
    AnalysisBackend,
    BackendCapability,
    BackendEvidence,
    BackendIdentity,
    BackendResult,
    BackendStatus,
    ResourceLimits,
    ensure_json_domain,
)
from .dynamic import DynamicEvidence

CAPABILITIES = frozenset(
    {
        BackendCapability.CFG,
        BackendCapability.DATAFLOW,
        BackendCapability.SYMBOLIC,
        BackendCapability.TAINT,
        BackendCapability.EMULATION,
        BackendCapability.DYNAMIC_SYMBOLIC,
        BackendCapability.REGISTER_TRACE,
        BackendCapability.MEMORY_TRACE,
        BackendCapability.BRANCH_TRACE,
        BackendCapability.CALL_STUBS,
        BackendCapability.CONCRETE_EXECUTION,
        BackendCapability.HEADLESS,
    }
)

HARNESS_OPERATIONS = ("emulate", "taint", "trace")
DEFAULT_INTERPRETER = ".backend-envs/triton/bin/python"


class TritonBackend(AnalysisBackend):
    identity = BackendIdentity(
        name="triton",
        version="unknown",
        independence_family="triton-symbolic",
        capabilities=CAPABILITIES,
        implementation="external-worker",
    )

    def __init__(
        self,
        limits: ResourceLimits | None = None,
        interpreter: str | Path | None = None,
        worker: str | Path | None = None,
    ) -> None:
        super().__init__(limits)
        configured = interpreter or os.environ.get("ORBISPROBE_TRITON_PYTHON")
        if configured is None:
            configured = Path(__file__).parents[2] / DEFAULT_INTERPRETER
        self.interpreter = Path(configured).expanduser().absolute()
        self.worker = Path(
            worker or Path(__file__).parent / "workers" / "triton_worker.py"
        ).expanduser().absolute()
        self.script_dir = Path(__file__).parent / "workers"

    @staticmethod
    def _preexec():  # pragma: no cover - exercised through subprocess
        os.setsid()
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))

    def version(self) -> str:
        if not self.interpreter.is_file():
            return "unavailable"
        try:
            completed = subprocess.run(
                [
                    str(self.interpreter),
                    "-c",
                    "import importlib.metadata as m; print(m.version('triton-library'))",
                ],
                text=True,
                capture_output=True,
                timeout=60,
                check=False,
                shell=False,
            )
        except (OSError, subprocess.TimeoutExpired):
            return "unavailable"
        if completed.returncode != 0:
            return "unavailable"
        reported = completed.stdout.strip()
        if not re.match(r"^\d+\.\d+", reported):
            # A stand-in or misconfigured interpreter must not be mistaken for a working engine.
            return "unknown"
        return reported

    def _identity(self, version: str | None = None) -> BackendIdentity:
        return BackendIdentity(
            name="triton",
            version=version or self.version(),
            independence_family="triton-symbolic",
            capabilities=CAPABILITIES,
            implementation="external-worker",
        )

    def availability(self) -> BackendResult:
        identity = self._identity()
        if not self.interpreter.is_file() or not os.access(self.interpreter, os.X_OK):
            return BackendResult.unavailable(
                identity, f"triton interpreter unavailable: {self.interpreter}"
            )
        if not self.worker.is_file():
            return BackendResult.unavailable(identity, f"triton worker unavailable: {self.worker}")
        version = self.version()
        if version in {"unavailable", "unknown"}:
            return BackendResult.unavailable(identity, "triton-library is not installed in the worker env")
        return BackendResult.completed(
            self._identity(version),
            {
                "available": True,
                "interpreter": str(self.interpreter),
                "worker": str(self.worker),
                "stub_registry_version": STUB_REGISTRY_VERSION,
            },
        )

    @staticmethod
    def _parse_worker_response(payload: str) -> dict[str, Any]:
        def reject_constant(token: str) -> Any:
            raise ValueError(f"non-finite JSON constant {token!r} is not accepted from a backend")

        raw = json.loads(payload, parse_constant=reject_constant)
        if not isinstance(raw, dict):
            raise TypeError("worker response must be a JSON object")
        if not isinstance(raw.get("status"), str):
            raise TypeError("worker response status must be a string")
        BackendStatus(raw["status"])
        if not isinstance(raw.get("version"), str):
            raise TypeError("worker response version must be a string")
        for key, expected in (
            ("data", dict),
            ("errors", list),
            ("unknowns", list),
        ):
            if key in raw and not isinstance(raw[key], expected):
                raise TypeError(f"worker response {key} has invalid type")
        ensure_json_domain(raw.get("data", {}), "worker.data")
        return raw

    def _run_harness(
        self,
        harness: Harness,
        operation: str,
        binary_sha256: str,
        binary_path: Path,
    ) -> BackendResult:
        identity = self._identity()
        if operation not in HARNESS_OPERATIONS:
            return BackendResult(
                identity=identity,
                status=BackendStatus.ERROR,
                errors=[f"unsupported harness operation: {operation}"],
                partial=True,
            )
        available = self.availability()
        if available.status is not BackendStatus.COMPLETED:
            return available
        if harness.binary_sha256 != binary_sha256:
            return BackendResult(
                identity=identity,
                status=BackendStatus.ERROR,
                errors=[
                    (
                        "harness binary_sha256 does not match the binary under analysis "
                        f"({harness.binary_sha256} != {binary_sha256})"
                    )
                ],
                partial=True,
            )
        request = {
            "harness": harness.normalized(),
            "harness_sha256": harness.harness_sha256,
            "binary": str(binary_path),
            "operation": operation,
            "limits": {
                **self.limits.to_dict(),
                "timeout_seconds": min(self.limits.timeout_seconds, harness.timeout_seconds),
                "instruction_limit": min(
                    self.limits.maximum_steps, harness.instruction_limit
                ),
                "branch_limit": harness.branch_limit,
                "max_symbolic_expressions": harness.max_symbolic_expressions,
                "max_trace_entries": harness.max_trace_entries,
            },
        }
        return self._invoke(request, identity)

    def run_harness(self, request: dict[str, Any]) -> BackendResult:
        harness = request.get("harness")
        if not isinstance(harness, Harness):
            return BackendResult(
                identity=self._identity(),
                status=BackendStatus.ERROR,
                errors=["run_harness requires a validated Harness object"],
                partial=True,
            )
        try:
            binary_path = Path(str(request["binary"])).expanduser().resolve()
        except (KeyError, TypeError) as exc:
            return BackendResult(
                identity=self._identity(),
                status=BackendStatus.ERROR,
                errors=[f"run_harness requires a binary path: {exc}"],
                partial=True,
            )
        if not binary_path.is_file():
            return BackendResult(
                identity=self._identity(),
                status=BackendStatus.ERROR,
                errors=[f"binary is not a regular file: {binary_path}"],
                partial=True,
            )
        binary_sha256 = str(request.get("binary_sha256") or harness.binary_sha256)
        return self._run_harness(
            harness, str(request.get("operation", "emulate")), binary_sha256, binary_path
        )

    def _invoke(self, payload: dict[str, Any], identity: BackendIdentity) -> BackendResult:
        try:
            completed = subprocess.run(
                [str(self.interpreter), str(self.worker)],
                input=json.dumps(payload, sort_keys=True, allow_nan=False),
                text=True,
                capture_output=True,
                timeout=self.limits.timeout_seconds,
                check=False,
                shell=False,
                preexec_fn=self._preexec,
            )
        except subprocess.TimeoutExpired:
            return BackendResult(
                identity=identity,
                status=BackendStatus.TIMEOUT,
                errors=[f"triton exceeded {self.limits.timeout_seconds}s timeout"],
                partial=True,
            )
        except OSError as exc:
            return BackendResult.unavailable(identity, f"triton worker launch failed: {exc}")
        if len(completed.stdout) > 16 * 1024 * 1024:
            return BackendResult(
                identity=identity,
                status=BackendStatus.RESOURCE_LIMIT,
                errors=["triton worker output exceeded 16 MiB"],
                partial=True,
            )
        try:
            raw = self._parse_worker_response(completed.stdout)
        except (json.JSONDecodeError, TypeError, ValueError, KeyError) as exc:
            return BackendResult(
                identity=identity,
                status=BackendStatus.ERROR,
                errors=[f"triton worker returned invalid JSON response: {type(exc).__name__}: {exc}"],
                partial=True,
                metrics={"stderr": completed.stderr[-2000:]},
            )
        status = BackendStatus(raw["status"])
        errors = [str(item) for item in raw.get("errors", [])]
        if completed.returncode != 0 and status is BackendStatus.COMPLETED:
            status = BackendStatus.ERROR
            errors.append(f"triton worker exited {completed.returncode}")
        data = dict(raw.get("data", {}))
        unknowns = [str(item) for item in raw.get("unknowns", [])]
        if completed.returncode != 0:
            # A worker that failed must not contribute evidence, even if it printed a COMPLETED
            # payload before dying.
            evidence: list[BackendEvidence] = []
            data = {
                "execution_status": "ERROR",
                "stop_reason": "WORKER_EXIT",
                "instructions_executed": data.get("instructions_executed", 0),
            }
        else:
            evidence = self._build_evidence(data, payload)
        return BackendResult(
            identity=self._identity(raw.get("version") or None),
            status=status,
            data=data,
            evidence=evidence,
            errors=errors,
            unknowns=unknowns,
            partial=status
            in {
                BackendStatus.PARTIAL,
                BackendStatus.ANALYSIS_INCOMPLETE,
                BackendStatus.TIMEOUT,
                BackendStatus.RESOURCE_LIMIT,
            },
            metrics={
                "elapsed_seconds": data.get("elapsed_seconds"),
                "exit_code": completed.returncode,
                "stub_registry_version": STUB_REGISTRY_VERSION,
            },
        )

    @staticmethod
    def _build_evidence(data: dict[str, Any], payload: dict[str, Any]) -> list[BackendEvidence]:
        function = int(payload["harness"]["function_entry"])
        evidence: list[BackendEvidence] = []
        for flow in data.get("taint_flows", [])[:64]:
            sink = flow.get("sink")
            if not sink:
                continue
            evidence.append(
                BackendEvidence(
                    kind="taint_flow",
                    subject=f"{flow['source']}->{sink}",
                    value={
                        "source": flow["source"],
                        "sink": sink,
                        "sink_address": flow.get("sink_address"),
                        "transformations": len(flow.get("transformations", [])),
                    },
                    address=flow.get("sink_address") if isinstance(flow.get("sink_address"), int) else None,
                    provenance={
                        "source_class": "emulated",
                        "engine": "triton",
                        "harness_sha256": payload.get("harness_sha256"),
                        "execution_status": data.get("execution_status"),
                    },
                )
            )
        for violation in data.get("memory_violations", [])[:64]:
            evidence.append(
                BackendEvidence(
                    kind="memory_violation",
                    subject=f"{violation.get('kind')}@0x{int(violation.get('address') or 0):x}",
                    value=violation.get("kind"),
                    address=int(violation["address"]) if isinstance(violation.get("address"), int) else None,
                    provenance={
                        "source_class": "emulated",
                        "engine": "triton",
                        "harness_sha256": payload.get("harness_sha256"),
                    },
                )
            )
        for branch in data.get("branches", [])[:32]:
            if not branch.get("constraints"):
                continue
            evidence.append(
                BackendEvidence(
                    kind="branch_constraint",
                    subject=f"branch@0x{int(branch['address']):x}",
                    value=list(branch.get("constraints", []))[:4],
                    address=int(branch["address"]),
                    confidence="INFERRED",
                    provenance={
                        "source_class": "symbolic",
                        "engine": "triton",
                        "harness_sha256": payload.get("harness_sha256"),
                        "taken": branch.get("taken"),
                    },
                )
            )
        evidence.append(
            BackendEvidence(
                kind="execution_status",
                subject=f"harness@{function:#x}",
                value=data.get("execution_status"),
                address=function,
                confidence="SUPPORTED",
                provenance={
                    "source_class": "emulated",
                    "engine": "triton",
                    "harness_sha256": payload.get("harness_sha256"),
                    "stop_reason": data.get("stop_reason"),
                    "instructions_executed": data.get("instructions_executed"),
                },
            )
        )
        return evidence

    def dynamic_evidence(
        self, harness: Harness, binary_sha256: str, result: BackendResult
    ) -> DynamicEvidence | None:
        """Assemble the compact, hash-bound dynamic record for a successful run."""

        if result.status not in {BackendStatus.COMPLETED, BackendStatus.PARTIAL}:
            return None
        data = result.data
        return DynamicEvidence(
            backend="triton",
            backend_version=result.identity.version,
            binary_sha256=binary_sha256,
            harness_sha256=harness.harness_sha256,
            function=harness.function_entry,
            input_sha256=_input_sha256(harness),
            execution_status=str(data.get("execution_status", "ERROR")),
            instructions_executed=int(data.get("instructions_executed", 0)),
            branches=list(data.get("branches", [])),
            calls=list(data.get("calls", [])),
            stubs_used=list(data.get("stubs_used", [])),
            taint_flows=list(data.get("taint_flows", [])),
            memory_reads=list(data.get("memory_reads", [])),
            memory_writes=list(data.get("memory_writes", [])),
            memory_violations=list(data.get("memory_violations", [])),
            return_value=data.get("return_value"),
            stop_reason=str(data.get("stop_reason", "UNKNOWN")),
            trace_sha256=data.get("trace_sha256"),
            trace_entry_count=int(data.get("trace_entry_count", 0)),
            trace_truncated=bool(data.get("trace_truncated", False)),
            symbolic_inputs=list(data.get("symbolic_inputs", [])),
            path_constraints=list(data.get("path_constraints", []))[:32],
            unknowns=list(data.get("unknowns", [])),
        )

    # Static-analysis surface is not provided by an emulation backend.
    def _unsupported(self, operation: str) -> BackendResult:
        return BackendResult(
            identity=self._identity(),
            status=BackendStatus.ANALYSIS_INCOMPLETE,
            errors=[f"triton backend does not implement {operation}; use run_harness"],
            partial=True,
        )

    def analyze_function(self, request: dict[str, Any]) -> BackendResult:
        return self._unsupported("analyze_function")

    def recover_cfg(self, request: dict[str, Any]) -> BackendResult:
        return self._unsupported("recover_cfg")

    def trace_value(self, request: dict[str, Any]) -> BackendResult:
        harness = request.get("harness")
        if isinstance(harness, Harness):
            return self.run_harness({**request, "operation": "taint"})
        return self._unsupported("trace_value")

    def find_definitions(self, request: dict[str, Any]) -> BackendResult:
        return self._unsupported("find_definitions")

    def find_consumers(self, request: dict[str, Any]) -> BackendResult:
        return self._unsupported("find_consumers")

    def resolve_call_arguments(self, request: dict[str, Any]) -> BackendResult:
        return self._unsupported("resolve_call_arguments")

    def evaluate_branch_constraints(self, request: dict[str, Any]) -> BackendResult:
        harness = request.get("harness")
        if isinstance(harness, Harness):
            return self.run_harness({**request, "operation": "emulate"})
        return self._unsupported("evaluate_branch_constraints")

    def analyze_memory_access(self, request: dict[str, Any]) -> BackendResult:
        harness = request.get("harness")
        if isinstance(harness, Harness):
            return self.run_harness({**request, "operation": "trace"})
        return self._unsupported("analyze_memory_access")


def _input_sha256(harness: Harness) -> str:
    payload = [
        {
            "name": region.name,
            "address": region.address,
            "size": region.size,
            "concrete_value": region.concrete_value,
            "symbolic": region.symbolic,
            "tainted": region.tainted,
        }
        for region in harness.input_regions
    ]
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()
