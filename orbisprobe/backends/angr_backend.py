from __future__ import annotations

import hashlib
import json
import os
import subprocess
from pathlib import Path
from typing import Any

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

CAPABILITIES = frozenset(
    {
        BackendCapability.CFG,
        BackendCapability.DATAFLOW,
        BackendCapability.SYMBOLIC,
        BackendCapability.CALLGRAPH,
        BackendCapability.MEMORY_MODEL,
        BackendCapability.HEADLESS,
    }
)


class AngrBackend(AnalysisBackend):
    identity = BackendIdentity(
        name="angr",
        version="unknown",
        independence_family="angr-vex",
        capabilities=CAPABILITIES,
        implementation="external-worker",
    )

    def __init__(
        self,
        limits: ResourceLimits | None = None,
        interpreter: str | Path | None = None,
    ) -> None:
        super().__init__(limits)
        configured = interpreter or os.environ.get("ORBISPROBE_ANGR_PYTHON")
        if configured is None:
            configured = Path.cwd() / ".backend-envs" / "angr" / "bin" / "python"
        self.interpreter = Path(configured).expanduser().absolute()
        self.worker = Path(__file__).parent / "workers" / "angr_worker.py"

    def _identity(self, version: str) -> BackendIdentity:
        return BackendIdentity(
            name="angr",
            version=version,
            independence_family="angr-vex",
            capabilities=CAPABILITIES,
            implementation="external-worker",
        )

    def _preexec(self):
        import resource

        memory = self.limits.memory_mb * 1024 * 1024
        resource.setrlimit(resource.RLIMIT_AS, (memory, memory))
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))

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
        for key, default_type in (
            ("data", dict),
            ("evidence", list),
            ("errors", list),
            ("unknowns", list),
            ("metrics", dict),
        ):
            if key in raw and not isinstance(raw[key], default_type):
                raise TypeError(f"worker response {key} has invalid type")
        if "partial" in raw and not isinstance(raw["partial"], bool):
            raise TypeError("worker response partial must be boolean")
        if any(not isinstance(item, dict) for item in raw.get("evidence", [])):
            raise TypeError("worker evidence entries must be objects")
        ensure_json_domain(raw.get("data", {}), "worker.data")
        ensure_json_domain(raw.get("metrics", {}), "worker.metrics")
        for index, item in enumerate(raw.get("evidence", [])):
            ensure_json_domain(item.get("value"), f"worker.evidence[{index}].value")
            ensure_json_domain(item.get("provenance"), f"worker.evidence[{index}].provenance")
        return raw

    @staticmethod
    def _validate_request(request: dict[str, Any]) -> dict[str, Any]:
        clean = dict(request)
        if "binary" in clean:
            path = Path(clean["binary"]).expanduser().resolve()
            if not path.is_file():
                raise ValueError(f"binary is not a regular file: {path}")
            clean["binary"] = str(path)
            clean["binary_sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()
        if clean.get("architecture", "x86_64") != "x86_64":
            raise ValueError("angr backend currently supports x86_64 only")
        for key in ("base", "function", "function_end", "from", "to", "consumer"):
            if key in clean and (not isinstance(clean[key], int) or isinstance(clean[key], bool) or clean[key] < 0):
                raise ValueError(f"{key} must be a non-negative integer")
        return clean

    def _invoke(self, operation: str, request: dict[str, Any] | None = None) -> BackendResult:
        if not self.interpreter.is_file() or not os.access(self.interpreter, os.X_OK):
            return BackendResult.unavailable(self.identity, f"angr interpreter unavailable: {self.interpreter}")
        try:
            clean = self._validate_request(request or {})
        except (OSError, ValueError, TypeError) as exc:
            return BackendResult(
                identity=self.identity,
                status=BackendStatus.ERROR,
                errors=[f"invalid request: {exc}"],
            )
        payload = {
            "operation": operation,
            "request": clean,
            "limits": self.limits.to_dict(),
        }
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
                identity=self.identity,
                status=BackendStatus.TIMEOUT,
                errors=[f"angr exceeded {self.limits.timeout_seconds}s timeout"],
                partial=True,
            )
        except OSError as exc:
            return BackendResult.unavailable(self.identity, f"angr worker launch failed: {exc}")
        if len(completed.stdout) > 16 * 1024 * 1024:
            return BackendResult(
                identity=self.identity,
                status=BackendStatus.RESOURCE_LIMIT,
                errors=["angr worker output exceeded 16 MiB"],
                partial=True,
            )
        try:
            raw = self._parse_worker_response(completed.stdout)
            version = raw["version"]
            identity = self._identity(version)
            status = BackendStatus(raw["status"])
            errors = [str(item) for item in raw.get("errors", [])]
            if completed.returncode != 0 and status is BackendStatus.COMPLETED:
                status = BackendStatus.ERROR
                errors.append(f"angr worker exited {completed.returncode}")
            evidence = [BackendEvidence.from_dict(item) for item in raw.get("evidence", [])]
        except (json.JSONDecodeError, TypeError, ValueError, KeyError) as exc:
            return BackendResult(
                identity=self.identity,
                status=BackendStatus.ERROR,
                errors=[f"angr worker returned invalid JSON response: {type(exc).__name__}: {exc}"],
                metrics={"stderr": completed.stderr[-2000:]},
            )
        return BackendResult(
            identity=identity,
            status=status,
            data=dict(raw.get("data", {})),
            evidence=evidence,
            errors=errors,
            unknowns=[str(item) for item in raw.get("unknowns", [])],
            partial=status
            in {
                BackendStatus.ANALYSIS_INCOMPLETE,
                BackendStatus.PARTIAL,
                BackendStatus.RESOURCE_LIMIT,
                BackendStatus.TIMEOUT,
            },
            metrics=dict(raw.get("metrics", {})),
        )

    def availability(self) -> BackendResult:
        return self._invoke("version")

    def version(self) -> str:
        return self.availability().identity.version

    def analyze_function(self, request: dict[str, Any]) -> BackendResult:
        return self._invoke("analyze_function", request)

    def recover_cfg(self, request: dict[str, Any]) -> BackendResult:
        return self._invoke("recover_cfg", request)

    def trace_value(self, request: dict[str, Any]) -> BackendResult:
        return self._invoke("trace_value", request)

    def find_definitions(self, request: dict[str, Any]) -> BackendResult:
        return self._invoke("find_definitions", request)

    def find_consumers(self, request: dict[str, Any]) -> BackendResult:
        return self._invoke("find_consumers", request)

    def resolve_call_arguments(self, request: dict[str, Any]) -> BackendResult:
        return self._invoke("resolve_call_arguments", request)

    def evaluate_branch_constraints(self, request: dict[str, Any]) -> BackendResult:
        return self._invoke("evaluate_branch_constraints", request)

    def analyze_memory_access(self, request: dict[str, Any]) -> BackendResult:
        return self._invoke("analyze_memory_access", request)
