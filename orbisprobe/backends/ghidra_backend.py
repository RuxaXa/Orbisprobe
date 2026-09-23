from __future__ import annotations

import hashlib
import json
import os
import signal
import subprocess
import tempfile
import time
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
)

CAPABILITIES = frozenset(
    {
        BackendCapability.CFG,
        BackendCapability.DATAFLOW,
        BackendCapability.CALLGRAPH,
        BackendCapability.DECOMPILER,
        BackendCapability.HEADLESS,
        BackendCapability.MEMORY_MODEL,
    }
)
ADDRESS_KEYS = {"address", "entry", "target", "from", "image_base", "block"}


class GhidraBackend(AnalysisBackend):
    identity = BackendIdentity(
        name="ghidra",
        version="unknown",
        independence_family="ghidra-pcode",
        capabilities=CAPABILITIES,
        implementation="headless-pcode",
    )

    def __init__(
        self,
        limits: ResourceLimits | None = None,
        ghidra_home: str | Path | None = None,
        java_home: str | Path | None = None,
    ) -> None:
        super().__init__(limits)
        configured = ghidra_home or os.environ.get("ORBISPROBE_GHIDRA_HOME")
        if configured is None:
            candidates = [
                Path("/home/hermes/tools/ghidra_12.1.3_PUBLIC"),
                Path("/opt/ghidra"),
            ]
            configured = next((item for item in candidates if item.is_dir()), candidates[0])
        self.ghidra_home = Path(configured).expanduser().absolute()
        configured_java = java_home or os.environ.get("ORBISPROBE_JAVA_HOME")
        if configured_java is None:
            java_candidates = [
                Path("/home/hermes/tools/localroot/usr/lib/jvm/java-21-openjdk-amd64"),
                Path("/home/hermes/tools/jdk25/jdk-25.0.4.1+1"),
                Path("/usr/lib/jvm/java-21-openjdk-amd64"),
            ]
            configured_java = next(
                (item for item in java_candidates if (item / "bin" / "java").is_file()),
                None,
            )
        self.java_home = Path(configured_java).expanduser().absolute() if configured_java else None
        self.headless = self.ghidra_home / "support" / "analyzeHeadless"
        self.properties = self.ghidra_home / "Ghidra" / "application.properties"
        self.script_dir = Path(__file__).parent / "ghidra_scripts"

    def version(self) -> str:
        try:
            for line in self.properties.read_text(encoding="utf-8").splitlines():
                if line.startswith("application.version="):
                    return line.split("=", 1)[1].strip()
        except OSError:
            pass
        return "unknown"

    def _identity(self) -> BackendIdentity:
        return BackendIdentity(
            name="ghidra",
            version=self.version(),
            independence_family="ghidra-pcode",
            capabilities=CAPABILITIES,
            implementation="headless-pcode",
        )

    def availability(self) -> BackendResult:
        identity = self._identity()
        if not self.headless.is_file() or not os.access(self.headless, os.X_OK):
            return BackendResult.unavailable(identity, f"analyzeHeadless unavailable: {self.headless}")
        if not self.script_dir.is_dir():
            return BackendResult.unavailable(identity, f"Ghidra scripts unavailable: {self.script_dir}")
        return BackendResult.completed(
            identity,
            {
                "available": True,
                "ghidra_home": str(self.ghidra_home),
                "headless": str(self.headless),
                "java_home": str(self.java_home) if self.java_home else None,
            },
        )

    @staticmethod
    def _normalize(value: Any, key: str | None = None) -> Any:
        if isinstance(value, dict):
            return {item_key: GhidraBackend._normalize(item_value, item_key) for item_key, item_value in value.items()}
        if isinstance(value, list):
            return [GhidraBackend._normalize(item) for item in value]
        if key in ADDRESS_KEYS and isinstance(value, str) and value.startswith("0x"):
            return int(value, 16)
        return value

    @staticmethod
    def _validate_request(request: dict[str, Any]) -> dict[str, Any]:
        clean = dict(request)
        binary = Path(clean["binary"]).expanduser().resolve()
        if not binary.is_file():
            raise ValueError(f"binary is not a regular file: {binary}")
        if clean.get("architecture", "x86_64") != "x86_64":
            raise ValueError("Ghidra backend currently supports x86_64 only")
        clean["binary"] = str(binary)
        clean["binary_sha256"] = hashlib.sha256(binary.read_bytes()).hexdigest()
        for key in ("base", "function"):
            if key not in clean or not isinstance(clean[key], int) or isinstance(clean[key], bool) or clean[key] < 0:
                raise ValueError(f"{key} must be a non-negative integer")
        return clean

    def _run_process(self, command: list[str], environment: dict[str, str]) -> subprocess.CompletedProcess[str]:
        process = subprocess.Popen(
            command,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=environment,
            shell=False,
            start_new_session=True,
        )
        try:
            stdout, stderr = process.communicate(timeout=self.limits.timeout_seconds)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            stdout, stderr = process.communicate()
            raise subprocess.TimeoutExpired(command, self.limits.timeout_seconds, stdout, stderr)
        return subprocess.CompletedProcess(command, process.returncode, stdout, stderr)

    def _analyze(self, request: dict[str, Any]) -> BackendResult:
        identity = self._identity()
        available = self.availability()
        if available.status is not BackendStatus.COMPLETED:
            return available
        try:
            clean = self._validate_request(request)
        except (OSError, ValueError, TypeError, KeyError) as exc:
            return BackendResult(identity, BackendStatus.ERROR, errors=[f"invalid request: {exc}"])

        started = time.monotonic()
        with tempfile.TemporaryDirectory(prefix="orbisprobe-ghidra-") as temporary:
            root = Path(temporary)
            project = root / "project"
            project.mkdir(mode=0o700)
            output = root / "evidence.json"
            command = [
                str(self.headless),
                str(project),
                "OrbisProbe",
                "-import",
                clean["binary"],
                "-overwrite",
                "-processor",
                "x86:LE:64:default",
                "-cspec",
                "gcc",
                "-loader",
                "BinaryLoader",
                "-loader-baseAddr",
                hex(clean["base"]),
                "-analysisTimeoutPerFile",
                str(max(1, self.limits.timeout_seconds - 5)),
                "-max-cpu",
                "1",
                "-scriptPath",
                str(self.script_dir),
                "-postScript",
                "OrbisProbeExport.java",
                str(output),
                hex(clean["function"]),
                str(self.limits.maximum_graph_size),
                "-deleteProject",
            ]
            bounded_noanalysis = Path(clean["binary"]).stat().st_size > 1024 * 1024
            if bounded_noanalysis:
                command.insert(command.index("-analysisTimeoutPerFile"), "-noanalysis")
            environment = os.environ.copy()
            environment["GHIDRA_HEADLESS_MAXMEM"] = f"{self.limits.memory_mb}M"
            if self.java_home is not None:
                environment["JAVA_HOME"] = str(self.java_home)
            try:
                completed = self._run_process(command, environment)
            except subprocess.TimeoutExpired:
                return BackendResult(
                    identity,
                    BackendStatus.TIMEOUT,
                    errors=[f"Ghidra exceeded {self.limits.timeout_seconds}s timeout"],
                    partial=True,
                    metrics={"elapsed_seconds": round(time.monotonic() - started, 6)},
                )
            except OSError as exc:
                return BackendResult.unavailable(identity, f"Ghidra launch failed: {exc}")
            if not output.is_file():
                return BackendResult(
                    identity,
                    BackendStatus.ERROR,
                    errors=[f"Ghidra produced no JSON (exit {completed.returncode})"],
                    metrics={
                        "elapsed_seconds": round(time.monotonic() - started, 6),
                        "stdout": completed.stdout[-4000:],
                        "stderr": completed.stderr[-4000:],
                    },
                )
            if output.stat().st_size > 16 * 1024 * 1024:
                return BackendResult(
                    identity,
                    BackendStatus.RESOURCE_LIMIT,
                    errors=["Ghidra JSON exceeded 16 MiB"],
                    partial=True,
                    metrics={"elapsed_seconds": round(time.monotonic() - started, 6)},
                )
            try:
                raw = self._normalize(json.loads(output.read_text(encoding="utf-8")))
            except (OSError, ValueError, TypeError, json.JSONDecodeError) as exc:
                return BackendResult(
                    identity,
                    BackendStatus.ERROR,
                    errors=[f"invalid Ghidra JSON: {exc}"],
                )
            partial = bool(raw.get("partial", False)) or completed.returncode != 0
            status = BackendStatus.PARTIAL if partial else BackendStatus.COMPLETED
            evidence = [
                BackendEvidence(
                    kind="pcode",
                    subject=f"{item.get('opcode')}@0x{item.get('address', 0):x}",
                    value=item.get("opcode"),
                    address=item.get("address"),
                    provenance={"source_class": "static", "engine": "ghidra-pcode"},
                )
                for item in raw.get("pcode", [])[:256]
            ]
            unknowns = []
            if partial:
                unknowns.append("Ghidra export reached item or analysis limit")
            return BackendResult(
                identity=identity,
                status=status,
                data=raw,
                evidence=evidence,
                unknowns=unknowns,
                partial=partial,
                metrics={
                    "elapsed_seconds": round(time.monotonic() - started, 6),
                    "exit_code": completed.returncode,
                    "bounded_noanalysis": bounded_noanalysis,
                },
            )

    def analyze_function(self, request: dict[str, Any]) -> BackendResult:
        return self._analyze(request)

    def recover_cfg(self, request: dict[str, Any]) -> BackendResult:
        result = self._analyze(request)
        result.data = {"function": result.data.get("function"), "blocks": result.data.get("blocks", []), "calls": result.data.get("calls", [])}
        return result

    def trace_value(self, request: dict[str, Any]) -> BackendResult:
        result = self._analyze(request)
        result.status = BackendStatus.ANALYSIS_INCOMPLETE if result.status is BackendStatus.COMPLETED else result.status
        result.unknowns.append("Ghidra raw p-code export does not yet close a value trace")
        return result

    def find_definitions(self, request: dict[str, Any]) -> BackendResult:
        result = self._analyze(request)
        result.data = {"definitions": result.data.get("definitions", [])}
        return result

    def find_consumers(self, request: dict[str, Any]) -> BackendResult:
        result = self._analyze(request)
        result.data = {"consumers": result.data.get("consumers", [])}
        return result

    def resolve_call_arguments(self, request: dict[str, Any]) -> BackendResult:
        result = self._analyze(request)
        result.status = BackendStatus.ANALYSIS_INCOMPLETE if result.status is BackendStatus.COMPLETED else result.status
        result.data = {"arguments": [], "calls": result.data.get("calls", [])}
        result.unknowns.append("parameter recovery exported; call argument proof is incomplete")
        return result

    def evaluate_branch_constraints(self, request: dict[str, Any]) -> BackendResult:
        result = self._analyze(request)
        result.status = BackendStatus.ANALYSIS_INCOMPLETE if result.status is BackendStatus.COMPLETED else result.status
        result.data = {"constraints": [], "blocks": result.data.get("blocks", [])}
        result.unknowns.append("Ghidra static p-code does not solve symbolic branch constraints")
        return result

    def analyze_memory_access(self, request: dict[str, Any]) -> BackendResult:
        result = self._analyze(request)
        result.data = {"memory_accesses": result.data.get("memory_accesses", [])}
        return result
