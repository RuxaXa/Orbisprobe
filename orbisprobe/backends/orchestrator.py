from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from orbisprobe import __version__
from orbisprobe.harness import STUB_REGISTRY_VERSION, Harness

from .base import BackendIdentity, BackendResult, BackendStatus, ResourceLimits
from .cache import AnalysisCache, CacheRequest
from .consensus import ConsensusEngine, ConsensusReport
from .registry import BackendRegistry

OPERATIONS = {
    "analyze_function",
    "recover_cfg",
    "trace_value",
    "find_definitions",
    "find_consumers",
    "resolve_call_arguments",
    "evaluate_branch_constraints",
    "analyze_memory_access",
}

#: Operations that execute a validated function harness instead of a static analysis.
HARNESS_OPERATIONS = ("emulate", "taint", "trace")


@dataclass
class MultiBackendReport:
    operation: str
    results: list[BackendResult]
    consensus: ConsensusReport
    cache_hits: list[str] = field(default_factory=list)
    dynamic_evidence: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "operation": self.operation,
            "results": [item.to_dict() for item in self.results],
            "consensus": self.consensus.to_dict(),
            "cache_hits": self.cache_hits,
            "dynamic_evidence": self.dynamic_evidence,
        }


class BackendOrchestrator:
    def __init__(
        self,
        registry: BackendRegistry,
        cache: AnalysisCache,
        consensus: ConsensusEngine | None = None,
        limits: ResourceLimits | None = None,
    ) -> None:
        self.registry = registry
        self.cache = cache
        self.consensus_engine = consensus or ConsensusEngine()
        self.limits = limits or ResourceLimits()

    @staticmethod
    def _binary_hash(request: dict[str, Any]) -> str:
        path = Path(request["binary"]).expanduser().resolve()
        if not path.is_file():
            raise ValueError(f"binary is not a regular file: {path}")
        return hashlib.sha256(path.read_bytes()).hexdigest()

    def run(
        self,
        operation: str,
        request: dict[str, Any],
        backends: list[str],
    ) -> MultiBackendReport:
        if operation not in OPERATIONS:
            raise ValueError(f"unsupported backend operation: {operation}")
        binary_hash = self._binary_hash(request)
        results: list[BackendResult] = []
        cache_hits: list[str] = []
        available_families: set[str] = set()
        for name in backends:
            try:
                result = self._run_one(
                    name, operation, request, binary_hash, available_families, cache_hits
                )
            except Exception as exc:  # noqa: BLE001 - a broken adapter must never abort the run
                result = BackendResult(
                    identity=BackendIdentity(
                        name=name,
                        version="unknown",
                        independence_family=f"unresolved-{name}",
                        capabilities=frozenset(),
                    ),
                    status=BackendStatus.ERROR,
                    data={"analysis_mode": "PARTIAL_ANALYSIS", "effective_capabilities": []},
                    errors=[f"backend setup raised {type(exc).__name__}: {exc}"],
                    partial=True,
                )
            results.append(result)
        consensus = self.consensus_engine.combine(results, available_families=available_families)
        return MultiBackendReport(operation, results, consensus, cache_hits)

    def _run_one(
        self,
        name: str,
        operation: str,
        request: dict[str, Any],
        binary_hash: str,
        available_families: set[str],
        cache_hits: list[str],
    ) -> BackendResult:
        """Run a single backend. Every failure mode is returned, never raised."""

        try:
            backend = self.registry.create(name, self.limits)
            if backend is None:
                return self.registry.status(name, self.limits)
            availability = self.registry.status(name, self.limits)
            if availability.status is not BackendStatus.COMPLETED:
                return availability
            available_families.add(backend.identity.independence_family)
            parameters = {key: value for key, value in request.items() if key != "binary"}
            cache_request = CacheRequest(
                binary_sha256=binary_hash,
                backend=name,
                backend_version=availability.identity.version,
                orbisprobe_version=__version__,
                base_address=int(request.get("base", 0)),
                operation=operation,
                parameters=parameters,
                resource_limits=self.limits.to_dict(),
                backend_fingerprint=backend.cache_fingerprint(),
            )
            cached = self.cache.load(cache_request)
            if cached is not None:
                cache_hits.append(name)
                return cached
            method = getattr(backend, operation)
            try:
                result = method(request)
            except Exception as exc:  # noqa: BLE001 - a crashing backend must never abort the run
                result = BackendResult(
                    identity=backend.identity,
                    status=BackendStatus.ERROR,
                    data={"analysis_mode": "PARTIAL_ANALYSIS", "effective_capabilities": []},
                    errors=[f"backend raised {type(exc).__name__}: {exc}"],
                    partial=True,
                )
            if result.status in {
                BackendStatus.COMPLETED,
                BackendStatus.PARTIAL,
                BackendStatus.ANALYSIS_INCOMPLETE,
            }:
                try:
                    self.cache.store(cache_request, result)
                except (OSError, TypeError, ValueError):
                    pass
            return result
        except (KeyError, TypeError, ValueError, OSError, RuntimeError) as exc:
            return BackendResult(
                identity=BackendIdentity(
                    name=name,
                    version="unknown",
                    independence_family=f"unresolved-{name}",
                    capabilities=frozenset(),
                ),
                status=BackendStatus.ERROR,
                data={"analysis_mode": "PARTIAL_ANALYSIS", "effective_capabilities": []},
                errors=[f"backend setup failed: {type(exc).__name__}: {exc}"],
                partial=True,
            )

    def run_harness(
        self,
        harness: Harness,
        binary: str | Path,
        operation: str = "emulate",
        backends: list[str] | None = None,
    ) -> MultiBackendReport:
        """Execute one validated harness on the named dynamic backends.

        The harness SHA-256, the input SHA-256, the stub-registry version, the backend version, and
        the resource limits all participate in the cache key, so a harness edit, an input edit, or a
        worker change can never reuse a stale execution record.
        """

        if operation not in HARNESS_OPERATIONS:
            raise ValueError(f"unsupported harness operation: {operation}")
        binary_path = Path(binary).expanduser().resolve()
        if not binary_path.is_file():
            raise ValueError(f"binary is not a regular file: {binary_path}")
        binary_hash = hashlib.sha256(binary_path.read_bytes()).hexdigest()
        if binary_hash != harness.binary_sha256:
            raise ValueError(
                "harness binary_sha256 does not match the binary under analysis "
                f"({harness.binary_sha256} != {binary_hash})"
            )
        names = list(backends or ["triton"])
        results: list[BackendResult] = []
        cache_hits: list[str] = []
        dynamic: list[dict[str, Any]] = []
        available_families: set[str] = set()
        for name in names:
            try:
                result, record = self._run_harness_backend(
                    name, harness, binary_path, binary_hash, operation, cache_hits
                )
            except Exception as exc:  # noqa: BLE001 - a broken adapter must never abort the run
                result = BackendResult(
                    identity=BackendIdentity(
                        name=name,
                        version="unknown",
                        independence_family=f"unresolved-{name}",
                        capabilities=frozenset(),
                    ),
                    status=BackendStatus.ERROR,
                    errors=[f"harness setup raised {type(exc).__name__}: {exc}"],
                    partial=True,
                )
                record = None
            results.append(result)
            if record is not None:
                dynamic.append(record)
            available_families.add(result.identity.independence_family)
        consensus = self.consensus_engine.combine(results, available_families=available_families)
        return MultiBackendReport(operation, results, consensus, cache_hits, dynamic)

    def _run_harness_backend(
        self,
        name: str,
        harness: Harness,
        binary_path: Path,
        binary_hash: str,
        operation: str,
        cache_hits: list[str],
    ) -> tuple[BackendResult, dict[str, Any] | None]:
        backend = self.registry.create(name, self.limits)
        if backend is None:
            return self.registry.status(name, self.limits), None
        availability = self.registry.status(name, self.limits)
        if availability.status is not BackendStatus.COMPLETED:
            return availability, None
        parameters = {
            "harness_sha256": harness.harness_sha256,
            "harness_id": harness.harness_id,
            "input_sha256": harness_input_sha256(harness),
            "function_entry": harness.function_entry,
            "operation": operation,
            "stub_registry_version": STUB_REGISTRY_VERSION,
        }
        cache_request = CacheRequest(
            binary_sha256=binary_hash,
            backend=name,
            backend_version=availability.identity.version,
            orbisprobe_version=__version__,
            base_address=harness.base,
            operation=f"harness:{operation}",
            parameters=parameters,
            resource_limits=self.limits.to_dict(),
            backend_fingerprint=backend.cache_fingerprint(),
        )
        cached = self.cache.load(cache_request)
        if cached is not None:
            cache_hits.append(name)
            return cached, None
        result = backend.run_harness(
            {
                "harness": harness,
                "binary": str(binary_path),
                "binary_sha256": binary_hash,
                "operation": operation,
            }
        )
        record: dict[str, Any] | None = None
        producer = backend.dynamic_evidence
        if producer is not None:
            try:
                evidence_record = producer(harness, binary_hash, result)
            except Exception:  # noqa: BLE001 - evidence assembly must not break the run
                evidence_record = None
            if evidence_record is not None and hasattr(evidence_record, "to_dict"):
                record = evidence_record.to_dict()
                result.data = {**result.data, "dynamic_evidence": record}
        if result.status in {
            BackendStatus.COMPLETED,
            BackendStatus.PARTIAL,
            BackendStatus.ANALYSIS_INCOMPLETE,
        }:
            try:
                self.cache.store(cache_request, result)
            except (OSError, TypeError, ValueError):
                pass
        return result, record


def default_registry() -> BackendRegistry:
    from .angr_backend import AngrBackend
    from .ghidra_backend import GhidraBackend
    from .native_backend import NativeBackend
    from .triton_backend import TritonBackend

    registry = BackendRegistry()
    registry.register(NativeBackend)
    registry.register(AngrBackend)
    registry.register(GhidraBackend)
    registry.register(TritonBackend)
    return registry


def harness_input_sha256(harness: Harness) -> str:
    """Deterministic hash of a harness's input payloads (used in the cache key)."""

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
