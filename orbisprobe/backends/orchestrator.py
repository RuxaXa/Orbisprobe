from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from orbisprobe import __version__

from .base import BackendResult, BackendStatus, ResourceLimits
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


@dataclass
class MultiBackendReport:
    operation: str
    results: list[BackendResult]
    consensus: ConsensusReport
    cache_hits: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "operation": self.operation,
            "results": [item.to_dict() for item in self.results],
            "consensus": self.consensus.to_dict(),
            "cache_hits": self.cache_hits,
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
            backend = self.registry.create(name, self.limits)
            if backend is None:
                results.append(self.registry.status(name, self.limits))
                continue
            availability = self.registry.status(name, self.limits)
            if availability.status is not BackendStatus.COMPLETED:
                results.append(availability)
                continue
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
                backend_fingerprint=backend.cache_fingerprint(),
            )
            cached = self.cache.load(cache_request)
            if cached is not None:
                results.append(cached)
                cache_hits.append(name)
                continue
            method = getattr(backend, operation)
            result = method(request)
            results.append(result)
            if result.status in {
                BackendStatus.COMPLETED,
                BackendStatus.PARTIAL,
                BackendStatus.ANALYSIS_INCOMPLETE,
            }:
                self.cache.store(cache_request, result)
        consensus = self.consensus_engine.combine(results, available_families=available_families)
        return MultiBackendReport(operation, results, consensus, cache_hits)


def default_registry() -> BackendRegistry:
    from .angr_backend import AngrBackend
    from .ghidra_backend import GhidraBackend
    from .native_backend import NativeBackend

    registry = BackendRegistry()
    registry.register(NativeBackend)
    registry.register(AngrBackend)
    registry.register(GhidraBackend)
    return registry
