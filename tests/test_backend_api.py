from __future__ import annotations

import json
from pathlib import Path

import pytest

from orbisprobe.backends.base import (
    AnalysisBackend,
    BackendCapability,
    BackendEvidence,
    BackendIdentity,
    BackendResult,
    BackendStatus,
    ResourceLimits,
)
from orbisprobe.backends.cache import AnalysisCache, CacheRequest
from orbisprobe.backends.registry import BackendRegistry


class StubBackend(AnalysisBackend):
    identity = BackendIdentity(
        name="stub",
        version="1.2.3",
        independence_family="stub-ir",
        capabilities=frozenset({BackendCapability.CFG, BackendCapability.DATAFLOW}),
    )

    def availability(self):
        return BackendResult.completed(self.identity, {"available": True})

    def version(self):
        return "1.2.3"

    def analyze_function(self, request):
        return BackendResult.completed(
            self.identity,
            {"function": request["function"]},
            evidence=[BackendEvidence("definition", "rax", "rdi", address=0x1000)],
        )

    def recover_cfg(self, request):
        return BackendResult.completed(self.identity, {"nodes": [request["function"]]})

    def trace_value(self, request):
        return BackendResult.completed(self.identity, {"trace": [request["source"]]})

    def find_definitions(self, request):
        return BackendResult.completed(self.identity, {"definitions": []})

    def find_consumers(self, request):
        return BackendResult.completed(self.identity, {"consumers": []})

    def resolve_call_arguments(self, request):
        return BackendResult.completed(self.identity, {"arguments": []})

    def evaluate_branch_constraints(self, request):
        return BackendResult.completed(self.identity, {"constraints": []})

    def analyze_memory_access(self, request):
        return BackendResult.completed(self.identity, {"accesses": []})


def test_backend_contract_and_json_export():
    backend = StubBackend(ResourceLimits(timeout_seconds=3, state_ceiling=7))
    result = backend.analyze_function({"function": 0x1000})
    assert result.status is BackendStatus.COMPLETED
    assert result.identity.capabilities == frozenset(
        {BackendCapability.CFG, BackendCapability.DATAFLOW}
    )
    payload = result.to_dict()
    assert payload["backend"]["name"] == "stub"
    assert payload["evidence"][0]["address"] == 0x1000
    assert json.loads(backend.export_evidence(result))["status"] == "COMPLETED"


def test_unavailable_and_incomplete_are_structured_not_exceptions():
    identity = StubBackend.identity
    unavailable = BackendResult.unavailable(identity, "dependency missing")
    incomplete = BackendResult.incomplete(identity, "state ceiling", {"states": 7})
    assert unavailable.status is BackendStatus.BACKEND_UNAVAILABLE
    assert incomplete.status is BackendStatus.ANALYSIS_INCOMPLETE
    assert incomplete.partial is True


def test_backend_cannot_inject_confirmed_status():
    with pytest.raises(ValueError):
        BackendEvidence("value_domain", "r15", "user", confidence="CONFIRMED")


def test_resource_limits_reject_unbounded_or_invalid_values():
    with pytest.raises(ValueError):
        ResourceLimits(timeout_seconds=0)
    with pytest.raises(ValueError):
        ResourceLimits(state_ceiling=-1)
    limits = ResourceLimits()
    assert limits.timeout_seconds <= 300
    assert limits.state_ceiling > 0
    assert limits.maximum_graph_size > 0


def test_registry_auto_order_skips_unavailable():
    registry = BackendRegistry()
    registry.register(StubBackend)
    available = registry.available(["missing", "stub"])
    assert [backend.identity.name for backend in available] == ["stub"]
    missing = registry.status("missing")
    assert missing.status is BackendStatus.BACKEND_UNAVAILABLE


def test_cache_key_binds_every_security_relevant_input(tmp_path: Path):
    cache = AnalysisCache(tmp_path)
    request = CacheRequest(
        binary_sha256="a" * 64,
        backend="stub",
        backend_version="1.2.3",
        orbisprobe_version="0.2.0.dev1",
        base_address=0x400000,
        operation="analyze_function",
        parameters={"function": 0x401000, "timeout": 3},
    )
    key = cache.key(request)
    result = BackendResult.completed(StubBackend.identity, {"ok": True})
    cache.store(request, result)
    assert cache.load(request).to_dict() == result.to_dict()
    changed = CacheRequest(**{**request.__dict__, "base_address": 0x500000})
    assert cache.key(changed) != key
    assert cache.load(changed) is None
    changed_adapter = CacheRequest(**{**request.__dict__, "backend_fingerprint": "new-code"})
    assert cache.key(changed_adapter) != key


def test_cache_rejects_invalid_binary_hash_and_path_escape(tmp_path: Path):
    cache = AnalysisCache(tmp_path)
    with pytest.raises(ValueError):
        cache.key(
            CacheRequest(
                binary_sha256="../bad",
                backend="stub",
                backend_version="1",
                orbisprobe_version="1",
                base_address=0,
                operation="x",
                parameters={},
            )
        )
