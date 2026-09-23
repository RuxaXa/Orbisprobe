from __future__ import annotations

import json
from pathlib import Path

import pytest

from orbisprobe.backends.angr_backend import AngrBackend
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
from orbisprobe.backends.consensus import ConsensusClassification, ConsensusEngine
from orbisprobe.backends.ghidra_backend import GhidraBackend
from orbisprobe.backends.orchestrator import BackendOrchestrator
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
        orbisprobe_version="0.2.0.dev2",
        base_address=0x400000,
        operation="analyze_function",
        parameters={"function": 0x401000},
        resource_limits=ResourceLimits(timeout_seconds=3).to_dict(),
        backend_fingerprint="adapter-v1",
    )
    key = cache.key(request)
    result = BackendResult.completed(StubBackend.identity, {"ok": True})
    cache.store(request, result)
    assert cache.load(request).to_dict() == result.to_dict()
    changes = {
        "binary_sha256": "b" * 64,
        "backend_version": "1.2.4",
        "orbisprobe_version": "0.2.0.dev3",
        "base_address": 0x500000,
        "parameters": {"function": 0x402000},
        "resource_limits": ResourceLimits(timeout_seconds=4).to_dict(),
        "backend_fingerprint": "adapter-v2",
    }
    for field, value in changes.items():
        changed = CacheRequest(**{**request.__dict__, field: value})
        assert cache.key(changed) != key, field
        assert cache.load(changed) is None, field

    cache_path = cache._path(request)
    poisoned = json.loads(cache_path.read_text(encoding="utf-8"))
    poisoned["result"]["evidence"] = [
        BackendEvidence(
            "value_domain", "r15@0x1000", ["attacker-controlled"]
        ).to_dict()
    ]
    cache_path.write_text(json.dumps(poisoned), encoding="utf-8")
    assert cache.load(request) is None


def test_cache_fingerprint_tracks_angr_worker_and_ghidra_script(tmp_path: Path):
    worker = tmp_path / "angr_worker.py"
    worker.write_text("version = 1\n", encoding="utf-8")
    angr = AngrBackend(interpreter=tmp_path / "missing")
    angr.worker = worker
    angr_before = angr.cache_fingerprint()
    worker.write_text("version = 2\n", encoding="utf-8")
    assert angr.cache_fingerprint() != angr_before

    scripts = tmp_path / "ghidra_scripts"
    scripts.mkdir()
    script = scripts / "OrbisProbeExport.java"
    script.write_text("class ExportV1 {}\n", encoding="utf-8")
    ghidra = GhidraBackend(ghidra_home=tmp_path / "missing")
    ghidra.script_dir = scripts
    ghidra_before = ghidra.cache_fingerprint()
    script.write_text("class ExportV2 {}\n", encoding="utf-8")
    assert ghidra.cache_fingerprint() != ghidra_before


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


class CrashBackend(StubBackend):
    identity = BackendIdentity(
        name="crash",
        version="1",
        independence_family="crash-ir",
        capabilities=frozenset({BackendCapability.CFG}),
    )

    def analyze_function(self, request):
        raise RuntimeError("simulated backend crash")


class BrokenFingerprintBackend(StubBackend):
    identity = BackendIdentity(
        name="broken",
        version="1",
        independence_family="broken-ir",
        capabilities=frozenset({BackendCapability.CFG}),
    )

    def cache_fingerprint(self) -> str:
        raise OSError("fingerprint unavailable")


def test_evidence_address_must_be_an_integer_or_none():
    for address in (float("nan"), float("inf"), "0x401000", {"a": 1}, True):
        with pytest.raises(TypeError):
            BackendEvidence("pcode", "LOAD@0x1", "LOAD", address=address)
        with pytest.raises(TypeError):
            BackendEvidence.from_dict(
                {"kind": "pcode", "subject": "LOAD@0x1", "value": "LOAD", "address": address}
            )
    assert BackendEvidence("pcode", "LOAD@0x1", "LOAD", address=None).address is None
    assert BackendEvidence.from_dict(
        {"kind": "pcode", "subject": "LOAD@0x1", "value": "LOAD", "address": 0x401000}
    ).address == 0x401000


def test_runtime_evidence_from_a_non_runtime_adapter_cannot_confirm():
    static = BackendEvidence("value_domain", "r15@consumer", 0xA8)
    impostor = BackendResult.completed(
        BackendIdentity("angr", "9.2.184", "angr-vex", frozenset()),
        {},
        [
            BackendEvidence(
                "value_domain",
                "r15@consumer",
                0xA8,
                provenance={"source_class": "runtime_real"},
            )
        ],
    )
    report = ConsensusEngine().combine(
        [BackendResult.completed(StubBackend.identity, {}, [static]), impostor]
    )
    claim = report.claims[0]
    assert claim.classification is ConsensusClassification.STRONGLY_SUPPORTED
    assert "runtime evidence from a non-runtime adapter was ignored for promotion" in claim.unknowns


def test_broken_adapter_fingerprint_is_isolated_as_error(tmp_path: Path):
    binary = tmp_path / "x.bin"
    binary.write_bytes(b"\x90\xc3")
    registry = BackendRegistry()
    registry.register(StubBackend)
    registry.register(BrokenFingerprintBackend)
    report = BackendOrchestrator(registry, AnalysisCache(tmp_path / "cache")).run(
        "analyze_function",
        {"binary": str(binary), "base": 0, "function": 0x1000},
        ["broken", "stub"],
    )
    statuses = {item.identity.name: item.status for item in report.results}
    assert statuses["broken"] is BackendStatus.ERROR
    assert statuses["stub"] is BackendStatus.COMPLETED
    broken = next(item for item in report.results if item.identity.name == "broken")
    assert "fingerprint unavailable" in broken.errors[0]


def test_orchestrator_isolates_a_crashing_backend(tmp_path: Path):
    binary = tmp_path / "x.bin"
    binary.write_bytes(b"\x90\xc3")
    registry = BackendRegistry()
    registry.register(StubBackend)
    registry.register(CrashBackend)
    report = BackendOrchestrator(registry, AnalysisCache(tmp_path / "cache")).run(
        "analyze_function",
        {"binary": str(binary), "base": 0, "function": 0x1000},
        ["crash", "stub"],
    )
    statuses = {item.identity.name: item.status for item in report.results}
    assert statuses["crash"] is BackendStatus.ERROR
    assert statuses["stub"] is BackendStatus.COMPLETED
    crashed = next(item for item in report.results if item.identity.name == "crash")
    assert crashed.partial is True
    assert "simulated backend crash" in crashed.errors[0]


def test_non_finite_evidence_values_are_rejected_before_voting():
    for value in (float("nan"), float("inf"), float("-inf")):
        with pytest.raises(ValueError):
            BackendEvidence("value_domain", "r15@consumer", value)
    with pytest.raises(ValueError):
        BackendEvidence("value_domain", "r15@consumer", {"nested": [float("nan")]})


def test_unrepresentable_evidence_is_excluded_without_aborting_consensus():
    identity = StubBackend.identity
    victim = BackendEvidence("value_domain", "r15@consumer", 1)
    object.__setattr__(victim, "value", float("nan"))
    good = BackendResult.completed(
        identity, {}, [BackendEvidence("value_domain", "r15@consumer", 1)]
    )
    report = ConsensusEngine().combine(
        [BackendResult.completed(identity, {}, [victim]), good]
    )
    assert report.claims[0].classification is ConsensusClassification.SUPPORTED
    assert report.excluded_evidence
    assert "not strict-JSON representable" in report.excluded_evidence[0]
    assert report.to_dict()["excluded_evidence"] == report.excluded_evidence


def test_backend_output_cannot_declare_runtime_evidence():
    payload = {
        "kind": "value_domain",
        "subject": "r15@consumer",
        "value": 0xA8,
        "confidence": "SUPPORTED",
        "provenance": {"source_class": "runtime_real"},
    }
    with pytest.raises(ValueError):
        BackendEvidence.from_dict(payload)
    with pytest.raises(ValueError):
        BackendEvidence.from_dict({**payload, "provenance": {"source_class": "trusted"}})

    static = BackendEvidence.from_dict({**payload, "provenance": {"source_class": "static"}})
    assert static.provenance["source_class"] == "static"

    native = BackendResult.completed(
        StubBackend.identity, {}, [BackendEvidence("value_domain", "r15@consumer", 0xA8)]
    )
    internal_runtime = BackendResult.completed(
        BackendIdentity("runtime-log", "1", "real-target-runtime", frozenset()),
        {},
        [
            BackendEvidence(
                "value_domain",
                "r15@consumer",
                0xA8,
                provenance={"source_class": "runtime_real"},
            )
        ],
    )
    report = ConsensusEngine().combine([native, internal_runtime])
    assert report.claims[0].classification is ConsensusClassification.CONFIRMED
