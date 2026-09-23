from pathlib import Path

from orbisprobe.backends.base import (
    AnalysisBackend,
    BackendCapability,
    BackendEvidence,
    BackendIdentity,
    BackendResult,
)
from orbisprobe.backends.cache import AnalysisCache
from orbisprobe.backends.orchestrator import BackendOrchestrator
from orbisprobe.backends.registry import BackendRegistry


class CountingBackend(AnalysisBackend):
    identity = BackendIdentity(
        "counting",
        "1",
        "counting-ir",
        frozenset({BackendCapability.DATAFLOW}),
    )
    calls = 0

    def availability(self):
        return BackendResult.completed(self.identity, {"available": True})

    def version(self):
        return "1"

    def trace_value(self, request):
        type(self).calls += 1
        return BackendResult.completed(
            self.identity,
            {},
            [BackendEvidence("value_domain", "r15@0x1000", "user_ptr")],
        )

    analyze_function = trace_value
    recover_cfg = trace_value
    find_definitions = trace_value
    find_consumers = trace_value
    resolve_call_arguments = trace_value
    evaluate_branch_constraints = trace_value
    analyze_memory_access = trace_value


def test_orchestrator_uses_cache_and_returns_consensus(tmp_path: Path):
    binary = tmp_path / "x.bin"
    binary.write_bytes(b"\x90\xc3")
    registry = BackendRegistry()
    registry.register(CountingBackend)
    CountingBackend.calls = 0
    orchestrator = BackendOrchestrator(registry, AnalysisCache(tmp_path / "cache"))
    request = {
        "binary": str(binary),
        "architecture": "x86_64",
        "base": 0x1000,
        "function": 0x1000,
        "function_end": 0x1002,
        "source": {"register": "r15"},
    }
    first = orchestrator.run("trace_value", request, ["counting"])
    second = orchestrator.run("trace_value", request, ["counting"])
    assert CountingBackend.calls == 1
    assert first.cache_hits == []
    assert second.cache_hits == ["counting"]
    assert first.consensus.claims[0].subject == "r15@0x1000"


def test_orchestrator_reports_unavailable_and_continues(tmp_path: Path):
    binary = tmp_path / "x.bin"
    binary.write_bytes(b"\xc3")
    registry = BackendRegistry()
    registry.register(CountingBackend)
    report = BackendOrchestrator(registry, AnalysisCache(tmp_path / "cache")).run(
        "analyze_function",
        {"binary": str(binary), "base": 0, "function": 0},
        ["missing", "counting"],
    )
    assert report.results[0].status.value == "BACKEND_UNAVAILABLE"
    assert report.results[1].status.value == "COMPLETED"


def test_orchestrator_rejects_unknown_operation(tmp_path: Path):
    registry = BackendRegistry()
    registry.register(CountingBackend)
    orchestrator = BackendOrchestrator(registry, AnalysisCache(tmp_path / "cache"))
    try:
        orchestrator.run("__dict__", {"binary": "/tmp/no"}, ["counting"])
    except ValueError as exc:
        assert "unsupported backend operation" in str(exc)
    else:
        raise AssertionError("unknown operation was accepted")
