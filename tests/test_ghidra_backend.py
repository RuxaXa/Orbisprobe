from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from orbisprobe.backends.base import BackendCapability, BackendStatus, ResourceLimits
from orbisprobe.backends.ghidra_backend import GhidraBackend

GHIDRA_HOME = Path("/home/hermes/tools/ghidra_12.1.3_PUBLIC")


def fixture(tmp_path: Path) -> Path:
    # push rbp; mov rbp,rsp; mov rax,[rdi+8]; mov [rsi+0x10],rax; ret
    path = tmp_path / "pcode.bin"
    path.write_bytes(bytes.fromhex("55 48 89 e5 48 8b 47 08 48 89 46 10 c3"))
    return path


def backend() -> GhidraBackend:
    return GhidraBackend(
        ghidra_home=GHIDRA_HOME,
        limits=ResourceLimits(timeout_seconds=60, memory_mb=2048, maximum_graph_size=5000),
    )


def install_fake_runner(monkeypatch, instance: GhidraBackend, payload: str | None, returncode: int = 0):
    captured = {}

    def fake_run(command, environment):
        captured["command"] = command
        captured["environment"] = environment
        if payload is not None:
            output = Path(command[command.index("-postScript") + 2])
            output.write_text(payload, encoding="utf-8")
        return subprocess.CompletedProcess(command, returncode, "", "")

    monkeypatch.setattr(instance, "_run_process", fake_run)
    return captured


def valid_export(entry: str = "0x400000") -> str:
    return json.dumps(
        {
            "schema": "orbisprobe-ghidra-pcode-v1",
            "partial": False,
            "function": {"entry": entry},
            "instructions": [{"address": entry, "mnemonic": "ret"}],
            "pcode": [],
            "definitions": [],
            "consumers": [],
            "memory_accesses": [],
            "calls": [],
            "blocks": [],
            "xrefs": [],
            "parameters": [],
            "stack_variables": [],
            "decompiler_c": "return;",
        }
    )


def test_ghidra_availability_and_capabilities():
    result = backend().availability()
    assert result.status is BackendStatus.COMPLETED
    assert result.identity.version == "12.1.3"
    assert result.data["available"] is True
    assert {
        BackendCapability.CFG,
        BackendCapability.DATAFLOW,
        BackendCapability.CALLGRAPH,
        BackendCapability.DECOMPILER,
        BackendCapability.HEADLESS,
    } <= result.identity.capabilities


def test_ghidra_headless_exports_normalized_pcode(tmp_path: Path):
    binary = fixture(tmp_path)
    result = backend().analyze_function(
        {
            "binary": str(binary),
            "architecture": "x86_64",
            "base": 0x400000,
            "function": 0x400000,
        }
    )
    assert result.status in {BackendStatus.COMPLETED, BackendStatus.PARTIAL}
    assert result.data["function"]["entry"] == 0x400000
    mnemonics = {item["opcode"] for item in result.data["pcode"]}
    assert "LOAD" in mnemonics
    assert "STORE" in mnemonics
    assert result.data["instructions"]
    assert result.data["analysis_mode"] == "FULL_ANALYSIS"
    assert "DECOMPILER" in result.data["effective_capabilities"]
    assert result.metrics["elapsed_seconds"] < 60


def test_ghidra_export_supports_api_views(tmp_path: Path):
    binary = fixture(tmp_path)
    request = {
        "binary": str(binary),
        "architecture": "x86_64",
        "base": 0x500000,
        "function": 0x500000,
    }
    assert "blocks" in backend().recover_cfg(request).data
    assert "definitions" in backend().find_definitions(request).data
    assert "consumers" in backend().find_consumers(request).data
    assert "memory_accesses" in backend().analyze_memory_access(request).data


def test_missing_ghidra_is_cleanly_unavailable(tmp_path: Path):
    result = GhidraBackend(ghidra_home=tmp_path / "missing").availability()
    assert result.status is BackendStatus.BACKEND_UNAVAILABLE


def test_large_raw_image_uses_bounded_noanalysis_mode(tmp_path: Path):
    binary = tmp_path / "large.bin"
    # stack local, register copy, in-range direct call, epilogue, callee
    code = bytes.fromhex(
        "55 48 89 e5 48 83 ec 20 48 89 7d f8 48 8b 45 f8 "
        "e8 06 00 00 00 48 83 c4 20 5d c3 31 c0 c3"
    )
    binary.write_bytes(code + b"\x00" * (1024 * 1024 + 1))
    result = backend().analyze_function(
        {
            "binary": str(binary),
            "architecture": "x86_64",
            "base": 0x600000,
            "function": 0x600000,
        }
    )
    assert result.status in {BackendStatus.COMPLETED, BackendStatus.PARTIAL}
    assert result.metrics["bounded_noanalysis"] is True
    assert result.data["analysis_mode"] == "BOUNDED_ANALYSIS"
    assert result.data["function"]["entry"] == 0x600000
    assert all(0x600000 <= item["address"] < 0x600000 + len(code) for item in result.data["instructions"])
    assert result.data["calls"] == [{"address": 0x600010, "target": 0x60001B}]
    pcode_operations = {item["opcode"] for item in result.data["pcode"]}
    assert {"CALL", "LOAD", "STORE"} <= pcode_operations
    assert any(
        node.get("register")
        for item in result.data["pcode"]
        for node in [item.get("output", {}), *item.get("inputs", [])]
    )
    assert result.data["decompiler_c"]
    assert {"CFG", "DATAFLOW", "CALLGRAPH", "DECOMPILER", "MEMORY_MODEL"} <= set(
        result.data["effective_capabilities"]
    )


def test_ghidra_item_ceiling_is_explicit_partial_analysis(tmp_path: Path):
    binary = fixture(tmp_path)
    limited = GhidraBackend(
        ghidra_home=GHIDRA_HOME,
        limits=ResourceLimits(timeout_seconds=60, maximum_graph_size=1),
    ).analyze_function(
        {
            "binary": str(binary),
            "architecture": "x86_64",
            "base": 0x700000,
            "function": 0x700000,
        }
    )
    assert limited.status is BackendStatus.PARTIAL
    assert limited.partial is True
    assert limited.data["analysis_mode"] == "PARTIAL_ANALYSIS"


@pytest.mark.parametrize(
    "payload",
    ["not-json", '{"partial":', "[]", "null", "42", '"text"', '{"partial":false}'],
)
def test_ghidra_malformed_or_truncated_json_is_structured_error(
    tmp_path: Path, monkeypatch, payload: str
):
    instance = backend()
    install_fake_runner(monkeypatch, instance, payload)
    result = instance.analyze_function(
        {"binary": str(fixture(tmp_path)), "base": 0x400000, "function": 0x400000}
    )
    assert result.status is BackendStatus.ERROR
    assert result.partial is True
    assert result.data["analysis_mode"] == "PARTIAL_ANALYSIS"
    assert result.evidence == []


def test_ghidra_huge_external_output_hits_resource_limit(tmp_path: Path, monkeypatch):
    instance = backend()
    install_fake_runner(monkeypatch, instance, "x" * (16 * 1024 * 1024 + 1))
    result = instance.analyze_function(
        {"binary": str(fixture(tmp_path)), "base": 0x400000, "function": 0x400000}
    )
    assert result.status is BackendStatus.RESOURCE_LIMIT
    assert result.partial is True
    assert result.evidence == []


def test_ghidra_nonzero_exit_with_valid_output_is_partial(tmp_path: Path, monkeypatch):
    payload = valid_export()
    instance = backend()
    install_fake_runner(monkeypatch, instance, payload, returncode=9)
    result = instance.analyze_function(
        {"binary": str(fixture(tmp_path)), "base": 0x400000, "function": 0x400000}
    )
    assert result.status is BackendStatus.PARTIAL
    assert result.partial is True
    assert result.data["analysis_mode"] == "PARTIAL_ANALYSIS"


def test_ghidra_missing_output_and_timeout_fail_closed(tmp_path: Path, monkeypatch):
    request = {"binary": str(fixture(tmp_path)), "base": 0x400000, "function": 0x400000}
    missing_output = backend()
    install_fake_runner(monkeypatch, missing_output, None)
    missing_result = missing_output.analyze_function(request)
    assert missing_result.status is BackendStatus.ERROR
    assert missing_result.evidence == []

    timed_out = backend()

    def timeout(command, environment):
        raise subprocess.TimeoutExpired(command, 1)

    monkeypatch.setattr(timed_out, "_run_process", timeout)
    timeout_result = timed_out.analyze_function(request)
    assert timeout_result.status is BackendStatus.TIMEOUT
    assert timeout_result.partial is True
    assert timeout_result.evidence == []


def test_ghidra_invalid_inputs_and_unsafe_filename_fail_closed(tmp_path: Path, monkeypatch):
    instance = backend()
    missing = instance.analyze_function(
        {"binary": str(tmp_path / "missing.bin"), "base": 0, "function": 0}
    )
    invalid = instance.analyze_function(
        {"binary": str(fixture(tmp_path)), "base": -1, "function": 0}
    )
    assert missing.status is invalid.status is BackendStatus.ERROR

    sentinel = tmp_path / "PWNED"
    unsafe = tmp_path / "x;touch PWNED.bin"
    unsafe.write_bytes(bytes.fromhex("c3"))
    payload = valid_export("0x800000")
    captured = install_fake_runner(monkeypatch, instance, payload)
    result = instance.analyze_function(
        {"binary": str(unsafe), "base": 0x800000, "function": 0x800000}
    )
    assert result.status is BackendStatus.COMPLETED
    command = captured["command"]
    assert command[command.index("-import") + 1] == str(unsafe.resolve())
    assert not sentinel.exists()


def ghidra_result_for(tmp_path: Path, monkeypatch, payload: str):
    instance = backend()
    install_fake_runner(monkeypatch, instance, payload)
    return instance.analyze_function(
        {"binary": str(fixture(tmp_path)), "base": 0x400000, "function": 0x400000}
    )


def test_ghidra_null_pcode_address_is_not_lost_or_crashing(tmp_path: Path, monkeypatch):
    payload = json.dumps(
        {
            **json.loads(valid_export()),
            "pcode": [{"opcode": "LOAD", "address": None}],
        }
    )
    result = ghidra_result_for(tmp_path, monkeypatch, payload)
    assert result.status in {BackendStatus.COMPLETED, BackendStatus.PARTIAL}
    assert result.evidence
    assert result.evidence[0].subject == "LOAD@unknown"
    assert result.evidence[0].address is None


@pytest.mark.parametrize(
    "payload",
    [
        json.dumps({**json.loads(valid_export()), "pcode": [{"opcode": "LOAD", "address": "1000"}]}),
        json.dumps({**json.loads(valid_export()), "pcode": [{"opcode": "LOAD", "address": {"a": 1}}]}),
        json.dumps({**json.loads(valid_export()), "pcode": [{"opcode": "LOAD", "address": True}]}),
        json.dumps({**json.loads(valid_export()), "pcode": [{"opcode": 7, "address": 0x400000}]}),
        json.dumps({**json.loads(valid_export()), "pcode": ["LOAD"]}),
        json.dumps(
            {**json.loads(valid_export()), "instructions": [{"address": 0x400000, "mnemonic": 5}]}
        ),
        json.dumps(
            {**json.loads(valid_export()), "instructions": [{"address": None, "mnemonic": "ret"}]}
        ),
        json.dumps({**json.loads(valid_export()), "function": {"entry": True}}),
    ],
)
def test_ghidra_nested_wrong_shaped_output_fails_closed(
    tmp_path: Path, monkeypatch, payload: str
):
    result = ghidra_result_for(tmp_path, monkeypatch, payload)
    assert result.status is BackendStatus.ERROR
    assert result.partial is True
    assert result.evidence == []
    assert result.data["analysis_mode"] == "PARTIAL_ANALYSIS"
    assert result.errors


def test_ghidra_non_finite_numbers_fail_closed(tmp_path: Path, monkeypatch):
    payload = json.dumps(
        {
            "schema": "orbisprobe-ghidra-pcode-v1",
            "partial": False,
            "function": {"entry": 0x400000},
            "instructions": [],
            "pcode": [],
            "definitions": [],
            "consumers": [],
            "memory_accesses": [{"address": 0x400000, "access": 1, "size": float("nan")}],
            "calls": [],
            "blocks": [],
            "xrefs": [],
            "parameters": [],
            "stack_variables": [],
        }
    )
    result = ghidra_result_for(tmp_path, monkeypatch, payload)
    assert result.status is BackendStatus.ERROR
    assert result.evidence == []
