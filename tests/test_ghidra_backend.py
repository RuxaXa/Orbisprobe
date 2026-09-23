from __future__ import annotations

from pathlib import Path

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
    code = bytes.fromhex("55 48 89 e5 48 8b 47 08 c3")
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
    assert result.data["function"]["entry"] == 0x600000
