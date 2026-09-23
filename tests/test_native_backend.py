from importlib.metadata import version as distribution_version
from pathlib import Path

from orbisprobe.backends.base import BackendCapability, BackendStatus
from orbisprobe.backends.native_backend import NativeBackend


def test_native_backend_implements_common_contract(tmp_path: Path):
    binary = tmp_path / "flow.bin"
    # mov rax,[rsi+8]; mov rbx,rax; call +0; mov rdi,rbx; ret
    binary.write_bytes(bytes.fromhex("48 8b 46 08 48 89 c3 e8 00 00 00 00 48 89 df c3"))
    backend = NativeBackend()
    available = backend.availability()
    assert available.status is BackendStatus.COMPLETED
    assert BackendCapability.DATAFLOW in available.identity.capabilities
    request = {
        "binary": str(binary),
        "architecture": "x86_64",
        "base": 0x400000,
        "function": 0x400000,
        "function_end": 0x400010,
        "source": {"kind": "memory", "base_register": "rsi", "offset": 8},
    }
    result = backend.trace_value(request)
    assert result.status is BackendStatus.COMPLETED
    assert any(item["kind"] == "definition" for item in result.data["events"])
    assert any(item["kind"] == "call_clobber" for item in result.data["events"])
    assert result.evidence


def test_native_backend_uses_pinned_capstone_distribution_version():
    backend = NativeBackend()
    assert distribution_version("capstone") == "5.0.9"
    assert backend.version() == "5.0.9"
    assert backend.identity.version == "5.0.9"
