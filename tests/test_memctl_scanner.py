from pathlib import Path

from orbisprobe.analysis.binary import BinaryImage
from orbisprobe.surfaces.memctl import scan_memctl


def test_memctl_detects_pci_config_and_tom_msr_without_claiming_control(tmp_path: Path):
    # mov edx,0xcf8; in eax,dx; mov edx,0xcfc; out dx,eax; mov ecx,TOM; rdmsr; ret
    data = bytes.fromhex(
        "55 48 89 e5 "
        "ba f8 0c 00 00 ed "
        "ba fc 0c 00 00 ef "
        "b9 1a 00 01 c0 0f 32 c3"
    )
    path = tmp_path / "memctl.bin"
    path.write_bytes(data)
    result = scan_memctl(BinaryImage.open(path, architecture="x86_64", base=0x3000))
    assert result.classification == "MEMCTL-ADDRESS-MAP-CANDIDATE"
    surface = result.surfaces[0]
    kinds = {item.kind for item in surface.evidence}
    assert {"pci_config_port", "config_read", "config_write", "address_map_msr"} <= kinds
    assert surface.status.value == "UNKNOWN"
    assert "register semantics on target silicon" in surface.unknowns


def test_memctl_none_is_clean(tmp_path: Path):
    path = tmp_path / "none.bin"
    path.write_bytes(b"\x90\xc3")
    result = scan_memctl(BinaryImage.open(path, architecture="x86_64", base=0))
    assert result.classification == "MEMCTL-NONE"
    assert result.surfaces == []


def test_memctl_attribution_stops_at_call_clobber(tmp_path: Path):
    data = bytes.fromhex(
        "ba f8 0c 00 00 e8 00 00 00 00 ef "
        "b9 1a 00 01 c0 e8 00 00 00 00 0f 32 c3"
    )
    path = tmp_path / "clobber.bin"
    path.write_bytes(data)
    result = scan_memctl(BinaryImage.open(path, architecture="x86_64", base=0x4000))
    assert result.classification == "MEMCTL-NONE"
