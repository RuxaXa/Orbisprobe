import json
from pathlib import Path

from orbisprobe.analysis.binary import BinaryImage
from orbisprobe.surfaces.secure import scan_secure


def test_case003_fixture_recognizes_host_descriptor_without_exploit_claim(tmp_path: Path):
    fixture = json.loads(
        (Path(__file__).parent / "fixtures" / "case003_host_descriptor.json").read_text(encoding="utf-8")
    )
    binary = tmp_path / "case003.bin"
    binary.write_bytes(bytes.fromhex(fixture["binary_hex"]))
    result = scan_secure(BinaryImage.open(binary, architecture="x86_64", base=0x638000))
    assert result.classification == fixture["expected_classification"]
    surface = result.surfaces[0]
    assert surface.status.value == fixture["expected_status"]
    assert surface.surface_type.value == "SAMU_SECURE"
    assert surface.candidate_priority == "P3"
    kinds = {item.kind for item in surface.evidence}
    assert {
        "descriptor_size", "tag_compare", "address_field", "op_field", "repeated_mutable_read"
    } <= kinds
    serialized = json.dumps(result.to_dict()).lower()
    assert "exploit confirmed" not in serialized
    assert "secure consumer semantics unknown" in surface.unknowns
    assert result.graph.to_dict()["edges"] == []


def test_secure_pattern_fragment_alone_is_not_surface(tmp_path: Path):
    binary = tmp_path / "weak.bin"
    binary.write_bytes(bytes.fromhex("ba 80 00 00 00 c3"))
    result = scan_secure(BinaryImage.open(binary, architecture="x86_64", base=0))
    assert result.classification == "SECURE-NONE"
    assert result.surfaces == []


def test_secure_partial_patterns_in_different_functions_are_not_combined(tmp_path: Path):
    first = bytes.fromhex("55 48 89 e5 ba 80 00 00 00 83 f8 07 83 f8 08 c3")
    second = bytes.fromhex(
        "55 48 89 e5 48 8b 46 08 8b 4e 10 49 8b 47 28 e8 00 00 00 00 "
        "49 8b 47 28 c3"
    )
    binary = tmp_path / "split.bin"
    binary.write_bytes(first + b"\x90" * 0x1100 + second)
    result = scan_secure(BinaryImage.open(binary, architecture="x86_64", base=0x5000))
    assert result.classification == "SECURE-NONE"
    assert result.surfaces == []


def test_secure_store_only_fields_are_not_repeated_mutable_reads(tmp_path: Path):
    data = bytes.fromhex(
        "55 48 89 e5 ba 80 00 00 00 83 f8 07 83 f8 08 83 f8 09 "
        "48 89 46 08 89 4e 10 "
        "49 89 47 28 49 89 57 30 49 89 4f 38 e8 00 00 00 00 "
        "49 89 47 28 49 89 57 30 49 89 4f 38 c3"
    )
    binary = tmp_path / "stores.bin"
    binary.write_bytes(data)
    result = scan_secure(BinaryImage.open(binary, architecture="x86_64", base=0x6000))
    assert result.classification == "HOST-ONLY-CHAIN"
    assert result.surfaces[0].candidate_priority == "P4"
    assert not any(item.kind == "repeated_mutable_read" for item in result.surfaces[0].evidence)


def test_secure_unconditional_jump_stops_cross_function_combination(tmp_path: Path):
    first = bytes.fromhex(
        "55 48 89 e5 ba 80 00 00 00 83 f8 07 83 f8 08 83 f8 09 e9 00 00 00 00"
    )
    second = bytes.fromhex("55 48 89 e5 48 8b 46 08 8b 4e 10 c3")
    binary = tmp_path / "jump-split.bin"
    binary.write_bytes(first + second)
    result = scan_secure(BinaryImage.open(binary, architecture="x86_64", base=0x7000))
    assert result.classification == "SECURE-NONE"
    assert result.surfaces == []
