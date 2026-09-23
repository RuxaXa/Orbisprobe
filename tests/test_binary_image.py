from pathlib import Path

import pytest

from orbisprobe.analysis.binary import BinaryImage, UnsupportedArchitecture


def test_binary_image_uses_virtual_address_domain(tmp_path: Path):
    path = tmp_path / "fixture.bin"
    path.write_bytes(bytes.fromhex("90 c3"))
    image = BinaryImage.open(path, architecture="x86_64", base=0x1000)
    instructions = list(image.disassemble())
    assert [instruction.address for instruction in instructions] == [0x1000, 0x1001]
    assert image.file_offset(0x1001) == 1
    assert image.virtual_address(1) == 0x1001
    assert len(image.sha256) == 64


def test_binary_image_rejects_invalid_addresses_and_architecture(tmp_path: Path):
    path = tmp_path / "fixture.bin"
    path.write_bytes(b"\x90")
    with pytest.raises(UnsupportedArchitecture):
        BinaryImage.open(path, architecture="arm64", base=0)
    image = BinaryImage.open(path, architecture="x86_64", base=0x2000)
    with pytest.raises(ValueError, match="outside binary"):
        image.file_offset(0x1FFF)
    with pytest.raises(ValueError, match="outside binary"):
        list(image.disassemble(start=0x3000))


def test_empty_and_truncated_binary_do_not_crash(tmp_path: Path):
    path = tmp_path / "empty.bin"
    path.write_bytes(b"")
    image = BinaryImage.open(path, architecture="x86_64", base=0)
    assert list(image.disassemble()) == []
    path.write_bytes(b"\x0f")
    image = BinaryImage.open(path, architecture="x86_64", base=0)
    instructions = list(image.disassemble())
    assert all(instruction.mnemonic == ".byte" for instruction in instructions)


def test_candidate_localization_still_requires_decoded_instruction(tmp_path: Path):
    path = tmp_path / "imm.bin"
    path.write_bytes(bytes.fromhex("b8 70 0a 00 00 c3 70 0a 00 00"))
    image = BinaryImage.open(path, architecture="x86_64", base=0x4000)
    hits = image.find_mov_immediate(0xA70)
    assert [(instruction.address, instruction.mnemonic) for instruction in hits] == [(0x4000, "mov")]
    assert image.decode_one(0x4000).op_str == "eax, 0xa70"


def test_candidate_localization_finds_decoded_memory_displacement(tmp_path: Path):
    path = tmp_path / "disp.bin"
    path.write_bytes(bytes.fromhex("48 8b 87 70 0a 00 00 c3"))
    image = BinaryImage.open(path, architecture="x86_64", base=0x5000)
    hits = image.find_memory_displacement(0xA70)
    assert [(instruction.address, instruction.op_str) for instruction in hits] == [
        (0x5000, "rax, qword ptr [rdi + 0xa70]")
    ]
