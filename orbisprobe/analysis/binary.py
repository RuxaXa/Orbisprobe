from __future__ import annotations

import hashlib
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path


class UnsupportedArchitecture(ValueError):
    pass


@dataclass(frozen=True)
class BinaryImage:
    path: Path
    architecture: str
    base: int
    data: bytes
    sha256: str

    @classmethod
    def open(
        cls,
        path: str | Path,
        *,
        architecture: str = "x86_64",
        base: int = 0,
    ) -> BinaryImage:
        if architecture != "x86_64":
            raise UnsupportedArchitecture(f"unsupported architecture: {architecture}")
        if not isinstance(base, int) or isinstance(base, bool) or base < 0:
            raise ValueError("base must be a non-negative integer")
        resolved = Path(path).resolve()
        data = resolved.read_bytes()
        return cls(
            path=resolved,
            architecture=architecture,
            base=base,
            data=data,
            sha256=hashlib.sha256(data).hexdigest(),
        )

    @property
    def size(self) -> int:
        return len(self.data)

    def virtual_address(self, offset: int) -> int:
        if not isinstance(offset, int) or offset < 0 or offset >= self.size:
            raise ValueError("offset outside binary")
        return self.base + offset

    def file_offset(self, address: int) -> int:
        if not isinstance(address, int) or address < self.base or address >= self.base + self.size:
            raise ValueError("address outside binary")
        return address - self.base

    def read(self, address: int, length: int) -> bytes:
        if not isinstance(length, int) or isinstance(length, bool) or length < 0:
            raise ValueError("length must be a non-negative integer")
        offset = self.file_offset(address)
        if offset + length > self.size:
            raise ValueError("read exceeds binary")
        return self.data[offset : offset + length]

    def disassemble(
        self,
        *,
        start: int | None = None,
        end: int | None = None,
    ) -> Iterator:
        try:
            from capstone import CS_ARCH_X86, CS_MODE_64, Cs
        except ImportError as exc:
            raise RuntimeError("x86-64 analysis requires capstone") from exc
        if self.size == 0:
            return iter(())
        start_address = self.base if start is None else start
        end_address = self.base + self.size if end is None else end
        if start_address < self.base or start_address >= self.base + self.size:
            raise ValueError("start address outside binary")
        if end_address < start_address or end_address > self.base + self.size:
            raise ValueError("end address outside binary")
        start_offset = start_address - self.base
        end_offset = end_address - self.base
        md = Cs(CS_ARCH_X86, CS_MODE_64)
        md.detail = True
        md.skipdata = True
        return md.disasm(self.data[start_offset:end_offset], start_address)

    def find_bytes(self, pattern: bytes, max_hits: int = 10000) -> list[int]:
        if not pattern:
            raise ValueError("pattern must not be empty")
        hits: list[int] = []
        start = 0
        while len(hits) < max_hits:
            offset = self.data.find(pattern, start)
            if offset < 0:
                break
            hits.append(self.base + offset)
            start = offset + 1
        return hits

    def decode_one(self, address: int):
        offset = self.file_offset(address)
        end = min(self.size, offset + 15)
        instructions = self.disassemble(start=address, end=self.base + end)
        instruction = next(iter(instructions), None)
        if instruction is None or instruction.address != address or instruction.mnemonic == ".byte":
            return None
        return instruction

    def find_mov_immediate(self, value: int, max_hits: int = 10000) -> list:
        if not isinstance(value, int) or isinstance(value, bool):
            raise TypeError("immediate value must be an integer")
        encoded = (value & 0xFFFFFFFF).to_bytes(4, "little")
        instructions = []
        seen: set[int] = set()
        for immediate_address in self.find_bytes(encoded, max_hits=max_hits):
            immediate_offset = immediate_address - self.base
            if immediate_offset < 1:
                continue
            opcode = self.data[immediate_offset - 1]
            if not 0xB8 <= opcode <= 0xBF:
                continue
            address = immediate_address - 1
            instruction = self.decode_one(address)
            if (
                instruction is not None
                and instruction.mnemonic == "mov"
                and address not in seen
            ):
                seen.add(address)
                instructions.append(instruction)
        return instructions

    def find_memory_displacement(self, value: int, max_hits: int = 10000) -> list:
        if not isinstance(value, int) or isinstance(value, bool):
            raise TypeError("displacement value must be an integer")
        try:
            from capstone import CS_OP_MEM
        except ImportError as exc:
            raise RuntimeError("x86-64 analysis requires capstone") from exc
        encoded = (value & 0xFFFFFFFF).to_bytes(4, "little")
        instructions = []
        seen: set[int] = set()
        for displacement_address in self.find_bytes(encoded, max_hits=max_hits):
            displacement_offset = displacement_address - self.base
            candidates = []
            for start_offset in range(max(0, displacement_offset - 11), displacement_offset + 1):
                address = self.base + start_offset
                instruction = self.decode_one(address)
                if instruction is None or instruction.address + instruction.size < displacement_address + 4:
                    continue
                if any(
                    operand.type == CS_OP_MEM and operand.mem.disp == value
                    for operand in instruction.operands
                ):
                    candidates.append(instruction)
            if candidates:
                instruction = min(candidates, key=lambda item: item.address)
                if instruction.address not in seen:
                    seen.add(instruction.address)
                    instructions.append(instruction)
        return sorted(instructions, key=lambda instruction: instruction.address)

    def find_ascii(self, needles: list[bytes]) -> list[tuple[int, bytes]]:
        hits: list[tuple[int, bytes]] = []
        lowered = self.data.lower()
        for needle in needles:
            normalized = needle.lower()
            start = 0
            while True:
                offset = lowered.find(normalized, start)
                if offset < 0:
                    break
                hits.append((self.base + offset, needle))
                start = offset + 1
        return sorted(hits, key=lambda item: (item[0], item[1]))

    def heuristic_function_start(self, address: int, max_back: int = 512) -> int | None:
        offset = self.file_offset(address)
        lower = max(0, offset - max_back)
        window = self.data[lower : offset + 1]
        prologues = (b"\x55\x48\x89\xe5", b"\x55\x48\x8b\xec", b"\x41\x57\x41\x56")
        candidates: list[int] = []
        for prologue in prologues:
            cursor = 0
            while True:
                found = window.find(prologue, cursor)
                if found < 0:
                    break
                candidates.append(lower + found)
                cursor = found + 1
        if not candidates:
            return None
        return self.base + max(candidates)
