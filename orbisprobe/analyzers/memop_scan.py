from __future__ import annotations

from dataclasses import asdict, dataclass
from pathlib import Path


@dataclass
class Candidate:
    address: int
    mnemonic: str
    op_str: str
    reason: str

def scan_raw_x86_64(path: str, base: int = 0, start: int = 0, length: int | None = None) -> list[dict]:
    try:
        from capstone import CS_ARCH_X86, CS_MODE_64, Cs
    except ImportError as exc:
        raise RuntimeError("scan-memops requires capstone; install with: pip install -e .") from exc
    data = Path(path).read_bytes()
    view = data[start:] if length is None else data[start:start+length]
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = False
    out: list[Candidate] = []
    prev: list = []
    for insn in md.disasm(view, base + start):
        if insn.mnemonic == "call" and prev:
            nearby = prev[-6:]
            for x in nearby:
                if not x.mnemonic.startswith("mov"):
                    continue
                if not (x.op_str.startswith("edx,") or x.op_str.startswith("rdx,")):
                    continue
                src = x.op_str.split(",", 1)[1].strip()
                # Register/memory sourced values are triage candidates; constants are not.
                if not src.startswith("0x"):
                    out.append(Candidate(insn.address, insn.mnemonic, insn.op_str,
                                         f"size-like {x.op_str} within six instructions before call"))
                    break
        prev.append(insn)
        if len(prev) > 8:
            prev.pop(0)
    return [asdict(x) for x in out]
