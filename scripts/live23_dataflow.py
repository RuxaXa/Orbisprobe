#!/usr/bin/env python3
"""M2-LIVE2.3 — focused dataflow for the RC-001 caller chain (r15 provenance, consumer use of rdi).

Prints, for each function of interest: the instructions around the RC-001 callsite, every write to r15,
which register a value is copied into before being dereferenced, and the calls the consumer makes. The
output is raw instruction evidence, so any engine can re-check each statement.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

import live22_discovery as discovery

RC001 = 0xFFFFFFFFD05AC8F0
CALLERS_L1 = (0xFFFFFFFFD05A7E20, 0xFFFFFFFFD05A8C32)
CALLSITES_L1 = (0xFFFFFFFFD05A8013, 0xFFFFFFFFD05A91D7)
CALLERS_L2 = (0xFFFFFFFFD05A7BF0, 0xFFFFFFFFD05ACCDB)
CONSUMER = 0xFFFFFFFFD057E7B0


def disasm(md, window: bytes, at: int, limit: int = 400) -> list:
    offset = at - 0xFFFFFFFFD00D0000 - 0x1000
    return discovery.disassemble_function(md, window, offset, 0xFFFFFFFFD00D0000 + 0x1000, 8192, limit)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--image", required=True)
    parser.add_argument("--out", required=True)
    parser.add_argument("--window", type=int, default=40)
    args = parser.parse_args()

    from capstone import CS_ARCH_X86, CS_MODE_64, Cs

    image = Path(args.image)
    data = image.read_bytes()
    window = data[0x1000:0x1000 + 13619544]
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = False

    report: dict = {"functions": {}, "unknowns": []}

    def record(name: str, entry: int, focus: list[int]) -> None:
        instructions = disasm(md, window, entry, 600)
        lines = [f"0x{i.address:x} {i.mnemonic} {i.op_str}" for i in instructions]
        r15_writes, rdi_copies, calls, derefs = [], [], [], []
        carries: dict[str, str] = {}
        for insn in instructions:
            mnemonic, ops = insn.mnemonic, insn.op_str
            parts = [p.strip() for p in ops.split(",", 1)] if "," in ops else [ops.strip()]
            if parts and parts[0] in ("r15", "r15d", "r15w", "r15b"):
                r15_writes.append(f"0x{insn.address:x} {mnemonic} {ops}")
            if mnemonic == "call":
                calls.append(f"0x{insn.address:x} call {ops}")
            if len(parts) == 2:
                dst, src = parts
                if src in ("rdi", "edi") and dst not in ("rdi", "edi"):
                    rdi_copies.append(f"0x{insn.address:x} {mnemonic} {ops}")
                    carries[dst] = "rdi"
                mem = discovery.mem_operand(src)
                if mem and (mem[0] == "rdi" or carries.get(mem[0]) == "rdi"):
                    derefs.append(f"0x{insn.address:x} {mnemonic} {ops}  (base {mem[0]})")
                if mem and ", [" in dst:
                    pass
        report["functions"][name] = {
            "entry": f"0x{entry:x}", "instruction_count": len(instructions),
            "r15_writes": r15_writes, "rdi_copies": rdi_copies, "rdi_derefs": derefs,
            "call_count": len(calls), "calls_sample": calls[:14],
            "focus": {f"0x{a:x}": [
                line for line in lines
                if a - args.window * 4 <= int(line.split()[0], 16) <= a + args.window * 4] for a in focus},
        }

    record("rc001", RC001, [0xFFFFFFFFD05AC963, 0xFFFFFFFFD05AC96A, 0xFFFFFFFFD05AC974, 0xFFFFFFFFD05AC98B])
    record("caller_l1_a", CALLERS_L1[0], list(CALLSITES_L1))
    record("caller_l1_b", CALLERS_L1[1], list(CALLSITES_L1))
    for index, caller in enumerate(CALLERS_L2, start=1):
        record(f"caller_l2_{index}", caller, [])
    record("consumer", CONSUMER, [])

    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    Path(args.out).write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    for name, info in report["functions"].items():
        print(f"== {name} @ {info['entry']} ({info['instruction_count']} insns, {info['call_count']} calls)")
        print(f"   r15 writes : {info['r15_writes'][:4]}")
        print(f"   rdi copies : {info['rdi_copies'][:6]}")
        print(f"   rdi derefs : {info['rdi_derefs'][:6]}")
        for site, lines in info["focus"].items():
            print(f"   around {site}:")
            for line in lines[:12]:
                print(f"      {line}")
    print(f"evidence: {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
