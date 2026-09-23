#!/usr/bin/env python3
"""LIVE2.2 diagnostic: why the strict chain detector finds no candidate in the FW13.52 image.

Measures the detector's filter funnel and, independently of the tracker, counts how often a function
body loads from a memory operand based on an argument register. That separates "no such chain exists"
from "the provenance model cannot see it".
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

import live22_discovery as discovery

ARG_REGS = {"rdi", "rsi", "rdx", "rcx", "r8", "r9"}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--image", required=True)
    parser.add_argument("--base", required=True, type=lambda v: int(v, 0))
    parser.add_argument("--start", type=lambda v: int(v, 0), default=0x1000)
    parser.add_argument("--length", type=lambda v: int(v, 0), default=None)
    parser.add_argument("--functions", type=int, default=2000)
    parser.add_argument("--out", required=True)
    args = parser.parse_args()

    from capstone import CS_ARCH_X86, CS_MODE_64, Cs

    image = Path(args.image)
    data = image.read_bytes()
    length = args.length if args.length is not None else len(data)
    window = data[args.start:args.start + length]
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = False
    base = args.base + args.start

    entries = discovery.function_offsets(window, base, md, 200000, 4096)
    funnel: dict[str, int] = {}
    functions_sampled = 0
    arg_register_reads = 0
    stack_base_reads = 0
    other_base_reads = 0
    examples: list[str] = []
    for offset in entries[: args.functions]:
        instructions = discovery.disassemble_function(md, window, offset, base, 4096, 400)
        if len(instructions) < 6:
            continue
        functions_sampled += 1
        _found, stats = discovery.analyze_function(instructions, base, 40, base + offset, 0, 6)
        for key, value in stats.items():
            funnel[key] = funnel.get(key, 0) + value
        for insn in instructions:
            if not (insn.mnemonic.startswith("mov") and "," in insn.op_str):
                continue
            mem = discovery.mem_operand(insn.op_str.split(",", 1)[1])
            if mem is None:
                continue
            if mem[0] in ARG_REGS:
                arg_register_reads += 1
                if len(examples) < 5:
                    examples.append(f"0x{insn.address:x} {insn.mnemonic} {insn.op_str}")
            elif mem[0] in ("rbp", "rsp"):
                stack_base_reads += 1
            else:
                other_base_reads += 1

    report = {
        "image": str(image), "image_sha256": discovery.sha256_file(image),
        "kernel_base": f"0x{args.base:x}", "functions_sampled": functions_sampled,
        "detector_funnel": funnel,
        "independent_counts": {
            "memory_reads_via_argument_register": arg_register_reads,
            "memory_reads_via_stack_frame_pointer": stack_base_reads,
            "memory_reads_via_other_base": other_base_reads,
        },
        "reading": ("A zero argument-register read count means this kernel region reaches fields through "
                    "stack-reloaded or derived pointers, so the detector's provenance model -- not the "
                    "absence of chains -- is the limiting factor. No candidate may be claimed from this."),
        "examples": examples,
    }
    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    Path(args.out).write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({k: report[k] for k in ("functions_sampled", "detector_funnel",
                                             "independent_counts")}, indent=2))
    print(f"evidence: {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
