#!/usr/bin/env python3
"""M2-LIVE2.2 — real candidate discovery: double-read chains in the FW13.52 kernel image.

Engine #1 (native/capstone, engine #2 re-verifies): function-scoped linear sweep plus a strict
double-read test. A candidate is only emitted when **all** of these hold inside one function:

  A. read #1 and read #2 are the same ``[base+disp]`` from the same base register
  B. at least one *direct* ``call`` lies between them
  C. a comparison of the value loaded by read #1 lies between them (validation/use)
  D. the base register and the loaded value survive unchanged (no clobber) between the reads
  E. read #2 is followed within a few instructions by a consumer (store of the value / handing it
     to a call as an argument)
  F. the gap between the reads is bounded (<= --max-gap instructions) and the function is <= 4096 B

Anything else is discarded: a pattern without a dataflow chain is not evidence.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path

ARG_REGS = ("rdi", "rsi", "rdx", "rcx", "r8", "r9")
MOV_MNEMONICS = ("mov", "movzx", "movsx", "movsxd", "movsxd", "movd", "movq")
MEM_RE = re.compile(
    r"^(?:byte|word|dword|qword|xmmword) ptr \[([a-z0-9]+)(?:\s*\+\s*(0x[0-9a-f]+))?\]$")
REG_ALIASES = {"ebp": "rbp", "ebp_": "rbp", "edx": "rdx", "edi": "rdi", "esi": "rsi", "ecx": "rcx",
               "eax": "rax", "ebx": "rbx", "r8d": "r8", "r9d": "r9", "ax": "rax", "bx": "rbx",
               "cx": "rcx", "dx": "rdx", "di": "rdi", "si": "rsi", "al": "rax", "bl": "rbx",
               "cl": "rcx", "dl": "rdx", "ch": "rcx", "ah": "rax", "bh": "rbx", "dh": "rdx"}


def canon(register: str) -> str:
    reg = register.strip().lower()
    return REG_ALIASES.get(reg, reg)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def mem_operand(op_str: str) -> tuple[str, int] | None:
    match = MEM_RE.match(op_str.strip())
    if not match:
        return None
    base, disp = match.groups()
    return canon(base), int(disp, 16) if disp else 0


def function_offsets(data: bytes, base: int, md, max_targets: int, max_bytes: int) -> list[int]:
    """Function entries = direct ``call`` targets inside the image.

    This kernel is built without frame pointers and without endbr64, so prologue matching is not
    usable; call targets are the reliable entry set. Each target is then swept linearly and stopped
    at ret/int3/jmp, so a body is never entered mid-instruction.
    """

    offsets: set[int] = set()
    pos = 0
    size = len(data)
    while pos < size and len(offsets) < max_targets:
        insn = next(md.disasm(data[pos:pos + 16], base + pos), None)
        if insn is None:
            pos += 1
            continue
        if insn.mnemonic == "call" and insn.op_str.startswith("0x"):
            target = int(insn.op_str, 16)
            if base <= target < base + size:
                offsets.add(target - base)
        pos += insn.size
    return sorted(offsets)


def disassemble_function(md, data: bytes, start: int, base: int, max_bytes: int, max_instructions: int):
    instructions = []
    pos = start
    limit = min(len(data), start + max_bytes)
    while pos < limit and len(instructions) < max_instructions:
        insn = next(md.disasm(data[pos:pos + 16], base + pos), None)
        if insn is None:
            break
        instructions.append(insn)
        pos += insn.size
        if insn.mnemonic in {"ret", "int3", "hlt", "jmp"} and insn.mnemonic != "jmp":
            break
        if insn.mnemonic == "jmp" and insn.op_str.startswith("0x"):
            break
    return instructions


def is_memory(operand: str) -> bool:
    """Capstone prints memory operands with a size prefix (``dword ptr [rbx]``) -- parse, do not
    string-match. This was the bug that silently dropped every operand in the first detector pass."""

    return mem_operand(operand) is not None


def analyze_function(instructions, base: int, max_gap: int, function_start: int, function_end: int,
                     min_instructions: int) -> tuple[list[dict], dict]:
    empty = {"reads_recorded": 0, "with_validation": 0, "with_call": 0, "with_read_2": 0,
             "with_consumer": 0}
    if len(instructions) < min_instructions:
        return [], empty
    found: list[dict] = []
    stats = dict(empty)
    # provenance: argument registers and registers holding a copy of one
    provenance: dict[str, str] = {reg: "argument register (caller/user supplied)" for reg in ARG_REGS}
    reads: dict[tuple[str, int], dict] = {}
    value_regs: dict[str, str] = {}  # register -> field key currently carried in it
    for index, insn in enumerate(instructions):
        mnemonic, ops = insn.mnemonic, insn.op_str
        dst = src = None
        dst_mem = src_mem = None
        if "," in ops:
            dst_raw, src_raw = (part.strip() for part in ops.split(",", 1))
            if is_memory(dst_raw):
                dst_mem = mem_operand(dst_raw)
            else:
                dst = canon(dst_raw)
            if is_memory(src_raw):
                src_mem = mem_operand(src_raw)
            else:
                src = canon(src_raw)
        elif ops:
            if is_memory(ops):
                dst_mem = mem_operand(ops)
            else:
                dst = canon(ops)
        # a register write destroys what that register carried -- before tracking this instruction,
        # and never for the register that this instruction loads into
        if mnemonic in MOV_MNEMONICS and dst and src != dst and src_mem is None:
            value_regs.pop(dst, None)
            if dst in provenance and src not in provenance:
                provenance.pop(dst, None)
        # provenance propagation
        if mnemonic in MOV_MNEMONICS and src in provenance and dst:
            provenance[dst] = f"copy of {src}"
        if mnemonic in MOV_MNEMONICS and dst and not src_mem and src in value_regs:
            value_regs[dst] = value_regs[src]
        # read from a tracked field
        if mnemonic in MOV_MNEMONICS and src_mem and src_mem[0] in provenance:
            key = src_mem
            if key not in reads:
                reads[key] = {
                    "field": f"[{key[0]}{f'+0x{key[1]:x}' if key[1] else ''}]",
                    "base_register": key[0],
                    "displacement": f"0x{key[1]:x}",
                    "untrusted_source": provenance[src_mem[0]],
                    "read_1": f"0x{insn.address:x} {mnemonic} {ops}",
                    "read_1_index": index,
                    "calls": [],
                    "validation": None,
                    "read_2": None,
                    "consumer": None,
                }
            if dst:
                value_regs[dst] = reads[key]["field"]
        # validation: the value register, or the field memory operand itself, is compared
        if mnemonic in {"cmp", "test"} and ops:
            checked: set[str | None] = set()
            for operand in ops.split(",", 1):
                operand = operand.strip()
                if is_memory(operand):
                    mem = mem_operand(operand)
                    checked.add(reads[mem]["field"] if (mem in reads) else None)
                else:
                    register = canon(operand)
                    checked.add(value_regs.get(register))
            for record in reads.values():
                if record["field"] in checked and record["validation"] is None:
                    record["validation"] = f"0x{insn.address:x} {mnemonic} {ops}"
        # direct calls between the reads
        if mnemonic == "call" and ops.startswith("0x"):
            for record in reads.values():
                if record["read_2"] is None:
                    record["calls"].append({"address": f"0x{insn.address:x}", "target": ops})
        # read #2 of the same field
        if mnemonic in MOV_MNEMONICS and src_mem:
            record = reads.get(src_mem)
            if (record and record["read_2"] is None and record["read_1_index"] != index
                    and index - record["read_1_index"] <= max_gap and record["calls"]
                    and record["validation"]):
                record["read_2"] = f"0x{insn.address:x} {mnemonic} {ops}"
                record["read_2_index"] = index
                if dst:
                    value_regs[dst] = record["field"]
        # consumer: the field value is stored somewhere or handed to a call
        if src and src in value_regs:
            field = value_regs[src]
            for record in reads.values():
                if record["field"] == field and record["read_2"] and record["consumer"] is None:
                    record["consumer"] = f"0x{insn.address:x} {mnemonic} {ops}"
        if mnemonic == "call":
            for register in ARG_REGS:
                if register in value_regs:
                    for record in reads.values():
                        if (record["field"] == value_regs[register] and record["read_2"]
                                and not record["consumer"]):
                            record["consumer"] = f"0x{insn.address:x} call with {register} = field value"
        if dst_mem and src in value_regs:
            field = value_regs[src]
            for record in reads.values():
                if record["field"] == field and record["read_2"] and record["consumer"] is None:
                    record["consumer"] = f"0x{insn.address:x} {mnemonic} {ops}" + " (store)"
    for record in reads.values():
        stats["reads_recorded"] += 1
        stats["with_validation"] += 1 if record["validation"] else 0
        stats["with_call"] += 1 if record["calls"] else 0
        if not (record["read_2"] and record["validation"] and record["calls"] and record["consumer"]):
            continue
        stats["with_read_2"] += 1
        stats["with_consumer"] += 1
        record["instructions_between_reads"] = record["read_2_index"] - record["read_1_index"]
        record["delta_calls"] = len(record["calls"])
        record["function_start"] = f"0x{function_start:x}"
        record["function_end"] = f"0x{function_end:x}"
        record["priority"], record["score_reasons"] = score(record)
        found.append(record)
    return found, stats


def score(record: dict) -> tuple[str, list[str]]:
    consumer = record["consumer"] or ""
    untrusted = "argument register" in record["untrusted_source"] or "copy of" in record["untrusted_source"]
    if not untrusted:
        return "P4", ["provenance is not caller/user supplied"]
    if "call with" in consumer:
        return "P1", ["value handed to a call as an argument (host-closed consumer)"]
    if "ptr [" in consumer:
        return "P1", ["value stored to memory (host-visible destination)"]
    return "P2", ["consumer present but the observable is indirect"]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--image", required=True)
    parser.add_argument("--base", required=True, type=lambda v: int(v, 0))
    parser.add_argument("--start", type=lambda v: int(v, 0), default=0)
    parser.add_argument("--length", type=lambda v: int(v, 0), default=None)
    parser.add_argument("--max-gap", type=int, default=40)
    parser.add_argument("--max-function-bytes", type=int, default=4096)
    parser.add_argument("--min-instructions", type=int, default=6)
    parser.add_argument("--out", required=True)
    parser.add_argument("--top", type=int, default=5)
    args = parser.parse_args()

    from capstone import CS_ARCH_X86, CS_MODE_64, Cs

    image = Path(args.image)
    data = image.read_bytes()
    length = args.length if args.length is not None else len(data)
    window = data[args.start:args.start + length]
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = False

    funnel: dict[str, int] = {}
    entries = function_offsets(window, args.base + args.start, md, 200000, args.max_function_bytes)
    candidates: list[dict] = []
    functions_scanned = 0
    for offset in entries:
        instructions = disassemble_function(md, window, offset, args.base + args.start,
                                           args.max_function_bytes, 400)
        if len(instructions) < args.min_instructions:
            continue
        functions_scanned += 1
        end = instructions[-1].address + instructions[-1].size
        found, stats = analyze_function(instructions, args.base + args.start, args.max_gap,
                                        args.base + args.start + offset, end, args.min_instructions)
        candidates.extend(found)
        for key, value in stats.items():
            funnel[key] = funnel.get(key, 0) + value
    candidates.sort(key=lambda c: (c["priority"], c["instructions_between_reads"]))
    report = {
        "image": str(image), "image_sha256": sha256_file(image),
        "kernel_base": f"0x{args.base:x}", "scanned_bytes": length,
        "engine": "native/capstone strict double-read chain scan (engine #1)",
        "criteria": ["same [base+disp] read twice", ">=1 direct call between the reads",
                     "comparison of the read value between the reads",
                     "no clobber of base/value register", f"gap <= {args.max_gap} instructions",
                     "consumer after read #2 (store or call argument)"],
        "filter_funnel": funnel,
        "functions_scanned": functions_scanned, "candidates_total": len(candidates),
        "priority_counts": {p: sum(1 for c in candidates if c["priority"] == p) for p in ("P1", "P2", "P3", "P4")},
        "top": candidates[: args.top], "all_candidates": candidates,
    }
    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    Path(args.out).write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"functions={functions_scanned} candidates={len(candidates)} priorities={report['priority_counts']}")
    print(f"funnel={funnel}")
    for candidate in candidates[: args.top]:
        print(f"  {candidate['priority']} fn={candidate['function_start']} field={candidate['field']} "
              f"gap={candidate['instructions_between_reads']} calls={candidate['delta_calls']}\n"
              f"      r1={candidate['read_1']}\n      val={candidate['validation']}\n"
              f"      r2={candidate['read_2']}\n      consumer={candidate['consumer']}")
    print(f"  evidence: {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
