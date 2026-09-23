#!/usr/bin/env python3
"""M2-LIVE2.3 — real reachability closure for RC-001 in the FW13.52 kernel image.

Answers, with addresses and instructions only:

* who calls RC-001 (direct callsites), recursively upward (bounded depth)
* where r15 comes from in each caller (callee-saved register: it is set somewhere up the chain)
* which instruction actually writes ``[r?+0xf8]`` anywhere in the image (field mutability)
* which callee the consumer call at the end of RC-001 targets, and whether that callee dereferences
  the pointer it receives (security sensitivity C1/C2/C3)

Every claim in the output is an instruction address that a second engine can re-check. No symbol
guessing, no "looks like a pointer" reasoning.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

import live22_discovery as discovery

RC001 = 0xFFFFFFFFD05AC8F0
RC001_END = 0xFFFFFFFFD05AC9BE
READ1 = 0xFFFFFFFFD05AC963
VALIDATION = 0xFFFFFFFFD05AC96A
READ2 = 0xFFFFFFFFD05AC974
CONSUMER = 0xFFFFFFFFD05AC98B
FIELD_DISP = 0xF8
MAX_DEPTH = 4
MAX_CALLERS_PER_NODE = 12


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def analyse(instructions, base: int) -> dict:
    """Calls, r15 writes, and every access with displacement 0xf8 in one function body."""

    calls, r15_writes, field_ops, derefs = [], [], [], []
    for insn in instructions:
        mnemonic, ops = insn.mnemonic, insn.op_str
        if mnemonic == "call" and ops.startswith("0x"):
            calls.append({"address": f"0x{insn.address:x}", "target": ops})
        if ops.startswith(("r15,", "r15 ")) or ", r15" in ops:
            r15_writes.append({"address": f"0x{insn.address:x}", "instruction": f"{mnemonic} {ops}",
                               "writes_r15": ops.split(",", 1)[0].strip() in ("r15", "r15d", "r15w")})
        if "," in ops:
            dst, src = (part.strip() for part in ops.split(",", 1))
            for operand, kind in ((dst, "write"), (src, "read")):
                mem = discovery.mem_operand(operand)
                if mem and mem[1] == FIELD_DISP:
                    field_ops.append({"address": f"0x{insn.address:x}", "kind": kind,
                                      "instruction": f"{mnemonic} {ops}", "base": mem[0]})
            mem_src = discovery.mem_operand(src)
            if mem_src and mem_src[0] == "rdi":
                derefs.append({"address": f"0x{insn.address:x}", "instruction": f"{mnemonic} {ops}",
                               "base": "rdi"})
    return {"calls": calls, "r15": r15_writes, "field_ops": field_ops, "rdi_derefs": derefs}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--image", required=True)
    parser.add_argument("--base", required=True, type=lambda v: int(v, 0))
    parser.add_argument("--start", type=lambda v: int(v, 0), default=0x1000)
    parser.add_argument("--length", type=lambda v: int(v, 0), default=None)
    parser.add_argument("--out", required=True)
    parser.add_argument("--depth", type=int, default=MAX_DEPTH)
    args = parser.parse_args()

    from capstone import CS_ARCH_X86, CS_MODE_64, Cs

    image = Path(args.image)
    data = image.read_bytes()
    length = args.length if args.length is not None else len(data)
    window = data[args.start:args.start + length]
    base = args.base + args.start
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = False

    # full linear sweep: every direct call site is indexed, independent of function-body truncation
    def sweep_calls() -> list[tuple[int, int]]:
        sites: list[tuple[int, int]] = []
        pos = 0
        while pos < len(window):
            insn = next(md.disasm(window[pos:pos + 16], base + pos), None)
            if insn is None:
                pos += 1
                continue
            if insn.mnemonic == "call" and insn.op_str.startswith("0x"):
                sites.append((base + pos, int(insn.op_str, 16)))
            pos += insn.size
        return sites

    all_call_sites = sweep_calls()
    # window offsets (for disassembly) and absolute targets (for the call graph) are different domains
    entries = sorted({target - base for _site, target in all_call_sites
                      if base <= target < base + length})
    bodies: dict[int, list] = {}
    for offset in entries:
        instructions = discovery.disassemble_function(md, window, offset, base, 4096, 400)
        if len(instructions) >= 4:
            bodies[base + offset] = instructions

    # index: callsite -> target, and per-function facts
    call_sites: dict[int, list[int]] = {}     # target -> [callsite addresses]
    for site, target in all_call_sites:
        call_sites.setdefault(target, []).append(site)

    sorted_entries = sorted(bodies)

    def owner_of(address: int) -> int | None:
        import bisect
        index = bisect.bisect_right(sorted_entries, address) - 1
        if index < 0:
            return None
        entry = sorted_entries[index]
        return entry if address < entry + 4096 else None

    facts: dict[int, dict] = {}
    field_writers: list[dict] = []
    for entry, instructions in bodies.items():
        info = analyse(instructions, base)
        facts[entry] = info
        for op in info["field_ops"]:
            if op["kind"] == "write":
                field_writers.append({"function": f"0x{entry:x}", **op})

    # upward closure from RC-001
    chain: list[dict] = []
    level = {RC001}
    seen = {RC001}
    for depth in range(1, args.depth + 1):
        nxt: set[int] = set()
        for target in sorted(level):
            for site in call_sites.get(target, [])[:MAX_CALLERS_PER_NODE]:
                owner = owner_of(site)
                chain.append({"level": depth, "callee": f"0x{target:x}", "callsite": f"0x{site:x}",
                              "caller": f"0x{owner:x}" if owner else "unknown",
                              "caller_r15_writes": (facts.get(owner, {}).get("r15", []) if owner else [])[:4]})
                if owner and owner not in seen:
                    seen.add(owner)
                    nxt.add(owner)
        level = nxt
        if not level:
            break

    consumer_target = None
    consumer_body: dict = {}
    rc_body = analyse(bodies.get(RC001, []), base)
    for call in rc_body["calls"]:
        if int(call["address"], 16) == CONSUMER:
            consumer_target = int(call["target"], 16)
    if consumer_target is not None:
        consumer_instructions = bodies.get(consumer_target, [])
        consumer_body = {
            "entry": f"0x{consumer_target:x}",
            "instructions_head": [f"0x{i.address:x} {i.mnemonic} {i.op_str}" for i in consumer_instructions[:12]],
            **analyse(consumer_instructions, base),
        }

    report = {
        "image": str(image), "image_sha256": sha256_file(image), "kernel_base": f"0x{args.base:x}",
        "rc001": {"function": f"0x{RC001:x}-0x{RC001_END:x}", "read_1": f"0x{READ1:x}",
                  "validation": f"0x{VALIDATION:x}", "read_2": f"0x{READ2:x}",
                  "consumer_call": f"0x{CONSUMER:x}",
                  "rc001_r15_writes": rc_body["r15"],
                  "instructions": [f"0x{i.address:x} {i.mnemonic} {i.op_str}" for i in bodies.get(RC001, [])[:24]],
                  "field_ops_0xf8": rc_body["field_ops"]},
        "functions_indexed": len(bodies),
        "direct_call_sites_indexed": len(all_call_sites),
        "callers_of_rc001": [f"0x{s:x}" for s in call_sites.get(RC001, [])],
        "callers": chain,
        "caller_depth_reached": max([c["level"] for c in chain], default=0),
        "field_writers_0xf8_total": len(field_writers),
        "field_writers_0xf8_sample": field_writers[:20],
        "consumer": consumer_body,
        "unknowns": [
            "indirect calls (call r?/call [r?]) are not followed: caller closure is direct-call only",
            "register-renamed aliases of r15 inside callers are not propagated automatically",
            "no symbols: object types/owners are inferred from instructions, not from a symbol table",
        ],
    }
    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    Path(args.out).write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"functions indexed: {len(bodies)}  callers found: {len(chain)} (depth {report['caller_depth_reached']})")
    for entry in chain[:12]:
        print(f"  L{entry['level']} caller={entry['caller']} callsite={entry['callsite']} -> {entry['callee']}"
              f"  r15_writes={len(entry['caller_r15_writes'])}")
    print(f"  consumer: {consumer_body.get('entry')} derefs_rdi={len(consumer_body.get('rdi_derefs', []))}")
    for line in consumer_body.get("instructions_head", [])[:8]:
        print("    ", line)
    print(f"  field writers to +0xf8 in image: {len(field_writers)}")
    print(f"  evidence: {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
