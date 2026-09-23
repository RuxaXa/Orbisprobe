#!/usr/bin/env python3
"""M2-LIVE2.4 — object / writer / consumer / dispatch closure for RC-001 (offline only).

Answers five questions with instruction-level evidence:

1. object model for ``r15`` (fields 0x78/0x88/0xf0/0xf8: read sites, write sites, width, pointer-ness)
2. which ``[r?+0xf8]`` writers actually belong to the same object family (neighbouring-offset correlation
   instead of "all stores in the kernel")
3. what the consumer ``0xffffffffd057e7b0`` really does with the pointer it receives (followed through its
   own body and one level of callees)
4. how RC-001/dispatch could be reached indirectly: every indirect call in the L1 callers, the load that
   feeds the target register, and a direct search for RC-001's address as a pointer in the image data
5. the three suspected sweep artefacts: executable-region / instruction-boundary / function-containment
   checks that decide whether they are real callsites

No PS4 contact, no writes, no requests.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

import live22_discovery as discovery

BASE = 0xFFFFFFFFD00D0000
START = 0x1000
LENGTH = 13619544
RC001 = 0xFFFFFFFFD05AC8F0
CALLERS = (0xFFFFFFFFD05A7E20, 0xFFFFFFFFD05A8C32)
CALLSITES = (0xFFFFFFFFD05A8013, 0xFFFFFFFFD05A91D7)
CONSUMER = 0xFFFFFFFFD057E7B0
FIELDS = (0x78, 0x88, 0xF0, 0xF8)
ARTEFACTS = (0xFFFFFFFFD0D6C4C8, 0xFFFFFFFFD0D70540, 0xFFFFFFFFD0D507F0)
CMP_MNEMONICS = {"cmp", "test"}


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--image", required=True)
    parser.add_argument("--out", required=True)
    args = parser.parse_args()

    from capstone import CS_ARCH_X86, CS_MODE_64, Cs

    image = Path(args.image)
    data = image.read_bytes()
    window = data[START:START + LENGTH]
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = False

    def body(address: int, limit: int = 800) -> list:
        return discovery.disassemble_function(md, window, address - BASE - START, BASE + START, 16384, limit)

    def instruction_facts(instructions) -> dict:
        """Per-field accesses, indirect branches, and the register flow we care about."""

        facts = {"fields": {f"0x{f:x}": {"reads": [], "writes": []} for f in FIELDS},
                 "indirect": [], "direct_calls": [], "pointer_tests": [], "spin": [],
                 "reg_copies": [], "memory_writes": []}
        for insn in instructions:
            ops = insn.op_str
            mnemonic = insn.mnemonic
            parts = [p.strip() for p in ops.split(",", 1)] if "," in ops else [ops.strip()]
            if mnemonic == "call":
                if ops.startswith("0x"):
                    facts["direct_calls"].append(f"0x{insn.address:x} call {ops}")
                else:
                    facts["indirect"].append(f"0x{insn.address:x} call {ops}")
            if mnemonic in ("jmp", "jmpq") and not ops.startswith("0x"):
                facts["indirect"].append(f"0x{insn.address:x} jmp {ops}")
            if len(parts) == 2:
                dst, src = parts
                mem = discovery.mem_operand(src)
                if mem and mem[1] in FIELDS:
                    facts["fields"][f"0x{mem[1]:x}"]["reads"].append(
                        {"address": f"0x{insn.address:x}", "instruction": f"{mnemonic} {ops}",
                         "base_register": mem[0]})
                mem_dst = discovery.mem_operand(dst)
                if mem_dst and mem_dst[1] in FIELDS:
                    facts["fields"][f"0x{mem_dst[1]:x}"]["writes"].append(
                        {"address": f"0x{insn.address:x}", "instruction": f"{mnemonic} {ops}",
                         "base_register": mem_dst[0]})
                if mem_dst and not dst.startswith("["):
                    facts["memory_writes"].append(f"0x{insn.address:x} {mnemonic} {ops}")
                if src in ("rdi", "edi") and not dst.startswith("[") and dst not in ("rdi", "edi"):
                    facts["reg_copies"].append(f"0x{insn.address:x} {mnemonic} {ops}")
            if mnemonic in CMP_MNEMONICS and "rbx" in ops:
                facts["pointer_tests"].append(f"0x{insn.address:x} {mnemonic} {ops}")
        return facts

    rc001_body = body(RC001)
    rc001_facts = instruction_facts(rc001_body)

    # ---------------- 1./14. object model + the field_78 write and the poll that follows
    object_model = {
        "object_register": "r15",
        "provenance": "0xffffffffd05ac90e mov r15, rdi  (arg1; RC-001 takes the object as its first argument)",
        "fields": {
            "field_78": {"reads": rc001_facts["fields"]["0x78"]["reads"],
                         "writes": rc001_facts["fields"]["0x78"]["writes"],
                         "width_bytes": 8, "pointer_like": True,
                         "use": "value moved to rbx and then written/read through: `mov [rbx],0` followed by a "
                                "bounded poll of `[rbx]` — consistent with a lock/completion word "
                                "(SUPPORTED, not confirmed)"},
            "field_88": {"reads": rc001_facts["fields"]["0x88"]["reads"],
                         "writes": rc001_facts["fields"]["0x88"]["writes"],
                         "width_bytes": 8, "pointer_like": True,
                         "use": "loaded into r14 and passed as the 2nd argument (rsi) to the consumer call"},
            "field_f0": {"reads": rc001_facts["fields"]["0xf0"]["reads"],
                         "writes": rc001_facts["fields"]["0xf0"]["writes"],
                         "width_bytes": 8, "pointer_like": True,
                         "use": "loaded into rdi and passed as the 1st argument to the consumer call at 0xffffffffd05ac938"},
            "field_f8": {"reads": rc001_facts["fields"]["0xf8"]["reads"],
                         "writes": rc001_facts["fields"]["0xf8"]["writes"],
                         "width_bytes": 8, "pointer_like": True,
                         "use": "read twice (0xffffffffd05ac963 NULL-checked, 0xffffffffd05ac974) and handed "
                                "to the consumer as rdi at 0xffffffffd05ac98b"},
        },
        "write_through_pointer": [w for w in rc001_facts["memory_writes"]],
        "poll_sequence": [f"0x{i.address:x} {i.mnemonic} {i.op_str}" for i in rc001_body
                          if 0xFFFFFFFFD05AC93D <= i.address <= 0xFFFFFFFFD05AC9A0][:14],
    }

    # ---------------- 4. indirect calls in the L1 callers + RC-001 address as a data pointer
    caller_facts = {}
    for caller in CALLERS:
        instructions = body(caller)
        caller_facts[f"0x{caller:x}"] = instruction_facts(instructions)
    rc001_pointer = struct.pack("<Q", RC001)
    pointer_hits = []
    search_from = 0
    while True:
        index = data.find(rc001_pointer, search_from)
        if index < 0:
            break
        pointer_hits.append(f"0x{BASE + index:x}")
        search_from = index + 1
    caller_pointer_hits = []
    for caller in CALLERS:
        pattern = struct.pack("<Q", caller)
        start_from = 0
        while True:
            index = data.find(pattern, start_from)
            if index < 0:
                break
            caller_pointer_hits.append({"caller": f"0x{caller:x}", "table_slot": f"0x{BASE + index:x}"})
            start_from = index + 1

    # ---------------- 5. false-xref filter for the three suspected artefacts
    all_call_sites = []
    pos = 0
    while pos < len(window):
        insn = next(md.disasm(window[pos:pos + 16], BASE + START + pos), None)
        if insn is None:
            pos += 1
            continue
        if insn.mnemonic == "call" and insn.op_str.startswith("0x"):
            all_call_sites.append(BASE + START + pos)
        pos += insn.size
    entry_set = sorted({target for _s, target in
                        ((s, int(next(md.disasm(window[s - BASE - START:s - BASE - START + 16], s)).op_str, 16))
                         for s in all_call_sites)})
    artefact_report = {}
    for artefact in ARTEFACTS:
        offset = artefact - BASE - START
        in_image = 0 <= offset < len(window)
        segment_exec = 0 <= (artefact - BASE) < 0xCFE758          # executable segment (ELF seg2)
        contained = False
        for entry in entry_set:
            if entry <= artefact < entry + 16384:
                candidate_body = body(entry, limit=120)
                if candidate_body and candidate_body[0].address <= artefact <= candidate_body[-1].address:
                    contained = True
                break
        artefact_report[f"0x{artefact:x}"] = {
            "inside_image": in_image, "inside_exec_segment": segment_exec,
            "inside_a_function_body_from_the_call_target_map": contained,
            "verdict": "REAL_CALLSITE" if (in_image and segment_exec and contained) else "SWEEP_ARTEFACT",
        }

    # ---------------- 3./10. consumer closure: follow rdi through the consumer and one callee level
    consumer_body = body(CONSUMER, limit=1200)
    consumer_facts = instruction_facts(consumer_body)
    handle_regs = {"rdi"}
    forwarded, deref, stored = [], [], []
    for insn in consumer_body:
        ops = insn.op_str
        parts = [p.strip() for p in ops.split(",", 1)] if "," in ops else [ops.strip()]
        if len(parts) == 2:
            dst, src = parts
            if src in handle_regs and not dst.startswith("["):
                handle_regs.add(dst)
                if dst not in ("rdi", "edi"):
                    stored.append(f"0x{insn.address:x} {insn.mnemonic} {ops}  (pointer copied, not a store)")
            mem = discovery.mem_operand(src)
            if mem and mem[0] in handle_regs:
                deref.append(f"0x{insn.address:x} {insn.mnemonic} {ops}  (read via {mem[0]})")
            mem_dst = discovery.mem_operand(dst)
            if mem_dst and src in handle_regs:
                stored.append(f"0x{insn.address:x} {insn.mnemonic} {ops}  (pointer stored to memory)")
            if insn.mnemonic == "call" and parts[0] in handle_regs:
                forwarded.append(f"0x{insn.address:x} call {ops}  (argument {parts[0]} = handle)")
    callee_detail = {}
    for entry in forwarded[:3]:
        target = entry.split("call", 1)[1].strip().split()[0]
        if target.startswith("0x"):
            try:
                callee = body(int(target, 16), limit=600)
            except Exception as exc:  # noqa: BLE001 - an unresolvable callee is recorded, not hidden
                callee_detail[target] = {"error": f"{type(exc).__name__}: {exc}"}
                continue
            callee_facts = instruction_facts(callee)
            callee_detail[target] = {
                "instructions": len(callee),
                "rdi_derefs": [line for line in callee_facts["memory_writes"]][:4],
                "direct_calls": callee_facts["direct_calls"][:6],
                "indirect": callee_facts["indirect"][:4],
            }
    consumer_semantics = {
        "entry": f"0x{CONSUMER:x}", "instructions_analysed": len(consumer_body),
        "direct_calls": consumer_facts["direct_calls"][:12], "indirect_calls": consumer_facts["indirect"][:6],
        "pointer_copies": stored[:8], "pointer_reads": deref[:8], "pointer_forwarded": forwarded[:6],
        "callees_checked": callee_detail,
        "security_class": "C4" if not deref else ("C2" if not forwarded else "C3"),
    }

    # ---------------- 2. field_f8 writers correlated by object family (neighbouring offsets)
    field_f8_writers = []
    neighbour_offsets = {f"0x{f:x}" for f in FIELDS if f != 0xF8}
    entries = discovery.function_offsets(window, BASE + START, md, 200000, 4096)
    for offset in entries:
        instructions = discovery.disassemble_function(md, window, offset, BASE + START, 4096, 400)
        if len(instructions) < 6:
            continue
        touches = set()
        writes_f8 = []
        for insn in instructions:
            ops = insn.op_str
            if "," not in ops:
                continue
            dst, src = (p.strip() for p in ops.split(",", 1))
            for operand, kind in ((dst, "w"), (src, "r")):
                mem = discovery.mem_operand(operand)
                if mem is None:
                    continue
                key = f"0x{mem[1]:x}"
                if mem[1] == 0xF8 and kind == "w":
                    writes_f8.append(f"0x{insn.address:x} {insn.mnemonic} {ops}")
                touches.add(key)
        if writes_f8:
            family = len(touches & neighbour_offsets)
            field_f8_writers.append({
                "function": f"0x{BASE + START + offset:x}",
                "writes": writes_f8[:3],
                "neighbour_offsets_seen": sorted(touches & neighbour_offsets),
                "family_correlation": family,
                "status": "SUPPORTED" if family >= 2 else ("UNKNOWN" if family == 1 else "UNRELATED"),
            })
    field_f8_writers.sort(key=lambda item: -item["family_correlation"])

    report = {
        "image": str(image), "image_sha256": sha256_file(image),
        "rc001": {"address": f"0x{RC001:x}", "instructions": len(rc001_body),
                  "body": [f"0x{i.address:x} {i.mnemonic} {i.op_str}" for i in rc001_body],
                  "direct_calls": rc001_facts["direct_calls"], "indirect_calls": rc001_facts["indirect"],
                  "pointer_tests": rc001_facts["pointer_tests"]},
        "object_model": object_model,
        "caller_facts": caller_facts,
        "dispatching": {"rc001_address_as_pointer_in_data": pointer_hits,
                        "caller_addresses_as_pointer_in_data": caller_pointer_hits},
        "artefact_filter": artefact_report,
        "consumer_semantics": consumer_semantics,
        "field_f8_writers": field_f8_writers[:25],
        "field_f8_writer_counts": {status: sum(1 for w in field_f8_writers if w["status"] == status)
                                   for status in ("SUPPORTED", "UNKNOWN", "UNRELATED")},
        "unknowns": [
            "no symbols: object type, allocator and vtable membership cannot be named from the image alone",
            ("indirect call targets are documented with their load source, but a possible-value set needs "
            "symbolic execution (angr) on the caller, which is reported separately"),
            "writer correlation uses neighbouring-offset families, not a type system",
        ],
    }
    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    Path(args.out).write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    print(f"== RC-001 ({len(rc001_body)} instructions) indirect calls: {len(rc001_facts['indirect'])}")
    print(f"== object model fields: {sorted(object_model['fields'])}")
    print(f"== field_78 write: {object_model['fields']['field_78']['use'][:90]}")
    print(f"== RC-001 address as data pointer: {pointer_hits or 'not found'}")
    print(f"== caller addresses as data pointers: {len(caller_pointer_hits)} hits")
    for artefact, info in artefact_report.items():
        print(f"== artefact {artefact}: {info['verdict']} (exec={info['inside_exec_segment']}, "
              f"contained={info['inside_a_function_body_from_the_call_target_map']})")
    print(f"== consumer: {consumer_semantics['instructions_analysed']} insns, "
          f"calls={len(consumer_semantics['direct_calls'])}, pointer_reads={len(consumer_semantics['pointer_reads'])}, "
          f"forwarded={len(consumer_semantics['pointer_forwarded'])}, class={consumer_semantics['security_class']}")
    for line in consumer_semantics["pointer_reads"][:4]:
        print("    ", line)
    print(f"== field_f8 writers: {report['field_f8_writer_counts']}")
    for writer in field_f8_writers[:6]:
        print(f"    {writer['status']:9} fn={writer['function']} family={writer['family_correlation']} "
              f"neighbours={writer['neighbour_offsets_seen']} {writer['writes'][0] if writer['writes'] else ''}")
    print(f"evidence: {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
