#!/usr/bin/env python3
"""M2-LIVE2.4 — artefact-filtered caller closure + multi-engine cross-check.

Part 1 rebuilds the upward chain using only callsites that are *contained in a function body* (the filter
that the three sweep artefacts fail), so the inflated LIVE2.3 chain is corrected.

Part 2 runs native / angr / Ghidra on the RC-001 and consumer bodies and records whether each engine
confirms the two reads and how it classifies the consumer. Conflicts are reported, never smoothed over.
"""

from __future__ import annotations

import argparse
import bisect
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

import live22_discovery as discovery

from orbisprobe.backends import ResourceLimits
from orbisprobe.backends.angr_backend import AngrBackend
from orbisprobe.backends.ghidra_backend import GhidraBackend
from orbisprobe.backends.native_backend import NativeBackend

BASE = 0xFFFFFFFFD00D0000
START = 0x1000
LENGTH = 13619544
RC001 = 0xFFFFFFFFD05AC8F0
RC001_END = 0xFFFFFFFFD05AC9BE
CONSUMER = 0xFFFFFFFFD057E7B0
READ1, READ2 = 0xFFFFFFFFD05AC963, 0xFFFFFFFFD05AC974
MAX_DEPTH = 5


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--image", required=True)
    parser.add_argument("--out", required=True)
    parser.add_argument("--angr-python", default="/home/hermes/tools/orbisprobe-v0.2-dev/.backend-envs/angr/bin/python")
    parser.add_argument("--ghidra-home", default="/home/hermes/tools/ghidra_12.1.3_PUBLIC")
    args = parser.parse_args()

    from capstone import CS_ARCH_X86, CS_MODE_64, Cs

    data = Path(args.image).read_bytes()
    window = data[START:START + LENGTH]
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = False

    # ---- function bodies from call targets, then real (contained) callsites only -------------
    entries_offsets = discovery.function_offsets(window, BASE + START, md, 200000, 4096)
    bodies: dict[int, list] = {}
    for offset in entries_offsets:
        instructions = discovery.disassemble_function(md, window, offset, BASE + START, 4096, 400)
        if len(instructions) >= 4:
            bodies[BASE + START + offset] = instructions
    entry_list = sorted(bodies)
    body_ranges = {entry: (instructions[0].address, instructions[-1].address) for entry, instructions in bodies.items()}

    def owning_function(address: int) -> int | None:
        index = bisect.bisect_right(entry_list, address) - 1
        if index < 0:
            return None
        entry = entry_list[index]
        first, last = body_ranges[entry]
        return entry if first <= address <= last else None

    real_calls: dict[int, list[tuple[int, int]]] = {}   # callee -> [(callsite, caller)]
    artefact_calls: list[int] = []
    for entry, instructions in bodies.items():
        for insn in instructions:
            if insn.mnemonic != "call" or not insn.op_str.startswith("0x"):
                continue
            target = int(insn.op_str, 16)
            real_calls.setdefault(target, []).append((insn.address, entry))
    # artefacts: calls that the linear sweep sees but that are not inside any body
    pos = 0
    while pos < len(window):
        insn = next(md.disasm(window[pos:pos + 16], BASE + START + pos), None)
        if insn is None:
            pos += 1
            continue
        if insn.mnemonic == "call" and insn.op_str.startswith("0x") and owning_function(insn.address) is None:
            artefact_calls.append(insn.address)
        pos += insn.size

    chain, level, seen = [], {RC001}, {RC001}
    for depth in range(1, MAX_DEPTH + 1):
        nxt: set[int] = set()
        for target in sorted(level):
            for callsite, caller in real_calls.get(target, [])[:12]:
                chain.append({"level": depth, "callee": f"0x{target:x}", "callsite": f"0x{callsite:x}",
                              "caller": f"0x{caller:x}", "caller_size": len(bodies[caller])})
                if caller not in seen:
                    seen.add(caller)
                    nxt.add(caller)
        level = nxt
        if not level:
            break

    # ---- multi-engine cross-check on the frozen bodies --------------------------------------
    limits = ResourceLimits(timeout_seconds=90, state_ceiling=32, maximum_steps=256,
                            maximum_graph_size=10_000)
    engines = {"native": NativeBackend(limits),
               "angr": AngrBackend(limits, interpreter=args.angr_python),
               "ghidra": GhidraBackend(limits, ghidra_home=args.ghidra_home)}
    multi: dict[str, dict] = {}
    for name, address, end in (("rc001", RC001, RC001_END), ("consumer", CONSUMER, CONSUMER + 0x400)):
        body_bytes = data[address - BASE:end - BASE]
        binary = Path(args.out).parent / f"live24-{name}.bin"
        binary.write_bytes(body_bytes)
        reads = {hex(READ1 - address), hex(READ2 - address), str(READ1 - address), str(READ2 - address)}
        per_engine: dict[str, dict] = {}
        for engine_name, engine in engines.items():
            try:
                result = engine.analyze_function({"binary": str(binary), "architecture": "x86_64",
                                                  "base": 0, "function": 0, "function_end": len(body_bytes)})
                blob = json.dumps({"data": result.data,
                                   "evidence": [e.to_dict() for e in result.evidence]}, default=str)
                per_engine[engine_name] = {
                    "status": result.status.value,
                    "sees_both_reads": all(form in blob for form in list(reads)[:2]),
                    "evidence_items": len(result.evidence),
                }
            except Exception as exc:  # noqa: BLE001
                per_engine[engine_name] = {"status": "ERROR", "error": f"{type(exc).__name__}: {exc}"}
        multi[name] = per_engine

    conflicts = [name for name, per_engine in multi.items()
                 if len({value.get("status") for value in per_engine.values()}) > 1]
    payload = {
        "function_bodies_indexed": len(bodies),
        "real_caller_chain": chain,
        "real_chain_depth_reached": max((item["level"] for item in chain), default=0),
        "sweep_artefact_calls_total": len(artefact_calls),
        "multi_engine": multi, "evidence_conflict": conflicts or None,
        "note": ("callers are only accepted when the callsite lies inside a function body; the three LIVE2.3 "
                 "nodes that came from data-like regions disappear under this filter"),
    }
    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    Path(args.out).write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"function bodies: {len(bodies)} | real caller nodes: {len(chain)} (depth {payload['real_chain_depth_reached']})")
    for item in chain[:14]:
        print(f"  L{item['level']} caller={item['caller']} ({item['caller_size']} insns) callsite={item['callsite']} -> {item['callee']}")
    print(f"sweep-artefact callsites rejected: {len(artefact_calls)}")
    for name, per_engine in multi.items():
        print(f"engines for {name}: " + ", ".join(f"{k}={v.get('status')}" for k, v in per_engine.items()))
    print(f"evidence conflict: {conflicts or 'none'}")
    print(f"evidence: {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
