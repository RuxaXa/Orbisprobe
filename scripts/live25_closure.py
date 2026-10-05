#!/usr/bin/env python3
"""M2-LIVE2.5 — turn the whole-image Ghidra export into recovered boundaries, consumer semantics, the
upward chain and the R25 classification.

Input is the JSON written by Live25Closure.java, plus the linear-sweep function map for the delta.
Everything printed is either a recovered address/count from Ghidra or a measured comparison.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "scripts"))

import live22_discovery as discovery

from orbisprobe.live.wholeimage import (
    R25Evidence,
    classify,
    consumer_semantics,
    sweep_delta,
)

BASE = 0xFFFFFFFFD00D0000
START = 0x1000
LENGTH = 13619544
RC001 = 0xFFFFFFFFD05AC8F0
CALLERS = (0xFFFFFFFFD05A7E20, 0xFFFFFFFFD05A8C32)
CONSUMER = 0xFFFFFFFFD057E7B0
ARTEFACTS = (0xFFFFFFFFD0D6C4C8, 0xFFFFFFFFD0D70540, 0xFFFFFFFFD0D507F0)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--ghidra", required=True)
    parser.add_argument("--image", required=True)
    parser.add_argument("--out", required=True)
    args = parser.parse_args()

    from capstone import CS_ARCH_X86, CS_MODE_64, Cs

    ghidra = json.loads(Path(args.ghidra).read_text())
    functions = ghidra["functions"]
    image = Path(args.image).read_bytes()
    window = image[START:START + LENGTH]
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = False

    # ---- recovered boundaries vs the linear sweep ------------------------------------------
    cfg_boundaries = {entry: (info.get("entry", ""), info.get("end", ""))
                      for entry, info in functions.items() if isinstance(info, dict) and info.get("recovered")}
    sweep_offsets = discovery.function_offsets(window, BASE + START, md, 200000, 4096)
    sweep_functions = {f"{BASE + START + offset:x}" for offset in sweep_offsets}
    delta = sweep_delta(cfg_boundaries, sweep_functions)
    analysed_entries = {info.get("entry", "") for info in functions.values()
                        if isinstance(info, dict) and info.get("recovered")}
    like_for_like = {
        "analysed": len(analysed_entries),
        "also_in_linear_sweep": len([e for e in analysed_entries if e in sweep_functions]),
        "missed_by_linear_sweep": sorted(e for e in analysed_entries if e not in sweep_functions),
    }

    # ---- consumer semantics from decompiled C ----------------------------------------------
    consumer_entry = None
    for entry, info in functions.items():
        if isinstance(info, dict) and info.get("entry", "").lower().endswith(f"{CONSUMER & 0xFFFFFFFF:x}"):
            consumer_entry = entry
    consumer_info = functions.get(consumer_entry, {}) if consumer_entry else {}
    consumer_c = consumer_info.get("decompiled_c", "")
    consumer_class, consumer_reasons = consumer_semantics(consumer_c, "rdi")
    if consumer_class == "C4" and consumer_c:
        for variable in ("param_1", "handle", "p", "obj", "arg1"):
            candidate_class, candidate_reasons = consumer_semantics(consumer_c, variable)
            if candidate_class != "C4":
                consumer_class, consumer_reasons = candidate_class, [f"variable '{variable}': {r}"
                                                                     for r in candidate_reasons]
                break

    # ---- upward chain / root ---------------------------------------------------------------
    edges = ghidra.get("edges", [])
    by_from: dict[str, list[dict]] = {}
    for edge in edges:
        by_from.setdefault(edge["from"], []).append(edge)
    # upward chain: use the recovered incoming-call references (`callers`) of each analysed function
    callers_of = {entry: info.get("callers", []) for entry, info in functions.items()
                  if isinstance(info, dict) and info.get("recovered")}
    entry_of = {entry: info.get("entry", "") for entry, info in functions.items()
                if isinstance(info, dict) and info.get("recovered")}
    by_entry = {info["entry"]: key for key, info in functions.items()
                if isinstance(info, dict) and info.get("recovered")}
    chain, frontier, seen = [], [None], set()
    frontier = [key for key, info in functions.items()
                if isinstance(info, dict) and info.get("entry", "").lower() == f"0x{RC001:x}"]
    for key in frontier:
        seen.add(key)
    for depth in range(1, 8):
        nxt: list[str] = []
        for key in frontier:
            for caller_ref in callers_of.get(key, []):
                caller_entry = caller_ref.split(" @ ")[0]
                chain.append({"level": depth, "caller": caller_entry, "callsite": caller_ref.split(" @ ")[-1],
                              "callee": entry_of.get(key, "")})
                caller_key = by_entry.get(caller_entry)
                if caller_key and caller_key not in seen:
                    seen.add(caller_key)
                    nxt.append(caller_key)
        frontier = nxt
        if not frontier:
            break
    # root classification: a node with no callers is either a real root or an unresolved dispatch site
    root_nodes = [entry for key, info in functions.items()
                  if isinstance(info, dict) and info.get("recovered") and not info.get("callers")
                  for entry in [info.get("entry", "")]]
    roots_with_indirect = [entry for key, info in functions.items()
                           if isinstance(info, dict) and info.get("recovered") and not info.get("callers")
                           and info.get("indirect_calls")]
    root_class = ("UNRESOLVED_INDIRECT_DISPATCH" if roots_with_indirect else
                  ("KERNEL_INTERNAL" if root_nodes else "UNKNOWN"))

    # ---- object fields and the L1 indirect callsites ---------------------------------------
    object_fields: dict[str, dict] = {}
    for entry, info in functions.items():
        if not isinstance(info, dict) or not info.get("recovered"):
            continue
        for access in info.get("object_field_accesses", []):
            offset = access.split(" ")[0]
            object_fields.setdefault(offset, {"sites": [], "functions": []})
            object_fields[offset]["sites"].append({"function": info["entry"], "site": access})
            object_fields[offset]["functions"].append(info["entry"])
    indirect = {}
    for address in (f"0x{CALLERS[0]:x}", f"0x{CALLERS[1]:x}"):
        for entry, info in functions.items():
            if isinstance(info, dict) and info.get("entry") == address:
                indirect[address] = info.get("indirect_calls", [])
    artefacts_now = {f"0x{a:x}": ("in recovered function"
                                 if any(a >= int(v[0], 16) and a <= int(v[1], 16)
                                        for v in cfg_boundaries.values() if v[0] and v[1]) else "SWEEP_ARTEFACT (still)")
                     for a in ARTEFACTS}
    field_f8_writers = []
    for entry, info in functions.items():
        if not isinstance(info, dict) or not info.get("recovered"):
            continue
        for access in info.get("object_field_accesses", []):
            if access.startswith("0xf8"):
                field_f8_writers.append({"function": info["entry"], "access": access})

    rc_info = next((info for info in functions.values()
                    if isinstance(info, dict) and info.get("entry", "").lower() == f"0x{RC001:x}"), {})
    rc_c = rc_info.get("decompiled_c", "")
    strings = sorted({token for token in ("HP3D", "GFX ring", "kernel write", "EOP")
                      if token.lower() in rc_c.lower()})

    evidence = R25Evidence(
        candidate_id="RC-001", cfg_boundaries=cfg_boundaries,
        sweep_functions=sweep_functions if len(sweep_functions) < 5000 else set(),
        root_entry=(root_nodes[0] if root_class == "KERNEL_INTERNAL" and root_nodes else ""),
        root_class=root_class,
        root_edges=[f"L{c['level']} {c['caller']} @ {c['callsite']} -> {c['callee']}" for c in chain[:16]],
        indirect_targets_resolved=all(bool(v) for v in indirect.values()) if indirect else False,
        object_fields=object_fields, constructor_found=False, destructor_found=False,
        field_writer_status={"recovered_writers": len(field_f8_writers)},
        user_influence="UNKNOWN", mutability="UNKNOWN", consumer_class=consumer_class,
        consumer_closed=bool(consumer_c),
        field_78_semantics=("VOLATILE_SYNC_STATE" if ("= 0;" in rc_c and "== 1" in rc_c) else "UNRESOLVED"),
        volatile_path_proven=("= 0;" in rc_c and "== 1" in rc_c and "== 2" in rc_c),
        missing_artifact=("indirect-call / possible-value resolution for the dispatch sites that terminate the "
                          "upward chain (CALL qword ptr [RBX+0x8], JMP RAX, CALL [RAX+0x21850]); user influence on "
                          "the ring context object is not derivable from this artifact"))
    outcome, reason, blockers = classify(evidence)

    report = {
        "ghidra": {"file": ghidra.get("file"), "image_base": ghidra.get("image_base"),
                   "function_count": ghidra.get("function_count"),
                   "analysed_functions": ghidra.get("analysed_functions"),
                   "decompiled_functions": ghidra.get("decompiled_functions")},
        "recovered": {entry: {"entry": info.get("entry"), "end": info.get("end"), "name": info.get("name"),
                              "instructions": info.get("instructions"), "pcode_ops": info.get("pcode_ops"),
                              "basic_blocks": info.get("basic_blocks"), "callers": info.get("callers"),
                              "indirect_calls": info.get("indirect_calls"),
                              "decompiled": info.get("decompiled")}
                      for entry, info in functions.items() if isinstance(info, dict) and info.get("recovered")},
        "sweep_delta": delta.to_dict(), "sweep_delta_like_for_like": like_for_like,
        "rc001_semantics": {"strings_recognised": strings,
                            "field_78_completion": ("VOLATILE_SYNC_STATE"
                                                    if ("= 0;" in rc_c and "== 1" in rc_c) else "UNRESOLVED"),
                            "decompiled_c": rc_c[:3000]},
        "consumer": {"entry": consumer_entry, "class": consumer_class, "reasons": consumer_reasons,
                     "decompiled_c": consumer_c[:4000]},
        "upward_chain": chain, "root_candidate": evidence.root_entry, "root_class": evidence.root_class,
        "object_fields": {k: {"accesses": len(v["sites"]), "functions": sorted(set(v["functions"]))[:12]}
                          for k, v in object_fields.items()},
        "indirect_calls_l1": indirect, "artefact_status": artefacts_now,
        "field_f8_writers_recovered": field_f8_writers[:20],
        "r25_outcome": outcome, "reason": reason, "blockers": blockers,
        "closure_evidence": evidence.to_dict(),
    }
    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    Path(args.out).write_text(json.dumps(report, indent=2, sort_keys=True, default=str) + "\n", encoding="utf-8")
    print(f"ghidra: functions={ghidra.get('function_count')} analysed={ghidra.get('analysed_functions')} "
          f"decompiled={ghidra.get('decompiled_functions')}")
    print(f"sweep delta: cfg={delta.cfg_functions} sweep={delta.sweep_functions} reproduced={len(delta.reproduced)} "
          f"sweep_only={len(delta.sweep_only)} cfg_only={len(delta.cfg_only)} fpr={delta.false_positive_rate}")
    print(f"consumer: entry={consumer_entry} class={consumer_class} reasons={consumer_reasons}")
    print(f"upward chain nodes: {len(chain)} root_candidate={evidence.root_entry}")
    for item in chain[:8]:
        print(f"  L{item['level']} {item['caller']} @ {item['callsite']} -> {item['callee']}")
    print(f"object fields seen: { {k: v['accesses'] for k, v in report['object_fields'].items()} }")
    print(f"indirect calls in L1 callers: {indirect}")
    print(f"artefacts: {artefacts_now}")
    print(f"R25: {outcome} — {reason}")
    for blocker in blockers:
        print(f"  BLOCKER: {blocker}")
    print(f"evidence: {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
