#!/usr/bin/env python3
"""M2-LIVE2.3 — turn the static closure into the pre-live classification (RCR-A..D).

Reads the reachability and dataflow evidence, re-derives the decisive facts from the instructions
(kernel writes inside the candidate, the exact read #1/#2 shape, the consumer's use of the pointer) and
writes the verdict together with every open blocker. No live action, no mutation.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from live22_discovery import disassemble_function, mem_operand

from orbisprobe.live.reachability import (
    C4,
    ReachabilityEvidence,
    classify,
)

RC001 = 0xFFFFFFFFD05AC8F0
BASE = 0xFFFFFFFFD00D0000
START = 0x1000
CONSUMER = 0xFFFFFFFFD057E7B0


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--image", required=True)
    parser.add_argument("--reachability", required=True)
    parser.add_argument("--dataflow", required=True)
    parser.add_argument("--discovery", default="")
    parser.add_argument("--out", required=True)
    args = parser.parse_args()

    from capstone import CS_ARCH_X86, CS_MODE_64, Cs

    data = Path(args.image).read_bytes()
    window = data[START:START + 13619544]
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = False
    reach = json.loads(Path(args.reachability).read_text())
    flow = json.loads(Path(args.dataflow).read_text())

    body = disassemble_function(md, window, RC001 - BASE - START, BASE + START, 8192, 600)
    writes, reads, validation, consumer_call = [], [], None, None
    for insn in body:
        ops = insn.op_str
        if "," in ops:
            dst, _src = (part.strip() for part in ops.split(",", 1))
            if mem_operand(dst) is not None:
                writes.append(f"0x{insn.address:x} {insn.mnemonic} {ops}")
            line = f"0x{insn.address:x} {insn.mnemonic} {ops}"
            if insn.address in (0xFFFFFFFFD05AC963, 0xFFFFFFFFD05AC974):
                reads.append(line)
            if insn.address == 0xFFFFFFFFD05AC96A:
                validation = line
            # the consumer call is the first call after read #2 (address from the LIVE2.2 discovery)
            if (consumer_call is None and insn.mnemonic == "call"
                    and insn.address > 0xFFFFFFFFD05AC974):
                consumer_call = line

    # the linear sweep stops RC-001's body at an internal jump, so fall back to the discovery record
    if consumer_call is None and args.discovery:
        for candidate in json.loads(Path(args.discovery).read_text()).get("all_candidates", []):
            start = str(candidate.get("function_start", "")).strip().lower()
            if start in (f"0x{RC001:x}", f"0x0x{RC001:x}"):
                consumer_call = str(candidate.get("consumer", "")) + "   [source: engine #1 discovery]"
                break
    consumer = flow["functions"]["consumer"]
    consumer_class = C4                     # conservative: pointer use not closed
    consumer_note = ("no direct [rdi] dereference observed in the analysed window, but the pointer is "
                     "spilled and the function makes "
                     f"{consumer['call_count']} calls: behaviour is not closed -> C4")

    evidence = ReachabilityEvidence(
        candidate_id="RC-001",
        function=f"0x{RC001:x}-0x{0xFFFFFFFFD05AC9BE:x}",
        field="[r15+0xf8]",
        read_1=reads[0] if reads else "",
        read_2=reads[1] if len(reads) > 1 else "",
        intervening_call=consumer_call or "",
        consumer=f"0x{CONSUMER:x} (rdi = field value); {consumer_note}",
        consumer_security_class=consumer_class,
        kernel_writes_on_path=writes[:6],
        user_control="UNKNOWN",             # r15 = argument object; no syscall/ioctl connection proven
        mutability="UNKNOWN",               # writers exist in the image, no lock/lifetime analysis
        lock_between_reads=None,
        persistent_sink_proof="NOT_PROVEN",
        callers=[f"{c['caller']} @ {c['callsite']}" for c in reach["callers"] if c["level"] == 1],
        unresolved=[
            "indirect callers (call reg / call [mem]) are not followed: the root entry is not closed",
            "caller bodies are truncated by the linear sweep, so r15/argument setup per callsite is open",
            ("three deeper callsites (0xd0d6c4c8, 0xd0d70540, 0xd0d507f0) lie in data-like regions and may be "
            "sweep artefacts, not real calls"),
            "no symbols: object type/owner of r15 and the +0xf8 field cannot be named",
        ],
    )
    verdict, reason, blockers = classify(evidence)
    payload = {
        "candidate_id": "RC-001", "read_1": evidence.read_1, "validation": validation,
        "read_2": evidence.read_2, "consumer_call": evidence.intervening_call,
        "kernel_writes_on_path": evidence.kernel_writes_on_path,
        "validation_semantics": "NULL check only (test rdi,rdi + conditional jump); no revalidation before read #2",
        "consumer": evidence.consumer, "consumer_security_class": consumer_class,
        "user_control": evidence.user_control, "mutability": evidence.mutability,
        "persistent_sink_proof": evidence.persistent_sink_proof,
        "callers_level1": evidence.callers,
        "unresolved": evidence.unresolved,
        "rcr_classification": verdict, "reason": reason, "blockers": blockers,
        "live_test": "NOT PERFORMED (PLAN_ONLY)" if verdict != "RCR-A" else "ALLOWED",
    }
    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    Path(args.out).write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"verdict: {verdict} — {reason}")
    print(f"read #1 : {evidence.read_1}")
    print(f"validat : {validation}")
    print(f"read #2 : {evidence.read_2}")
    print(f"consumer: {evidence.intervening_call}")
    print(f"kernel writes inside the candidate: {len(evidence.kernel_writes_on_path)}")
    for write in evidence.kernel_writes_on_path[:3]:
        print(f"   {write}")
    for blocker in blockers:
        print(f"  BLOCKER: {blocker}")
    print(f"evidence: {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
