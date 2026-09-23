#!/usr/bin/env python3
"""M2-LIVE2.9 — offline reclassification of the LIVE2.8 runtime window and the 0x218xx layout.

No console contact: this consumes the frozen runtime evidence, the kernel dump and the earlier
Ghidra/native extractions.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "scripts"))

from orbisprobe.live.layout import (
    R29Evidence,
    access_matrix,
    classify,
    classify_target,
    reinterpret_window,
)

DUMP_BASE = 0xFFFFFFFFD00D0000
LIVE_KB = 0xFFFFFFFF9C768000
DELTA_TO_DUMP = DUMP_BASE - LIVE_KB
TEXT_END_DUMP = DUMP_BASE + 0xCFE758
LIVE28 = Path("/home/hermes/audits/ps4b-soc-workbench/live28-20260923")
LIVE26 = Path("/home/hermes/audits/ps4b-soc-workbench/live26-20260923")
LIVE27 = Path("/home/hermes/audits/ps4b-soc-workbench/live27-20260923")
LIVE25 = Path("/home/hermes/audits/ps4b-soc-workbench/live25-20260923")
WINDOW_OFFSETS = (0x21800, 0x21808, 0x21810, 0x21820, 0x21830, 0x21840, 0x21850, 0x21858, 0x21860,
                  0x21864, 0x21868, 0x2186C, 0x21870, 0x21890, 0x21898)


def main() -> int:
    out = Path("/home/hermes/audits/ps4b-soc-workbench/live29-20260923")
    out.mkdir(parents=True, exist_ok=True)
    image = Path("/home/hermes/audits/playstation-ps4/fw1352-ps4b-20260920/kernel-dump/kernel.bin").read_bytes()
    live28 = json.loads(max(LIVE28.glob("live28-*-live28.json")).read_text())
    window_hex = next(r["data_hex"] for r in live28["reads"] if r["label"].startswith("context window"))
    raw_window = bytes.fromhex(window_hex)
    live_values = {0x21810: 0xFFFFFFFF9CF76718, 0x21820: 0xFFFFFFFF9CF7671F,
                   0x21830: 0xFFFFFFFF9CF76726, 0x21840: 0xFFFFFFFF9CF7672D}

    # 1./2. the four runtime values, rebased, with their bytes and tier
    targets = []
    for offset, live in live_values.items():
        dump_va = live + DELTA_TO_DUMP
        file_offset = dump_va - DUMP_BASE
        blob = image[file_offset:file_offset + 16]
        tier, level, reason = classify_target(dump_va, kernel_base=DUMP_BASE, kernel_text_end=TEXT_END_DUMP,
                                              instruction_boundaries=set(), function_starts=set(),
                                              target_bytes=blob)
        targets.append({"struct_offset": f"0x{offset:x}", "live_value": f"0x{live:x}",
                        "rebased_dump": f"0x{dump_va:x}", "bytes": blob[:10].hex(),
                        "ascii": blob.split(b"\x00", 1)[0].decode("latin-1", "replace"),
                        "tier": tier, "tier_level": level, "reason": reason})
    print("=== rebased runtime values ===")
    for item in targets:
        print(f"  {item['struct_offset']}: {item['live_value']} -> {item['rebased_dump']} "
              f"{item['ascii']!r} => {item['tier']}")

    # 3. +7 raster explanation
    raster = []
    for index in range(6):
        dump_va = 0xFFFFFFFFD08DE718 + 7 * index
        blob = image[dump_va - DUMP_BASE:dump_va - DUMP_BASE + 8]
        text = blob.split(b"\x00", 1)[0].decode("latin-1", "replace")
        raster.append({"address": f"0x{dump_va:x}", "text": text, "terminated": bool(blob.find(b"\x00") == len(text)),
                       "step": 7})
    print("=== +7 raster ===", [r["text"] for r in raster])

    # 4. static access matrix for the 0x218xx offsets (from the LIVE2.6 scan + LIVE2.7 callback sites)
    dispatch = json.loads((LIVE26 / "dispatch-closure.json").read_text())
    field27 = json.loads((LIVE27 / "field-closure.json").read_text())
    entries: list[dict] = []
    for row in dispatch.get("neighbour_0x21850", []):
        instruction = str(row.get("instruction", ""))
        entries.append({"offset": row.get("offset", ""), "instruction": instruction})
    for row in field27.get("callback_0x21850", []):
        instruction = str(row).split("(")[0].strip()
        entries.append({"offset": "0x21850", "instruction": instruction})
    matrix = access_matrix(entries)
    print("=== access matrix (0x218xx) ===")
    for offset in sorted(matrix, key=lambda value: int(value, 16)):
        cell = matrix[offset]
        print(f"  {offset}: n={cell['accesses']} widths={cell['widths']} read={cell['read']} "
              f"write={cell['write']} call/jmp={cell['call_jmp']} cmp={cell['compare']}")

    # 5. writer lifecycle for +0x21850 from the LIVE2.7 decompilation
    writer = field27["functions"].get("ffffffffd0580850", {}).get("decompiled_c", "")
    lifecycle = {
        "writer": "0xffffffffd0580aaf  MOV qword ptr [RDI + 0x21850],R14  (in FUN_ffffffffd0580850)",
        "clear": "0xffffffffd057f8e4  MOV qword ptr [RDI + 0x21850],0  (in FUN_ffffffffd057f200)",
        "guard_and_call": ["0xffffffffd057f887 CMP qword ptr [RDI + 0x21850],0",
                           "0xffffffffd057f8bc CALL qword ptr [RAX + 0x21850]"],
        "r14_provenance": ("R14 is written into the slot together with the global context path "
                           "(PTR_DAT_ffffffffd2458a28 + 0x21830 selection, 'Can't register GPU GUI Idle "
                           "interrupt' string next to the slot's neighbourhood) -> a registration-time "
                           "callback assignment"),
        "writer_context_present": "GPU GUI idle interrupt registration" in writer or "21850" in writer,
    }

    # 10. registration state classification
    strings = image[0xFFFFFFFFD08DE6F0 - DUMP_BASE:0xFFFFFFFFD08DE760 - DUMP_BASE].split(b"\x00")
    printable = [s.decode("latin-1", "replace") for s in strings if len(s) >= 3]
    registration = ("DEVICE_INIT" if any("Idle interrup" in s for s in printable) else "UNKNOWN")

    # 11. raw window reinterpretation
    rows = reinterpret_window(raw_window, base_offset=0x217D8, kernel_base=LIVE_KB, kernel_text_end=TEXT_END_DUMP,
                              dump_base=DUMP_BASE, live_base=LIVE_KB)
    for row in rows:
        offset = int(row["offset"], 16)
        row["static_offset_of_interest"] = any(offset <= want < offset + 8 for want in WINDOW_OFFSETS)

    neighbours = {item["struct_offset"]: item["tier"] for item in targets}
    evidence = R29Evidence(candidate_id="RC-001", callback_layout_disproved=False,
                           callback_registration_state=registration,
                           neighbour_target_classes=neighbours, neighbour_values_are_data=True,
                           mixed_struct=True, window_from_expected_struct=True)
    outcome, reason, notes = classify(evidence)
    verdict = {"candidate_id": "RC-001", "mode": "offline reclassification (no console contact)",
               "rebase": {"live_kbase": f"0x{LIVE_KB:x}", "dump_base": f"0x{DUMP_BASE:x}",
                          "live_to_dump_delta": f"+0x{DELTA_TO_DUMP:x}"},
               "runtime_values_reclassified": targets,
               "plus7_raster": raster,
               "raster_explanation": ("the four values are pointers to successive 7-byte string literals "
                                      "(6 characters + NUL): GC_SRB, GC_SRM, GC_SRI, GC_IDLE — the +7 step is the "
                                      "string pitch, not a field pitch"),
               "neighbourhood_strings": printable,
               "access_matrix_0x218xx": matrix,
               "callback_writer_lifecycle": lifecycle,
               "callback_registration_state": registration,
               "runtime_window_reinterpreted": rows,
               "retractions": {"LIVE2.8_alignment_argument":
                               "RETRACTED as a *reason*: alignment is not required for x86-64 code pointers. The "
                               "values were rejected correctly in outcome (they are data), but the reasoning was "
                               "wrong and the tier vocabulary is replaced by DATA_NOT_CODE/EXECUTABLE_CODE_TARGET.",
                               "LIVE2.8_R28_B":
                               "REVISED: the runtime window does not contradict the +0x21850 layout; the slot is "
                               "simply unregistered in the observed state, and the neighbouring fields are char* "
                               "name pointers. New outcome R29-C."},
               "r29_outcome": outcome, "reason": reason, "notes": notes,
               "closure_evidence": evidence.to_dict()}
    (out / "r29-verdict.json").write_text(json.dumps(verdict, indent=2, sort_keys=True, default=str) + "\n",
                                          encoding="utf-8")
    print(f"\nR29: {outcome} — {reason}")
    for note in notes:
        print("   note:", note)
    print("evidence:", out / "r29-verdict.json")
    return 0


if __name__ == "__main__":
    sys.exit(main())
