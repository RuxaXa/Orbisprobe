#!/usr/bin/env python3
"""M2-LIVE2.10 — read-only runtime closure attempt for RC-001 (campaign primary track).

Discipline: no 9090 polling, no bare TCP probes, exactly one payload delivery, fresh greeting/instance.
Reads: kernel text/data/heap/direct-map only, <=0x100 bytes each, bounded pointer chains (<=32 nodes,
cycle detection), no MMIO, no unknown-class dereference, no writes, no ioctl, no callback invocation.
"""

from __future__ import annotations

import json
import socket
import sys
import time
from pathlib import Path

ROOT = Path(__file__).parents[1]
sys.path.insert(0, str(ROOT)); sys.path.insert(0, str(ROOT / "scripts"))

from orbisprobe.live.attach import (
    InstanceLedger,
    SingleGreetingOwner,
    capture_log_baseline,
    preflight,
    validate_greeting,
    wait_for_start,
)
from orbisprobe.live.channel import ConsoleChannel
from orbisprobe.live.introspect import (
    bounded_read_length,
    classify_address,
    pointer_sanity,
    rebound_object_address,
)
from orbisprobe.live.layout import classify_target, looks_like_string
from orbisprobe.live.transport import WorkerConfig, WorkerConsoleTransport

DUMP_BASE = 0xFFFFFFFFD00D0000
ANCHOR_STATIC = 0xFFFFFFFFD2458A28
TEXT_SIZE = 0xCFE758
IMAGE_SIZE = 0x2A00000
RC001_SHAPE = (0x78, 0x88, 0xF0, 0xF8)
MAX_NODES = 32
OBJ_HEAD = 0x100
TABLE_INDEX = 0x12
TABLE_NEIGHBOURS = (0x11, 0x13)


def load_function_starts() -> set[int]:
    starts: set[int] = set()
    p = Path("/home/hermes/audits/ps4b-soc-workbench/live25-20260923/ghidra-closure.json")
    if p.is_file():
        for info in json.loads(p.read_text()).get("functions", {}).values():
            if isinstance(info, dict) and info.get("entry"):
                starts.add(int(info["entry"], 16))
    from live22_discovery import function_offsets
    img = Path("/home/hermes/audits/playstation-ps4/fw1352-ps4b-20260920/kernel-dump/kernel.bin")
    if img.is_file():
        from capstone import CS_ARCH_X86, CS_MODE_64, Cs
        window = img.read_bytes()[0x1000:0x1000 + 13619544]
        md = Cs(CS_ARCH_X86, CS_MODE_64); md.detail = False
        starts.update(DUMP_BASE + 0x1000 + o for o in function_offsets(window, DUMP_BASE + 0x1000, md, 200000, 4096))
    return starts


def main() -> int:
    out = Path("/home/hermes/audits/ps4b-soc-workbench/campaign-20260923")
    out.mkdir(parents=True, exist_ok=True)
    rec: dict = {"run": "M2-LIVE2.10", "mode": "READ-ONLY", "reads": [], "objects": [], "chain": []}
    tr = WorkerConsoleTransport(WorkerConfig(ssh_target="neo@192.168.1.148", console_ip="192.168.1.141"))
    ssh = lambda c: tr.ssh(c).stdout
    try:
        pre = preflight(ssh, console_ip="192.168.1.141", console_port=9090, host_port=9026,
                        bridge_log="/tmp/console_bridge.log")
        rec["preflight"] = {"icmp": pre.non_loader_context.get("icmp"), "bridge_pid": pre.bridge_pid,
                            "stale": len(pre.stale_payload_connections), "ok": pre.ok}
        if not pre.ok:
            rec["blocker"] = f"preflight blocked: {pre.blockers}"
            return _finish(rec, out, "R30-D (live unavailable)")
        if pre.bridge_pid or pre.stale_payload_connections:
            tr.stop_bridge()
        started = tr.start_bridge(lifetime=900)
        if "BRIDGE-STARTED" not in str(started):
            rec["blocker"] = "bridge did not start"
            return _finish(rec, out, "R30-D (live unavailable)")
        baseline = capture_log_baseline(ssh, "/tmp/console_bridge.log")
        binary = tr.fetch_payload()
        rec["payload_sha256"] = __import__("hashlib").sha256(binary).hexdigest()
        delivered = time.time()
        delivery = tr.send_payload(binary, timeout=20)
        rec["delivery"] = {k: v for k, v in delivery.items() if k != "body"}
        if not delivery.get("ok"):
            rec["blocker"] = f"delivery failed: {delivery.get('error')}"
            return _finish(rec, out, "R30-D (live unavailable)")
        witness = wait_for_start(ssh, bridge_log="/tmp/console_bridge.log", delivered_epoch=delivered,
                                 timeout=45, baseline=baseline)
        if not witness.observed:
            rec["blocker"] = "payload start not observed"
            return _finish(rec, out, "R30-D (live unavailable)")
        tr.open_tunnel()
        ch = ConsoleChannel(socket.create_connection(("127.0.0.1", tr.config.local_port), timeout=10),
                            default_timeout=30)
        SingleGreetingOwner().consume()
        greeting = ch.recv_frame(timeout=30).decode("utf-8", "replace")
        ledger = InstanceLedger(out / "payload-instances.json")
        ok, violations, info = validate_greeting(greeting, previous_instances=ledger.instances(),
                                                delivered_epoch=delivered)
        rec["greeting"] = {"instance": info["instance"], "nonce": info["greeting"].get("nonce"),
                           "violations": violations}
        if not ok:
            rec["blocker"] = f"greeting rejected: {violations}"
            return _finish(rec, out, "R30-D (live unavailable)")
        ledger.record(info["instance"], run_id="live210", pid=info["greeting"].get("pid", ""),
                      firmware=info["greeting"].get("fw", ""))
        target_info = ch.request("INFO", timeout=15)
        kbase = int(str(target_info.get("kbase", "0x0")), 16)
        text_end, image_end = kbase + TEXT_SIZE, kbase + IMAGE_SIZE
        delta = kbase - DUMP_BASE
        funcs = load_function_starts()
        rec["identity"] = {"fw": target_info.get("fw"), "kbase": f"0x{kbase:x}", "delta": f"0x{delta:x}",
                           "functions_known": len(funcs), "instance": info["instance"]}

        def read(address: int, length: int, label: str) -> bytes:
            length, _clamped = bounded_read_length(length, 0x100)
            klass = classify_address(address, kernel_base=kbase, kernel_text_end=text_end, kernel_image_end=image_end)
            if klass not in ("KERNEL_TEXT", "KERNEL_DATA", "KERNEL_HEAP", "DIRECT_MAP"):
                rec["reads"].append({"label": label, "address": f"0x{address:x}", "class": klass, "blocked": True})
                return b""
            resp = ch.request("READ", timeout=15, kaddr=address, len=length)
            blob = bytes.fromhex(str(resp.get("hex", "")))
            rec["reads"].append({"label": label, "address": f"0x{address:x}", "class": klass, "length": length,
                                 "ok": bool(resp.get("ok")), "hex": blob.hex()[:64],
                                 "string": looks_like_string(blob)[0] if blob else False})
            return blob

        def qwords(blob: bytes) -> dict[int, int]:
            return {i: int.from_bytes(blob[i:i + 8], "little") for i in range(0, len(blob) - 7, 8)}

        # identity proof + anchor
        magic = read(kbase, 16, "kbase ELF header")
        rec["rebase_proof"] = {"elf_magic": magic[:4] == b"\x7fELF", "hex": magic[:8].hex()}
        anchor = qwords(read(rebound_object_address(ANCHOR_STATIC, dump_base=DUMP_BASE, live_base=kbase), 8,
                             "GC context anchor")).get(0, 0)
        ok_a, why_a, cls_a = pointer_sanity(anchor, kernel_base=kbase, kernel_text_end=text_end,
                                           kernel_image_end=image_end)
        rec["anchor"] = {"value": f"0x{anchor:x}", "sane": ok_a, "reason": why_a, "class": cls_a}
        if not ok_a:
            rec["blocker"] = f"anchor not sane: {why_a}"
            ch.request("QUIT", timeout=10)
            return _finish(rec, out, "R30-D (no trusted root)")
        ctx = read(anchor, OBJ_HEAD, "GC context head 0x100")
        ctx_q = qwords(ctx)
        rec["context_pointers"] = {f"0x{off:x}": f"0x{val:x}" for off, val in ctx_q.items()
                                   if val and cls_ok(val, kbase, text_end, image_end)}
        # trusted discovery: walk sane pointers (bounded, cycle-detected) looking for the RC-001 shape
        queue = [(f"0x{off:x}", val, 1) for off, val in ctx_q.items() if cls_ok(val, kbase, text_end, image_end)]
        seen: set[int] = {anchor}
        nodes = 0
        while queue and nodes < MAX_NODES:
            origin, address, depth = queue.pop(0)
            if address in seen:
                continue
            seen.add(address)
            nodes += 1
            blob = read(address, OBJ_HEAD, f"object head via {origin} (depth {depth})")
            fields = qwords(blob)
            shape = {}
            for offset in RC001_SHAPE:
                value = fields.get(offset, 0)
                if value:
                    sane, why, klass = pointer_sanity(value, kernel_base=kbase, kernel_text_end=text_end,
                                                      kernel_image_end=image_end)
                    shape[f"0x{offset:x}"] = {"value": f"0x{value:x}", "sane": sane, "class": klass, "why": why}
                else:
                    shape[f"0x{offset:x}"] = {"value": "0x0", "sane": False, "class": "NULL", "why": "null"}
            matches = sum(1 for item in shape.values() if item["sane"])
            entry = {"address": f"0x{address:x}", "depth": depth, "shape": shape, "matches": matches}
            rec["objects"].append(entry)
            if matches >= 3:
                rec["rc001_candidate"] = entry
                table = fields.get(0x28, 0)
                sane_t, why_t, cls_t = pointer_sanity(table, kernel_base=kbase, kernel_text_end=text_end,
                                                      kernel_image_end=image_end, require_alignment=True)
                rec["table"] = {"obj_0x28": f"0x{table:x}", "sane": sane_t, "reason": why_t, "class": cls_t}
                if sane_t:
                    for index in (TABLE_INDEX,) + TABLE_NEIGHBOURS:
                        slot = read(table + index * 8, 0x10, f"ops entry index 0x{index:x}")
                        slot_q = qwords(slot)
                        target = slot_q.get(8, 0)
                        blob_t = read(target, 16, f"target bytes index 0x{index:x}") if target else b""
                        tier, level, reason = classify_target(
                            target, kernel_base=DUMP_BASE + delta * 0, kernel_text_end=kbase + TEXT_SIZE,
                            instruction_boundaries=set(), function_starts={f + delta for f in funcs},
                            target_bytes=blob_t)
                        rec.setdefault("entries", []).append(
                            {"index": f"0x{index:x}", "slot_raw": slot.hex()[:32], "target": f"0x{target:x}",
                             "tier": tier, "level": level, "reason": reason})
                for offset in (0xF0, 0xF8):
                    value = fields.get(offset, 0)
                    if value:
                        head = read(value, 0x40, f"ring object via obj+0x{offset:x}")
                        rec.setdefault("rings", []).append(
                            {"field": f"0x{offset:x}", "pointer": f"0x{value:x}", "head_hex": head[:32].hex()})
                break
            if depth < 2:
                for off, val in fields.items():
                    if val and cls_ok(val, kbase, text_end, image_end):
                        queue.append((f"0x{address:x}+0x{off:x}", val, depth + 1))
        ch.request("QUIT", timeout=10)
        ch.close()
        if rec.get("rc001_candidate"):
            outcome = "R30-C" if rec.get("table", {}).get("sane") else "R30-C (object found, table unresolved)"
        else:
            outcome = "R30-D (no RC-001-shaped runtime instance reachable from the trusted root)"
        rec["outcome"] = outcome
    except Exception as exc:  # noqa: BLE001
        rec["error"] = f"{type(exc).__name__}: {exc}"
        rec["outcome"] = f"R30-D? ({type(exc).__name__})"
    finally:
        tr.close()
    return _finish(rec, out, rec.get("outcome", "UNKNOWN"))


def cls_ok(value: int, kbase: int, text_end: int, image_end: int) -> bool:
    klass = classify_address(value, kernel_base=kbase, kernel_text_end=text_end, kernel_image_end=image_end)
    return klass in ("KERNEL_DATA", "KERNEL_HEAP", "DIRECT_MAP")


def _finish(rec: dict, out: Path, outcome: str) -> int:
    rec["finished_utc"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    p = out / f"live210-{time.strftime('%H%M%S')}.json"
    p.write_text(json.dumps(rec, indent=2, sort_keys=True, default=str) + "\n", encoding="utf-8")
    print("outcome:", outcome)
    print("evidence:", p)
    return 0


if __name__ == "__main__":
    sys.exit(main())
