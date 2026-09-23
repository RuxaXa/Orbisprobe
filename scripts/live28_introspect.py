#!/usr/bin/env python3
"""M2-LIVE2.8 - read-only runtime introspection of the GC context and the ops-table anchor.

Only INFO / PING / READ(kaddr) / QUIT are ever sent. There is no WRITE, no RACE/TR, no ioctl, no callback
invocation, no ring submit. Every pointer is classified and sanity-checked before it is dereferenced, and
every read is bounded to 0x100 bytes.
"""

from __future__ import annotations

import argparse
import json
import socket
import sys
import time
from pathlib import Path

ROOT = Path(__file__).parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT))

from live2_toctou import sha

from orbisprobe.live.attach import (
    InstanceLedger,
    SingleGreetingOwner,
    Timeouts,
    capture_log_baseline,
    preflight,
    validate_greeting,
    wait_for_start,
)
from orbisprobe.live.channel import ConsoleChannel
from orbisprobe.live.introspect import (
    KERNEL_TEXT,
    R28Evidence,
    bounded_read_length,
    classify_address,
    pointer_sanity,
    rebound_object_address,
    validate_function_target,
)
from orbisprobe.live.introspect import (
    classify as classify_r28,
)
from orbisprobe.live.transport import WorkerConfig, WorkerConsoleTransport

DUMP_BASE = 0xFFFFFFFFD00D0000
ANCHOR_STATIC = 0xFFFFFFFFD2458A28           # PTR_DAT_ffffffffd2458a28 (global GC context pointer)
ANCHOR_ALT = 0xFFFFFFFFD2458A28 + 0x2100     # nearby same-global family member for sanity
WINDOW_START = 0x217D8
WINDOW_END = 0x218A0
CALLBACK_OFFSET = 0x21850
OBJECT_FIELDS = (0x78, 0x88, 0xF0, 0xF8)
CONTEXT_POINTER_OFFSETS = (0x21800, 0x21808, 0x21810, 0x21820, 0x21830, 0x21840, 0x21858, 0x21860, 0x21898)
SNAPSHOT_FIELDS = (0x21850, 0x21800, 0x21808, 0x21890)


def load_function_starts() -> set[int]:
    """Function boundaries: the CFG-recovered Ghidra set plus the linear-sweep map."""

    starts: set[int] = set()
    ghidra = Path("/home/hermes/audits/ps4b-soc-workbench/live25-20260923/ghidra-closure.json")
    if ghidra.is_file():
        data = json.loads(ghidra.read_text())
        for info in data.get("functions", {}).values():
            if isinstance(info, dict) and info.get("entry"):
                starts.add(int(info["entry"], 16))
    from live22_discovery import function_offsets

    image = Path("/home/hermes/audits/playstation-ps4/fw1352-ps4b-20260920/kernel-dump/kernel.bin")
    if image.is_file():
        from capstone import CS_ARCH_X86, CS_MODE_64, Cs

        window = image.read_bytes()[0x1000:0x1000 + 13619544]
        md = Cs(CS_ARCH_X86, CS_MODE_64)
        md.detail = False
        starts.update(DUMP_BASE + 0x1000 + offset for offset in function_offsets(window, DUMP_BASE + 0x1000, md, 200000, 4096))
    return starts


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--evidence-dir", default="/home/hermes/audits/ps4b-soc-workbench/live28-20260923")
    parser.add_argument("--run-id", default=time.strftime("live28-%Y%m%dT%H%M%S"))
    parser.add_argument("--console", default="192.168.1.141")
    parser.add_argument("--worker", default="neo@192.168.1.148")
    parser.add_argument("--snapshots", type=int, default=3)
    args = parser.parse_args()
    out = Path(args.evidence_dir)
    out.mkdir(parents=True, exist_ok=True)
    timeouts = Timeouts()
    record: dict = {"run_id": args.run_id, "mode": "READ-ONLY introspection",
                    "allowed_commands": ["INFO", "PING", "READ(kaddr)", "QUIT"],
                    "forbidden": ["WRITE", "RACE", "TR", "DRW", "ioctl", "callback", "ring submit"],
                    "utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "reads": []}
    transport = WorkerConsoleTransport(WorkerConfig(ssh_target=args.worker, console_ip=args.console))
    ssh = lambda cmd: transport.ssh(cmd).stdout
    evidence = R28Evidence()
    verdict = "NOT DONE"
    try:
        existing = preflight(ssh, console_ip=args.console, console_port=transport.config.payload_port,
                             host_port=transport.config.bridge_host_port, bridge_log="/tmp/console_bridge.log")
        record["preflight_before_reset"] = existing.to_dict()
        print(f"[1] previous session: bridge_pid={existing.bridge_pid or '-'} stale={len(existing.stale_payload_connections)}")
        if existing.bridge_pid or existing.stale_payload_connections:
            record["bridge_stop"] = transport.stop_bridge()
        started = transport.start_bridge(lifetime=900)
        record["bridge_start"] = started
        if "BRIDGE-STARTED" not in str(started):
            record["blocker"] = "bridge did not start"
            evidence.blocker = "bridge did not start"
            return _finish(record, evidence, out, args.run_id, "NOT DONE (BRIDGE_BIND_TIMEOUT)")
        baseline = capture_log_baseline(ssh, "/tmp/console_bridge.log")
        binary = transport.fetch_payload()
        record["payload_sha256"] = sha(binary)
        delivered_epoch = time.time()
        delivery = transport.send_payload(binary, timeout=timeouts.loader_delivery)
        record["delivery"] = {k: v for k, v in delivery.items() if k != "body"}
        print(f"[2] delivery: ok={delivery.get('ok')} status={delivery.get('status')}")
        start = wait_for_start(ssh, bridge_log="/tmp/console_bridge.log", delivered_epoch=delivered_epoch,
                               timeout=timeouts.payload_start, baseline=baseline)
        record["start_witness"] = start.to_dict()
        if not start.observed:
            evidence.blocker = "payload start not observed"
            return _finish(record, evidence, out, args.run_id, "NOT DONE (PAYLOAD_DELIVERED / START_NOT_OBSERVED)")
        transport.open_tunnel()
        sock = socket.create_connection(("127.0.0.1", transport.config.local_port), timeout=10)
        owner = SingleGreetingOwner()
        channel = ConsoleChannel(sock, default_timeout=timeouts.greeting)
        if not owner.consume():
            raise RuntimeError("greeting already consumed")
        greeting = channel.recv_frame(timeout=timeouts.greeting).decode("utf-8", "replace")
        ledger = InstanceLedger(out / "payload-instances.json")
        ok, violations, info = validate_greeting(greeting, previous_instances=ledger.instances(),
                                                 delivered_epoch=delivered_epoch)
        record["greeting"] = info
        record["greeting_violations"] = violations
        print(f"[3] greeting: {greeting.strip()[:110]}")
        if not ok:
            evidence.blocker = f"greeting rejected: {violations}"
            return _finish(record, evidence, out, args.run_id, "NOT DONE (greeting rejected)")
        ledger.record(info["instance"], run_id=args.run_id, pid=info["greeting"].get("pid", ""),
                      firmware=info["greeting"].get("fw", ""))
        target_info = channel.request("INFO", timeout=15)
        ping = channel.request("PING", timeout=10)
        record["info"] = target_info
        record["ping"] = ping
        kbase = int(str(target_info.get("kbase", "0x0")), 16)
        # INFO's text/data are *payload symbol* addresses, not kernel ranges: the kernel window comes from
        # the dumped image geometry (text 0xCFE758) and a safe upper bound; the payload's own
        # kernel_readable() gate stays the authoritative check.
        # verified by probe: the image spans the full 44 MB dump (the GC context anchor sits 0x2388a28
        # bytes past the base), so the window must cover it; the payload's kernel_readable() gate
        # remains the authoritative check.
        text_end = kbase + 0xCFE758
        image_end = kbase + 0x2A00000
        payload_symbols = {"sp": target_info.get("sp"), "text": target_info.get("text"),
                           "data": target_info.get("data"), "heap": target_info.get("heap")}
        delta = kbase - DUMP_BASE
        function_starts = load_function_starts()
        record["identity"] = {"firmware": target_info.get("fw"), "kbase": f"0x{kbase:x}",
                              "text_end": f"0x{text_end:x}", "image_end": f"0x{image_end:x}",
                              "payload_symbols_user_space": payload_symbols,
                              "rebased_by": f"0x{delta:x}", "function_starts_known": len(function_starts),
                              "pid": target_info.get("pid"), "instance": info["instance"]}
        evidence.boot_base = kbase
        print(f"[4] identity: fw={target_info.get('fw')} kbase=0x{kbase:x} rebase=0x{delta:x} "
              f"text_end=0x{text_end:x} functions={len(function_starts)}")

        def read(address: int, length: int, label: str) -> dict:
            length, clamped = bounded_read_length(length)
            klass = classify_address(address, kernel_base=kbase, kernel_text_end=text_end,
                                     kernel_image_end=image_end)
            if klass not in ("KERNEL_TEXT", "KERNEL_DATA", "KERNEL_HEAP", "DIRECT_MAP"):
                entry = {"label": label, "address": f"0x{address:x}", "class": klass, "blocked": True,
                         "reason": f"class {klass} is not readable"}
                record["reads"].append(entry)
                return entry
            response = channel.request("READ", timeout=15, kaddr=address, len=length)
            entry = {"label": label, "address": f"0x{address:x}", "length": length, "class": klass,
                     "clamped": clamped, "ok": bool(response.get("ok")),
                     "data_hex": response.get("data_hex") or response.get("hex", ""),
                     "sha256": response.get("sha256", ""), "timestamp": time.strftime("%H:%M:%S")}
            record["reads"].append(entry)
            return entry

        anchor_address = rebound_object_address(ANCHOR_STATIC, dump_base=DUMP_BASE, live_base=kbase)
        anchor = read(anchor_address, 8, "GC context anchor (PTR_DAT_ffffffffd2458a28)")
        anchor_value = int.from_bytes(bytes.fromhex(anchor.get("data_hex", "") or "0" * 16)[:8], "little")
        evidence.anchor_address = anchor["address"]
        evidence.anchor_value = f"0x{anchor_value:x}"
        ok_ptr, reason, klass = pointer_sanity(anchor_value, kernel_base=kbase, kernel_text_end=text_end,
                                               kernel_image_end=image_end)
        record["anchor_sanity"] = {"ok": ok_ptr, "reason": reason, "class": klass}
        print(f"[5] anchor {anchor['address']} -> 0x{anchor_value:x} [{klass}] {reason}")
        if not ok_ptr:
            evidence.blocker = f"anchor pointer not sane: {reason}"
            channel.request("QUIT", timeout=10)
            return _finish(record, evidence, out, args.run_id, "NOT DONE (R28-D anchor)")
        evidence.context_readable = True
        window = read(anchor_value + WINDOW_START, WINDOW_END - WINDOW_START, "context window 0x217d8-0x218a0")
        raw = bytes.fromhex(window.get("data_hex", "") or "")
        for offset in CONTEXT_POINTER_OFFSETS + (CALLBACK_OFFSET,):
            index = offset - WINDOW_START
            if index + 8 <= len(raw):
                value = int.from_bytes(raw[index:index + 8], "little")
                evidence.context_window[f"0x{offset:x}"] = f"0x{value:x}"
        callback_value = int(evidence.context_window.get(f"0x{CALLBACK_OFFSET:x}", "0x0"), 16)
        evidence.callback_target = f"0x{callback_value:x}"
        if callback_value:
            class_name, reason = validate_function_target(callback_value, kernel_base=kbase, kernel_text_end=text_end,
                                                          function_starts=function_starts)
            evidence.callback_class = class_name
            record["callback_validation"] = {"value": f"0x{callback_value:x}", "class": class_name,
                                             "reason": reason}
        print(f"[6] callback +0x21850 = 0x{callback_value:x} -> {evidence.callback_class}")
        for field in CONTEXT_POINTER_OFFSETS:
            key = f"0x{field:x}"
            value = int(evidence.context_window.get(key, "0x0"), 16)
            if value:
                ok_p, reason_p, klass_p = pointer_sanity(value, kernel_base=kbase, kernel_text_end=text_end,
                                                         kernel_image_end=image_end)
                record.setdefault("context_pointers", {})[key] = {"value": f"0x{value:x}", "class": klass_p,
                                                                  "sane": ok_p, "reason": reason_p}
        # bounded two-level probe: does a context pointer lead to an object with a plausible +0x28 table pointer?
        for field in CONTEXT_POINTER_OFFSETS:
            value = int(evidence.context_window.get(f"0x{field:x}", "0x0"), 16)
            if not value:
                continue
            ok_p, _, klass_p = pointer_sanity(value, kernel_base=kbase, kernel_text_end=text_end,
                                              kernel_image_end=image_end)
            if not ok_p or klass_p == KERNEL_TEXT:
                continue
            head = read(value, 0x40, f"object head for context+0x{field:x}")
            raw_head = bytes.fromhex(head.get("data_hex", "") or "")
            if len(raw_head) >= 0x30:
                table = int.from_bytes(raw_head[0x28:0x30], "little")
                record.setdefault("table_probe", []).append({"via": f"0x{field:x}", "object": f"0x{value:x}",
                                                             "obj_0x28": f"0x{table:x}"})
                ok_t, _reason_t, klass_t = pointer_sanity(table, kernel_base=kbase, kernel_text_end=text_end,
                                                           kernel_image_end=image_end)
                if ok_t and klass_t != KERNEL_TEXT:
                    evidence.table_pointer = f"0x{table:x}"
                    entry_address = table + 0x12 * 8
                    entry = read(entry_address, 0x18, "ops-table entry 0x12 (+ neighbours)")
                    raw_entry = bytes.fromhex(entry.get("data_hex", "") or "")
                    if len(raw_entry) >= 0x10:
                        target = int.from_bytes(raw_entry[0x08:0x10], "little")
                        evidence.entry_0x12_target = f"0x{target:x}"
                        tl, reason_l = validate_function_target(target, kernel_base=kbase, kernel_text_end=text_end,
                                                                function_starts=function_starts)
                        evidence.entry_target_class = tl
                        record["entry_0x12"] = {"table": f"0x{table:x}", "entry": f"0x{entry_address:x}",
                                                "target": f"0x{target:x}", "class": tl, "reason": reason_l}
                        print(f"[8] entry 0x12 target = 0x{target:x} -> {tl} ({reason_l})")
                        if len(raw_entry) >= 0x18:
                            neighbour = int.from_bytes(raw_entry[0x10:0x18], "little")
                            evidence.neighbor_entries["0x13"] = f"0x{neighbour:x}"
                    break
        # bounded multi-snapshot for natural change observation
        samples: list[dict[str, str]] = []
        for index in range(max(1, args.snapshots)):
            snap = read(anchor_value + SNAPSHOT_FIELDS[0], 8, f"snapshot{index} callback")
            raw_snap = bytes.fromhex(snap.get("data_hex", "") or "")
            value = int.from_bytes(raw_snap[:8], "little") if len(raw_snap) >= 8 else 0
            samples.append({"t": f"t{index}", "callback": f"0x{value:x}"})
            if index + 1 < args.snapshots:
                time.sleep(2)
        evidence.snapshots = len(samples)
        record["snapshots"] = samples
        values = {item["callback"] for item in samples}
        evidence.changed_between_snapshots = [] if len(values) == 1 else ["callback"]
        record["snapshot_outcome"] = "NO_CHANGE_OBSERVED" if len(values) == 1 else "MUTABLE_SUPPORTED"
        print(f"[9] snapshots: {samples} -> {record['snapshot_outcome']}")
        quit_response = channel.request("QUIT", timeout=10)
        record["quit"] = quit_response
        channel.close()
        outcome, reason, notes = classify_r28(evidence)
        record["r28_outcome"] = outcome
        record["reason"] = reason
        record["notes"] = notes
        verdict = f"{outcome} — {reason}"
    except Exception as exc:  # noqa: BLE001 - the classification matters, not the traceback
        record["error"] = f"{type(exc).__name__}: {exc}"
        outcome, reason, _ = classify_r28(evidence)
        record["r28_outcome"] = outcome
        record["reason"] = reason
        verdict = f"NOT DONE ({type(exc).__name__})"
    finally:
        transport.close()
    return _finish(record, evidence, out, args.run_id, verdict)


def _finish(record: dict, evidence: R28Evidence, out: Path, run_id: str, verdict: str) -> int:
    record["closure_evidence"] = evidence.to_dict()
    record["verdict"] = verdict
    record["finished_utc"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    path = out / f"{run_id}-live28.json"
    path.write_text(json.dumps(record, indent=2, sort_keys=True, default=str) + "\n", encoding="utf-8")
    print(f"verdict: {verdict}\nevidence: {path}")
    return 0 if "R28-" in verdict else 1


if __name__ == "__main__":
    sys.exit(main())
