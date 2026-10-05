#!/usr/bin/env python3
"""LIVE2.8 probe: verify the KASLR rebase semantics with three bounded kernel reads.

READ only (no WRITE, no RACE, no ioctl). The first read is the decisive one: the kernel image starts
with the ELF magic, so reading it at the payload-reported base proves or disproves the rebase model.
"""

from __future__ import annotations

import json
import socket
import sys
import time
from pathlib import Path

ROOT = Path(__file__).parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT))

from orbisprobe.live.attach import (
    InstanceLedger,
    SingleGreetingOwner,
    capture_log_baseline,
    preflight,
    validate_greeting,
    wait_for_start,
)
from orbisprobe.live.channel import ConsoleChannel
from orbisprobe.live.transport import WorkerConfig, WorkerConsoleTransport

DUMP_BASE = 0xFFFFFFFFD00D0000
PRISON0_DELTA = 0x1A5C0C0          # validated in LIVE0: PRISON0 == kbase + 0x1a5c0c0
ANCHOR_STATIC = 0xFFFFFFFFD2458A28


def main() -> int:
    out = Path("/home/hermes/audits/ps4b-soc-workbench/live28-20260923")
    out.mkdir(parents=True, exist_ok=True)
    record: dict = {"mode": "READ-ONLY rebase probe", "reads": []}
    transport = WorkerConsoleTransport(WorkerConfig(ssh_target="neo@192.168.1.148", console_ip="192.168.1.141"))
    ssh = lambda cmd: transport.ssh(cmd).stdout
    try:
        existing = preflight(ssh, console_ip="192.168.1.141", console_port=9090, host_port=9026,
                             bridge_log="/tmp/console_bridge.log")
        if existing.bridge_pid or existing.stale_payload_connections:
            transport.stop_bridge()
        started = transport.start_bridge(lifetime=600)
        record["bridge_start"] = started
        baseline = capture_log_baseline(ssh, "/tmp/console_bridge.log")
        binary = transport.fetch_payload()
        delivered = time.time()
        delivery = transport.send_payload(binary, timeout=20)
        record["delivery"] = {k: v for k, v in delivery.items() if k != "body"}
        start = wait_for_start(ssh, bridge_log="/tmp/console_bridge.log", delivered_epoch=delivered,
                               timeout=45, baseline=baseline)
        record["start_witness"] = start.to_dict()
        if not start.observed:
            record["verdict"] = "NOT DONE (payload start not observed)"
            return _finish(record, out)
        transport.open_tunnel()
        channel = ConsoleChannel(socket.create_connection(("127.0.0.1", transport.config.local_port), timeout=10),
                                 default_timeout=30)
        owner = SingleGreetingOwner()
        owner.consume()
        greeting = channel.recv_frame(timeout=30).decode("utf-8", "replace")
        ledger = InstanceLedger(out / "payload-instances.json")
        ok, violations, info = validate_greeting(greeting, previous_instances=ledger.instances(),
                                                delivered_epoch=delivered)
        record["greeting"] = info
        if not ok:
            record["verdict"] = f"NOT DONE (greeting rejected: {violations})"
            return _finish(record, out)
        ledger.record(info["instance"], run_id=f"probe-{int(time.time())}", pid=info["greeting"].get("pid", ""),
                      firmware=info["greeting"].get("fw", ""))
        target_info = channel.request("INFO", timeout=15)
        kbase = int(str(target_info.get("kbase", "0x0")), 16)
        record["kbase"] = f"0x{kbase:x}"
        record["rebase_delta"] = f"0x{kbase - DUMP_BASE:x}"
        probes = {
            "kbase_head": kbase,
            "prison0_slot": kbase + PRISON0_DELTA,
            "anchor_rebased": ANCHOR_STATIC + (kbase - DUMP_BASE),
            "anchor_static_raw": ANCHOR_STATIC,
        }
        for label, address in probes.items():
            response = channel.request("READ", timeout=15, kaddr=address, len=0x20)
            entry = {"label": label, "address": f"0x{address:x}", "ok": bool(response.get("ok")),
                     "msg": response.get("msg", ""), "code": response.get("code", ""),
                     "hex": str(response.get("hex", ""))[:64]}
            record["reads"].append(entry)
            print(f"  {label:18} 0x{address:x} ok={entry['ok']} msg={entry['msg']} hex={entry['hex'][:32]}")
        head = record["reads"][0]["hex"]
        magic_ok = head.startswith("7f454c46")
        record["rebase_model_verified"] = magic_ok      # recorded before any further request
        channel.request("QUIT", timeout=10)
        channel.close()
        record["verdict"] = ("REBASE_MODEL_CONFIRMED (ELF magic at kbase)" if magic_ok else
                             "REBASE_MODEL_NOT_CONFIRMED (kbase does not start with ELF magic)")
        print("verdict:", record["verdict"])
    except Exception as exc:  # noqa: BLE001
        record["error"] = f"{type(exc).__name__}: {exc}"
        record["verdict"] = f"NOT DONE ({type(exc).__name__})"
        print("error:", record["error"][:160])
    finally:
        transport.close()
    return _finish(record, out)


def _finish(record: dict, out: Path) -> int:
    path = out / f"probe-{time.strftime('%Y%m%dT%H%M%S')}.json"
    path.write_text(json.dumps(record, indent=2, sort_keys=True, default=str) + "\n", encoding="utf-8")
    print("evidence:", path)
    return 0


if __name__ == "__main__":
    sys.exit(main())
