#!/usr/bin/env python3
"""LIVE2.2.2 — read-only attach diagnostic (§11). No TR, no WRITE, no race.

preflight (read-only) → stop stale bridge → fresh bridge → delivery → wait START → wait GREETING →
instance validation → bind → INFO/PING → QUIT. Every step has its own timeout and the failure state is
named exactly, never flattened into "payload did not attach".
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

from live2_toctou import DEFAULT_EVIDENCE, sha

from orbisprobe.live.attach import (
    READY,
    STALE_ATTACHMENT,
    InstanceLedger,
    SingleGreetingOwner,
    Timeouts,
    capture_log_baseline,
    classify,
    preflight,
    validate_greeting,
    wait_for_start,
)
from orbisprobe.live.channel import ConsoleChannel
from orbisprobe.live.transport import WorkerConfig, WorkerConsoleTransport


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--evidence-dir", default=str(DEFAULT_EVIDENCE))
    parser.add_argument("--run-id", default=time.strftime("attach-%Y%m%dT%H%M%S"))
    parser.add_argument("--console", default="192.168.1.141")
    parser.add_argument("--worker", default="neo@192.168.1.148")
    args = parser.parse_args()
    out = Path(args.evidence_dir)
    out.mkdir(parents=True, exist_ok=True)
    timeouts = Timeouts()
    record: dict = {"run_id": args.run_id, "phase": "attach-diagnostic", "read_only": True,
                    "timeouts": timeouts.__dict__, "utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}

    transport = WorkerConsoleTransport(WorkerConfig(ssh_target=args.worker, console_ip=args.console))
    ssh = lambda cmd: transport.ssh(cmd).stdout
    verdict = "NOT DONE"
    try:
        # §8 ordering: discard any previous bridge session FIRST, so the preflight judges a fresh log
        # (a still-bound payload session from an earlier attempt would otherwise block a new delivery)
        existing = preflight(ssh, console_ip=args.console, console_port=transport.config.payload_port,
                             host_port=transport.config.bridge_host_port,
                             bridge_log="/tmp/console_bridge.log")
        record["preflight_before_reset"] = existing.to_dict()
        print(f"[1] previous session check: bridge_pid={existing.bridge_pid or '-'} "
              f"stale_payload={len(existing.stale_payload_connections)} log_lines={existing.log_lines}")
        if existing.bridge_pid or existing.stale_payload_connections:
            print("[2] discarding the previous bridge session (worker-side only)")
            record["bridge_stop"] = transport.stop_bridge()

        started = transport.start_bridge(lifetime=900)
        record["bridge_start"] = started
        print(f"    bridge: {str(started)[:120]}")
        if "BRIDGE-STARTED" not in str(started):
            record["classification"] = "BRIDGE_BIND_TIMEOUT"
            record["detail"] = str(started)[:200]
            return _finish(record, out, args.run_id, "NOT DONE (BRIDGE_BIND_TIMEOUT)")

        build = transport.build_payload()
        record["payload_build"] = build.to_dict()
        print(f"    build: {str(build.to_dict())[:100]}")
        print("[3] preflight on the fresh session (read-only, no loader probe)")
        pre = preflight(ssh, console_ip=args.console, console_port=transport.config.payload_port,
                        host_port=transport.config.bridge_host_port,
                        bridge_log="/tmp/console_bridge.log")
        record["preflight"] = pre.to_dict()
        print(f"    icmp={pre.non_loader_context.get('icmp')} loader_state={pre.loader_state} "
              f"bridge_pid={pre.bridge_pid or '-'} listen={pre.bridge_listen_sockets} "
              f"stale_payload={len(pre.stale_payload_connections)} log_lines={pre.log_lines}")
        print("    (loader port deliberately not probed: bare connects can put the single-shot "
              "endpoint into an error state - reachability is decided by the delivery attempt)")
        if not pre.ok:
            record["classification"] = pre.classification or STALE_ATTACHMENT
            record["detail"] = "; ".join(pre.blockers)
            return _finish(record, out, args.run_id, f"NOT DONE ({pre.classification or STALE_ATTACHMENT})")
        # clock-free witness baseline: only lines that appear AFTER this snapshot count as a start
        bridge_baseline = capture_log_baseline(ssh, "/tmp/console_bridge.log")
        binary = transport.fetch_payload()
        delivered_epoch = time.time()
        print(f"[3] delivery ({len(binary)} bytes, sha256 {sha(binary)[:16]}…)")
        delivery = transport.send_payload(binary, timeout=timeouts.loader_delivery)
        record["delivery"] = {k: v for k, v in delivery.items() if k != "body"}
        record["delivered_epoch"] = delivered_epoch
        delivered = bool(delivery.get("ok"))
        print(f"    loader: ok={delivered} status={delivery.get('status')}")

        print(f"[4] waiting for the payload start witness (max {timeouts.payload_start}s)")
        start = wait_for_start(ssh, bridge_log="/tmp/console_bridge.log",
                               delivered_epoch=delivered_epoch, timeout=timeouts.payload_start,
                               baseline=bridge_baseline)
        record["start_witness"] = start.to_dict()
        print(f"    start_observed={start.observed} {start.evidence[:80]}")

        greeting_ok, bound, greeting_text = False, False, ""
        if start.observed:
            print(f"[5] binding the channel (bridge bind, then greeting, max {timeouts.greeting}s)")
            try:
                transport.open_tunnel()
                sock = socket.create_connection(("127.0.0.1", transport.config.local_port), timeout=10)
                owner = SingleGreetingOwner()
                channel = ConsoleChannel(sock, default_timeout=timeouts.greeting)
                if not owner.consume():
                    raise RuntimeError("greeting stream already consumed by another reader")
                greeting_text = channel.recv_frame(timeout=timeouts.greeting).decode("utf-8", "replace")
                channel.greeting = greeting_text  # type: ignore[attr-defined]
                bound = True
                ledger = InstanceLedger(out / "payload-instances.json")
                greeting_ok, violations, info = validate_greeting(
                    greeting_text, previous_instances=ledger.instances(), delivered_epoch=delivered_epoch)
                record["greeting"] = info
                record["greeting_violations"] = violations
                print(f"    greeting: {greeting_text.strip()[:110]}")
                if greeting_ok:
                    ledger.record(info["instance"], run_id=args.run_id,
                                  pid=info["greeting"].get("pid", ""),
                                  firmware=info["greeting"].get("fw", ""))
                    ping = channel.request("PING", timeout=10)
                    info_resp = channel.request("INFO", timeout=10)
                    record["ping"] = ping
                    record["info"] = info_resp
                    print(f"    PING ok={ping.get('ok')} INFO ok={info_resp.get('ok')} "
                          f"pid={info_resp.get('pid')} instance={info_resp.get('instance', info['instance'])}")
                    quit_resp = channel.request("QUIT", timeout=10)
                    record["quit"] = quit_resp
                    print(f"    QUIT ok={quit_resp.get('ok')} ({quit_resp.get('reason', '')})")
                channel.close()
            except Exception as exc:  # noqa: BLE001 - the failure class is what matters here
                record["channel_error"] = f"{type(exc).__name__}: {exc}"
                print(f"    channel error: {record['channel_error'][:120]}")
        classification, detail = classify(preflight_ok=pre.ok, delivered=delivered, start=start,
                                          greeting_ok=greeting_ok, bound=bound,
                                          delivery_error=str(delivery.get("error", "")))
        record["classification"] = classification
        record["detail"] = detail
        print(f"[6] classification: {classification} — {detail}")
        verdict = "PASS (READY)" if classification == READY else f"NOT DONE ({classification})"
    finally:
        transport.close()
    return _finish(record, out, args.run_id, verdict)


def _finish(record: dict, out: Path, run_id: str, verdict: str) -> int:
    record["verdict"] = verdict
    record["finished_utc"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    path = out / f"{run_id}-attach.json"
    path.write_text(json.dumps(record, indent=2, sort_keys=True, default=str) + "\n", encoding="utf-8")
    print(f"verdict: {verdict}\nevidence: {path}")
    return 0 if verdict.startswith("PASS") else 1


if __name__ == "__main__":
    sys.exit(main())
