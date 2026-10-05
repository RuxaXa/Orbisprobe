#!/usr/bin/env python3
"""M2-LIVE2.1 — overlap / timing engine closure on the real PS4.

Proves that the bounded writer actually mutates *during* the request window before any split-view
statement is made. Same candidate (CAND-2), same validity class, same two valid values.

  RACE (mode/max_trans/max_ms) → [writer_ready] → DR (t1/w1/w2/t2) → RSTOP [request_done] → RTRACE

Classification (§5): T2-A OVERLAP_CONFIRMED (only then split-view is evaluated), T2-B NO_OVERLAP,
T2-C TIMING_UNKNOWN, T2-D fault → STOP.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path
from typing import Any

ROOT = Path(__file__).parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from live2_toctou import (
    DEFAULT_EVIDENCE,
    FIELD_OFFSET,
    Report,
    restore_region,
    sha,
    u64_field,
)

from orbisprobe.live.evidence import EvidenceWriter
from orbisprobe.live.plan import canary_for
from orbisprobe.live.policy import LivePolicy
from orbisprobe.live.ps4_target import AdapterConfig, Ps4LiveTarget
from orbisprobe.live.splitview import (
    MAX_ATTEMPTS_PER_CONFIG,
    MAX_TRANSITIONS,
    MAX_WRITER_MS,
    PHASE1_ATTEMPTS_PER_CONFIG,
    SCHED_MODES,
    SPLIT_VIEW_CONFIRMED,
    T2_A,
    T2_B,
    T2_C,
    T2_D,
    cand2_executable,
    cand3_case003,
    classify_overlap,
    classify_split,
    negative_control_verdict,
    parse_trace,
    should_escalate,
    transitions_inside,
)
from orbisprobe.live.transport import WorkerConfig, WorkerConsoleTransport

CONFIGS = tuple({"mode": mode, "label": label, "max_ms": 100, "max_trans": 100000}
                for label, mode in SCHED_MODES)


def run_one(
    target: Ps4LiveTarget, record, *, attempt_id: str, value_a: int, value_b: int,
    config: dict[str, Any], alternate: bool = True,
) -> dict[str, Any]:
    """One synchronised attempt: ready → request → request_done → trace."""

    response = target.channel.request(
        "DRW", timeout=target.config.request_timeout, buf="a", off=FIELD_OFFSET,
        a=value_a, b=value_b, mode=config["mode"], ms=config["max_ms"],
        alt=1 if alternate else 0,
    )
    writer_ready = bool(response.get("ready") in (1, "1", True))
    trace = parse_trace(response)
    t1 = int(response.get("rst", 0) or 0)   # request_start, payload-side, immediately before read 1
    t2 = int(response.get("rdone", 0) or 0)  # request_done, payload-side, immediately after read 2
    w1, w2 = response.get("w1", ""), response.get("w2", "")
    transitions = int(response.get("trans", 0) or 0)
    fault = None
    if not response.get("ok"):
        fault = f"protocol error: drw={response.get('ok')} err={response.get('msg', '')}"
    overlap_class, overlap_reason, overlap_detail = classify_overlap(
        t1_us=t1, t2_us=t2, trace=trace, writer_ran=bool(transitions) and writer_ready, fault=fault
    )
    split_class, split_reason = classify_split(w1, w2, overlap_class)
    inside = transitions_inside(trace, t1, t2)
    return {
        "attempt_id": attempt_id,
        "candidate_id": "CAND-2",
        "config": {k: config[k] for k in ("label", "mode", "max_ms", "max_trans")},
        "alternate": alternate,
        "writer_ready": writer_ready,
        "transitions": transitions,
        "transitions_inside_request_window": len(inside),
        "request_window_us": (t2 - t1) if (t1 and t2) else None,
        "t_first": min((e["timestamp_us"] for e in trace), default=0),
        "t_last": max((e["timestamp_us"] for e in trace), default=0),
        "writer_done": bool(response.get("ready") in (1, "1", True)),
        "t1_us": t1, "t2_us": t2,
        "w1": w1, "w2": w2,
        "read_phase_1": {"value": w1, "timestamp_us": t1},
        "read_phase_2": {"value": w2, "timestamp_us": t2},
        "overlap_class": overlap_class,
        "overlap_reason": overlap_reason,
        "overlap_inside": overlap_detail.get("inside", []),
        "split_class": split_class,
        "split_reason": split_reason,
        "other_rc": response.get("other_rc", "n/a"),
        "ring_total": int(response.get("ring_total", 0) or 0),
        "trace": trace,
        "fault": fault,
    }


def run_batch(
    target: Ps4LiveTarget, report: Report, record, *, label: str, value_a: int, value_b: int,
    config: dict[str, Any], attempts: int, alternate: bool = True,
) -> tuple[list[dict[str, Any]], str | None]:
    rows: list[dict[str, Any]] = []
    fault: str | None = None
    for index in range(1, attempts + 1):
        row = run_one(target, record, attempt_id=f"{label}-{index}", value_a=value_a,
                      value_b=value_b, config=config, alternate=alternate)
        rows.append(row)
        if row["fault"]:
            fault = f"{row['attempt_id']}: {row['fault']}"
            break
        if target.state_integrity_unknown:
            fault = "state integrity unknown"
            break
    inside = sum(1 for r in rows if r["transitions_inside_request_window"] >= 1)
    report.add(test=label, operation="batch",
               result="PASS" if not fault else T2_D,
               detail=(f"{config['label']} attempts={len(rows)} overlap={inside} "
                       f"overlap_rate={inside / max(len(rows), 1):.2f} "
                       f"trans/req={sum(r['transitions_inside_request_window'] for r in rows) / max(len(rows), 1):.1f} "
                       f"splits={sum(1 for r in rows if r['split_class'] == SPLIT_VIEW_CONFIRMED)}"))
    return rows, fault


def live_phase(args: argparse.Namespace, out: Path, evidence: EvidenceWriter) -> int:
    report = Report()
    summary: dict[str, Any] = {
        "run_id": args.run_id, "phase": "live2.1", "console": args.console, "worker": args.worker,
        "started_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "candidate": cand2_executable().to_dict(),
        "case003": {"candidate_id": "CAND-3", "status": "PLAN_ONLY",
                    "record": cand3_case003().to_dict()},
        "scheduling_modes": [c[0] for c in SCHED_MODES],
        "writer_limits": {"max_ms": MAX_WRITER_MS, "max_trans": MAX_TRANSITIONS},
        "attempt_budgets": {"phase1_per_config": PHASE1_ATTEMPTS_PER_CONFIG,
                            "max_per_config": MAX_ATTEMPTS_PER_CONFIG, "escalated_max": 1000},
        "timestamp_unit": "microseconds (sceKernelGetProcessTime)",
    }
    cand2 = cand2_executable()
    allowed, blockers = cand2.gate()
    summary["candidate_gate"] = {"executable": allowed, "blockers": blockers}
    transport = WorkerConsoleTransport(WorkerConfig(ssh_target=args.worker, console_ip=args.console))
    try:
        build = transport.build_payload()
        summary["payload_build"] = build.to_dict()
        binary = transport.fetch_payload()
        summary["payload_binary_sha256"] = sha(binary)
        transport.start_bridge(lifetime=1800)
        send = transport.send_payload(binary)
        summary["payload_send"] = {k: v for k, v in send.items() if k != "body"}
        report.add(test="T1", operation="payload_delivery", result="PASS" if send.get("ok") else "FAIL",
                   detail=f"HTTP {send.get('status')}")
        if not send.get("ok"):
            return _finish(report, summary, out, args.run_id)
        transport.open_tunnel()
        channel = transport.open_channel(timeout=60)
        target = Ps4LiveTarget(channel, policy=LivePolicy(level="LIVE0-U"), evidence=evidence,
                               config=AdapterConfig(console_host=args.console,
                                                    console_endpoint=f"{args.console}:9090"))
        info = target.get_target_info()
        if not info.get("ok"):
            report.add(test="T2", operation="target_info", result="FAIL", detail=str(info)[:120])
            return _finish(report, summary, out, args.run_id)
        identity = target.capture_identity()
        records, problems = target.capture_buffer_allocations(
            process_name=args.process_name, injection_pid=args.injection_pid,
            test_offset=FIELD_OFFSET, test_length=32)
        report.add(test="OWN", operation="ownership", result="PASS" if len(records) == 2 else "FAIL",
                   detail=f"A=0x{records['A'].allocation_base:x} B=0x{records['B'].allocation_base:x}"
                          if len(records) == 2 else str(problems))
        if len(records) != 2:
            return _finish(report, summary, out, args.run_id)
        record = records["A"]
        summary["static_binding"] = {
            "candidate_id": "CAND-2",
            "read_set_1": f"load u64 @ 0x{record.test_base + FIELD_OFFSET:x} (phase 1, timestamped)",
            "read_set_2": f"load u64 @ 0x{record.test_base + FIELD_OFFSET:x} (phase 2, timestamped)",
            "intervening_calls": ["kernel copyout of buffer B", "writer-thread toggle loop"],
            "binary_sha256": summary["payload_binary_sha256"],
            "kernel_base": f"0x{identity.kernel_base:x}", "session_id": identity.session_id,
            "pid": record.pid, "instance": record.payload_instance,
            "generation": record.allocation_generation,
        }
        original = target.read_memory(record.test_base, 32, test="ORIG")
        if not original.get("ok"):
            report.add(test="BASE", operation="baseline", result="FAIL", detail="unreadable")
            return _finish(report, summary, out, args.run_id)
        original_bytes = bytes.fromhex(original["data_hex"])
        summary["baseline"] = {"sha256": original["sha256"], "hex": original["data_hex"]}

        canary_a = canary_for(f"{args.run_id}-field-A", 32)
        canary_b = canary_for(f"{args.run_id}-field-B", 32)
        value_a, value_b = u64_field(canary_a, 1), u64_field(canary_b, 2)
        summary["values"] = {"value_a": f"0x{value_a:016x}", "value_b": f"0x{value_b:016x}",
                             "canary_a_sha256": sha(canary_a), "canary_b_sha256": sha(canary_b)}
        report.add(test="VALS", operation="A/B values", result="PASS" if value_a != value_b else "FAIL",
                   detail=f"a=0x{value_a:x} b=0x{value_b:x}")

        # §7 negative control: same writer machine, always value A
        neg_rows, neg_fault = run_batch(target, report, record, label="NEG-A2A", value_a=value_a,
                                        value_b=value_a, config=CONFIGS[0],
                                        attempts=PHASE1_ATTEMPTS_PER_CONFIG, alternate=False)
        neg_witnesses = [(r["w1"], r["w2"], r["overlap_class"] == T2_A) for r in neg_rows]
        neg_ok, neg_reason = negative_control_verdict(neg_witnesses)
        neg_overlap = sum(1 for r in neg_rows if r["overlap_class"] == T2_A)
        summary["negative_control"] = {"attempts": len(neg_rows), "overlap": neg_overlap,
                                       "ok": neg_ok, "reason": neg_reason, "fault": neg_fault,
                                       "rows": neg_rows}
        report.add(test="NEG-A2A", operation="negative_control", result="PASS" if neg_ok and not neg_fault else "FAIL",
                   detail=f"attempts={len(neg_rows)} overlap={neg_overlap} {neg_reason[:70]}")
        if not neg_ok or neg_fault:
            summary["classification"] = T2_D
            summary["stopped"] = "negative control broke the measurement model"
            summary["restore"] = restore_region(target, record, original_bytes, "FINAL-NEG")
            return _finish(report, summary, out, args.run_id)

        # §8 phase 1: 20 attempts per scheduling mode, adjust timing (not iteration count) until overlap
        phase1: dict[str, Any] = {}
        best = None
        all_rows: list[dict[str, Any]] = []
        fault: str | None = None
        for config in CONFIGS:
            rows, batch_fault = run_batch(target, report, record, label=f"P1-{config['label']}",
                                          value_a=value_a, value_b=value_b, config=config,
                                          attempts=PHASE1_ATTEMPTS_PER_CONFIG)
            inside = sum(1 for r in rows if r["transitions_inside_request_window"] >= 1)
            phase1[config["label"]] = {"config": config, "attempts": len(rows), "overlap_attempts": inside,
                                       "overlap_rate": inside / max(len(rows), 1),
                                       "transitions_inside_total":
                                           sum(r["transitions_inside_request_window"] for r in rows),
                                       "fault": batch_fault}
            all_rows.extend(rows)
            if batch_fault:
                fault = batch_fault
                break
            if inside and best is None:
                best = config
        summary["phase1"] = phase1

        # §8/§9 phase 2: continue with the mode that produced overlap (bounded)
        phase2: dict[str, Any] = {}
        config = best or CONFIGS[0]
        if not fault:
            rate = phase1.get(config["label"], {}).get("overlap_rate", 0.0)
            budget = MAX_ATTEMPTS_PER_CONFIG if should_escalate(rate) else 1000
            budget = min(budget, 1000 - len(all_rows)) if should_escalate(rate) else MAX_ATTEMPTS_PER_CONFIG
            rows, fault = run_batch(target, report, record, label=f"P2-{config['label']}",
                                    value_a=value_a, value_b=value_b, config=config, attempts=budget)
            all_rows.extend(rows)
            inside = sum(1 for r in rows if r["transitions_inside_request_window"] >= 1)
            phase2 = {"config": config, "attempts": len(rows), "overlap_attempts": inside,
                      "overlap_rate": inside / max(len(rows), 1),
                      "escalated": should_escalate(rate)}
        summary["phase2"] = phase2

        # §4/§5/§6: only T2-A attempts feed the split-view statement
        overlap_attempts = [r for r in all_rows if r["overlap_class"] == T2_A]
        splits = [r for r in overlap_attempts if r["split_class"] == SPLIT_VIEW_CONFIRMED]
        classes = [r["overlap_class"] for r in all_rows]
        overall = T2_D if fault else (T2_A if overlap_attempts else (T2_B if all_rows else T2_C))
        if fault:
            classification = T2_D
        elif overlap_attempts and splits:
            classification = SPLIT_VIEW_CONFIRMED
        elif overlap_attempts:
            classification = "OVERLAP_CONFIRMED / NO_SPLIT_VIEW_OBSERVED"
        else:
            classification = T2_B if any(r["transitions"] for r in all_rows) else T2_C
        summary["overlap_engine"] = {
            "attempts": len(all_rows), "overlap_attempts": len(overlap_attempts),
            "overlap_rate": len(overlap_attempts) / max(len(all_rows), 1),
            "transitions_inside_total": sum(r["transitions_inside_request_window"] for r in all_rows),
            "transitions_total": sum(r["transitions"] for r in all_rows),
            "w1_eq_w2": sum(1 for r in all_rows if r["w1"] == r["w2"]),
            "w1_ne_w2": sum(1 for r in all_rows if r["w1"] != r["w2"]),
            "split_count": len(splits),
            "per_class": {c: classes.count(c) for c in (T2_A, T2_B, T2_C, T2_D)},
            "fault": fault,
        }
        summary["classification"] = classification
        summary["best_trace"] = (overlap_attempts[0] if overlap_attempts else (all_rows[0] if all_rows else {}))
        report.add(test="CLASS", operation="timing_engine", result=overall, detail=classification)
        summary["attempts"] = all_rows

        restored = restore_region(target, record, original_bytes, "FINAL")
        summary["restore"] = restored
        report.add(test="FINAL", operation="restore_verify",
                   result="PASS" if restored["ok"] else "FAIL",
                   detail=f"{restored['restore_state']} sha={restored['sha256'][:16]}…")
        summary["state_integrity"] = ("OK" if restored["ok"] and not target.state_integrity_unknown
                                      else "STATE_INTEGRITY_UNKNOWN")
        target.close()
    finally:
        transport.close()
    return _finish(report, summary, out, args.run_id)


def _finish(report: Report, summary: dict[str, Any], out: Path, run_id: str) -> int:
    summary["finished_utc"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    summary["rows"] = report.rows
    summary["failures"] = report.failed
    ok = (report.rows and not report.failed
          and summary.get("state_integrity", "OK") == "OK"
          and summary.get("classification") != T2_D)
    summary["verdict"] = "PASS" if ok else "NOT DONE"
    path = out / f"{run_id}-live21-summary.json"
    path.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print("\n== summary ==")
    print(f"  rows: {len(report.rows)} failures: {len(report.failed)}")
    print(f"  timing engine: {summary.get('overlap_engine', {}).get('per_class')}")
    print(f"  overlap rate: {summary.get('overlap_engine', {}).get('overlap_rate')}")
    print(f"  split count: {summary.get('overlap_engine', {}).get('split_count')}")
    print(f"  classification: {summary.get('classification')}")
    print(f"  verdict: {summary['verdict']}\n  evidence: {path}")
    return 0 if ok else 1


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--phase", choices=["live21"], default="live21")
    parser.add_argument("--evidence-dir", default=str(DEFAULT_EVIDENCE))
    parser.add_argument("--run-id", default=time.strftime("live21-%Y%m%dT%H%M%S"))
    parser.add_argument("--console", default="192.168.1.141")
    parser.add_argument("--worker", default="neo@192.168.1.148")
    parser.add_argument("--process-name", default="ScePartyDaemon")
    parser.add_argument("--injection-pid", type=int, default=None)
    args = parser.parse_args()
    out = Path(args.evidence_dir)
    out.mkdir(parents=True, exist_ok=True)
    json.dump(cand3_case003().to_dict(), (out / "CAND-3-record.json").open("w", encoding="utf-8"),
              indent=2, sort_keys=True)
    return live_phase(args, out, EvidenceWriter(out, args.run_id))


if __name__ == "__main__":
    sys.exit(main())
