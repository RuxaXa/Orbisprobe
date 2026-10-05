#!/usr/bin/env python3
"""M2-LIVE2 — bounded split-view / TOCTOU testing on the real PS4.

Only valid A/B states, only user-owned memory, bounded writer (iterations + runtime), restore-bound,
no kernel write, no invalid pointer, no unbounded loop.

  plan   candidate records + chain-closure gates (no console)
  live2  full run: identity/ownership → static binding → baseline → negative control →
         phase-1 timing discovery → phase-2 bounded attempts → classification → minimisation
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import time
from pathlib import Path
from typing import Any

ROOT = Path(__file__).parents[1]
sys.path.insert(0, str(ROOT / "tests"))

from orbisprobe.live.evidence import EvidenceWriter
from orbisprobe.live.plan import canary_for
from orbisprobe.live.policy import LivePolicy
from orbisprobe.live.ps4_target import AdapterConfig, Ps4LiveTarget
from orbisprobe.live.splitview import (
    ESCALATED_MAX_ATTEMPTS,
    PHASE1_MAX_ATTEMPTS,
    PHASE2_MAX_ATTEMPTS,
    R2_A,
    R2_C,
    R2_D,
    R2_E,
    AttemptRecord,
    cand2_executable,
    cand3_case003,
    classify_attempts,
)
from orbisprobe.live.transport import WorkerConfig, WorkerConsoleTransport

DEFAULT_EVIDENCE = Path("/home/hermes/audits/ps4b-soc-workbench/live2-20260923")
FIELD_OFFSET = 0x100
PHASE1_CONFIGS = (
    {"ms": 20, "iters": 200},
    {"ms": 50, "iters": 1000},
    {"ms": 200, "iters": 5000},
)
MINIMISATION_CONFIGS = ({"ms": 50, "iters": 1000}, {"ms": 50, "iters": 200}, {"ms": 20, "iters": 50})


class Report:
    def __init__(self) -> None:
        self.rows: list[dict[str, Any]] = []

    def add(self, **row: Any) -> dict[str, Any]:
        self.rows.append(row)
        print(
            f"  {row.get('test', '?'):<12} {row.get('operation', ''):<24} "
            f"{row.get('result', '?'):<14}" + (f" {str(row.get('detail', ''))[:100]}" if row.get("detail") else "")
        )
        return row

    @property
    def failed(self) -> list[dict[str, Any]]:
        return [r for r in self.rows if r.get("result") in {"FAIL", R2_E}]


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def u64_field(canary: bytes, salt: int) -> int:
    """Deterministic u64 seed for the toggled field, derived from the canary and a salt."""

    return int.from_bytes(hashlib.sha256(canary + bytes([salt])).digest()[:8], "little") | 1


def attempt(
    target: Ps4LiveTarget,
    report: Report,
    record,
    *,
    attempt_id: str,
    value_a: int,
    value_b: int,
    config: dict[str, int],
    alternate: bool = True,
) -> AttemptRecord:
    writer_start = time.time()
    started = target.channel.request(
        "RACE",
        timeout=target.config.request_timeout,
        buf="a",
        off=FIELD_OFFSET,
        a=value_a,
        b=value_b,
        iters=config["iters"],
        ms=config["ms"],
        alt=1 if alternate else 0,
    )
    # the RACE command takes the plain offset inside the selected buffer
    request_start = time.time()
    response = target.channel.request(
        "DR", timeout=target.config.request_timeout, buf="a", off=FIELD_OFFSET
    )
    request_end = time.time()
    stopped = target.channel.request("RSTOP", timeout=target.config.request_timeout)

    ok = bool(response.get("ok"))
    w1 = response.get("w1", "")
    w2 = response.get("w2", "")
    t1, t2 = int(response.get("t1", 0) or 0), int(response.get("t2", 0) or 0)
    t_first = int(stopped.get("t_first", 0) or 0)
    t_last = int(stopped.get("t_last", 0) or 0)
    transitions = int(stopped.get("transitions", 0) or 0)
    overlap = bool(t_first and t_last and t_last >= t1 and t_first <= t2)
    rec = AttemptRecord(
        attempt_id=attempt_id,
        candidate_id="CAND-2",
        target_identity={},
        writer_start=int(writer_start * 1000),
        request_start=int(request_start * 1000),
        writer_events={
            "started": started.get("ok", False),
            "transitions": transitions,
            "t_first": t_first,
            "t_last": t_last,
            "overlap": overlap,
            "config": config,
            "alternate": alternate,
        },
        request_end=int(request_end * 1000),
        ab_transitions=transitions,
        observables={"other_rc": response.get("other_rc", "n/a")},
        status={"race_ok": bool(started.get("ok")), "dr_ok": ok, "rstop_ok": bool(stopped.get("ok"))},
        response_hash=sha(response.get("command", "").encode() + str(w1).encode() + str(w2).encode()),
        restore_result="PENDING",
        read_phase_1_value=w1,
        read_phase_2_value=w2,
        witness_source="payload-side timestamped double read (direct)",
        confidence="direct" if (w1 and w2 and w1 != w2) else "n/a",
        error=None if (ok and started.get("ok")) else f"dr={ok} race={started.get('ok')}",
    )
    return rec


def run_batch(
    target: Ps4LiveTarget,
    report: Report,
    record,
    *,
    label: str,
    value_a: int,
    value_b: int,
    config: dict[str, int],
    attempts: int,
    alternate: bool = True,
) -> tuple[list[AttemptRecord], bool, str | None]:
    records: list[AttemptRecord] = []
    overlap_seen = False
    fault: str | None = None
    for index in range(1, attempts + 1):
        rec = attempt(
            target, report, record,
            attempt_id=f"{label}-{index}", value_a=value_a, value_b=value_b,
            config=config, alternate=alternate,
        )
        records.append(rec)
        overlap_seen = overlap_seen or bool(rec.writer_events["overlap"])
        if rec.error:
            fault = f"attempt {rec.attempt_id}: {rec.error}"
            break
        if target.state_integrity_unknown:
            fault = "state integrity unknown"
            break
    return records, overlap_seen, fault


def restore_region(target: Ps4LiveTarget, record, original: bytes, test: str) -> dict[str, Any]:
    write = target.channel.request(
        "WRITE", timeout=target.config.write_timeout, mutation=True,
        kaddr=record.test_base, hex=original.hex(), buf="a",
    )
    verify = target.read_memory(record.test_base, len(original), test=f"{test}-verify")
    ok = bool(verify.get("ok")) and bytes.fromhex(verify["data_hex"]) == original
    return {"ok": ok, "restore_state": "RESTORED_CONFIRMED" if ok else "STATE_INTEGRITY_UNKNOWN",
            "sha256": verify.get("sha256", "unavailable"), "adapter_rc": write.get("ok")}


def plan_phase(out: Path) -> int:
    print("== LIVE2 candidates ==")
    ok_all = True
    for candidate in (cand2_executable(), cand3_case003()):
        allowed, blockers = candidate.gate()
        print(f"\n  {candidate.candidate_id}: executable={candidate.executable} gate={allowed}")
        for key, value in candidate.to_dict().items():
            print(f"    {key}: {str(value)[:130]}")
        if blockers:
            for blocker in blockers:
                print(f"    BLOCKER: {blocker}")
        (out / f"{candidate.candidate_id}-record.json").write_text(
            json.dumps({"candidate": candidate.to_dict(), "gate": {"executable": allowed, "blockers": blockers}},
                       indent=2, sort_keys=True) + "\n", encoding="utf-8")
        if candidate.executable and not allowed:
            ok_all = False
    return 0 if ok_all else 1


def live_phase(args: argparse.Namespace, evidence: EvidenceWriter, out: Path) -> int:
    report = Report()
    summary: dict[str, Any] = {
        "run_id": args.run_id, "phase": "live2", "console": args.console, "worker": args.worker,
        "started_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "candidates": {c.candidate_id: c.to_dict() for c in (cand2_executable(), cand3_case003())},
        "attempt_budget": {"phase1_max": PHASE1_MAX_ATTEMPTS, "phase2_max": PHASE2_MAX_ATTEMPTS,
                           "escalated_max": ESCALATED_MAX_ATTEMPTS},
    }
    cand2 = cand2_executable()
    allowed, blockers = cand2.gate()
    summary["candidate_gate"] = {"executable": allowed, "blockers": blockers}
    if not allowed:
        report.add(test="CAND", operation="candidate_gate", result="PLAN_ONLY", detail="; ".join(blockers))
        return _finish(report, summary, out, args.run_id)

    transport = WorkerConsoleTransport(WorkerConfig(ssh_target=args.worker, console_ip=args.console))
    try:
        build = transport.build_payload()
        summary["payload_build"] = build.to_dict()
        binary = transport.fetch_payload()
        summary["payload_binary_sha256"] = sha(binary)
        transport.start_bridge(lifetime=1800)
        send = transport.send_payload(binary)
        summary["payload_send"] = {k: v for k, v in send.items() if k != "body"}
        if not send.get("ok"):
            report.add(test="T1", operation="payload_delivery", result="FAIL", detail=str(send))
            return _finish(report, summary, out, args.run_id)
        report.add(test="T1", operation="payload_delivery", result="PASS",
                   detail=f"HTTP {send.get('status')} sha={send.get('sha256', '')[:16]}")
        transport.open_tunnel()
        channel = transport.open_channel(timeout=60)
        summary["greeting"] = getattr(channel, "greeting", "")

        target = Ps4LiveTarget(channel, policy=LivePolicy(level="LIVE0-U"), evidence=evidence,
                               config=AdapterConfig(console_host=args.console,
                                                    console_endpoint=f"{args.console}:9090"))
        info = target.get_target_info()
        if not info.get("ok"):
            report.add(test="R2", operation="target_info", result="FAIL", detail=str(info)[:120])
            return _finish(report, summary, out, args.run_id)
        identity = target.capture_identity()
        records, problems = target.capture_buffer_allocations(
            process_name=args.process_name, injection_pid=args.injection_pid,
            test_offset=FIELD_OFFSET, test_length=32,
        )
        report.add(test="OWN", operation="ownership", result="PASS" if len(records) == 2 else "FAIL",
                   detail=f"A=0x{records['A'].allocation_base:x} B=0x{records['B'].allocation_base:x}"
                          if len(records) == 2 else str(problems))
        if len(records) != 2:
            return _finish(report, summary, out, args.run_id)
        record = records["A"]

        # §15 static expectation binding
        static = {
            "candidate_id": "CAND-2",
            "read_set_1": f"load u64 @ 0x{record.test_base + FIELD_OFFSET:x} (phase 1)",
            "read_set_2": f"load u64 @ 0x{record.test_base + FIELD_OFFSET:x} (phase 2)",
            "intervening_calls": ["kernel copyout of buffer B", "writer-thread toggle"],
            "field_offsets": [FIELD_OFFSET],
            "binary_sha256": summary["payload_binary_sha256"],
            "kernel_base": f"0x{identity.kernel_base:x}",
            "session_id": identity.session_id,
            "pid": records["A"].pid,
            "instance": records["A"].payload_instance,
            "generation": records["A"].allocation_generation,
        }
        (out / f"{args.run_id}-static-binding.json").write_text(
            json.dumps(static, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        summary["static_binding"] = static

        original = target.read_memory(record.test_base, 32, test="ORIG")
        if not original.get("ok"):
            report.add(test="BASE", operation="baseline", result="FAIL", detail="unreadable")
            return _finish(report, summary, out, args.run_id)
        original_bytes = bytes.fromhex(original["data_hex"])
        summary["baseline"] = {"sha256": original["sha256"], "hex": original["data_hex"]}
        report.add(test="BASE", operation="baseline", result="PASS", detail=f"sha={original['sha256'][:16]}…")

        canary_a = canary_for(f"{args.run_id}-field-A", 32)
        canary_b = canary_for(f"{args.run_id}-field-B", 32)
        value_a, value_b = u64_field(canary_a, 1), u64_field(canary_b, 2)
        summary["values"] = {"value_a": f"0x{value_a:016x}", "value_b": f"0x{value_b:016x}",
                             "canary_a_sha256": sha(canary_a), "canary_b_sha256": sha(canary_b)}
        report.add(test="VALS", operation="A/B values", result="PASS",
                   detail=f"a=0x{value_a:x} b=0x{value_b:x} distinct={value_a != value_b}")

        # §14 negative control: A→A (writer toggles between the same value)
        neg_records, neg_overlap, neg_fault = run_batch(
            target, report, record, label="NEG-A2A", value_a=value_a, value_b=value_a,
            config=PHASE1_CONFIGS[1], attempts=20, alternate=False,
        )
        neg_split = [r for r in neg_records if r.read_phase_1_value != r.read_phase_2_value]
        summary["negative_control"] = {
            "attempts": len(neg_records), "splits": len(neg_split), "overlap": neg_overlap,
            "fault": neg_fault,
        }
        report.add(test="NEG-A2A", operation="negative_control",
                   result="PASS" if (not neg_split and not neg_fault) else "FAIL",
                   detail=f"attempts={len(neg_records)} splits={len(neg_split)} overlap={neg_overlap}")

        # §7 phase 1 timing discovery
        best_config, best_overlap = None, False
        phase1: dict[str, Any] = {}
        for index, config in enumerate(PHASE1_CONFIGS, start=1):
            records_cfg, overlap, fault = run_batch(
                target, report, record, label=f"P1C{index}", value_a=value_a, value_b=value_b,
                config=config, attempts=10,
            )
            phase1[f"config{index}"] = {
                "config": config, "attempts": len(records_cfg), "overlap": overlap, "fault": fault,
                "splits": len([r for r in records_cfg if r.read_phase_1_value != r.read_phase_2_value]),
            }
            report.add(test=f"P1C{index}", operation="timing_discovery",
                       result="PASS" if not fault else R2_E,
                       detail=f"{config} attempts={len(records_cfg)} overlap={overlap} "
                              f"splits={phase1[f'config{index}']['splits']}")
            if fault:
                summary["classification"] = R2_E
                summary["fault"] = fault
                break
            if overlap and best_config is None:
                best_config, best_overlap = config, True
        summary["phase1"] = phase1
        config = best_config or PHASE1_CONFIGS[1]

        # §8/§11 phase 2 bounded attempts
        attempts: list[AttemptRecord] = []
        overlap = best_overlap
        fault = summary.get("fault")
        for index, count in enumerate((PHASE2_MAX_ATTEMPTS,)):
            if fault:
                break
            batch, batch_overlap, batch_fault = run_batch(
                target, report, record, label=f"P2-{index + 1}", value_a=value_a, value_b=value_b,
                config=config, attempts=count,
            )
            attempts.extend(batch)
            overlap = overlap or batch_overlap
            fault = batch_fault
            splits = [r for r in attempts if r.read_phase_1_value != r.read_phase_2_value]
            report.add(test="P2", operation="bounded_attempts",
                       result="PASS" if not fault else R2_E,
                       detail=f"config={config} attempts={len(attempts)} overlap={overlap} splits={len(splits)}")
            if splits or fault:
                break

        classification, reason, detail = classify_attempts(attempts, writer_overlap=overlap, fault=fault)
        summary["phase2"] = {"attempts": len(attempts), "overlap": overlap, "config": config}
        summary["classification"] = classification
        summary["classification_reason"] = reason
        summary["classification_detail"] = detail
        report.add(test="CLASS", operation="classification", result=classification, detail=reason[:120])

        # §21 minimisation if a split was seen
        minimised: dict[str, Any] = {}
        if classification == R2_A:
            for index, mini in enumerate(MINIMISATION_CONFIGS, start=1):
                batch, mini_overlap, mini_fault = run_batch(
                    target, report, record, label=f"MIN{index}", value_a=value_a, value_b=value_b,
                    config=mini, attempts=10,
                )
                splits = len([r for r in batch if r.read_phase_1_value != r.read_phase_2_value])
                minimised[f"config{index}"] = {"config": mini, "attempts": len(batch),
                                               "splits": splits, "fault": mini_fault,
                                               "overlap": mini_overlap}
                report.add(test=f"MIN{index}", operation="minimisation",
                           result="PASS" if splits else "NO_SPLIT",
                           detail=f"{mini} splits={splits}/{len(batch)}")
                if splits:
                    break
        summary["minimisation"] = minimised

        # §13 restore after the batch
        restored = restore_region(target, record, original_bytes, "FINAL")
        summary["restore"] = restored
        report.add(test="FINAL", operation="restore_verify",
                   result="PASS" if restored["ok"] else "FAIL",
                   detail=f"restore={restored['restore_state']} sha={restored['sha256'][:16]}…")
        summary["attempts"] = [r.to_dict() for r in attempts]
        summary["negative_control_attempts"] = [r.to_dict() for r in neg_records]
        summary["state_integrity"] = (
            "OK" if restored["ok"] and not target.state_integrity_unknown else "STATE_INTEGRITY_UNKNOWN"
        )
        target.close()
    finally:
        transport.close()
    return _finish(report, summary, out, args.run_id)


def _finish(report: Report, summary: dict[str, Any], out: Path, run_id: str) -> int:
    summary["finished_utc"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    summary["rows"] = report.rows
    summary["failures"] = report.failed
    split_or_clean = summary.get("classification") in {R2_A, R2_C, R2_D, None}
    summary["verdict"] = "PASS" if report.rows and not report.failed and split_or_clean else "NOT DONE"
    path = out / f"{run_id}-live2-summary.json"
    path.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print("\n== summary ==")
    print(f"  rows: {len(report.rows)} failures: {len(report.failed)}")
    print(f"  classification: {summary.get('classification')}")
    print(f"  verdict: {summary['verdict']}")
    print(f"  evidence: {path}")
    return 0 if summary["verdict"] == "PASS" else 1


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--phase", choices=["plan", "live2"], default="plan")
    parser.add_argument("--evidence-dir", default=str(DEFAULT_EVIDENCE))
    parser.add_argument("--run-id", default=time.strftime("live2-%Y%m%dT%H%M%S"))
    parser.add_argument("--console", default="192.168.1.141")
    parser.add_argument("--worker", default="neo@192.168.1.148")
    parser.add_argument("--process-name", default="unknown")
    parser.add_argument("--injection-pid", type=int, default=None)
    args = parser.parse_args()
    out = Path(args.evidence_dir)
    out.mkdir(parents=True, exist_ok=True)
    if args.phase == "plan":
        return plan_phase(out)
    return live_phase(args, EvidenceWriter(out, args.run_id), out)


if __name__ == "__main__":
    sys.exit(main())
