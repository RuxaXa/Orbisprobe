#!/usr/bin/env python3
"""M2-LIVE1 — deterministic A/B on the real PS4 (host-side consumer).

One controlled variable changes between A and B. A and B are two separate payload-owned
allocations with equal size, equal permissions, equal ownership class, equal lifecycle class, both
non-persistent, non-MMIO, non-kernel, non-secure. Nothing is toggled during a single operation —
no race, no invalid input, no kernel write.

Candidate (CAND-1): the kernel-copyout consumer (the payload's proven ``get_memory_dump`` path,
exposed as ``KREAD_USER``) reading the selected payload-owned buffer.

Phases:
  plan      candidate record + gate only (no console)
  live1     full sequence: identity → ownership(A/B) → baseline → negative control → A → B →
            content/address control → repeat A2/B2 → classification → evidence
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


from orbisprobe.live.abexperiment import (
    ExperimentRecord,
    classify_pair,
    noise_fields,
)
from orbisprobe.live.candidate import CandidateRecord
from orbisprobe.live.evidence import EvidenceWriter
from orbisprobe.live.plan import RestoreSteps, WriteOp, canary_for
from orbisprobe.live.policy import LivePolicy
from orbisprobe.live.ps4_target import AdapterConfig, Ps4LiveTarget
from orbisprobe.live.transport import WorkerConfig, WorkerConsoleTransport

DEFAULT_EVIDENCE = Path("/home/hermes/audits/ps4b-soc-workbench/live1-20260923")
TEST_OFFSET = 0x100
CANARY_LEN = 32
CONSUMER = "kernel copyout of the selected payload-owned user buffer (payload KREAD_USER path)"

CANDIDATE = CandidateRecord(
    candidate_id="CAND-1",
    hypothesis=(
        "The kernel copyout consumer returns exactly the bytes held by the selected payload-owned "
        "user buffer, so changing only which buffer is consumed (A vs B) changes only the consumed "
        "buffer observable and nothing else."
    ),
    controlled_field="which payload-owned user buffer the consumer reads (A vs B)",
    value_a="buffer A (own allocation, generation A)",
    value_b="buffer B (own allocation, generation B)",
    validation={
        "valid_a": True,
        "valid_b": True,
        "same_shape": True,
        "evidence": (
            "A and B are separate payload mmap allocations of 0x1000 bytes, both reported with "
            "allocation return == base, generation >= 1; ownership confirmed per buffer; both "
            "readable and writable through the adapter"
        ),
    },
    consumer=CONSUMER,
    expected_effect="consumed-buffer observable equals the selected buffer's content; rc=0 for both arms",
    observable=(
        "consumed_buffer_sha256",
        "status_rc",
        "other_buffer_sha256",
        "klog_delta",
    ),
    risk="low: two valid user-owned allocations, read-only consumer, no invalid input",
    persistent_sinks=("NONE",),
    restore_plan="READ ORIGINAL → WRITE CANARY → READBACK → CONSUME → OBSERVE → RESTORE → READBACK VERIFY",
)


class Report:
    def __init__(self) -> None:
        self.rows: list[dict[str, Any]] = []

    def add(self, **row: Any) -> dict[str, Any]:
        self.rows.append(row)
        print(
            f"  {row.get('test', '?'):<12} {row.get('operation', ''):<26} {row.get('result', '?'):<16}"
            + (f" {str(row.get('detail', ''))[:110]}" if row.get("detail") else "")
        )
        return row

    @property
    def failed(self) -> list[dict[str, Any]]:
        return [r for r in self.rows if r.get("result") in {"FAIL", "AB-E"}]


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def consume(target: Ps4LiveTarget, record, label: str, test: str) -> dict[str, Any]:
    """The consumer: one kernel-copyout read of the selected buffer's test range."""

    address = record.test_base
    response = target.channel.request(
        "KREAD_USER",
        timeout=target.config.request_timeout,
        kaddr=address,
        len=CANARY_LEN,
        buf=label.lower(),
    )
    ok = bool(response.get("ok")) and response.get("hex")
    data = bytes.fromhex(response["hex"]) if ok else b""
    return {
        "ok": ok,
        "rc": response.get("rc", response.get("code", "n/a")),
        "data": data,
        "sha256": sha(data) if ok else "unavailable",
        "address": f"0x{address:x}",
    }


def write_buffer(target: Ps4LiveTarget, record, payload: bytes, test: str, label: str) -> dict[str, Any]:
    """Bounded write into our own allocation + independent readback, with restore on mismatch."""

    baseline = target.read_memory(record.test_base, len(payload), test=f"{test}-base")
    if not baseline.get("ok"):
        return {"ok": False, "error": "baseline unreadable"}
    original = bytes.fromhex(baseline["data_hex"])
    response = target.channel.request(
        "WRITE",
        timeout=target.config.write_timeout,
        mutation=True,
        kaddr=record.test_base,
        hex=payload.hex(),
        buf=label.lower(),
    )
    if not response.get("ok"):
        return {"ok": False, "error": response.get("error", "write refused")}
    readback = target.read_memory(record.test_base, len(payload), test=f"{test}-readback")
    if not readback.get("ok") or bytes.fromhex(readback["data_hex"]) != payload:
        return {"ok": False, "error": "readback mismatch", "original": original}
    return {"ok": True, "original": original, "readback_sha256": readback["sha256"]}


def restore_buffer(target: Ps4LiveTarget, record, original: bytes, test: str, label: str) -> dict[str, Any]:
    response = target.channel.request(
        "WRITE",
        timeout=target.config.write_timeout,
        mutation=True,
        kaddr=record.test_base,
        hex=original.hex(),
        buf=label.lower(),
    )
    verify = target.read_memory(record.test_base, len(original), test=f"{test}-restore-readback")
    ok = bool(verify.get("ok")) and bytes.fromhex(verify["data_hex"]) == original
    return {
        "ok": ok,
        "restore_state": "RESTORED_CONFIRMED" if ok else "STATE_INTEGRITY_UNKNOWN",
        "sha256": verify.get("sha256", "unavailable"),
        "adapter_rc": response.get("ok"),
    }


def run_target_test(
    target: Ps4LiveTarget,
    report: Report,
    *,
    variant: str,
    label: str,
    other_label: str,
    canary: bytes,
    experiment_id: str,
    baseline_other: bytes,
) -> tuple[ExperimentRecord, bytes]:
    """Exactly one A/B arm: dry-run → preconditions → write canary → consume → observe → restore."""

    record = target.buffer_allocations[label]
    other = target.buffer_allocations[other_label]
    dry = _dry_run(target, record, canary, label, experiment_id)
    report.add(
        test=f"{experiment_id}-dry",
        operation="dry_run",
        result="PASS" if dry["ok"] else "FAIL",
        detail=(
            f"variant={variant} class={dry['address_class']} addr={dry['address']} len={CANARY_LEN} "
            f"one_mutation={dry['mutations'] == 1} restore_steps={dry['restore_steps']}"
        ),
    )
    if not dry["ok"]:
        return _record(experiment_id, variant, record, canary, {}, {}, b"", "ABORTED"), b""

    before = target.read_memory(record.test_base, CANARY_LEN, test=f"{experiment_id}-before")
    wrote = write_buffer(target, record, canary, experiment_id, label)
    if not wrote.get("ok"):
        return _record(experiment_id, variant, record, canary, {}, {}, b"", "WRITE_FAILED"), b""

    consumed = consume(target, record, label, experiment_id)
    other_now = target.read_memory(other.test_base, CANARY_LEN, test=f"{experiment_id}-other")
    restored = restore_buffer(target, record, wrote["original"], experiment_id, label)

    report.add(
        test=experiment_id,
        operation="ab_arm",
        result="PASS" if consumed["ok"] and restored["ok"] else "FAIL",
        detail=(
            f"{variant}: consumed={consumed['sha256'][:16]} rc={consumed['rc']} "
            f"other_buffer_unchanged={other_now.get('sha256') == sha(baseline_other)} "
            f"restore={restored['restore_state']}"
        ),
    )
    obs = {
        "consumed_buffer_sha256": consumed["sha256"],
        "other_buffer_sha256": other_now.get("sha256", "unavailable"),
    }
    rec = _record(
        experiment_id,
        variant,
        record,
        canary,
        obs,
        {"rc": consumed["rc"], "status": "ok" if consumed["ok"] else "error"},
        consumed["data"],
        restored["restore_state"],
        before_hash=before.get("sha256", ""),
        readback=wrote.get("readback_sha256", ""),
        restore_hash=restored["sha256"],
    )
    return rec, consumed["data"]


def _dry_run(target, record, canary, label, experiment_id) -> dict[str, Any]:
    target.dry_run = True
    try:
        plan = _plan(experiment_id, record, canary)
        result = target.write_memory(plan, test=f"{experiment_id}-dry")
    finally:
        target.dry_run = False
    report = result.get("dry_run") or {}
    return {
        "ok": result.get("result") == "DRY_RUN",
        "address_class": report.get("address_class"),
        "address": report.get("address"),
        "mutations": report.get("mutations"),
        "restore_steps": all((report.get("restore_steps") or {}).values()),
    }


def _plan(experiment_id: str, record, canary: bytes):
    from orbisprobe.live.plan import ExperimentPlan, ReadOp

    return ExperimentPlan(
        plan_id=experiment_id,
        level="LIVE0-U",
        reads=(ReadOp(address=record.test_base, length=len(canary), address_class="USER"),),
        writes=(
            WriteOp(address=record.test_base, data=canary, address_class="USER", label="canary"),
        ),
        expected={"canary": canary.hex()},
        restore_steps=RestoreSteps(True, True, True, True),
        declared_sink="USER_MEMORY",
    )


def _record(experiment_id, variant, record, canary, observables, status, consumed, restore_state,
            before_hash="", readback="", restore_hash="") -> ExperimentRecord:
    return ExperimentRecord(
        experiment_id=experiment_id,
        candidate_id=CANDIDATE.candidate_id,
        target_identity={},
        input_variant=variant,
        allocation=record.to_dict(),
        controlled_field=CANDIDATE.controlled_field,
        before_hash=before_hash,
        write_hash=sha(canary),
        readback_hash=readback,
        observable_hashes=observables,
        return_status=status,
        restore_hash=restore_hash,
        restore_state=restore_state,
        classification="",
        extra={"consumed_sha256": sha(consumed) if consumed else "", "pair_id": ""},
    )


def plan_phase(evidence: EvidenceWriter, out: Path) -> dict[str, Any]:
    allowed, blockers = CANDIDATE.gate()
    print("== candidate gate ==")
    print(f"  candidate: {CANDIDATE.candidate_id}  executable={allowed}")
    for key, value in CANDIDATE.to_dict().items():
        print(f"    {key}: {str(value)[:150]}")
    if blockers:
        for blocker in blockers:
            print(f"  BLOCKER: {blocker}")
    (out / "candidate-record.json").write_text(CANDIDATE.to_json() + "\n", encoding="utf-8")
    return {"executable": allowed, "blockers": blockers, "candidate": CANDIDATE.to_dict()}


def live_phase(args: argparse.Namespace, evidence: EvidenceWriter, out: Path) -> int:
    report = Report()
    summary: dict[str, Any] = {
        "run_id": args.run_id,
        "phase": "live1",
        "console": args.console,
        "worker": args.worker,
        "started_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "candidate": CANDIDATE.to_dict(),
    }
    allowed, blockers = CANDIDATE.gate()
    summary["candidate_gate"] = {"executable": allowed, "blockers": blockers}
    if not allowed:
        report.add(
            test="CAND", operation="candidate_gate", result="PLAN_ONLY", detail="; ".join(blockers)
        )
        return _finish(report, summary, out, args.run_id)

    transport = WorkerConsoleTransport(WorkerConfig(ssh_target=args.worker, console_ip=args.console))
    try:
        build = transport.build_payload()
        summary["payload_build"] = build.to_dict()
        binary = transport.fetch_payload()
        summary["payload_binary_sha256"] = sha(binary)
        transport.start_bridge(lifetime=1500)
        send = transport.send_payload(binary)
        summary["payload_send"] = {k: v for k, v in send.items() if k != "body"}
        if not send.get("ok"):
            report.add(test="T1", operation="payload_delivery", result="FAIL", detail=str(send))
            return _finish(report, summary, out, args.run_id)
        report.add(
            test="T1", operation="payload_delivery", result="PASS",
            detail=f"HTTP {send.get('status')} sha={send.get('sha256', '')[:16]}",
        )
        transport.open_tunnel()
        channel = transport.open_channel(timeout=60)
        summary["greeting"] = getattr(channel, "greeting", "")

        target = Ps4LiveTarget(
            channel,
            policy=LivePolicy(level="LIVE0-U"),
            evidence=evidence,
            config=AdapterConfig(
                console_host=args.console, console_endpoint=f"{args.console}:9090"
            ),
        )
        info = target.get_target_info()
        if not info.get("ok"):
            report.add(test="R2", operation="target_info", result="FAIL", detail=str(info)[:120])
            return _finish(report, summary, out, args.run_id)
        identity = target.capture_identity()
        summary["identity"] = identity.to_dict()
        summary["allocation_view"] = {
            "kernel_base": f"0x{info['kernel_base']:x}",
            "pid": info["pid"],
            "instance": info["instance_id"],
            "buffers": [b.to_dict() for b in (target.payload_info.buffers if target.payload_info else ())],
        }
        report.add(
            test="R2b", operation="identity", result="PASS",
            detail=f"session={identity.session_id[:16]}… kbase=0x{identity.kernel_base:x}",
        )

        records, problems = target.capture_buffer_allocations(
            process_name=args.process_name,
            injection_pid=args.injection_pid,
            test_offset=TEST_OFFSET,
            test_length=CANARY_LEN,
        )
        for name in ("A", "B"):
            reasons = problems.get(name, [])
            report.add(
                test=f"OWN-{name}",
                operation="buffer_ownership",
                result="PASS" if name in records else "FAIL",
                detail=(
                    f"base=0x{records[name].allocation_base:x} gen={records[name].allocation_generation} "
                    f"pid=0x{records[name].pid:x} instance={records[name].payload_instance} "
                    f"range=0x{records[name].test_base:x}+0x{CANARY_LEN:x}"
                    if name in records
                    else "; ".join(reasons)[:140]
                ),
            )
        summary["ownership"] = {k: v.to_dict() for k, v in records.items()}
        summary["ownership_problems"] = problems
        if len(records) != 2:
            report.add(test="OWN", operation="gate", result="FAIL", detail="A/B ownership incomplete")
            return _finish(report, summary, out, args.run_id)

        a, b = records["A"], records["B"]
        base_a = target.read_memory(a.test_base, CANARY_LEN, test="BASE-A")
        base_b = target.read_memory(b.test_base, CANARY_LEN, test="BASE-B")
        summary["baseline"] = {
            "buffer_a_sha256": base_a.get("sha256"),
            "buffer_b_sha256": base_b.get("sha256"),
            "buffer_a_hex": base_a.get("data_hex"),
            "buffer_b_hex": base_b.get("data_hex"),
        }
        report.add(
            test="BASE", operation="baseline", result="PASS",
            detail=f"A={base_a.get('sha256', '')[:16]}… B={base_b.get('sha256', '')[:16]}…",
        )

        # §22 negative control: identical configuration twice (no mutation)
        c1 = consume(target, a, "A", "A1")
        c2 = consume(target, a, "A", "A2")
        offsets = noise_fields(c1["data"], c2["data"])
        summary["negative_control"] = {
            "A1_sha256": c1["sha256"],
            "A2_sha256": c2["sha256"],
            "noise_offsets": offsets,
            "identical": c1["sha256"] == c2["sha256"],
        }
        report.add(
            test="A1A2", operation="negative_control",
            result="PASS" if c1["sha256"] == c2["sha256"] else "FAIL",
            detail=f"A1={c1['sha256'][:16]}… A2={c2['sha256'][:16]}… noise_offsets={offsets}",
        )

        canary_a = canary_for(f"{args.run_id}-canary-A", CANARY_LEN)
        canary_b = canary_for(f"{args.run_id}-canary-B", CANARY_LEN)
        summary["canaries"] = {"A": sha(canary_a), "B": sha(canary_b)}

        rec_a1, cons_a1 = run_target_test(
            target, report, variant="A", label="A", other_label="B", canary=canary_a,
            experiment_id="AB-A1", baseline_other=bytes.fromhex(base_b["data_hex"]),
        )
        rec_b1, cons_b1 = run_target_test(
            target, report, variant="B", label="B", other_label="A", canary=canary_b,
            experiment_id="AB-B1", baseline_other=bytes.fromhex(base_a["data_hex"]),
        )
        pair1 = classify_pair(
            a=rec_a1, b=rec_b1, noise_offsets=offsets, expected_region=(0, CANARY_LEN)
        )
        report.add(
            test="PAIR1", operation="ab_pair", result=pair1.classification,
            detail=f"{pair1.reason[:120]} delta={json.dumps(pair1.observed_delta.get('hash'))[:80]}",
        )

        # §13 content-vs-address control: same address (buffer A), content of B
        rec_c, cons_c = run_target_test(
            target, report, variant="A-content-B", label="A", other_label="B", canary=canary_b,
            experiment_id="AB-C1", baseline_other=bytes.fromhex(base_b["data_hex"]),
        )
        control = classify_pair(
            a=rec_a1, b=rec_c, noise_offsets=offsets, expected_region=(0, CANARY_LEN)
        )
        summary["control_same_address"] = control.to_dict()
        report.add(
            test="CTRL", operation="content_vs_address", result=control.classification,
            detail=f"same address, content A vs B: {control.reason[:110]}",
        )

        # §12 repeatability: exactly one further A→B sequence
        rec_a2, cons_a2 = run_target_test(
            target, report, variant="A", label="A", other_label="B", canary=canary_a,
            experiment_id="AB-A2", baseline_other=bytes.fromhex(base_b["data_hex"]),
        )
        rec_b2, cons_b2 = run_target_test(
            target, report, variant="B", label="B", other_label="A", canary=canary_b,
            experiment_id="AB-B2", baseline_other=bytes.fromhex(base_a["data_hex"]),
        )
        pair2 = classify_pair(
            a=rec_a2, b=rec_b2, noise_offsets=offsets, expected_region=(0, CANARY_LEN)
        )
        reproducible = (
            pair1.classification == pair2.classification
            and (cons_a1 == cons_a2) and (cons_b1 == cons_b2)
        )
        summary["repeatability"] = {
            "pair1": pair1.to_dict(), "pair2": pair2.to_dict(), "reproducible": reproducible,
        }
        report.add(
            test="PAIR2", operation="ab_pair", result=pair2.classification,
            detail=f"repeat identical: {reproducible}",
        )

        # restore verification for both buffers at the end of the sequence
        final_a = target.read_memory(a.test_base, CANARY_LEN, test="FINAL-A")
        final_b = target.read_memory(b.test_base, CANARY_LEN, test="FINAL-B")
        restored = (
            final_a.get("sha256") == base_a.get("sha256")
            and final_b.get("sha256") == base_b.get("sha256")
        )
        report.add(
            test="FINAL", operation="restore_verify",
            result="PASS" if restored else "FAIL",
            detail=f"A==original {final_a.get('sha256') == base_a.get('sha256')}, "
                   f"B==original {final_b.get('sha256') == base_b.get('sha256')}",
        )
        summary["experiments"] = [r.to_dict() for r in (rec_a1, rec_b1, rec_c, rec_a2, rec_b2)]
        summary["pairs"] = [pair1.to_dict(), pair2.to_dict()]
        summary["consumed"] = {
            "A1": sha(cons_a1), "B1": sha(cons_b1), "C1": sha(cons_c),
            "A2": sha(cons_a2), "B2": sha(cons_b2),
        }
        summary["classification"] = pair1.classification
        summary["state_integrity"] = (
            "OK" if restored and not target.state_integrity_unknown else "STATE_INTEGRITY_UNKNOWN"
        )
        target.close()
    finally:
        transport.close()

    return _finish(report, summary, out, args.run_id)


def _finish(report: Report, summary: dict[str, Any], out: Path, run_id: str) -> int:
    summary["finished_utc"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    summary["rows"] = report.rows
    summary["failures"] = report.failed
    passed_phases = [r["result"] for r in report.rows]
    summary["verdict"] = "PASS" if report.rows and not report.failed else "NOT DONE"
    path = out / f"{run_id}-live1-summary.json"
    path.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print("\n== summary ==")
    print(f"  rows: {len(report.rows)} failures: {len(report.failed)}")
    print(f"  results: {sorted(set(passed_phases))}")
    print(f"  verdict: {summary['verdict']}")
    print(f"  evidence: {path}")
    return 0 if summary["verdict"] == "PASS" else 1


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--phase", choices=["plan", "live1"], default="plan")
    parser.add_argument("--evidence-dir", default=str(DEFAULT_EVIDENCE))
    parser.add_argument("--run-id", default=time.strftime("live1-%Y%m%dT%H%M%S"))
    parser.add_argument("--console", default="192.168.1.141")
    parser.add_argument("--worker", default="neo@192.168.1.148")
    parser.add_argument("--process-name", default="unknown")
    parser.add_argument("--injection-pid", type=int, default=None)
    args = parser.parse_args()

    out = Path(args.evidence_dir)
    out.mkdir(parents=True, exist_ok=True)
    evidence = EvidenceWriter(out, args.run_id)
    if args.phase == "plan":
        result = plan_phase(evidence, out)
        return 0 if result["executable"] else 1
    return live_phase(args, evidence, out)


if __name__ == "__main__":
    sys.exit(main())
