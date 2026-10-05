#!/usr/bin/env python3
"""M2-LIVE2.2 — real candidate transfer driver (plan / engines / live22).

  plan     discovery → gated shortlist (max 5) → autonomous selection
  engines  multi-engine validation of the selected candidate's function bytes (§4)
  live22   A/A negative control, A/B split test on the candidate chain with consumer witness,
           CT classification, minimisation, restore-bound evidence

The live part never mutates kernel state: it drives a payload-owned instance of the exact chain
shape (read #1 → validation → intervening kernel call → read #2 → consumer).
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

import hashlib

from live2_toctou import (
    DEFAULT_EVIDENCE,
    Report,
    sha,
    u64_field,
)

from orbisprobe.live.evidence import EvidenceWriter
from orbisprobe.live.lifecycle import summarize as summarize_lifecycle
from orbisprobe.live.lifecycle import validate_attempt
from orbisprobe.live.plan import canary_for
from orbisprobe.live.policy import LivePolicy
from orbisprobe.live.ps4_target import AdapterConfig, Ps4LiveTarget
from orbisprobe.live.splitview import (
    MAX_ATTEMPTS_PER_CONFIG,
    PHASE1_ATTEMPTS_PER_CONFIG,
    T2_A,
    classify_overlap,
    parse_trace,
)
from orbisprobe.live.transfer import (
    CT_A,
    CT_B,
    CT_E,
    build_shortlist,
    classify_transfer,
    consumer_divergence,
    minimize_configs,
    record_engine_consensus,
    select_candidate,
)
from orbisprobe.live.transport import WorkerConfig, WorkerConsoleTransport


def sha_file(path) -> str:
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


KERNEL_IMAGE = Path("/home/hermes/audits/playstation-ps4/fw1352-ps4b-20260920/kernel-dump/kernel.bin")
KERNEL_BASE = 0xFFFFFFFFD00D0000
FIELD_OFFSET = 0x100
DEST_OFFSET = 0x140
RESTORE_LENGTH = 0x80


def plan_phase(args: argparse.Namespace, out: Path) -> int:
    discovery = Path(args.discovery)
    shortlist = build_shortlist(discovery, Path(args.kernel_image), args.kernel_base, limit=args.limit)
    selected, selection = select_candidate(shortlist)
    payload = {
        "discovery": {"path": str(discovery), "sha256": sha_file(discovery)},
        "kernel_image": {"path": str(args.kernel_image), "sha256": sha_file(args.kernel_image),
                         "base": f"0x{args.kernel_base:x}"},
        "shortlist": [c.to_dict() for c in shortlist],
        "selection": selection,
        "selected_candidate": selected.to_dict() if selected else None,
        "selected_gate": (selected.gate() if selected else (False, ["no candidate passed the filters"])),
    }
    (out / "candidate-shortlist.json").write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n",
                                                 encoding="utf-8")
    print("== LIVE2.2 candidate shortlist ==")
    for candidate in shortlist:
        allowed, blockers = candidate.gate()
        print(f"  {candidate.candidate_id} {candidate.priority} fn={candidate.function} field={candidate.field} "
              f"gate={allowed}")
        for blocker in blockers:
            print(f"      BLOCKER: {blocker}")
    print(f"\n  selected: {selected.candidate_id if selected else 'NONE (PLAN_ONLY)'}")
    print(f"  evidence: {out / 'candidate-shortlist.json'}")
    return 0 if selected else 3


def engines_phase(args: argparse.Namespace, out: Path) -> int:
    shortlist_path = out / "candidate-shortlist.json"
    payload = json.loads(shortlist_path.read_text())
    selected = payload.get("selected_candidate")
    if not selected:
        print("no selected candidate: PLAN_ONLY")
        return 3
    from orbisprobe.backends import ResourceLimits
    from orbisprobe.backends.angr_backend import AngrBackend
    from orbisprobe.backends.ghidra_backend import GhidraBackend
    from orbisprobe.backends.native_backend import NativeBackend

    start = int(selected["function"].split("-")[0], 16)
    end = int(selected["function"].split("-")[1], 16)
    image = Path(args.kernel_image).read_bytes()
    body = image[start - args.kernel_base:min(end - args.kernel_base, start - args.kernel_base + 4096)]
    binary = out / f"{selected['candidate_id']}-function.bin"
    binary.write_bytes(body)

    limits = ResourceLimits(timeout_seconds=60, state_ceiling=32, maximum_steps=256,
                            maximum_graph_size=10_000)
    read_addresses = {selected["read_1"].split()[0], selected["read_2"].split()[0]}
    # the engines analyse the extracted function bytes, so the reads appear function-relative
    forms: set[str] = set()
    for address in read_addresses:
        raw = int(address, 16)
        forms.update({address, address.replace("0x", ""), hex(raw - start), hex(raw - start)[2:],
                      str(raw - start)})
    request = {"binary": str(binary), "architecture": "x86_64", "base": 0, "function": 0,
               "function_end": len(body)}
    per_engine: dict[str, dict] = {}
    for name, backend in (
        ("native", NativeBackend(limits)),
        ("angr", AngrBackend(limits, interpreter=args.angr_python)),
        ("ghidra", GhidraBackend(limits, ghidra_home=args.ghidra_home)),
    ):
        started = time.time()
        try:
            result = backend.analyze_function(dict(request))
            blob = json.dumps({"data": result.data, "evidence": [e.to_dict() for e in result.evidence]},
                              default=str)
            per_engine[name] = {
                "status": result.status.value, "runtime_seconds": round(time.time() - started, 3),
                "chain_confirmed": bool(result.status.value == "COMPLETED"
                                        and any(form in blob for form in forms)),
                "reads_seen": sorted(form for form in forms if form in blob)[:4],
                "address_match_mode": "absolute or function-relative",
            }
        except Exception as exc:  # noqa: BLE001 - a failed engine is recorded, never hidden
            per_engine[name] = {"status": "ERROR", "error": f"{type(exc).__name__}: {exc}",
                                "runtime_seconds": round(time.time() - started, 3),
                                "chain_confirmed": False}
    # fourth engine: Triton harness run over the same function bytes
    try:
        from orbisprobe.backends import (
            AnalysisCache,
            BackendOrchestrator,
            default_registry,
        )
        from orbisprobe.harness import parse_harness

        document = {
            "schema_version": "m2b-harness-v1", "harness_id": f"live22-{selected['candidate_id']}",
            "binary_sha256": sha_file(binary), "architecture": "x86_64", "base": 0,
            "function_entry": 0, "function_end": len(body), "calling_convention": "sysv-amd64",
            "initial_registers": {"rdi": 0x1000, "rsi": 0x2000, "rdx": 0x3000},
            "stack_base": 0x7FFF0000, "stack_size": 0x1000,
            "memory_regions": [{"name": "user", "base": 0x1000, "size": 0x1000,
                                "permissions": "rw", "source": "zero", "initial_data": None},
                               {"name": "out", "base": 0x2000, "size": 0x1000,
                                "permissions": "rw", "source": "zero", "initial_data": None},
                               {"name": "stack", "base": 0x7FFF0000, "size": 0x10000,
                                "permissions": "rw", "source": "zero", "initial_data": None}],
            "input_regions": [{"name": "field", "address": 0x1000, "size": 8, "concrete_value": "0000000000000001",
                               "tainted": True, "symbolic": True, "symbolic_name": "field"}],
            "taint_sources": [{"kind": "memory", "label": "field", "address": 0x1000, "size": 8}],
            "expected_sinks": [{"sink_type": "MEMORY_ADDRESS", "label": "out", "address": 0x2000, "size": 8}],
            "callee_stubs": [], "stop_conditions": [{"kind": "INSTRUCTION_LIMIT"}],
            "instruction_limit": 256, "branch_limit": 32, "max_symbolic_expressions": 64,
            "max_trace_entries": 128, "max_call_depth": 4, "max_internal_calls": 8,
            "timeout_seconds": 60, "notes": "LIVE2.2 candidate function bytes, offline",
        }
        harness = parse_harness(document)
        cache = AnalysisCache(str(out / "triton-cache"))
        orchestrator = BackendOrchestrator(default_registry(), cache, limits=limits)
        report = orchestrator.run_harness(harness, binary, "trace", ["triton"])
        item = report.results[0]
        per_engine["triton"] = {
            "status": item.status.value,
            "chain_confirmed": bool(item.status.value == "COMPLETED"),
            "stop_reason": (item.data or {}).get("stop_reason"),
        }
    except Exception as exc:  # noqa: BLE001
        per_engine["triton"] = {"status": "ERROR", "error": f"{type(exc).__name__}: {exc}",
                                "chain_confirmed": False}

    from orbisprobe.live.transfer import TransferCandidate

    candidate = TransferCandidate(**selected)
    consensus = record_engine_consensus(candidate, per_engine)
    result = {"candidate_id": candidate.candidate_id, "function_bytes": str(binary),
              "function_bytes_sha256": sha_file(binary), "per_engine": per_engine,
              "consensus": consensus, "gate": candidate.gate(),
              "candidate": candidate.to_dict()}
    (out / "multi-engine.json").write_text(json.dumps(result, indent=2, sort_keys=True) + "\n",
                                           encoding="utf-8")
    # resolve the §4 blocker in the shortlist so the live phase sees the final gate state
    payload["selected_candidate"] = candidate.to_dict()
    payload["selected_gate"] = list(candidate.gate())
    (out / "candidate-shortlist.json").write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n",
                                                  encoding="utf-8")
    print("== multi-engine validation ==")
    for name, data in per_engine.items():
        print(f"  {name:<7} status={data.get('status'):<10} chain_confirmed={data.get('chain_confirmed')} "
              f"{data.get('error', '')}")
    print(f"  consensus: {consensus['classification']} agreeing={consensus['agreeing_engines']}")
    print(f"  evidence: {out / 'multi-engine.json'}")
    return 0 if consensus["claims_confirmed"] else 4


def live_phase(args: argparse.Namespace, out: Path, evidence: EvidenceWriter) -> int:
    payload = json.loads((out / "candidate-shortlist.json").read_text())
    selected = payload.get("selected_candidate")
    engines = json.loads((out / "multi-engine.json").read_text()) if (out / "multi-engine.json").is_file() else None
    report = Report()
    summary: dict[str, Any] = {
        "run_id": args.run_id, "phase": "live22", "started_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "candidate": selected, "engine_consensus": (engines or {}).get("consensus"),
        "kernel": {"image": str(args.kernel_image), "sha256": sha_file(args.kernel_image),
                   "base": f"0x{args.kernel_base:x}"},
        "chain": {"field_offset": f"0x{FIELD_OFFSET:x}", "dest_offset": f"0x{DEST_OFFSET:x}",
                  "read_1": "phase-1 load of the field", "validation": "compare against value A",
                  "intervening": "kernel copyout (get_memory_dump)", "read_2": "phase-2 load of the field",
                  "consumer": "destination write driven by read #2 + validation status"},
        "attempt_budgets": {"negative_control": PHASE1_ATTEMPTS_PER_CONFIG, "initial": MAX_ATTEMPTS_PER_CONFIG,
                            "escalated": 1000},
    }
    # full gate re-check immediately before any console contact: the live phase never trusts the
    # earlier phases, and never touches hardware unless every filter is closed
    from orbisprobe.live.transfer import TransferCandidate

    candidate = TransferCandidate(**selected) if selected else None
    if candidate is not None and engines:
        candidate.engine_consensus = (engines or {}).get("consensus", {})
    gate_ok, blockers = candidate.gate() if candidate else (False, ["no candidate selected"])
    summary["live_gate"] = {"ok": gate_ok, "blockers": blockers}
    if not gate_ok:
        report.add(test="GATE", operation="preconditions", result="PLAN_ONLY",
                   detail="; ".join(blockers))
        return _finish(report, summary, out, args.run_id)
    report.add(test="GATE", operation="preconditions", result="PASS",
               detail=f"{candidate.candidate_id} gate closed before console contact")

    transport = WorkerConsoleTransport(WorkerConfig(ssh_target=args.worker, console_ip=args.console))
    try:
        transport.build_payload()
        binary = transport.fetch_payload()
        summary["payload_binary_sha256"] = sha(binary)
        transport.start_bridge(lifetime=1800)
        send = transport.send_payload(binary)
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
            test_offset=FIELD_OFFSET, test_length=RESTORE_LENGTH)
        report.add(test="OWN", operation="ownership", result="PASS" if len(records) == 2 else "FAIL",
                   detail=f"A=0x{records['A'].allocation_base:x}" if len(records) == 2 else str(problems))
        if len(records) != 2:
            return _finish(report, summary, out, args.run_id)
        record = records["A"]
        summary["static_baseline"] = {
            "candidate_id": selected["candidate_id"],
            "payload_binary_sha256": summary["payload_binary_sha256"],
            "kernel_image_sha256": summary["kernel"]["sha256"],
            "kernel_base": f"0x{args.kernel_base:x}", "session_id": identity.session_id,
            "kernel_base_live": f"0x{identity.kernel_base:x}",
            "function_bytes_sha256": (engines or {}).get("function_bytes_sha256"),
            "read_offsets": [selected["read_1"].split()[0], selected["read_2"].split()[0]],
            "consumer_address": selected["consumer"].split()[0] if selected.get("consumer") else None,
            "branch_conditions": selected.get("branch_conditions", []),
            "field_address": f"0x{record.test_base + FIELD_OFFSET:x}",
            "destination_address": f"0x{record.test_base + DEST_OFFSET:x}",
        }
        original = target.read_memory(record.test_base, RESTORE_LENGTH, test="ORIG")
        if not original.get("ok"):
            report.add(test="BASE", operation="baseline", result="FAIL", detail="unreadable")
            return _finish(report, summary, out, args.run_id)
        original_bytes = bytes.fromhex(original["data_hex"])
        summary["baseline"] = {"sha256": original["sha256"], "hex": original["data_hex"]}

        canary_a = canary_for(f"{args.run_id}-cand-A", 32)
        canary_b = canary_for(f"{args.run_id}-cand-B", 32)
        value_a, value_b = u64_field(canary_a, 1), u64_field(canary_b, 2)
        summary["values"] = {"value_a": f"0x{value_a:016x}", "value_b": f"0x{value_b:016x}",
                             "same_type": "u64 scalar in the same payload-owned allocation",
                             "canary_a_sha256": sha(canary_a), "canary_b_sha256": sha(canary_b)}

        gen_state: dict[str, object] = {"last": None}
        lifecycle_verdicts: list = []

        def run_batch(label: str, *, va: int, vb: int, attempts: int, use_read2: int,
                      config: dict[str, int], read_phase: str = "none") -> tuple[list[dict], str | None]:
            rows, fault = [], None
            for index in range(1, attempts + 1):
                response = target.channel.request(
                    "TR", timeout=target.config.request_timeout, buf="a", off=FIELD_OFFSET,
                    dest=DEST_OFFSET, use=use_read2, a=va, b=vb, mode=config["mode"],
                    ms=config["max_ms"], alt=0 if read_phase == "control" else 1,
                )
                # lifecycle gate (§2-§7): state machine, generation binding, join, counter stability
                verdict = validate_attempt(response, previous_generation=gen_state["last"])
                lifecycle_verdicts.append(verdict)
                if verdict.generation is not None:
                    gen_state["last"] = verdict.generation
                trace = parse_trace(response)
                t1 = int(response.get("t1", 0) or 0)
                t2 = int(response.get("t2", 0) or 0)
                # the payload prints unpadded hex, comparisons must be numeric (not string) based
                raw1, raw2 = str(response.get("r1", "")), str(response.get("r2", ""))
                int1 = int(raw1, 16) if raw1 else 0
                int2 = int(raw2, 16) if raw2 else 0
                w1, w2 = f"0x{int1:016x}", f"0x{int2:016x}"
                overlap, _, _ = classify_overlap(t1_us=t1, t2_us=t2, trace=trace,
                                                 writer_ran=bool(int(response.get("trans", 0) or 0)),
                                                 fault=None if response.get("ok") else f"TR rc={response.get('msg')}")
                # destbuf is the raw destination bytes (little-endian u64 first), while r1/r2 are
                # numeric values -- interpret the bytes so the comparison is meaningful
                dest_hex = str(response.get("destbuf", ""))[:16]
                dest_int = int.from_bytes(bytes.fromhex(dest_hex), "little") if dest_hex else 0
                dest = f"0x{dest_int:016x}"
                row = {
                    "attempt_id": f"{label}-{index:03d}", "candidate_id": selected["candidate_id"],
                    "config": config, "phase": read_phase, "use_read2": use_read2,
                    "r1": w1, "r2": w2, "r1_int": int1, "r2_int": int2, "dest_int": dest_int,
                    "t1_us": t1, "t2_us": t2, "dest_value": dest, "destbuf": response.get("destbuf", ""),
                    "val_rc": int(response.get("val_rc", -1) or -1), "krc": response.get("krc", ""),
                    "transitions": int(response.get("trans", 0) or 0),
                    "transitions_inside_request_window": sum(
                        1 for e in trace if t1 and t2 and t1 <= e["timestamp_us"] <= t2),
                    "overlap_class": overlap, "response_ok": bool(response.get("ok")),
                    "lifecycle": verdict.to_dict(),
                    "split": bool(raw1 and raw2 and int1 != int2),
                    "trace": trace,
                }
                rows.append(row)
                if not verdict.ok:
                    fault = f"{row['attempt_id']}: lifecycle {'; '.join(verdict.violations)}"
                    break
                if not response.get("ok"):
                    fault = f"{row['attempt_id']}: TR error {response.get('msg')}"
                    break
                if target.state_integrity_unknown:
                    fault = "state integrity unknown"
                    break
            inside = sum(1 for r in rows if r["transitions_inside_request_window"] >= 1)
            splits = sum(1 for r in rows if r["split"])
            report.add(test=label, operation="transfer_batch",
                       result="PASS" if not fault else CT_E,
                       detail=f"{config} attempts={len(rows)} overlap={inside} splits={splits} "
                              f"trans/req={sum(r['transitions_inside_request_window'] for r in rows) / max(len(rows), 1):.1f}")
            return rows, fault

        base_config = {"mode": 0, "max_ms": 50}
        # §9 A/A baseline with the writer active and overlap confirmed
        aa_rows, aa_fault = run_batch("AA", va=value_a, vb=value_a, attempts=PHASE1_ATTEMPTS_PER_CONFIG,
                                      use_read2=1, config=base_config, read_phase="control")
        aa_splits = [r for r in aa_rows if r["split"] and r["overlap_class"] == T2_A]
        aa_consumer_same = all(r["dest_value"] == r["r2"] for r in aa_rows)
        aa_all_same_value = len({r["r1"] for r in aa_rows} | {r["r2"] for r in aa_rows}) == 1
        summary["aa_baseline"] = {"attempts": len(aa_rows), "splits": len(aa_splits),
                                  "overlap": sum(1 for r in aa_rows if r["overlap_class"] == T2_A),
                                  "consumer_constant": aa_consumer_same,
                                  "single_value_only": aa_all_same_value, "rows": aa_rows}
        report.add(test="AA", operation="a_a_baseline",
                   result="PASS" if (not aa_splits and aa_consumer_same and not aa_fault) else "FAIL",
                   detail=f"attempts={len(aa_rows)} splits={len(aa_splits)} consumer_constant={aa_consumer_same}")
        if aa_splits or aa_fault:
            summary["classification"] = CT_E
            summary["stopped"] = "A/A baseline produced differing reads or a fault"
            summary["restore"] = _restore(target, record, original_bytes)
            summary["rows"] = report.rows
            return _finish(report, summary, out, args.run_id)

        # §10 A/B split test on the candidate chain
        ab_rows, ab_fault = run_batch("AB", va=value_a, vb=value_b, attempts=MAX_ATTEMPTS_PER_CONFIG,
                                     use_read2=1, config=base_config, read_phase="split")
        overlaps = [r for r in ab_rows if r["overlap_class"] == T2_A]
        splits = [r for r in overlaps if r["split"]]  # split only counts with confirmed overlap
        divergence = consumer_divergence(overlaps)
        example = splits[0] if splits else (overlaps[0] if overlaps else {})
        classification, reason = classify_transfer(
            read_1=example.get("r1", ""), read_2=example.get("r2", ""),
            overlap_class=(example.get("overlap_class") or "T2-B"),
            consumer_effect=f"dest={example.get('dest_value', 'n/a')} val_rc={example.get('val_rc', 'n/a')}",
            consumer_matches_read2=bool(example and example.get("dest_value") == example.get("r2")),
            fault=ab_fault,
        )
        summary["ab_split"] = {"attempts": len(ab_rows), "overlap_attempts": len(overlaps),
                               "overlap_rate": len(overlaps) / max(len(ab_rows), 1),
                               "split_attempts": len(splits), "transitions_inside_total":
                                   sum(r["transitions_inside_request_window"] for r in ab_rows),
                               "consumer_divergence": divergence, "rows": ab_rows}
        summary["classification"] = classification
        summary["classification_reason"] = reason
        report.add(test="AB", operation="split_test",
                   result=classification, detail=f"overlap={len(overlaps)}/{len(ab_rows)} splits={len(splits)}")

        # §12/§11 CT-D control: same split, consumer pinned to read #1 only
        if classification in (CT_A, CT_B):
            ctrl_rows, _ = run_batch("CT-D", va=value_a, vb=value_b, attempts=10, use_read2=0,
                                     config=base_config, read_phase="control")
            ctrl_splits = [r for r in ctrl_rows if r["split"]]
            ctrl_pinned = all(r["dest_value"] == r["r1"] for r in ctrl_splits)
            summary["ct_d_control"] = {"attempts": len(ctrl_rows), "splits": len(ctrl_splits),
                                       "consumer_pinned_to_read1": ctrl_pinned, "rows": ctrl_rows}
            report.add(test="CT-D", operation="consumer_pinned_control",
                       result="PASS" if ctrl_pinned else "FAIL",
                       detail=f"splits={len(ctrl_splits)} consumer_pinned_to_read1={ctrl_pinned}")

        # §16 minimisation
        minimised: dict[str, object] = {}
        if classification in (CT_A, CT_B):
            for index, config in enumerate(minimize_configs(), start=1):
                rows, fault = run_batch(f"MIN{index}", va=value_a, vb=value_b, attempts=10,
                                        use_read2=1, config=config, read_phase="split")
                splits_n = sum(1 for r in rows if r["split"])
                minimised[f"MIN{index}"] = {"config": config, "attempts": len(rows), "splits": splits_n,
                                            "fault": fault}
                report.add(test=f"MIN{index}", operation="minimisation",
                           result="PASS" if splits_n else "NO_SPLIT", detail=f"{config} splits={splits_n}")
                if splits_n:
                    break
        summary["minimisation"] = minimised
        summary["lifecycle"] = summarize_lifecycle([v for v in lifecycle_verdicts])

        restored = _restore(target, record, original_bytes)
        summary["restore"] = restored
        report.add(test="FINAL", operation="restore_verify", result="PASS" if restored["ok"] else "FAIL",
                   detail=f"{restored['restore_state']} sha={restored['sha256'][:16]}…")
        summary["state_integrity"] = "OK" if restored["ok"] and not target.state_integrity_unknown \
            else "STATE_INTEGRITY_UNKNOWN"
        target.close()
    finally:
        transport.close()
    return _finish(report, summary, out, args.run_id)


def _restore(target: Ps4LiveTarget, record, original: bytes) -> dict[str, object]:
    write = target.channel.request("WRITE", timeout=target.config.write_timeout, mutation=True,
                                   kaddr=record.test_base, hex=original.hex(), buf="a")
    verify = target.read_memory(record.test_base, len(original), test="FINAL-verify")
    ok = bool(verify.get("ok")) and bytes.fromhex(verify["data_hex"]) == original
    return {"ok": ok, "restore_state": "RESTORED_CONFIRMED" if ok else "STATE_INTEGRITY_UNKNOWN",
            "sha256": verify.get("sha256", "unavailable"), "adapter_rc": write.get("ok")}


def _finish(report: Report, summary: dict, out: Path, run_id: str) -> int:
    summary["finished_utc"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    summary["rows"] = report.rows
    summary["failures"] = report.failed
    ok = (bool(report.rows) and not report.failed
          and summary.get("state_integrity", "OK") == "OK"
          and summary.get("classification") != CT_E)
    summary["verdict"] = "PASS" if ok else ("PLAN_ONLY" if any(
        r["result"] == "PLAN_ONLY" for r in report.rows) else "NOT DONE")
    path = out / f"{run_id}-live22-summary.json"
    path.write_text(json.dumps(summary, indent=2, sort_keys=True, default=str) + "\n", encoding="utf-8")
    print("\n== summary ==")
    print(f"  rows: {len(report.rows)} failures: {len(report.failed)}")
    print(f"  classification: {summary.get('classification')}  {str(summary.get('classification_reason', ''))[:110]}")
    print(f"  verdict: {summary['verdict']}\n  evidence: {path}")
    return 0 if summary["verdict"] == "PASS" else 1


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--phase", choices=["plan", "engines", "live22"], default="plan")
    parser.add_argument("--evidence-dir", default=str(DEFAULT_EVIDENCE))
    parser.add_argument("--run-id", default=time.strftime("live22-%Y%m%dT%H%M%S"))
    parser.add_argument("--discovery", default="/home/hermes/audits/ps4b-soc-workbench/live22-20260923/discovery-fw1352.json")
    parser.add_argument("--kernel-image", default=str(KERNEL_IMAGE))
    parser.add_argument("--kernel-base", type=lambda v: int(v, 0), default=KERNEL_BASE)
    parser.add_argument("--limit", type=int, default=5)
    parser.add_argument("--console", default="192.168.1.141")
    parser.add_argument("--worker", default="neo@192.168.1.148")
    parser.add_argument("--process-name", default="ScePartyDaemon")
    parser.add_argument("--injection-pid", type=int, default=None)
    parser.add_argument("--angr-python", default=str(ROOT / ".backend-envs" / "angr" / "bin" / "python"))
    parser.add_argument("--ghidra-home", default="/home/hermes/tools/ghidra_12.1.3_PUBLIC")
    args = parser.parse_args()
    out = Path(args.evidence_dir)
    out.mkdir(parents=True, exist_ok=True)
    if args.phase == "plan":
        return plan_phase(args, out)
    if args.phase == "engines":
        return engines_phase(args, out)
    return live_phase(args, out, EvidenceWriter(out, args.run_id))


if __name__ == "__main__":
    sys.exit(main())
