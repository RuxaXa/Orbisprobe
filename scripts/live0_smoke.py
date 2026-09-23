#!/usr/bin/env python3
"""M2-LIVE0 smoke matrix runner.

Phases:

``offline``   policy negative tests A–G and the adapter failure taxonomy — no console involved
``dry-run``   every planned live experiment is evaluated without dispatching a mutation
``live-r``    R1–R5 + F: ping, target identity, KBASE, known RX bytes, repeat-read stability
``live-u``    U1–U5, repeated, with verified restore between runs
``all``       offline → dry-run → live-r → live-u (LIVE0-S is evaluated last and may be skipped)

Every mutating experiment is executed once, through the adapter's full cycle
(baseline → dispatch → readback → restore → restore-readback → verify). Nothing here triggers a
service request, a kernel write, flash/NVS/SNVS access or a persistent change.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import socket
import sys
import threading
import time
from pathlib import Path
from typing import Any

ROOT = Path(__file__).parents[1]
sys.path.insert(0, str(ROOT / "tests"))

from live0_harness import (
    DUMP_BASE,
    FAKE_KBASE,
    KERNEL_DUMP,
    RecordingOnlyChannel,
    ScriptedChannel,
    dump_available,
    expectations,
    expected_base_relative,
    make_target,
    write_plan,
)

from orbisprobe.live.evidence import EvidenceWriter, MutationState, RestoreState
from orbisprobe.live.plan import (
    ExperimentPlan,
    RestoreSteps,
    WriteOp,
    canary_for,
)
from orbisprobe.live.policy import LivePolicy
from orbisprobe.live.ps4_target import AdapterConfig, Ps4LiveTarget
from orbisprobe.live.transport import WorkerConfig, WorkerConsoleTransport

DEFAULT_EVIDENCE = Path("/home/hermes/audits/ps4b-soc-workbench/live0-20260923")
CANARY_LEN = 32
#: Offset inside our own allocation. Only this bounded range is ever touched.
TEST_OFFSET = 0x100
RUNS_PER_BUFFER = 3
#: Set per invocation so every canary cycle gets its own experiment id.
CURRENT_RUN_ID = 'run'


class Report:
    def __init__(self) -> None:
        self.rows: list[dict[str, Any]] = []

    def add(self, **row: Any) -> dict[str, Any]:
        self.rows.append(row)
        status = row.get("result", "?")
        print(
            f"  {row.get('test', '?'):<10} {row.get('operation', ''):<22} "
            f"{status}"
            + (f"  {row.get('detail', '')}" if row.get("detail") else "")
        )
        return row

    @property
    def failed(self) -> list[dict[str, Any]]:
        return [row for row in self.rows if row.get("result") in {"FAIL", "BLOCK_UNEXPECTED"}]


def offline_negative_tests(report: Report) -> None:
    print("\n== §20 policy negative tests (no console, no mutation) ==")
    level = "LIVE0-U"
    cases: list[tuple[str, str]] = [
        ("A", "write to KERNEL_TEXT"),
        ("B", "write to UNKNOWN"),
        ("C", "write without restore_steps"),
        ("D", "persistent sink plan"),
        ("E", "oversized write"),
        ("F", "wrong target identity"),
        ("G", "stale KBASE from a previous boot"),
    ]
    for letter, label in cases:
        channel = RecordingOnlyChannel()
        target = make_target(channel, level=level)
        plan = _negative_plan(letter)
        result = target.write_memory(plan)
        # only state-changing requests count as a dispatched mutation (INFO/READ are setup)
        dispatched = any(request["mutation"] for request in channel.requests)
        report.add(
            test=f"NEG-{letter}",
            operation="policy_block",
            result="PASS" if result["result"] == "BLOCK" and not dispatched else "FAIL",
            detail=f"{label}: {result.get('error', result.get('result'))[:90]}",
            dispatched=dispatched,
        )


def _negative_plan(letter: str) -> ExperimentPlan:
    if letter == "A":
        return write_plan(
            address=FAKE_KBASE + 0x1000, length=16, plan_id="negA", address_class="UNKNOWN"
        )
    if letter == "B":
        return write_plan(
            address=0xDEADBEEF, length=16, plan_id="negB", address_class="UNKNOWN"
        )
    if letter == "C":
        plan = write_plan(address=0x0000000021A00000, length=16, plan_id="negC")
        plan.restore_steps = RestoreSteps()
        return plan
    if letter == "D":
        return write_plan(
            address=0x0000000021A00000, length=16, plan_id="negD", declared_sink="SNVS_WRITE"
        )
    if letter == "E":
        canary = bytes(0x1800)
        return ExperimentPlan(
            plan_id="negE",
            level="LIVE0-U",
            writes=(WriteOp(address=0x0000000021A00000, data=canary, address_class="USER"),),
            expected={"canary": canary.hex()},
            restore_steps=RestoreSteps(True, True, True, True),
        )
    if letter == "F":
        plan = write_plan(address=0x0000000021A00000, length=16, plan_id="negF")
        plan.expected["session_id"] = "other-session"
        plan.expected["target_name"] = "ps4a-dead"
        return plan
    plan = write_plan(address=0x0000000021A00000, length=16, plan_id="negG")
    plan.expected["kernel_base"] = 0xFFFFFFFF90000000
    return plan


def offline_failure_tests(report: Report) -> None:
    print("\n== §21 adapter failure taxonomy (scripted channels) ==")
    scenarios = [
        ("F1", {"READ": "timeout_before_write"}, "ABORT", "no mutation dispatched"),
        ("F2", {"WRITE": "timeout_after_write"}, "FAIL", "attempted + latched"),
        ("F3", {"WRITE": "disconnect_before_restore"}, "FAIL", "attempted + latched"),
        ("F4", {"READ": "malformed_response"}, "ABORT", "structured malformed_response"),
        ("F5", {"READ": "partial_response"}, "ABORT", "structured partial_response"),
    ]
    for test, faults, expected_result, note in scenarios:
        target = make_target(ScriptedChannel(fail_on=faults), level="LIVE0-U")
        outcome = target.write_memory(write_plan(plan_id=f"{test}-plan"), test=test)
        observed = outcome["result"]
        ok = observed == expected_result
        if expected_result == "FAIL":
            ok = ok and outcome.get("mutation_state") != MutationState.NONE.value
        else:
            # a read-side fault must abort before dispatch and name the injected fault class
            injected = next(iter(faults.values()))
            ok = ok and outcome.get("cause") == injected
        report.add(
            test=test,
            operation="failure_injection",
            result="PASS" if ok else "FAIL",
            detail=(
                f"{note}: result={observed} mutation={outcome.get('mutation_state')} "
                f"restore={outcome.get('restore_state')} latch={target.state_integrity_unknown}"
            ),
        )
    # restore mismatch
    target = make_target(ScriptedChannel(fail_on={"READ": "restore_readback_mismatch"}))
    outcome = target.write_memory(write_plan(plan_id="F6-plan"), test="F6")
    report.add(
        test="F6",
        operation="failure_injection",
        result="PASS"
        if outcome["restore_state"] == RestoreState.UNKNOWN.value and target.state_integrity_unknown
        else "FAIL",
        detail=(
            f"restore mismatch: restore={outcome['restore_state']} "
            f"latch={target.state_integrity_unknown}"
        ),
    )
    # no-op write: success claimed by the payload but the readback disagrees
    class NoOpWrites(ScriptedChannel):
        def request(self, command, *, timeout=None, mutation=False, expect=None, **fields):
            if command in {"READ", "VERIFY"}:
                self.requests.append({"command": command, "fields": fields, "mutation": False})
                length = int(fields["len"])
                return {"ok": True, "command": command, "rc": "0", "hex": "5a" * length}
            if command == "WRITE":
                self.requests.append({"command": command, "fields": fields, "mutation": mutation})
                return {"ok": True, "command": "WRITE", "rc": "0"}
            return super().request(
                command, timeout=timeout, mutation=mutation, expect=expect, **fields
            )

    target = make_target(NoOpWrites())
    outcome = target.write_memory(write_plan(plan_id="F7-plan"), test="F7")
    report.add(
        test="F7",
        operation="failure_injection",
        result="PASS"
        if outcome["mutation_state"] == MutationState.MUTATION_FAILED.value
        and outcome["restore_state"] == RestoreState.CONFIRMED.value
        else "FAIL",
        detail=(
            f"payload claimed success, readback disagreed: mutation={outcome['mutation_state']} "
            f"restore={outcome['restore_state']}"
        ),
    )


def dry_run(report: Report, evidence: EvidenceWriter) -> None:
    print("\n== §14 dry-run of every planned live experiment ==")
    channel = ScriptedChannel()
    target = make_target(channel, level="LIVE0-U", dry_run=True, evidence=evidence)
    outcome = target.write_memory(write_plan(plan_id="U-dry"), test="DRY-U")
    report.add(
        test="DRY-U",
        operation="dry_run_write",
        result=(
            "PASS"
            if outcome["result"] == "DRY_RUN"
            and all(not request["mutation"] for request in channel.requests)
            else "FAIL"
        ),
        detail=f"plan shown, policy {outcome.get('policy')}, no mutation dispatched",
    )


# --------------------------------------------------------------------- live
def live_r(target: Ps4LiveTarget, report: Report, evidence: EvidenceWriter) -> dict[str, Any]:
    print("\n== §17 LIVE0-R: read-only transport validation ==")
    context: dict[str, Any] = {}

    ping = target.ping()
    report.add(
        test="R1",
        operation="ping",
        result="PASS" if ping.get("ok") else "FAIL",
        detail=f"payload={ping.get('payload')} uptime_ms={ping.get('uptime_ms')}",
    )

    info = target.get_target_info()
    if not info.get("ok"):
        report.add(test="R2", operation="target_info", result="FAIL", detail=str(info)[:120])
        return context
    context["info"] = info
    report.add(
        test="R2",
        operation="target_info",
        result="PASS",
        detail=(
            f"fw={info['firmware']} payload={info['payload_version']} "
            f"kbase=0x{info['kernel_base']:x} buf=0x{info['test_buffer']:x}"
        ),
    )

    identity = target.capture_identity()
    context["identity"] = identity
    report.add(
        test="R2b",
        operation="identity_gate",
        result="PASS",
        detail=(
            f"session={identity.session_id[:16]}… fw={identity.firmware} "
            f"kbase=0x{identity.kernel_base:x} fingerprint={identity.kernel_fingerprint[:16]}…"
        ),
    )

    snapshot = target.snapshot_state()
    context["snapshot"] = snapshot
    base_ok = all(snapshot.get("base_relative_ok", {}).values())
    report.add(
        test="R3",
        operation="kbase_cross_check",
        result="PASS" if base_ok else "FAIL",
        detail=(
            "PRISON0 == kbase+0x1a5c0c0 and M_TEMP == kbase+0x1a42f70: "
            + json.dumps(snapshot.get("base_relative_ok", {}))
        ),
    )

    if not dump_available():
        report.add(
            test="R4",
            operation="known_rx_read",
            result="SKIPPED_NO_DUMP",
            detail="validated kernel dump not present",
        )
        return context

    exp = expectations()
    expected_deltas = expected_base_relative()
    kbase = int(info["kernel_base"])
    for name, expectation in exp.items():
        expected_live = expectation.expected_live_bytes(kbase, DUMP_BASE)
        raw = target.read_memory(
            kbase + expectation.rva,
            expectation.length,
            test=f"R4-{name}",
            operation="read_memory",
            label=f"dump rva=0x{expectation.rva:x}",
        )
        if not raw.get("ok"):
            report.add(
                test=f"R4-{name}",
                operation="read_memory",
                result="FAIL",
                detail=f"unreadable: {raw.get('error', raw.get('error_type'))}",
            )
            continue
        live = bytes.fromhex(raw["data_hex"])
        if live == expectation.data:
            classification = "STATIC_BYTES_MATCH"
        elif live == expected_live and expectation.relocated_fields:
            classification = "RELOCATED_FIELD_MATCH"
        else:
            classification = "MISMATCH"
        detail = (
            f"rva=0x{expectation.rva:x} len={expectation.length} class={classification} "
            f"live={raw['sha256'][:16]}… dump={expectation.sha256[:16]}… "
            f"rebased={hashlib.sha256(expected_live).hexdigest()[:16]}…"
        )
        for offset, size in expectation.relocated_fields:
            dumped = int.from_bytes(expectation.data[offset : offset + size], "little")
            observed = int.from_bytes(live[offset : offset + size], "little")
            detail += (
                f" field@0x{offset:x}: live-base=0x{observed - kbase:x} "
                f"dump-base=0x{dumped - DUMP_BASE:x}"
            )
        # a second, expectation-bound read proves the rebased expectation itself passes
        rebased = target.read_memory(
            kbase + expectation.rva,
            expectation.length,
            test=f"R4b-{name}",
            expect_bytes=expected_live,
            operation="read_memory",
            label="rebased expectation",
        )
        report.add(
            test=f"R4-{name}",
            operation="kernel_read_vs_dump",
            result="PASS" if classification != "MISMATCH" else "FAIL",
            detail=detail + f" rebased_expectation={rebased.get('result')}",
            classification=classification,
        )

    for name, delta in expected_deltas.items():
        slot_rva = {"prison0": 0x0111FA18, "m_temp": 0x01520D00}[name]
        result = target.read_memory(kbase + slot_rva, 8, test=f"R3-{name}", operation="read_memory")
        if not result.get("ok"):
            report.add(test=f"R3-{name}", operation="read_memory", result="FAIL", detail="unreadable")
            continue
        value = int.from_bytes(bytes.fromhex(result["data_hex"]), "little")
        expected_value = kbase + delta
        report.add(
            test=f"R3-{name}",
            operation="read_memory",
            result="PASS" if value == expected_value else "FAIL",
            detail=f"0x{value:x} vs expected 0x{expected_value:x}",
        )

    print("  -- R5 repeat-read stability --")
    repeat_ok = True
    for name, expectation in exp.items():
        first = target.read_memory(kbase + expectation.rva, expectation.length, test=f"R5a-{name}")
        second = target.read_memory(kbase + expectation.rva, expectation.length, test=f"R5b-{name}")
        same = first.get("sha256") == second.get("sha256") and first.get("sha256")
        repeat_ok = repeat_ok and bool(same)
        report.add(
            test=f"R5-{name}",
            operation="repeat_read",
            result="PASS" if same else "FAIL",
            detail=f"identical={bool(same)} sha={first.get('sha256', '')[:16]}…",
        )
    context["repeat_stable"] = repeat_ok

    procs = target.get_process_info(max_procs=5)
    report.add(
        test="R5-F",
        operation="bounded_pointer_walk",
        result="PASS" if procs.get("ok") else "FAIL",
        detail=f"depth={procs.get('depth_used')} procs={[p.get('p_comm') for p in procs.get('processes', [])][:5]}",
    )
    context["processes"] = procs
    return context


def injection_context(transport: WorkerConsoleTransport, console: str, seconds: float = 5.0) -> dict[str, Any]:
    """Read the console's klog once and extract the loader's injection statement.

    GoldHEN names the process it injected into; combined with the payload's own ``getpid()`` that
    closes the ownership chain (our payload runs in the process the loader named).
    """

    lines: list[str] = []
    try:
        with socket.create_connection((console, 3232), timeout=5) as sock:
            sock.settimeout(seconds)
            deadline = time.time() + seconds
            while time.time() < deadline:
                try:
                    chunk = sock.recv(65536)
                except TimeoutError:
                    break
                if not chunk:
                    break
                lines.extend(chunk.decode("latin1", "replace").splitlines())
    except OSError as exc:
        return {"ok": False, "error": f"{type(exc).__name__}: {exc}", "lines": []}


def start_injection_scrape(console: str, seconds: float = 25.0) -> dict[str, Any]:
    """Start the klog scrape in the background *before* delivery.

    The klog is a live stream with no history: the loader's "jailbroken target process" line is
    emitted at delivery time, so a scrape that starts afterwards never sees it.
    """

    box: dict[str, Any] = {"done": False}
    lines: list[str] = []

    def worker() -> None:
        try:
            with socket.create_connection((console, 3232), timeout=5) as sock:
                sock.settimeout(seconds)
                deadline = time.time() + seconds
                while time.time() < deadline:
                    try:
                        chunk = sock.recv(65536)
                    except TimeoutError:
                        break
                    if not chunk:
                        break
                    lines.extend(chunk.decode("latin1", "replace").splitlines())
        except OSError as exc:
            box["error"] = f"{type(exc).__name__}: {exc}"
        finally:
            box["done"] = True
            box["lines"] = list(lines)

    thread = threading.Thread(target=worker, daemon=True)
    thread.start()
    box["thread"] = thread
    return box


def finish_injection_scrape(box: dict[str, Any]) -> dict[str, Any]:
    thread = box.get("thread")
    if thread is not None:
        thread.join(timeout=30)
    lines = box.get("lines", [])
    text = "\n".join(lines)
    match = re.search(r"jailbroken target process \[proc: ([^-]+) - pid: (\d+)\]", text)
    return {
        "ok": True,
        "process_name": match.group(1).strip() if match else "unknown",
        "pid": int(match.group(2)) if match else None,
        "launch_confirmations": len(re.findall(r"payload launched successfully", text)),
        "injection_line": match.group(0) if match else None,
        "payload_lines": [line for line in lines if "live0" in line][-8:],
        "klog_bytes": sum(len(line) for line in lines),
    }
    match = re.search(r"jailbroken target process \[proc: ([^-]+) - pid: (\d+)\]", text)
    launches = re.findall(r"payload launched successfully", text)
    context: dict[str, Any] = {
        "ok": True,
        "process_name": match.group(1).strip() if match else "unknown",
        "pid": int(match.group(2)) if match else None,
        "launch_confirmations": len(launches),
        "injection_line": match.group(0) if match else None,
        "end_lines": [line for line in lines if "live0" in line][-6:],
    }
    return context


def live_ownership(
    target: Ps4LiveTarget, report: Report, injection: dict[str, Any]
) -> dict[str, Any]:
    """Ownership gate: the test buffer must be this instance's own allocation result."""

    print("\n== ownership gate (before any user-space mutation) ==")
    info = target.get_target_info()
    if not info.get("ok"):
        report.add(
            test="OWN-1",
            operation="ownership_gate",
            result="FAIL",
            detail=f"target info unavailable: {info.get('error', info.get('error_type'))}",
        )
        return {}
    record = target.capture_allocation(
        process_name=str(injection.get("process_name", "unknown")),
        injection_pid=injection.get("pid") if isinstance(injection.get("pid"), int) else None,
        test_offset=TEST_OFFSET,
        test_length=CANARY_LEN,
    )
    if record is None:
        report.add(
            test="OWN-1",
            operation="ownership_gate",
            result="FAIL",
            detail="no payload-attributed allocation; LIVE0-U refused",
        )
        return {}
    same_pid = injection.get("pid") is None or injection.get("pid") == record.pid
    report.add(
        test="OWN-1",
        operation="ownership_gate",
        result="PASS" if same_pid else "FAIL",
        detail=(
            f"call={record.allocation_call} base=0x{record.allocation_base:x} "
            f"size=0x{record.allocation_size:x} gen={record.allocation_generation} "
            f"pid=0x{record.pid:x} process={record.process_name} "
            f"loader_pid={injection.get('pid')} instance={record.payload_instance} "
            f"test_range=0x{record.test_base:x}+0x{record.test_length:x}"
        ),
        allocation=record.to_dict(),
    )
    return record.to_dict()


def live_u(
    target: Ps4LiveTarget, report: Report, evidence: EvidenceWriter, allocation: dict[str, Any]
) -> dict[str, Any]:
    print("\n== §6/§19 LIVE0-U: user test buffer, repeated ==")
    context: dict[str, Any] = {"allocation": allocation, "cycles": [], "baselines": []}
    record = target.allocation
    if record is None:
        report.add(test="U0", operation="ownership_gate", result="FAIL", detail="no allocation")
        return context

    # ---- §4: dry-run of the exact plan, with every required field reported ----
    dry_plan = write_plan(
        address=record.test_base,
        length=CANARY_LEN,
        plan_id="U-dryrun",
        canary=canary_for("U-dryrun", CANARY_LEN),
    )
    target.dry_run = True
    dry_result = target.write_memory(dry_plan, test="U-DRY")
    target.dry_run = False
    dry = dry_result.get("dry_run", {})
    required = (
        "target_identity",
        "pid",
        "process_name",
        "allocation",
        "address_class",
        "address",
        "length",
        "original_sha256",
        "write_sha256",
        "restore_sha256",
        "persistent_sinks",
        "mutations",
        "restore_steps",
    )
    missing = [key for key in required if key not in dry]
    report.add(
        test="U-DRY",
        operation="dry_run",
        result="PASS" if dry_result.get("result") == "DRY_RUN" and not missing else "FAIL",
        detail=(
            f"pid={dry.get('pid')} proc={dry.get('process_name')} class={dry.get('address_class')} "
            f"addr={dry.get('address')} len={dry.get('length')} "
            f"original={(dry.get('original_sha256') or '')[:16]}… "
            f"write={(dry.get('write_sha256') or '')[:16]}… "
            f"restore={(dry.get('restore_sha256') or '')[:16]}… "
            f"sink_touched={dry.get('persistent_sink_touched')} mutations={dry.get('mutations')} "
            f"restore_steps={all(dry.get('restore_steps', {}).values())} missing={missing}"
        ),
        dry_run=dry,
    )

    # ---- §6/§19: three independent cycles, new experiment id and baseline each ----
    previous_post_restore: str | None = None
    for run in range(1, RUNS_PER_BUFFER + 1):
        experiment_id = f"LIVE0-U-{CURRENT_RUN_ID}-cycle{run}"
        print(f"  -- U cycle {run} ({experiment_id}) --")
        baseline = target.read_memory(
            record.test_base, CANARY_LEN, test=f"U1-{run}", operation="baseline_read"
        )
        if not baseline.get("ok"):
            report.add(
                test=f"U1-{run}", operation="baseline_read", result="FAIL", detail="unreadable"
            )
            return context
        context["baselines"].append(baseline["sha256"])
        chained = previous_post_restore is None or baseline["sha256"] == previous_post_restore
        report.add(
            test=f"U1-{run}",
            operation="baseline_read",
            result="PASS" if chained else "FAIL",
            detail=(
                f"range=0x{record.test_base:x}+0x{CANARY_LEN:x} sha={baseline['sha256'][:16]}… "
                f"matches_previous_post_restore={chained}"
            ),
            sha256=baseline["sha256"],
        )

        independent = target.channel.request(
            "KREAD_USER", timeout=target.config.request_timeout, kaddr=record.test_base, len=CANARY_LEN
        )
        independent_ok = independent.get("ok") and independent.get("hex") == baseline["data_hex"]
        report.add(
            test=f"U1b-{run}",
            operation="kread_user",
            result="PASS" if independent_ok else "PARTIAL",
            detail=(
                "kernel-copyout readback matches the user-space baseline"
                if independent_ok
                else f"independent path unavailable/differs: {independent.get('code', independent.get('error_type'))}"
            ),
        )

        canary = canary_for(experiment_id, CANARY_LEN)
        plan = write_plan(
            address=record.test_base, length=CANARY_LEN, plan_id=experiment_id, canary=canary
        )
        plan.expected["session_id"] = target.identity.session_id if target.identity else None
        plan.expected["kernel_base"] = target.kernel_base
        outcome = target.write_memory(plan, test=f"U-{run}")
        post_write_ok = outcome.get("observed_hex") == canary.hex()
        final = target.readback(record.test_base, CANARY_LEN, test=f"U5-{run}")
        post_restore_ok = final.get("sha256") == baseline["sha256"]
        previous_post_restore = final.get("sha256")

        report.add(
            test=f"U2-{run}",
            operation="canary_write",
            result="PASS"
            if outcome["mutation_state"] == MutationState.MUTATION_CONFIRMED.value
            else "FAIL",
            detail=(
                f"experiment={experiment_id} canary_sha={hashlib.sha256(canary).hexdigest()[:16]}… "
                f"mutation={outcome['mutation_state']}"
            ),
            original_sha256=baseline["sha256"],
            write_sha256=hashlib.sha256(canary).hexdigest(),
        )
        report.add(
            test=f"U3-{run}",
            operation="post_write_readback",
            result="PASS" if post_write_ok else "FAIL",
            detail=(
                f"post_write_sha={hashlib.sha256(bytes.fromhex(outcome['observed_hex'])).hexdigest()[:16]}… "
                f"equals_canary={post_write_ok}"
            ),
        )
        report.add(
            test=f"U4-{run}",
            operation="restore",
            result="PASS" if outcome["restore_state"] == RestoreState.CONFIRMED.value else "FAIL",
            detail=f"restore={outcome['restore_state']} error={outcome.get('error')}",
        )
        report.add(
            test=f"U5-{run}",
            operation="restore_readback",
            result="PASS" if post_restore_ok else "FAIL",
            detail=(
                f"post_restore_sha={final.get('sha256', 'unreadable')[:16]}… "
                f"equals_original={post_restore_ok}"
            ),
            restore_sha256=final.get("sha256"),
        )
        context["cycles"].append(
            {
                "cycle": run,
                "experiment_id": experiment_id,
                "original_sha256": baseline["sha256"],
                "write_sha256": hashlib.sha256(canary).hexdigest(),
                "post_restore_sha256": final.get("sha256"),
                "post_write_equals_canary": post_write_ok,
                "post_restore_equals_original": post_restore_ok,
                "mutation_state": outcome["mutation_state"],
                "restore_state": outcome["restore_state"],
            }
        )
        if target.state_integrity_unknown:
            report.add(
                test=f"U-{run}",
                operation="state_integrity",
                result="FAIL",
                detail=f"state integrity unknown: {target.state_integrity_reason}",
            )
            break

    if len(context["baselines"]) >= 2:
        report.add(
            test="U-repeat",
            operation="residue_check",
            result="PASS" if len(set(context["baselines"])) == 1 else "FAIL",
            detail=(
                f"{len(context['baselines'])} cycles, distinct original hashes: "
                f"{len(set(context['baselines']))}"
            ),
        )
    return context


def live_s(target: Ps4LiveTarget, report: Report) -> None:
    print("\n== §8 LIVE0-S: shared/mapped test buffer ==")
    # No shared region with proven ownership, size, lifecycle, no-persistence and no-secure-state
    # is available on this console; the only shared regions in the inventory (GPUVM/pup_update
    # staging, SBRAM, IOMMU rings) are UNKNOWN-class or belong to the secure path.
    reason = (
        "No shared/GPUVM/staging buffer currently has sufficiently proven ownership, size, "
        "lifecycle and non-persistence for mutation."
    )
    for index, operation in enumerate(
        ["shared_baseline", "shared_canary", "shared_readback", "shared_restore", "shared_restore_verify"],
        start=1,
    ):
        report.add(
            test=f"S{index}",
            operation=operation,
            result="SKIPPED_SAFETY",
            detail=reason,
        )


# --------------------------------------------------------------------- main
def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--phase",
        choices=["offline", "dry-run", "live-r", "live-u", "all"],
        default="all",
    )
    parser.add_argument("--evidence-dir", default=str(DEFAULT_EVIDENCE))
    parser.add_argument("--run-id", default=time.strftime("live0-%Y%m%dT%H%M%S"))
    parser.add_argument("--console", default="192.168.1.141")
    parser.add_argument("--worker", default="neo@192.168.1.148")
    args = parser.parse_args()

    global CURRENT_RUN_ID
    CURRENT_RUN_ID = args.run_id
    evidence_dir = Path(args.evidence_dir)
    evidence_dir.mkdir(parents=True, exist_ok=True)
    evidence = EvidenceWriter(evidence_dir, args.run_id)
    report = Report()

    summary: dict[str, Any] = {
        "run_id": args.run_id,
        "phase": args.phase,
        "console": args.console,
        "worker": args.worker,
        "started_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "orbisprobe_commit": _git(["rev-parse", "HEAD"]),
        "orbisprobe_branch": _git(["branch", "--show-current"]),
        "orbisprobe_tree": _git(["rev-parse", "HEAD^{tree}"]),
        "kernel_dump_sha256": _dump_hash(),
    }

    if args.phase in {"offline", "all"}:
        offline_negative_tests(report)
        offline_failure_tests(report)

    if args.phase in {"dry-run", "all"}:
        dry_run(report, evidence)

    if args.phase in {"live-r", "live-u", "all"}:
        config = WorkerConfig(ssh_target=args.worker, console_ip=args.console)
        transport = WorkerConsoleTransport(config)
        try:
            print("\n== transport bring-up ==")
            build = transport.build_payload()
            print(f"  build: {json.dumps(build.to_dict())}")
            summary["payload_build"] = build.to_dict()
            if not build.second_build_identical:
                report.add(
                    test="T0", operation="payload_build", result="FAIL", detail="double build differs"
                )
                return _finish(report, summary, evidence_dir, args.run_id)
            binary = transport.fetch_payload()
            summary["payload_binary_sha256"] = hashlib.sha256(binary).hexdigest()
            summary["payload_binary_size"] = len(binary)

            bridge = transport.start_bridge(lifetime=1200)
            print(f"  bridge: {bridge}")
            injection_box = (
                start_injection_scrape(args.console)
                if args.phase in {"live-u", "all"}
                else None
            )
            send = transport.send_payload(binary)
            print(f"  send: {json.dumps({k: v for k, v in send.items() if k != 'body'})}")
            summary["payload_send"] = {k: v for k, v in send.items() if k != "body"}
            if not send.get("ok"):
                report.add(
                    test="T1", operation="payload_delivery", result="FAIL", detail=str(send)
                )
                return _finish(report, summary, evidence_dir, args.run_id)
            report.add(
                test="T1",
                operation="payload_delivery",
                result="PASS",
                detail=f"HTTP {send.get('status')} size={send.get('size')} sha={send.get('sha256', '')[:16]}…",
            )

            transport.open_tunnel()
            channel = transport.open_channel(timeout=45)
            summary["payload_greeting"] = getattr(channel, "greeting", "")
            print(f"  greeting: {summary['payload_greeting']}")

            policy = LivePolicy(level="LIVE0-U")
            target = Ps4LiveTarget(
                channel,
                policy=policy,
                evidence=evidence,
                config=AdapterConfig(
                    console_host=args.console,
                    console_endpoint=f"{args.console}:9090",
                ),
            )
            # The identity gate (R1/R2/R2b) runs before every live phase, including LIVE0-U.
            context = live_r(target, report, evidence)
            summary["identity"] = (
                context["identity"].to_dict() if context.get("identity") else None
            )
            summary["snapshot"] = context.get("snapshot")
            summary["live_r_repeat_stable"] = context.get("repeat_stable")
            if args.phase in {"live-u", "all"}:
                injection = (
                    finish_injection_scrape(injection_box)
                    if injection_box is not None
                    else injection_context(transport, args.console)
                )
                summary["injection_context"] = injection
                report.add(
                    test="OWN-0",
                    operation="loader_injection",
                    result="PASS"
                    if injection.get("pid")
                    else "PASS_WITHOUT_KLOG_CORROBORATION",
                    detail=(
                        f"proc={injection.get('process_name')} pid={injection.get('pid')} "
                        f"launch_confirmations={injection.get('launch_confirmations')}"
                    ),
                )
                allocation = live_ownership(target, report, injection)
                if allocation:
                    u_context = live_u(target, report, evidence, allocation)
                    summary["live_u"] = {
                        key: value for key, value in u_context.items() if key != "allocation"
                    }
                    live_s(target, report)
                else:
                    report.add(
                        test="U-BLOCK",
                        operation="ownership_gate",
                        result="FAIL",
                        detail="ownership gate failed: LIVE0-U not started",
                    )
            target.close()
        except Exception as exc:  # noqa: BLE001 - report any transport failure as evidence
            report.add(
                test="T-EXC",
                operation="transport",
                result="FAIL",
                detail=f"{type(exc).__name__}: {exc}",
            )
        finally:
            transport.close()

    return _finish(report, summary, evidence_dir, args.run_id)


def _finish(report: Report, summary: dict[str, Any], evidence_dir: Path, run_id: str) -> int:
    summary["finished_utc"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    summary["rows"] = report.rows
    summary["failures"] = report.failed
    summary["verdict"] = _verdict(report)
    path = evidence_dir / f"{run_id}-summary.json"
    path.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    report_path = _write_report(report, summary, evidence_dir, run_id)
    print("\n== summary ==")
    print(f"  rows: {len(report.rows)}  failures: {len(report.failed)}")
    print(f"  verdict: {summary['verdict']}")
    print(f"  evidence: {path}")
    print(f"  report:   {report_path}")
    return 0 if summary["verdict"] == "PASS" else 1


def _write_report(report: Report, summary: dict[str, Any], evidence_dir: Path, run_id: str) -> Path:
    """Consolidated section-18 report: one row per test plus the run identity block."""

    columns = (
        "test",
        "operation",
        "result",
        "classification",
        "address_class",
        "address",
        "length",
        "sha256",
        "mutation_state",
        "restore_state",
        "detail",
    )
    lines = [
        f"# M2-LIVE0 consolidated evidence report - {run_id}",
        "",
        "## Run identity",
        "",
        f"- target: {summary.get('console')} (payload endpoint {summary.get('console')}:9090)",
        f"- worker/relay: {summary.get('worker')} (bridge + SSH local forward)",
        (
            f"- orbisprobe commit: {summary.get('orbisprobe_commit')} "
            f"(branch {summary.get('orbisprobe_branch')}, tree {summary.get('orbisprobe_tree')})"
        ),
        f"- started/finished: {summary.get('started_utc')} / {summary.get('finished_utc')}",
        f"- kernel dump reference: {summary.get('kernel_dump_sha256')}",
        f"- payload: {json.dumps(summary.get('payload_build'))}",
        f"- payload send: {json.dumps(summary.get('payload_send'))}",
        f"- greeting: {summary.get('payload_greeting')}",
        f"- injection context: {json.dumps(summary.get('injection_context'))}",
        f"- identity: {json.dumps(summary.get('identity'))}",
        f"- verdict: **{summary.get('verdict')}**",
        "",
        "## Test rows",
        "",
        "| " + " | ".join(columns) + " |",
        "|" + "|".join(["---"] * len(columns)) + "|",
    ]
    for row in report.rows:
        cells = []
        for column in columns:
            value = row.get(column)
            if column == "detail":
                value = str(value).replace("|", "/")[:160]
            cells.append("" if value is None else str(value))
        lines.append("| " + " | ".join(cells) + " |")

    cycles = (summary.get("live_u") or {}).get("cycles") or []
    if cycles:
        lines += ["", "## LIVE0-U cycles (original / canary / post-restore)", ""]
        lines += [
            "| cycle | experiment | original sha256 | write sha256 | post-restore sha256 | confirmed |",
            "|---|---|---|---|---|---|",
        ]
        for cycle in cycles:
            lines.append(
                f"| {cycle['cycle']} | {cycle['experiment_id']} | {cycle['original_sha256'][:16]} | "
                f"{cycle['write_sha256'][:16]} | {(cycle['post_restore_sha256'] or 'n/a')[:16]} | "
                f"{cycle['post_write_equals_canary'] and cycle['post_restore_equals_original']} |"
            )
    path = evidence_dir / f"{run_id}-report.md"
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


def _verdict(report: Report) -> str:
    if report.failed:
        return "NOT DONE"
    return "PASS"


def _git(args: list[str]) -> str:
    import subprocess

    result = subprocess.run(["git", *args], cwd=ROOT, capture_output=True, text=True, check=False)
    return result.stdout.strip()


def _dump_hash() -> str | None:
    if not KERNEL_DUMP.is_file():
        return None
    return hashlib.sha256(KERNEL_DUMP.read_bytes()).hexdigest()


if __name__ == "__main__":
    sys.exit(main())
