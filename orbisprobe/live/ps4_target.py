"""PS4 live transport adapter (M2-LIVE0).

Implements the required primitives behind the existing OrbisProbe target interface
(:class:`orbisprobe.targets.base.Target`):

``ping`` · ``get_target_info`` · ``get_kbase`` · ``read_memory`` · ``write_memory`` ·
``readback`` · ``snapshot_state`` (+ optional ``get_klog`` · ``get_process_info``)

Design rules that the implementation enforces structurally rather than by convention:

* Nothing is written unless the caller supplied a :class:`ExperimentPlan` with complete restore
  steps, the policy allowed it, and a baseline read succeeded first.
* ``write_memory`` is never a bare store: it is always the full cycle
  baseline → dispatch → readback → restore → restore-readback → verify.
* The adapter's success claim is never sufficient. A write counts as successful only when the
  post-write readback equals the expected bytes, and a restore only when the restore readback
  equals the baseline bytes (§13).
* Once a mutation has been dispatched, its state is at least ``MUTATION_ATTEMPTED``; a lost
  response never means "nothing changed" (§7). An unverifiable restore latches
  ``STATE_INTEGRITY_UNKNOWN`` and forbids further mutations in this boot (§12).
* No shell/command-execution primitive is exposed.
"""

from __future__ import annotations

import hashlib
import json
import socket
import time
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from typing import Any, Protocol

from ..targets.base import Target
from .channel import ChannelError, DryRunChannel
from .classification import USER_MAX, AddressClass, region_of
from .evidence import (
    EvidenceRecord,
    EvidenceWriter,
    MutationState,
    RestoreState,
    data_binding,
)
from .identity import TargetIdentity
from .plan import ExperimentPlan
from .policy import HARD_BLOCK_SINKS, LivePolicy, PolicyDecision
from .profile import DEFAULT_PROFILE, KernelProfile

ADAPTER_VERSION = "orbisprobe-live0-adapter-1"

MUTATION_PRIMITIVES = frozenset({"write_memory"})

#: Allocation calls whose result the host is willing to treat as our own user test buffer.
ALLOWED_ALLOCATION_CALLS = frozenset({"mmap"})


class ChannelLike(Protocol):
    def request(self, command: str, *, timeout=None, mutation: bool = False, **fields) -> dict[
        str, Any
    ]: ...

    def close(self) -> None: ...


@dataclass
class AdapterConfig:
    console_host: str = "192.168.1.141"
    payload_port: int = 9090
    klog_port: int = 3232
    console_endpoint: str = "192.168.1.141"
    request_timeout: float = 20.0
    write_timeout: float = 30.0
    klog_max_bytes: int = 32768
    klog_seconds: float = 3.0
    adapter_version: str = ADAPTER_VERSION


def utc_now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def as_int(value: Any) -> int:
    """Tolerant integer parse for payload fields.

    ``payload_info`` is updated with both the parsed identity dict and the raw wire response, so a
    numeric field may be an ``int`` or a ``"0x..."`` string depending on which write won. Never
    raise on a payload-supplied value: an unparsable field must fail a gate, not crash the run.
    """

    if isinstance(value, bool):
        return 0
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return 0
        try:
            return int(text, 16) if text.lower().startswith("0x") else int(text, 10)
        except ValueError:
            return 0
    return 0


PAYLOAD_INFO_REQUIRED = (
    "pid",
    "instance_id",
    "allocation_method",
    "allocation_base",
    "allocation_return",
    "allocation_size",
    "allocation_generation",
    "session_id",
)


@dataclass(frozen=True)
class PayloadInfo:
    """The single validated source of truth for payload-reported values.

    Produced exactly once per ``INFO`` response by :func:`parse_payload_info` and never merged with,
    or overwritten by, the raw response dict — the raw dict lives in ``raw_target_info`` and is
    evidence only. A parser that cannot fill every ``PAYLOAD_INFO_REQUIRED`` field is a hard
    ``PAYLOAD_INFO_INCOMPLETE`` failure, never a default-0 structure.
    """

    pid: int
    process_name: str
    instance_id: str
    allocation_method: str
    allocation_base: int
    allocation_return: int
    allocation_size: int
    allocation_generation: int
    payload_version: str
    firmware: str
    kbase: int
    session_id: str = ""
    endpoint: str = ""
    test_buffer: int = 0
    test_buffer_size: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "pid": self.pid,
            "process_name": self.process_name,
            "instance_id": self.instance_id,
            "allocation_method": self.allocation_method,
            "allocation_base": f"0x{self.allocation_base:x}",
            "allocation_return": f"0x{self.allocation_return:x}",
            "allocation_size": f"0x{self.allocation_size:x}",
            "allocation_generation": self.allocation_generation,
            "payload_version": self.payload_version,
            "firmware": self.firmware,
            "kbase": f"0x{self.kbase:x}",
            "session_id": self.session_id,
            "endpoint": self.endpoint,
        }

    def with_session(self, session_id: str) -> PayloadInfo:
        return replace(self, session_id=session_id)


def parse_payload_info(
    response: dict[str, Any],
    *,
    process_name: str = "unknown",
    endpoint: str = "",
    session_id: str = "",
) -> tuple[PayloadInfo | None, list[str]]:
    """raw response -> parser -> validation -> PayloadInfo.

    Returns ``(None, missing_fields)`` when a required field is absent, empty or zero; the caller
    must treat that as ``PAYLOAD_INFO_INCOMPLETE`` and refuse mutation.
    """

    missing: list[str] = []

    def text(key: str) -> str:
        value = response.get(key)
        return value.strip() if isinstance(value, str) else ""

    def number(key: str, field: str, *, required_nonzero: bool = True) -> int:
        raw = response.get(key)
        if raw in (None, ""):
            missing.append(field)
            return 0
        value = as_int(raw)
        if value == 0 and required_nonzero:
            missing.append(field)
        return value

    pid = number("pid", "pid")
    allocation_base = number("buf", "allocation_base")
    allocation_return = number("alloc_ret", "allocation_return")
    allocation_size = number("alloc_size", "allocation_size")
    allocation_generation = number("alloc_seq", "allocation_generation")
    method = text("alloc")
    if not method:
        missing.append("allocation_method")
    instance_id = text("instance")
    if not instance_id:
        missing.append("instance_id")
    payload_version = text("payload") or "unknown"
    firmware = text("fw")
    if not firmware:
        missing.append("firmware")
    kbase = number("kbase", "kbase")
    if missing:
        return None, sorted(set(missing))
    return (
        PayloadInfo(
            pid=pid,
            process_name=process_name,
            instance_id=instance_id,
            allocation_method=method,
            allocation_base=allocation_base,
            allocation_return=allocation_return,
            allocation_size=allocation_size,
            allocation_generation=allocation_generation,
            payload_version=payload_version,
            firmware=firmware,
            kbase=kbase,
            session_id=session_id,
            endpoint=endpoint,
            test_buffer=allocation_base,
            test_buffer_size=allocation_size,
        ),
        [],
    )


@dataclass(frozen=True)
class AllocationRecord:
    """Provenance of the user-space test buffer, captured per payload attachment.

    A buffer may only be used for LIVE0-U when the whole chain below is reported by the payload in
    this attachment: an allocation *call* happened, its return value is the recorded buffer base,
    the recorded size is the allocation size, and the address is inside the user range. A base
    that is merely *found* (pattern/pointer search) or derived from an existing Sony object has no
    such chain and is refused.
    """

    session_id: str
    pid: int
    process_name: str
    allocation_call: str
    allocation_base: int
    allocation_size: int
    allocation_generation: int
    payload_instance: str
    test_offset: int
    test_length: int
    captured_utc: str = ""

    @property
    def test_base(self) -> int:
        return self.allocation_base + self.test_offset

    def covers(self, address: int, length: int) -> bool:
        return (
            address >= self.allocation_base
            and address + length <= self.allocation_base + self.allocation_size
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "session_id": self.session_id,
            "pid": self.pid,
            "process_name": self.process_name,
            "allocation_call": self.allocation_call,
            "allocation_base": f"0x{self.allocation_base:x}",
            "allocation_size": f"0x{self.allocation_size:x}",
            "allocation_generation": self.allocation_generation,
            "payload_instance": self.payload_instance,
            "test_offset": f"0x{self.test_offset:x}",
            "test_length": self.test_length,
            "test_base": f"0x{self.test_base:x}",
            "captured_utc": self.captured_utc,
        }


class Ps4LiveTarget(Target):
    def __init__(
        self,
        channel: ChannelLike | None = None,
        *,
        policy: LivePolicy | None = None,
        profile: KernelProfile = DEFAULT_PROFILE,
        config: AdapterConfig | None = None,
        evidence: EvidenceWriter | None = None,
        dry_run: bool = False,
        identity: TargetIdentity | None = None,
    ) -> None:
        self.channel = channel if channel is not None else DryRunChannel()
        self.policy = policy or LivePolicy(level="LIVE0-R")
        self.profile = profile
        self.config = config or AdapterConfig()
        self.evidence = evidence
        self.dry_run = dry_run
        self.identity = identity
        self.kernel_base: int | None = None
        #: Evidence only — never read for decisions.
        self.raw_target_info: dict[str, Any] = {}
        self.last_ping: dict[str, Any] = {}
        #: The validated, write-once structure all gates read.
        self.payload_info: PayloadInfo | None = None
        self.payload_info_missing: list[str] = []
        self.injection_context: dict[str, Any] = {}
        self.allocation_stale_reason: str = ""
        self.test_buffer: int | None = None
        self.test_buffer_size: int = 0
        self.allocation: AllocationRecord | None = None
        self.state_integrity_unknown = False
        self.state_integrity_reason = ""
        self.late_responses: list[dict[str, Any]] = []
        self._test_index = 0

    # ------------------------------------------------------------------ helpers
    def _next_test(self, prefix: str) -> str:
        self._test_index += 1
        return f"{prefix}{self._test_index}"

    def _base_record(self, **kwargs: Any) -> EvidenceRecord:
        identity = self.identity
        return EvidenceRecord(
            target_name=identity.target_name if identity else "unbound",
            session_id=identity.session_id if identity else "unbound",
            firmware=identity.firmware if identity else str(self.profile.firmware),
            kernel_base=self.kernel_base or 0,
            adapter_version=self.config.adapter_version,
            payload_version=self.payload_info.payload_version if self.payload_info else "",
            endpoint=self.config.console_endpoint,
            timestamp_utc=utc_now(),
            **kwargs,
        )

    def _emit(self, record: EvidenceRecord) -> EvidenceRecord:
        if self.evidence is not None:
            self.evidence.record(record)
        return record

    def _block(self, test: str, reason: str, **kwargs: Any) -> dict[str, Any]:
        record = self._base_record(
            test=test,
            address_class="UNKNOWN",
            address=kwargs.pop("address", 0),
            length=kwargs.pop("length", 0),
            operation=kwargs.pop("operation", "blocked"),
            expected=kwargs.pop("expected", ""),
            observed=kwargs.pop("observed", "BLOCKED"),
            mutation_state=MutationState.NONE.value,
            restore_state=RestoreState.NOT_REQUIRED.value,
            adapter_status="blocked",
            result="BLOCK",
            error_type=kwargs.pop("error_type", "policy_block"),
            error=reason,
            **kwargs,
        )
        self._emit(record)
        return {"ok": False, "result": "BLOCK", "error_type": "policy_block", "error": reason}

    # ------------------------------------------------------------------ primitives
    def ping(self) -> dict[str, Any]:
        test = self._next_test("R")
        try:
            response = self.channel.request("PING", timeout=self.config.request_timeout)
        except ChannelError as exc:
            self._emit(
                self._base_record(
                    test=test,
                    address_class="NONE",
                    address=0,
                    length=0,
                    operation="ping",
                    expected="payload alive",
                    observed="NO RESPONSE",
                    mutation_state=MutationState.NONE.value,
                    restore_state=RestoreState.NOT_REQUIRED.value,
                    adapter_status=exc.error_type,
                    result="FAIL",
                    error_type=exc.error_type,
                    error=str(exc),
                )
            )
            return exc.to_dict()
        # ping data is evidence only; the validated structure stays the single truth
        self.last_ping = {k: v for k, v in response.items() if k not in {"ok", "command"}}
        self._emit(
            self._base_record(
                test=test,
                address_class="NONE",
                address=0,
                length=0,
                operation="ping",
                expected="payload alive",
                observed=f"payload={response.get('payload')} uptime_ms={response.get('uptime_ms')}",
                mutation_state=MutationState.NONE.value,
                restore_state=RestoreState.NOT_REQUIRED.value,
                adapter_status="ok",
                result="PASS",
            )
        )
        return response

    def get_target_info(self) -> dict[str, Any]:
        test = self._next_test("R")
        try:
            response = self.channel.request("INFO", timeout=self.config.request_timeout)
        except ChannelError as exc:
            return exc.to_dict()
        if not response.get("ok"):
            return response
        # raw response is evidence only; it is never merged into the parsed structure
        self.raw_target_info = dict(response)
        session_id = self.identity.session_id if self.identity else ""
        parsed, missing = parse_payload_info(
            response,
            process_name=str(self.injection_context.get("process_name", "unknown")),
            endpoint=self.config.console_endpoint,
            session_id=session_id,
        )
        self.payload_info_missing = missing
        if parsed is None:
            # Fail closed. A previously validated structure is left untouched rather than being
            # replaced by defaults, and no gate may act on incomplete information.
            return {
                "ok": False,
                "error_type": "PAYLOAD_INFO_INCOMPLETE",
                "missing_fields": missing,
                "error": "payload INFO incomplete: " + ", ".join(missing),
            }
        previous = self.payload_info
        if previous is not None:
            changed: list[str] = []
            for name in ("pid", "allocation_base", "allocation_generation"):
                before, after = getattr(previous, name), getattr(parsed, name)
                if before != after:
                    changed.append(f"{name}: 0x{before:x} -> 0x{after:x}")
            for name in ("instance_id", "session_id"):
                before, after = getattr(previous, name), getattr(parsed, name)
                if before != after:
                    changed.append(f"{name}: {before} -> {after}")
            if changed:
                # never silently update the old record: invalidate it and require re-capture
                self.allocation_stale_reason = (
                    "payload/session changed since capture: " + "; ".join(changed)
                )
                self.allocation = None
        self.payload_info = parsed
        kernel_base = parsed.kbase
        self.kernel_base = kernel_base
        self.test_buffer = parsed.test_buffer
        self.test_buffer_size = parsed.test_buffer_size
        if kernel_base:
            self.policy.image = _image_layout(self.profile, kernel_base)
        if parsed.test_buffer:
            owned = region_of(
                "live0-test-buffer",
                parsed.test_buffer,
                parsed.test_buffer_size,
                AddressClass.USER,
            )
            self.policy.owned_regions = (owned,)
        self._emit(
            self._base_record(
                test=test,
                address_class="NONE",
                address=0,
                length=0,
                operation="get_target_info",
                expected="identity fields reported",
                observed=(
                    f"fw={parsed.firmware} kbase=0x{parsed.kbase:x} "
                    f"payload={parsed.payload_version} buf=0x{parsed.test_buffer:x} "
                    f"pid=0x{parsed.pid:x} instance={parsed.instance_id}"
                ),
                mutation_state=MutationState.NONE.value,
                restore_state=RestoreState.NOT_REQUIRED.value,
                adapter_status="ok",
                result="PASS",
                extra={
                    "raw_response": self.raw_target_info,
                    "parsed": parsed.to_dict(),
                },
            )
        )
        info = {
            "ok": True,
            **parsed.to_dict(),
            # convenience views of the validated structure (never raw-response values)
            "kernel_base": parsed.kbase,
            "test_buffer": parsed.test_buffer,
            "test_buffer_size": parsed.test_buffer_size,
            "payload_version": parsed.payload_version,
            "missing_fields": [],
        }
        return info

    def get_kbase(self) -> dict[str, Any]:
        if self.kernel_base is None:
            info = self.get_target_info()
            if not info.get("ok"):
                return info
        return {"ok": True, "kernel_base": f"0x{self.kernel_base:016x}"}

    # ------------------------------------------------------------------ ownership gate
    def capture_allocation(
        self,
        *,
        process_name: str = "unknown",
        injection_pid: int | None = None,
        test_offset: int = 0x100,
        test_length: int = 32,
    ) -> AllocationRecord | None:
        """Prove that the test buffer is this payload instance's own allocation result.

        Refuses (returns ``None`` and records a BLOCK row) when any link of the chain is missing:
        allocation call, returned base == recorded buffer base, allocation size == recorded size,
        user-range address, existing identity/session, and — when the loader named the injection
        process — a matching pid.
        """

        info = self.payload_info
        test = "OWN-1"
        reasons: list[str] = []
        if info is None:
            reasons.append(
                "PAYLOAD_INFO_INCOMPLETE: "
                + (", ".join(self.payload_info_missing) or "no validated payload info received")
            )
        else:
            call = info.allocation_method
            base = info.allocation_base
            size = info.allocation_size
            alloc_ret = info.allocation_return
            alloc_size = info.allocation_size
            pid = info.pid
            instance = info.instance_id
            generation = info.allocation_generation
            # A: allocation primitive
            if call not in ALLOWED_ALLOCATION_CALLS:
                reasons.append(f"A: allocation method {call!r} is not an allowed allocator")
            # B: the recorded base IS the allocation result
            if base != alloc_ret:
                reasons.append(
                    f"B: recorded buffer 0x{base:x} is not the allocation result 0x{alloc_ret:x}"
                )
            # C: non-zero size
            if alloc_size <= 0:
                reasons.append("C: allocation size is zero")
            if size != alloc_size:
                reasons.append(
                    f"C: recorded size 0x{size:x} is not the allocation size 0x{alloc_size:x}"
                )
            # D: bounded test range inside the allocation
            if test_offset < 0 or test_length <= 0:
                reasons.append("D: invalid test range")
            elif test_offset + test_length > size:
                reasons.append(
                    f"D: test range 0x{test_offset:x}+0x{test_length:x} exceeds the allocation "
                    f"0x{size:x}"
                )
            # E/F/G/H: instance, pid, generation, session
            if not instance:
                reasons.append("E: instance id missing")
            if not pid:
                reasons.append("F: pid missing")
            if generation < 1:
                reasons.append("G: allocation generation missing")
            if not info.session_id:
                reasons.append("H: session id missing")
            if self.identity is not None and info.session_id != self.identity.session_id:
                reasons.append(
                    f"H: session {info.session_id} does not match the bound session "
                    f"{self.identity.session_id}"
                )
            if self.identity is None:
                reasons.append("H: no identity bound to this attachment")
            if not base or base >= USER_MAX:
                reasons.append(f"B: allocation base 0x{base:x} is not in the user address range")
            # klog is corroborating evidence only: absent is fine, contradicting is not
            if injection_pid is not None and pid and injection_pid != pid:
                reasons.append(
                    f"CONFLICT: loader reported injection into pid 0x{injection_pid:x}, payload "
                    f"runs as pid 0x{pid:x}"
                )
        call = info.allocation_method if info is not None else ""
        base = info.allocation_base if info is not None else 0
        size = info.allocation_size if info is not None else 0
        alloc_ret = info.allocation_return if info is not None else 0
        alloc_size = info.allocation_size if info is not None else 0
        pid = info.pid if info is not None else 0
        instance = info.instance_id if info is not None else ""
        generation = info.allocation_generation if info is not None else 0
        injection_claim = (
            "INJECTION_CONTEXT_CONFIRMED"
            if injection_pid is not None and pid and injection_pid == pid
            else "INJECTION_CONTEXT_CORROBORATION_MISSING"
        )
        if injection_pid is None or not pid:
            klog_state = "absent"
        elif injection_pid == pid:
            klog_state = "corroborating_match"
        else:
            klog_state = "contradicting"
        if reasons:
            self._block(
                test,
                "ownership gate failed: " + "; ".join(reasons),
                address=base,
                length=size,
                operation="capture_allocation",
                expected="payload-attributed allocation",
                observed="REFUSED",
            )
            return None
        record = AllocationRecord(
            session_id=self.identity.session_id if self.identity else "unbound",
            pid=pid,
            process_name=process_name,
            allocation_call=call,
            allocation_base=base,
            allocation_size=size,
            allocation_generation=generation,
            payload_instance=instance,
            test_offset=test_offset,
            test_length=test_length,
            captured_utc=utc_now(),
        )
        self.allocation = record
        self.test_buffer = base
        self.test_buffer_size = size
        self.policy.owned_regions = (
            region_of("live0-test-buffer", base, size, AddressClass.USER),
        )
        self._emit(
            self._base_record(
                test=test,
                address_class=AddressClass.USER.value,
                address=base,
                length=size,
                operation="capture_allocation",
                expected="payload-attributed allocation",
                observed=(
                    f"call={call} ret=0x{alloc_ret:x} size=0x{alloc_size:x} gen={generation} "
                    f"pid=0x{pid:x} instance={instance}"
                ),
                mutation_state=MutationState.NONE.value,
                restore_state=RestoreState.NOT_REQUIRED.value,
                adapter_status="ok",
                result="PASS",
                extra={
                    **record.to_dict(),
                    "BUFFER_OWNERSHIP": "OWNERSHIP_CONFIRMED",
                    "INJECTION_CONTEXT": injection_claim,
                    "klog_corroboration": klog_state,
                    "payload_info": self.payload_info.to_dict() if self.payload_info else None,
                    "raw_info_sha256": hashlib.sha256(
                        json.dumps(self.raw_target_info, sort_keys=True).encode()
                    ).hexdigest(),
                },
            )
        )
        return record

    def allocation_block(self) -> str | None:
        """Reasons the current allocation record may not be used for a mutation right now."""

        if self.payload_info is None and self.payload_info_missing:
            return (
                "PAYLOAD_INFO_INCOMPLETE: a user-space mutation requires complete payload "
                "info (" + ", ".join(self.payload_info_missing) + ")"
            )
        record = self.allocation
        if record is None:
            return (
                "no allocation record: a user-space mutation requires a freshly captured "
                "payload-attributed allocation"
            )
        if self.allocation_stale_reason:
            return "STALE buffer: " + self.allocation_stale_reason
        info = self.payload_info
        if info is None:
            return "STALE buffer: no validated payload info"
        if self.identity is not None and record.session_id != self.identity.session_id:
            return "STALE buffer: bound session changed since the allocation was captured"
        checks = (
            (info.instance_id, record.payload_instance, "payload instance"),
            (info.pid, record.pid, "payload pid"),
            (info.allocation_base, record.allocation_base, "allocation base"),
            (info.allocation_generation, record.allocation_generation, "allocation generation"),
        )
        for current, captured, label in checks:
            if current != captured:
                return f"STALE buffer: {label} changed since capture"
        return None

    def test_range(self, length: int, offset: int | None = None) -> tuple[int, int]:
        """Resolve the bounded test range inside our own allocation (never the whole buffer)."""

        record = self.allocation
        if record is None:
            raise ValueError("no allocation record")
        off = record.test_offset if offset is None else offset
        if off < 0 or length <= 0:
            raise ValueError("invalid test range")
        if off + length > record.allocation_size:
            raise ValueError(
                f"test range 0x{off:x}+0x{length:x} exceeds allocation 0x{record.allocation_size:x}"
            )
        return record.allocation_base + off, length

    def _dry_run_report(self, plan: ExperimentPlan, decision: PolicyDecision) -> dict[str, Any]:
        """Everything a mutating plan must show before it is allowed to dispatch anything."""

        op = plan.writes[0]
        report: dict[str, Any] = {
            "plan_id": plan.plan_id,
            "level": plan.level,
            "policy_allowed": decision.allowed,
            "policy_blocks": list(decision.blocks),
            "target_identity": self.identity.to_dict() if self.identity else None,
            "pid": self.payload_info.pid if self.payload_info else 0,
            "process_name": self.allocation.process_name if self.allocation else "unknown",
            "allocation": self.allocation.to_dict() if self.allocation else None,
            "address_class": decision.classifications.get(op.address, "UNKNOWN"),
            "address": f"0x{op.address:x}",
            "length": op.length,
            "write_sha256": hashlib.sha256(op.data).hexdigest(),
            "mutations": len(plan.writes),
            "restore_steps": {
                "baseline_read": plan.restore_steps.baseline_read,
                "restore_write": plan.restore_steps.restore_write,
                "restore_readback": plan.restore_steps.restore_readback,
                "verify_equality": plan.restore_steps.verify_equality,
            },
            "persistent_sinks": list(HARD_BLOCK_SINKS),
            "persistent_sink_touched": plan.declared_sink in HARD_BLOCK_SINKS,
        }
        baseline = self.read_memory(
            op.address, op.length, test=f"{plan.plan_id}-dry-baseline", operation="dry_run_read"
        )
        if baseline.get("ok"):
            report["original_sha256"] = baseline["sha256"]
            report["restore_sha256"] = baseline["sha256"]
        else:
            report["original_sha256"] = None
            report["restore_sha256"] = None
            report["baseline_error"] = baseline.get("error", baseline.get("error_type"))
        return report

    def capture_identity(self, *, target_name: str = "ps4b-cuh2116a") -> TargetIdentity:
        info = self.get_target_info()
        if not info.get("ok"):
            raise ChannelError(
                info.get("error_type", "identity_failure"), info.get("error", "no identity")
            )
        snapshot = self.snapshot_state()
        witnesses = {
            key: snapshot.get("values", {}).get(key) for key in sorted(self.profile.heap_pointers)
        }
        witnesses["prison0_delta_ok"] = snapshot.get("base_relative_ok", {}).get("prison0")
        session_id = TargetIdentity.derive_session_id(
            firmware=str(info["firmware"]),
            kernel_base=int(info["kernel_base"]),
            witnesses=witnesses,
        )
        fingerprint = self.kernel_fingerprint()
        if self.payload_info is not None:
            self.payload_info = self.payload_info.with_session(session_id)
        self.identity = TargetIdentity(
            target_name=target_name,
            firmware=str(info["firmware"]),
            session_id=session_id,
            kernel_base=int(info["kernel_base"]),
            kernel_fingerprint=fingerprint,
            adapter_version=self.config.adapter_version,
            payload_version=str(info["payload_version"]),
            endpoint=str(info["endpoint"]),
            captured_utc=utc_now(),
            consistency_witnesses=witnesses,
        )
        return self.identity

    # ------------------------------------------------------------------ reads
    def _read_allowed(self, address: int, length: int) -> str | None:
        cls = self.policy.classify(address)
        if cls is AddressClass.MMIO and not self.policy.allow_mmio_read:
            return f"MMIO read at 0x{address:x} is not classified safe"
        if cls.value not in self.policy.allowed_read_classes:
            return f"read class {cls.value} at 0x{address:x} is not allowed"
        if length > self.policy.max_read:
            return f"read of 0x{length:x} bytes exceeds max_read 0x{self.policy.max_read:x}"
        if not self.policy.owned_regions and cls is AddressClass.USER:
            return f"USER address 0x{address:x} is not owned by this adapter"
        return None

    def read_memory(
        self,
        address: int,
        length: int,
        *,
        test: str = "",
        operation: str = "read_memory",
        expect_sha256: str | None = None,
        expect_bytes: bytes | None = None,
        label: str = "",
    ) -> dict[str, Any]:
        test = test or self._next_test("R")
        block = self._read_allowed(address, length)
        if block:
            return self._block(test, block, address=address, length=length, operation=operation)
        cls = self.policy.classify(address)
        # The payload's READ path is a kernel copyout and refuses user addresses by design; our own
        # user-space test buffer is read through VERIFY (direct user load) instead, with KREAD_USER
        # available as an independent kernel-path cross-check.
        command = "VERIFY" if cls is AddressClass.USER else "READ"
        try:
            response = self.channel.request(
                command,
                timeout=self.config.request_timeout,
                kaddr=address,
                len=length,
            )
        except ChannelError as exc:
            self._emit(
                self._base_record(
                    test=test,
                    address_class=cls.value,
                    address=address,
                    length=length,
                    operation=operation,
                    expected=f"{length} bytes",
                    observed="NO RESPONSE",
                    mutation_state=MutationState.NONE.value,
                    restore_state=RestoreState.NOT_REQUIRED.value,
                    adapter_status=exc.error_type,
                    result="FAIL",
                    error_type=exc.error_type,
                    error=str(exc),
                )
            )
            return exc.to_dict()
        if not response.get("ok"):
            return {"ok": False, **response}
        payload_rc = response.get("rc", "0")
        if payload_rc not in {"0", "0x0"}:
            return {
                "ok": False,
                "error_type": "read_fault",
                "error": f"payload read rc={payload_rc}",
                "address": f"0x{address:x}",
                "length": length,
            }
        try:
            data = bytes.fromhex(response.get("hex", ""))
        except ValueError as exc:
            return {"ok": False, "error_type": "malformed_response", "error": str(exc)}
        if len(data) != length:
            return {
                "ok": False,
                "error_type": "partial_response",
                "error": f"expected {length} bytes, payload returned {len(data)}",
            }
        digest = hashlib.sha256(data).hexdigest()
        preview_hex, artifact = None, None
        if self.evidence is not None:
            _d, preview_hex, artifact = data_binding(self.evidence, f"{test}-{address:x}", data)
        expected_text = ""
        result = "PASS"
        if expect_bytes is not None:
            expected_text = hashlib.sha256(expect_bytes).hexdigest()
            result = "PASS" if data == expect_bytes else "FAIL"
        elif expect_sha256 is not None:
            expected_text = expect_sha256
            result = "PASS" if digest == expect_sha256 else "FAIL"
        self._emit(
            self._base_record(
                test=test,
                address_class=cls.value,
                address=address,
                length=length,
                operation=operation,
                expected=expected_text or f"{length} bytes",
                observed=digest,
                mutation_state=MutationState.NONE.value,
                restore_state=RestoreState.NOT_REQUIRED.value,
                adapter_status="ok",
                result=result,
                sha256=digest,
                preview_hex=preview_hex,
                artifact_path=artifact,
                notes=label,
            )
        )
        return {
            "ok": True,
            "address": f"0x{address:x}",
            "length": length,
            "sha256": digest,
            "data_hex": data.hex() if length <= 256 else None,
            "data": data if length <= 256 else None,
            "address_class": cls.value,
            "result": result,
        }

    def readback(self, address: int, length: int, *, test: str = "") -> dict[str, Any]:
        return self.read_memory(address, length, test=test, operation="readback")

    def kernel_fingerprint(self) -> str:
        """SHA-256 over the image-relative content samples (boot-independent image identity)."""

        kernel_base = self.kernel_base
        if kernel_base is None:
            raise ChannelError("no_kernel_base", "kernel base unknown")
        digest = hashlib.sha256()
        for name in sorted(self.profile.content_rvas):
            rva = self.profile.content_rvas[name]
            length = 64 if name == "elf_header" else 256
            result = self.read_memory(
                kernel_base + rva,
                length,
                test=f"FP-{name}",
                operation="read_memory",
                label="kernel fingerprint sample",
            )
            digest.update(name.encode())
            digest.update(str(rva).encode())
            digest.update(str(result.get("sha256", "unavailable")).encode())
        return digest.hexdigest()

    def snapshot_state(self, *, test: str = "") -> dict[str, Any]:
        test = test or self._next_test("R")
        if self.kernel_base is None:
            return {"ok": False, "error_type": "no_kernel_base", "error": "kernel base unknown"}
        values: dict[str, Any] = {}
        base_relative_ok: dict[str, Any] = {}
        for name, (rva, delta) in sorted(self.profile.base_relative.items()):
            result = self.read_memory(
                self.kernel_base + rva,
                8,
                test=f"{test}-{name}",
                operation="snapshot_state",
                label=f"{name} pointer slot",
            )
            if not result.get("ok"):
                values[name] = None
                base_relative_ok[name] = False
                continue
            raw = bytes.fromhex(result["data_hex"])
            value = int.from_bytes(raw, "little")
            values[name] = f"0x{value:016x}"
            base_relative_ok[name] = value == self.kernel_base + delta
        heap: dict[str, Any] = {}
        for name, rva in sorted(self.profile.heap_pointers.items()):
            result = self.read_memory(
                self.kernel_base + rva,
                8,
                test=f"{test}-{name}",
                operation="snapshot_state",
                label=f"{name} pointer slot",
            )
            if not result.get("ok"):
                heap[name] = None
                continue
            value = int.from_bytes(bytes.fromhex(result["data_hex"]), "little")
            heap[name] = f"0x{value:016x}"
        return {
            "ok": True,
            "kernel_base": f"0x{self.kernel_base:016x}",
            "values": {**values, **heap},
            "base_relative_ok": base_relative_ok,
            "timestamp_utc": utc_now(),
        }

    # ------------------------------------------------------------------ writes
    def write_memory(self, plan: ExperimentPlan, *, test: str = "") -> dict[str, Any]:
        """Execute the full, bounded mutation cycle for ``plan``.

        This is the only path that mutates anything, and it always ends with a restore attempt.
        """

        if not plan.writes:
            return {"ok": False, "result": "BLOCK", "error_type": "no_write_in_plan"}
        test = test or self._next_test("U")
        op = plan.writes[0]

        if self.state_integrity_unknown:
            return self._block(
                test,
                "state integrity unknown in this boot: further mutations refused "
                f"({self.state_integrity_reason})",
                address=op.address,
                length=op.length,
                operation="write_memory",
            )

        allocation_block = self.allocation_block()
        if allocation_block:
            return self._block(
                test,
                allocation_block,
                address=op.address,
                length=op.length,
                operation="write_memory",
                expected=f"canary over {op.length} bytes",
            )

        if self.allocation is not None and not self.allocation.covers(op.address, op.length):
            return self._block(
                test,
                f"plan address 0x{op.address:x}+0x{op.length:x} is outside the allocated test "
                f"buffer 0x{self.allocation.allocation_base:x}+0x{self.allocation.allocation_size:x}",
                address=op.address,
                length=op.length,
                operation="write_memory",
                expected=f"canary over {op.length} bytes",
            )

        decision: PolicyDecision = self.policy.evaluate(
            plan, self.identity, live_kernel_base=self.kernel_base
        )
        if not decision.allowed:
            return self._block(
                test,
                "; ".join(decision.blocks),
                address=op.address,
                length=op.length,
                operation="write_memory",
                expected=f"canary over {op.length} bytes",
            )

        if self.dry_run:
            dry = self._dry_run_report(plan, decision)
            self._emit(
                self._base_record(
                    test=test,
                    address_class=decision.classifications.get(op.address, "UNKNOWN"),
                    address=op.address,
                    length=op.length,
                    operation="write_memory",
                    expected=f"canary over {op.length} bytes",
                    observed="DRY_RUN: no mutation dispatched",
                    mutation_state=MutationState.NONE.value,
                    restore_state=RestoreState.NOT_REQUIRED.value,
                    adapter_status="dry_run",
                    result="DRY_RUN",
                    notes="policy allowed; mutation suppressed by dry-run mode",
                    extra=dry,
                )
            )
            return {"ok": True, "result": "DRY_RUN", "dry_run": dry, "policy": decision.blocks}

        # 1. baseline
        baseline_result = self.read_memory(
            op.address,
            op.length,
            test=f"{test}-baseline",
            operation="baseline_read",
            label="pre-write baseline",
        )
        if not baseline_result.get("ok"):
            return {
                "ok": False,
                "result": "ABORT",
                "error_type": "baseline_failed",
                "cause": baseline_result.get("error_type"),
                "error": baseline_result.get("error", "baseline read failed"),
            }
        baseline = bytes.fromhex(baseline_result["data_hex"])
        if baseline == op.data:
            return {
                "ok": False,
                "result": "ABORT",
                "error_type": "canary_equals_baseline",
                "error": "canary already equals the baseline; not a discriminating mutation",
            }

        mutation_state = MutationState.NONE.value
        restore_state = RestoreState.PENDING.value
        dispatched = False
        write_error: str | None = None
        try:
            response = self.channel.request(
                "WRITE",
                timeout=self.config.write_timeout,
                mutation=True,
                kaddr=op.address,
                hex=op.data.hex(),
            )
            dispatched = True
            if not response.get("ok"):
                write_error = str(response.get("error", "payload reported write error"))
        except ChannelError as exc:
            dispatched = bool(exc.dispatched) or exc.error_type.endswith("after_write")
            write_error = f"{exc.error_type}: {exc}"

        if dispatched:
            mutation_state = MutationState.MUTATION_ATTEMPTED.value

        # 2. readback / verify
        observed_hex = None
        if dispatched and write_error is None:
            verify = self.read_memory(
                op.address,
                op.length,
                test=f"{test}-readback",
                operation="post_write_readback",
                label="independent readback after write",
            )
            if verify.get("ok"):
                observed_hex = "".join(
                    f"{b:02x}" for b in bytes.fromhex(verify["data_hex"])
                )
                if bytes.fromhex(observed_hex) == op.data:
                    mutation_state = MutationState.MUTATION_CONFIRMED.value
                else:
                    mutation_state = MutationState.MUTATION_FAILED.value
            else:
                write_error = write_error or verify.get("error", "readback failed")

        # 3. restore — always attempted once something was dispatched
        restored = False
        if dispatched:
            restore_state = RestoreState.PENDING.value
            try:
                self.channel.request(
                    "WRITE",
                    timeout=self.config.write_timeout,
                    mutation=True,
                    kaddr=op.address,
                    hex=baseline.hex(),
                )
                verify_restore = self.read_memory(
                    op.address,
                    op.length,
                    test=f"{test}-restore-readback",
                    operation="restore_readback",
                    label="readback after restore",
                )
                if verify_restore.get("ok") and bytes.fromhex(verify_restore["data_hex"]) == baseline:
                    restore_state = RestoreState.CONFIRMED.value
                    restored = True
                else:
                    restore_state = RestoreState.FAILED.value
            except ChannelError as exc:
                restore_state = RestoreState.UNKNOWN.value
                write_error = f"restore failed: {exc.error_type}: {exc}"

        if dispatched and not restored:
            self.state_integrity_unknown = True
            self.state_integrity_reason = (
                write_error or "restore could not be verified equal to the baseline"
            )
            restore_state = RestoreState.UNKNOWN.value

        result = "PASS" if (mutation_state == MutationState.MUTATION_CONFIRMED.value and restored) else "FAIL"
        if dispatched and mutation_state == MutationState.MUTATION_ATTEMPTED.value and restored:
            result = "PARTIAL"

        self._emit(
            self._base_record(
                test=test,
                address_class=decision.classifications.get(op.address, "UNKNOWN"),
                address=op.address,
                length=op.length,
                operation="write_memory",
                expected=hashlib.sha256(op.data).hexdigest(),
                observed=observed_hex or (write_error or "not dispatched"),
                mutation_state=mutation_state,
                restore_state=restore_state,
                adapter_status="ok" if write_error is None else "error",
                result=result,
                sha256=hashlib.sha256(op.data).hexdigest(),
                preview_hex=op.data[:64].hex(),
                error_type=None if write_error is None else "write_cycle_error",
                error=write_error,
                extra={
                    "baseline_sha256": hashlib.sha256(baseline).hexdigest(),
                    "plan_id": plan.plan_id,
                },
            )
        )
        return {
            "ok": result in {"PASS", "PARTIAL"},
            "result": result,
            "mutation_state": mutation_state,
            "restore_state": restore_state,
            "observed_hex": observed_hex,
            "error": write_error,
        }

    # ------------------------------------------------------------------ optional
    def get_klog(self, *, test: str = "") -> dict[str, Any]:
        test = test or self._next_test("K")
        if self.dry_run:
            return {"ok": True, "result": "DRY_RUN", "lines": []}
        chunks: list[bytes] = []
        try:
            with socket.create_connection(
                (self.config.console_host, self.config.klog_port), timeout=5
            ) as sock:
                sock.settimeout(self.config.klog_seconds)
                deadline = time.time() + self.config.klog_seconds
                total = 0
                while time.time() < deadline and total < self.config.klog_max_bytes:
                    try:
                        chunk = sock.recv(8192)
                    except TimeoutError:
                        break
                    if not chunk:
                        break
                    chunks.append(chunk)
                    total += len(chunk)
        except OSError as exc:
            return {"ok": False, "error_type": "klog_unreachable", "error": str(exc)}
        data = b"".join(chunks)
        digest = hashlib.sha256(data).hexdigest()
        self._emit(
            self._base_record(
                test=test,
                address_class="NONE",
                address=0,
                length=len(data),
                operation="get_klog",
                expected="bounded klog window",
                observed=digest,
                mutation_state=MutationState.NONE.value,
                restore_state=RestoreState.NOT_REQUIRED.value,
                adapter_status="ok",
                result="PASS",
                sha256=digest,
            )
        )
        return {
            "ok": True,
            "length": len(data),
            "sha256": digest,
            "lines": data.decode("utf-8", "replace").splitlines()[-40:],
        }

    def get_process_info(self, *, max_procs: int = 8, test: str = "") -> dict[str, Any]:
        """Bounded read-only allproc walk. Depth <= 2, canonical/aligned guards, cycle detection."""

        test = test or self._next_test("P")
        if self.kernel_base is None:
            return {"ok": False, "error_type": "no_kernel_base", "error": "kernel base unknown"}
        layout = self.profile.proc_layout
        head_rva = self.profile.heap_pointers.get("allproc")
        kernel_base = self.kernel_base
        if head_rva is None or kernel_base is None:
            return {"ok": False, "error_type": "no_allproc_offset", "error": "profile lacks allproc"}
        head = self.read_memory(
            kernel_base + head_rva, 8, test=f"{test}-head", operation="get_process_info"
        )
        if not head.get("ok"):
            return {"ok": False, "error_type": "allproc_unreadable", "error": head.get("error", "")}
        address = int.from_bytes(bytes.fromhex(head["data_hex"]), "little")
        seen: set[int] = set()
        processes: list[dict[str, Any]] = []
        depth = 0
        while address and len(processes) < max_procs and depth < self.policy.max_pointer_depth:
            if address in seen:
                processes.append({"note": "CYCLE_DETECTED", "address": f"0x{address:x}"})
                break
            seen.add(address)
            comm = self.read_memory(
                address + layout["p_comm"],
                16,
                test=f"{test}-comm{depth}",
                operation="get_process_info",
            )
            if not comm.get("ok"):
                processes.append({"note": "COMM_UNREADABLE", "address": f"0x{address:x}"})
                break
            name = bytes.fromhex(comm["data_hex"]).split(b"\x00")[0].decode("ascii", "replace")
            processes.append({"address": f"0x{address:x}", "p_comm": name})
            nxt = self.read_memory(
                address + layout["le_next"],
                8,
                test=f"{test}-next{depth}",
                operation="get_process_info",
            )
            if not nxt.get("ok"):
                break
            address = int.from_bytes(bytes.fromhex(nxt["data_hex"]), "little")
            depth += 1
        return {"ok": True, "processes": processes, "depth_used": depth}

    # ------------------------------------------------------------------ interface
    def execute(self, kind: str, args: dict[str, Any]) -> dict[str, Any]:
        """Target interface. ``write_memory`` requires a plan, never a bare store."""

        if kind == "ping":
            return self.ping()
        if kind == "get_target_info":
            return self.get_target_info()
        if kind == "get_kbase":
            return self.get_kbase()
        if kind == "read_memory":
            return self.read_memory(
                int(args["address"]),
                int(args["length"]),
                test=str(args.get("test", "")),
            )
        if kind == "readback":
            return self.readback(int(args["address"]), int(args["length"]))
        if kind == "snapshot_state":
            return self.snapshot_state()
        if kind == "write_memory":
            plan = args.get("plan")
            if not isinstance(plan, ExperimentPlan):
                return {
                    "ok": False,
                    "result": "BLOCK",
                    "error_type": "plan_required",
                    "error": "write_memory requires an ExperimentPlan with restore steps",
                }
            return self.write_memory(plan)
        if kind == "get_klog":
            return self.get_klog()
        if kind == "get_process_info":
            return self.get_process_info()
        return {
            "ok": False,
            "error_type": "unsupported_operation",
            "error": f"live adapter does not implement {kind}",
        }

    def close(self) -> None:
        try:
            self.channel.request("QUIT", timeout=3.0)
        except (ChannelError, OSError):
            pass
        self.channel.close()


def _image_layout(profile: KernelProfile, kernel_base: int):
    from .classification import KernelImageLayout

    return KernelImageLayout(
        base=kernel_base,
        span=profile.image_span,
        text_end=profile.text_end,
        data_end=profile.data_end,
    )
