"""Shared LIVE0 test harness: scripted channels, plan builders, offline expectations.

Used by both the pytest suite and the live smoke runner so the negative and failure scenarios are
literally the same code in both places.
"""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

from orbisprobe.live.channel import ChannelError, parse_response
from orbisprobe.live.classification import AddressClass, KernelImageLayout, region_of
from orbisprobe.live.evidence import EvidenceWriter
from orbisprobe.live.identity import TargetIdentity
from orbisprobe.live.plan import (
    ExperimentPlan,
    ReadOp,
    RestoreSteps,
    WriteOp,
    canary_for,
)
from orbisprobe.live.policy import LivePolicy
from orbisprobe.live.profile import DEFAULT_PROFILE
from orbisprobe.live.ps4_target import AdapterConfig, Ps4LiveTarget
from orbisprobe.live.transport import OfflineExpectation, dump_pointer

KERNEL_DUMP = Path(
    "/home/hermes/audits/playstation-ps4/fw1352-ps4b-20260920/kernel-dump/kernel.bin"
)
KERNEL_DUMP_SHA256 = "cf157ffdbae872a20bbb9a46c8518b53d96c1ed75d4e73878466a295d92eca35"
DUMP_BASE = 0xFFFFFFFFD00D0000

FAKE_KBASE = 0xFFFFFFFFD00D0000
FAKE_BUFFER = 0x0000000021A00000  # a user-range address owned by the payload
FAKE_BUFFER_LEN = 0x1000
FAKE_PID = 0x2E
FAKE_BUFFER_B = 0x0000000022A00000
FAKE_TEST_OFFSET = 0x100
FAKE_TEST_LENGTH = 32


def make_identity(kernel_base: int = FAKE_KBASE, session_id: str = "sess-a") -> TargetIdentity:
    return TargetIdentity(
        target_name="ps4b-cuh2116a",
        firmware="13.52",
        session_id=session_id,
        kernel_base=kernel_base,
        kernel_fingerprint="deadbeef",
        adapter_version="test",
        payload_version="live0-1",
        endpoint="192.168.1.141",
        captured_utc="2026-09-23T00:00:00Z",
        consistency_witnesses={"allproc": "0xffff82da44230000"},
    )


def fake_payload_info(**overrides: Any) -> dict[str, Any]:
    """The parsed INFO shape the adapter stores (see Ps4LiveTarget.get_target_info)."""

    info: dict[str, Any] = {
        "payload": "live0-1",
        "test_buffer": FAKE_BUFFER,
        "test_buffer_size": FAKE_BUFFER_LEN,
        "allocation_call": "mmap",
        "allocation_ret": FAKE_BUFFER,
        "allocation_size": FAKE_BUFFER_LEN,
        "allocation_generation": 1,
        "pid": FAKE_PID,
        "payload_instance": "0x1234abcd",
    }
    info.update(overrides)
    return info


def two_buffer_info() -> dict[str, Any]:
    """A parsed INFO dict that reports two payload-owned allocations (LIVE1 A/B)."""

    return fake_payload_info(
        buf_a=FAKE_BUFFER, buf_a_ret=FAKE_BUFFER, buf_a_size=FAKE_BUFFER_LEN, buf_a_gen=1, buf_b=FAKE_BUFFER_B, buf_b_ret=FAKE_BUFFER_B, buf_b_size=FAKE_BUFFER_LEN, buf_b_gen=2
    )


def make_policy(level: str = "LIVE0-U", kernel_base: int = FAKE_KBASE) -> LivePolicy:
    policy = LivePolicy(level=level)
    policy.image = KernelImageLayout(base=kernel_base)
    policy.owned_regions = (
        region_of("live0-test-buffer", FAKE_BUFFER, FAKE_BUFFER_LEN, AddressClass.USER),
    )
    return policy


def make_target(
    channel: Any,
    *,
    level: str = "LIVE0-U",
    identity: TargetIdentity | None = None,
    kernel_base: int = FAKE_KBASE,
    dry_run: bool = False,
    evidence: EvidenceWriter | None = None,
    state_integrity_unknown: bool = False,
) -> Ps4LiveTarget:
    target = Ps4LiveTarget(
        channel,
        policy=make_policy(level, kernel_base),
        evidence=evidence,
        dry_run=dry_run,
        identity=identity if identity is not None else make_identity(kernel_base),
        config=AdapterConfig(console_endpoint="fake"),
    )
    target.kernel_base = kernel_base
    target.test_buffer = FAKE_BUFFER
    target.test_buffer_size = FAKE_BUFFER_LEN
    # Exercise the real pipeline: INFO -> parser -> validated PayloadInfo -> ownership gate.
    target.injection_context = {"process_name": "ScePartyDaemon", "pid": FAKE_PID}
    info = target.get_target_info()
    if not info.get("ok"):
        raise AssertionError(f"harness INFO did not parse: {info}")
    if target.identity is not None:
        target.capture_allocation(
            process_name="ScePartyDaemon",
            injection_pid=FAKE_PID,
            test_offset=FAKE_TEST_OFFSET,
            test_length=FAKE_TEST_LENGTH,
        )
    if state_integrity_unknown:
        target.state_integrity_unknown = True
        target.state_integrity_reason = "simulated prior failure"
    return target


def write_plan(
    address: int = FAKE_BUFFER,
    length: int = 16,
    plan_id: str = "U-canary",
    level: str = "LIVE0-U",
    address_class: str = "USER",
    declared_sink: str = "USER_MEMORY",
    notes: str = "",
    complete_restore: bool = True,
    canary: bytes | None = None,
) -> ExperimentPlan:
    data = canary if canary is not None else canary_for(plan_id, length)
    return ExperimentPlan(
        plan_id=plan_id,
        level=level,
        reads=(ReadOp(address=address, length=length, address_class=address_class),),
        writes=(
            WriteOp(address=address, data=data, address_class=address_class, label="canary"),
        ),
        expected={"canary": data.hex()},
        restore_steps=(
            RestoreSteps(
                baseline_read=True,
                restore_write=True,
                restore_readback=True,
                verify_equality=True,
            )
            if complete_restore
            else RestoreSteps(baseline_read=True)
        ),
        declared_sink=declared_sink,
        notes=notes,
    )


def read_plan(address: int, length: int, plan_id: str = "R-read") -> ExperimentPlan:
    return ExperimentPlan(
        plan_id=plan_id,
        level="LIVE0-R",
        reads=(ReadOp(address=address, length=length, address_class="UNKNOWN"),),
    )


# --------------------------------------------------------------------- fakes
def ok_read(hexdata: str) -> bytes:
    return f"OK READ kaddr=0x0 len=0x{len(hexdata) // 2:x} rc=0 hex={hexdata}".encode()


class ScriptedChannel:
    """Replies from a script; records every request. Optional fault injection per command."""

    def __init__(
        self,
        *,
        reads: dict[str, bytes] | None = None,
        default_read_hex: str = "5a" * 0x1000,
        fail_on: dict[str, Any] | None = None,
        buffers: bool = False,
    ) -> None:
        self.buffers = buffers
        self.reads = reads or {}
        self.default_read_hex = default_read_hex
        self.fail_on = fail_on or {}
        self.requests: list[dict[str, Any]] = []
        self.late_responses: list[dict[str, Any]] = []
        self.closed = False
        self._state: dict[str, bytearray] = {}

    def request(self, command: str, *, timeout=None, mutation=False, expect=None, **fields):
        self.requests.append({"command": command, "fields": fields, "mutation": mutation})
        fault = self.fail_on.get(command)
        if fault is None and command in {"READ", "VERIFY", "KREAD_USER"}:
            fault = self.fail_on.get("READ")  # user-buffer reads go through VERIFY
        if fault == "timeout_before_write" and not mutation:
            raise ChannelError("timeout_before_write", "simulated timeout before dispatch")
        if fault == "timeout_after_write" and mutation:
            self.closed = True
            raise ChannelError(
                "timeout_after_write", "simulated timeout after dispatch", dispatched=True
            )
        if fault == "disconnect_before_restore" and mutation:
            raise ChannelError("disconnect", "simulated disconnect", dispatched=True)
        if fault == "malformed_response":
            raise ChannelError("malformed_response", "simulated garbage")
        if fault == "partial_response":
            raise ChannelError("partial_response", "simulated truncation")
        extra: dict[str, Any] = {}
        if self.buffers:
            extra = {
                "buf_a": f"0x{FAKE_BUFFER:016x}",
                "buf_a_ret": f"0x{FAKE_BUFFER:016x}",
                "buf_a_size": f"0x{FAKE_BUFFER_LEN:x}",
                "buf_a_gen": "1",
                "buf_b": f"0x{FAKE_BUFFER_B:016x}",
                "buf_b_ret": f"0x{FAKE_BUFFER_B:016x}",
                "buf_b_size": f"0x{FAKE_BUFFER_LEN:x}",
                "buf_b_gen": "2",
            }
        if command == "PING":
            return {"ok": True, "command": "PING", "payload": "live0-1", "uptime_ms": "10"}
        if command == "INFO":
            return {
                "ok": True,
                "command": "INFO",
                "fw": "1352",
                "payload": "live0-1",
                "kbase": f"0x{FAKE_KBASE:016x}",
                "sp": "0x7ffffffff000",
                "text": "0x0000000021b00000",
                "data": "0x0000000021b01000",
                "stack": "0x7ffffffee000",
                "heap": "0x0000000021c00000",
                "buf": f"0x{FAKE_BUFFER:016x}",
                "buflen": f"0x{FAKE_BUFFER_LEN:x}",
                "alloc": "mmap",
                "alloc_ret": f"0x{FAKE_BUFFER:016x}",
                "alloc_size": f"0x{FAKE_BUFFER_LEN:x}",
                "alloc_seq": "1",
                "pid": f"0x{FAKE_PID:x}",
                "instance": "0x1234abcd",
                **extra,
            }
        if command in {"READ", "KREAD_USER"}:
            address = int(fields["kaddr"])
            length = int(fields["len"])
            key = f"{address:#x}"
            if fault == "read_fault":
                return {"ok": True, "command": command, "kaddr": key, "len": "0x0", "rc": "-1"}
            if fault == "restore_readback_mismatch":
                # the baseline read succeeds, every later read does not match it
                self._read_count = getattr(self, "_read_count", 0) + 1
                value = "5a" if self._read_count == 1 else "ee"
                return {
                    "ok": True,
                    "command": command,
                    "rc": "0",
                    "hex": value * length,
                }
            if fault == "readback_mismatch" and command == "READ":
                base = self._state.get("buffer", bytearray(b"\x5a" * FAKE_BUFFER_LEN))
                return {
                    "ok": True,
                    "command": command,
                    "rc": "0",
                    "hex": bytes(base[address - FAKE_BUFFER : address - FAKE_BUFFER + length]).hex(),
                }
            if key in self.reads:
                return {
                    "ok": True,
                    "command": command,
                    "rc": "0",
                    "hex": self.reads[key].hex(),
                }
            if FAKE_BUFFER_B <= address and address + length <= FAKE_BUFFER_B + FAKE_BUFFER_LEN:
                base_b = self._state.setdefault("buffer_b", bytearray(b"\xa5" * FAKE_BUFFER_LEN))
                if command == "WRITE":
                    data = bytes.fromhex(fields["hex"])
                    base_b[address - FAKE_BUFFER_B : address - FAKE_BUFFER_B + len(data)] = data
                    return {"ok": True, "command": "WRITE", "rc": "0"}
                return {
                    "ok": True,
                    "command": command,
                    "rc": "0",
                    "hex": bytes(
                        base_b[address - FAKE_BUFFER_B : address - FAKE_BUFFER_B + length]
                    ).hex(),
                }
            if FAKE_BUFFER <= address and address + length <= FAKE_BUFFER + FAKE_BUFFER_LEN:
                base = self._state.setdefault("buffer", bytearray(b"\x5a" * FAKE_BUFFER_LEN))
                return {
                    "ok": True,
                    "command": command,
                    "rc": "0",
                    "hex": bytes(
                        base[address - FAKE_BUFFER : address - FAKE_BUFFER + length]
                    ).hex(),
                }
            return {"ok": True, "command": command, "rc": "0", "hex": self.default_read_hex[: 2 * length]}
        if command == "VERIFY":
            address = int(fields["kaddr"])
            length = int(fields["len"])
            if fault == "read_fault":
                return {"ok": True, "command": command, "kaddr": f"{address:#x}", "len": "0x0", "rc": "-1"}
            if fault == "restore_readback_mismatch":
                self._read_count = getattr(self, "_read_count", 0) + 1
                value = "5a" if self._read_count == 1 else "ee"
                return {"ok": True, "command": command, "rc": "0", "hex": value * length}
            base = self._state.get("buffer", bytearray(b"\x5a" * FAKE_BUFFER_LEN))
            return {
                "ok": True,
                "command": command,
                "rc": "0",
                "hex": bytes(base[address - FAKE_BUFFER : address - FAKE_BUFFER + length]).hex(),
            }
        if command == "WRITE":
            address = int(fields["kaddr"])
            data = bytes.fromhex(fields["hex"])
            base = self._state.setdefault("buffer", bytearray(b"\x5a" * FAKE_BUFFER_LEN))
            if fault == "restore_mismatch":
                # accept the write but never actually change the bytes -> readback mismatch
                return {"ok": True, "command": "WRITE", "rc": "0"}
            base[address - FAKE_BUFFER : address - FAKE_BUFFER + len(data)] = data
            return {"ok": True, "command": "WRITE", "rc": "0"}
        if command == "QUIT":
            return {"ok": True, "command": "QUIT", "reason": "quit"}
        return {"ok": False, "command": command, "error_type": "payload_error", "error": "unsupported"}

    def close(self) -> None:
        self.closed = True


class RecordingOnlyChannel:
    """Channel that fails the test if anything at all is mutated. Used by the §20 negative tests."""

    def __init__(self) -> None:
        self.requests: list[dict[str, Any]] = []

    def request(self, command: str, *, timeout=None, mutation=False, expect=None, **fields):
        self.requests.append({"command": command, "fields": fields, "mutation": mutation})
        if mutation:
            raise AssertionError(
                f"a real mutation was dispatched during a policy negative test: {command} {fields}"
            )
        if command == "INFO":
            return {
                "ok": True,
                "command": "INFO",
                "fw": "1352",
                "payload": "live0-1",
                "kbase": f"0x{FAKE_KBASE:016x}",
                "sp": "0x7ffffffff000",
                "text": "0x0000000021b00000",
                "data": "0x0000000021b01000",
                "stack": "0x7ffffffee000",
                "heap": "0x0000000021c00000",
                "buf": f"0x{FAKE_BUFFER:016x}",
                "buflen": f"0x{FAKE_BUFFER_LEN:x}",
                "alloc": "mmap",
                "alloc_ret": f"0x{FAKE_BUFFER:016x}",
                "alloc_size": f"0x{FAKE_BUFFER_LEN:x}",
                "alloc_seq": "1",
                "pid": f"0x{FAKE_PID:x}",
                "instance": "0x1234abcd",
            }
        return {"ok": True, "command": command, "rc": "0", "hex": "5a" * 32}

    def close(self) -> None:
        pass


# ------------------------------------------------------------- offline facts
def dump_available() -> bool:
    return KERNEL_DUMP.is_file()


def expectations() -> dict[str, OfflineExpectation]:
    profile = DEFAULT_PROFILE
    out: dict[str, OfflineExpectation] = {}
    for name, rva in profile.content_rvas.items():
        length = 64 if name == "elf_header" else 256
        out[name] = OfflineExpectation.from_dump(
            KERNEL_DUMP,
            KERNEL_DUMP_SHA256,
            name,
            rva,
            length,
            relocated_fields=tuple(profile.relocated_fields.get(name, ())),
        )
    return out


def expected_base_relative() -> dict[str, int]:
    """Expected live pointer values, expressed relative to the live kernel base."""

    return {
        "prison0": dump_pointer(KERNEL_DUMP, 0x0111FA18) - DUMP_BASE,
        "m_temp": dump_pointer(KERNEL_DUMP, 0x01520D00) - DUMP_BASE,
    }


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def parse_ok(response: bytes) -> dict[str, Any]:
    return parse_response(response)



