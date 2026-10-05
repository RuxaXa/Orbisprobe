"""LIVE2.2.2 — attach state machine, preflight and greeting/instance binding.

``send_payload`` returning HTTP 200 only proves that the loader *accepted* the binary. It says nothing
about the payload starting, greeting, or the relay binding. This module keeps those transitions
separate, each with its own timeout, and names exactly which one did not happen:

    LOADER_REACHABLE → PAYLOAD_DELIVERED → PAYLOAD_STARTED → PAYLOAD_GREETING_SEEN
                     → BRIDGE_CHANNEL_BOUND → READY

Failure classes: START_NOT_OBSERVED, GREETING_TIMEOUT, BRIDGE_BIND_TIMEOUT, STALE_ATTACHMENT.
The greeting is bound to a *fresh* payload instance id: a stale greeting can never admit a new run.

RULE — the loader port is never probed (learned the hard way, see the project runbook
``MORGEN-RUNBOOK-ONLINE-LADDER.md`` §1/§7: "kein Polling - Sonden ohne Daten koennen
'invalid payload format' ausloesen" and "9090 refused -> Blocker, melden. NICHT pollen"):

* the GoldHEN web API on 9090 is a single-shot payload endpoint. A bare TCP connect that sends no
  request can put it into an error state, and repeated probes keep it down / make it flap;
* reachability is therefore decided by the *delivery attempt itself* (HTTP 200 vs. connection error),
  never by a pre-probe;
* only non-loader services (ICMP, klog 3232, FTP 2121) may be observed for context.
"""

from __future__ import annotations

import json
import re
import time
from collections.abc import Callable
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

LOADER_REACHABLE = "LOADER_REACHABLE"
PAYLOAD_DELIVERED = "PAYLOAD_DELIVERED"
PAYLOAD_STARTED = "PAYLOAD_STARTED"
PAYLOAD_GREETING_SEEN = "PAYLOAD_GREETING_SEEN"
BRIDGE_CHANNEL_BOUND = "BRIDGE_CHANNEL_BOUND"
READY = "READY"

START_NOT_OBSERVED = "START_NOT_OBSERVED"
GREETING_TIMEOUT = "GREETING_TIMEOUT"
BRIDGE_BIND_TIMEOUT = "BRIDGE_BIND_TIMEOUT"
STALE_ATTACHMENT = "STALE_ATTACHMENT"

_TS_RE = re.compile(r"\[(\d{1,2}):(\d{2}):(\d{2})\]")


@dataclass(frozen=True)
class Timeouts:
    """§7: one timeout per transition instead of a single shared one."""

    loader_delivery: float = 20.0
    bridge_bind: float = 30.0
    payload_start: float = 45.0
    greeting: float = 30.0


@dataclass
class Preflight:
    loader_state: str = "UNKNOWN (not probed by design)"
    non_loader_context: dict[str, str] = field(default_factory=dict)
    bridge_pid: str = ""
    bridge_listen_sockets: list[str] = field(default_factory=list)
    stale_payload_connections: list[str] = field(default_factory=list)
    stale_host_connections: list[str] = field(default_factory=list)
    log_lines: int = 0
    ok: bool = False
    blockers: list[str] = field(default_factory=list)
    classification: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class StartWitness:
    observed: bool = False
    evidence: str = ""
    payload_age_s: float | None = None
    source: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def parse_listen_sockets(ss_output: str, host_port: int) -> list[str]:
    """Pull the *local address* column out of ``ss -ltn`` (state recv-q send-q local peer ...)."""

    found: list[str] = []
    for line in ss_output.splitlines():
        fields = line.split()
        if len(fields) < 4 or not fields[0].startswith("LISTEN"):
            continue
        local = fields[3]
        if local.endswith(f":{host_port}"):
            found.append(local)
    return found


def bridge_log_lines(ssh: Callable[[str], str], log_path: str) -> list[str]:
    raw = ssh(f"cat {log_path} 2>/dev/null")
    return [line for line in raw.splitlines() if line.strip()]


def _log_age_seconds(line: str, now: float | None = None) -> float | None:
    """Bridge log timestamps are wall-clock HH:MM:SS; compare against local wall clock."""

    match = _TS_RE.search(line)
    if not match:
        return None
    hour, minute, second = (int(part) for part in match.groups())
    stamp = time.localtime(now if now is not None else time.time())
    logged = hour * 3600 + minute * 60 + second
    current = stamp.tm_hour * 3600 + stamp.tm_min * 60 + stamp.tm_sec
    delta = current - logged
    if delta < -3600:      # midnight wrap
        delta += 86400
    return float(delta)


def preflight(ssh: Callable[[str], str], *, console_ip: str, console_port: int, host_port: int,
              bridge_log: str = "/tmp/console_bridge.log", max_stale_age_s: float = 300.0) -> Preflight:
    """§3/§9: read-only picture of loader, bridge process, listener sockets and stale sessions."""

    result = Preflight()
    # the loader port is deliberately NOT probed; ICMP is the only touch and it cannot disturb it
    result.non_loader_context["icmp"] = ssh(
        f"ping -c 2 -W 2 {console_ip} >/dev/null 2>&1 && echo alive || echo unreachable").strip()
    pgrep = ssh("pgrep -af '[c]onsole_bridge.py'").strip()
    result.bridge_pid = pgrep.split()[0] if pgrep else ""
    listeners = ssh("ss -ltn 2>/dev/null").strip()
    result.bridge_listen_sockets = parse_listen_sockets(listeners, host_port)
    lines = bridge_log_lines(ssh, bridge_log)
    result.log_lines = len(lines)
    now = time.time()
    for line in lines:
        if "payload connected from" in line:
            age = _log_age_seconds(line, now)
            if age is None or age <= max_stale_age_s:
                result.stale_payload_connections.append(line.strip())
        if "host connected from" in line:
            age = _log_age_seconds(line, now)
            if age is None or age <= max_stale_age_s:
                result.stale_host_connections.append(line.strip())
    if result.non_loader_context.get("icmp") != "alive":
        result.blockers.append("console does not answer ICMP")
    # NOTE: a missing bridge is NOT a blocker here -- the diagnostic starts a fresh bridge right after
    # the preflight; requiring a pre-existing one made every cold start a false "STALE_ATTACHMENT".
    # Only a *stale, still-bound payload session* blocks the run (it would race with a new delivery).
    if result.stale_payload_connections:
        result.blockers.append("stale payload session still bound to the bridge")
        result.classification = STALE_ATTACHMENT
    result.ok = not result.blockers
    return result


def capture_log_baseline(ssh: Callable[[str], str], bridge_log: str) -> set[str]:
    """Snapshot the log lines present before delivery: the only clock-free way to spot a new one."""

    return set(bridge_log_lines(ssh, bridge_log))


def wait_for_start(ssh: Callable[[str], str], *, bridge_log: str, delivered_epoch: float = 0.0,
                   timeout: float, poll: float = 2.0,
                   baseline: set[str] | None = None) -> StartWitness:
    """§5: wait for a *start* witness (bridge accepts the payload connection) -- never mutate.

    The witness is a log line that was **not present before the delivery** (``baseline``). Comparing the
    remote log's wall clock against the local clock is deliberately avoided: the worker's clock can be
    offset by minutes, which made a real payload connection look "too old" and hid it.
    """

    deadline = time.time() + timeout
    last = StartWitness()
    while time.time() < deadline:
        for line in bridge_log_lines(ssh, bridge_log):
            if "payload connected from" not in line:
                continue
            stripped = line.strip()
            is_new = (baseline is None) or (stripped not in baseline)
            if not is_new:
                continue
            last = StartWitness(observed=True, evidence=stripped, source="bridge log: new payload connection",
                                payload_age_s=None)
            return last
        time.sleep(poll)
    return last


def parse_greeting(greeting: str) -> dict[str, str]:
    tokens = greeting.strip().split()
    data: dict[str, str] = {"status": tokens[0] if tokens else "", "command": tokens[1] if len(tokens) > 1 else ""}
    for token in tokens[2:]:
        if "=" in token:
            key, value = token.split("=", 1)
            data[key] = value
    return data


def validate_greeting(greeting: str, *, previous_instances: set[str],
                      delivered_epoch: float) -> tuple[bool, list[str], dict[str, Any]]:
    """§4: only a greeting from the freshly delivered instance may unlock the run."""

    data = parse_greeting(greeting)
    violations: list[str] = []
    instance = data.get("instance", "")
    if data.get("command") != "HELLO":
        violations.append(f"greeting is not HELLO: {greeting.strip()[:60]!r}")
    if not instance:
        violations.append("greeting carries no instance id")
    elif instance in previous_instances:
        violations.append(f"stale greeting: instance {instance} was already consumed")
    for required in ("pid", "payload"):
        if required not in data:
            violations.append(f"greeting misses {required}")
    # Firmware: akzeptiere die alte nackte Form ("fw") UND die basis-explizite Form
    # ("fw_dec"/"fw_hex", seit Phase 12W'). Beides muss vorhanden und konsistent sein.
    if "fw" in data:
        try:
            data["fw_consistent"] = int(str(data["fw"])) in (1352, 0x1352)
        except ValueError:
            violations.append(f"greeting fw not numeric: {data['fw']!r}")
    elif "fw_dec" in data and "fw_hex" in data:
        try:
            if int(str(data["fw_dec"])) != int(str(data["fw_hex"]), 16):
                violations.append("greeting fw_dec/fw_hex disagree")
        except ValueError:
            violations.append("greeting fw_dec/fw_hex not numeric")
    else:
        violations.append("greeting misses firmware (fw or fw_dec/fw_hex)")
    age = None
    if delivered_epoch:
        age = time.time() - delivered_epoch
    return (not violations), violations, {"greeting": data, "instance": instance, "age_s": age}


def classify(*, preflight_ok: bool, delivered: bool, start: StartWitness,
             greeting_ok: bool, bound: bool, delivery_error: str = "") -> tuple[str, str]:
    """Reachability is inferred from the delivery attempt, never from a pre-probe (see module docstring)."""

    if not preflight_ok:
        return STALE_ATTACHMENT, "preflight blocked: stale or missing bridge state"
    if not delivered:
        hint = " (loader refused the connection)" if "refused" in delivery_error.lower() else ""
        return LOADER_REACHABLE, f"delivery failed: the loader port did not accept the payload{hint}"
    if not start.observed:
        return f"{PAYLOAD_DELIVERED} / {START_NOT_OBSERVED}", "payload never connected to the bridge"
    if not greeting_ok:
        return f"{PAYLOAD_STARTED} / {GREETING_TIMEOUT}", "payload started but no valid greeting arrived"
    if not bound:
        return f"{PAYLOAD_GREETING_SEEN} / {BRIDGE_BIND_TIMEOUT}", "channel did not bind"
    return READY, "attach complete"


class InstanceLedger:
    """Records consumed payload instances so a stale greeting cannot be replayed into a new run."""

    def __init__(self, path: Path) -> None:
        self.path = Path(path)
        self.entries: list[dict[str, Any]] = []
        if self.path.is_file():
            try:
                self.entries = json.loads(self.path.read_text())
            except json.JSONDecodeError:
                self.entries = []

    def instances(self) -> set[str]:
        return {str(entry.get("instance", "")) for entry in self.entries if entry.get("instance")}

    def record(self, instance: str, *, run_id: str, pid: str = "", firmware: str = "") -> None:
        self.entries.append({"instance": instance, "run_id": run_id, "pid": pid,
                             "firmware": firmware, "recorded_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ",
                                                                                 time.gmtime())})
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps(self.entries, indent=2, sort_keys=True) + "\n", encoding="utf-8")


class SingleGreetingOwner:
    """§6: exactly one reader may consume the greeting stream (a probe must never eat it)."""

    def __init__(self) -> None:
        self.consumed = False

    def consume(self) -> bool:
        if self.consumed:
            return False
        self.consumed = True
        return True
