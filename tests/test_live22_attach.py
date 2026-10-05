"""LIVE2.2.2 attach state machine regression tests A-G (§10). Offline, fully mocked."""

from __future__ import annotations

import json
import time
from pathlib import Path

from orbisprobe.live.attach import (
    READY,
    STALE_ATTACHMENT,
    START_NOT_OBSERVED,
    InstanceLedger,
    SingleGreetingOwner,
    classify,
    preflight,
    validate_greeting,
    wait_for_start,
)

GREETING = ("OK HELLO payload=live0-1 fw=1352 kbase=0xffffffffdfd50000 instance=0x123388e743 "
            "pid=0x2e nonce=123456789")


def _ssh(responses: dict[str, str], dynamic: dict | None = None):
    def run(command: str) -> str:
        if dynamic:
            for needle, func in dynamic.items():
                if needle in command:
                    return func()
        for needle, response in responses.items():
            if needle in command:
                return response
        return ""
    return run


def test_a_delivered_but_never_started_is_named_exactly():
    ssh = _ssh({"cat /tmp/console_bridge.log": "[21:22:46] BRIDGE-READY payload_port=9025 host_port=9026",
                "ss -ltn": "LISTEN 0 1 127.0.0.1:9026",
                "onsole_bridge": "4242 python3 /tmp/console_bridge.py 9025 9026 900",
                "ping -c 2": "alive"})
    pre = preflight(ssh, console_ip="192.168.1.141", console_port=9090, host_port=9026)
    assert pre.ok and pre.bridge_pid == "4242" and pre.bridge_listen_sockets
    start = wait_for_start(ssh, bridge_log="/tmp/console_bridge.log", delivered_epoch=time.time(),
                           timeout=0.2, poll=0.05)
    assert not start.observed
    state, detail = classify(preflight_ok=pre.ok, delivered=True, start=start, greeting_ok=False,
                             bound=False)
    assert state == f"PAYLOAD_DELIVERED / {START_NOT_OBSERVED}" and "never connected" in detail


def test_b_stale_greeting_is_rejected():
    ok, violations, _ = validate_greeting(GREETING, previous_instances={"0x123388e743"},
                                          delivered_epoch=time.time())
    assert not ok and any("stale greeting" in v for v in violations)


def test_c_fresh_greeting_is_accepted_and_ready():
    ok, violations, info = validate_greeting(GREETING, previous_instances=set(),
                                             delivered_epoch=time.time() - 3)
    assert ok and violations == []
    assert info["instance"] == "0x123388e743" and info["greeting"]["pid"] == "0x2e"
    state, _ = classify(preflight_ok=True, delivered=True,
                        start=type("S", (), {"observed": True})(), greeting_ok=True, bound=True)
    assert state == READY


def test_c_greeting_must_be_hello_and_complete():
    ok, violations, _ = validate_greeting("OK PONG x=1", previous_instances=set(), delivered_epoch=0)
    assert not ok and any("not HELLO" in v for v in violations)
    ok2, violations2, _ = validate_greeting("OK HELLO instance=0x1", previous_instances=set(),
                                            delivered_epoch=0)
    assert not ok2 and any("misses pid" in v for v in violations2)


def test_d_greeting_can_only_be_consumed_once():
    owner = SingleGreetingOwner()
    assert owner.consume() is True
    assert owner.consume() is False


def test_e_two_instances_only_the_fresh_one_is_accepted():
    ledger = InstanceLedger(Path("/tmp/does-not-exist-live22-ledger.json"))
    ledger.entries = [{"instance": "0xaaaa"}, {"instance": "0xbbbb"}]
    old, _, _ = validate_greeting(GREETING.replace("0x123388e743", "0xaaaa"),
                                  previous_instances=ledger.instances(), delivered_epoch=time.time())
    new, _, _ = validate_greeting(GREETING.replace("0x123388e743", "0xcccc"),
                                  previous_instances=ledger.instances(), delivered_epoch=time.time())
    assert not old and new


def test_f_stale_bridge_connection_blocks_the_run():
    now = time.strftime("%H:%M:%S")
    ssh = _ssh({"cat /tmp/console_bridge.log": "[21:22:46] BRIDGE-READY\n"
                                               f"[{now}] payload connected from 192.168.1.141:51000",
                "ss -ltn": "LISTEN 0 1 127.0.0.1:9026",
                "onsole_bridge": "4242 python3 /tmp/console_bridge.py",
                "ping -c 2": "alive"})
    pre = preflight(ssh, console_ip="192.168.1.141", console_port=9090, host_port=9026)
    assert not pre.ok and pre.classification == STALE_ATTACHMENT
    assert any("stale payload session" in b for b in pre.blockers)
    state, _ = classify(preflight_ok=pre.ok, delivered=False,
                        start=type("S", (), {"observed": False})(), greeting_ok=False, bound=False)
    assert state == STALE_ATTACHMENT


def test_missing_bridge_is_not_a_preflight_blocker():
    """Cold start: the diagnostic starts the bridge *after* the preflight (regression)."""

    ssh = _ssh({"cat /tmp/console_bridge.log": "[21:22:46] BRIDGE-READY payload_port=9025 host_port=9026",
                "ss -ltn": "",
                "onsole_bridge": "",
                "ping -c 2": "alive"})
    pre = preflight(ssh, console_ip="192.168.1.141", console_port=9090, host_port=9026)
    assert pre.ok and pre.blockers == [] and pre.bridge_pid == ""
    state, _ = classify(preflight_ok=pre.ok, delivered=True,
                        start=type("S", (), {"observed": True})(), greeting_ok=True, bound=True)
    assert state == READY
    cold, detail = classify(preflight_ok=pre.ok, delivered=False,
                            start=type("S", (), {"observed": False})(), greeting_ok=False, bound=False,
                            delivery_error="ConnectionRefusedError: refused")
    assert cold.startswith("LOADER_REACHABLE") and "refused the connection" in detail


def test_g_bridge_alive_without_traffic_is_not_a_stale_attachment():
    ssh = _ssh({"cat /tmp/console_bridge.log": "[21:22:46] BRIDGE-READY payload_port=9025 host_port=9026",
                "ss -ltn": "LISTEN 0 1 0.0.0.0:9025\nLISTEN 0 1 127.0.0.1:9026",
                "onsole_bridge": "4242 python3 /tmp/console_bridge.py",
                "ping -c 2": "alive"})
    pre = preflight(ssh, console_ip="192.168.1.141", console_port=9090, host_port=9026)
    assert pre.ok and pre.classification == "" and pre.log_lines == 1


def test_preflight_never_probes_the_loader_port():
    """Regression: a bare connect to the single-shot loader port can break it (runbook §1/§7)."""

    issued: list[str] = []

    def ssh(command: str) -> str:
        issued.append(command)
        if "cat /tmp/console_bridge.log" in command:
            return "[21:22:46] BRIDGE-READY payload_port=9025 host_port=9026"
        if "ss -ltn" in command:
            return "LISTEN 0 1 127.0.0.1:9026"
        if "onsole_bridge" in command:
            return "4242 python3 /tmp/console_bridge.py"
        if "ping -c 2" in command:
            return "alive"
        return ""

    pre = preflight(ssh, console_ip="192.168.1.141", console_port=9090, host_port=9026)
    assert pre.ok and pre.loader_state.startswith("UNKNOWN")
    assert pre.non_loader_context["icmp"] == "alive"
    for command in issued:
        assert "9090" not in command.replace("host_port=9025", ""), f"loader port was probed: {command}"
        assert "/dev/tcp/" not in command, f"raw TCP probe issued: {command}"


def test_loader_unreachable_is_reported_from_the_delivery_attempt():
    from orbisprobe.live.attach import LOADER_REACHABLE

    state, detail = classify(preflight_ok=True, delivered=False,
                             start=type("S", (), {"observed": False})(), greeting_ok=False, bound=False,
                             delivery_error="ConnectionRefusedError: refused")
    assert state == LOADER_REACHABLE and "refused the connection" in detail


def test_listen_socket_parser_uses_the_local_address_column():
    from orbisprobe.live.attach import parse_listen_sockets

    ss = ("State Recv-Q Send-Q Local Address:Port Peer Address:Port Process\n"
          "LISTEN 0 1 0.0.0.0:9025 0.0.0.0:*\n"
          "LISTEN 0 1 127.0.0.1:9026 0.0.0.0:*\n"
          "LISTEN 0 128 0.0.0.0:22 0.0.0.0:*")
    assert parse_listen_sockets(ss, 9026) == ["127.0.0.1:9026"]
    assert parse_listen_sockets(ss, 9025) == ["0.0.0.0:9025"]
    assert parse_listen_sockets(ss, 9099) == []


def test_start_witness_detects_a_new_payload_connection():
    counter = {"n": 0}

    def dynamic():
        counter["n"] += 1
        if counter["n"] < 2:
            return "[21:22:46] BRIDGE-READY payload_port=9025"
        now = time.strftime("%H:%M:%S")
        return (f"[21:22:46] BRIDGE-READY payload_port=9025\n"
                f"[{now}] payload connected from 192.168.1.141:51001")

    ssh = _ssh({}, dynamic={"cat /tmp/console_bridge.log": dynamic})
    witness = wait_for_start(ssh, bridge_log="/tmp/console_bridge.log", delivered_epoch=time.time(),
                             timeout=5, poll=0.05)
    assert witness.observed and "payload connected" in witness.evidence


def test_start_witness_ignores_pre_existing_lines_and_clock_skew():
    """Regression: a stale 'payload connected' line must not count, a new one must - regardless of clocks."""

    from orbisprobe.live.attach import capture_log_baseline

    old_line = "[22:10:26] payload connected from 192.168.1.141:56516"
    state = {"log": f"[22:10:23] BRIDGE-READY payload_port=9025\n{old_line}"}
    ssh = _ssh({}, dynamic={"cat /tmp/console_bridge.log": lambda: state["log"]})

    baseline = capture_log_baseline(ssh, "/tmp/console_bridge.log")
    assert baseline == {"[22:10:23] BRIDGE-READY payload_port=9025", old_line}
    # only the pre-existing line is in the log -> no witness, even though it exists
    assert not wait_for_start(ssh, bridge_log="/tmp/console_bridge.log", timeout=0.2, poll=0.05,
                              baseline=baseline).observed
    # a new connection line appears -> witness, with no timestamp comparison involved
    state["log"] += "\n[22:31:07] payload connected from 192.168.1.141:56888"
    witness = wait_for_start(ssh, bridge_log="/tmp/console_bridge.log", timeout=2, poll=0.05,
                             baseline=baseline)
    assert witness.observed and "56888" in witness.evidence
    assert witness.payload_age_s is None and "new payload connection" in witness.source


def test_instance_ledger_records_and_blocks_replay(tmp_path):
    path = tmp_path / "instances.json"
    ledger = InstanceLedger(path)
    assert ledger.instances() == set()
    ledger.record("0xdeadbeef", run_id="r1", pid="0x2e", firmware="1352")
    reloaded = InstanceLedger(path)
    assert reloaded.instances() == {"0xdeadbeef"}
    ok, violations, _ = validate_greeting(GREETING.replace("0x123388e743", "0xdeadbeef"),
                                          previous_instances=reloaded.instances(),
                                          delivered_epoch=time.time())
    assert not ok and any("already consumed" in v for v in violations)
    assert json.loads(path.read_text())[0]["run_id"] == "r1"
