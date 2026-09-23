"""Transport for the LIVE0 adapter.

Everything that touches the real console lives here, and it reuses the existing, already-proven
infrastructure instead of building a parallel stack:

* payload build  — the pinned libPS4 tree on the LAN worker (``crt0.s`` + ``linker.x`` +
  ``libPS4.a``), built twice and byte-compared
* payload delivery — one HTTP ``POST /payload`` to the GoldHEN Payloader on the console
* payload output/commands — the existing relay port on the worker, bridged bidirectionally by
  ``console_bridge.py`` and reached from here through an SSH local forward

The Hermes segment cannot route into the console's LAN and the console cannot route back, so the
worker is the single hop in both directions. No second kernel-RW stack is introduced.
"""

from __future__ import annotations

import hashlib
import http.client
import json
import shlex
import socket
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Self

from .channel import ConsoleChannel

PAYLOAD_DIR = Path(__file__).parent / "payload"
BRIDGE_SCRIPT = PAYLOAD_DIR / "console_bridge.py"
BRIDGE_CTL = PAYLOAD_DIR / "bridge_ctl.sh"
PAYLOAD_SOURCE = PAYLOAD_DIR / "ps4_live0_payload.c"


@dataclass
class WorkerConfig:
    ssh_target: str = "neo@192.168.1.148"
    worker_ip: str = "192.168.1.148"
    console_ip: str = "192.168.1.141"
    payload_port: int = 9090
    bridge_payload_port: int = 9025
    bridge_host_port: int = 9026
    local_port: int = 19026
    sdk_dir: str = "/home/neo/bls-oracle/sdk/libPS4"
    build_dir: str = "/home/neo/m6build/live0"
    ssh_options: tuple[str, ...] = (
        "-o",
        "BatchMode=yes",
        "-o",
        "ConnectTimeout=10",
    )


@dataclass
class PayloadBuild:
    name: str
    size: int
    sha256: str
    elf_sha256: str
    relocation_count: int
    warnings: int
    second_build_identical: bool
    local_path: str = ""

    def to_dict(self) -> dict[str, object]:
        return {
            "name": self.name,
            "size": self.size,
            "sha256": self.sha256,
            "elf_sha256": self.elf_sha256,
            "relocation_count": self.relocation_count,
            "warnings": self.warnings,
            "second_build_identical": self.second_build_identical,
        }


BUILD_TEMPLATE = r"""
set -u
SDK={sdk}
W={workdir}
NAME={name}
CF="-I$SDK/include -Os -std=c11 -fno-builtin -mcmodel=small -march=btver2 -m64 -fpie -fPIC -Wall"
build() {{
  out=$1
  mkdir -p "$out" || return 9
  cd "$out" || return 9
  cp "$W/$NAME.c" . || return 9
  gcc -c -o crt0.o $SDK/crt0.s $CF > build.log 2>&1 || return 9
  gcc -c -o $NAME.o $NAME.c $CF >> build.log 2>&1 || return 9
  gcc -T $SDK/linker.x -nostartfiles -nostdlib -o $NAME.elf crt0.o $NAME.o $SDK/libPS4.a -m64 >> build.log 2>&1 || return 9
  objcopy -O binary $NAME.elf $NAME.bin || return 9
  return 0
}}
build "$W/build1" || {{ echo "BUILD1-FAILED"; tail -20 "$W/build1/build.log"; exit 9; }}
build "$W/build2" || {{ echo "BUILD2-FAILED"; tail -20 "$W/build2/build.log"; exit 9; }}
H1=$(sha256sum "$W/build1/$NAME.bin" | cut -d' ' -f1)
H2=$(sha256sum "$W/build2/$NAME.bin" | cut -d' ' -f1)
E1=$(sha256sum "$W/build1/$NAME.elf" | cut -d' ' -f1)
S1=$(stat -c %s "$W/build1/$NAME.bin")
REL=$(readelf -rW "$W/build1/$NAME.elf" | grep -cE 'R_X86_64' || true)
WARN=$(grep -cE 'error|warning' "$W/build1/build.log" || true)
LINKER=$(readlink -f "$W/build1/$NAME.elf" >/dev/null && echo ok || echo fail)
echo "BUILD-RESULT name=$NAME size=$S1 bin_sha256=$H1 bin2_sha256=$H2 elf_sha256=$E1 relocations=$REL warnings=$WARN"
[ "$H1" = "$H2" ] && echo "DOUBLE-BUILD identical" || echo "DOUBLE-BUILD differs"
"""


class WorkerConsoleTransport:
    """SSH-driven bridge control plus the one-shot payload delivery."""

    def __init__(self, config: WorkerConfig | None = None) -> None:
        self.config = config or WorkerConfig()
        self._tunnel: subprocess.Popen | None = None
        self.bridge_log: list[str] = []

    # ------------------------------------------------------------------ ssh
    def ssh(self, command: str, timeout: float = 120.0) -> subprocess.CompletedProcess:
        return subprocess.run(
            ["ssh", *self.config.ssh_options, self.config.ssh_target, command],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )

    def push_file(self, local: Path, remote: str) -> subprocess.CompletedProcess:
        payload = Path(local).read_bytes()
        encoded = payload.hex()
        program = (
            "import sys,binascii,pathlib;"
            f"p=pathlib.Path({remote!r});p.parent.mkdir(parents=True,exist_ok=True);"
            "p.write_bytes(binascii.unhexlify(sys.stdin.read().strip()))"
        )
        command = f"python3 -c {shlex.quote(program)}"
        return subprocess.run(
            ["ssh", *self.config.ssh_options, self.config.ssh_target, command],
            input=encoded,
            capture_output=True,
            text=True,
            timeout=120,
            check=False,
        )

    # ------------------------------------------------------------------ bridge
    def start_bridge(self, lifetime: float = 1200.0) -> dict[str, object]:
        """Start the bidirectional bridge on the worker through a control script.

        Inline compound backgrounding commands do not survive ``ssh host "..."`` reliably, and a
        silent failure there is indistinguishable from "the payload never attached" — so the
        worker-side logic lives in ``bridge_ctl.sh`` and is invoked with plain arguments.
        """

        self.push_file(BRIDGE_SCRIPT, "/tmp/console_bridge.py")
        self.push_file(BRIDGE_CTL, "/tmp/bridge_ctl.sh")
        command = (
            "bash /tmp/bridge_ctl.sh start "
            f"{self.config.bridge_payload_port} {self.config.bridge_host_port} {int(lifetime)}"
        )
        result = self.ssh(command, timeout=90)
        output = result.stdout.strip()
        if "BRIDGE-STARTED" not in output:
            raise RuntimeError(
                f"console bridge did not come up: rc={result.returncode} out={output} "
                f"err={result.stderr.strip()}"
            )
        return {"started": True, "output": output}

    def stop_bridge(self) -> str:
        result = self.ssh("bash /tmp/bridge_ctl.sh stop", timeout=30)
        return result.stdout.strip()

    def bridge_status(self) -> str:
        result = self.ssh("bash /tmp/bridge_ctl.sh status", timeout=30)
        return result.stdout.strip()

    # ------------------------------------------------------------------ tunnel
    @staticmethod
    def _local_port_listening(port: int) -> bool:
        """True when something in this namespace listens on ``port`` (no TCP connection made).

        A readiness probe that opens a real connection would be accepted by the bridge as *the*
        host connection, consuming the payload's single greeting; readiness is therefore checked
        through the kernel's socket table instead.
        """

        needle = f":{port:04X}"
        try:
            with open("/proc/net/tcp", encoding="utf-8") as handle:
                for line in handle.readlines()[1:]:
                    fields = line.split()
                    if len(fields) < 4:
                        continue
                    if fields[1].endswith(needle) and fields[3] == "0A":
                        return True
        except OSError:
            return False
        return False

    def open_tunnel(self, timeout: float = 25.0) -> None:
        if self._tunnel is not None:
            return
        self._tunnel = subprocess.Popen(
            [
                "ssh",
                *self.config.ssh_options,
                "-N",
                "-L",
                f"127.0.0.1:{self.config.local_port}:127.0.0.1:{self.config.bridge_host_port}",
                self.config.ssh_target,
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        deadline = time.time() + timeout
        while time.time() < deadline:
            if self._local_port_listening(self.config.local_port):
                return
            time.sleep(0.5)
        raise TimeoutError(
            f"SSH local forward on port {self.config.local_port} did not come up in {timeout}s"
        )

    def open_channel(self, timeout: float = 60.0) -> ConsoleChannel:
        """Wait for the payload to attach, then return the framed channel.

        The first successful TCP connection is kept: it may already be the bridge's accepted host
        side, and discarding it would consume the payload's greeting and then look like a silent
        disconnect.
        """

        deadline = time.time() + timeout
        last_error = "no attempt"
        while time.time() < deadline:
            try:
                sock = socket.create_connection(("127.0.0.1", self.config.local_port), timeout=5)
            except OSError as exc:
                last_error = f"connect: {type(exc).__name__}: {exc}"
                time.sleep(0.5)
                continue
            sock.settimeout(30.0)
            channel = ConsoleChannel(sock)
            try:
                greeting = channel.recv_frame(timeout=min(30.0, max(5.0, deadline - time.time())))
            except Exception as exc:  # noqa: BLE001 - retry until the payload attaches
                last_error = f"greeting: {type(exc).__name__}: {exc}"
                channel.close()
                time.sleep(0.5)
                continue
            channel.greeting = greeting.decode("utf-8", "replace")  # type: ignore[attr-defined]
            return channel
        raise TimeoutError(f"payload did not attach within {timeout}s (last: {last_error})")

    # ------------------------------------------------------------------ build
    def build_payload(self, name: str = "ps4_live0_payload", timeout: float = 600.0) -> PayloadBuild:
        remote_c = f"{self.config.build_dir}/{name}.c"
        self.ssh(f"mkdir -p {shlex.quote(self.config.build_dir)}", timeout=30)
        push = self.push_file(PAYLOAD_SOURCE, remote_c)
        if push.returncode != 0:
            raise RuntimeError(f"payload source upload failed: {push.stderr}")
        command = BUILD_TEMPLATE.format(
            sdk=shlex.quote(self.config.sdk_dir),
            workdir=shlex.quote(self.config.build_dir),
            name=name,
        )
        result = self.ssh(command, timeout=timeout)
        fields: dict[str, str] = {}
        for line in result.stdout.splitlines():
            if line.startswith("BUILD-RESULT"):
                for token in line.split()[1:]:
                    if "=" in token:
                        key, value = token.split("=", 1)
                        fields[key] = value
        if "bin_sha256" not in fields:
            raise RuntimeError(
                f"payload build failed: {result.stdout[-2000:]} {result.stderr[-2000:]}"
            )
        return PayloadBuild(
            name=name,
            size=int(fields["size"]),
            sha256=fields["bin_sha256"],
            elf_sha256=fields["elf_sha256"],
            relocation_count=int(fields["relocations"]),
            warnings=int(fields["warnings"]),
            second_build_identical=fields["bin_sha256"] == fields["bin2_sha256"],
        )

    def fetch_payload(self, name: str = "ps4_live0_payload") -> bytes:
        result = self.ssh(
            f"base64 -w0 {shlex.quote(self.config.build_dir)}/build1/{name}.bin", timeout=120
        )
        if result.returncode != 0:
            raise RuntimeError(f"payload fetch failed: {result.stderr}")
        import base64

        return base64.b64decode(result.stdout.strip())

    # ------------------------------------------------------------------ delivery
    def send_payload(self, binary: bytes, *, timeout: float = 20.0) -> dict[str, object]:
        """Exactly one upload: connect == send, no probe connection beforehand."""

        digest = hashlib.sha256(binary).hexdigest()
        try:
            conn = http.client.HTTPConnection(
                self.config.console_ip, self.config.payload_port, timeout=timeout
            )
            conn.request(
                "POST",
                "/payload",
                body=binary,
                headers={"Content-Type": "application/octet-stream"},
            )
            response = conn.getresponse()
            body = response.read()
            headers = dict(response.getheaders())
            conn.close()
        except OSError as exc:
            return {
                "ok": False,
                "error_type": "send_failure",
                "error": f"{type(exc).__name__}: {exc}",
                "sha256": digest,
                "size": len(binary),
            }
        return {
            "ok": 200 <= response.status < 300,
            "status": response.status,
            "reason": response.reason,
            "body": body[:512].decode("utf-8", "replace"),
            "headers": {k: v for k, v in headers.items() if k.lower() == "x-powered-by"},
            "sha256": digest,
            "size": len(binary),
        }

    # ------------------------------------------------------------------ teardown
    def close(self) -> None:
        if self._tunnel is not None:
            self._tunnel.terminate()
            try:
                self._tunnel.wait(timeout=5)
            except subprocess.TimeoutExpired:  # pragma: no cover
                self._tunnel.kill()
            self._tunnel = None

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()


@dataclass
class OfflineExpectation:
    """Offline-derived expectation for one read, from the validated kernel dump."""

    label: str
    rva: int
    length: int
    sha256: str
    data: bytes = field(repr=False, default=b"")
    relocated_fields: tuple[tuple[int, int], ...] = ()

    def expected_live_bytes(
        self, live_kernel_base: int, dump_base: int, little_endian: bool = True
    ) -> bytes:
        """Dump bytes with every relocated pointer rebased onto this boot's kernel base.

        The kernel image is boot-stable except for pointer fields the loader relocates, so a raw
        byte comparison would fail on those and hide whether the transport is correct. Every byte
        outside the declared relocated fields must still match the dump exactly.
        """

        out = bytearray(self.data)
        delta = live_kernel_base - dump_base
        for offset, size in self.relocated_fields:
            order = "little" if little_endian else "big"
            value = int.from_bytes(out[offset : offset + size], order)
            out[offset : offset + size] = (value + delta).to_bytes(size, order)
        return bytes(out)

    @staticmethod
    def from_dump(
        dump_path: Path,
        dump_sha256: str,
        label: str,
        rva: int,
        length: int,
        relocated_fields: tuple[tuple[int, int], ...] = (),
    ):
        data = dump_path.read_bytes()
        digest = hashlib.sha256(data).hexdigest()
        if digest != dump_sha256:
            raise ValueError(f"kernel dump hash mismatch: {digest} != {dump_sha256}")
        chunk = data[rva : rva + length]
        return OfflineExpectation(
            label=label,
            rva=rva,
            length=length,
            sha256=hashlib.sha256(chunk).hexdigest(),
            data=chunk,
            relocated_fields=relocated_fields,
        )


def dump_pointer(dump_path: Path, rva: int) -> int:
    data = dump_path.read_bytes()
    return int.from_bytes(data[rva : rva + 8], "little")


def summarize_build(build: PayloadBuild) -> str:
    return json.dumps(build.to_dict(), sort_keys=True)
