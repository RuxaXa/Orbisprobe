"""Console channel: framing, request/response, and failure classification.

The channel talks to the on-console LIVE0 payload through the existing LAN relay. It is transport
agnostic (any socket-like object), so the failure-injection tests can substitute a fake without a
console.

Failure taxonomy (LIVE0 §21) is explicit because the *phase* decides the mutation state:

``connect_failure``         never reached the payload — nothing was dispatched
``timeout_before_write``    request timed out before any mutation was on the wire
``timeout_after_write``     mutation was dispatched, response lost — state unknown, must restore
``malformed_response``      payload answered with garbage
``partial_response``        frame header/content truncated
``disconnect``              peer closed the connection
``protocol_error``          well-formed frame with an unexpected body
"""

from __future__ import annotations

import time
from typing import Any, Protocol

FRAME_HEADER = b"#"
HEADER_LEN = 9  # b"#" + 8 hex digits
MAX_FRAME_BYTES = 0x40000


class ChannelError(Exception):
    def __init__(self, error_type: str, message: str, *, dispatched: bool = False) -> None:
        super().__init__(message)
        self.error_type = error_type
        self.dispatched = dispatched

    def to_dict(self) -> dict[str, Any]:
        return {
            "ok": False,
            "error_type": self.error_type,
            "error": str(self),
            "dispatched": self.dispatched,
        }


class SocketLike(Protocol):
    def sendall(self, data: bytes, *args: Any) -> None: ...
    def recv(self, size: int) -> bytes: ...
    def settimeout(self, value: float) -> None: ...
    def close(self) -> None: ...


def encode_frame(payload: bytes) -> bytes:
    if len(payload) > MAX_FRAME_BYTES:
        raise ValueError("frame too large")
    return FRAME_HEADER + f"{len(payload):08x}".encode() + payload


def parse_response(payload: bytes) -> dict[str, Any]:
    """Parse ``OK <CMD> k=v ...`` / ``ERR <CMD> code=<n> msg=<text>`` into a dict."""

    try:
        text = payload.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ChannelError("malformed_response", f"non-UTF8 response: {exc}") from exc
    text = text.strip()
    if not text:
        raise ChannelError("malformed_response", "empty response")
    parts = text.split(" ")
    status = parts[0]
    if status not in {"OK", "ERR"}:
        raise ChannelError("protocol_error", f"unexpected status {status!r}")
    command = parts[1] if len(parts) > 1 else ""
    result: dict[str, Any] = {"ok": status == "OK", "command": command}
    for token in parts[2:]:
        if "=" not in token:
            continue
        key, value = token.split("=", 1)
        result[key] = value
    if not result["ok"]:
        result["error_type"] = "payload_error"
        result["error"] = result.get("msg", "payload reported an error")
        result["code"] = result.get("code", "")
    return result


class ConsoleChannel:
    """Framed request/response channel to one payload instance."""

    def __init__(self, sock: SocketLike, *, default_timeout: float = 20.0) -> None:
        self.sock = sock
        self.default_timeout = default_timeout
        self._buffer = b""
        self.closed = False
        #: Responses that arrived out of order (e.g. a late reply to a timed-out mutation).
        self.late_responses: list[dict[str, Any]] = []

    # ------------------------------------------------------------------ framing
    def _read_exact(self, size: int, timeout: float) -> bytes:
        while len(self._buffer) < size:
            try:
                self.sock.settimeout(timeout)
                chunk = self.sock.recv(65536)
            except TimeoutError as exc:
                # socket.timeout is an alias of TimeoutError on supported interpreters.
                raise ChannelError("timeout_before_write", f"timeout after {timeout}s") from exc
            except OSError as exc:
                raise ChannelError("disconnect", f"socket error: {exc}") from exc
            if not chunk:
                raise ChannelError("disconnect", "peer closed the connection")
            self._buffer += chunk
        out, self._buffer = self._buffer[:size], self._buffer[size:]
        return out

    def recv_frame(self, timeout: float | None = None) -> bytes:
        timeout = self.default_timeout if timeout is None else timeout
        header = self._read_exact(HEADER_LEN, timeout)
        if not header.startswith(FRAME_HEADER):
            raise ChannelError(
                "malformed_response", f"bad frame header {header[:1]!r}"
            )
        try:
            length = int(header[1:9], 16)
        except ValueError as exc:
            raise ChannelError("malformed_response", f"bad frame length {header[1:9]!r}") from exc
        if length > MAX_FRAME_BYTES:
            raise ChannelError("malformed_response", f"frame length {length} exceeds bound")
        if length == 0:
            return b""
        body = self._read_exact(length, timeout)
        if len(body) != length:
            raise ChannelError("partial_response", f"expected {length} bytes, got {len(body)}")
        return body

    def send_frame(self, payload: bytes) -> None:
        try:
            self.sock.sendall(encode_frame(payload))
        except OSError as exc:
            raise ChannelError("disconnect", f"send failed: {exc}") from exc

    # ------------------------------------------------------------------ requests
    def request(
        self,
        command: str,
        *,
        timeout: float | None = None,
        mutation: bool = False,
        expect: str | None = None,
        max_skew_frames: int = 4,
        **fields: Any,
    ) -> dict[str, Any]:
        """Send one command and read the matching response.

        ``mutation=True`` marks the request as state-changing: once the frame has been written, a
        timeout or disconnect is reported with ``dispatched=True`` so the caller can never assume
        "nothing changed" (LIVE0 §7).

        Answers to earlier, lost requests are kept in :attr:`late_responses` instead of being
        mistaken for this request's answer; without that, a recovery read after a timed-out write
        could consume the late write reply and mis-report the mutation state.
        """

        budget = self.default_timeout if timeout is None else timeout
        deadline = time.monotonic() + budget
        tokens = [command]
        for key, value in fields.items():
            if value is None:
                continue
            if isinstance(value, int):
                tokens.append(f"{key}=0x{value:x}")
            else:
                tokens.append(f"{key}={value}")
        body = " ".join(tokens).encode("ascii")
        self.send_frame(body)
        expected = expect or command
        skew = 0
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise ChannelError(
                    "timeout_after_write" if mutation else "timeout_before_write",
                    f"no response within {budget}s",
                    dispatched=mutation,
                )
            try:
                response = self.recv_frame(remaining)
            except ChannelError as exc:
                if mutation and exc.error_type.startswith("timeout"):
                    exc.error_type = "timeout_after_write"
                exc.dispatched = mutation
                raise
            parsed = parse_response(response)
            parsed["dispatched"] = mutation
            if parsed.get("command") == expected:
                return parsed
            self.late_responses.append(parsed)
            skew += 1
            if skew >= max_skew_frames:
                raise ChannelError(
                    "protocol_error",
                    f"too many out-of-order responses (last={parsed.get('command')!r})",
                    dispatched=mutation,
                )

    def close(self) -> None:
        if self.closed:
            return
        self.closed = True
        try:
            self.sock.close()
        except OSError:
            pass


class DryRunChannel:
    """Channel that performs no I/O. Every mutating request is refused locally."""

    def __init__(self, identity_info: dict[str, Any] | None = None) -> None:
        self.closed = False
        self.requests: list[dict[str, Any]] = []
        self.identity_info = identity_info or {}

    def request(self, command: str, *, timeout=None, mutation=False, **fields) -> dict[str, Any]:
        self.requests.append({"command": command, "fields": fields, "mutation": mutation})
        if mutation:
            raise ChannelError(
                "dry_run_refused", "dry-run mode refuses mutating operations", dispatched=False
            )
        if command == "INFO":
            return {"ok": True, "command": "INFO", **self.identity_info}
        if command == "PING":
            return {"ok": True, "command": "PING", "payload": "dry-run", "uptime_ms": "0"}
        return {"ok": True, "command": command, "dry_run": "1"}

    def close(self) -> None:
        self.closed = True
