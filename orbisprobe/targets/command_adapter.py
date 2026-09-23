from __future__ import annotations

import json
import subprocess
from typing import Any

from .base import Target


class CommandAdapter(Target):
    """Bridge to an existing Hermes/PS4 transport.

    The external adapter reads one JSON object on stdin and writes one JSON object
    on stdout. OrbisProbe does not embed console-specific transport or payload code.
    """

    def __init__(self, argv: list[str], timeout_seconds: float = 30.0):
        self.argv = argv
        self.timeout_seconds = timeout_seconds

    def execute(self, kind: str, args: dict[str, Any]) -> dict[str, Any]:
        payload = json.dumps({"kind": kind, "args": args}).encode()
        try:
            process = subprocess.run(
                self.argv,
                input=payload,
                capture_output=True,
                check=False,
                timeout=self.timeout_seconds,
            )
        except subprocess.TimeoutExpired:
            return {
                "ok": False,
                "error_type": "adapter_timeout",
                "error": "adapter timeout",
                "timeout_seconds": self.timeout_seconds,
            }
        except OSError as exc:
            return {
                "ok": False,
                "error_type": "adapter_spawn_failure",
                "error": str(exc),
            }
        if process.returncode != 0:
            return {
                "ok": False,
                "error_type": "adapter_exit_failure",
                "error": "adapter exited nonzero",
                "returncode": process.returncode,
                "stderr": process.stderr.decode(errors="replace")[:2048],
            }
        try:
            result = json.loads(process.stdout.decode())
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            return {
                "ok": False,
                "error_type": "malformed_adapter_response",
                "error": str(exc),
            }
        if not isinstance(result, dict):
            return {
                "ok": False,
                "error_type": "malformed_adapter_response",
                "error": "adapter response must be a JSON object",
            }
        return result
