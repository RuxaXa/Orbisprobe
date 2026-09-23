from __future__ import annotations

import hashlib
import json
import os
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

SENSITIVE_KEY_PARTS = (
    "api_key",
    "authorization",
    "cookie",
    "credential",
    "passwd",
    "password",
    "private_key",
    "secret",
    "token",
)
MAX_HEX_CHARS = 256
MAX_TEXT_CHARS = 2048


@dataclass
class Event:
    run_id: str
    experiment_id: str
    kind: str
    data: dict[str, Any]
    ts: str


def _sanitize(value: Any) -> Any:
    if isinstance(value, dict):
        cleaned: dict[str, Any] = {}
        for raw_key, raw_value in value.items():
            key = str(raw_key)
            lowered = key.lower()
            if any(part in lowered for part in SENSITIVE_KEY_PARTS):
                cleaned[key] = "[REDACTED]"
                continue
            if lowered.endswith("data_hex") and isinstance(raw_value, str) and len(raw_value) > MAX_HEX_CHARS:
                try:
                    binary = bytes.fromhex(raw_value)
                except ValueError:
                    binary = raw_value.encode("utf-8", errors="replace")
                cleaned[key] = raw_value[:64] + "...[TRUNCATED]"
                cleaned[f"{key}_bytes"] = len(binary)
                cleaned[f"{key}_sha256"] = hashlib.sha256(binary).hexdigest()
                continue
            cleaned[key] = _sanitize(raw_value)
        return cleaned
    if isinstance(value, list):
        return [_sanitize(item) for item in value]
    if isinstance(value, tuple):
        return [_sanitize(item) for item in value]
    if isinstance(value, str) and len(value) > MAX_TEXT_CHARS:
        encoded = value.encode("utf-8", errors="replace")
        return {
            "preview": value[:512] + "...[TRUNCATED]",
            "utf8_bytes": len(encoded),
            "sha256": hashlib.sha256(encoded).hexdigest(),
        }
    return value


class EvidenceLog:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def append(self, run_id: str, experiment_id: str, kind: str, data: dict[str, Any]):
        event = Event(
            run_id,
            experiment_id,
            kind,
            _sanitize(data),
            datetime.now(UTC).isoformat(),
        )
        with self.path.open("a", encoding="utf-8") as stream:
            stream.write(json.dumps(asdict(event), sort_keys=True, ensure_ascii=False) + "\n")
            stream.flush()
            os.fsync(stream.fileno())

    def read(self) -> list[dict[str, Any]]:
        if not self.path.exists():
            return []
        return [
            json.loads(line)
            for line in self.path.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
