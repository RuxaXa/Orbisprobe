"""Evidence records for live operations.

One row per operation, hash-bound, with a bounded preview only. Large payloads are never inlined:
they are written to an artifact file and referenced by SHA-256 (LIVE0 §5).
"""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import asdict, dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

MAX_PREVIEW_BYTES = 64
PREVIEW_INLINE_LIMIT_BYTES = 256


class MutationState(str, Enum):
    NONE = "NONE"
    MUTATION_ATTEMPTED = "MUTATION_ATTEMPTED"
    MUTATION_CONFIRMED = "MUTATION_CONFIRMED"
    MUTATION_FAILED = "MUTATION_FAILED"
    RESTORE_ATTEMPTED = "RESTORE_ATTEMPTED"
    RESTORED_CONFIRMED = "RESTORED_CONFIRMED"
    RESTORE_FAILED = "RESTORE_FAILED"
    STATE_INTEGRITY_UNKNOWN = "STATE_INTEGRITY_UNKNOWN"


class RestoreState(str, Enum):
    NOT_REQUIRED = "NOT_REQUIRED"
    PENDING = "PENDING"
    CONFIRMED = "RESTORED_CONFIRMED"
    FAILED = "RESTORE_FAILED"
    UNKNOWN = "STATE_INTEGRITY_UNKNOWN"


@dataclass
class EvidenceRecord:
    test: str
    target_name: str
    session_id: str
    firmware: str
    kernel_base: int
    address_class: str
    address: int
    length: int
    operation: str
    expected: str
    observed: str
    mutation_state: str
    restore_state: str
    adapter_status: str
    result: str
    sha256: str | None = None
    preview_hex: str | None = None
    artifact_path: str | None = None
    timestamp_utc: str = ""
    adapter_version: str = ""
    payload_version: str = ""
    endpoint: str = ""
    error_type: str | None = None
    error: str | None = None
    notes: str = ""
    extra: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["address"] = f"0x{self.address:016x}" if self.address else None
        payload["kernel_base"] = f"0x{self.kernel_base:016x}" if self.kernel_base else None
        return payload

    def to_jsonl(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True)


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def preview(data: bytes, limit: int = MAX_PREVIEW_BYTES) -> str:
    return data[:limit].hex()


class EvidenceWriter:
    """Append-only JSONL evidence plus hashed artifacts for large reads."""

    def __init__(self, directory: str | Path, run_id: str) -> None:
        self.dir = Path(directory)
        self.dir.mkdir(parents=True, exist_ok=True)
        self.artifacts = self.dir / "artifacts"
        self.artifacts.mkdir(exist_ok=True)
        self.run_id = run_id
        self.jsonl_path = self.dir / f"{run_id}.jsonl"
        self._records: list[EvidenceRecord] = []

    def record(self, record: EvidenceRecord) -> EvidenceRecord:
        self._records.append(record)
        with open(self.jsonl_path, "a", encoding="utf-8") as handle:
            handle.write(record.to_jsonl() + "\n")
        return record

    def store(self, name: str, data: bytes) -> tuple[str, str]:
        """Store raw bytes as an artifact; return (sha256, path)."""

        digest = sha256_hex(data)
        path = self.artifacts / f"{self.run_id}-{name}-{digest[:16]}.bin"
        if not path.exists():
            with open(path, "wb") as handle:
                handle.write(data)
                handle.flush()
                os.fsync(handle.fileno())
        return digest, str(path)

    @property
    def records(self) -> list[EvidenceRecord]:
        return list(self._records)


def data_binding(writer: EvidenceWriter, name: str, data: bytes) -> tuple[str, str, str | None]:
    """Return (sha256, preview_hex, artifact_path) applying the inline/preview bounds."""

    digest = sha256_hex(data)
    if not data:
        return digest, "", None
    if len(data) <= PREVIEW_INLINE_LIMIT_BYTES:
        return digest, data.hex(), None
    _digest, path = writer.store(name, data)
    return digest, preview(data), path
