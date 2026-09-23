from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import tempfile
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from .base import BackendResult


@dataclass(frozen=True)
class CacheRequest:
    binary_sha256: str
    backend: str
    backend_version: str
    orbisprobe_version: str
    base_address: int
    operation: str
    parameters: dict[str, Any]
    resource_limits: dict[str, int] = field(default_factory=dict)
    backend_fingerprint: str = ""


class AnalysisCache:
    def __init__(self, root: str | Path) -> None:
        self.root = Path(root).expanduser().resolve()
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
        self._integrity_key = self._load_or_create_integrity_key()

    def _load_or_create_integrity_key(self) -> bytes:
        path = self.root / ".integrity-key"
        try:
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError:
            pass
        else:
            try:
                key = secrets.token_bytes(32)
                os.write(fd, key)
                os.fsync(fd)
            finally:
                os.close(fd)
        key = path.read_bytes()
        if len(key) != 32:
            raise ValueError("cache integrity key must be exactly 32 bytes")
        return key

    @staticmethod
    def _canonical(value: Any) -> bytes:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")

    def _signature(self, payload: dict[str, Any]) -> str:
        return hmac.new(self._integrity_key, self._canonical(payload), hashlib.sha256).hexdigest()

    def key(self, request: CacheRequest) -> str:
        digest = request.binary_sha256.lower()
        if len(digest) != 64 or any(ch not in "0123456789abcdef" for ch in digest):
            raise ValueError("binary_sha256 must be 64 lowercase hexadecimal characters")
        if request.base_address < 0:
            raise ValueError("base_address must be non-negative")
        raw = json.dumps(asdict(request), sort_keys=True, separators=(",", ":"), allow_nan=False)
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()

    def _path(self, request: CacheRequest) -> Path:
        key = self.key(request)
        path = self.root / key[:2] / f"{key}.json"
        resolved_parent = path.parent.resolve()
        if self.root not in resolved_parent.parents and resolved_parent != self.root:
            raise ValueError("cache path escaped cache root")
        return path

    def load(self, request: CacheRequest) -> BackendResult | None:
        path = self._path(request)
        if not path.is_file():
            return None
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
            if not isinstance(raw, dict):
                return None
            signature = raw.pop("signature", None)
            if not isinstance(signature, str) or not hmac.compare_digest(
                signature, self._signature(raw)
            ):
                return None
            if raw.get("cache_key") != self.key(request):
                return None
            if raw.get("request") != asdict(request):
                return None
            result = BackendResult.from_dict(raw["result"])
            if (
                result.identity.name != request.backend
                or result.identity.version != request.backend_version
            ):
                return None
            return result
        except (OSError, ValueError, TypeError, KeyError, json.JSONDecodeError):
            return None

    def store(self, request: CacheRequest, result: BackendResult) -> Path:
        path = self._path(request)
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        payload: dict[str, Any] = {
            "cache_key": self.key(request),
            "request": asdict(request),
            "result": result.to_dict(),
        }
        payload["signature"] = self._signature(payload)
        data = json.dumps(payload, sort_keys=True, indent=2, allow_nan=False) + "\n"
        fd, temporary = tempfile.mkstemp(prefix=".cache-", suffix=".json", dir=path.parent)
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                handle.write(data)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, path)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)
        return path
