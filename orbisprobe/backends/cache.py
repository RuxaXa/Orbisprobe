from __future__ import annotations

import hashlib
import json
import os
import tempfile
from dataclasses import asdict, dataclass
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
    backend_fingerprint: str = ""


class AnalysisCache:
    def __init__(self, root: str | Path) -> None:
        self.root = Path(root).expanduser().resolve()
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)

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
            if raw.get("cache_key") != self.key(request):
                return None
            return BackendResult.from_dict(raw["result"])
        except (OSError, ValueError, TypeError, KeyError, json.JSONDecodeError):
            return None

    def store(self, request: CacheRequest, result: BackendResult) -> Path:
        path = self._path(request)
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        payload = {
            "cache_key": self.key(request),
            "request": asdict(request),
            "result": result.to_dict(),
        }
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
