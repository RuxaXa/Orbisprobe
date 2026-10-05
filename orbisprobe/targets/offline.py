from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

from .base import Target


class OfflineTarget(Target):
    def execute(self, kind: str, args: dict[str, Any]) -> dict[str, Any]:
        if kind == "read_file":
            p = Path(args["path"])
            offset = int(args.get("offset", 0))
            length = int(args.get("length", p.stat().st_size - offset))
            data = p.read_bytes()[offset:offset+length]
            return {"ok": True, "length": len(data), "sha256": hashlib.sha256(data).hexdigest(), "data_hex": data.hex()}
        if kind == "hash_file":
            data = Path(args["path"]).read_bytes()
            return {"ok": True, "sha256": hashlib.sha256(data).hexdigest(), "length": len(data)}
        raise ValueError(f"offline target does not support {kind}")
