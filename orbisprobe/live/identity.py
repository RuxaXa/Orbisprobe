"""Target identity for a live run.

No pointer, kernel base or session value may be carried over from a previous boot: every mutating
plan must be bound to an identity captured in the *same* boot (LIVE0 §2). This module defines the
captured identity and the staleness rules derived from it.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass(frozen=True)
class TargetIdentity:
    target_name: str
    firmware: str
    session_id: str
    kernel_base: int
    kernel_fingerprint: str
    adapter_version: str
    payload_version: str
    endpoint: str
    captured_utc: str
    consistency_witnesses: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["kernel_base"] = f"0x{self.kernel_base:016x}"
        return payload

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True)

    @staticmethod
    def derive_session_id(
        *,
        firmware: str,
        kernel_base: int,
        witnesses: dict[str, Any],
    ) -> str:
        """Per-boot session id derived from runtime-varying, boot-scoped observables.

        The witnesses are kernel pointers/values that change with the boot (KASLR base, heap
        allocations). Two different boots must not hash to the same session id.
        """

        material = json.dumps(
            {
                "firmware": firmware,
                "kernel_base": f"0x{kernel_base:016x}",
                "witnesses": witnesses,
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        return hashlib.sha256(material.encode("utf-8")).hexdigest()

    def same_boot_as(self, kernel_base: int, session_id: str) -> bool:
        return self.kernel_base == kernel_base and self.session_id == session_id

    def check_staleness(self, live_kernel_base: int) -> str | None:
        """Return a block reason when the identity belongs to another boot."""

        if live_kernel_base != self.kernel_base:
            return (
                "stale identity: kernel base changed "
                f"(bound 0x{self.kernel_base:016x} != live 0x{live_kernel_base:016x}); "
                "re-capture identity for this boot"
            )
        return None
