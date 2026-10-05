from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .manifest import load_manifest, manifest_sha256, verify_manifest
from .model import closed_schema, require_hex_digest, require_text, require_tuple


@dataclass(frozen=True)
class RemediationRequest:
    """Input for a separate remediation pass: previous freeze, findings, allowed paths."""

    previous_package: str
    previous_package_sha256sums_sha256: str
    findings: tuple[str, ...]
    allowed_paths: tuple[str, ...]

    def __post_init__(self) -> None:
        require_text("RemediationRequest.previous_package", self.previous_package)
        require_hex_digest(
            "RemediationRequest.previous_package_sha256sums_sha256", self.previous_package_sha256sums_sha256
        )
        object.__setattr__(self, "findings", require_tuple("RemediationRequest.findings", self.findings))
        object.__setattr__(
            self, "allowed_paths", require_tuple("RemediationRequest.allowed_paths", self.allowed_paths)
        )
        if not self.findings:
            raise ValueError("a remediation pass requires at least one finding")
        if not self.allowed_paths:
            raise ValueError("a remediation pass requires an explicit allowed path set")

    def to_dict(self) -> dict[str, Any]:
        return {
            "previous_package": self.previous_package,
            "previous_package_sha256sums_sha256": self.previous_package_sha256sums_sha256,
            "findings": list(self.findings),
            "allowed_paths": list(self.allowed_paths),
        }

    @classmethod
    def from_dict(cls, value: object) -> RemediationRequest:
        data = closed_schema(
            "RemediationRequest",
            value,
            {"previous_package", "previous_package_sha256sums_sha256", "findings", "allowed_paths"},
        )
        return cls(
            previous_package=data["previous_package"],
            previous_package_sha256sums_sha256=data["previous_package_sha256sums_sha256"],
            findings=tuple(data["findings"]),
            allowed_paths=tuple(data["allowed_paths"]),
        )


def plan_remediation(
    *,
    request: RemediationRequest,
    current_package: str | Path,
) -> dict[str, Any]:
    """Audit a remediation against its previous freeze.

    The old package stays historical: nothing in it is rewritten, and any edit outside the
    explicitly allowed path set fails the audit instead of being silently accepted.
    """

    previous = Path(request.previous_package).resolve()
    current = Path(current_package).resolve()

    previous_hash = manifest_sha256(previous)
    if previous_hash != request.previous_package_sha256sums_sha256:
        raise ValueError(
            f"stale remediation request: previous freeze is {previous_hash}, request names "
            f"{request.previous_package_sha256sums_sha256}"
        )
    for label, root in (("previous", previous), ("current", current)):
        report = verify_manifest(root, strict=True)
        if not report.ok:
            raise ValueError(f"{label} package is not MANIFEST_OK: {report.status} {report.to_dict()}")

    current_hash = manifest_sha256(current)
    if current_hash == previous_hash:
        raise ValueError("remediation produced no new freeze (package hash unchanged)")

    previous_entries = load_manifest(previous)
    current_entries = load_manifest(current)
    changed = sorted(
        path
        for path, digest in current_entries.items()
        if path in previous_entries and previous_entries[path] != digest
    )
    added = sorted(set(current_entries) - set(previous_entries))
    removed = sorted(set(previous_entries) - set(current_entries))
    untouched = sorted(set(previous_entries) & set(current_entries) - set(changed))
    touched = tuple(sorted({*changed, *added, *removed}))
    allowed = set(request.allowed_paths)
    out_of_scope = sorted(path for path in touched if path not in allowed)

    return {
        "schema": "orbisprobe-evidence-pass-remediation-v1",
        "status": "REMEDIATION_READY" if not out_of_scope else "CHANGES_REQUIRED",
        "previous_package": str(previous),
        "previous_sha256sums_sha256": previous_hash,
        "current_package": str(current),
        "current_sha256sums_sha256": current_hash,
        "changed": changed,
        "added": added,
        "removed": removed,
        "out_of_scope": out_of_scope,
        "allowed_paths": list(request.allowed_paths),
        "unaffected_artifacts": len(untouched),
        "findings": list(request.findings),
        "previous_package_preserved": previous.is_dir() and manifest_sha256(previous) == previous_hash,
        "requires_review_of": current_hash,
        "auto_remediation": False,
    }
