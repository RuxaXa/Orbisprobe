from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .model import require_hex_digest, sha256_file

MANIFEST_NAME = "SHA256SUMS"
# Post-freeze annexes: produced after the freeze, deliberately outside the manifest.
ANNEX_FILES = ("verification-result.json",)
ANNEX_PREFIXES = ("review/",)


@dataclass(frozen=True)
class ManifestReport:
    status: str
    entries: int
    duplicates: tuple[str, ...]
    missing: tuple[str, ...]
    unexpected: tuple[str, ...]
    mismatched: tuple[str, ...]

    @property
    def ok(self) -> bool:
        return self.status == "MANIFEST_OK"

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "entries": self.entries,
            "duplicates": list(self.duplicates),
            "missing": list(self.missing),
            "unexpected": list(self.unexpected),
            "mismatched": list(self.mismatched),
        }


def is_annex(relative: str) -> bool:
    return relative in ANNEX_FILES or any(relative.startswith(prefix) for prefix in ANNEX_PREFIXES)


def artifact_paths(root: str | Path) -> tuple[str, ...]:
    """Every frozen artifact path (relative, sorted) excluding the manifest and annexes."""

    resolved = Path(root)
    found: list[str] = []
    for path in resolved.rglob("*"):
        if path.is_symlink():
            raise ValueError(f"frozen package must not contain symlinks: {path}")
        if not path.is_file():
            continue
        relative = str(path.relative_to(resolved))
        if relative == MANIFEST_NAME or is_annex(relative):
            continue
        found.append(relative)
    return tuple(sorted(found))


def build_manifest(root: str | Path) -> dict[str, str]:
    resolved = Path(root)
    return {relative: sha256_file(resolved / relative) for relative in artifact_paths(resolved)}


def render_manifest(entries: dict[str, str]) -> str:
    return "".join(f"{digest}  ./{relative}\n" for relative, digest in sorted(entries.items()))


def parse_manifest(text: str) -> dict[str, str]:
    entries: dict[str, str] = {}
    for line in text.splitlines():
        if not line.strip():
            continue
        if "  " not in line:
            raise ValueError(f"malformed manifest line: {line!r}")
        digest, relative = line.split("  ", 1)
        require_hex_digest("manifest digest", digest)
        relative = relative.removeprefix("./")
        if not relative or relative.startswith("/") or ".." in Path(relative).parts:
            raise ValueError(f"manifest path must be package-relative: {relative!r}")
        if relative in entries:
            entries[relative] = entries[relative]
        entries[relative] = digest
    return entries


def verify_manifest(root: str | Path, *, strict: bool = False) -> ManifestReport:
    """Verify manifest completeness and integrity; ``MANIFEST_OK`` only when complete."""

    resolved = Path(root)
    manifest_path = resolved / MANIFEST_NAME
    if not manifest_path.is_file():
        return ManifestReport("MANIFEST_INCOMPLETE", 0, (), (MANIFEST_NAME,), (), ())
    raw_lines = [line for line in manifest_path.read_text(encoding="utf-8").splitlines() if line.strip()]
    seen: set[str] = set()
    duplicates: list[str] = []
    entries: dict[str, str] = {}
    for line in raw_lines:
        if "  " not in line:
            raise ValueError(f"malformed manifest line: {line!r}")
        digest, relative = line.split("  ", 1)
        require_hex_digest("manifest digest", digest)
        relative = relative.removeprefix("./")
        if relative in seen:
            duplicates.append(relative)
        seen.add(relative)
        entries[relative] = digest

    missing: list[str] = []
    mismatched: list[str] = []
    for relative, digest in sorted(entries.items()):
        target = resolved / relative
        if not target.is_file():
            missing.append(relative)
            continue
        if sha256_file(target) != digest:
            mismatched.append(relative)

    present = set(artifact_paths(resolved))
    unexpected = sorted(present - set(entries))
    if not strict:
        unexpected = []

    status = "MANIFEST_OK" if not (duplicates or missing or mismatched or unexpected) else "MANIFEST_INCOMPLETE"
    return ManifestReport(
        status=status,
        entries=len(entries),
        duplicates=tuple(duplicates),
        missing=tuple(missing),
        unexpected=tuple(unexpected),
        mismatched=tuple(mismatched),
    )


def manifest_sha256(root: str | Path) -> str:
    manifest_path = Path(root) / MANIFEST_NAME
    if not manifest_path.is_file():
        raise ValueError(f"manifest is missing: {manifest_path}")
    return sha256_file(manifest_path)


def load_manifest(root: str | Path) -> dict[str, str]:
    return parse_manifest((Path(root) / MANIFEST_NAME).read_text(encoding="utf-8"))


def load_json(path: str | Path) -> Any:
    return json.loads(Path(path).read_text(encoding="utf-8"))
