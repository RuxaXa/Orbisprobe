#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import stat
import zipfile
from pathlib import Path, PurePosixPath

VERSION = "0.1.1-hermes.2"
ARCHIVE_ROOT = f"orbisprobe-v{VERSION}"
FIXED_TIMESTAMP = (1980, 1, 1, 0, 0, 0)
TOP_LEVEL_FILES = {
    "CHANGELOG.md",
    "HARDENING-REPORT.md",
    "README.md",
    "SECURITY.md",
    "pyproject.toml",
}
SOURCE_SUFFIXES = {
    "orbisprobe": {".py"},
    "tests": {".py"},
    "examples": {".json"},
    "scripts": {".py"},
}
FORBIDDEN_PARTS = {
    ".git",
    ".pytest_cache",
    ".ruff_cache",
    ".venv",
    "__pycache__",
    "evidence",
    "orbisprobe.egg-info",
}
FORBIDDEN_MARKERS = (
    b"-----BEGIN " + b"PRIVATE KEY-----",
    b"-----BEGIN " + b"OPENSSH PRIVATE KEY-----",
    b"/home/hermes/" + b".hermes/secrets/",
)


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def collect_payload(root: Path) -> dict[str, bytes]:
    payload: dict[str, bytes] = {}
    for name in sorted(TOP_LEVEL_FILES):
        path = root / name
        if not path.is_file():
            raise FileNotFoundError(f"required release file is missing: {name}")
        payload[name] = path.read_bytes()

    for directory, suffixes in SOURCE_SUFFIXES.items():
        base = root / directory
        if not base.is_dir():
            raise FileNotFoundError(f"required release directory is missing: {directory}")
        for path in sorted(base.rglob("*")):
            if not path.is_file() or path.suffix not in suffixes:
                continue
            relative = path.relative_to(root)
            if path.is_symlink() or any(part in FORBIDDEN_PARTS for part in relative.parts):
                raise ValueError(f"forbidden release path: {relative.as_posix()}")
            payload[relative.as_posix()] = path.read_bytes()

    for relative, data in payload.items():
        if PurePosixPath(relative).is_absolute() or ".." in PurePosixPath(relative).parts:
            raise ValueError(f"unsafe release path: {relative}")
        for marker in FORBIDDEN_MARKERS:
            if marker in data:
                raise ValueError(f"forbidden secret marker in {relative}")

    checksum_lines = [
        f"{sha256(payload[path])}  {path}"
        for path in sorted(payload)
    ]
    payload["SHA256SUMS"] = ("\n".join(checksum_lines) + "\n").encode("utf-8")
    return payload


def write_archive(root: Path, output: Path) -> str:
    payload = collect_payload(root)
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = output.with_name(output.name + ".tmp")
    if temporary.exists():
        temporary.unlink()
    with zipfile.ZipFile(
        temporary,
        "w",
        compression=zipfile.ZIP_DEFLATED,
        compresslevel=9,
        strict_timestamps=True,
    ) as archive:
        for relative in sorted(payload):
            member = f"{ARCHIVE_ROOT}/{relative}"
            info = zipfile.ZipInfo(member, date_time=FIXED_TIMESTAMP)
            info.compress_type = zipfile.ZIP_DEFLATED
            info.create_system = 3
            mode = 0o755 if relative.startswith("scripts/") else 0o644
            info.external_attr = (stat.S_IFREG | mode) << 16
            info.flag_bits = 0
            archive.writestr(info, payload[relative], compress_type=zipfile.ZIP_DEFLATED, compresslevel=9)
    temporary.replace(output)
    return sha256(output.read_bytes())


def main() -> int:
    parser = argparse.ArgumentParser(description="Build deterministic OrbisProbe source archive")
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    digest = write_archive(args.root.resolve(), args.out.resolve())
    print(f"{digest}  {args.out.resolve()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
