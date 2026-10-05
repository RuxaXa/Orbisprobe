from __future__ import annotations

import hashlib
import os
import secrets
import stat
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class ProtectedSource:
    resolved_path: Path
    device: int
    inode: int
    sha256: str

    @property
    def identity(self) -> tuple[int, int]:
        return (self.device, self.inode)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def capture_protected_sources(paths: Iterable[str | Path]) -> tuple[ProtectedSource, ...]:
    protected: list[ProtectedSource] = []
    seen: set[Path] = set()
    for path_value in paths:
        path = Path(path_value).resolve(strict=True)
        if path in seen:
            continue
        info = path.stat()
        if not stat.S_ISREG(info.st_mode):
            raise ValueError(f"source evidence must be a regular file: {path}")
        protected.append(
            ProtectedSource(
                resolved_path=path,
                device=info.st_dev,
                inode=info.st_ino,
                sha256=_sha256(path),
            )
        )
        seen.add(path)
    return tuple(sorted(protected, key=lambda item: str(item.resolved_path)))


def verify_protected_sources(sources: Iterable[ProtectedSource]) -> None:
    for source in sources:
        try:
            info = source.resolved_path.stat()
        except OSError as exc:
            raise RuntimeError("source evidence changed during migration") from exc
        if (
            not stat.S_ISREG(info.st_mode)
            or (info.st_dev, info.st_ino) != source.identity
            or _sha256(source.resolved_path) != source.sha256
        ):
            raise RuntimeError("source evidence changed during migration")


def _assert_no_symlink_components(path: Path) -> None:
    absolute = path.absolute()
    current = Path(absolute.anchor)
    for part in absolute.parts[1:]:
        current /= part
        try:
            info = current.lstat()
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(info.st_mode):
            raise ValueError(f"output path contains symlink component: {current}")


def _overlaps_source_structure(output: Path, source: ProtectedSource) -> bool:
    source_path = source.resolved_path
    source_root = source_path.parent
    return (
        output == source_path
        or output == source_root
        or output.is_relative_to(source_path)
        or output.is_relative_to(source_root)
        or source_path.is_relative_to(output)
    )


def validate_output_root(
    output_dir: str | Path, sources: Iterable[ProtectedSource]
) -> Path:
    lexical = Path(output_dir).absolute()
    resolved = lexical.resolve(strict=False)
    for source in sources:
        if _overlaps_source_structure(resolved, source):
            raise ValueError(f"output directory overlaps source evidence: {resolved}")
    _assert_no_symlink_components(lexical)
    return resolved


def prepare_output_directory(
    output_dir: str | Path, sources: Iterable[ProtectedSource]
) -> Path:
    protected = tuple(sources)
    resolved = validate_output_root(output_dir, protected)
    resolved.mkdir(parents=True, exist_ok=True)
    _assert_no_symlink_components(resolved)
    if not resolved.is_dir():
        raise ValueError(f"output directory is not a directory: {resolved}")
    return validate_output_root(resolved, protected)


def _relative_target(output_root: Path, target: str | Path) -> Path:
    relative = Path(target)
    if relative.is_absolute() or not relative.parts or ".." in relative.parts:
        raise ValueError(f"output target must be relative to output directory: {target}")
    candidate = output_root.joinpath(relative)
    if not candidate.is_relative_to(output_root):
        raise ValueError(f"output target escapes output directory: {target}")
    return candidate


def _validate_existing_leaf(
    target: Path, sources: tuple[ProtectedSource, ...]
) -> None:
    try:
        info = target.lstat()
    except FileNotFoundError:
        return
    if stat.S_ISLNK(info.st_mode):
        raise ValueError(f"output leaf must not be a symlink: {target}")
    if not stat.S_ISREG(info.st_mode):
        raise ValueError(f"output leaf must be a regular file: {target}")
    identity = (info.st_dev, info.st_ino)
    if any(identity == source.identity for source in sources):
        raise ValueError(f"output leaf aliases source evidence: {target}")
    resolved = target.resolve(strict=True)
    if any(resolved == source.resolved_path for source in sources):
        raise ValueError(f"output leaf aliases source evidence: {target}")


def preflight_output_targets(
    output_root: str | Path,
    targets: Iterable[str | Path],
    sources: Iterable[ProtectedSource],
) -> tuple[Path, ...]:
    protected = tuple(sources)
    root = validate_output_root(output_root, protected)
    if not root.is_dir():
        raise ValueError(f"output directory is not a directory: {root}")
    checked: list[Path] = []
    seen: set[Path] = set()
    for target_value in targets:
        target = _relative_target(root, target_value)
        if target in seen:
            raise ValueError(f"duplicate output target: {target}")
        _assert_no_symlink_components(target.parent)
        if not target.parent.is_dir():
            raise ValueError(f"output parent is not a directory: {target.parent}")
        if target.parent.resolve(strict=True) != target.parent:
            raise ValueError(f"output parent aliases another directory: {target.parent}")
        _validate_existing_leaf(target, protected)
        checked.append(target)
        seen.add(target)
    return tuple(checked)


def _open_parent_directory(output_root: Path, target: Path) -> int:
    relative_parent = target.parent.relative_to(output_root)
    flags = os.O_RDONLY | os.O_DIRECTORY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(output_root, flags)
    try:
        for component in relative_parent.parts:
            next_descriptor = os.open(component, flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = next_descriptor
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _validate_leaf_at_fd(
    directory_fd: int,
    leaf_name: str,
    display_path: Path,
    sources: tuple[ProtectedSource, ...],
) -> None:
    try:
        info = os.stat(leaf_name, dir_fd=directory_fd, follow_symlinks=False)
    except FileNotFoundError:
        return
    if stat.S_ISLNK(info.st_mode):
        raise ValueError(f"output leaf must not be a symlink: {display_path}")
    if not stat.S_ISREG(info.st_mode):
        raise ValueError(f"output leaf must be a regular file: {display_path}")
    identity = (info.st_dev, info.st_ino)
    if any(identity == source.identity for source in sources):
        raise ValueError(f"output leaf aliases source evidence: {display_path}")


def safe_atomic_write_bytes(
    path: str | Path,
    content: bytes,
    *,
    output_root: str | Path,
    protected_sources: Iterable[ProtectedSource] = (),
) -> None:
    protected = tuple(protected_sources)
    root = validate_output_root(output_root, protected)
    target_path = Path(path)
    if not target_path.is_absolute():
        target_path = target_path.absolute()
    try:
        relative = target_path.relative_to(root)
    except ValueError as exc:
        raise ValueError(f"output target escapes output directory: {target_path}") from exc
    target = _relative_target(root, relative)
    preflight_output_targets(root, (relative,), protected)

    directory_fd = _open_parent_directory(root, target)
    temporary = f".{target.name}.tmp-{os.getpid()}-{secrets.token_hex(8)}"
    temp_fd: int | None = None
    temp_exists = False
    try:
        parent_info = os.fstat(directory_fd)
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        temp_fd = os.open(temporary, flags, 0o644, dir_fd=directory_fd)
        temp_exists = True
        view = memoryview(content)
        while view:
            written = os.write(temp_fd, view)
            if written <= 0:
                raise OSError("short write to temporary output file")
            view = view[written:]
        os.fsync(temp_fd)
        os.close(temp_fd)
        temp_fd = None

        _assert_no_symlink_components(target.parent)
        current_parent = target.parent.stat(follow_symlinks=False)
        if (current_parent.st_dev, current_parent.st_ino) != (
            parent_info.st_dev,
            parent_info.st_ino,
        ):
            raise ValueError(f"output parent changed during write: {target.parent}")
        _validate_leaf_at_fd(directory_fd, target.name, target, protected)
        os.replace(
            temporary,
            target.name,
            src_dir_fd=directory_fd,
            dst_dir_fd=directory_fd,
        )
        temp_exists = False
        os.fsync(directory_fd)
    finally:
        if temp_fd is not None:
            os.close(temp_fd)
        if temp_exists:
            try:
                os.unlink(temporary, dir_fd=directory_fd)
            except FileNotFoundError:
                pass
        os.close(directory_fd)


def safe_atomic_write_text(
    path: str | Path,
    content: str,
    *,
    output_root: str | Path,
    protected_sources: Iterable[ProtectedSource] = (),
) -> None:
    safe_atomic_write_bytes(
        path,
        content.encode("utf-8"),
        output_root=output_root,
        protected_sources=protected_sources,
    )
