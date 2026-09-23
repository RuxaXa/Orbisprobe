import hashlib
import zipfile
from pathlib import Path

from scripts.build_release import ARCHIVE_ROOT, write_archive


def test_release_archives_are_byte_identical_and_hygienic(tmp_path: Path):
    root = Path(__file__).resolve().parents[1]
    first = tmp_path / "first.zip"
    second = tmp_path / "second.zip"
    first_sha = write_archive(root, first)
    second_sha = write_archive(root, second)
    assert first.read_bytes() == second.read_bytes()
    assert first_sha == second_sha == hashlib.sha256(first.read_bytes()).hexdigest()

    with zipfile.ZipFile(first) as archive:
        infos = archive.infolist()
        names = [info.filename for info in infos]
        assert len(names) == len(set(names))
        assert archive.testzip() is None
        assert all(info.date_time == (1980, 1, 1, 0, 0, 0) for info in infos)
        assert all(name.startswith(f"{ARCHIVE_ROOT}/") for name in names)
        assert not any(
            forbidden in name
            for name in names
            for forbidden in (".venv", "__pycache__", ".pytest_cache", ".ruff_cache", "/evidence/")
        )

        manifest_name = f"{ARCHIVE_ROOT}/SHA256SUMS"
        manifest = archive.read(manifest_name).decode("utf-8").splitlines()
        for line in manifest:
            expected, relative = line.split("  ", 1)
            assert hashlib.sha256(archive.read(f"{ARCHIVE_ROOT}/{relative}")).hexdigest() == expected
