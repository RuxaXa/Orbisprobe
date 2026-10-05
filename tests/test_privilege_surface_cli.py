import json
from pathlib import Path

from orbisprobe.cli import main


def secure_fixture(tmp_path: Path) -> Path:
    fixture = json.loads(
        (Path(__file__).parent / "fixtures" / "case003_host_descriptor.json").read_text(encoding="utf-8")
    )
    path = tmp_path / "secure.bin"
    path.write_bytes(bytes.fromhex(fixture["binary_hex"]))
    return path


def test_privilege_surface_secure_json_cli(tmp_path: Path, capsys):
    path = secure_fixture(tmp_path)
    code = main([
        "privilege-surface", "secure", str(path),
        "--base", "0x638000", "--json",
    ])
    assert code == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["mode"] == "secure"
    assert payload["binary"]["base"] == 0x638000
    assert payload["surfaces"][0]["surface_type"] == "SAMU_SECURE"
    assert payload["surfaces"][0]["classification"] == "CROSS-PROCESSOR-CANDIDATE"


def test_privilege_surface_all_and_human_output(tmp_path: Path, capsys):
    path = secure_fixture(tmp_path)
    assert main(["privilege-surface", "all", str(path), "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert [track["track"] for track in payload["tracks"]] == ["svm", "iommu", "secure", "memctl"]
    assert main(["privilege-surface", "secure", str(path)]) == 0
    human = capsys.readouterr().out
    assert "Privilege surfaces" in human
    assert "CROSS-PROCESSOR-CANDIDATE" in human


def test_privilege_surface_unsupported_architecture_is_nonzero(tmp_path: Path, capsys):
    path = secure_fixture(tmp_path)
    code = main([
        "privilege-surface", "all", str(path), "--architecture", "arm64", "--json",
    ])
    assert code != 0
    assert "unsupported architecture" in capsys.readouterr().err
