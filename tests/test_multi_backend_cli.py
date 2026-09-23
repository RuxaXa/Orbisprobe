import json
import os
from pathlib import Path

from orbisprobe.cli import main

ANGR_PYTHON = Path(
    os.environ.get(
        "ORBISPROBE_ANGR_PYTHON",
        Path(__file__).parents[1] / ".backend-envs" / "angr" / "bin" / "python",
    )
)


def fixture(tmp_path: Path) -> Path:
    path = tmp_path / "flow.bin"
    path.write_bytes(bytes.fromhex("55 48 89 e5 49 83 fc 01 77 05 4c 89 e0 90 c3 31 c0 c3"))
    return path


def test_backends_command_reports_versions(capsys):
    code = main(["backends", "--json"])
    assert code == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["native"]["status"] == "COMPLETED"
    assert payload["angr"]["backend"]["version"] == "9.2.184"
    assert payload["ghidra"]["backend"]["version"] == "12.1.3"
    assert payload["binaryninja"]["status"] == "BACKEND_UNAVAILABLE"


def test_analyze_dataflow_angr_json(tmp_path: Path, capsys, monkeypatch):
    binary = fixture(tmp_path)
    monkeypatch.setenv("ORBISPROBE_ANGR_PYTHON", str(ANGR_PYTHON))
    code = main(
        [
            "analyze-dataflow",
            str(binary),
            "--backend",
            "angr",
            "--base",
            "0x400000",
            "--function",
            "0x400000",
            "--function-end",
            "0x400012",
            "--source-register",
            "r12",
            "--consumer",
            "0x40000d",
            "--json",
            "--cache-dir",
            str(tmp_path / "cache"),
        ]
    )
    assert code == 0
    payload = json.loads(capsys.readouterr().out)
    result = payload["results"][0]
    assert result["backend"]["name"] == "angr"
    assert result["data"]["value_domain"] == [0, 1]


def test_prove_path_angr_is_bounded(tmp_path: Path, capsys, monkeypatch):
    binary = fixture(tmp_path)
    monkeypatch.setenv("ORBISPROBE_ANGR_PYTHON", str(ANGR_PYTHON))
    code = main(
        [
            "prove-path",
            str(binary),
            "--backend",
            "angr",
            "--base",
            "0x400000",
            "--function",
            "0x400000",
            "--function-end",
            "0x400012",
            "--from",
            "0x400000",
            "--to",
            "0x40000d",
            "--symbolic-register",
            "r12",
            "--json",
            "--cache-dir",
            str(tmp_path / "cache"),
        ]
    )
    assert code == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["results"][0]["data"]["reachable"] is True


def test_privilege_surface_backend_adds_backend_evidence(tmp_path: Path, capsys):
    binary = tmp_path / "svm.bin"
    binary.write_bytes(bytes.fromhex("55 48 89 e5 0f 01 d8 c3"))
    code = main(
        [
            "privilege-surface",
            "svm",
            str(binary),
            "--base",
            "0x1000",
            "--backend",
            "native",
            "--json",
            "--cache-dir",
            str(tmp_path / "cache"),
        ]
    )
    assert code == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["surfaces"]
    assert payload["backend_analysis"][0]["surface_id"] == payload["surfaces"][0]["surface_id"]
    assert payload["backend_analysis"][0]["results"][0]["backend"]["name"] == "native"
