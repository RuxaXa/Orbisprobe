from pathlib import Path

from orbisprobe.analysis.binary import BinaryImage
from orbisprobe.surfaces.svm import scan_svm


def image(tmp_path: Path, name: str, hex_bytes: str) -> BinaryImage:
    path = tmp_path / name
    path.write_bytes(bytes.fromhex(hex_bytes))
    return BinaryImage.open(path, architecture="x86_64", base=0x1000)


def test_svm_instruction_alone_is_capability_only(tmp_path: Path):
    result = scan_svm(image(tmp_path, "cap.bin", "55 48 89 e5 0f 01 d8 c3"))
    assert result.classification == "SVM-CAPABILITY-ONLY"
    assert len(result.surfaces) == 1
    surface = result.surfaces[0]
    assert surface.surface_type.value == "SVM_HV"
    assert surface.status.value == "SUPPORTED"
    assert "runtime role" in surface.unknowns
    assert any(item.raw.get("mnemonic") == "vmrun" for item in surface.evidence)
    assert result.graph.to_dict()["edges"] == []


def test_svm_init_sequence_is_not_overclaimed_active(tmp_path: Path):
    # EFER.SVME RMW, VM_HSAVE_PA write, 4K control-size immediate, VMRUN.
    fixture = (
        "55 48 89 e5 "
        "b9 80 00 00 c0 0f 32 0d 00 10 00 00 0f 30 "
        "b9 17 01 01 c0 0f 30 "
        "b8 00 10 00 00 0f 01 d8 c3"
    )
    result = scan_svm(image(tmp_path, "init.bin", fixture))
    assert result.classification == "SVM-INITIALIZED"
    surface = result.surfaces[0]
    assert surface.confidence.value == "MEDIUM"
    assert surface.classification == "SVM-INITIALIZED"
    assert "active runtime role" in surface.unknowns
    kinds = {item.kind for item in surface.evidence}
    assert {"svm_instruction", "svm_msr", "control_structure_hint"} <= kinds


def test_svm_none_and_truncated_are_clean(tmp_path: Path):
    assert scan_svm(image(tmp_path, "none.bin", "90 c3")).classification == "SVM-NONE"
    assert scan_svm(image(tmp_path, "truncated.bin", "0f 01")).classification == "SVM-NONE"


def test_generic_efer_access_does_not_prove_svm_initialization(tmp_path: Path):
    fixture = "55 48 89 e5 b9 80 00 00 c0 0f 32 0f 30 0f 01 de c3"
    result = scan_svm(image(tmp_path, "efer-only.bin", fixture))
    assert result.classification == "SVM-CAPABILITY-ONLY"
    assert "EFER.SVME initialization sequence" in result.surfaces[0].unknowns


def test_svm_msr_attribution_stops_on_call_clobber_and_ecx_overwrite(tmp_path: Path):
    call_clobber = "b9 80 00 00 c0 e8 00 00 00 00 0f 30 0f 01 de c3"
    overwritten = "b9 80 00 00 c0 b9 10 00 00 00 0f 30 0f 01 de c3"
    for name, fixture in (("call.bin", call_clobber), ("overwrite.bin", overwritten)):
        result = scan_svm(image(tmp_path, name, fixture))
        assert result.classification == "SVM-CAPABILITY-ONLY"
        assert not any(item.kind == "svm_msr" for item in result.surfaces[0].evidence)


def test_svm_svme_requires_eax_and_local_initialization(tmp_path: Path):
    wrong_register = "b9 80 00 00 c0 0f 32 81 cb 00 10 00 00 0f 30 0f 01 d8 c3"
    assert scan_svm(image(tmp_path, "wrong-reg.bin", wrong_register)).classification == "SVM-CAPABILITY-ONLY"

    binary = tmp_path / "far.bin"
    binary.write_bytes(
        bytes.fromhex("55 48 89 e5 0f 01 d8 c3")
        + b"\x90" * 0x500
        + bytes.fromhex("55 48 89 e5 b9 17 01 01 c0 0f 30 c3")
    )
    result = scan_svm(BinaryImage.open(binary, architecture="x86_64", base=0x8000))
    assert result.classification == "SVM-CAPABILITY-ONLY"


def test_svm_svme_eax_lifetime_must_reach_wrmsr(tmp_path: Path):
    stale = (
        "55 48 89 e5 b9 80 00 00 c0 0f 32 0d 00 10 00 00 "
        "b8 00 00 00 00 0f 30 0f 01 d8 c3"
    )
    result = scan_svm(image(tmp_path, "stale-eax.bin", stale))
    assert result.classification == "SVM-CAPABILITY-ONLY"


def test_svm_nearby_different_functions_do_not_combine_initialization(tmp_path: Path):
    binary = tmp_path / "near-functions.bin"
    binary.write_bytes(
        bytes.fromhex("55 48 89 e5 0f 01 d8 c3")
        + b"\x90" * 0x80
        + bytes.fromhex("55 48 89 e5 b9 17 01 01 c0 0f 30 c3")
    )
    result = scan_svm(BinaryImage.open(binary, architecture="x86_64", base=0x9000))
    assert result.classification == "SVM-CAPABILITY-ONLY"
