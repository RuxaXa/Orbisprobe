"""LIVE0 evidence and identity tests (LIVE0 §2, §5)."""

from __future__ import annotations

from pathlib import Path

from orbisprobe.live.evidence import (
    MAX_PREVIEW_BYTES,
    PREVIEW_INLINE_LIMIT_BYTES,
    EvidenceRecord,
    EvidenceWriter,
    MutationState,
    RestoreState,
    data_binding,
)
from orbisprobe.live.identity import TargetIdentity


def test_small_payloads_are_inlined_and_large_ones_are_referenced(tmp_path: Path):
    writer = EvidenceWriter(tmp_path, "run")
    small = b"\x01" * 64
    _digest, preview_hex, artifact = data_binding(writer, "small", small)
    assert artifact is None
    assert preview_hex == small.hex()

    large = bytes(range(256)) * 4
    _digest, preview_hex, artifact = data_binding(writer, "large", large)
    assert artifact is not None
    assert len(preview_hex) == MAX_PREVIEW_BYTES * 2
    stored = Path(artifact)
    assert stored.is_file()
    assert stored.stat().st_size == len(large)
    assert PREVIEW_INLINE_LIMIT_BYTES < len(large)


def test_evidence_record_serialises_addresses_as_hex(tmp_path: Path):
    record = EvidenceRecord(
        test="R4",
        target_name="ps4b",
        session_id="s",
        firmware="13.52",
        kernel_base=0xFFFFFFFFD00D0000,
        address_class="KERNEL_TEXT",
        address=0xFFFFFFFFD00D0000,
        length=64,
        operation="read_memory",
        expected="a" * 64,
        observed="a" * 64,
        mutation_state=MutationState.NONE.value,
        restore_state=RestoreState.NOT_REQUIRED.value,
        adapter_status="ok",
        result="PASS",
    )
    payload = record.to_dict()
    assert payload["address"] == "0xffffffffd00d0000"
    assert payload["kernel_base"] == "0xffffffffd00d0000"
    writer = EvidenceWriter(tmp_path, "run2")
    writer.record(record)
    line = (tmp_path / "run2.jsonl").read_text().strip()
    assert '"result": "PASS"' in line


def test_session_id_changes_with_boot_observables():
    a = TargetIdentity.derive_session_id(
        firmware="13.52", kernel_base=0xFFFFFFFFD00D0000, witnesses={"allproc": "0x1"}
    )
    b = TargetIdentity.derive_session_id(
        firmware="13.52", kernel_base=0xFFFFFFFFD00D0000, witnesses={"allproc": "0x1"}
    )
    c = TargetIdentity.derive_session_id(
        firmware="13.52", kernel_base=0xFFFFFFFF90000000, witnesses={"allproc": "0x2"}
    )
    assert a == b and len(a) == 64
    assert a != c


def test_identity_staleness_detection():
    identity = TargetIdentity(
        target_name="ps4b",
        firmware="13.52",
        session_id="s",
        kernel_base=0xFFFFFFFFD00D0000,
        kernel_fingerprint="f",
        adapter_version="a",
        payload_version="p",
        endpoint="e",
        captured_utc="t",
    )
    assert identity.check_staleness(0xFFFFFFFFD00D0000) is None
    assert identity.check_staleness(0xFFFFFFFF90000000) is not None
    assert identity.same_boot_as(0xFFFFFFFFD00D0000, "s")
    assert not identity.same_boot_as(0xFFFFFFFFD00D0000, "other")
