"""LIVE1 A/B experiment records, noise masking and classification (§10–§13, §21–§23).

One variable changes between A and B. Observables are compared *after* volatile fields have been
identified from the A1/A2 negative control and masked explicitly — never by eyeballing.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from typing import Any


class ABClass(str):
    A = "AB-A"  # deterministic input sensitivity, attribution to the consumer clear
    B = "AB-B"  # input-sensitive behavior, attribution unclear
    C = "AB-C"  # no observable sensitivity for this field
    D = "AB-D"  # one input is rejected -> validation differential candidate
    E = "AB-E"  # fault / unexpected state -> STOP, no retry


@dataclass
class ExperimentRecord:
    experiment_id: str
    candidate_id: str
    target_identity: dict[str, Any]
    input_variant: str
    allocation: dict[str, Any]
    controlled_field: str
    before_hash: str
    write_hash: str
    readback_hash: str
    observable_hashes: dict[str, str]
    return_status: dict[str, Any]
    restore_hash: str
    restore_state: str
    classification: str = ""
    error: str | None = None
    extra: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True)


@dataclass
class ABPairRecord:
    pair_id: str
    experiment_a: str
    experiment_b: str
    changed_variable: str
    observed_delta: dict[str, Any]
    reproducible: bool | None
    classification: str
    reason: str = ""
    noise_masked: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def byte_differences(first: bytes, second: bytes) -> dict[str, Any]:
    """Per-offset difference summary for two equal-length buffers."""

    if len(first) != len(second):
        return {"length_mismatch": [len(first), len(second)]}
    offsets = [i for i, (a, b) in enumerate(zip(first, second)) if a != b]
    return {
        "length": len(first),
        "count": len(offsets),
        "offsets": offsets,
        "first": offsets[0] if offsets else None,
        "last": offsets[-1] if offsets else None,
        "contiguous": bool(offsets) and offsets == list(range(offsets[0], offsets[-1] + 1)),
    }


def noise_fields(control_a: bytes, control_b: bytes) -> list[int]:
    """Offsets that differ between two *identical* configurations (A1/A2 negative control).

    These are volatile fields; they are recorded and masked rather than dismissed.
    """

    return byte_differences(control_a, control_b).get("offsets", [])


def mask_noise(data: bytes, offsets: list[int]) -> bytes:
    out = bytearray(data)
    for offset in offsets:
        if 0 <= offset < len(out):
            out[offset] = 0
    return bytes(out)


def classify_pair(
    *,
    a: ExperimentRecord,
    b: ExperimentRecord,
    noise_offsets: list[int],
    expected_region: tuple[int, int] | None,
    reproducible: bool | None = None,
    repeat_confirmed: bool | None = None,
) -> ABPairRecord:
    """Classify an A/B pair strictly from the recorded observables."""

    def masked(record: ExperimentRecord) -> dict[str, Any]:
        return {
            "observables": {
                key: value for key, value in sorted(record.observable_hashes.items())
            },
            "return_status": {k: v for k, v in sorted(record.return_status.items()) if k != "timing"},
        }

    delta: dict[str, Any] = {}
    fault = []
    for record in (a, b):
        if record.error or record.restore_state not in {"RESTORED_CONFIRMED", "NOT_REQUIRED"}:
            fault.append(
                f"{record.experiment_id}: error={record.error} restore_state={record.restore_state}"
            )
    if fault:
        return ABPairRecord(
            pair_id=a.extra.get("pair_id", ""),
            experiment_a=a.experiment_id,
            experiment_b=b.experiment_id,
            changed_variable=a.controlled_field,
            observed_delta={"fault": fault},
            reproducible=reproducible,
            classification=ABClass.E,
            reason="fault or unverified restore in one arm; STOP, no retry",
            noise_masked={"offsets": noise_offsets},
        )

    status_keys = set(a.return_status) | set(b.return_status)
    status_diff = {
        key: [a.return_status.get(key), b.return_status.get(key)]
        for key in sorted(status_keys)
        if key != "timing" and a.return_status.get(key) != b.return_status.get(key)
    }
    hash_keys = set(a.observable_hashes) | set(b.observable_hashes)
    hash_diff = {
        key: [a.observable_hashes.get(key), b.observable_hashes.get(key)]
        for key in sorted(hash_keys)
        if a.observable_hashes.get(key) != b.observable_hashes.get(key)
    }
    delta["status"] = status_diff
    delta["hash"] = hash_diff
    delta["masked"] = {"a": masked(a), "b": masked(b)}

    rejection = {"rejected", "invalid", "error"}
    a_rejected = str(a.return_status.get("rc", "")).lower() in rejection or a.error is not None
    b_rejected = str(b.return_status.get("rc", "")).lower() in rejection or b.error is not None
    if a_rejected != b_rejected:
        return ABPairRecord(
            pair_id=a.extra.get("pair_id", ""),
            experiment_a=a.experiment_id,
            experiment_b=b.experiment_id,
            changed_variable=a.controlled_field,
            observed_delta=delta,
            reproducible=reproducible,
            classification=ABClass.D,
            reason="one input variant was rejected while the other was accepted",
            noise_masked={"offsets": noise_offsets},
        )

    if not status_diff and not hash_diff:
        return ABPairRecord(
            pair_id=a.extra.get("pair_id", ""),
            experiment_a=a.experiment_id,
            experiment_b=b.experiment_id,
            changed_variable=a.controlled_field,
            observed_delta=delta,
            reproducible=reproducible,
            classification=ABClass.C,
            reason="observables identical after noise masking: no sensitivity for this field",
            noise_masked={"offsets": noise_offsets},
        )

    expected_only = bool(hash_diff) and bool(expected_region) and all(
        key.startswith("consumed_buffer") for key in hash_diff
    )
    if expected_only and not status_diff and repeat_confirmed is not False:
        return ABPairRecord(
            pair_id=a.extra.get("pair_id", ""),
            experiment_a=a.experiment_id,
            experiment_b=b.experiment_id,
            changed_variable=a.controlled_field,
            observed_delta=delta,
            reproducible=reproducible,
            classification=ABClass.A,
            reason=(
                "difference confined to the consumed-buffer observable of the controlled field; "
                "status/return identical"
            ),
            noise_masked={"offsets": noise_offsets},
        )
    return ABPairRecord(
        pair_id=a.extra.get("pair_id", ""),
        experiment_a=a.experiment_id,
        experiment_b=b.experiment_id,
        changed_variable=a.controlled_field,
        observed_delta=delta,
        reproducible=reproducible,
        classification=ABClass.B,
        reason="observables differ but attribution to the consumer is not unique",
        noise_masked={"offsets": noise_offsets},
    )
