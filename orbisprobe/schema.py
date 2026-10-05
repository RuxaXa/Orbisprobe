from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any


class RiskClass(str, Enum):
    OFFLINE = "offline"
    READ_ONLY = "read_only"
    VOLATILE_USER = "volatile_user"
    VOLATILE_SHARED = "volatile_shared"
    REVERSIBLE_KERNEL_RAM = "reversible_kernel_ram"
    ACTIVE_REQUEST = "active_request"
    PERSISTENT = "persistent"

class EvidenceState(str, Enum):
    CONFIRMED = "CONFIRMED"
    SUPPORTED = "SUPPORTED"
    INFERRED = "INFERRED"
    UNKNOWN = "UNKNOWN"
    DISPROVED = "DISPROVED"
    REVISED = "REVIDIERT"

@dataclass
class Step:
    kind: str
    args: dict[str, Any] = field(default_factory=dict)

@dataclass
class Oracle:
    kind: str
    args: dict[str, Any] = field(default_factory=dict)

@dataclass
class Experiment:
    id: str
    title: str
    hypothesis: str
    risk: RiskClass
    controlled_input: str = ""
    validation: str = ""
    consumer: str = ""
    expected_effect: str = ""
    observable: str = ""
    experiment: str = ""
    preconditions: list[str] = field(default_factory=list)
    forbidden_sinks: list[str] = field(default_factory=list)
    reachable_sinks: list[str] = field(default_factory=list)
    validation_steps: list[Step] = field(default_factory=list)
    steps: list[Step] = field(default_factory=list)
    oracles: list[Oracle] = field(default_factory=list)
    restore_steps: list[Step] = field(default_factory=list)
    stop_on: list[str] = field(default_factory=lambda: ["fault", "unexpected_reboot", "control_channel_loss"])
    metadata: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_json(cls, path: str) -> Experiment:
        with open(path, "r", encoding="utf-8") as source:
            obj = json.load(source, parse_constant=_reject_nonfinite)
        if not isinstance(obj, dict):
            raise TypeError("experiment plan must be a JSON object")
        obj["risk"] = RiskClass(obj["risk"])
        obj["validation_steps"] = [Step(**x) for x in obj.get("validation_steps", [])]
        obj["steps"] = [Step(**x) for x in obj.get("steps", [])]
        obj["oracles"] = [Oracle(**x) for x in obj.get("oracles", [])]
        obj["restore_steps"] = [Step(**x) for x in obj.get("restore_steps", [])]
        experiment = cls(**obj)
        experiment.assert_valid_structure()
        return experiment

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["risk"] = self.risk.value
        return d

    def assert_valid_structure(self) -> None:
        if not isinstance(self.risk, RiskClass):
            raise TypeError("risk must be a RiskClass")
        for name in (
            "id",
            "title",
            "hypothesis",
            "controlled_input",
            "validation",
            "consumer",
            "expected_effect",
            "observable",
            "experiment",
        ):
            if not isinstance(getattr(self, name), str):
                raise TypeError(f"{name} must be a string")
        if not isinstance(self.metadata, dict):
            raise TypeError("metadata must be an object")
        for name in ("preconditions", "forbidden_sinks", "reachable_sinks", "stop_on"):
            value = getattr(self, name)
            if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
                raise TypeError(f"{name} must be a list of strings")
        for name in ("validation_steps", "steps", "restore_steps"):
            value = getattr(self, name)
            if not isinstance(value, list):
                raise TypeError(f"{name} must be a list")
            for step in value:
                if not isinstance(step, Step) or not isinstance(step.kind, str) or not isinstance(step.args, dict):
                    raise TypeError(f"{name} entries require string kind and object args")
        if not isinstance(self.oracles, list):
            raise TypeError("oracles must be a list")
        for oracle in self.oracles:
            if not isinstance(oracle, Oracle) or not isinstance(oracle.kind, str) or not isinstance(oracle.args, dict):
                raise TypeError("oracles entries require string kind and object args")
        canonical_experiment_bytes(self)


def _reject_nonfinite(value: str) -> None:
    raise ValueError(f"non-finite JSON number is forbidden: {value}")


def canonical_experiment_bytes(exp: Experiment) -> bytes:
    return json.dumps(
        exp.to_dict(),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def experiment_sha256(exp: Experiment) -> str:
    return hashlib.sha256(canonical_experiment_bytes(exp)).hexdigest()
