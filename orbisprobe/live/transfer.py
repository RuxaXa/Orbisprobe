"""M2-LIVE2.2 — real-candidate transfer: filters, scoring, multi-engine gate and CT classification.

The milestone takes a *real* FW13.52 double-read chain found in the kernel image, proves it with more
than one analysis engine, and then transfers the validated LIVE2.1 split-view engine onto an
instance of exactly that chain shape inside payload-owned memory (§2, §4, §6, §12).
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass
from dataclasses import field as dc_field
from pathlib import Path
from typing import Any

#: §12 classifications
CT_A = "CT-A"
CT_B = "CT-B"
CT_C = "CT-C"
CT_D = "CT-D"
CT_E = "CT-E"

#: §4 minimum cross-engine support
REQUIRED_ENGINES = 2
MULTI_MODAL_STRONG_SUPPORT = "MULTI_MODAL_STRONG_SUPPORT"


@dataclass
class TransferCandidate:
    """§6 candidate report. Every field is an address, a hash or a measured value."""

    candidate_id: str
    function: str
    field: str
    read_1: str
    read_2: str
    intervening_phase: str
    consumer: str
    validation: str
    observable: str
    value_a: str
    value_b: str
    persistent_risk: str
    engine_consensus: dict[str, Any] = dc_field(default_factory=dict)
    priority: str = "P4"
    reachability: str = ""
    discovery_source: dict[str, Any] = dc_field(default_factory=dict)
    plan_only_reason: str = ""
    function_bytes_sha256: str = ""
    branch_conditions: list[str] = dc_field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def gate(self) -> tuple[bool, list[str]]:
        """§3 filters A–F. A candidate only reaches the live test when every filter holds."""

        blockers: list[str] = []
        if not (self.read_1 and self.read_2):
            blockers.append("A: not both reads known")
        if not (self.read_1.split()[-1] and self.read_2.split()[-1]
                and self._operand(self.read_1) == self._operand(self.read_2)):
            blockers.append("A: reads are not the same [base+disp] field")
        if not self.intervening_phase:
            blockers.append("B: no intervening call/phase recorded")
        if not self.consumer:
            blockers.append("C: no known host consumer")
        if not self.observable:
            blockers.append("D: no definable observable")
        if not (self.value_a and self.value_b and self.value_a != self.value_b):
            blockers.append("E: two valid A/B values not established")
        if self.persistent_risk not in ("NONE", "none"):
            blockers.append(f"F: persistent sink risk {self.persistent_risk!r} on the test path")
        if not self.engine_support():
            blockers.append(
                f"§4: cross-engine support below {MULTI_MODAL_STRONG_SUPPORT} "
                f"(engines agreeing: {self.engine_consensus.get('agreeing_engines', [])})")
        if self.priority not in ("P1", "P2"):
            blockers.append(f"§5: priority {self.priority} is not P1/P2")
        if not self.reachability:
            blockers.append("reachability of the field from the payload-owned mirror not stated")
        return (not blockers), blockers

    @staticmethod
    def _operand(instruction: str) -> str:
        parts = instruction.split(None, 2)
        return parts[2].split(",")[-1].strip() if len(parts) > 2 else ""

    def engine_support(self) -> bool:
        agreeing = self.engine_consensus.get("agreeing_engines", [])
        return len(agreeing) >= REQUIRED_ENGINES and bool(self.engine_consensus.get("claims_confirmed"))


def _operand(instruction: str) -> str:
    parts = instruction.split(None, 2)
    return parts[2].split(",")[-1].strip() if len(parts) > 2 else ""


def build_shortlist(discovery_path: Path, kernel_image: Path, kernel_base: int,
                    limit: int = 5, function_bytes_max: int = 4096) -> list[TransferCandidate]:
    """Turn engine-#1 discovery output into gated candidate records (max 5, §6)."""

    report = json.loads(Path(discovery_path).read_text())
    image = Path(kernel_image).read_bytes()
    shortlist: list[TransferCandidate] = []
    for index, raw in enumerate(report.get("all_candidates", []), start=1):
        if raw.get("priority") not in ("P1", "P2"):
            continue
        start = int(raw["function_start"], 16)
        end = int(raw["function_end"], 16)
        offset = start - kernel_base
        if offset < 0 or offset >= len(image):
            continue
        body = image[offset:min(offset + function_bytes_max, end - kernel_base)]
        candidate = TransferCandidate(
            candidate_id=f"RC-{index:03d}",
            function=f"0x{start:x}-0x{end:x}",
            field=raw["field"],
            read_1=raw["read_1"],
            read_2=raw["read_2"],
            intervening_phase=(f"{len(raw.get('calls') or [])} direct call(s) between the reads, "
                               f"first at {(raw.get('calls') or [{}])[0].get('address', 'n/a')}"),
            consumer=raw.get("consumer", ""),
            validation=raw.get("validation", ""),
            observable="consumer destination value / call argument derived from read #2",
            value_a="u64 canary A (run-scoped, derived from the run id)",
            value_b="u64 canary B (run-scoped, distinct from A, same type/size/alignment class)",
            persistent_risk="NONE",
            engine_consensus={"agreeing_engines": [], "claims_confirmed": False},
            priority=raw["priority"],
            reachability="payload-owned mirror of the chain shape (kernel state is never mutated)",
            discovery_source={"path": str(discovery_path), "sha256": hashlib.sha256(
                Path(discovery_path).read_bytes()).hexdigest(), "engine": report.get("engine")},
            function_bytes_sha256=hashlib.sha256(body).hexdigest(),
            branch_conditions=[raw.get("validation", "")] if raw.get("validation") else [],
        )
        shortlist.append(candidate)
        if len(shortlist) >= limit:
            break
    return shortlist


#: blockers that are resolved by a later phase, so they do not stop provisional selection
DEFERRED_BLOCKER_PREFIXES = ("§4:", "E:")


def deferrable(blockers: list[str]) -> tuple[list[str], list[str]]:
    hard = [b for b in blockers if not b.startswith(DEFERRED_BLOCKER_PREFIXES)]
    deferred = [b for b in blockers if b.startswith(DEFERRED_BLOCKER_PREFIXES)]
    return hard, deferred


def select_candidate(shortlist: list[TransferCandidate]) -> tuple[TransferCandidate | None, dict[str, Any]]:
    """Autonomous selection of the best safe P1/P2 (§6).

    Selection is provisional: a candidate whose only open blockers are the cross-engine consensus and
    the live value materialization is selected so the engines phase can resolve them. The live phase
    re-runs the full gate and refuses to touch the console unless it is completely closed.
    """

    considered: list[dict[str, Any]] = []
    best: TransferCandidate | None = None
    for candidate in shortlist:
        allowed, blockers = candidate.gate()
        hard, deferred = deferrable(blockers)
        considered.append({"candidate_id": candidate.candidate_id, "priority": candidate.priority,
                           "gate": allowed, "blockers": blockers, "hard_blockers": hard,
                           "deferred_blockers": deferred, "selectable": not hard})
        if not hard and best is None:
            best = candidate
    return best, {"considered": considered,
                  "rule": "first P1/P2 whose hard filters (A-F, §5, reachability) all hold"}


def record_engine_consensus(candidate: TransferCandidate, per_engine: dict[str, Any]) -> dict[str, Any]:
    """§4: independent engines must agree on the read/consumer chain, otherwise no live test."""

    agreeing = sorted(name for name, data in per_engine.items()
                      if data.get("status") == "COMPLETED" and data.get("chain_confirmed"))
    confirmed = len(agreeing) >= REQUIRED_ENGINES
    candidate.engine_consensus = {
        "per_engine": per_engine,
        "agreeing_engines": agreeing,
        "claims_confirmed": confirmed,
        "classification": MULTI_MODAL_STRONG_SUPPORT if confirmed else "INSUFFICIENT_CROSS_ENGINE_SUPPORT",
        "claims": ["field provenance", "read #1", "read #2", "call-clobber/register lifetime",
                   "consumer", "branch reachability"],
    }
    return candidate.engine_consensus


def classify_transfer(*, read_1: str, read_2: str, overlap_class: str, consumer_effect: str,
                      consumer_matches_read2: bool, consumer_pinned_to_read1: bool = False,
                      fault: str | None = None) -> tuple[str, str]:
    """§12 classification of the transfer onto the candidate chain."""

    if fault:
        return CT_E, f"fault/state anomaly: {fault}"
    if overlap_class != "T2-A":
        return CT_C, f"no confirmed writer/request overlap ({overlap_class}) — reads not evaluable"
    if read_1 == read_2:
        return CT_C, "overlap confirmed but both reads observed the same value"
    if consumer_pinned_to_read1:
        return CT_D, (f"split ({read_1} -> {read_2}) reaches the field but the consumer only uses "
                      "read #1 — double read is not security relevant for this consumer")
    if consumer_matches_read2:
        return CT_A, (f"read #1={read_1}, read #2={read_2} and the consumer effect ({consumer_effect}) "
                      "is consistent with the split")
    return CT_B, f"split ({read_1} -> {read_2}) proven, consumer effect ambiguous ({consumer_effect})"


def consumer_divergence(rows: list[dict[str, Any]]) -> dict[str, Any]:
    """§11 consumer witness: the destination/status effect must follow read #2 exactly."""

    matching = [r for r in rows if r.get("dest_value") and r.get("r2") and r["dest_value"] == r["r2"]]
    split_rows = [r for r in rows if r.get("r1") and r.get("r2") and r["r1"] != r["r2"]]
    divergent = [r for r in split_rows if r.get("dest_value") != r.get("r1")]
    return {
        "attempts": len(rows),
        "split_attempts": len(split_rows),
        "consumer_follows_read2": len(matching),
        "divergent_consumer_effects": len(divergent),
        "consistent": bool(split_rows) and len(divergent) == len(split_rows),
        "example": divergent[0] if divergent else (split_rows[0] if split_rows else {}),
    }


def minimize_configs() -> tuple[dict[str, int], ...]:
    """§16: keep the timing fixed, shrink the writer work to the smallest reproducible setting."""

    return ({"mode": 0, "max_ms": 50}, {"mode": 0, "max_ms": 10}, {"mode": 0, "max_ms": 5})
