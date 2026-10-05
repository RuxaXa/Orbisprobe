from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class CandidatePriority(str, Enum):
    P1 = "P1"
    P2 = "P2"
    P3 = "P3"
    P4 = "P4"


@dataclass(frozen=True)
class RankingFactors:
    controllability: float = 0.0
    validation_gap: float = 0.0
    privilege_distance: float = 0.0
    consumer_confidence: float = 0.0
    observable_quality: float = 0.0
    reproducibility: float = 0.0
    persistent_risk: float = 0.0
    host_closed: bool = False
    cross_processor: bool = False

    def normalized(self) -> RankingFactors:
        values = {
            name: min(1.0, max(0.0, float(getattr(self, name))))
            for name in (
                "controllability",
                "validation_gap",
                "privilege_distance",
                "consumer_confidence",
                "observable_quality",
                "reproducibility",
                "persistent_risk",
            )
        }
        return RankingFactors(
            **values,
            host_closed=self.host_closed,
            cross_processor=self.cross_processor,
        )


def rank_candidate(factors: RankingFactors) -> tuple[CandidatePriority, float]:
    f = factors.normalized()
    score = (
        0.22 * f.controllability
        + 0.20 * f.validation_gap
        + 0.15 * f.privilege_distance
        + 0.18 * f.consumer_confidence
        + 0.10 * f.observable_quality
        + 0.15 * f.reproducibility
        - 0.20 * f.persistent_risk
    )
    score = round(min(1.0, max(0.0, score)), 4)
    if f.host_closed and f.controllability >= 0.75 and f.consumer_confidence >= 0.75:
        priority = CandidatePriority.P1
    elif f.host_closed and f.validation_gap >= 0.65 and f.consumer_confidence >= 0.55:
        priority = CandidatePriority.P2
    elif f.cross_processor and f.consumer_confidence >= 0.35:
        priority = CandidatePriority.P3
    else:
        priority = CandidatePriority.P4
    return priority, score
