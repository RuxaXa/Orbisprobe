from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .graph import ResearchGraph
from .model import SurfaceFinding


@dataclass
class TrackScanResult:
    track: str
    classification: str
    surfaces: list[SurfaceFinding] = field(default_factory=list)
    graph: ResearchGraph = field(default_factory=ResearchGraph)
    diagnostics: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "track": self.track,
            "classification": self.classification,
            "surfaces": [surface.to_dict() for surface in self.surfaces],
            "candidates": [
                {
                    "surface_id": surface.surface_id,
                    "priority": surface.candidate_priority,
                    "score": surface.candidate_score,
                    "classification": surface.classification,
                }
                for surface in self.surfaces
            ],
            "open_chains": [
                {"surface_id": surface.surface_id, "unknowns": list(surface.unknowns)}
                for surface in self.surfaces
                if surface.unknowns
            ],
            "graph": self.graph.to_dict(),
            "diagnostics": list(self.diagnostics),
        }
