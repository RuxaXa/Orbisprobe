from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from orbisprobe.analysis.binary import BinaryImage

from .iommu import scan_iommu
from .memctl import scan_memctl
from .scanner import TrackScanResult
from .secure import scan_secure
from .svm import scan_svm

TRACK_ORDER = ("svm", "iommu", "secure", "memctl")
TRACK_SCANNERS = {
    "svm": scan_svm,
    "iommu": scan_iommu,
    "secure": scan_secure,
    "memctl": scan_memctl,
}


@dataclass
class PrivilegeSurfaceReport:
    mode: str
    image: BinaryImage
    tracks: list[TrackScanResult]

    @property
    def surfaces(self):
        return [surface for track in self.tracks for surface in track.surfaces]

    def to_dict(self) -> dict[str, Any]:
        track_data = [track.to_dict() for track in self.tracks]
        surface_data = [surface.to_dict() for surface in self.surfaces]
        return {
            "mode": self.mode,
            "binary": {
                "path": str(self.image.path),
                "sha256": self.image.sha256,
                "size": self.image.size,
                "architecture": self.image.architecture,
                "base": self.image.base,
            },
            "tracks": track_data,
            "surfaces": surface_data,
            "candidates": [
                candidate
                for track in track_data
                for candidate in track["candidates"]
            ],
            "open_chains": [
                chain
                for track in track_data
                for chain in track["open_chains"]
            ],
            "graphs": [
                {"track": track["track"], "graph": track["graph"]}
                for track in track_data
            ],
            "diagnostics": [
                {"track": track["track"], "message": message}
                for track in track_data
                for message in track["diagnostics"]
            ],
        }

    def to_text(self) -> str:
        lines = [
            "# OrbisProbe Privilege surfaces",
            f"Binary: {self.image.path}",
            f"SHA-256: {self.image.sha256}",
            f"Architecture: {self.image.architecture}",
            f"Base: 0x{self.image.base:x}",
            f"Privilege surfaces: {len(self.surfaces)}",
            "",
        ]
        for track in self.tracks:
            lines.append(f"## {track.track}: {track.classification}")
            if not track.surfaces:
                lines.append("- no promoted surface")
            for surface in track.surfaces:
                address = f"0x{surface.address:x}" if surface.address is not None else "unknown"
                lines.extend(
                    [
                        f"- {surface.surface_id}",
                        f"  type: {surface.surface_type.value}",
                        f"  classification: {surface.classification}",
                        f"  status/confidence: {surface.status.value}/{surface.confidence.value}",
                        f"  function/address: {surface.function or 'unknown'} / {address}",
                        f"  boundary: {surface.boundary.value} ({surface.boundary_type})",
                        f"  candidate: {surface.candidate_priority} score={surface.candidate_score:.4f}",
                        f"  evidence items: {len(surface.evidence)}",
                        "  unknowns: " + ("; ".join(surface.unknowns) if surface.unknowns else "none"),
                    ]
                )
            for diagnostic in track.diagnostics:
                lines.append(f"- diagnostic: {diagnostic}")
            lines.append("")
        lines.append("Pattern hits are triage evidence, not vulnerability findings.")
        return "\n".join(lines)


def scan_privilege_surface(mode: str, image: BinaryImage) -> PrivilegeSurfaceReport:
    if mode == "all":
        tracks = [TRACK_SCANNERS[name](image) for name in TRACK_ORDER]
    elif mode in TRACK_SCANNERS:
        tracks = [TRACK_SCANNERS[mode](image)]
    else:
        raise ValueError(f"unknown privilege-surface mode: {mode}")
    return PrivilegeSurfaceReport(mode=mode, image=image, tracks=tracks)
