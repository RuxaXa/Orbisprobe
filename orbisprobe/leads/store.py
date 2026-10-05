from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .model import LeadStatus, ResearchLead
from .safe_io import ProtectedSource, prepare_output_directory, safe_atomic_write_text
from .scoring import score_lead


@dataclass(frozen=True)
class LeadStore:
    leads: tuple[ResearchLead, ...]
    schema: str = "orbisprobe-research-leads-v1"

    def __post_init__(self) -> None:
        if not isinstance(self.leads, tuple) or any(not isinstance(lead, ResearchLead) for lead in self.leads):
            raise TypeError("leads must be a tuple of ResearchLead")
        ordered = tuple(sorted(self.leads, key=lambda lead: lead.lead_id))
        if len({lead.lead_id for lead in ordered}) != len(ordered):
            raise ValueError("lead IDs must be unique")
        pre_score = {
            LeadStatus.DISCOVERED,
            LeadStatus.SCORED,
            LeadStatus.EDGE_ANALYZED,
        }
        for lead in ordered:
            if lead.status in pre_score:
                continue
            normalized = score_lead(lead)
            if normalized.status is not lead.status or normalized.mode is not lead.mode:
                raise ValueError(
                    f"lead {lead.lead_id} status/mode conflicts with activation policy"
                )
        object.__setattr__(self, "leads", ordered)

    def to_dict(self) -> dict[str, Any]:
        return {"schema": self.schema, "count": len(self.leads), "leads": [lead.to_dict() for lead in self.leads]}

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2, sort_keys=True, allow_nan=False) + "\n"

    def save(
        self,
        path: str | Path,
        *,
        output_root: str | Path | None = None,
        protected_sources: tuple[ProtectedSource, ...] = (),
    ) -> None:
        target = Path(path).absolute()
        root = prepare_output_directory(
            output_root if output_root is not None else target.parent,
            protected_sources,
        )
        safe_atomic_write_text(
            target,
            self.to_json(),
            output_root=root,
            protected_sources=protected_sources,
        )

    @classmethod
    def load(cls, path: str | Path) -> LeadStore:
        value = json.loads(Path(path).read_text(encoding="utf-8"))
        if isinstance(value, list):
            records = value
            schema = "orbisprobe-research-leads-v1"
        elif isinstance(value, dict):
            unknown = set(value) - {"schema", "count", "leads"}
            if unknown:
                raise ValueError(
                    f"LeadStore has unknown fields: {', '.join(sorted(unknown))}"
                )
            records = value.get("leads")
            schema = value.get("schema", "orbisprobe-research-leads-v1")
        else:
            raise TypeError("lead store must be an object or array")
        if not isinstance(records, list):
            raise TypeError("lead store requires a leads array")
        return cls(tuple(ResearchLead.from_dict(item) for item in records), schema=schema)

    def score_all(self) -> LeadStore:
        return LeadStore(tuple(score_lead(lead) for lead in self.leads), schema=self.schema)

    def get(self, lead_id: str) -> ResearchLead:
        for lead in self.leads:
            if lead.lead_id == lead_id:
                return lead
        raise KeyError(lead_id)
