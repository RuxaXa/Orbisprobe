from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any


class Target(ABC):
    @abstractmethod
    def execute(self, kind: str, args: dict[str, Any]) -> dict[str, Any]:
        raise NotImplementedError
