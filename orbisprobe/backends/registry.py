from __future__ import annotations

from collections.abc import Iterable

from .base import (
    AnalysisBackend,
    BackendCapability,
    BackendIdentity,
    BackendResult,
    ResourceLimits,
)


class BackendRegistry:
    def __init__(self) -> None:
        self._backends: dict[str, type[AnalysisBackend]] = {}

    def register(self, backend: type[AnalysisBackend]) -> None:
        name = backend.identity.name
        if name in self._backends:
            raise ValueError(f"backend already registered: {name}")
        self._backends[name] = backend

    def names(self) -> list[str]:
        return sorted(self._backends)

    def create(self, name: str, limits: ResourceLimits | None = None) -> AnalysisBackend | None:
        backend = self._backends.get(name)
        return backend(limits=limits) if backend is not None else None

    def status(self, name: str, limits: ResourceLimits | None = None) -> BackendResult:
        backend = self.create(name, limits)
        if backend is None:
            identity = BackendIdentity(
                name=name,
                version="unknown",
                independence_family="unknown",
                capabilities=frozenset(),
            )
            return BackendResult.unavailable(identity, "backend is not registered")
        try:
            return backend.availability()
        except Exception as exc:  # noqa: BLE001 - plugins must fail closed
            return BackendResult.unavailable(backend.identity, f"availability failed: {type(exc).__name__}: {exc}")

    def available(
        self,
        preferred: Iterable[str] | None = None,
        capability: BackendCapability | None = None,
    ) -> list[AnalysisBackend]:
        names = list(preferred) if preferred is not None else self.names()
        result: list[AnalysisBackend] = []
        for name in names:
            backend = self.create(name)
            if backend is None:
                continue
            if capability is not None and capability not in backend.identity.capabilities:
                continue
            try:
                status = backend.availability()
            except Exception:  # noqa: BLE001 - plugins must not break orchestration
                status = None
            if status is not None and status.status.value == "COMPLETED" and status.data.get("available") is True:
                result.append(backend)
        return result
