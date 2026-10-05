"""M2-B function harness model.

A harness is a serializable, hash-bound description of a single offline function execution:
memory layout, inputs, taint sources, expected sinks, callee stubs, and stop conditions.

Nothing in this package executes code from a harness document. Stub behaviour is referenced by
name and resolved against the explicit stub registry in :mod:`orbisprobe.harness.registry`.
"""

from .model import (
    HARNESS_INVALID,
    SUPPORTED_SCHEMA_VERSION,
    CalleeStub,
    Harness,
    HarnessError,
    InputRegion,
    MemoryRegion,
    OutputRegion,
    SinkType,
    StopCondition,
    TaintSource,
    load_harness,
    parse_harness,
    validate_harness,
)
from .registry import STUB_REGISTRY_VERSION, resolve_stub

__all__ = [
    "HARNESS_INVALID",
    "STUB_REGISTRY_VERSION",
    "SUPPORTED_SCHEMA_VERSION",
    "CalleeStub",
    "Harness",
    "HarnessError",
    "InputRegion",
    "MemoryRegion",
    "OutputRegion",
    "SinkType",
    "StopCondition",
    "TaintSource",
    "load_harness",
    "parse_harness",
    "resolve_stub",
    "validate_harness",
]
