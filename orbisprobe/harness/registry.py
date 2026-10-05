"""Explicit callee-stub registry.

Only deterministic, fully specified functions may be stubbed. There are deliberately no generic
"return 0" fallbacks: an unknown call must stop the run as ``STUB_REQUIRED`` instead of being
silently skipped, and every stub that ran appears in the dynamic evidence.

Harness documents reference a stub by *name* only. Behaviour never comes from the harness file.
"""

from __future__ import annotations

from dataclasses import dataclass

#: Bumped whenever a stub's semantics change; part of the analysis cache key.
STUB_REGISTRY_VERSION = "1"

MEMORY_NONE = "NONE"
MEMORY_WRITE_DEST_FROM_SRC = "WRITE_DEST_BYTES_FROM_SRC"
MEMORY_WRITE_DEST_FILL = "WRITE_DEST_FILL"

TAINT_NONE = "NONE"
TAINT_COPY_SRC_TO_DEST = "COPY_SRC_BYTES_TO_DEST"
TAINT_FILL_VALUE_TO_DEST = "FILL_VALUE_TO_DEST"
TAINT_PROPAGATE_ARG0 = "PROPAGATE_ARG0"
TAINT_COPY_SRC_TO_DEST_OVERLAP_SAFE = "COPY_SRC_BYTES_TO_DEST_OVERLAP_SAFE"


@dataclass(frozen=True)
class StubSpec:
    name: str
    abi: str
    arguments: tuple[str, ...]
    returns: str | None
    clobbers: frozenset[str]
    preserves: frozenset[str]
    memory_effect: str
    taint_semantics: str
    deterministic: bool
    description: str

    def to_dict(self) -> dict[str, object]:
        return {
            "name": self.name,
            "abi": self.abi,
            "arguments": list(self.arguments),
            "returns": self.returns,
            "clobbers": sorted(self.clobbers),
            "preserves": sorted(self.preserves),
            "memory_effect": self.memory_effect,
            "taint_semantics": self.taint_semantics,
            "deterministic": self.deterministic,
            "description": self.description,
        }


CALLER_SAVED = ("rax", "rcx", "rdx", "rsi", "rdi", "r8", "r9", "r10", "r11")
CALLEE_SAVED = ("rbx", "rbp", "r12", "r13", "r14", "r15")
#: Stub clobbers exclude the result register and the argument registers the stub consumes, because
#: the harness adapter writes those explicitly.
_CALL_CLOBBER = frozenset({"rcx", "r8", "r9", "r10", "r11"})

STUBS: dict[str, StubSpec] = {
    "memcpy": StubSpec(
        name="memcpy",
        abi="sysv-amd64",
        arguments=("rdi", "rsi", "rdx"),
        returns="rax",
        clobbers=_CALL_CLOBBER,
        preserves=frozenset(CALLEE_SAVED),
        memory_effect=MEMORY_WRITE_DEST_FROM_SRC,
        taint_semantics=TAINT_COPY_SRC_TO_DEST,
        deterministic=True,
        description="copy rdx bytes from rsi to rdi; returns rdi",
    ),
    "memmove": StubSpec(
        name="memmove",
        abi="sysv-amd64",
        arguments=("rdi", "rsi", "rdx"),
        returns="rax",
        clobbers=_CALL_CLOBBER,
        preserves=frozenset(CALLEE_SAVED),
        memory_effect=MEMORY_WRITE_DEST_FROM_SRC,
        taint_semantics=TAINT_COPY_SRC_TO_DEST_OVERLAP_SAFE,
        deterministic=True,
        description="overlap-safe byte copy rdx bytes from rsi to rdi; returns rdi",
    ),
    "memset": StubSpec(
        name="memset",
        abi="sysv-amd64",
        arguments=("rdi", "esi", "rdx"),
        returns="rax",
        clobbers=_CALL_CLOBBER,
        preserves=frozenset(CALLEE_SAVED),
        memory_effect=MEMORY_WRITE_DEST_FILL,
        taint_semantics=TAINT_FILL_VALUE_TO_DEST,
        deterministic=True,
        description="fill rdx bytes at rdi with the low byte of esi; returns rdi",
    ),
    "alloc_region": StubSpec(
        name="alloc_region",
        abi="sysv-amd64",
        arguments=("rdi",),
        returns="rax",
        clobbers=_CALL_CLOBBER,
        preserves=frozenset(CALLEE_SAVED),
        memory_effect=MEMORY_NONE,
        taint_semantics=TAINT_NONE,
        deterministic=True,
        description=(
            "deterministic allocator result; the returned address is fixed by the harness stub "
            "declaration and must name a mapped writable region"
        ),
    ),
    "status_ok": StubSpec(
        name="status_ok",
        abi="sysv-amd64",
        arguments=(),
        returns="rax",
        clobbers=_CALL_CLOBBER,
        preserves=frozenset(CALLEE_SAVED),
        memory_effect=MEMORY_NONE,
        taint_semantics=TAINT_NONE,
        deterministic=True,
        description="status getter returning the harness-declared constant status",
    ),
    "pure_identity": StubSpec(
        name="pure_identity",
        abi="sysv-amd64",
        arguments=("rdi",),
        returns="rax",
        clobbers=_CALL_CLOBBER,
        preserves=frozenset(CALLEE_SAVED),
        memory_effect=MEMORY_NONE,
        taint_semantics=TAINT_PROPAGATE_ARG0,
        deterministic=True,
        description="pure helper returning its first argument unchanged",
    ),
    "pure_zero": StubSpec(
        name="pure_zero",
        abi="sysv-amd64",
        arguments=(),
        returns="rax",
        clobbers=_CALL_CLOBBER,
        preserves=frozenset(CALLEE_SAVED),
        memory_effect=MEMORY_NONE,
        taint_semantics=TAINT_NONE,
        deterministic=True,
        description="pure helper returning the constant integer zero",
    ),
}


def resolve_stub(name: str) -> StubSpec | None:
    """Resolve a stub name against the allowlist. Unknown names are never invented."""

    return STUBS.get(name)


def registry_document() -> dict[str, object]:
    return {
        "version": STUB_REGISTRY_VERSION,
        "stubs": {name: spec.to_dict() for name, spec in sorted(STUBS.items())},
    }
