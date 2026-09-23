"""Kernel profile constants for live verification.

Every constant here is derived from an artefact that is verified by hash before use; nothing is
guessed. The FW 13.52 profile is taken from this console's own validated kernel dump
(``fw1352-ps4b-20260920/kernel-dump`` — 44,040,192 bytes, SHA-256
``cf157ffdbae872a20bbb9a46c8518b53d96c1ed75d4e73878466a295d92eca35``, ELF64 ET_EXEC).

Two kinds of expectation are distinguished, and both are needed:

* **image-relative content** — bytes loaded from the image file (ELF header, text). These must be
  byte-identical to the dump at the same file offset, because the dump is the same firmware with
  the same loader patches.
* **base-relative values** — pointers stored in the image's data segment that are relocated to the
  boot's KASLR base. Their *difference* to the base is a cross-boot invariant, so the live value
  must equal ``live_kernel_base + delta``.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class KernelProfile:
    name: str
    firmware: str
    dump_sha256: str
    dump_size: int
    #: Span of the mapped image, used for KERNEL_TEXT/KERNEL_DATA classification.
    image_span: int
    text_end: int
    data_end: int
    #: Image-relative offsets whose bytes must match the dump exactly.
    content_rvas: dict[str, int] = field(default_factory=dict)
    #: Fields inside a content sample that the loader relocates to the boot's kernel base, as
    #: (offset-in-sample, size). Everything else in the sample must be byte-identical.
    relocated_fields: dict[str, tuple[tuple[int, int], ...]] = field(default_factory=dict)
    #: Offsets of pointer slots plus their expected delta to the kernel base.
    base_relative: dict[str, tuple[int, int]] = field(default_factory=dict)
    #: Offsets of pointers that are expected to be canonical kernel-VM/heap allocations.
    heap_pointers: dict[str, int] = field(default_factory=dict)
    #: struct proc layout offsets used by the bounded process walk.
    proc_layout: dict[str, int] = field(default_factory=dict)


def _fw1352_ps4b() -> KernelProfile:
    return KernelProfile(
        name="ps4b-cuh2116a-fw1352",
        firmware="13.52",
        dump_sha256="cf157ffdbae872a20bbb9a46c8518b53d96c1ed75d4e73878466a295d92eca35",
        dump_size=44040192,
        image_span=0x2A10000,
        text_end=0xCFE758,
        data_end=0x16665E8,
        content_rvas={
            "elf_header": 0x0,  # ELF64 header as loaded, 64 bytes
            "text_sample": 0x100000,  # 256 bytes inside PT_LOAD RX
            "rownames_sample": 0x140000,  # 256 bytes inside PT_LOAD RX
        },
        # Measured on this console: the in-memory ELF header's e_entry is relocated to the boot's
        # KASLR base (live 0xffffffffdfdb a410 = base + 0x6a410 against dump base + 0x6a410),
        # while every other header byte is boot-stable. Comparing a raw hash would fail on that
        # one field and prove nothing about the transport, so it is checked as a base-relative
        # pointer instead.
        relocated_fields={"elf_header": ((0x18, 8),)},
        base_relative={
            # PRISON0: pointer to the prison0 struct; delta verified against the dump.
            "prison0": (0x0111FA18, 0x1A5C0C0),
            # M_TEMP: uma zone pointer; delta verified against the dump.
            "m_temp": (0x01520D00, 0x1A42F70),
        },
        heap_pointers={
            "allproc": 0x01B28538,
            "rootvnode": 0x02136E90,
        },
        proc_layout={"le_next": 0x00, "p_ucred": 0x40, "p_fd": 0x48, "p_comm": 0x454},
    )


PROFILES: dict[str, KernelProfile] = {
    "13.52": _fw1352_ps4b(),
}

DEFAULT_PROFILE = PROFILES["13.52"]
