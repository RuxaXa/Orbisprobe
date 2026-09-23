"""Fail-closed address classification for live target access.

Every live read/write must name the class of its target address *before* the access is issued, and
the policy decides which classes are permitted. The rule table below is deliberately explicit about
its provenance; anything not covered is ``UNKNOWN``, and ``UNKNOWN`` is write-blocked and
read-blocked unless a plan explicitly allows it.

Evidence sources for the ranges (all in-repo or measured on this console, never guessed):

* PID 0x18 kernel image span and its segment bounds — the validated FW13.52 dump of this console
  (``fw1352-ps4b-20260920/kernel-dump``, 44,040,192 bytes, SHA-256 ``cf157ffd…``); the image is
  contiguous from ``kernel_base`` and its PT_LOAD program headers give the text/data split.
* Kernel-VM allocations below the direct map — measured pointers on this console
  (``ALLPROC``/``ROOTVNODE`` from the FW13.52 dump point into ``0xffff82…``).
* Direct-map formula ``KVA = 0xffffff8000000000 + PA`` — project note, consistent with the
  measured kernel-image placement above the direct map.
* MMIO windows — from the CASE-001/PCI enumeration record (``0xF8000000``, ``0xFED80000``,
  ``0xFED00000``, ``0xFEB00000``, ``0xE4800000``); they are only classified as MMIO, never
  accessed, because MMIO reads are outside LIVE0 unless separately declared safe.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

CANONICAL_HIGH_MIN = 0xFFFF800000000000
USER_MAX = 0x0000800000000000

#: Direct map window (KVA = 0xffffff8000000000 + PA), 16 GiB of physical address space.
DIRECT_MAP_BASE = 0xFFFFFF8000000000
DIRECT_MAP_END = 0xFFFFFF8400000000

#: Kernel VM region between the canonical kernel start and the direct map.
KERNEL_VM_BASE = CANONICAL_HIGH_MIN
KERNEL_VM_END = DIRECT_MAP_BASE

#: Measured FW13.52 kernel image span on this console (dump size, rounded up to a 2 MiB page).
KERNEL_IMAGE_SPAN = 0x2A10000

#: Low MMIO windows below the user range, from the PCI/CASE-001 enumeration record.
LOW_MMIO_WINDOWS: tuple[tuple[int, int], ...] = (
    (0x00000000E0000000, 0x00000000F0000000),
    (0x00000000F0000000, 0x0000000100000000),
)


class AddressClass(str, Enum):
    USER = "USER"
    KERNEL_HEAP = "KERNEL_HEAP"
    KERNEL_DATA = "KERNEL_DATA"
    KERNEL_TEXT = "KERNEL_TEXT"
    DIRECT_MAP = "DIRECT_MAP"
    SHARED_MAPPING = "SHARED_MAPPING"
    GPUVM = "GPUVM"
    MMIO = "MMIO"
    UNKNOWN = "UNKNOWN"


@dataclass(frozen=True)
class KernelImageLayout:
    """Segment bounds of the kernel image, relative to its base."""

    base: int
    span: int = KERNEL_IMAGE_SPAN
    text_end: int = 0xCFE758  # PT_LOAD RX: file offset 0x0 .. 0xCFE758
    data_end: int = 0x16665E8  # PT_LOAD RW file end (0xD20000 + 0x6065E8) - relative start

    @property
    def end(self) -> int:
        return self.base + self.span


@dataclass(frozen=True)
class Region:
    """A region the caller positively owns (payload buffer) or declares (shared/GPUVM window)."""

    name: str
    start: int
    size: int
    address_class: AddressClass

    @property
    def end(self) -> int:
        return self.start + self.size

    def contains(self, address: int, length: int = 1) -> bool:
        return self.start <= address and address + length <= self.end


def is_canonical(address: int) -> bool:
    """x86-64 canonical form: bits 63:48 are all 0 (user) or all 1 (kernel)."""

    if address < 0 or address > 0xFFFFFFFFFFFFFFFF:
        return False
    high = (address >> 48) & 0xFFFF
    return high == 0x0000 or high == 0xFFFF


def classify(
    address: int,
    *,
    image: KernelImageLayout | None = None,
    owned_regions: list[Region] | tuple[Region, ...] = (),
    mmio_windows: tuple[tuple[int, int], ...] = LOW_MMIO_WINDOWS,
    gpuvm_regions: tuple[Region, ...] = (),
) -> AddressClass:
    """Classify one address. Never guesses: unmatched input is ``UNKNOWN``."""

    if not is_canonical(address):
        return AddressClass.UNKNOWN

    # Positively owned regions win: they are the only ones we can prove we own.
    for region in owned_regions:
        if region.contains(address):
            return region.address_class

    for region in gpuvm_regions:
        if region.contains(address):
            return region.address_class

    for start, end in mmio_windows:
        if start <= address < end:
            return AddressClass.MMIO

    if image is not None and image.base <= address < image.end:
        offset = address - image.base
        if offset < image.text_end:
            return AddressClass.KERNEL_TEXT
        return AddressClass.KERNEL_DATA

    if KERNEL_VM_BASE <= address < KERNEL_VM_END:
        return AddressClass.KERNEL_HEAP

    if DIRECT_MAP_BASE <= address < DIRECT_MAP_END:
        return AddressClass.DIRECT_MAP

    if address < USER_MAX:
        # Low but not owned by us. Could be another process, an MMIO BAR or a device window;
        # without positive evidence it is unknown and therefore blocked.
        return AddressClass.UNKNOWN

    return AddressClass.UNKNOWN


def region_of(
    name: str,
    start: int,
    size: int,
    address_class: AddressClass,
) -> Region:
    return Region(name=name, start=start, size=size, address_class=address_class)
