"""Live access policy: what may be read, what may be written, what is always blocked.

Fail-closed by construction: a plan is refused unless every operation is positively allowed. The
persistent hard block (flash/NOR/FSL/SNVS/Syscon/NVS/eFuse/keys/firmware commit/bootloader/
persistent signature-check patch) is checked first and cannot be overridden by anything a plan
claims about itself (§16).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from .classification import AddressClass, KernelImageLayout, classify
from .identity import TargetIdentity
from .plan import ExperimentPlan

#: LIVE0 read bound per operation.
LIVE0_MAX_READ = 0x1000
#: Pointer-chain depth bound.
LIVE0_MAX_POINTER_DEPTH = 3
#: Write bound per operation in LIVE0 (user/shared memory only).
LIVE0_MAX_WRITE = 0x1000


class PersistentSink(str, Enum):
    FLASH = "FLASH"
    NOR = "NOR"
    FSL = "FSL"
    SNVS_WRITE = "SNVS_WRITE"
    SYSCON_PERSISTENT_STATE = "SYSCON_PERSISTENT_STATE"
    NVS_NVRAM = "NVS_NVRAM"
    KEY_PROVISIONING = "KEY_PROVISIONING"
    EFUSE_OTP = "EFUSE_OTP"
    FIRMWARE_UPDATE_COMMIT = "FIRMWARE_UPDATE_COMMIT"
    FILESYSTEM_PERSISTENT = "FILESYSTEM_PERSISTENT"
    BOOTLOADER = "BOOTLOADER"
    ELF_SIGN_CHECK_PATCH = "ELF_SIGN_CHECK_PATCH"


HARD_BLOCK_SINKS: frozenset[str] = frozenset(item.value for item in PersistentSink)

#: Substrings that, when they appear in a declared sink or a plan note, force the hard block even
#: if the plan labels itself otherwise.
HARD_BLOCK_KEYWORDS: tuple[str, ...] = (
    "flash",
    "nor",
    "fsl",
    "snvs",
    "syscon",
    "nvs",
    "nvram",
    "efuse",
    "otp",
    "keymgr",
    "key_provision",
    "firmware_commit",
    "pup_update",
    "bootloader",
    "elf_sign",
    "sflash",
    "sbram",
)


class PolicyLevel(str, Enum):
    LIVE0_R = "LIVE0-R"
    LIVE0_U = "LIVE0-U"
    LIVE0_S = "LIVE0-S"
    LIVE0_K = "LIVE0-K"


@dataclass(frozen=True)
class PolicyDecision:
    allowed: bool
    blocks: tuple[str, ...] = ()
    reasons: tuple[str, ...] = ()
    classifications: dict[int, str] = field(default_factory=dict)

    def __bool__(self) -> bool:  # pragma: no cover - convenience
        return self.allowed


@dataclass
class LivePolicy:
    """Policy for one live level.

    ``allowed_write_classes`` is intentionally tiny: LIVE0 permits writes in USER memory only and
    (if explicitly opened) SHARED_MAPPING. Everything else is refused.
    """

    level: str = PolicyLevel.LIVE0_R.value
    allowed_write_classes: frozenset[str] = frozenset({AddressClass.USER.value})
    allowed_read_classes: frozenset[str] = frozenset(
        {
            AddressClass.USER.value,
            AddressClass.KERNEL_TEXT.value,
            AddressClass.KERNEL_DATA.value,
            AddressClass.KERNEL_HEAP.value,
            AddressClass.DIRECT_MAP.value,
        }
    )
    max_read: int = LIVE0_MAX_READ
    max_write: int = LIVE0_MAX_WRITE
    max_pointer_depth: int = LIVE0_MAX_POINTER_DEPTH
    allow_mmio_read: bool = False
    require_identity: bool = True
    #: Kernel-image layout of the target, used for KERNEL_TEXT/KERNEL_DATA classification.
    image: KernelImageLayout | None = None
    #: Regions we positively own (the payload's own user test buffer).
    owned_regions: tuple = ()
    #: Device/GPU windows, declared as data and never touched in LIVE0.
    gpuvm_regions: tuple = ()

    def classify(self, address: int) -> AddressClass:
        return classify(
            address,
            image=self.image,
            owned_regions=self.owned_regions,
            gpuvm_regions=self.gpuvm_regions,
        )

    # ------------------------------------------------------------------ checks
    def _hard_block(self, sink: str, notes: str = "") -> str | None:
        haystack = f"{sink} {notes}".lower()
        if sink in HARD_BLOCK_SINKS:
            return f"persistent hard block: declared sink {sink}"
        for keyword in HARD_BLOCK_KEYWORDS:
            if keyword in haystack:
                return f"persistent hard block: plan references {keyword!r}"
        return None

    def evaluate(
        self,
        plan: ExperimentPlan,
        identity: TargetIdentity | None = None,
        live_kernel_base: int | None = None,
    ) -> PolicyDecision:
        blocks: list[str] = []
        reasons: list[str] = []

        hard = self._hard_block(plan.declared_sink, plan.notes + " " + str(plan.expected))
        if hard:
            blocks.append(hard)

        if plan.level != self.level:
            blocks.append(f"plan level {plan.level} does not match policy level {self.level}")

        if self.require_identity and identity is None:
            blocks.append("no target identity bound to this plan")

        if identity is not None and live_kernel_base is not None:
            staleness = identity.check_staleness(live_kernel_base)
            if staleness:
                blocks.append(staleness)

        # The plan may bind itself to the identity it was written for; a mismatch is a target
        # mix-up and is refused before any I/O.
        expected_session = plan.expected.get("session_id")
        if expected_session is not None and (
            identity is None or expected_session != identity.session_id
        ):
            blocks.append(
                "plan identity mismatch: plan expects session "
                f"{expected_session}, bound identity is "
                f"{identity.session_id if identity else 'unbound'}"
            )
        expected_target = plan.expected.get("target_name")
        if expected_target is not None and (
            identity is None or expected_target != identity.target_name
        ):
            blocks.append(
                f"plan target mismatch: plan expects {expected_target}, "
                f"bound identity is {identity.target_name if identity else 'unbound'}"
            )
        expected_base = plan.expected.get("kernel_base")
        if expected_base is not None and live_kernel_base is not None and int(
            expected_base
        ) != live_kernel_base:
            blocks.append(
                "stale kernel base in plan: expected "
                f"0x{int(expected_base):016x}, live 0x{live_kernel_base:016x}"
            )

        classifications: dict[int, str] = {}

        for op in plan.reads:
            cls = self.classify(op.address)
            classifications[op.address] = cls.value
            if op.length > self.max_read:
                blocks.append(
                    f"read of 0x{op.length:x} bytes at 0x{op.address:x} exceeds max_read "
                    f"0x{self.max_read:x}"
                )
            if cls is AddressClass.MMIO and not self.allow_mmio_read:
                blocks.append(f"MMIO read at 0x{op.address:x} is not classified safe")
            elif cls.value not in self.allowed_read_classes:
                blocks.append(f"read class {cls.value} at 0x{op.address:x} is not allowed")
            if op.address_class != "UNKNOWN" and op.address_class != cls.value:
                blocks.append(
                    f"declared read class {op.address_class} contradicts classification {cls.value} "
                    f"at 0x{op.address:x}"
                )

        for op in plan.writes:
            cls = self.classify(op.address)
            classifications[op.address] = cls.value
            if cls.value not in self.allowed_write_classes:
                blocks.append(
                    f"write class {cls.value} at 0x{op.address:x} is not allowed for {self.level}"
                )
            if op.length > self.max_write:
                blocks.append(
                    f"write of 0x{op.length:x} bytes at 0x{op.address:x} exceeds max_write "
                    f"0x{self.max_write:x}"
                )
            if not plan.restore_steps.complete:
                blocks.append("mutating plan without complete restore steps")

        if plan.mutating and self.level == PolicyLevel.LIVE0_R.value:
            blocks.append("LIVE0-R is read-only; mutating plan refused")

        if not blocks:
            reasons.append(
                f"{len(plan.reads)} read(s), {len(plan.writes)} write(s) allowed under {self.level}"
            )

        return PolicyDecision(
            allowed=not blocks,
            blocks=tuple(blocks),
            reasons=tuple(reasons),
            classifications=classifications,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "level": self.level,
            "allowed_write_classes": sorted(self.allowed_write_classes),
            "allowed_read_classes": sorted(self.allowed_read_classes),
            "max_read": self.max_read,
            "max_write": self.max_write,
            "max_pointer_depth": self.max_pointer_depth,
            "allow_mmio_read": self.allow_mmio_read,
            "hard_block_sinks": sorted(HARD_BLOCK_SINKS),
        }
