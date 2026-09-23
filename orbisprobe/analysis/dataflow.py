from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

from .binary import BinaryImage

CALLER_SAVED = {"rax", "rcx", "rdx", "rsi", "rdi", "r8", "r9", "r10", "r11"}
CALLEE_SAVED = {"rbx", "rbp", "r12", "r13", "r14", "r15"}

_REGISTER_ALIASES = {
    "al": "rax", "ah": "rax", "ax": "rax", "eax": "rax", "rax": "rax",
    "bl": "rbx", "bh": "rbx", "bx": "rbx", "ebx": "rbx", "rbx": "rbx",
    "cl": "rcx", "ch": "rcx", "cx": "rcx", "ecx": "rcx", "rcx": "rcx",
    "dl": "rdx", "dh": "rdx", "dx": "rdx", "edx": "rdx", "rdx": "rdx",
    "sil": "rsi", "si": "rsi", "esi": "rsi", "rsi": "rsi",
    "dil": "rdi", "di": "rdi", "edi": "rdi", "rdi": "rdi",
    "bpl": "rbp", "bp": "rbp", "ebp": "rbp", "rbp": "rbp",
    "spl": "rsp", "sp": "rsp", "esp": "rsp", "rsp": "rsp",
}
for _number in range(8, 16):
    for _suffix in ("b", "w", "d", ""):
        _REGISTER_ALIASES[f"r{_number}{_suffix}"] = f"r{_number}"


def normalize_register(name: str) -> str:
    return _REGISTER_ALIASES.get(name.lower(), name.lower())


@dataclass(frozen=True)
class SourceSpec:
    register: str | None = None
    definition_address: int | None = None
    memory_base: str | None = None
    memory_displacement: int | None = None


@dataclass(frozen=True)
class DataflowEvent:
    address: int
    instruction: str
    event: str
    register: str | None
    detail: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class DataflowResult:
    function: int
    end: int
    source: SourceSpec
    events: list[DataflowEvent] = field(default_factory=list)
    call_clobber_complete: bool = True
    control_flow_complete: bool = True
    unknowns: list[str] = field(default_factory=list)

    @property
    def proof_complete(self) -> bool:
        return self.call_clobber_complete and self.control_flow_complete and not self.unknowns

    def to_dict(self) -> dict[str, Any]:
        return {
            "function": self.function,
            "end": self.end,
            "source": asdict(self.source),
            "events": [event.to_dict() for event in self.events],
            "call_clobber_complete": self.call_clobber_complete,
            "control_flow_complete": self.control_flow_complete,
            "proof_complete": self.proof_complete,
            "unknowns": list(self.unknowns),
        }


class DataflowAnalyzer:
    def __init__(self, image: BinaryImage):
        self.image = image

    def analyze(
        self,
        *,
        function: int,
        end: int,
        source: SourceSpec,
        consumer: int | None = None,
    ) -> DataflowResult:
        instructions = list(self.image.disassemble(start=function, end=end))
        result = DataflowResult(function=function, end=end, source=source)
        tracked: dict[str, str] = {}
        if source.register is not None and source.definition_address is None:
            tracked[normalize_register(source.register)] = "declared source"

        try:
            from capstone import CS_OP_MEM, CS_OP_REG
        except ImportError as exc:
            raise RuntimeError("dataflow analysis requires capstone") from exc

        for instruction in instructions:
            if instruction.mnemonic == ".byte":
                continue
            text = f"{instruction.mnemonic} {instruction.op_str}".strip()
            propagated_destinations: set[str] = set()

            if (
                source.register is not None
                and source.definition_address == instruction.address
            ):
                register = normalize_register(source.register)
                tracked[register] = "declared source"
                result.events.append(
                    DataflowEvent(instruction.address, text, "definition", register, "explicit source definition")
                )

            if source.memory_base is not None:
                for operand_index, operand in enumerate(instruction.operands):
                    if operand.type != CS_OP_MEM:
                        continue
                    base_name = instruction.reg_name(operand.mem.base) if operand.mem.base else ""
                    if (
                        normalize_register(base_name) == normalize_register(source.memory_base)
                        and operand.mem.disp == source.memory_displacement
                        and operand_index > 0
                        and instruction.operands[0].type == CS_OP_REG
                    ):
                        destination = normalize_register(instruction.reg_name(instruction.operands[0].reg))
                        tracked[destination] = f"memory {source.memory_base}{source.memory_displacement:+#x}"
                        propagated_destinations.add(destination)
                        result.events.append(
                            DataflowEvent(
                                instruction.address,
                                text,
                                "definition",
                                destination,
                                "memory-field source loaded",
                            )
                        )

            read_ids, write_ids = instruction.regs_access()
            read_registers = {normalize_register(instruction.reg_name(reg_id)) for reg_id in read_ids}
            write_registers = {normalize_register(instruction.reg_name(reg_id)) for reg_id in write_ids}
            for register in sorted(read_registers & tracked.keys()):
                result.events.append(
                    DataflowEvent(
                        instruction.address,
                        text,
                        "consumer" if instruction.address == consumer or consumer is None else "use",
                        register,
                        "tracked value read",
                    )
                )

            if (
                instruction.mnemonic in {"mov", "movzx", "movsx", "movsxd", "lea"}
                and len(instruction.operands) >= 2
                and instruction.operands[0].type == CS_OP_REG
                and instruction.operands[1].type == CS_OP_REG
            ):
                source_register = normalize_register(instruction.reg_name(instruction.operands[1].reg))
                if source_register in tracked:
                    destination = normalize_register(instruction.reg_name(instruction.operands[0].reg))
                    tracked[destination] = tracked[source_register]
                    propagated_destinations.add(destination)
                    result.events.append(
                        DataflowEvent(
                            instruction.address,
                            text,
                            "propagation",
                            destination,
                            f"copied from {source_register}",
                        )
                    )

            if instruction.mnemonic == "call":
                for register in sorted(set(tracked) & CALLER_SAVED):
                    result.events.append(
                        DataflowEvent(
                            instruction.address,
                            text,
                            "call_clobber",
                            register,
                            "SysV caller-saved register invalidated",
                        )
                    )
                    tracked.pop(register, None)

            for register in sorted(write_registers & tracked.keys()):
                if register in propagated_destinations:
                    continue
                result.events.append(
                    DataflowEvent(
                        instruction.address,
                        text,
                        "overwrite",
                        register,
                        "tracked value overwritten",
                    )
                )
                tracked.pop(register, None)

            if instruction.mnemonic.startswith("j") and instruction.mnemonic != "jmp":
                result.events.append(
                    DataflowEvent(
                        instruction.address,
                        text,
                        "merge",
                        None,
                        "conditional control-flow merge requires CFG proof",
                    )
                )
                result.control_flow_complete = False
                if "conditional branch merge not reconstructed" not in result.unknowns:
                    result.unknowns.append("conditional branch merge not reconstructed")

        return result
