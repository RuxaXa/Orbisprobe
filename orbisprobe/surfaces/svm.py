from __future__ import annotations

from orbisprobe.analysis.binary import BinaryImage
from orbisprobe.analysis.dataflow import normalize_register

from .graph import GraphNode, NodeType, ResearchGraph
from .model import (
    BoundaryType,
    Confidence,
    Evidence,
    SurfaceFinding,
    SurfaceStatus,
    SurfaceType,
)
from .ranking import RankingFactors, rank_candidate
from .scanner import TrackScanResult

SVM_OPCODES = {
    "vmrun": bytes.fromhex("0f01d8"),
    "vmmcall": bytes.fromhex("0f01d9"),
    "vmload": bytes.fromhex("0f01da"),
    "vmsave": bytes.fromhex("0f01db"),
    "stgi": bytes.fromhex("0f01dc"),
    "clgi": bytes.fromhex("0f01dd"),
    "skinit": bytes.fromhex("0f01de"),
    "invlpga": bytes.fromhex("0f01df"),
}
SVM_MSRS = {
    0xC0000080: "EFER",
    0xC0010114: "VM_CR",
    0xC0010115: "IGNNE",
    0xC0010116: "SMM_CTL",
    0xC0010117: "VM_HSAVE_PA",
    0xC0010118: "SVM_LOCK_KEY",
    0xC0010119: "SVM_KEY_MSR",
}
def scan_svm(image: BinaryImage) -> TrackScanResult:
    evidence: list[Evidence] = []
    seen: set[tuple[str, int, str]] = set()
    svm_instruction_addresses: list[int] = []
    msr_names: set[str] = set()
    initialization_addresses: list[int] = []
    for expected_mnemonic, opcode in SVM_OPCODES.items():
        for address in image.find_bytes(opcode, max_hits=4096):
            instruction = image.decode_one(address)
            if instruction is None or instruction.mnemonic.lower() != expected_mnemonic:
                continue
            mnemonic = instruction.mnemonic.lower()
            svm_instruction_addresses.append(instruction.address)
            key = ("svm_instruction", instruction.address, mnemonic)
            if key not in seen:
                seen.add(key)
                evidence.append(
                    Evidence(
                        kind="svm_instruction",
                        address=instruction.address,
                        detail=f"decoded privileged instruction {mnemonic}",
                        raw={"mnemonic": mnemonic, "op_str": instruction.op_str},
                    )
                )

    image_end = image.base + image.size
    try:
        from capstone import CS_OP_IMM, CS_OP_REG
    except ImportError as exc:
        raise RuntimeError("SVM scanning requires capstone") from exc
    for msr, msr_name in SVM_MSRS.items():
        for move in image.find_mov_immediate(msr, max_hits=4096):
            window_end = min(image_end, move.address + 64)
            window = list(image.disassemble(start=move.address, end=window_end))
            rdmsr_positions: list[int] = []
            svme_or_positions: list[int] = []
            wrmsr_positions: list[int] = []
            for position, instruction in enumerate(window):
                mnemonic = instruction.mnemonic.lower()
                if mnemonic == ".byte":
                    break
                if mnemonic.startswith("ret"):
                    break
                if position > 0:
                    if mnemonic == "call":
                        break
                    _read_ids, write_ids = instruction.regs_access()
                    if any(
                        normalize_register(instruction.reg_name(register)) == "rcx"
                        for register in write_ids
                    ):
                        break
                if mnemonic not in {"rdmsr", "wrmsr"}:
                    if (
                        mnemonic == "or"
                        and len(instruction.operands) >= 2
                        and instruction.operands[0].type == CS_OP_REG
                        and normalize_register(instruction.reg_name(instruction.operands[0].reg)) == "rax"
                        and any(
                            operand.type == CS_OP_IMM and operand.imm == 0x1000
                            for operand in instruction.operands[1:]
                        )
                    ):
                        svme_or_positions.append(position)
                    continue
                if mnemonic == "rdmsr":
                    rdmsr_positions.append(position)
                else:
                    wrmsr_positions.append(position)
                    if msr_name == "VM_HSAVE_PA":
                        initialization_addresses.append(instruction.address)
                msr_names.add(msr_name)
                key = ("svm_msr", instruction.address, f"{msr_name}:{mnemonic}")
                if key not in seen:
                    seen.add(key)
                    evidence.append(
                        Evidence(
                            kind="svm_msr",
                            address=instruction.address,
                            detail=f"{mnemonic} with decoded ECX MSR {msr_name}",
                            raw={"mnemonic": mnemonic, "msr": msr, "msr_name": msr_name},
                        )
                    )
            if msr_name == "EFER" and any(
                read < bit_set < write
                for read in rdmsr_positions
                for bit_set in svme_or_positions
                for write in wrmsr_positions
            ):
                initialization_addresses.extend(
                    window[write].address
                    for write in wrmsr_positions
                    if any(
                        read < bit_set < write
                        for read in rdmsr_positions
                        for bit_set in svme_or_positions
                    )
                )

    control_instructions = image.find_mov_immediate(0x1000, max_hits=4096)
    for address in image.find_bytes(bytes.fromhex("0d00100000"), max_hits=4096):
        instruction = image.decode_one(address)
        if instruction is not None and instruction.mnemonic == "or":
            control_instructions.append(instruction)
    svm_anchor_addresses = [*svm_instruction_addresses, *[item.address for item in evidence if item.address]]
    local_control_instructions = [
        instruction
        for instruction in control_instructions
        if any(abs(instruction.address - anchor) <= 0x200 for anchor in svm_anchor_addresses)
    ]
    control_hint = bool(local_control_instructions)

    if not svm_instruction_addresses and not msr_names:
        return TrackScanResult(track="svm", classification="SVM-NONE")

    local_initialization = any(
        abs(instruction_address - initialization_address) <= 0x400
        for instruction_address in svm_instruction_addresses
        for initialization_address in initialization_addresses
    )
    if svm_instruction_addresses and local_initialization:
        classification = "SVM-INITIALIZED"
        confidence = Confidence.MEDIUM
        status = SurfaceStatus.INFERRED
        unknowns = ["active runtime role", "VMCB provenance", "caller reachability"]
    else:
        classification = "SVM-CAPABILITY-ONLY"
        confidence = Confidence.LOW
        status = SurfaceStatus.SUPPORTED
        unknowns = ["initialization", "control structure", "caller", "runtime role"]
        if "EFER" in msr_names and not initialization_addresses:
            unknowns.append("EFER.SVME initialization sequence")

    if control_hint:
        evidence.append(
            Evidence(
                kind="control_structure_hint",
                address=local_control_instructions[0].address,
                detail="decoded 0x1000 immediate near SVM-related code; VMCB identity not proven",
                raw={"size": 0x1000},
            )
        )
    else:
        unknowns.append("4-KB control-structure evidence")

    first_address = svm_instruction_addresses[0] if svm_instruction_addresses else evidence[0].address
    function_address = image.heuristic_function_start(first_address) if first_address is not None else None
    if function_address is None:
        function_address = first_address
    function = f"sub_{function_address:x}" if function_address is not None else None
    priority, score = rank_candidate(
        RankingFactors(
            controllability=0.0,
            validation_gap=0.1,
            privilege_distance=0.9,
            consumer_confidence=0.45 if classification == "SVM-INITIALIZED" else 0.2,
            observable_quality=0.2,
            reproducibility=0.9,
        )
    )
    surface = SurfaceFinding.create(
        surface_type=SurfaceType.SVM_HV,
        binary=str(image.path),
        binary_sha256=image.sha256,
        architecture=image.architecture,
        function=function,
        address=first_address,
        source=["decoded instruction/MSR evidence from immutable binary"],
        validation=["Capstone x86-64 instruction-boundary decoding", "VA-domain addresses use supplied base"],
        boundary=BoundaryType.CPU_PRIVILEGE,
        consumer=["privileged SVM execution context not fully reconstructed"],
        observable=["offline instruction and MSR access evidence"],
        confidence=confidence,
        evidence=evidence,
        unknowns=sorted(set(unknowns)),
        status=status,
        boundary_type="CPU virtualization privilege boundary",
        candidate_priority=priority.value,
        candidate_score=score,
        open_chains=["instruction -> initialization -> VMCB -> caller -> runtime consumer"],
        classification=classification,
    )
    graph = ResearchGraph()
    function_id = f"function:{function or 'unknown'}"
    endpoint_id = "hardware:amd-svm"
    graph.add_node(GraphNode(function_id, NodeType.FUNCTION, {"address": function_address}))
    graph.add_node(GraphNode(endpoint_id, NodeType.HARDWARE_ENDPOINT, {"class": "SVM"}))
    return TrackScanResult(
        track="svm",
        classification=classification,
        surfaces=[surface],
        graph=graph,
    )
