from __future__ import annotations

from orbisprobe.analysis.binary import BinaryImage
from orbisprobe.analysis.dataflow import normalize_register

from .graph import EdgeType, GraphEdge, GraphNode, NodeType, ResearchGraph
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

PCI_CONFIG_PORTS = {0xCF8: "CONFIG_ADDRESS", 0xCFC: "CONFIG_DATA"}
MEMORY_MAP_MSRS = {
    0xC0010010: "SYSCFG",
    0xC001001A: "TOP_MEM",
    0xC001001D: "TOP_MEM2",
}


def scan_memctl(image: BinaryImage) -> TrackScanResult:
    evidence: list[Evidence] = []
    categories: set[str] = set()
    image_end = image.base + image.size

    for port, port_name in PCI_CONFIG_PORTS.items():
        for move in image.find_mov_immediate(port, max_hits=4096):
            destination = move.reg_name(move.operands[0].reg)
            if destination not in {"edx", "rdx", "dx"}:
                continue
            categories.add("pci_port")
            evidence.append(
                Evidence(
                    kind="pci_config_port",
                    address=move.address,
                    detail=f"decoded PCI config port {port_name} 0x{port:x}",
                    raw={"port": port},
                )
            )
            window_end = min(image_end, move.address + 24)
            for position, instruction in enumerate(image.disassemble(start=move.address, end=window_end)):
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
                        normalize_register(instruction.reg_name(register)) == "rdx"
                        for register in write_ids
                    ):
                        break
                if mnemonic in {"in", "insb", "insd", "insw"}:
                    categories.add("config_read")
                    evidence.append(
                        Evidence(
                            kind="config_read",
                            address=instruction.address,
                            detail=f"PCI config read through port 0x{port:x}",
                            raw={"port": port, "instruction": mnemonic},
                        )
                    )
                    break
                if mnemonic in {"out", "outsb", "outsd", "outsw"}:
                    categories.add("config_write")
                    evidence.append(
                        Evidence(
                            kind="config_write",
                            address=instruction.address,
                            detail=f"PCI config write through port 0x{port:x}",
                            raw={"port": port, "instruction": mnemonic},
                        )
                    )
                    break

    for msr, msr_name in MEMORY_MAP_MSRS.items():
        for move in image.find_mov_immediate(msr, max_hits=4096):
            destination = move.reg_name(move.operands[0].reg)
            if destination not in {"ecx", "rcx"}:
                continue
            window_end = min(image_end, move.address + 32)
            for position, instruction in enumerate(image.disassemble(start=move.address, end=window_end)):
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
                    continue
                categories.add("address_map")
                evidence.append(
                    Evidence(
                        kind="address_map_msr",
                        address=instruction.address,
                        detail=f"{mnemonic} for {msr_name}",
                        raw={"msr": msr, "name": msr_name},
                    )
                )
                break

    if len(categories) < 2:
        diagnostics = []
        if categories:
            diagnostics.append("memory-controller anchor found without independent boundary evidence")
        return TrackScanResult(track="memctl", classification="MEMCTL-NONE", diagnostics=diagnostics)

    classification = (
        "MEMCTL-ADDRESS-MAP-CANDIDATE"
        if "address_map" in categories
        else "MEMCTL-CONFIG-CANDIDATE"
    )
    first_address = min(item.address for item in evidence if item.address is not None)
    function_address = image.heuristic_function_start(first_address) or first_address
    function = f"sub_{function_address:x}"
    priority, score = rank_candidate(
        RankingFactors(
            controllability=0.05,
            validation_gap=0.15,
            privilege_distance=0.9,
            consumer_confidence=0.35,
            observable_quality=0.25,
            reproducibility=0.9,
            persistent_risk=0.8,
        )
    )
    surface = SurfaceFinding.create(
        surface_type=SurfaceType.MEMORY_CONTROLLER,
        binary=str(image.path),
        binary_sha256=image.sha256,
        architecture=image.architecture,
        function=function,
        address=first_address,
        source=["decoded PCI-config and Family-16h MSR instruction anchors"],
        validation=["instruction-boundary immediate extraction", "multiple evidence categories required"],
        boundary=BoundaryType.MEMORY_MAP,
        consumer=["memory-controller/northbridge consumer not reconstructed"],
        observable=["offline config access and address-map register evidence"],
        confidence=Confidence.LOW,
        evidence=evidence,
        unknowns=[
            "register semantics on target silicon",
            "runtime reachability",
            "lock/protection state",
            "effective address translation",
        ],
        status=SurfaceStatus.UNKNOWN,
        boundary_type="CPU to memory-controller configuration boundary",
        candidate_priority=priority.value,
        candidate_score=score,
        open_chains=["config source -> register selection -> address map -> protection boundary -> consumer"],
        classification=classification,
    )
    graph = ResearchGraph()
    function_id = f"function:{function}"
    object_id = f"object:memctl:{surface.surface_id}"
    endpoint_id = "hardware:memory-controller"
    graph.add_node(GraphNode(function_id, NodeType.FUNCTION, {"address": function_address}))
    graph.add_node(GraphNode(object_id, NodeType.OBJECT, {"classification": classification}))
    graph.add_node(GraphNode(endpoint_id, NodeType.HARDWARE_ENDPOINT, {"class": "MEMCTL"}))
    graph.add_edge(GraphEdge(function_id, object_id, EdgeType.WRITES))
    graph.add_edge(GraphEdge(object_id, endpoint_id, EdgeType.CONSUMES))
    return TrackScanResult(
        track="memctl",
        classification=classification,
        surfaces=[surface],
        graph=graph,
    )
