from __future__ import annotations

from orbisprobe.analysis.binary import BinaryImage

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

STRING_ANCHORS: dict[str, list[bytes]] = {
    "mapping": [b"gpuvm_map", b"unmap", b"iova", b"gpuva"],
    "dma": [b"dmac", b"dma copy", b"dma"],
    "device_table": [b"device table", b"devtable", b"domain"],
    "ring": [b"doorbell", b"command ring", b"event ring"],
    "invalidation": [b"invalidate", b"invalidation"],
}
RESEARCH_CONSTANTS = {
    0xA70: "known selector/field anchor 0xa70",
    0xC0000000: "shared DDR/APU aperture anchor 0xc0000000",
    0x61: "known GPUVM mapping-flag anchor 0x61",
}


def _balanced_evidence(items: list[Evidence], limit: int = 64) -> list[Evidence]:
    by_kind: dict[str, list[Evidence]] = {}
    for item in items:
        by_kind.setdefault(item.kind, []).append(item)
    selected: list[Evidence] = []
    index = 0
    kinds = sorted(by_kind)
    while len(selected) < limit:
        added = False
        for kind in kinds:
            if index < len(by_kind[kind]):
                selected.append(by_kind[kind][index])
                added = True
                if len(selected) == limit:
                    break
        if not added:
            break
        index += 1
    return selected


def scan_iommu(image: BinaryImage) -> TrackScanResult:
    evidence: list[Evidence] = []
    categories: set[str] = set()
    for category, needles in STRING_ANCHORS.items():
        for address, needle in image.find_ascii(needles):
            categories.add(f"string:{category}")
            evidence.append(
                Evidence(
                    kind="string_anchor",
                    address=address,
                    detail=f"decoded ASCII anchor {needle.decode(errors='replace')}",
                    raw={"category": category, "needle": needle.decode(errors="replace")},
                )
            )

    try:
        from capstone import CS_AC_WRITE, CS_OP_MEM
    except ImportError as exc:
        raise RuntimeError("IOMMU scanning requires capstone") from exc
    constant_addresses: list[int] = []
    descriptor_recorded = False
    image_end = image.base + image.size
    for immediate, detail in RESEARCH_CONSTANTS.items():
        for move in image.find_mov_immediate(immediate, max_hits=4096):
            categories.add("research_constant")
            constant_addresses.append(move.address)
            evidence.append(
                Evidence(
                    kind="research_constant",
                    address=move.address,
                    detail=detail,
                    raw={"value": immediate, "instruction": f"{move.mnemonic} {move.op_str}"},
                )
            )
            window_start = move.address + move.size
            if window_start >= image_end:
                continue
            window_end = min(image_end, window_start + 0x80)
            for instruction in image.disassemble(start=window_start, end=window_end):
                if instruction.mnemonic == ".byte":
                    continue
                if instruction.mnemonic.startswith("ret"):
                    break
                if (
                    instruction.operands
                    and instruction.operands[0].type == CS_OP_MEM
                    and instruction.operands[0].access & CS_AC_WRITE
                ):
                    if not descriptor_recorded:
                        categories.add("descriptor_write")
                        evidence.append(
                            Evidence(
                                kind="descriptor_write",
                                address=instruction.address,
                                detail=(
                                    "memory write near IOMMU/DMA research constant; "
                                    "descriptor semantics unproven"
                                ),
                                raw={"instruction": f"{instruction.mnemonic} {instruction.op_str}"},
                            )
                        )
                        descriptor_recorded = True
                    break

    for instruction in image.find_memory_displacement(0xA70, max_hits=4096):
        categories.add("research_constant")
        constant_addresses.append(instruction.address)
        evidence.append(
            Evidence(
                kind="research_constant",
                address=instruction.address,
                detail="decoded +0xa70 structure-field displacement",
                raw={
                    "value": 0xA70,
                    "role": "STRUCT_FIELD_DISPLACEMENT",
                    "instruction": f"{instruction.mnemonic} {instruction.op_str}",
                },
            )
        )

    independent_groups = {
        "strings" if item.startswith("string:") else item
        for item in categories
    }
    string_category_count = sum(1 for item in categories if item.startswith("string:"))
    sufficient = (
        len(independent_groups) >= 3
        or (string_category_count >= 2 and "research_constant" in categories)
    )
    if not sufficient:
        diagnostics = []
        if categories:
            diagnostics.append(
                "IOMMU/DMA anchors found but insufficient independent evidence; pattern-only hits were not promoted"
            )
        return TrackScanResult(track="iommu", classification="IOMMU-NONE", diagnostics=diagnostics)

    first_address = min(constant_addresses)
    function_address = image.heuristic_function_start(first_address)
    if function_address is None:
        function_address = first_address
    function = f"sub_{function_address:x}" if function_address is not None else None
    priority, score = rank_candidate(
        RankingFactors(
            controllability=0.15,
            validation_gap=0.25,
            privilege_distance=0.9,
            consumer_confidence=0.3,
            observable_quality=0.35,
            reproducibility=0.9,
        )
    )
    open_chains = [
        "source -> mapping validation -> translation -> descriptor -> hardware consumer",
        "map(A) -> validate(A) -> use(A) -> unmap/remap -> stale consumer",
        "mapping length -> DMA length differential",
        "validated aligned base -> later offset -> remaining extent",
        "validated device/domain X -> consumer device/domain Y",
        "table update -> invalidation -> stale translation",
        "request A creates state -> request B consumes without equivalent validation",
    ]
    surface = SurfaceFinding.create(
        surface_type=SurfaceType.IOMMU_DMA,
        binary=str(image.path),
        binary_sha256=image.sha256,
        architecture=image.architecture,
        function=function,
        address=first_address,
        source=["offline string/immediate/descriptor structural anchors"],
        validation=["instruction-boundary immediate extraction", "multiple evidence-category promotion gate"],
        boundary=BoundaryType.DMA_TRANSLATION,
        consumer=["DMA/IOMMU hardware consumer not reconstructed"],
        observable=["offline mapping, descriptor, and ring anchors"],
        confidence=Confidence.LOW,
        evidence=_balanced_evidence(evidence),
        unknowns=[
            "controlled source not established",
            "mapping validation not reconstructed",
            "translation root and device/domain identity unknown",
            "hardware consumer not reconstructed",
            "runtime reachability unknown",
        ],
        status=SurfaceStatus.UNKNOWN,
        boundary_type="IOMMU/DMA translation boundary candidate",
        candidate_priority=priority.value,
        candidate_score=score,
        open_chains=open_chains,
        classification="IOMMU-STRUCTURAL-CANDIDATE",
    )

    graph = ResearchGraph()
    function_id = f"function:{function or 'unknown'}"
    mapping_id = f"mapping:{surface.surface_id}"
    descriptor_id = f"descriptor:{surface.surface_id}"
    endpoint_id = "hardware:dma-iommu"
    graph.add_node(GraphNode(function_id, NodeType.FUNCTION, {"address": function_address}))
    graph.add_node(GraphNode(mapping_id, NodeType.MAPPING, {"validated": False}))
    graph.add_node(GraphNode(descriptor_id, NodeType.DESCRIPTOR, {"address_bearing": True}))
    graph.add_node(GraphNode(endpoint_id, NodeType.HARDWARE_ENDPOINT, {"class": "DMA/IOMMU"}))
    graph.add_edge(GraphEdge(function_id, mapping_id, EdgeType.MAPS))
    graph.add_edge(GraphEdge(mapping_id, descriptor_id, EdgeType.WRITES))
    graph.add_edge(GraphEdge(descriptor_id, endpoint_id, EdgeType.SUBMITS))
    return TrackScanResult(
        track="iommu",
        classification="IOMMU-STRUCTURAL-CANDIDATE",
        surfaces=[surface],
        graph=graph,
    )
