from __future__ import annotations

from collections import defaultdict
from typing import Any

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

KNOWN_TAGS = {7, 8, 9}
FIXED_MESSAGE_SIZES = {0x30: "request", 0x54: "response"}
CLASSIFICATION_ORDER = {
    "HOST-ONLY-CHAIN": 1,
    "SECURE-PARSER-CANDIDATE": 2,
    "CROSS-PROCESSOR-CANDIDATE": 3,
}


def _immediates(instruction: Any) -> list[int]:
    try:
        from capstone import CS_OP_IMM
    except ImportError as exc:
        raise RuntimeError("secure-surface scanning requires capstone") from exc
    return [operand.imm & 0xFFFFFFFFFFFFFFFF for operand in instruction.operands if operand.type == CS_OP_IMM]


def _balanced_evidence(items: list[Evidence], limit: int = 64) -> list[Evidence]:
    by_kind: dict[str, list[Evidence]] = {}
    for item in items:
        by_kind.setdefault(item.kind, []).append(item)
    selected: list[Evidence] = []
    index = 0
    while len(selected) < limit:
        added = False
        for kind in sorted(by_kind):
            if index < len(by_kind[kind]):
                selected.append(by_kind[kind][index])
                added = True
                if len(selected) == limit:
                    break
        if not added:
            break
        index += 1
    return selected


def _scan_window(
    image: BinaryImage,
    start: int,
    end: int,
    descriptor_addresses: list[int],
) -> dict[str, Any] | None:
    try:
        from capstone import CS_OP_MEM
    except ImportError as exc:
        raise RuntimeError("secure-surface scanning requires capstone") from exc

    tag_hits: list[tuple[int, int]] = []
    address_hits: list[int] = []
    op_hits: list[int] = []
    size_hits: list[tuple[int, int]] = []
    memory_reads: dict[tuple[str, int], list[int]] = defaultdict(list)
    call_addresses: list[int] = []
    for instruction in image.disassemble(start=start, end=end):
        if instruction.mnemonic == ".byte":
            continue
        mnemonic = instruction.mnemonic.lower()
        if mnemonic.startswith("ret"):
            break
        immediates = _immediates(instruction)
        if mnemonic == "cmp":
            for immediate in immediates:
                if immediate in KNOWN_TAGS:
                    tag_hits.append((instruction.address, immediate))
                if immediate in FIXED_MESSAGE_SIZES:
                    size_hits.append((instruction.address, immediate))
        if mnemonic == "call":
            call_addresses.append(instruction.address)
        for operand in instruction.operands:
            if operand.type != CS_OP_MEM:
                continue
            base = instruction.reg_name(operand.mem.base) if operand.mem.base else ""
            displacement = operand.mem.disp
            if displacement == 8:
                address_hits.append(instruction.address)
            if displacement == 0x10:
                op_hits.append(instruction.address)
            memory_reads[(base, displacement)].append(instruction.address)

    field_bases = {
        base
        for base, _displacement in memory_reads
        if base and (base, 8) in memory_reads and (base, 0x10) in memory_reads
    }
    address_hits = [
        address
        for base in field_bases
        for address in memory_reads[(base, 8)]
    ]
    op_hits = [
        address
        for base in field_bases
        for address in memory_reads[(base, 0x10)]
    ]
    fingerprint = (
        bool(descriptor_addresses)
        and KNOWN_TAGS.issubset({tag for _address, tag in tag_hits})
        and bool(field_bases)
    )
    if not fingerprint:
        return None

    evidence: list[Evidence] = []
    for address in descriptor_addresses[:8]:
        evidence.append(
            Evidence(
                kind="descriptor_size",
                address=address,
                detail="decoded 0x80 descriptor copy/stride immediate",
                raw={"size": 0x80},
            )
        )
    for address, tag in tag_hits[:16]:
        evidence.append(
            Evidence(
                kind="tag_compare",
                address=address,
                detail=f"small descriptor tag comparison: {tag}",
                raw={"tag": tag},
            )
        )
    for address in address_hits[:8]:
        evidence.append(
            Evidence(
                kind="address_field",
                address=address,
                detail="qword-like memory field at descriptor offset +8",
                raw={"offset": 8},
            )
        )
    for address in op_hits[:8]:
        evidence.append(
            Evidence(
                kind="op_field",
                address=address,
                detail="word/dword-like memory field at descriptor offset +0x10",
                raw={"offset": 0x10},
            )
        )
    for address, size in size_hits[:8]:
        evidence.append(
            Evidence(
                kind="fixed_message_size",
                address=address,
                detail=f"fixed {FIXED_MESSAGE_SIZES[size]} size 0x{size:x}",
                raw={"size": size, "role": FIXED_MESSAGE_SIZES[size]},
            )
        )

    repeated_with_call = False
    for base in sorted({base for base, _displacement in memory_reads if base}):
        offsets = (0x28, 0x30, 0x38)
        reads_by_offset = {
            displacement: sorted(set(memory_reads.get((base, displacement), [])))
            for displacement in offsets
        }
        if not all(len(addresses) >= 2 for addresses in reads_by_offset.values()):
            continue
        first_read = min(addresses[0] for addresses in reads_by_offset.values())
        last_read = max(addresses[-1] for addresses in reads_by_offset.values())
        if not any(first_read < call < last_read for call in call_addresses):
            continue
        repeated_with_call = True
        for displacement, addresses in reads_by_offset.items():
            evidence.append(
                Evidence(
                    kind="repeated_mutable_read",
                    address=addresses[0],
                    detail=f"field [{base}+0x{displacement:x}] reread across a call",
                    raw={"base": base, "offset": displacement, "reads": addresses},
                )
            )

    if repeated_with_call:
        classification = "CROSS-PROCESSOR-CANDIDATE"
        status = SurfaceStatus.SUPPORTED
        confidence = Confidence.MEDIUM
    elif len(size_hits) >= 2:
        classification = "SECURE-PARSER-CANDIDATE"
        status = SurfaceStatus.INFERRED
        confidence = Confidence.LOW
    else:
        classification = "HOST-ONLY-CHAIN"
        status = SurfaceStatus.INFERRED
        confidence = Confidence.LOW
    return {
        "classification": classification,
        "status": status,
        "confidence": confidence,
        "evidence": _balanced_evidence(evidence),
        "repeated": repeated_with_call,
    }


def scan_secure(image: BinaryImage) -> TrackScanResult:
    descriptor_moves = image.find_mov_immediate(0x80, max_hits=4096)
    image_end = image.base + image.size
    windows: dict[int, tuple[int, list[int]]] = {}
    for descriptor in descriptor_moves[:512]:
        start = image.heuristic_function_start(descriptor.address) or descriptor.address
        end = min(image_end, start + 0x1000)
        existing = windows.get(start)
        if existing is None:
            windows[start] = (end, [descriptor.address])
        else:
            existing[1].append(descriptor.address)

    surfaces: list[SurfaceFinding] = []
    graph = ResearchGraph()
    classifications: list[str] = []
    for start in sorted(windows):
        end, descriptor_addresses = windows[start]
        match = _scan_window(image, start, end, descriptor_addresses)
        if match is None:
            continue
        classification = match["classification"]
        classifications.append(classification)
        evidence = match["evidence"]
        first_address = min(item.address for item in evidence if item.address is not None)
        function = f"sub_{start:x}"
        repeated = bool(match["repeated"])
        priority, score = rank_candidate(
            RankingFactors(
                controllability=0.7 if repeated else 0.3,
                validation_gap=0.7 if repeated else 0.3,
                privilege_distance=0.9,
                consumer_confidence=0.55 if classification != "HOST-ONLY-CHAIN" else 0.25,
                observable_quality=0.2,
                reproducibility=0.9,
                cross_processor=classification != "HOST-ONLY-CHAIN",
            )
        )
        surface = SurfaceFinding.create(
            surface_type=SurfaceType.SAMU_SECURE,
            binary=str(image.path),
            binary_sha256=image.sha256,
            architecture=image.architecture,
            function=function,
            address=first_address,
            source=["host-side descriptor construction and repeated-read evidence"],
            validation=[
                "0x80/tag/+8/+0x10 structural fingerprint within one bounded function window",
                "instruction-boundary decoding",
            ],
            boundary=BoundaryType.CROSS_PROCESSOR,
            consumer=["secure-side descriptor consumer candidate"],
            observable=["host descriptor construction", "host repeated-read sequence"],
            confidence=match["confidence"],
            evidence=evidence,
            unknowns=[
                "secure consumer semantics unknown",
                "secure-side address validation unknown",
                "runtime effect and oracle unknown",
            ],
            status=match["status"],
            boundary_type="Host to SAMU/SBL cross-processor descriptor boundary",
            candidate_priority=priority.value,
            candidate_score=score,
            open_chains=[
                "controlled source -> host validation -> descriptor -> secure consumer -> observable effect"
            ],
            classification=classification,
        )
        surfaces.append(surface)
        function_id = f"function:{function}"
        descriptor_id = f"descriptor:{surface.surface_id}"
        endpoint_id = "hardware:samu-secure"
        graph.add_node(GraphNode(function_id, NodeType.FUNCTION, {"address": start}))
        graph.add_node(GraphNode(descriptor_id, NodeType.DESCRIPTOR, {"address_offset": 8, "op_offset": 16}))
        graph.add_node(GraphNode(endpoint_id, NodeType.HARDWARE_ENDPOINT, {"class": "SAMU/SBL"}))
        graph.add_edge(GraphEdge(function_id, descriptor_id, EdgeType.WRITES))
        graph.add_edge(GraphEdge(descriptor_id, endpoint_id, EdgeType.SUBMITS))

    if not surfaces:
        diagnostics = []
        if descriptor_moves:
            diagnostics.append("partial secure-descriptor patterns were not promoted across function windows")
        return TrackScanResult(track="secure", classification="SECURE-NONE", diagnostics=diagnostics)
    overall = max(classifications, key=lambda item: CLASSIFICATION_ORDER[item])
    return TrackScanResult(
        track="secure",
        classification=overall,
        surfaces=surfaces,
        graph=graph,
        diagnostics=["candidate-window cap reached" ] if len(descriptor_moves) > 512 else [],
    )
