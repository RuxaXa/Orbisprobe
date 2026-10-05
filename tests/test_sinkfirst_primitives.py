from __future__ import annotations

import json

import pytest

from orbisprobe.analysis.sinkfirst import (
    BackwardSliceStep,
    BlockerResolution,
    CandidateBlocker,
    FirmwareFunction,
    FunctionComparison,
    FunctionRelation,
    HardwareSink,
    HardwareSinkClass,
    MappingLifecycleGraph,
    MappingState,
    MappingTransition,
    ParkedCandidate,
    ProvenanceEdge,
    SinkBackwardSlice,
    SinkOperation,
    UserInfluence,
    UserSinkProvenancePath,
)
from orbisprobe.surfaces.model import Confidence


def test_hardware_sink_taxonomy_and_record_are_fail_closed_and_deterministic():
    sink = HardwareSink(
        sink_id="sink:gpu-doorbell",
        sink_class=HardwareSinkClass.MMIO_REGISTER,
        operation=SinkOperation.WRITE,
        firmware_id="fw-9.00",
        binary_sha256="ab" * 32,
        address=0xFFFF_8000,
        device="gpu",
        confidence=Confidence.HIGH,
        evidence=("insn:0x401000", "xref:0x400100"),
    )

    assert sink.persistent is False
    assert json.loads(sink.to_json()) == sink.to_dict()
    assert sink.to_json() == sink.to_json()
    assert '"address":4294934528' in sink.to_json()
    assert HardwareSinkClass.RING_STATE.value == "ring_state"
    assert HardwareSinkClass.DMA_VISIBLE.value == "dma_visible"
    assert HardwareSinkClass.GPUVM_VISIBLE.value == "gpuvm_visible"
    assert HardwareSinkClass.IOMMU_VISIBLE.value == "iommu_visible"
    assert HardwareSinkClass.DEVICE_COMMAND.value == "device_command"

    with pytest.raises(ValueError, match="binary_sha256"):
        HardwareSink(
            sink_id="sink:bad",
            sink_class=HardwareSinkClass.UNKNOWN,
            operation=SinkOperation.UNKNOWN,
            firmware_id="fw-9.00",
            binary_sha256="not-a-digest",
            address=0,
            device="unknown",
            confidence=Confidence.NONE,
        )


def test_sink_backward_slice_validates_dependencies_and_completeness():
    sink = HardwareSink(
        sink_id="sink:dmac-submit",
        sink_class=HardwareSinkClass.DMA_DESCRIPTOR,
        operation=SinkOperation.SUBMIT,
        firmware_id="fw-9.00",
        binary_sha256="cd" * 32,
        address=0x9000,
        device="dmac",
        confidence=Confidence.HIGH,
        evidence=("submit@0x9000",),
    )
    steps = (
        BackwardSliceStep(
            step_id="sink-write",
            address=0x9000,
            expression="submit descriptor",
            depends_on=("descriptor-base",),
            confidence=Confidence.HIGH,
            evidence=("mov [doorbell], rax",),
        ),
        BackwardSliceStep(
            step_id="descriptor-base",
            address=0x8FF0,
            expression="descriptor base from user buffer",
            confidence=Confidence.MEDIUM,
            evidence=("mov rax, [rdi+8]",),
        ),
    )
    backward_slice = SinkBackwardSlice(
        slice_id="slice:dmac-submit",
        sink=sink,
        sink_step="sink-write",
        steps=steps,
    )

    assert backward_slice.complete is True
    assert backward_slice.confidence is Confidence.MEDIUM
    assert backward_slice.to_dict()["steps"][0]["depends_on"] == ["descriptor-base"]

    incomplete = SinkBackwardSlice(
        slice_id="slice:dmac-submit-partial",
        sink=sink,
        sink_step="sink-write",
        steps=steps,
        unresolved=("indirect call target",),
    )
    assert incomplete.complete is False

    cyclic = (
        BackwardSliceStep("a", 1, "a", ("b",), Confidence.LOW),
        BackwardSliceStep("b", 2, "b", ("a",), Confidence.LOW),
    )
    with pytest.raises(ValueError, match="cycle"):
        SinkBackwardSlice("slice:cycle", sink, "a", cyclic)


def test_mapping_lifecycle_graph_accepts_only_legal_contiguous_transitions():
    transitions = (
        MappingTransition(MappingState.ALLOCATED, MappingState.MAPPED, 0x1000, Confidence.HIGH),
        MappingTransition(MappingState.MAPPED, MappingState.ACTIVE, 0x1010, Confidence.HIGH),
        MappingTransition(MappingState.ACTIVE, MappingState.INVALIDATED, 0x1020, Confidence.MEDIUM),
        MappingTransition(MappingState.INVALIDATED, MappingState.UNMAPPED, 0x1030, Confidence.HIGH),
        MappingTransition(MappingState.UNMAPPED, MappingState.RELEASED, 0x1040, Confidence.HIGH),
    )
    lifecycle = MappingLifecycleGraph(
        mapping_id="mapping:gpu-0",
        initial_state=MappingState.ALLOCATED,
        transitions=transitions,
    )

    assert lifecycle.final_state is MappingState.RELEASED
    assert lifecycle.complete is True
    assert lifecycle.to_dict()["transitions"][2]["target"] == "invalidated"

    with pytest.raises(ValueError, match="illegal mapping transition"):
        MappingLifecycleGraph(
            "mapping:bad",
            MappingState.ALLOCATED,
            (
                MappingTransition(
                    MappingState.ALLOCATED,
                    MappingState.MAPPED,
                    0x1000,
                    Confidence.HIGH,
                ),
                MappingTransition(
                    MappingState.MAPPED,
                    MappingState.RELEASED,
                    0x1010,
                    Confidence.HIGH,
                ),
            ),
        )

    discontinuous = (
        MappingTransition(MappingState.ALLOCATED, MappingState.MAPPED, 0x1000, Confidence.HIGH),
        MappingTransition(MappingState.INVALIDATED, MappingState.UNMAPPED, 0x1030, Confidence.HIGH),
    )
    with pytest.raises(ValueError, match="not contiguous"):
        MappingLifecycleGraph("mapping:gap", MappingState.ALLOCATED, discontinuous)


def test_user_to_sink_provenance_path_requires_contiguous_confident_edges():
    sink = HardwareSink(
        sink_id="sink:iommu-map",
        sink_class=HardwareSinkClass.IOMMU_MAPPING,
        operation=SinkOperation.MAP,
        firmware_id="fw-11.00",
        binary_sha256="ef" * 32,
        address=0xA000,
        device="iommu",
        confidence=Confidence.HIGH,
        evidence=("map@0xa000",),
    )
    edges = (
        ProvenanceEdge(
            "user:ioctl.arg0",
            "field:request.iova",
            "copies",
            Confidence.HIGH,
            ("copyin@0x7000",),
        ),
        ProvenanceEdge(
            "field:request.iova",
            "sink:iommu-map",
            "maps",
            Confidence.LOW,
            ("map@0xa000",),
        ),
    )
    path = UserSinkProvenancePath(
        path_id="path:user-iommu",
        user_source="user:ioctl.arg0",
        sink=sink,
        edges=edges,
        influence=UserInfluence.USER_INFLUENCED,
    )

    assert path.complete is True
    assert path.confidence is Confidence.LOW
    assert path.to_dict()["edges"][1]["confidence"] == "LOW"
    assert path.to_dict()["influence"] == "USER_INFLUENCED"

    uncertain = UserSinkProvenancePath(
        "path:user-iommu-unknown",
        "user:ioctl.arg0",
        sink,
        (ProvenanceEdge("user:ioctl.arg0", sink.sink_id, "maps", Confidence.NONE),),
    )
    assert uncertain.complete is False

    with pytest.raises(ValueError, match="not contiguous"):
        UserSinkProvenancePath(
            "path:broken",
            "user:ioctl.arg0",
            sink,
            (
                ProvenanceEdge("user:ioctl.arg0", "field:a", "copies", Confidence.HIGH),
                ProvenanceEdge("field:b", sink.sink_id, "maps", Confidence.HIGH),
            ),
        )


def test_cross_firmware_function_comparison_is_hash_bound_and_fail_closed():
    old = FirmwareFunction(
        firmware_id="fw-9.00",
        binary_sha256="12" * 32,
        function_id="sub_401000",
        address=0x401000,
        size=64,
        normalized_sha256="34" * 32,
        features=("calls:2", "blocks:4"),
    )
    new = FirmwareFunction(
        firmware_id="fw-11.00",
        binary_sha256="56" * 32,
        function_id="sub_501000",
        address=0x501000,
        size=64,
        normalized_sha256="34" * 32,
        features=("calls:2", "blocks:4"),
    )
    comparison = FunctionComparison(
        comparison_id="cmp:map-function",
        baseline=old,
        candidate=new,
        relation=FunctionRelation.EXACT,
        confidence=Confidence.HIGH,
        evidence=("normalized instruction hash",),
    )

    assert comparison.complete is True
    assert comparison.to_dict()["relation"] == "exact"
    assert json.loads(comparison.to_json())["candidate"]["firmware_id"] == "fw-11.00"

    changed_hash = FirmwareFunction(
        firmware_id="fw-11.00",
        binary_sha256="56" * 32,
        function_id="sub_501000",
        address=0x501000,
        size=64,
        normalized_sha256="78" * 32,
    )
    with pytest.raises(ValueError, match="EXACT"):
        FunctionComparison(
            "cmp:false-exact",
            old,
            changed_hash,
            FunctionRelation.EXACT,
            Confidence.HIGH,
        )

    missing = FunctionComparison(
        "cmp:missing",
        old,
        None,
        FunctionRelation.MISSING,
        Confidence.MEDIUM,
        ("no candidate above threshold",),
    )
    assert missing.candidate is None
    assert missing.complete is True


def test_parked_candidate_rehydrates_only_evidence_backed_blockers():
    candidate = ParkedCandidate(
        candidate_id="candidate:rc-001",
        blockers=(
            CandidateBlocker("blocker:target", "indirect target unresolved"),
            CandidateBlocker("blocker:sink", "sink class unresolved"),
        ),
    )
    partial = candidate.rehydrate(
        (
            BlockerResolution(
                "blocker:target",
                Confidence.HIGH,
                ("xref:0x1234",),
            ),
            BlockerResolution("blocker:sink", Confidence.NONE),
        )
    )

    assert partial.status == "PARKED"
    assert [item.blocker_id for item in partial.remaining] == ["blocker:sink"]
    assert partial.to_dict()["resolved"][0]["blocker_id"] == "blocker:target"

    ready = candidate.rehydrate(
        (
            BlockerResolution("blocker:target", Confidence.HIGH, ("xref:0x1234",)),
            BlockerResolution("blocker:sink", Confidence.MEDIUM, ("mmio-write@0x9000",)),
        )
    )
    assert ready.status == "READY"
    assert ready.remaining == ()

    with pytest.raises(ValueError, match="unknown blocker"):
        candidate.rehydrate(
            (BlockerResolution("blocker:not-present", Confidence.HIGH, ("evidence",)),)
        )
