from pathlib import Path

from orbisprobe.analysis.binary import BinaryImage
from orbisprobe.surfaces.iommu import scan_iommu


def image(tmp_path: Path, name: str, data: bytes) -> BinaryImage:
    path = tmp_path / name
    path.write_bytes(data)
    return BinaryImage.open(path, architecture="x86_64", base=0x2000)


def test_iommu_requires_multiple_structural_evidence_categories(tmp_path: Path):
    code = bytes.fromhex(
        "55 48 89 e5 "
        "b8 70 0a 00 00 "
        "bb 00 00 00 c0 "
        "89 47 20 "
        "e8 00 00 00 00 c3"
    )
    strings = b"gpuvm_map\x00DMAC\x00device table\x00doorbell\x00"
    result = scan_iommu(image(tmp_path, "iommu.bin", code + strings))
    assert result.classification == "IOMMU-STRUCTURAL-CANDIDATE"
    assert len(result.surfaces) == 1
    surface = result.surfaces[0]
    assert surface.surface_type.value == "IOMMU_DMA"
    assert surface.status.value == "UNKNOWN"
    assert surface.candidate_priority == "P4"
    kinds = {item.kind for item in surface.evidence}
    assert {"string_anchor", "research_constant", "descriptor_write"} <= kinds
    assert "hardware consumer not reconstructed" in surface.unknowns
    assert any("mapping validation" in chain for chain in surface.open_chains)
    assert result.graph.to_dict()["edges"] == []


def test_single_dma_string_is_not_promoted_to_surface(tmp_path: Path):
    result = scan_iommu(image(tmp_path, "weak.bin", b"random dma text\x00"))
    assert result.classification == "IOMMU-NONE"
    assert result.surfaces == []
    assert any("insufficient independent evidence" in item for item in result.diagnostics)


def test_iommu_evidence_cap_preserves_independent_categories(tmp_path: Path):
    strings = (b"unmap\x00" * 100) + b"DMAC\x00device table\x00"
    code = bytes.fromhex("b8 70 0a 00 00 89 47 20 c3")
    result = scan_iommu(image(tmp_path, "balanced.bin", strings + code))
    kinds = {item.kind for item in result.surfaces[0].evidence}
    assert {"string_anchor", "research_constant", "descriptor_write"} <= kinds
    assert len(result.surfaces[0].evidence) <= 64


def test_iommu_decodes_0xa70_as_structure_displacement(tmp_path: Path):
    code = bytes.fromhex("48 8b 87 70 0a 00 00 c3")
    strings = b"gpuvm_map\x00DMAC\x00device table\x00"
    result = scan_iommu(image(tmp_path, "disp.bin", code + strings))
    assert result.classification == "IOMMU-NONE"
    assert result.surfaces == []
    assert any("STRUCT_FIELD_DISPLACEMENT" in message for message in result.diagnostics)


def test_iommu_memory_read_is_not_descriptor_write(tmp_path: Path):
    code = bytes.fromhex("b8 70 0a 00 00 f6 47 20 12 c3")
    strings = b"gpuvm_map\x00DMAC\x00device table\x00"
    result = scan_iommu(image(tmp_path, "read-only.bin", code + strings))
    assert result.classification == "IOMMU-NONE"
    assert result.surfaces == []
