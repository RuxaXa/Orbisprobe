from orbisprobe.surfaces.model import (
    BoundaryType,
    Confidence,
    Evidence,
    SurfaceFinding,
    SurfaceStatus,
    SurfaceType,
)
from orbisprobe.surfaces.ranking import (
    CandidatePriority,
    RankingFactors,
    rank_candidate,
)


def test_surface_model_contains_required_fields_and_is_deterministic():
    evidence = [Evidence(kind="instruction", address=0x1000, detail="vmrun decoded")]
    first = SurfaceFinding.create(
        surface_type=SurfaceType.SVM_HV,
        binary="fixture.bin",
        binary_sha256="a" * 64,
        architecture="x86_64",
        function="sub_1000",
        address=0x1000,
        source=["decoded privileged instruction"],
        validation=["instruction boundary decoded by Capstone"],
        boundary=BoundaryType.CPU_PRIVILEGE,
        consumer=["unknown runtime consumer"],
        observable=["offline instruction presence"],
        confidence=Confidence.LOW,
        evidence=evidence,
        unknowns=["initialization", "runtime role"],
        status=SurfaceStatus.SUPPORTED,
    )
    second = SurfaceFinding.create(**first.creation_fields())
    assert first.surface_id == second.surface_id
    data = first.to_dict()
    for key in (
        "surface_id", "surface_type", "binary", "architecture", "function", "address",
        "source", "validation", "boundary", "consumer", "observable", "confidence",
        "evidence", "unknowns", "status",
    ):
        assert key in data
    assert data["surface_type"] == "SVM_HV"
    assert data["status"] == "SUPPORTED"
    assert data["address"] == 0x1000


def test_candidate_ranking_is_triage_not_vulnerability_label():
    priority, score = rank_candidate(
        RankingFactors(
            controllability=0.9,
            validation_gap=0.8,
            privilege_distance=0.8,
            consumer_confidence=0.9,
            observable_quality=0.8,
            reproducibility=0.9,
            persistent_risk=0.0,
            host_closed=True,
        )
    )
    assert priority == CandidatePriority.P1
    assert 0.0 <= score <= 1.0

    structural, _ = rank_candidate(RankingFactors(consumer_confidence=0.1))
    assert structural == CandidatePriority.P4
