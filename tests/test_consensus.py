from orbisprobe.backends.base import (
    BackendCapability,
    BackendEvidence,
    BackendIdentity,
    BackendResult,
)
from orbisprobe.backends.consensus import (
    ConsensusClassification,
    ConsensusEngine,
)


def identity(name, family, capabilities=(BackendCapability.DATAFLOW,)):
    return BackendIdentity(name, "1", family, frozenset(capabilities))


def result(name, family, value, *, source_class="static", subject="r15@consumer"):
    ident = identity(name, family)
    return BackendResult.completed(
        ident,
        {},
        [
            BackendEvidence(
                "value_domain",
                subject,
                value,
                provenance={"source_class": source_class},
            )
        ],
    )


def test_one_engine_is_supported_never_confirmed():
    report = ConsensusEngine().combine([result("native", "capstone-native", [0, 1])])
    claim = report.claims[0]
    assert claim.classification is ConsensusClassification.SUPPORTED
    assert claim.independent_families == ["capstone-native"]


def test_two_independent_static_engines_are_strongly_supported():
    report = ConsensusEngine().combine(
        [
            result("native", "capstone-native", [0, 1]),
            result("ghidra", "ghidra-pcode", [0, 1]),
        ]
    )
    assert report.claims[0].classification is ConsensusClassification.STRONGLY_SUPPORTED


def test_same_independence_family_counts_once():
    report = ConsensusEngine().combine(
        [
            result("native-a", "shared-disassembler", 7),
            result("native-b", "shared-disassembler", 7),
        ]
    )
    assert report.claims[0].classification is ConsensusClassification.SUPPORTED
    assert report.claims[0].independent_source_count == 1


def test_conflicting_values_never_promote():
    report = ConsensusEngine().combine(
        [
            result("native", "capstone-native", [0, 1]),
            result("angr", "angr-vex", [0, 1, 2], source_class="symbolic"),
        ]
    )
    claim = report.claims[0]
    assert claim.classification is ConsensusClassification.EVIDENCE_CONFLICT
    assert len(claim.conflicts) == 2


def test_static_plus_symbolic_agreement_is_strong_not_confirmed():
    report = ConsensusEngine().combine(
        [
            result("native", "capstone-native", 0xA8),
            result("angr", "angr-vex", 0xA8, source_class="symbolic"),
        ]
    )
    assert report.claims[0].classification is ConsensusClassification.STRONGLY_SUPPORTED


def test_real_runtime_plus_independent_static_can_confirm_but_backend_does_not_set_it():
    report = ConsensusEngine().combine(
        [
            result("native", "capstone-native", 0xA8),
            result("runtime-log", "real-target-runtime", 0xA8, source_class="runtime_real"),
        ]
    )
    assert report.claims[0].classification is ConsensusClassification.CONFIRMED


def test_register_lifetime_requires_cross_check_when_second_source_available():
    engine = ConsensusEngine(register_cross_check_required=True)
    report = engine.combine(
        [result("native", "capstone-native", "user_ptr", subject="r15@0x401000")],
        available_families={"capstone-native", "ghidra-pcode"},
    )
    claim = report.claims[0]
    assert claim.classification is ConsensusClassification.SUPPORTED
    assert "second independent register-lifetime source required" in claim.unknowns


def test_incomplete_results_are_reported_but_do_not_vote():
    unavailable = BackendResult.incomplete(identity("angr", "angr-vex"), "state ceiling")
    report = ConsensusEngine().combine(
        [result("native", "capstone-native", 1), unavailable]
    )
    assert report.claims[0].classification is ConsensusClassification.SUPPORTED
    assert report.backend_statuses["angr"] == "ANALYSIS_INCOMPLETE"


def test_support_and_refutation_are_conflict_without_majority_vote():
    supporting = result("native", "capstone-native", [0, 1])
    refuting = result("ghidra", "ghidra-pcode", [0, 1])
    refuting.evidence[0] = BackendEvidence(
        "value_domain",
        "r15@consumer",
        [0, 1],
        confidence="DISPROVED",
    )
    claim = ConsensusEngine().combine([supporting, refuting]).claims[0]
    assert claim.classification is ConsensusClassification.EVIDENCE_CONFLICT


def test_unanimous_refutation_is_disproved_not_supported():
    refuting = result("ghidra", "ghidra-pcode", "reachable")
    refuting.evidence[0] = BackendEvidence(
        "value_domain",
        "r15@consumer",
        "reachable",
        confidence="DISPROVED",
    )
    claim = ConsensusEngine().combine([refuting]).claims[0]
    assert claim.classification is ConsensusClassification.DISPROVED
