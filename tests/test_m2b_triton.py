from __future__ import annotations

import hashlib
import json
import os
import subprocess
from pathlib import Path

import pytest
from m2b_cases import CASES, case_by_id, materialize, write_harness_file

from orbisprobe.backends.base import (
    BackendCapability,
    BackendEvidence,
    BackendIdentity,
    BackendResult,
    BackendStatus,
    ResourceLimits,
)
from orbisprobe.backends.consensus import ConsensusClassification, ConsensusEngine
from orbisprobe.backends.dynamic import DynamicEvidence
from orbisprobe.backends.triton_backend import TritonBackend
from orbisprobe.harness import HarnessError, parse_harness, validate_harness

ROOT = Path(__file__).parents[1]
TRITON_PYTHON = Path(
    os.environ.get("ORBISPROBE_TRITON_PYTHON", ROOT / ".backend-envs" / "triton" / "bin" / "python")
)
requires_triton = pytest.mark.skipif(
    not TRITON_PYTHON.is_file(), reason="triton worker environment is not installed"
)


def backend() -> TritonBackend:
    return TritonBackend(
        interpreter=TRITON_PYTHON,
        limits=ResourceLimits(timeout_seconds=60, maximum_steps=4096),
    )


def run_case(case, tmp_path: Path, operation: str = "trace"):
    binary = materialize(case, tmp_path)
    harness = parse_harness(case.document())
    result = backend().run_harness(
        {
            "harness": harness,
            "binary": str(binary),
            "binary_sha256": case.binary_sha256(),
            "operation": operation,
        }
    )
    return harness, result


def sink_types(result: BackendResult) -> set[str]:
    sinks: set[str] = set()
    for flow in result.data.get("taint_flows", []):
        if flow.get("sink"):
            sinks.add(flow["sink"])
        for entry in flow.get("sinks", []):
            sinks.add(entry["sink"])
    return sinks


def tainted_sources(result: BackendResult) -> set[str]:
    return {
        flow["source"]
        for flow in result.data.get("taint_flows", [])
        if flow.get("sink") or flow.get("sinks")
    }


def sink_types_by_source(result: BackendResult) -> dict[str, set[str]]:
    """Which tainted source reached which sink - the per-claim attribution."""

    mapping: dict[str, set[str]] = {}
    for flow in result.data.get("taint_flows", []):
        sinks = {entry["sink"] for entry in flow.get("sinks", [])}
        if flow.get("sink"):
            sinks.add(flow["sink"])
        if sinks:
            mapping[flow["source"]] = sinks
    return mapping


@requires_triton
@pytest.mark.parametrize("case", CASES, ids=[case.case_id for case in CASES])
def test_synthetic_harness_cases(case, tmp_path: Path):
    harness, result = run_case(case, tmp_path)
    data = result.data
    assert harness.harness_sha256
    assert result.status.value in {"COMPLETED", "PARTIAL"}, result.errors
    assert data["execution_status"] == case.expected_status
    assert data["stop_reason"] == case.expected_stop
    assert len(data["memory_violations"]) == case.expected_violations
    assert sink_types(result) == case.expected_sink_types
    assert tainted_sources(result) == case.expected_tainted_sources
    assert {stub["behavior"] for stub in data["stubs_used"]} == case.expected_stub_behaviors
    assert len(data["branches"]) >= case.expected_min_branches
    if case.expected_sink_by_source:
        assert sink_types_by_source(result) == case.expected_sink_by_source
    if case.expected_min_constraints:
        rendered = [
            text for branch in data["branches"] for text in branch.get("constraints", [])
        ]
        assert rendered
        # Rendered constraints must be readable, never a bare object repr.
        assert not any("object at 0x" in text for text in rendered)
    if case.expected_memory_writes is not None:
        assert len(data["memory_writes"]) == case.expected_memory_writes
    if case.expected_return_value is not None:
        assert data["return_value"] == case.expected_return_value


@requires_triton
def test_taint_flow_transformations_are_recorded(tmp_path: Path):
    case = case_by_id("A-tainted-length-memcpy")
    _, result = run_case(case, tmp_path)
    flow = next(
        item for item in result.data["taint_flows"] if item["source"] == "user.data"
    )
    assert flow["transformations"]
    assert flow["sink"] == "MEMORY_WRITE_FROM_TAINTED_SOURCE"
    assert flow["reproducible"] is True
    assert flow["first_instruction"] is not None or flow["last_instruction"] is not None


@requires_triton
def test_unknown_callee_stops_the_run_instead_of_being_skipped(tmp_path: Path):
    case = case_by_id("A-tainted-length-memcpy")
    document = case.document()
    document["callee_stubs"] = []
    binary = materialize(case, tmp_path)
    harness = parse_harness(document)
    result = backend().run_harness(
        {
            "harness": harness,
            "binary": str(binary),
            "binary_sha256": case.binary_sha256(),
            "operation": "emulate",
        }
    )
    assert result.status is BackendStatus.ANALYSIS_INCOMPLETE
    assert result.data["stop_reason"] == "STUB_REQUIRED"
    assert result.data["calls"][0]["resolved"] is False
    assert result.data["stubs_used"] == []


@requires_triton
def test_unmapped_write_is_reported_as_violation(tmp_path: Path):
    case = case_by_id("C-tainted-pointer-to-descriptor")
    document = case.document()
    document["initial_registers"]["rdi"] = 0x900000  # not mapped at all
    binary = materialize(case, tmp_path)
    harness = parse_harness(
        {
            **document,
            "memory_regions": document["memory_regions"],
            "output_regions": [],
        }
    )
    result = backend().run_harness(
        {
            "harness": harness,
            "binary": str(binary),
            "binary_sha256": case.binary_sha256(),
            "operation": "emulate",
        }
    )
    assert result.data["memory_violations"]
    assert result.data["memory_violations"][0]["kind"] == "WRITE_UNMAPPED"
    assert result.status is BackendStatus.ANALYSIS_INCOMPLETE


@requires_triton
def test_instruction_limit_returns_resource_limit_not_a_verdict(tmp_path: Path):
    case = case_by_id("A-tainted-length-memcpy")
    document = case.document()
    document["instruction_limit"] = 1
    binary = materialize(case, tmp_path)
    harness = parse_harness(document)
    result = backend().run_harness(
        {
            "harness": harness,
            "binary": str(binary),
            "binary_sha256": case.binary_sha256(),
            "operation": "emulate",
        }
    )
    assert result.status is BackendStatus.RESOURCE_LIMIT
    assert result.data["stop_reason"] == "INSTRUCTION_LIMIT"


@requires_triton
def test_deterministic_repeat_produces_identical_record(tmp_path: Path):
    case = case_by_id("A-tainted-length-memcpy")
    _, first = run_case(case, tmp_path)
    _, second = run_case(case, tmp_path / "again")
    for key in ("execution_status", "stop_reason", "taint_flows", "memory_writes", "calls"):
        assert first.data[key] == second.data[key], key
    assert first.data["trace_sha256"] == second.data["trace_sha256"]


@requires_triton
def test_binary_hash_mismatch_is_rejected(tmp_path: Path):
    case = case_by_id("A-tainted-length-memcpy")
    binary = materialize(case, tmp_path)
    document = {**case.document(), "binary_sha256": "0" * 64}
    harness = parse_harness(document)
    result = backend().run_harness(
        {"harness": harness, "binary": str(binary), "operation": "emulate"}
    )
    assert result.status is BackendStatus.ERROR
    assert "mismatch" in result.errors[0]


def test_backend_availability_and_capabilities():
    result = backend().availability()
    if TRITON_PYTHON.is_file():
        assert result.status is BackendStatus.COMPLETED
        assert result.identity.version.startswith("1.")
    else:
        assert result.status is BackendStatus.BACKEND_UNAVAILABLE
    assert {
        BackendCapability.TAINT,
        BackendCapability.EMULATION,
        BackendCapability.CONCRETE_EXECUTION,
        BackendCapability.CALL_STUBS,
        BackendCapability.MEMORY_TRACE,
    } <= TritonBackend.identity.capabilities


def test_static_operations_are_not_faked(tmp_path: Path):
    result = backend().analyze_function({"binary": str(tmp_path / "x"), "base": 0, "function": 0})
    assert result.status is BackendStatus.ANALYSIS_INCOMPLETE
    assert "does not implement" in result.errors[0]


def test_missing_interpreter_is_unavailable(tmp_path: Path):
    missing = TritonBackend(interpreter=tmp_path / "missing-python")
    result = missing.availability()
    assert result.status is BackendStatus.BACKEND_UNAVAILABLE


def fake_interpreter(tmp_path: Path, name: str, worker_body: str) -> Path:
    """A stand-in interpreter that answers the version probe but misbehaves as the worker.

    Exercising the worker boundary requires the availability probe to succeed, otherwise the
    backend correctly returns BACKEND_UNAVAILABLE before the worker is ever launched.
    """

    script = tmp_path / name
    script.write_text(
        "#!/usr/bin/env python3\n"
        "import sys\n"
        "if len(sys.argv) > 1 and sys.argv[1] == '-c':\n"
        "    print('1.0.0rc4')\n"
        "    raise SystemExit(0)\n"
        + worker_body
    )
    script.chmod(0o700)
    return script


def worker_request(case, tmp_path: Path) -> dict:
    binary = materialize(case, tmp_path)
    return {
        "harness": parse_harness(case.document()),
        "binary": str(binary),
        "binary_sha256": case.binary_sha256(),
        "operation": "emulate",
    }


@pytest.mark.parametrize(
    "payload",
    ["not-json", '{"status":', "[]", "null", "42", '{"status":"COMPLETED"}'],
)
def test_malformed_worker_json_is_a_structured_error(tmp_path: Path, payload: str):
    interpreter = fake_interpreter(
        tmp_path, f"fake-{abs(hash(payload))}", f"sys.stdout.write({payload!r})\n"
    )
    request = worker_request(case_by_id("A-tainted-length-memcpy"), tmp_path)
    result = TritonBackend(interpreter=interpreter).run_harness(request)
    assert result.status is BackendStatus.ERROR
    assert result.evidence == []
    assert "invalid JSON response" in result.errors[0]


def test_huge_worker_output_hits_the_resource_limit(tmp_path: Path):
    interpreter = fake_interpreter(
        tmp_path, "huge-python", "sys.stdout.write('x' * (16 * 1024 * 1024 + 1))\n"
    )
    request = worker_request(case_by_id("A-tainted-length-memcpy"), tmp_path)
    result = TritonBackend(interpreter=interpreter).run_harness(request)
    assert result.status is BackendStatus.RESOURCE_LIMIT
    assert result.evidence == []


def test_worker_timeout_is_structured(tmp_path: Path):
    interpreter = fake_interpreter(tmp_path, "slow-python", "import time; time.sleep(30)\n")
    request = worker_request(case_by_id("A-tainted-length-memcpy"), tmp_path)
    result = TritonBackend(
        interpreter=interpreter, limits=ResourceLimits(timeout_seconds=1)
    ).run_harness(request)
    assert result.status is BackendStatus.TIMEOUT
    assert result.partial is True
    assert result.evidence == []


def test_worker_crash_is_isolated_from_the_core(tmp_path: Path):
    interpreter = fake_interpreter(
        tmp_path, "crash-python", "raise SystemExit(3)\n"
    )
    request = worker_request(case_by_id("A-tainted-length-memcpy"), tmp_path)
    result = TritonBackend(interpreter=interpreter).run_harness(request)
    assert result.status is BackendStatus.ERROR
    assert "invalid JSON response" in result.errors[0] or "exited" in result.errors[0]


def test_nonzero_worker_exit_cannot_report_completed(tmp_path: Path):
    payload = json.dumps(
        {"status": "COMPLETED", "version": "1.0.0rc4", "data": {}, "errors": [], "unknowns": []}
    )
    interpreter = fake_interpreter(
        tmp_path,
        "nonzero-python",
        f"import sys\nsys.stdout.write({payload!r})\nsys.exit(9)\n",
    )
    request = worker_request(case_by_id("A-tainted-length-memcpy"), tmp_path)
    result = TritonBackend(interpreter=interpreter).run_harness(request)
    assert result.status is BackendStatus.ERROR
    assert result.evidence == []


def test_garbage_version_probe_is_unavailable(tmp_path: Path):
    interpreter = tmp_path / "garbage-python"
    interpreter.write_text("#!/usr/bin/env python3\nprint('not-a-version')\n")
    interpreter.chmod(0o700)
    result = TritonBackend(interpreter=interpreter).availability()
    assert result.status is BackendStatus.BACKEND_UNAVAILABLE


@requires_triton
def test_initialization_write_versus_runtime_write_permissions(tmp_path: Path):
    """Seeding a read-only region is setup; an emulated write to it is a violation."""

    case = case_by_id("A-tainted-length-memcpy")
    document = json.loads(json.dumps(case.document()))
    seed = document["input_regions"][0]
    seed["concrete_value"] = "20" * 64
    # A store into the read-only "user" region (r--) after execution started.
    code = "48 c7 06 00 00 00 00 c3"  # mov qword ptr [rsi], 0; ret
    document["binary_sha256"] = hashlib.sha256(
        bytes.fromhex(code) + b"\x00" * (0x200 - len(bytes.fromhex(code)))
    ).hexdigest()
    document["callee_stubs"] = []
    document["initial_registers"]["rsi"] = 0x610000
    binary = tmp_path / "seed-vs-runtime.bin"
    binary.write_bytes(bytes.fromhex(code) + b"\x00" * (0x200 - len(bytes.fromhex(code))))
    harness = parse_harness(document)
    result = backend().run_harness(
        {
            "harness": harness,
            "binary": str(binary),
            "binary_sha256": document["binary_sha256"],
            "operation": "trace",
        }
    )
    # Seeding succeeded (no read violation on the read-only region) ...
    assert not [item for item in result.data["memory_violations"] if item["kind"].startswith("READ")]
    # ... while the emulated write into the same read-only region is denied.
    kinds = {item["kind"] for item in result.data["memory_violations"]}
    assert "WRITE_PERMISSION_DENIED" in kinds
    assert result.status is BackendStatus.ANALYSIS_INCOMPLETE


@requires_triton
@pytest.mark.parametrize(
    ("length", "expected"),
    [
        ("ffffffffffffffff", "STUB_LENGTH_OUT_OF_RANGE"),
        ("0100100000000000", "STUB_LENGTH_OUT_OF_RANGE"),
        ("0000000000100001", "STUB_LENGTH_OUT_OF_RANGE"),
        ("0000000000000000", None),
    ],
)
def test_stub_length_guard(tmp_path: Path, length: str, expected: str | None):
    case = case_by_id("A-tainted-length-memcpy")
    document = json.loads(json.dumps(case.document()))
    document["initial_registers"]["rdx"] = int.from_bytes(bytes.fromhex(length), "little")
    binary = materialize(case, tmp_path)
    harness = parse_harness(document)
    result = backend().run_harness(
        {
            "harness": harness,
            "binary": str(binary),
            "binary_sha256": case.binary_sha256(),
            "operation": "trace",
        }
    )
    kinds = {item["kind"] for item in result.data["memory_violations"]}
    if expected is None:
        assert not kinds
        assert result.data["stubs_used"][0]["bytes_copied"] == 0
    else:
        assert expected in kinds
        assert result.data["stubs_used"][0]["bytes_copied"] == 0
    assert result.status is not BackendStatus.ERROR


@requires_triton
@pytest.mark.parametrize(
    ("register_setup", "expected"),
    [
        ({"rdx": 0x2000}, "READ_OOB_REGION"),  # longer than the mapped source
        ({"rdi": 0x600F00, "rdx": 0x200}, "WRITE_OOB_REGION"),  # longer than the destination
    ],
)
def test_stub_length_beyond_mapped_regions(tmp_path: Path, register_setup, expected: str):
    case = case_by_id("A-tainted-length-memcpy")
    document = json.loads(json.dumps(case.document()))
    document["initial_registers"].update(register_setup)
    binary = materialize(case, tmp_path)
    harness = parse_harness(document)
    result = backend().run_harness(
        {
            "harness": harness,
            "binary": str(binary),
            "binary_sha256": case.binary_sha256(),
            "operation": "trace",
        }
    )
    kinds = {item["kind"] for item in result.data["memory_violations"]}
    assert expected in kinds
    assert result.data["stubs_used"][0]["bytes_copied"] == 0
    assert result.status is BackendStatus.ANALYSIS_INCOMPLETE


@requires_triton
def test_triton_api_contract_is_unchanged():
    """Pin the engine assumptions the worker depends on."""

    completed = subprocess.run(
        [str(TRITON_PYTHON), str(ROOT / "scripts" / "probe_triton_api.py")],
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr[-500:]
    facts = json.loads(completed.stdout)
    assert facts["reads_empty_before_processing"] is True
    assert facts["writes_empty_before_processing"] is True
    assert facts["reads_after_processing"] == ["rdi"]
    assert facts["access_entries_are_tuples"] is True
    assert facts["store_access_shape"] is True
    assert facts["processing_zero_is_not_an_error"] is True
    assert facts["ret_mnemonic"] == "ret"
    assert facts["instruction_bytes_must_be_exact"] is True
    # Documented engine quirk: str(PathConstraint) yields an object repr, so the worker must render
    # constraints explicitly through getTakenPredicate()/getBranchConstraints().
    assert facts["constraint_str_is_object_repr"] is True
    assert facts["constraint_predicate_available"] is True
    assert facts["taint_memory_requires_memoryaccess"] is True
    assert facts["taint_memory_via_memoryaccess_ok"] is True
    assert facts["symbolize_memory_via_memoryaccess_ok"] is True


# --- harness model ----------------------------------------------------------------------


def test_malformed_harness_is_rejected():
    case = CASES[0]
    document = case.document()
    document.pop("harness_id")
    errors = validate_harness(document)
    assert any("harness_id" in item for item in errors)
    with pytest.raises(HarnessError):
        parse_harness(document)


def test_overlapping_regions_are_rejected():
    document = CASES[0].document()
    document["memory_regions"] = document["memory_regions"] + [
        {
            "name": "overlap",
            "base": 0x600100,
            "size": 0x100,
            "permissions": "rw",
            "source": "zero",
        }
    ]
    assert any("overlap" in item for item in validate_harness(document))


def test_executable_writable_region_is_rejected():
    document = CASES[0].document()
    document["memory_regions"][0]["permissions"] = "rwx"
    assert any("executable writable" in item for item in validate_harness(document))


def test_unknown_stub_and_abi_mismatch_are_rejected():
    document = CASES[0].document()
    document["callee_stubs"] = [
        {"target": 0x500000, "name": "wildcard", "behavior": "generic_return_zero"}
    ]
    assert any("not in the stub registry" in item for item in validate_harness(document))

    document["callee_stubs"] = [
        {
            "target": 0x500000,
            "name": "bad_abi",
            "behavior": "memcpy",
            "register_effects": {"rbx": 0},
        }
    ]
    assert any("callee-saved" in item for item in validate_harness(document))


def test_invalid_addresses_and_inputs_are_rejected():
    document = CASES[0].document()
    document["function_entry"] = -1
    document["input_regions"] = [{"name": "outside", "address": 0xDEAD0000, "size": 8}]
    document["taint_sources"] = [{"kind": "register", "register": "notareg", "label": "x"}]
    errors = validate_harness(document)
    assert any("function_entry" in item for item in errors)
    assert any("not fully inside a mapped region" in item for item in errors)
    assert any("general-purpose register" in item for item in errors)


def _mutate_unknown_top_level(document):
    document["taint_source"] = []  # misspelled plural


def _mutate_typo_known_key(document):
    document["function_entr"] = document.pop("function_entry")


def _mutate_unknown_region_key(document):
    document["memory_regions"][0]["permisions"] = "rx"


def _mutate_unknown_input_key(document):
    document["input_regions"][0]["taint"] = True


def _mutate_unknown_stub_key(document):
    document["callee_stubs"][0]["clobber"] = []


def _mutate_unsupported_schema(document):
    document["schema_version"] = "m2b-harness-v2"


@pytest.mark.parametrize(
    ("mutate", "expected"),
    [
        (_mutate_unknown_top_level, "unknown keys"),
        (_mutate_typo_known_key, "unknown keys"),
        (_mutate_unknown_region_key, "unknown keys"),
        (_mutate_unknown_input_key, "unknown keys"),
        (_mutate_unknown_stub_key, "unknown keys"),
        (_mutate_unsupported_schema, "unsupported schema_version"),
    ],
)
def test_unknown_harness_keys_fail_closed(mutate, expected):
    document = json.loads(json.dumps(CASES[0].document()))
    mutate(document)
    errors = validate_harness(document)
    assert any(expected in item for item in errors), errors
    with pytest.raises(HarnessError) as failure:
        parse_harness(document)
    assert failure.value.code == "HARNESS_INVALID"
    assert failure.value.to_dict()["code"] == "HARNESS_INVALID"


@pytest.mark.parametrize(
    "mutate",
    [
        _mutate_unknown_top_level,
        _mutate_unknown_region_key,
        _mutate_unknown_stub_key,
        _mutate_unsupported_schema,
    ],
)
def test_invalid_harness_never_reaches_the_worker(tmp_path: Path, monkeypatch, mutate):
    calls: list[tuple] = []

    def explode(*args, **kwargs):  # pragma: no cover - must never run
        calls.append((args, kwargs))
        raise AssertionError("the worker must not be invoked for an invalid harness")

    monkeypatch.setattr(subprocess, "run", explode)
    document = json.loads(json.dumps(CASES[0].document()))
    mutate(document)
    with pytest.raises(HarnessError):
        parse_harness(document)
    assert calls == []


def test_harness_hash_is_stable_and_binding(tmp_path: Path):
    case = CASES[0]
    first = parse_harness(case.document())
    second = parse_harness(case.document())
    assert first.harness_sha256 == second.harness_sha256

    changed = case.document()
    changed["instruction_limit"] = 999
    assert parse_harness(changed).harness_sha256 != first.harness_sha256

    path = write_harness_file(case, tmp_path)
    assert json.loads(path.read_text())["harness_id"] == case.document()["harness_id"]


# --- dynamic evidence -------------------------------------------------------------------


def _dynamic(**overrides):
    payload = {
        "backend": "triton",
        "backend_version": "1.0.0rc4",
        "binary_sha256": "a" * 64,
        "harness_sha256": "b" * 64,
        "function": 0x400000,
        "input_sha256": "c" * 64,
        "execution_status": "COMPLETED",
        "instructions_executed": 3,
    }
    payload.update(overrides)
    return DynamicEvidence(**payload)


def test_dynamic_evidence_roundtrip_and_bounds():
    evidence = _dynamic(memory_reads=[{"address": 1}] * 200, taint_flows=[{"source": "x"}] * 200)
    payload = evidence.to_dict()
    assert payload["counts"]["memory_reads"] == 200
    assert len(payload["memory_reads"]) <= 64
    assert DynamicEvidence.from_dict(payload).execution_status == "COMPLETED"


def test_dynamic_evidence_rejects_runtime_provenance_and_bad_hash():
    with pytest.raises(ValueError):
        _dynamic(provenance="REAL_RUNTIME")
    with pytest.raises(ValueError):
        _dynamic(input_sha256="zz")
    with pytest.raises(ValueError):
        _dynamic(execution_status="NO_BUG")
    with pytest.raises(ValueError):
        DynamicEvidence.from_dict({**_dynamic().to_dict(), "votes": "yes"})


# --- consensus integration --------------------------------------------------------------


def _result(name, family, source_class, value, confidence="SUPPORTED"):
    return BackendResult.completed(
        BackendIdentity(name, "1", family, frozenset()),
        {},
        [
            BackendEvidence(
                "descriptor_field",
                "user+0x38->descriptor+0x08",
                value,
                confidence=confidence,
                provenance={"source_class": source_class},
            )
        ],
    )


def test_static_plus_emulated_is_multi_modal_but_never_runtime_confirmed():
    report = ConsensusEngine().combine(
        [
            _result("native", "capstone-native", "static", True),
            _result("triton", "triton-symbolic", "emulated", True),
        ]
    )
    claim = report.claims[0]
    assert claim.classification is ConsensusClassification.MULTI_MODAL_STRONG_SUPPORT
    assert claim.independent_source_count == 2


def test_emulated_alone_is_only_supported():
    report = ConsensusEngine().combine([_result("triton", "triton-symbolic", "emulated", True)])
    assert report.claims[0].classification is ConsensusClassification.SUPPORTED


def test_emulated_disagreement_is_a_conflict():
    report = ConsensusEngine().combine(
        [
            _result("native", "capstone-native", "static", True),
            _result("triton", "triton-symbolic", "emulated", False),
        ]
    )
    assert report.claims[0].classification is ConsensusClassification.EVIDENCE_CONFLICT


def test_three_engines_across_modalities_stay_multi_modal_not_confirmed():
    report = ConsensusEngine().combine(
        [
            _result("native", "capstone-native", "static", True),
            _result("angr", "angr-vex", "symbolic", True),
            _result("triton", "triton-symbolic", "emulated", True),
        ]
    )
    claim = report.claims[0]
    assert claim.classification is ConsensusClassification.MULTI_MODAL_STRONG_SUPPORT
    assert claim.classification is not ConsensusClassification.CONFIRMED


@requires_triton
@pytest.mark.parametrize("size", [1, 2, 4, 8, 16, 20, 24, 32, 48, 63, 64, 96, 128, 256])
def test_memory_taint_ranges_are_chunked_for_triton(size: int, tmp_path: Path):
    """Arbitrary harness taint ranges must not be passed as one illegal MemoryAccess."""

    case = case_by_id("A-tainted-length-memcpy")
    document = case.document()
    document["taint_sources"][0]["size"] = size
    binary = materialize(case, tmp_path)
    harness = parse_harness(document)
    result = backend().run_harness(
        {
            "harness": harness,
            "binary": str(binary),
            "binary_sha256": case.binary_sha256(),
            "operation": "trace",
        }
    )
    assert result.status is BackendStatus.COMPLETED, result.errors
    assert not any("MemoryAccess" in error for error in result.errors)


@requires_triton
@pytest.mark.parametrize(
    ("value_hex", "expected_taken"),
    [
        ("2000000000000000", False),
        ("2100000000000000", True),
    ],
)
def test_branch_evidence_reports_actual_taken_state(
    value_hex: str, expected_taken: bool, tmp_path: Path
):
    """The branch evidence must distinguish concrete fall-through from a taken jump."""

    case = case_by_id("G-symbolic-branch")
    document = case.document()
    document["input_regions"][0]["concrete_value"] = value_hex
    binary = materialize(case, tmp_path)
    harness = parse_harness(document)
    result = backend().run_harness(
        {
            "harness": harness,
            "binary": str(binary),
            "binary_sha256": case.binary_sha256(),
            "operation": "trace",
        }
    )
    assert result.status is BackendStatus.COMPLETED, result.errors
    assert result.data["branches"]
    branch = result.data["branches"][0]
    assert branch["taken"] is expected_taken
    assert (branch["next_rip"] != branch["fallthrough"]) is expected_taken
