"""LIVE2.2 candidate filters, cross-engine gate and CT classification (§3-§12). Offline only."""

from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path

import pytest

from orbisprobe.live.transfer import (
    CT_A,
    CT_B,
    CT_C,
    CT_D,
    CT_E,
    MULTI_MODAL_STRONG_SUPPORT,
    TransferCandidate,
    build_shortlist,
    classify_transfer,
    consumer_divergence,
    minimize_configs,
    record_engine_consensus,
    select_candidate,
)

KERNEL = Path("/home/hermes/audits/playstation-ps4/fw1352-ps4b-20260920/kernel-dump/kernel.bin")


def _candidate(**overrides) -> TransferCandidate:
    base = TransferCandidate(
        candidate_id="RC-001",
        function="0xffffffffd00d1560-0xffffffffd00d1600",
        field="[rdi+0x28]",
        read_1="0xffffffffd00d1580 mov eax, dword ptr [rdi + 0x28]",
        read_2="0xffffffffd00d15a0 mov ecx, dword ptr [rdi + 0x28]",
        intervening_phase="1 direct call(s) between the reads, first at 0xffffffffd00d1590",
        consumer="0xffffffffd00d15a5 mov dword ptr [rbx], ecx",
        validation="0xffffffffd00d1585 cmp eax, 0x1",
        observable="consumer destination value derived from read #2",
        value_a="0x11", value_b="0x22",
        persistent_risk="NONE",
        priority="P1",
        reachability="payload-owned mirror of the chain shape",
    )
    return replace(base, **overrides)


def _consensus(candidate: TransferCandidate) -> TransferCandidate:
    record_engine_consensus(candidate, {
        "native": {"status": "COMPLETED", "chain_confirmed": True},
        "angr": {"status": "COMPLETED", "chain_confirmed": True},
        "ghidra": {"status": "COMPLETED", "chain_confirmed": False},
    })
    return candidate


def test_gate_requires_the_same_field_on_both_reads():
    allowed, blockers = _candidate(read_2="0xffffffffd00d15a0 mov ecx, dword ptr [rdi + 0x30]").gate()
    assert not allowed and any(b.startswith("A:") for b in blockers)


def test_gate_requires_cross_engine_support():
    allowed, blockers = _candidate().gate()
    assert not allowed and any("MULTI_MODAL_STRONG_SUPPORT" in b for b in blockers)


def test_gate_requires_intervening_call_consumer_and_values():
    candidate = _candidate(intervening_phase="", consumer="", value_b="0x11")
    allowed, blockers = _candidate(intervening_phase="", consumer="", value_b="0x11").gate()
    assert not allowed
    assert any(b.startswith("B:") for b in blockers)
    assert any(b.startswith("C:") for b in blockers)
    assert any(b.startswith("E:") for b in blockers)
    assert candidate.value_a == candidate.value_b


def test_gate_blocks_persistent_sink_and_low_priority():
    allowed, blockers = _candidate(persistent_risk="FLASH").gate()
    assert not allowed and any(b.startswith("F:") for b in blockers)
    allowed, blockers = _candidate(priority="P3").gate()
    assert not allowed and any("P3" in b for b in blockers)


def test_full_gate_passes_for_confirmed_p1():
    candidate = _consensus(_candidate())
    allowed, blockers = candidate.gate()
    assert allowed and blockers == []
    assert candidate.engine_consensus["classification"] == MULTI_MODAL_STRONG_SUPPORT


def test_selection_skips_hard_blockers_and_allows_deferred_ones():
    hard = _candidate(candidate_id="RC-000",
                      read_2="0xffffffffd00d15a0 mov ecx, dword ptr [rdi + 0x30]")  # filter A fails
    provisional = _candidate(candidate_id="RC-001")  # only §4 consensus is still open
    selected, selection = select_candidate([hard, provisional])
    assert selected is provisional
    assert selection["considered"][0]["selectable"] is False
    assert selection["considered"][0]["hard_blockers"]
    assert selection["considered"][1]["selectable"] is True
    assert selection["considered"][1]["deferred_blockers"]


def test_live_phase_requires_the_full_gate_to_be_closed():
    """The deferred blockers must be resolved before the live phase may run (safety-relevant)."""
    record_engine_consensus(_candidate(), {"native": {"status": "COMPLETED", "chain_confirmed": True},
                                           "angr": {"status": "ERROR", "chain_confirmed": False}})
    allowed, blockers = _candidate().gate()
    assert not allowed and any("MULTI_MODAL" in b for b in blockers)


def test_classification_ct_a_when_consumer_follows_read2():
    classification, reason = classify_transfer(read_1="0x11", read_2="0x22", overlap_class="T2-A",
                                               consumer_effect="dest=0x22", consumer_matches_read2=True)
    assert classification == CT_A and "consistent with the split" in reason


def test_classification_ct_b_when_effect_ambiguous():
    classification, _ = classify_transfer(read_1="0x11", read_2="0x22", overlap_class="T2-A",
                                          consumer_effect="dest=unknown", consumer_matches_read2=False)
    assert classification == CT_B


def test_classification_ct_c_without_overlap_or_without_split():
    assert classify_transfer(read_1="0x11", read_2="0x22", overlap_class="T2-B",
                             consumer_effect="", consumer_matches_read2=False)[0] == CT_C
    assert classify_transfer(read_1="0x11", read_2="0x11", overlap_class="T2-A",
                             consumer_effect="", consumer_matches_read2=False)[0] == CT_C


def test_classification_ct_d_when_consumer_only_uses_read1():
    classification, reason = classify_transfer(read_1="0x11", read_2="0x22", overlap_class="T2-A",
                                               consumer_effect="dest=0x11", consumer_matches_read2=False,
                                               consumer_pinned_to_read1=True)
    assert classification == CT_D and "not security relevant" in reason


def test_classification_ct_e_on_fault():
    assert classify_transfer(read_1="0x11", read_2="0x22", overlap_class="T2-A", consumer_effect="",
                             consumer_matches_read2=False, fault="restore mismatch")[0] == CT_E


def test_consumer_divergence_measures_the_witness():
    rows = [
        {"r1": "0x11", "r2": "0x22", "dest_value": "0x22"},
        {"r1": "0x11", "r2": "0x11", "dest_value": "0x11"},
    ]
    result = consumer_divergence(rows)
    assert result["split_attempts"] == 1 and result["divergent_consumer_effects"] == 1 and result["consistent"]
    empty = consumer_divergence([{"r1": "0x11", "r2": "0x11", "dest_value": "0x11"}])
    assert not empty["consistent"] and empty["split_attempts"] == 0


def test_minimisation_is_bounded_and_keeps_the_mode():
    configs = minimize_configs()
    assert 1 <= len(configs) <= 3
    assert all(c["mode"] == 0 for c in configs)
    windows = [c["max_ms"] for c in configs]
    assert windows == sorted(windows, reverse=True), "minimisation shrinks the writer window step by step"
    assert windows[0] <= 50 and windows[-1] >= 1


@pytest.mark.skipif(not KERNEL.is_file(), reason="FW13.52 kernel image not present")
def test_shortlist_builds_gated_records_from_discovery(tmp_path):
    discovery = {"engine": "test", "all_candidates": [
        {"priority": "P1", "function_start": "0xffffffffd00d1560", "function_end": "0xffffffffd00d1600",
         "field": "[rdi+0x28]", "read_1": "0xffffffffd00d1580 mov eax, [rdi+0x28]",
         "read_2": "0xffffffffd00d15a0 mov ecx, [rdi+0x28]", "calls": [{"address": "0xffffffffd00d1590"}],
         "consumer": "0xffffffffd00d15a5 mov [rbx], ecx", "validation": "0xffffffffd00d1585 cmp eax, 1"}]}
    path = tmp_path / "discovery.json"
    path.write_text(json.dumps(discovery))
    shortlist = build_shortlist(path, KERNEL, 0xFFFFFFFFD00D0000, limit=5)
    assert len(shortlist) == 1
    record = shortlist[0]
    assert record.function_bytes_sha256 and record.read_1 and record.read_2
    allowed, blockers = record.gate()
    assert not allowed  # no cross-engine support yet: live test must not start
    assert any("MULTI_MODAL" in b for b in blockers)
