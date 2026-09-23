import json
from pathlib import Path

from orbisprobe.analysis.memop import MemopVerdict, analyze_memop_facts


def test_p2_1_631ad0_is_safe_invariant_not_overflow_candidate():
    fixture_path = Path(__file__).parent / "fixtures" / "p2_1_631ad0.json"
    facts = json.loads(fixture_path.read_text(encoding="utf-8"))
    result = analyze_memop_facts(facts)
    assert result.verdict == MemopVerdict.SAFE_INVARIANT
    assert result.length == 0xA8
    assert result.index_domain == [0, 1]
    assert result.destination_slot_size == 0xC0
    assert result.remaining_extent == 0x18
    assert "OOB" not in result.verdict.value
