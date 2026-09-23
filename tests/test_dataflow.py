from pathlib import Path

import pytest

from orbisprobe.analysis.binary import BinaryImage
from orbisprobe.analysis.dataflow import DataflowAnalyzer, SourceSpec


def make_fixture(tmp_path: Path) -> BinaryImage:
    # mov rax,[rsi+8]; mov rbx,rax; call next; mov rdi,rax; mov rdi,rbx; ret
    data = bytes.fromhex("48 8b 46 08 48 89 c3 e8 00 00 00 00 48 89 c7 48 89 df c3")
    path = tmp_path / "flow.bin"
    path.write_bytes(data)
    return BinaryImage.open(path, architecture="x86_64", base=0x1000)


def test_dataflow_models_definition_propagation_and_call_clobber(tmp_path: Path):
    result = DataflowAnalyzer(make_fixture(tmp_path)).analyze(
        function=0x1000,
        end=0x1013,
        source=SourceSpec(memory_base="rsi", memory_displacement=8),
    )
    events = [(event.event, event.register, event.address) for event in result.events]
    assert ("definition", "rax", 0x1000) in events
    assert ("propagation", "rbx", 0x1004) in events
    assert ("call_clobber", "rax", 0x1007) in events
    assert ("consumer", "rbx", 0x100F) in events
    assert not any(
        event.event == "consumer" and event.register == "rax" and event.address > 0x1007
        for event in result.events
    )
    assert result.call_clobber_complete is True


def test_dataflow_rejects_out_of_range_function(tmp_path: Path):
    analyzer = DataflowAnalyzer(make_fixture(tmp_path))
    with pytest.raises(ValueError, match="outside binary"):
        analyzer.analyze(
            function=0x9999,
            end=0x99A0,
            source=SourceSpec(register="rdi", definition_address=0x9999),
        )
