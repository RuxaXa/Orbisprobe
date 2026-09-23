"""LIVE2.9 reclassification tests (section 13). Alignment must no longer decide a target class."""

from __future__ import annotations

from orbisprobe.live.layout import (
    DATA_NOT_CODE,
    EXECUTABLE_CODE_TARGET,
    FUNCTION_ENTRY_CONFIRMED,
    INTERNAL_BLOCK_TARGET,
    MID_INSTRUCTION_INVALID,
    NOT_A_TARGET,
    R29_B,
    R29_C,
    R29_D,
    STRICT_FUNCTION_TARGET,
    THUNK_TARGET,
    VALID_EXECUTABLE_TARGET,
    R29Evidence,
    access_matrix,
    classify,
    classify_target,
    derive_access_width,
    looks_like_string,
    reinterpret_window,
)

KB = 0xFFFFFFFF9C768000
TEXT_END = KB + 0xCFE758
# instruction boundaries in this fixture are 7 bytes apart, exactly like the GC_SRB/GC_SRM raster
BOUNDARIES = {KB + 0x1000 + 7 * index for index in range(8)}
FUNCTIONS = {KB + 0x1000}
BLOCKS = {KB + 0x1000 + 7, KB + 0x1000 + 14}
THUNKS = {KB + 0x1000 + 21}


def test_unaligned_target_is_valid_when_it_is_a_boundary():
    # the old rule ("unaligned => invalid pointer") is wrong on x86-64 and must not come back
    address = KB + 0x1000 + 7          # ends in 7: unaligned, but a known boundary
    tier, level, reason = classify_target(address, kernel_base=KB, kernel_text_end=TEXT_END,
                                          instruction_boundaries=BOUNDARIES, function_starts=FUNCTIONS,
                                          block_starts=BLOCKS, thunks=THUNKS)
    assert tier == INTERNAL_BLOCK_TARGET and level == VALID_EXECUTABLE_TARGET and "block" in reason


def test_aligned_function_entry_is_strict():
    tier, level, _ = classify_target(KB + 0x1000, kernel_base=KB, kernel_text_end=TEXT_END,
                                     instruction_boundaries=BOUNDARIES, function_starts=FUNCTIONS,
                                     block_starts=BLOCKS, thunks=THUNKS)
    assert tier == FUNCTION_ENTRY_CONFIRMED and level == STRICT_FUNCTION_TARGET


def test_thunk_and_executable_tiers():
    tier, level, _ = classify_target(KB + 0x1000 + 21, kernel_base=KB, kernel_text_end=TEXT_END,
                                     instruction_boundaries=BOUNDARIES, function_starts=FUNCTIONS,
                                     block_starts=BLOCKS, thunks=THUNKS)
    assert tier == THUNK_TARGET and level == VALID_EXECUTABLE_TARGET
    tier2, level2, _ = classify_target(KB + 0x1000 + 28, kernel_base=KB, kernel_text_end=TEXT_END,
                                       instruction_boundaries=BOUNDARIES, function_starts=FUNCTIONS,
                                       block_starts=BLOCKS, thunks=THUNKS)
    assert tier2 == EXECUTABLE_CODE_TARGET and level2 == VALID_EXECUTABLE_TARGET


def test_mid_instruction_target_is_invalid():
    tier, level, reason = classify_target(KB + 0x1000 + 3, kernel_base=KB, kernel_text_end=TEXT_END,
                                          instruction_boundaries=BOUNDARIES, function_starts=FUNCTIONS,
                                          block_starts=BLOCKS, thunks=THUNKS)
    assert tier == MID_INSTRUCTION_INVALID and level == NOT_A_TARGET and "inside an instruction" in reason


def test_string_target_is_data_not_code():
    tier, level, reason = classify_target(KB + 0x2000, kernel_base=KB, kernel_text_end=TEXT_END,
                                          instruction_boundaries=BOUNDARIES, function_starts=FUNCTIONS,
                                          target_bytes=b"GC_SRB\x00\x00")
    assert tier == DATA_NOT_CODE and level == NOT_A_TARGET and "data" in reason


def test_looks_like_string_detects_the_real_strings():
    for text in (b"GC_SRB\x00", b"GC_SRM\x00", b"GC_IDLE\x00", b"gctask\x00"):
        assert looks_like_string(text)[0], text
    assert not looks_like_string(bytes.fromhex("4889e54883ec20"))[0]


def test_plus7_raster_is_seven_byte_string_literals():
    raw = b"GC_SRB\x00\x00GC_SRM\x00\x00GC_SRI\x00\x00GC_IDLE\x00"   # 32 bytes = four 8-byte fields
    rows = reinterpret_window(raw, base_offset=0x21810, kernel_base=KB, kernel_text_end=TEXT_END,
                              dump_base=0xFFFFFFFFD00D0000, live_base=KB)
    assert len(rows) == 4
    assert all(row["string_in_field"] for row in rows)
    assert [row["offset"] for row in rows] == ["0x21810", "0x21818", "0x21820", "0x21828"]
    assert all(row["raw"].startswith("47435f") for row in rows), "every field starts with the ASCII 'GC_'"


def test_reinterpret_window_rebases_kernel_pointers():
    live_pointer = 0xFFFFFFFF9CF76718
    raw = live_pointer.to_bytes(8, "little") + b"GC_SRM\x00\x00"
    rows = reinterpret_window(raw, base_offset=0x21810, kernel_base=KB, kernel_text_end=TEXT_END,
                              dump_base=0xFFFFFFFFD00D0000, live_base=KB)
    assert rows[0]["rebased_to_dump"] == "0xffffffffd08de718"
    assert rows[1]["string_in_field"] is True


def test_access_width_comes_from_the_operand_size():
    assert derive_access_width("MOV qword ptr [RBX + 0x21850],R14") == 8
    assert derive_access_width("MOV dword ptr [RBX + 0x21890],0x0") == 4
    assert derive_access_width("MOVZX EAX,word ptr [RBX + 0x21864]") == 2
    assert derive_access_width("CALL qword ptr [RAX + 0x21850]") == 8


def test_mixed_width_access_matrix():
    entries = [
        {"offset": "0x21850", "instruction": "CALL qword ptr [RAX + 0x21850]"},
        {"offset": "0x21850", "instruction": "MOV qword ptr [RDI + 0x21850],R14"},
        {"offset": "0x21890", "instruction": "MOV dword ptr [RBX + 0x21890],0x0"},
        {"offset": "0x21864", "instruction": "MOVZX EAX,word ptr [RBX + 0x21864]"},
    ]
    matrix = access_matrix(entries)
    assert matrix["0x21850"]["widths"] == [8] and matrix["0x21850"]["call_jmp"] == 1
    assert matrix["0x21890"]["widths"] == [4]
    assert matrix["0x21864"]["widths"] == [2]


def test_callback_zero_means_unregistered_not_disproved():
    evidence = R29Evidence(mixed_struct=True, neighbour_values_are_data=True,
                           callback_registration_state="DEVICE_INIT", callback_layout_disproved=False)
    outcome, reason, notes = classify(evidence)
    assert outcome == R29_C and "unregistered" in reason and any("retracted" in n for n in notes)


def test_layout_disproved_would_be_r29_b():
    assert classify(R29Evidence(callback_layout_disproved=True))[0] == R29_B


def test_window_from_another_struct_would_be_r29_d():
    assert classify(R29Evidence(window_from_expected_struct=False))[0] == R29_D
