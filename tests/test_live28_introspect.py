"""LIVE2.8 read-only introspection guards (tests for section 20). Offline only."""

from __future__ import annotations

import pytest

from orbisprobe.live.introspect import (
    CALLBACK_TARGET_CONFIRMED,
    DIRECT_MAP,
    INVALID_POINTER,
    KERNEL_DATA,
    KERNEL_TEXT,
    MMIO,
    R28_A,
    R28_B,
    R28_C,
    R28_D,
    TARGET_UNKNOWN,
    UNKNOWN,
    USER,
    R28Evidence,
    bounded_read_length,
    classify,
    classify_address,
    entry_model_check,
    pointer_sanity,
    rebound_object_address,
    stale_boot_rejection,
    validate_function_target,
)

KB = 0xFFFFFFFFDFD50000
TEXT_END = KB + 0xCFE758
IMAGE_END = KB + 0x2000000
FUNCTIONS = {KB + 0x4AC8F0, KB + 0x47E7B0}


def test_address_classification_fixtures():
    assert classify_address(KB + 0x1000, kernel_base=KB, kernel_text_end=TEXT_END, kernel_image_end=IMAGE_END) == KERNEL_TEXT
    assert classify_address(KB + 0xD00000, kernel_base=KB, kernel_text_end=TEXT_END,
                            kernel_image_end=IMAGE_END + 0x2000000) == KERNEL_DATA
    assert classify_address(0xFFFFFF8000000000 + 0x1000, kernel_base=KB, kernel_text_end=TEXT_END,
                            kernel_image_end=IMAGE_END) == DIRECT_MAP
    assert classify_address(0xD0000000, kernel_base=KB, kernel_text_end=TEXT_END, kernel_image_end=IMAGE_END) == MMIO
    assert classify_address(0x0000000012345678, kernel_base=KB, kernel_text_end=TEXT_END,
                            kernel_image_end=IMAGE_END) == USER
    assert classify_address(0xDEADBEEF00000000, kernel_base=KB, kernel_text_end=TEXT_END,
                            kernel_image_end=IMAGE_END) == UNKNOWN


def test_mmio_and_unknown_are_blocked():
    # MMIO is refused as a class; a non-canonical value is refused even earlier
    ok, reason, klass = pointer_sanity(0xD0000000, kernel_base=KB, kernel_text_end=TEXT_END,
                                       kernel_image_end=IMAGE_END)
    assert not ok and klass == MMIO and "blocked" in reason
    ok2, reason2, klass2 = pointer_sanity(0xDEADBEEF00000000, kernel_base=KB, kernel_text_end=TEXT_END,
                                          kernel_image_end=IMAGE_END)
    assert not ok2 and klass2 == UNKNOWN and "canonical" in reason2


def test_stale_boot_pointer_is_rejected():
    old = KB - 0x1000000
    ok, reason = stale_boot_rejection(KB + 0x4AC8F0, pointer_boot_base=old, current_boot_base=KB)
    assert not ok and "stale boot" in reason
    ok2, _ = stale_boot_rejection(KB + 0x4AC8F0, pointer_boot_base=KB, current_boot_base=KB)
    assert ok2


def test_rebase_uses_the_current_boot_delta():
    assert rebound_object_address(0xFFFFFFFFD2458A28, dump_base=0xFFFFFFFFD00D0000, live_base=KB) \
        == 0xFFFFFFFFD2458A28 + (KB - 0xFFFFFFFFD00D0000)


def test_bounded_read_length_clamps():
    assert bounded_read_length(0x40) == (0x40, False)
    assert bounded_read_length(0x400) == (0x100, True)
    with pytest.raises(ValueError):
        bounded_read_length(0)


def test_invalid_function_pointer_rejection():
    data_address = KB + 0x1500000
    klass, reason = validate_function_target(data_address, kernel_base=KB, kernel_text_end=TEXT_END,
                                             function_starts=FUNCTIONS)
    assert klass == INVALID_POINTER and "outside the kernel text" in reason
    assert validate_function_target(KB + 0x4AC901, kernel_base=KB, kernel_text_end=TEXT_END,
                                    function_starts=FUNCTIONS)[0] == TARGET_UNKNOWN
    assert validate_function_target(KB + 0x4AC8F0, kernel_base=KB, kernel_text_end=TEXT_END,
                                    function_starts=FUNCTIONS)[0] == CALLBACK_TARGET_CONFIRMED


def test_pointer_sanity_requires_alignment_and_class():
    ok, reason, _ = pointer_sanity(KB + 0x4AC8F1, kernel_base=KB, kernel_text_end=TEXT_END, kernel_image_end=IMAGE_END)
    assert not ok and "aligned" in reason
    ok2, _, klass = pointer_sanity(KB + 0x4AC8F0, kernel_base=KB, kernel_text_end=TEXT_END,
                                   kernel_image_end=IMAGE_END, expected_class=KERNEL_TEXT)
    assert ok2 and klass == KERNEL_TEXT
    ok3, reason3, _ = pointer_sanity(0x0000000012345678, kernel_base=KB, kernel_text_end=TEXT_END,
                                     kernel_image_end=IMAGE_END)
    assert not ok3 and "user address" in reason3


def test_entry_model_check_catches_arithmetic_drift():
    assert entry_model_check("index*8 + 8", "index * 8 + 8")[0]
    ok, reason = entry_model_check("index*8 + 8", "index*8")
    assert not ok and "model revision" in reason


def test_classification_outcomes():
    assert classify(R28Evidence(context_readable=False, blocker="anchor unreadable"))[0] == R28_D
    assert classify(R28Evidence(context_readable=True, model_consistent=False))[0] == R28_B
    resolved = R28Evidence(context_readable=True, entry_target_class=CALLBACK_TARGET_CONFIRMED,
                           rc001_object="0xffffff8000001000")
    assert classify(resolved)[0] == R28_A
    assert classify(R28Evidence(context_readable=True, rc001_object="0xffffff8000001000"))[0] == R28_C
    outcome, _, notes = classify(R28Evidence(context_readable=True))
    assert outcome == R28_C and notes
