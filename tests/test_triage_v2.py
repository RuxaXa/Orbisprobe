"""Tests for the campaign-v2 structured candidate triage."""

from __future__ import annotations

from orbisprobe.live.triage import (
    classify_consumer,
    consumer_kind,
    field_is_reread,
    funnel,
    resolve_consumer,
    store_consumer_class,
)

CALL = "0xffffffffd0781523 call with rdi = field val"


def test_field_is_reread_requires_the_same_offset():
    assert field_is_reread("0x... mov rbx, [rbx + 0x18]", "0x... mov rax, [rbx + 0x18]", "[rbx+0x18]")
    assert not field_is_reread("0x... mov rbx, [rbx + 0x18]", "0x... mov rax, [rbx + 0x20]", "[rbx+0x18]")
    # whitespace between the base register and the offset must not change the verdict
    assert field_is_reread("mov rbx, [rbx+0x18]", "mov rax, [rbx + 0x18]", "[rbx+0x18]")


def test_consumer_kind_is_derived_from_structured_evidence():
    assert consumer_kind({"callee": "0x10"}) == "call-direct"
    assert consumer_kind({"indirect_callsite": True}) == "call-indirect"
    assert consumer_kind({"consumer_instruction": "0x20 mov qword ptr [rax + 0x18], rbx"}) == "store"
    assert consumer_kind({"consumer_instruction": "0x20 cmp rbx, rax"}) == "unknown"


def test_resolve_consumer_uses_call_targets_not_regexes():
    calls = {"0xffffffffd0781523": "0xffffffffd041a680"}
    site, target, register, indirect = resolve_consumer({"consumer_instruction": CALL}, calls)
    assert site == "0xffffffffd0781523" and target == 0xFFFFFFFFD041A680 and register == "rdi"
    assert indirect is False
    # a callsite absent from the structured call model must not invent a target
    _s, target2, _r, _i = resolve_consumer({"consumer_instruction": "0xdeadbeef call with rdi = x"}, calls)
    assert target2 == 0


def test_classify_consumer_prefers_the_argument_parameter():
    def classifier(body, name):
        return ("C3", ["written"]) if name == "param_2" else ("C4", ["unused"])
    klass, reasons = classify_consumer("body", "rsi", classifier)
    assert klass == "C3" and reasons == ["param_2: written"]


def test_store_consumer_class_requires_a_different_destination():
    klass, _ = store_consumer_class({"read_1": "0x1 mov rbx, [rbx + 0x18]",
                                     "consumer_instruction": "0x2 mov qword ptr [rax + 0x18], rbx"})
    assert klass == "C3"
    klass2, _ = store_consumer_class({"read_1": "0x1 mov rbx, [rbx + 0x18]",
                                      "consumer_instruction": "0x2 mov qword ptr [rbx + 0x18], rbx"})
    assert klass2 == "C4"


def test_funnel_stages_and_survivor():
    base = {"cfg_confirmed": True, "field": "[rbx + 0x18]", "read_1": "mov rbx, [rbx + 0x18]",
            "read_2": "mov rax, [rbx + 0x18]", "validation": "cmp rbx, 0", "callee": "0x10",
            "consumer_class": "C3"}
    assert funnel(base).survivor
    assert funnel({**base, "cfg_confirmed": False}).stage == "A"
    assert funnel({**base, "read_2": "mov rax, [rbx + 0x20]"}).stage == "B"
    assert funnel({**base, "validation": ""}).stage == "C"
    assert funnel({**base, "consumer_class": "C1"}).stage == "D"
    assert funnel({**base, "callee": "", "consumer_instruction": "0x1 cmp rbx, rax"}).stage == "D"
