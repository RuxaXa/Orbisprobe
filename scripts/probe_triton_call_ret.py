#!/usr/bin/env python3
"""Probe the Triton CALL/RET execution semantics that the M2-B worker relies on.

This script runs inside the pinned Triton environment. It answers one decisive question: does
``processing()`` already implement the architectural stack effects of CALL and RET, or would the
worker have to emulate them itself? Emulating them on top of Triton's own semantics would produce a
double push/pop.

Output is one JSON object; tests/test_m2b_triton.py asserts the contract.
"""

from __future__ import annotations

import json


def main() -> int:
    from triton import ARCH, Instruction, TritonContext

    CODE = 0x400000
    STACK = 0x700000
    STACK_TOP = 0x700F00
    CALLEE = 0x400010
    facts: dict[str, object] = {}

    context = TritonContext()
    context.setArchitecture(ARCH.X86_64)
    code = bytearray(b"\x90" * 0x40)
    # call rel32 -> CALLEE
    rel = (CALLEE - (CODE + 5)) & 0xFFFFFFFF
    code[0:5] = b"\xe8" + rel.to_bytes(4, "little")
    code[5:6] = b"\xc3"  # caller ret
    code[0x10:0x11] = b"\xc3"  # callee ret
    context.setConcreteMemoryAreaValue(CODE, bytes(code))
    context.setConcreteMemoryAreaValue(STACK, b"\x00" * 0x1000)
    context.setConcreteRegisterValue(context.registers.rip, CODE)
    context.setConcreteRegisterValue(context.registers.rsp, STACK_TOP)

    def register_names(entries) -> list[str]:
        names = []
        for entry in entries:
            register = entry[0] if isinstance(entry, tuple) else entry
            name = getattr(register, "getName", None)
            if callable(name):
                names.append(name())
        return sorted(set(names))

    def process(address: int, size: int) -> dict[str, object]:
        raw = bytes(context.getConcreteMemoryAreaValue(address, 16))[:size]
        instruction = Instruction(address, raw)
        context.disassembly(instruction)
        before = {
            "rip": context.getConcreteRegisterValue(context.registers.rip),
            "rsp": context.getConcreteRegisterValue(context.registers.rsp),
            "at_rsp": int.from_bytes(
                bytes(context.getConcreteMemoryAreaValue(
                    context.getConcreteRegisterValue(context.registers.rsp), 8
                )),
                "little",
            ),
            "stores": [],
        }
        stores_before = [
            (int(access.getAddress()), int(access.getSize()))
            for access, _ast in instruction.getStoreAccess()
        ]
        context.processing(instruction)
        stores_after = [
            (int(access.getAddress()), int(access.getSize()))
            for access, _ast in instruction.getStoreAccess()
        ]
        after_rsp = context.getConcreteRegisterValue(context.registers.rsp)
        return {
            "instruction": instruction.getDisassembly(),
            "rip_before": before["rip"],
            "rsp_before": before["rsp"],
            "at_rsp_before": before["at_rsp"],
            "rip_after": context.getConcreteRegisterValue(context.registers.rip),
            "rsp_after": after_rsp,
            "at_rsp_after": int.from_bytes(
                bytes(context.getConcreteMemoryAreaValue(after_rsp, 8)), "little"
            ),
            "written_registers": register_names(instruction.getWrittenRegisters()),
            "stores": stores_after,
            "stores_visible_before_processing": stores_before,
            "callee_slot": int.from_bytes(bytes(context.getConcreteMemoryAreaValue(STACK_TOP - 8, 8)), "little"),
        }

    call = process(CODE, 5)
    facts["call"] = call
    facts["triton_implements_call_stack_effect"] = bool(
        call["rsp_after"] == call["rsp_before"] - 8
        and call["rip_after"] == CALLEE
        and call["callee_slot"] == CODE + 5
    )
    facts["call_writes_return_address_visible_in_memory"] = bool(call["callee_slot"] == CODE + 5)

    ret = process(CALLEE, 1)
    facts["ret"] = ret
    facts["triton_implements_ret_stack_effect"] = bool(
        ret["rsp_after"] == ret["rsp_before"] + 8 and ret["rip_after"] == CODE + 5
    )

    # ret imm16 (far/stack-cleanup variant)
    context.setConcreteMemoryAreaValue(CODE + 0x20, bytes.fromhex("c2 10 00"))
    context.setConcreteRegisterValue(context.registers.rsp, STACK_TOP)
    context.setConcreteMemoryAreaValue(STACK_TOP, (CODE + 0x40).to_bytes(8, "little"))
    ret_imm = process(CODE + 0x20, 3)
    facts["ret_imm16"] = ret_imm
    facts["ret_imm16_rsp_delta"] = ret_imm["rsp_after"] - ret_imm["rsp_before"]

    print(json.dumps(facts, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
