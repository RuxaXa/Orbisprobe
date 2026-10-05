#!/usr/bin/env python3
"""Probe the installed Triton API contract and print the observed facts as JSON.

This script runs inside the pinned Triton environment. The M2-B regression suite executes it and
asserts on the output, so the engine assumptions the worker relies on cannot silently regress when
the Triton revision changes.

Facts asserted by tests/test_m2b_triton.py:
* register read/write sets are populated only after processing();
* memory access lists contain (MemoryAccess, AstNode) tuples;
* processing() returning 0 is not an error signal;
* "ret" is not reliably flagged through CS_GRP_RET, the mnemonic must be checked;
* Instruction() requires exactly the instruction's bytes;
* path constraints must be rendered explicitly (a bare str() yields an object repr);
* symbolizeMemory()/taintMemory() take a MemoryAccess, not an (address, size) pair.
"""

from __future__ import annotations

import json


def main() -> int:
    from capstone import CS_ARCH_X86, CS_GRP_RET, CS_MODE_64, Cs
    from triton import ARCH, Instruction, MemoryAccess, TritonContext

    facts: dict[str, object] = {}
    context = TritonContext()
    context.setArchitecture(ARCH.X86_64)
    code = bytes.fromhex("48 89 f8 4d 89 e0 48 83 fa 20 77 02 c3 90 c3")
    base = 0x400000
    context.setConcreteMemoryAreaValue(base, code)
    context.setConcreteRegisterValue(context.registers.rdi, 0x600000)
    context.setConcreteRegisterValue(context.registers.r12, 0x10)
    long_instruction = Instruction(base, code)
    context.disassembly(long_instruction)
    facts["instruction_bytes_must_be_exact"] = long_instruction.getDisassembly().split()[0] == "mov"

    facts["taint_known"] = True
    context.taintRegister(context.registers.rdi)
    context.taintRegister(context.registers.r12)
    facts["taint_register_visible"] = bool(context.isRegisterTainted(context.registers.r12))
    facts["taint_memory_requires_memoryaccess"] = False
    try:
        context.taintMemory(0x600000, 8)
    except TypeError:
        facts["taint_memory_requires_memoryaccess"] = True
    context.taintMemory(MemoryAccess(0x600000, 8))
    facts["taint_memory_via_memoryaccess_ok"] = bool(context.isMemoryTainted(0x600000))

    context.setConcreteMemoryAreaValue(0x600000, b"\x00" * 64)
    symbolic_signature_ok = False
    try:
        context.symbolizeMemory(0x600000, 8)
    except TypeError:
        pass
    try:
        context.symbolizeMemory(MemoryAccess(0, 8))
        symbolic_signature_ok = True
    except Exception:  # noqa: BLE001
        symbolic_signature_ok = False
    facts["symbolize_memory_via_memoryaccess_ok"] = symbolic_signature_ok

    # instruction 1: mov rax, rdi  (concrete move, no symbolic expression)
    first = Instruction(base, code[:3])
    context.disassembly(first)
    facts["reads_empty_before_processing"] = len(first.getReadRegisters()) == 0
    facts["writes_empty_before_processing"] = len(first.getWrittenRegisters()) == 0
    processed_value = context.processing(first)
    facts["processing_zero_is_not_an_error"] = processed_value == 0 or processed_value is False
    facts["reads_after_processing"] = sorted(
        entry[0].getName() if isinstance(entry, tuple) else entry.getName()
        for entry in first.getReadRegisters()
    )
    facts["writes_after_processing"] = sorted(
        entry[0].getName() if isinstance(entry, tuple) else entry.getName()
        for entry in first.getWrittenRegisters()
    )
    facts["access_entries_are_tuples"] = all(
        isinstance(entry, tuple) and len(entry) == 2
        for entry in (*first.getLoadAccess(), *first.getStoreAccess())
    )

    # instruction 2: mov r8, r12 then a store, to observe the (MemoryAccess, AstNode) payload
    second = Instruction(base + 3, code[3:6])
    context.disassembly(second)
    context.processing(second)
    store_instruction = Instruction(0x400009, bytes.fromhex("48 89 07"))  # mov [rdi], rax
    context.disassembly(store_instruction)
    context.processing(store_instruction)
    stores = store_instruction.getStoreAccess()
    # The Triton binding exposes MemoryAccess as a factory bound to the architecture, not as a
    # Python class, so the payload is validated by shape rather than with isinstance().
    first_access = stores[0][0] if stores else None
    facts["store_access_shape"] = bool(
        stores
        and isinstance(stores[0], tuple)
        and callable(getattr(first_access, "getAddress", None))
        and callable(getattr(first_access, "getSize", None))
    )
    facts["store_access_type"] = type(first_access).__name__ if first_access is not None else None
    facts["store_access_address"] = hex(int(stores[0][0].getAddress())) if stores else None

    # branch / constraint rendering over a symbolic register so a constraint is actually created
    context.setConcreteRegisterValue(context.registers.r12, 0x10)
    context.symbolizeRegister(context.registers.r12, "sym_r12")
    compare = Instruction(0x400100, bytes.fromhex("49 83 fc 20"))  # cmp r12, 0x20
    context.disassembly(compare)
    context.processing(compare)
    branch = Instruction(0x400104, bytes.fromhex("77 02"))  # ja +2
    context.disassembly(branch)
    context.processing(branch)
    constraints = list(context.getPathConstraints())
    facts["path_constraint_count"] = len(constraints)
    facts["constraint_str_is_object_repr"] = None
    facts["constraint_predicate_available"] = False
    if constraints:
        rendered = [str(item) for item in constraints]
        facts["constraint_str_is_object_repr"] = any("object at 0x" in text for text in rendered)
        taken = getattr(constraints[-1], "getTakenPredicate", None)
        facts["constraint_predicate_available"] = bool(taken and taken() is not None)

    # ret detection
    disassembler = Cs(CS_ARCH_X86, CS_MODE_64)
    disassembler.detail = True
    ret_bytes = bytes.fromhex("c3")
    decoded = next(disassembler.disasm(ret_bytes, 0x401000, count=1), None)
    facts["ret_in_group_ret"] = bool(decoded and decoded.groups and CS_GRP_RET in decoded.groups)
    facts["ret_mnemonic"] = decoded.mnemonic if decoded else None

    from importlib import metadata

    try:
        facts["triton_version"] = metadata.version("triton-library")
    except Exception:  # noqa: BLE001
        facts["triton_version"] = "unknown"
    print(json.dumps(facts, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
