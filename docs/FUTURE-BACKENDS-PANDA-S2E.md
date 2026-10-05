# Future whole-system backend notes

## Status

`PANDA` and `S2E` are `FUTURE_BACKEND`. M2-A contains no runtime adapter, dependency, installer, project generator, or execution path for either system.

## Why deferred

- There is no validated whole-system PS4 machine model.
- Liverpool/Jaguar peripherals, SAMU/SBL behavior, southbridge devices, boot firmware, and platform initialization are not represented sufficiently for evidence-grade execution.
- A generic x86 VM that happens to execute isolated bytes is not PS4 runtime evidence.
- Building an emulator before a falsifiable platform model exists would consume weeks while producing ambiguous results.

## Future adapter boundary

A future adapter may implement the common backend contract only after it can provide:

- immutable machine/configuration provenance;
- image and disk hashes;
- architecture and memory-map identity;
- deterministic snapshot identity;
- bounded replay limits;
- explicit synthetic/stubbed devices;
- trace export into `BackendEvidence`;
- an `EMULATED_BEHAVIOR` source class, never `runtime_real`.

Whole-system results remain independent evidence only when the underlying semantic engine and machine model are independent from other voters. PANDA/QEMU plugins sharing one execution core count as one independence family.

## Revisit gate

Revisit only when at least one exists:

1. a reproducible PS4 machine model that reaches the relevant subsystem;
2. a narrowly extracted firmware/handler environment with validated device contracts;
3. a concrete candidate whose proof cannot be closed with native, angr, Ghidra, Triton, or Qiling.
