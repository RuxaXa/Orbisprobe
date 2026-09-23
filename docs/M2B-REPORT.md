# OrbisProbe M2-B1 dynamic-harness verification report

## Verdict before independent review

**Implementation gates: PASS. Independent immutable-snapshot review and final checkpoint commit: pending.**

The final user-facing verdict is not issued by this file. It is issued only after the exact tree documented here receives an independent `PASS` and is committed without modification.

## 1. Scope

M2-B1 adds offline dynamic analysis to the M2-A static backend set:

- `orbisprobe/harness/` — validated, hash-bound function-harness documents and the bounded stub registry
- `orbisprobe/backends/triton_backend.py`, `orbisprobe/backends/workers/triton_worker.py` — a Triton 1.0.0rc4 worker in its own pinned environment and process
- `orbisprobe/backends/dynamic.py` — the compact, hash-referenced dynamic evidence record
- orchestration, cache key, and consensus participation for dynamic runs

Triton is the only authority for architectural `CALL`/`RET`; the worker never performs a second push or pop. Registered stubs receive a real `CALL` and are intercepted on the next dispatch; the return uses the return address actually present on the emulated stack. Near `RET`/`RET imm16` are Triton-authoritative with a stack-slot snapshot before and after. `retf`/`iret` are rejected as `UNSUPPORTED_RETURN_FORM`.

No Qiling, AFL++, PANDA, S2E, Binary Ninja, PS4 transport, or live-target action is part of this checkpoint. No persistent-state experiment was planned or executed.

## 2. Backends in this run

| Backend | Version | Independence family | Status |
| --- | --- | --- | --- |
| native (Capstone) | 5.0.9 | `capstone-native` | `COMPLETED` |
| angr | 9.2.184 | `angr-vex` | `COMPLETED` |
| Ghidra Headless/P-code | 12.1.3 | `ghidra-pcode` | `COMPLETED` |
| Triton worker | 1.0.0rc4 | `triton-symbolic` | `COMPLETED` |

Capabilities reported by the Triton worker: `BRANCH_TRACE`, `CALL_STUBS`, `CFG`, `CONCRETE_EXECUTION`, `DATAFLOW`, `DYNAMIC_SYMBOLIC`, `EMULATION`, `HEADLESS`, `MEMORY_TRACE`, `REGISTER_TRACE`, `SYMBOLIC`, `TAINT`.

The frozen Stable archive remains unchanged:

```text
701441e07698183f9e7604033ea15f4324599f17dcc5dbed8b271bfa88ad87ef
```

## 3. Harness fixture matrix

14 synthetic harness cases (A–N) executed through the orchestrator against the hash-bound harness document: **14 PASS, 0 FAIL**.

| Case | execution_status | stop_reason | instructions |
| --- | --- | --- | --- |
| A-tainted-length-memcpy | `COMPLETED` | `RETURN` | 4 |
| B-tainted-index | `COMPLETED` | `RETURN` | 3 |
| C-tainted-pointer-to-descriptor | `COMPLETED` | `RETURN` | 2 |
| D-overwrite-clears-taint | `COMPLETED` | `RETURN` | 4 |
| E-caller-saved-clobber | `COMPLETED` | `RETURN` | 5 |
| F-callee-saved-preserved | `COMPLETED` | `RETURN` | 5 |
| G-symbolic-branch | `COMPLETED` | `RETURN` | 5 |
| H-dead-store | `COMPLETED` | `RETURN` | 3 |
| I-dead-stack-slot | `COMPLETED` | `RETURN` | 2 |
| J-validated-length | `COMPLETED` | `RETURN` | 6 |
| K-stale-validation | `COMPLETED` | `RETURN` | 7 |
| L-concrete-safe-invariant | `COMPLETED` | `RETURN` | 5 |
| M-r15-overwrite | `COMPLETED` | `RETURN` | 4 |
| N-rbx-overwrite | `COMPLETED` | `RETURN` | 4 |

Each row is checked against the hand-derived expectation table in `tests/m2b_cases.py`: execution status, stop reason, violation count, sink types, tainted sources, stub behaviours, minimum branch count, per-source sink attribution, memory-write count, rendered constraints, and return value.

## 4. Cross-engine research rows

Three frozen M2-A research cases re-run through the real harness. The dynamic engine adds bounded, offline evidence; it never issues the verdict.

### 4.1 P2-1 (`0x631ad0`, guarded index fragment)

- Native memop proof: `SAFE-INVARIANT`, length `0xA8`, index domain `[0, 1]`, destination slot `0xC0`
- angr: `COMPLETED`, `value_domain == [0, 1]`
- Ghidra: `COMPLETED`
- Native + angr value-domain consensus: `STRONGLY_SUPPORTED` with value `[0, 1]`
- Triton, concrete index values: `r12=0` → branch not taken, `rax=0`; `r12=1` → not taken, `rax=1`; `r12=2` → taken, `rax=0`; `r12=3` → taken, `rax=0`
- Triton status: `ANALYSIS_INCOMPLETE` / `UNMAPPED`. The 18-byte fragment restores no RSP before its `RET`, so the emulated return leaves the harness sentinel; this is a property of the fragment, documented as such, and is **not** evidence about the function
- The Triton P2-1 fragment terminates with `CORRUPTED_STACK_RETURN` because the extracted fragment does not contain the complete epilogue needed to restore the original stack frame. This is treated as a harness-fragment boundary and not as negative evidence about the real function.
- No OOB, no vulnerability, and no exploit claim is produced or altered

### 4.2 CASE-003 (host-side descriptor fragment, base `0x638000`)

- Native secure scan: `CROSS-PROCESSOR-CANDIDATE`, priority `P3`, unknowns include "secure consumer semantics unknown"
- angr: `COMPLETED`; Ghidra: `COMPLETED`
- Triton: `ANALYSIS_INCOMPLETE` / `UNMAPPED`, 26 instructions
- Dynamic taint evidence: `rsi` (tainted descriptor pointer) reaches `MEMORY_ADDRESS` sinks at `0x600008` and `0x600010` — exactly the descriptor field offsets the host-side structure claims
- 3 internal call events, all classified `INTERNAL`; stack-slot and depth evidence recorded per event
- One `CORRUPTED_STACK_RETURN` violation at the `RET` of `0x638041`: the two `call` instructions are call-to-next-instruction idioms and the fragment loops through itself
- Consensus: no shared secure-consumer claim; classification stays `CROSS-PROCESSOR-CANDIDATE`/`P3`. No engine promotes it

### 4.3 SVM (real FW9 kernel image, address `0xffffffffda3c9cb1`)

- Firmware image present and SHA-256 verified: `af3178da72e351368588d30d1ea6e6e1bdc5e6f909cd8226ec7d579dc0255dd4` (13,623,480 bytes, base `0xffffffffd9918000`)
- 64-byte immutable slice: SHA-256 `4833f35951f9f7386db4fb6da74d1db172dbc9aa8c6fba0ba0b8a466cb4fbdff`, matching the frozen M2-A fixture
- Native trace over the **real image**: `SVM-CAPABILITY-ONLY`, candidate `SURF-SVM_HV-278cf3aa83186b93`, priority `P4`, score `0.346`, open chains: 4-KB control-structure evidence, `EFER.SVME` initialization sequence, caller, control structure, initialization, runtime role
- Triton over the real slice: `RESOURCE_LIMIT` / `INSTRUCTION_LIMIT` (32 instructions), no memory violations, no taint source claimed for foreign kernel bytes
- angr: `ANALYSIS_INCOMPLETE` (CFGFast did not recover the requested function)
- Result: no engine confirms the SVM surface. `ANALYSIS_INCOMPLETE` and `RESOURCE_LIMIT` are recorded as missing analysis, never as a negative SVM claim

## 5. Evidence discipline

- Only `COMPLETED` backend results participate in consensus voting. `PARTIAL`, `ANALYSIS_INCOMPLETE`, `TIMEOUT`, `RESOURCE_LIMIT`, `ERROR`, and `BACKEND_UNAVAILABLE` results provide diagnostic evidence only, do not vote, and are never read as refutation.
- Dynamic evidence is offline-only: the evidence model rejects any provenance other than `emulated`/`symbolic`/`static`, so a backend can never manufacture runtime evidence or a `CONFIRMED` claim.
- A dynamic record is hash-bound: binary SHA-256, harness SHA-256, input SHA-256, stub-registry version, backend version, OrbisProbe version, base address, operation, and resource limits all participate in the cache key.
- Large traces are referenced by SHA-256, never inlined; inline lists are capped.
- Call evidence distinguishes `INTERNAL`, `REGISTERED_STUB`, `INDIRECT_CALL_UNRESOLVED`, and `INVALID_CALL_TARGET`; return evidence distinguishes the harness return from `EARLY_SENTINEL_RETURN`, `CORRUPTED_STACK_RETURN`, `CALL_STACK_UNDERFLOW`, `CONTROL_FLOW_CONFLICT`, `INVALID_RETURN_TARGET`, and `UNSUPPORTED_RETURN_FORM`.
- Branch evidence carries the executed decision (`taken`), `next_rip`, and `fallthrough`; `constraints` is empty for a purely concrete condition and that is not an error.

## 6. Defects found by the real-harness pass

Both defects were found by the first real-harness run of P2-1/CASE-003/SVM, are independent of the earlier CALL/RET work, and were fixed and re-verified within this checkpoint.

### 6.1 Memory taint ranges crashed the worker

A taint source covering more than one Triton-legal access was passed as a single `MemoryAccess`, raising an uncaught `TypeError`. Measured boundary before the fix:

```text
1, 2, 4, 8, 16, 32, 64      COMPLETED
17, 20, 24, 48, 63, 96, 128, 256   ERROR  TypeError: MemoryAccess::MemoryAccess(): size must be aligned.
```

Consequence: a harness that taints a realistic 128-byte descriptor region was not executable. The failure was isolated (structured `ERROR`, no fabricated result) but not a classified harness rejection.

Fix: taint ranges are decomposed into naturally aligned legal chunks (`64, 32, 16, 8, 4, 2, 1`); symbolic memory inputs use the same chunking. Regression: `1, 2, 4, 8, 16, 20, 24, 32, 48, 63, 64, 96, 128, 256` bytes all execute, plus a harness-level 128-byte range run.

### 6.2 Conditional-branch evidence always reported `taken`

Every conditional branch was recorded with a hardcoded `taken: True`, so a non-taken branch was indistinguishable from a taken one. Counter-proof from the P2-1 run with `r12=0`:

```text
recorded: {"address": 0x631ad8, "instruction": "ja 0x631adf", "taken": true}
executed: push rbp / mov rbp,rsp / cmp r12,1 / ja / mov rax,r12 / nop / ret
```

The fall-through instruction executed, and `rax` kept the index value; the branch was not taken.

Fix: `taken = post_instruction_rip != fallthrough` with `next_rip` and `fallthrough` stored in the record. Regression: a concrete value below the guard reports `taken=false`, a value above it reports `taken=true`; the P2-1 guard is additionally checked for `r12 = 0, 1, 2, 3` including instruction counts and return values.

## 7. Performance and cache

Measured on this host, offline, with the pinned environments (single run, median/max only):

```text
harness cold (empty cache)   0.457 s
harness warm (cache hit)     0.123 s
triton   median 0.441 s   max 0.466 s   (14 samples)
angr     median 0.938 s   max 1.185 s   (3 samples)
ghidra   median 8.682 s   max 8.795 s   (2 samples)
```

Cache regression (identical harness, identical cache directory):

```text
first run  cache_hits = []
second run cache_hits = ["triton"]
records identical      true
harness SHA-256        852706c5ab064941be061f6eafc9c81a7061bd2d63c8b60f9e258e864103337a
```

## 8. Reproducing

```bash
export ORBISPROBE_TRITON_PYTHON=.backend-envs/triton/bin/python
export ORBISPROBE_ANGR_PYTHON=.backend-envs/angr/bin/python
export ORBISPROBE_GHIDRA_HOME=/home/hermes/tools/ghidra_12.1.3_PUBLIC

python3 -m pytest -q tests/test_m2b_internal_calls.py tests/test_m2b_triton.py
python3 -m pytest -q
ruff check .

python3 scripts/run_m2b_matrix.py --out evidence/m2b-cross-engine.json
```

`evidence/m2b-cross-engine.json` is generated evidence and is git-ignored; the committed tree carries the runners, the fixtures, and the tests that assert every number in this report.

## 9. Known limitations

- B1 explores a single primary concrete path; alternate branches are not explored, and this is recorded as an explicit unknown on every dynamic run.
- The P2-1 and CASE-003 inputs are firmware-derived fragments without an epilogue that restores RSP; their `UNMAPPED` stop is a harness property, not a finding.
- The SVM slice is 64 bytes of a foreign kernel image with no caller, control structure, or initialization sequence in scope.
- Triton legal access sizes are bounded (powers of two up to 64 bytes); larger regions are chunked, which can split one semantic access into several taint entries.
- Ghidra analysis dominates runtime; it runs in a bounded mode and reports `FULL_ANALYSIS`/`BOUNDED_ANALYSIS`/`PARTIAL_ANALYSIS` accordingly.
- Binary Ninja remains `BACKEND_UNAVAILABLE`.

## 10. Next checkpoint

CASE-003, SVM, and P2-1 were re-run through the real harness for this checkpoint. Qiling, AFL++, PANDA, S2E, Binary Ninja integration, and any live or persistent-state work remain out of scope and were not started.
