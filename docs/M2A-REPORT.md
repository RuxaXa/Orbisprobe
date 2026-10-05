# OrbisProbe M2-A final-closure verification report

## Verdict before independent review

**Implementation gates: PASS. Independent immutable-snapshot review and final checkpoint commit: pending.**

The final user-facing verdict is not issued by this file. It is issued only after the exact tree documented here receives an independent `PASS` and is committed without modification.

## 1. Architecture

OrbisProbe remains the orchestrator, policy engine, evidence store, candidate graph, experiment planner, and classification layer. M2-A adds optional, bounded analysis backends:

- Native Capstone (`capstone-native`)
- angr/VEX/Claripy (`angr-vex`)
- Ghidra Headless/P-code (`ghidra-pcode`)
- Binary Ninja is optional and currently `BACKEND_UNAVAILABLE`

Backends emit atomic evidence. They cannot inject `CONFIRMED`. Only `COMPLETED` results vote. `ANALYSIS_INCOMPLETE`, `TIMEOUT`, `ERROR`, `BACKEND_UNAVAILABLE`, `RESOURCE_LIMIT`, and `PARTIAL` do not vote.

No Triton, Qiling, AFL++, PANDA, S2E, PS4 transport, or live-target action is part of this checkpoint.

## 2. Engine versions and Capstone resolution

- Native Capstone distribution: `5.0.9`
- angr: `9.2.184`
- Ghidra: `12.1.3`

The pinned Capstone wheel/distribution is `5.0.9`. Its upstream Python module exposes the stale internal string `capstone.__version__ == 5.0.7`; OrbisProbe deliberately uses `importlib.metadata.version("capstone") == "5.0.9"` for backend identity and cache keys. A regression test requires the installed distribution and Native backend identity to both be `5.0.9`.

The frozen Stable archive remains unchanged:

```text
701441e07698183f9e7604033ea15f4324599f17dcc5dbed8b271bfa88ad87ef
```

## 3. Consensus regression

Explicit tests cover:

- independent support(X) + support(X) → `STRONGLY_SUPPORTED`
- support(X) + refute(X) → `EVIDENCE_CONFLICT`
- independent refute(X) + refute(X) → `DISPROVED`
- support(X) + support(Y) → `EVIDENCE_CONFLICT`
- `COMPLETED` + `ANALYSIS_INCOMPLETE` → incomplete result does not vote
- `TIMEOUT`, `ERROR`, `BACKEND_UNAVAILABLE`, `RESOURCE_LIMIT`, and `PARTIAL` → no vote
- duplicate independence family → one independent source
- backend attempt to inject `CONFIRMED` → rejected

There is no majority vote across contradictory evidence.

## 4. angr incomplete semantics

A 64-byte immutable regression slice from the real FW9 SVM address is recorded in `tests/fixtures/m2a/fw900_svm_angr_incomplete.json` with:

- source binary SHA-256: `af3178da72e351368588d30d1ea6e6f909cd8226ec7d579dc0255dd4`
- function VA: `0xffffffffda3c9cb1`
- slice SHA-256: `4833f35951f9f7386db4fb6da74d1db172dbc9aa8c6fba0ba0b8a466cb4fbdff`

Expected and observed result:

```text
ANALYSIS_INCOMPLETE
unknown: CFGFast did not recover the requested function
no evidence vote
```

It is not `COMPLETED`, `DISPROVED`, or a negative SVM claim.

## 5. Ghidra analysis modes

Every Ghidra analysis result is marked:

- `FULL_ANALYSIS`
- `BOUNDED_ANALYSIS`
- `PARTIAL_ANALYSIS`

Large raw binaries use bounded `-noanalysis`, followed by explicit target-function disassembly and definition. Regression coverage verifies:

- exact target entry VA and instruction range
- target P-code including `LOAD`, `STORE`, and `CALL`
- direct call target preservation
- register varnodes
- stack memory operations
- decompiler output
- effective capability list

Ghidra does not advertise SSA. Item ceilings, nonzero exits, malformed/truncated output, timeouts, and oversized output are `PARTIAL_ANALYSIS` or fail closed; partial results do not vote.

## 6. Final fixture matrix

Evidence:

```text
evidence/m2a-fixture-matrix-final-v4.json
SHA-256 c434c58adc00a812d2d9b524f54de00e4029950a6e644a82175a4c602c8cdb76
```

Result:

```text
17 fixtures
17 PASS
0 FAIL
0 consensus conflicts
```

Rows:

- P2-1 — Native/angr/Ghidra `COMPLETED`; PASS
- CASE-003 — Native/angr/Ghidra `COMPLETED`; PASS
- r15 overwrite — Native/angr/Ghidra `COMPLETED`; PASS
- rbx overwrite — Native/angr/Ghidra `COMPLETED`; PASS
- stale EAX — Native/angr/Ghidra `COMPLETED`; PASS
- stale EDX — Native/angr/Ghidra `COMPLETED`; PASS
- call clobber — Native/angr/Ghidra `COMPLETED`; PASS
- callee-saved propagation — Native/angr/Ghidra `COMPLETED`; PASS
- dead stack slot — Native/angr/Ghidra `COMPLETED`; PASS
- dead store — Native/angr/Ghidra `COMPLETED`; PASS
- getter `0xc92aae80` — Native/angr/Ghidra `COMPLETED`; PASS
- tag `0xF`, limit `0x400`, snapshot offset `0x18` — Native/angr/Ghidra `COMPLETED`; PASS
- user pointer → descriptor — Native/angr/Ghidra `COMPLETED`; PASS
- safe memcpy — Native `COMPLETED`; angr/Ghidra `NOT_APPLICABLE` to fact-only fixture; PASS
- real overflow — Native `COMPLETED`; angr/Ghidra `NOT_APPLICABLE`; PASS
- index OOB — Native `COMPLETED`; angr/Ghidra `NOT_APPLICABLE`; PASS
- stale validation — Native `COMPLETED`; angr/Ghidra `NOT_APPLICABLE`; PASS

`NOT_APPLICABLE` is explicit abstention: those four invariant fixtures contain facts rather than executable bytes.

## 7. P2-1

Final result:

- Native: `SAFE-INVARIANT`
- length: `0xA8`
- index domain: `{0,1}`
- destination slot: `0xC0`
- angr: `{0,1}`
- Ghidra: control/P-code structure consistent
- Native + angr value-domain consensus: `STRONGLY_SUPPORTED`
- no OOB or vulnerability candidate

## 8. CASE-003

Final result:

- host descriptor recognized
- repeated host-side reads recognized
- address-like field recognized
- Native classification: `CROSS-PROCESSOR-CANDIDATE`, P3
- Secure consumer and Secure validation: `UNKNOWN`
- no confirmed exploit
- no arbitrary-address primitive claim
- no confirmed Secure OOB

## 9. Register lifetime

- r15 overwrite: old provenance does not reach consumer; angr value `{0}`; lifetime `STRONGLY_SUPPORTED = false`
- rbx overwrite: old provenance does not reach consumer; angr value `{0}`; lifetime `STRONGLY_SUPPORTED = false`
- stale EAX: remains `SVM-CAPABILITY-ONLY`
- stale EDX: remains `SVM-CAPABILITY-ONLY`
- call clobber: caller-saved provenance terminated
- callee-saved propagation: rbx provenance retained
- dead slot/dead store: no artificial consumer
- `call-clobber` and `callee-saved-propagation` results are now explicitly `partial` with the ABI
  assumption surfaced as an unknown, because an unknown callee is assumed to preserve callee-saved
  registers. No claim is presented as a completed proof.

## 10. FW9 final multi-engine run

Input:

```text
SHA-256 af3178da72e351368588d30d1ea6e6e1bdc5e6f909cd8226ec7d579dc0255dd4
Base 0xffffffffd9918000
```

Cold evidence:

```text
evidence/fw900-m2a-multi-engine-final-v4.json
SHA-256 f65b0dbb30a309581ce34bf1166c41b83f5e38717a5bf4b01b58857357d11e43
```

Warm-cache evidence:

```text
evidence/fw900-m2a-multi-engine-warm-v4.json
SHA-256 1328d1782c7fe8a0f4855873e232d15abbaf2880075b6e3645156a78f91ef8fd
```

Per track:

- SVM
  - classification: `SVM-CAPABILITY-ONLY`, P4
  - candidates: 1
  - Native: `COMPLETED`, Capstone `5.0.9`
  - angr: `ANALYSIS_INCOMPLETE`, one incomplete result, no vote
  - Ghidra: `COMPLETED`, `BOUNDED_ANALYSIS`
  - conflicts: 0
  - cold backend times: angr 4.254 s; Ghidra 8.048 s
- IOMMU
  - classification: `IOMMU-STRUCTURAL-CANDIDATE`, P4
  - candidates: 1
  - Native/angr/Ghidra: `COMPLETED`
  - Ghidra: `BOUNDED_ANALYSIS`
  - conflicts: 0
  - cold backend times: angr 3.805 s; Ghidra 12.617 s
- Secure
  - classification: `SECURE-NONE`
  - candidates: 0
  - Native scanner: `COMPLETED`
  - angr/Ghidra: `NOT_RUN` because no surface was promoted for backend follow-up
  - consensus: no claims
  - conflicts: 0
- Memory controller
  - classification: `MEMCTL-ADDRESS-MAP-CANDIDATE`, P4
  - candidates: 1
  - Native/angr/Ghidra: `COMPLETED`
  - Ghidra: `BOUNDED_ANALYSIS`
  - conflicts: 0
  - cold backend times: angr 3.666 s; Ghidra 12.651 s

No incomplete result is hidden or treated as negative evidence.

## 11. M1 → M2-A false-positive delta

- SVM: 1 candidate → 1 candidate; classification unchanged
- IOMMU: 1 → 1; classification unchanged
- Secure: 0 → 0; classification unchanged
- MemCtl: 1 → 1; classification unchanged

Delta is zero. M2-A added independent structural analysis and explicit incomplete states; it did not silently filter candidates or reduce recall. Secure stayed at zero because M1 had already removed its pattern-only false positives. No change is attributed to “better analysis” unless a backend emitted a matching atomic claim.

## 12. Performance

Fixture matrix wall time: 130.158 s.

Per-fixture backend samples:

- Native: median 0.000695 s; range 0.000010–0.001555 s; 17 samples
- angr: median 0.951058 s; range 0.917834–1.212566 s; 13 samples
- Ghidra: median 8.805571 s; range 8.432009–9.191354 s; 13 samples

FW9:

- cold wall time: 50.870 s
- warm wall time: 4.798 s
- angr timeouts: 0
- angr incomplete: 1 (SVM)
- Ghidra timeout: 0
- Ghidra mode: three bounded follow-ups, zero full, zero partial
- warm run: Native/angr/Ghidra cache hit on all three promoted surfaces

These are orchestration measurements, not precision microbenchmarks.

## 13. Cache validation

Cache keys and load validation cover:

- binary SHA-256
- backend version
- OrbisProbe version
- base address
- operation and analysis parameters
- resource limits
- adapter code fingerprint
- angr worker fingerprint
- Ghidra script fingerprint

Tampered cached backend identity/version is rejected. Invalid JSON and request-material mismatch are misses. No stale result reuse was observed; the final warm run hit only the exact cold-run requests.

Cache entries are HMAC-SHA256 authenticated with a per-cache-root 256-bit integrity key stored with
mode `0600`; altered result evidence is rejected before deserialization or voting. This does not
claim protection from a process already running as the same OS user.

External backend output is additionally constrained to a source-class allowlist (`static`,
`symbolic`, `inferred`, `unattributed`, `fixture`). A backend cannot declare `runtime_real`, so no
engine process can promote a claim to `CONFIRMED`; only OrbisProbe's own runtime-collection channel
can supply runtime evidence.

That runtime channel is enforced structurally as well: `runtime_real` is honoured only from adapter
identities in `RUNTIME_CHANNELS`. A runtime claim from any other adapter is ignored for promotion
and recorded as an unknown. Evidence `address` values are constrained to integer or `null`, so the
one remaining unvalidated evidence field can no longer break strict serialisation or consensus.
Per-backend isolation now covers adapter construction, availability probing, cache fingerprinting,
argument coercion, and the analysis call, so a broken adapter cannot abort a multi-engine run at any
of those points.

Non-finite JSON constants (`NaN`, `Infinity`) and values that are not strict-JSON representable are
rejected at the adapter boundary. Should such a value ever reach the consensus layer, it is excluded
from voting and reported in `excluded_evidence` instead of aborting the run. A backend adapter that
raises is converted into a structured `ERROR` result for that engine only; the remaining engines
still run and still contribute consensus.

## 14. External-output and isolation regression

Tests cover:

- malformed and truncated angr JSON
- malformed and truncated Ghidra JSON
- syntactically valid but structurally invalid non-object/wrong-schema backend JSON
- nested wrong-shaped P-code/instruction item fields (null, string, object, bool addresses or opcodes)
- non-finite JSON constants (`NaN`, `Infinity`, `-Infinity`) in worker and Ghidra output
- backend-declared `runtime_real` provenance
- a backend adapter that raises mid-run (isolated as `ERROR`, other engines continue)
- an adapter whose cache fingerprint or construction raises (isolated as `ERROR`)
- evidence `address` values that are non-integer, non-finite, or boolean
- output larger than 16 MiB
- backend nonzero exit
- timeout
- missing binary
- invalid base
- shell-metacharacter filename
- missing backend/interpreter

The core returns structured `ERROR`, `PARTIAL`, `TIMEOUT`, `RESOURCE_LIMIT`, or `BACKEND_UNAVAILABLE` without crashing or voting failed evidence. Subprocesses use argv with `shell=False`.

## 15. Verification gates

The closing source-tree gate after the cache/output-validation fixes is:

```text
213 passed
Ruff: All checks passed
git diff --check: passed
```

The immutable replacement snapshot is tested independently before review. Earlier test counts are intentionally not treated as closure evidence.

## 16. Review and checkpoint identity

The immutable snapshot manifest, independent review verdict, final commit, and tree hash are recorded externally after review. This file is part of the reviewed tree and is not rewritten after review.

## 17. Technical debt

1. Ghidra P-code is not claim-specific SSA lifetime evidence; Ghidra does not vote on such claims.
2. angr raw-blob models omit PS4 kernel runtime state and external callee semantics.
3. angr cannot recover the exact FW9 SVM function and correctly returns `ANALYSIS_INCOMPLETE`.
4. CASE-003 Secure-side semantics remain unavailable.
5. Native CFG remains intentionally heuristic.
6. Real-target runtime evidence was not collected; no M2-A claim is runtime-confirmed.
7. The register-lifetime model assumes SysV AMD64 semantics, assumes an unknown callee preserves
   callee-saved registers, and does not model `syscall`/`sysenter`/`int` clobbering of `rcx`/`r11`.
   These assumptions are surfaced as unknowns and force `proof_complete = false`, but they are not
   resolved.
8. A Ghidra P-code operation without an address is reported as `<opcode>@unknown` rather than
   dropped, so the missing address is visible instead of silently reconstructed.

## Stop condition

After an independent `PASS` and final exact-tree commit, M2-A stops. M2-B is not started automatically.