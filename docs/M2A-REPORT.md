# OrbisProbe M2-A verification report

## Verdict

**M2-A implementation candidate: complete and locally green; independent review pending.**

This milestone is development-only. It does not promote v0.2 to stable and does not alter frozen `0.1.1+hermes.2`.

## Scope and safety

- Branch: `v0.2-m2a`
- Version: `0.2.0.dev2`
- Offline analysis only
- No PS4 or other live target contacted
- No live read, write, reboot, HEN, or persistence experiment
- No Triton, Qiling, AFL++, PANDA, or S2E runtime integration
- Binary Ninja unavailable; no license bypass attempted

The frozen stable archive remained:

```text
701441e07698183f9e7604033ea15f4324599f17dcc5dbed8b271bfa88ad87ef
```

## Implemented engines

- Native Capstone, independence family `capstone-native`
- angr 9.2.184, independence family `angr-vex`
- Ghidra 12.1.3 Headless/P-code, independence family `ghidra-pcode`
- Binary Ninja represented as optional `BACKEND_UNAVAILABLE`

angr runs in a separate Python environment and process. Ghidra runs as a bounded external headless process. Neither is a mandatory core dependency.

## Verification gates

Final source-tree gate:

```text
156 passed in 105.14s
Ruff: All checks passed
Git diff whitespace check: passed
```

Targeted consensus gate:

```text
10 passed
```

The test suite covers:

- backend API and capability declarations;
- unavailable/incomplete/error/timeout results;
- cache isolation and adapter/worker fingerprint invalidation;
- Native register lifetime and call clobber;
- angr CFGFast, ReachingDefinitions, dependency edges, symbolic domains, high kernel bases, and timeout handling;
- Ghidra function/P-code export, bounded large-image mode, missing backend behavior, and API views;
- independence-family quorum, conflict detection, support/refutation contradiction, refutation, and status-injection rejection;
- CLI and privilege-surface backend integration;
- P2-1, CASE-003, overwrite, dead-slot, getter, tag/limit, and memop regressions.

## Packaging gates

A fresh editable core installation succeeded without installing angr into the core environment.

A wheel was built and checked to contain both external integration artifacts:

```text
orbisprobe/backends/workers/angr_worker.py
orbisprobe/backends/ghidra_scripts/OrbisProbeExport.java
```

Wheel SHA-256 from the final local gate:

```text
9136dc73db3e37e5c7e36ea189955640af23225312179a21e0e0c0a0ee89d4da
```

The deterministic source archive was generated twice byte-for-byte identically. Its final digest is recorded with the immutable review snapshot rather than embedded here, avoiding a self-referential archive hash.

The source archive is a development artifact, not a stable release.

## Cross-engine fixture results

Evidence file:

```text
evidence/m2a-fixture-matrix.json
SHA-256 005949182bb7d57e95656d843aa6b86d766d236dc480896e5d36b1b8d7668d11
```

### P2-1 / `0x631ad0`

- Native memop verdict: `SAFE-INVARIANT`
- Length: `0xA8`
- Index domain: `{0,1}`
- Destination slot size: `0xC0`
- angr symbolic domain: `{0,1}`
- Native + angr value-domain consensus: `STRONGLY_SUPPORTED`
- Ghidra confirms the branch/P-code shape but is not counted as an independent domain solver.
- Result: no false OOB finding.

### CASE-003

- Native classification: `CROSS-PROCESSOR-CANDIDATE`, P3
- angr and Ghidra independently recover relevant local memory/control structure.
- Secure-side consumer behavior and validation remain unknown.
- Result: candidate retained; no exploit or runtime claim.

### Register overwrite regressions

For both `r15` and `rbx` fixtures:

- Native finds that old provenance does not reach the consumer.
- angr resolves the overwritten value domain to `{0}`.
- Register-lifetime result is `STRONGLY_SUPPORTED = false` across Native and angr.
- No consensus conflict occurred.

### Dead stack slot

The test is slot-specific. It permits the legitimate `RET` stack load while proving that `[rbp-0x90]` is written and not subsequently consumed.

### Runtime cost on fixtures

Observed approximate wall-clock ranges:

- Native: about 0.001 s
- angr: about 1.4–2.4 s for the final recorded matrix cases
- Ghidra: about 14–18 s

All four recorded comparison cases completed with zero consensus conflicts.

## FW9 RX multi-engine comparison

Input:

```text
/home/hermes/session-handoffs/20260921_ps4b-soc-independent-analysis/kernel/fw900-kernel-rx.bin
SHA-256 af3178da72e351368588d30d1ea6e6e1bdc5e6f909cd8226ec7d579dc0255dd4
Base 0xffffffffd9918000
```

Evidence file:

```text
evidence/fw900-m2a-multi-engine.json
SHA-256 5e91d9efb9930b96ba0be2da2f0b7a27efe49dc0c10d207d11e745113e8ec051
```

M1 classifications remained unchanged:

- SVM: `SVM-CAPABILITY-ONLY`, P4
- IOMMU: `IOMMU-STRUCTURAL-CANDIDATE`, P4
- Secure: no promoted surface
- Memory controller: `MEMCTL-ADDRESS-MAP-CANDIDATE`, P4

Backend outcomes:

- SVM:
  - Native: `COMPLETED`
  - angr: `ANALYSIS_INCOMPLETE` because CFGFast did not recover the exact requested function
  - Ghidra: `COMPLETED`
- IOMMU:
  - Native, angr, and Ghidra: `COMPLETED`
- Memory controller:
  - Native, angr, and Ghidra: `COMPLETED`

No FW9 consensus conflict was emitted. The incomplete SVM angr result did not vote and did not block the other engines.

Observed uncached backend times for the three surfaces:

- angr: approximately 4.4 s, 6.5 s, and 6.0 s
- Ghidra: approximately 10.4 s, 26.5 s, and 24.1 s

A repeated identical run produced cache hits for Native, angr, and Ghidra on all three surfaces.

## False-positive and conflict assessment

- P2-1 remained safe.
- CASE-003 did not become an exploit claim.
- Dead stores did not become artificial consumers.
- `r15`/`rbx` overwrite terminated old provenance.
- Same-family evidence did not create false quorum.
- Complete support/refutation contradictions are conflicts, never majority-voted.
- Missing, errored, timed-out, or incomplete engines do not promote a claim.
- No conflict occurred in the recorded fixture or FW9 matrices.

## Technical unknowns and debt

1. Ghidra raw P-code export is not yet a claim-specific SSA register-lifetime proof and therefore does not vote on those claims.
2. angr raw-blob execution omits the PS4 kernel runtime environment and external callee semantics.
3. angr did not recover the exact FW9 SVM function; this is truthfully `ANALYSIS_INCOMPLETE`.
4. CASE-003 secure-side behavior is unavailable.
5. Native CFG is intentionally heuristic; deeper CFG/SSA evidence comes from external backends.
6. Real-target runtime evidence was not collected, so no M2-A result is runtime-confirmed.

## Conclusion

M2-A adds a bounded, optional, evidence-first multi-engine layer while preserving M1 classifications and the frozen stable branch. Local implementation, regression, packaging, deterministic-artifact, fixture, cache, and FW9 gates are green. Final acceptance requires an immutable snapshot and independent review.