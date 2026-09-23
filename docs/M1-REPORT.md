# OrbisProbe v0.2-M1 report

## Status

M1 implements an offline-only privilege-surface discovery layer on the separate `v0.2-dev` branch. The frozen `0.1.1+hermes.2` stable baseline was not modified.

- Development version: `0.2.0.dev1`
- Development tree: `/home/hermes/tools/orbisprobe-v0.2-dev`
- M1 candidate commit: `85a8541d3227dda3ffa1824f4bad2914c448c95c`
- Candidate tree: `98a365ca62a15ba49ed7c463fffabb91d1fd1a9b`
- Execution tier: offline only
- PS4 contact: none
- Target requests: none
- Writes: none
- Persistent-state hard-block: unchanged

## Architecture

The architecture is documented in `docs/M1-ARCHITECTURE.md`. M1 adds:

- immutable raw-binary identity and VA-domain address handling;
- candidate-localized x86-64 decoding;
- definition/overwrite/call-clobber/consumer lifetime tracing;
- common surface/status/confidence/evidence models;
- deterministic research graphs;
- P1–P4 candidate triage;
- SVM/HV, IOMMU/DMA, SAMU/secure, and memory-controller tracks;
- human and JSON `privilege-surface` reports.

The central claim chain is:

```text
controlled source
-> validation
-> privilege boundary
-> privileged consumer
-> observable effect
```

Missing links are emitted as unknowns/open chains. Pattern hits remain evidence, not findings.

## Implemented CLI

```text
orbisprobe privilege-surface svm IMAGE
orbisprobe privilege-surface iommu IMAGE
orbisprobe privilege-surface secure IMAGE
orbisprobe privilege-surface memctl IMAGE
orbisprobe privilege-surface all IMAGE
```

Common options:

- `--base`
- `--architecture`
- `--json`
- `--out`

M1 does not expose target contact or new experiment execution.

## Verification

Local candidate gates before independent review:

- Pytest: `110 passed`
- Ruff: `All checks passed!`
- Python compileall: passed
- Stable v0.1.1 test suite remains included and green
- Unsupported architecture, malformed/truncated images, invalid addresses, register overwrite, call-clobber, split-function patterns, memory-read/write classification, and evidence caps are covered.

The first immutable review found five material false-positive/graph-overclaim classes. Commit `b0fa5fb`
closed those classes. A second review found one remaining stale-EAX/function-boundary SVM issue;
commit `85a8541` adds lifetime and locality proofs. The final closure-review result is recorded in the
acceptance section.

## Fixture results

### P2-1 `0x631ad0`

Input facts:

- operation: `memcpy`
- length: invariant `0xA8`
- index domain: `{0,1}`
- destination slot: `0xC0`
- length mutable: false

Result:

- verdict: `SAFE-INVARIANT`
- remaining extent: `0x18`
- false OOB candidate: suppressed

### CASE-003

Recognized evidence:

- descriptor size/stride `0x80`
- tags 7, 8, and 9
- address-like field at `+8`
- operation field at `+0x10`
- fixed `0x30/0x54` message sizes
- repeated reads of `+0x28/+0x30/+0x38` across a call

Result:

- classification: `CROSS-PROCESSOR-CANDIDATE`
- status: `SUPPORTED`
- priority: `P3`
- secure consumer semantics: unknown
- secure-side validation: unknown
- runtime effect/oracle: unknown
- exploit claim: none

Fixture evidence:

- `/home/hermes/tools/orbisprobe-v0.2-dev/evidence/fixture-results.json`
- SHA-256: `ab655a9529a0ea38a3c43c1f9487c7f33931b2b21b7a0cd66dc79aeb322b01ee`

## FW9 RX offline example

Input:

- path: `/home/hermes/session-handoffs/20260921_ps4b-soc-independent-analysis/kernel/fw900-kernel-rx.bin`
- SHA-256: `af3178da72e351368588d30d1ea6e6e1bdc5e6f909cd8226ec7d579dc0255dd4`
- size: `13,623,480` bytes
- runtime base: `0xffffffffd9918000`

Command:

```bash
orbisprobe privilege-surface all fw900-kernel-rx.bin \
  --base 0xffffffffd9918000 --architecture x86_64 --json
```

Machine report:

- `/home/hermes/tools/orbisprobe-v0.2-dev/evidence/fw900-privilege-surface-all.json`
- SHA-256: `d6ca52c94c0b6e54e30f48ca5cdf0ea251ba892e0236f0d38cfb089e9ca42cf6`

Human report:

- `/home/hermes/tools/orbisprobe-v0.2-dev/evidence/fw900-privilege-surface-all.md`
- SHA-256: `7512c787c2162570563dfcb0fc40b87e60ed11bf8c7e0f87db0eaf2dd597e714`

### Surfaces

#### SVM/HV

- classification: `SVM-CAPABILITY-ONLY`
- priority: `P4`
- status/confidence: `SUPPORTED/LOW`
- anchor: decoded `SKINIT` plus EFER accesses
- not established: EFER.SVME initialization, VMCB provenance, caller, active runtime role
- conclusion: no active-hypervisor claim

#### IOMMU/DMA

- classification: `IOMMU-STRUCTURAL-CANDIDATE`
- priority: `P4`
- status/confidence: `UNKNOWN/LOW`
- evidence classes: mapping strings, decoded `0xa70`, decoded `+0xa70` displacement, shared-DDR `0xc0000000`, nearby actual memory write
- not established: controlled source, mapping validation, translation root, device/domain identity, hardware consumer, runtime reachability
- conclusion: structural audit candidate only

#### SAMU/secure

- classification: `SECURE-NONE`
- promoted surfaces: `0`
- partial same-window patterns were retained only as a diagnostic
- repeated CASE-003 mutable-read chain: not established in the FW9 scan result
- secure consumer/effect: unknown

#### Memory controller

- classification: `MEMCTL-ADDRESS-MAP-CANDIDATE`
- priority: `P4`
- status/confidence: `UNKNOWN/LOW`
- evidence: decoded `0xCF8/0xCFC` IN/OUT sequences and Family-16h address-map MSR anchors
- not established: target-silicon register semantics, lock/protection state, runtime reachability, effective translation
- no live manipulation proposed

## Known false positives and suppressions

During M1 development, the first broad secure matcher combined unrelated function windows and emitted 28 P3 candidates. The first review then demonstrated five blocking classes: pattern-only IOMMU promotion, write-only secure fields treated as reads, cross-jump secure combination, unrelated-register/global SVM initialization, and unproven graph edges. The final matcher set:

- isolates candidate function windows;
- requires all tags 7/8/9;
- requires `+8` and `+0x10` on a shared base context;
- requires repeated `+0x28/+0x30/+0x38` fields across a call for P3;
- downgrades host-only chains to P4;
- caps candidate windows and reports the cap.
- promotes IOMMU only when decoded constant evidence, at least two string categories, and an actual memory write coexist;
- records secure repeated reads only for operands carrying Capstone read access;
- terminates secure linear windows at unconditional jumps;
- requires EFER bit setting on EAX/RAX and local SVM initialization;
- emits semantic graph edges only for directly decoded MemCtl reads/writes; open chains remain edge-free.

The final FW9 scan promotes no secure surface rather than 28 cross-processor candidates.

Additional suppressions:

- generic EFER access no longer implies SVM initialization;
- ECX/DX provenance stops at calls and overwrites;
- memory reads are not labeled descriptor writes;
- string anchors are not treated as function names;
- P2-1 table invariants suppress the prior overflow false positive.

## Technical debt

- no full CFG/function recovery;
- conditional merges remain explicit unknowns;
- no public `analyze-dataflow` CLI yet;
- no string-to-code xref resolver;
- no IOMMU device-table/domain decoder;
- no VMCB parser or VMEXIT dispatcher reconstruction;
- SVM `ACTIVE-SUBSYSTEM` is intentionally not emitted by M1;
- secure candidate scan has a 512-window cap and may miss later candidates;
- getter-only `0xc92aae80`, dead-slot `[rbp-0x90]`, and Tag-0xF differential fixtures are deferred;
- no live validation or v0.2 experiment integration.

## Acceptance

The first immutable review of commit `b2dcaf3` correctly returned `FAIL`. The first closure review of
`b0fa5fb` correctly found the remaining SVM EAX-lifetime/function-locality defect. The final closure
candidate is commit `85a8541` with manifest SHA-256
`69f3242cc23231978593a5c2e36d2743374bbfd5cdfba9d627ec937a4ad17593`.

Final independent verdict: `PASS`.

- Manifest: 61/61 files matched hashes and sizes before/after review.
- Commit/tree: `85a8541d3227dda3ffa1824f4bad2914c448c95c` / `98a365ca62a15ba49ed7c463fffabb91d1fd1a9b`.
- Full no-cache suite: `110 passed`.
- Ruff: `All checks passed!`.
- Targeted scanner/stable-safety gate: `23 passed`.
- Adversarial SVM: valid EAX/RAX chains remain initialized; stale EAX, stale EDX, post-OR call, and split-function HSAVE remain capability-only.
- FW9: SVM capability-only P4, IOMMU structural P4, secure none, MemCtl address-map P4.
- Graph: no unproven SVM/IOMMU/secure semantic edges; MemCtl edges reflect decoded read/write operations only.
- Live/PS4 contact: none.

M1 is accepted as an offline development milestone. It is not a stable v0.2 release and does not
authorize live integration. Any further code change requires new tests, Ruff, FW9 scan, and review.
