# Changelog

## 0.2.0.dev2 — M2-A multi-engine analysis

- Added a capability-based backend API with structured availability, timeout, resource, partial, and error states.
- Added a SHA-256/version/base/parameter-bound analysis cache.
- Added Native Capstone, isolated angr 9.2.184, and Ghidra 12.1.3 Headless/P-code backends.
- Added bounded angr CFGFast, ReachingDefinitions, dependency, symbolic-domain, and path-constraint analysis.
- Added Ghidra function, call, xref, P-code, memory, parameter, stack, and decompiler export.
- Added independence-aware consensus and `EVIDENCE_CONFLICT` handling.
- Added `backends`, `analyze-dataflow`, `prove-path`, and `privilege-surface --backend` CLI integration.
- Added shared P2-1, CASE-003, overwrite, dead-slot, getter, Tag-0xF, memop, and synthetic dataflow fixtures.
- Kept Binary Ninja optional/unavailable and deferred Triton, Qiling, AFL++, PANDA, and S2E.

## 0.2.0.dev1 — M1

- Added the common privilege-surface model, evidence statuses, deterministic IDs, and P1–P4 triage.
- Added an internal research graph with typed nodes, edges, and bounded path queries.
- Added candidate-localized offline SVM/HV, IOMMU/DMA, SAMU/secure, and memory-controller scanners.
- Added x86-64 definition/overwrite/call-clobber/consumer lifetime tracing.
- Added `privilege-surface svm|iommu|secure|memctl|all` with human and JSON output.
- Added P2-1 `0x631ad0` and CASE-003 regression fixtures.
- Added malformed, truncated, unsupported-architecture, invalid-address, call-clobber, and false-positive tests.
- Kept all live access and persistent-state functionality out of M1.

## 0.1.1+hermes.2

Security-hardening release based on the original OrbisProbe v0.1 source package.

### Added

- Canonical, SHA-256-bound experiment plans.
- Explicit CLI exit-code contract: completed `0`, blocked `2`, runtime failure `3`, restore/state-integrity failure `4`.
- Required live-plan research chain and x86-64 dataflow fields.
- Non-mutating validation steps bound one-to-one to named preconditions.
- Reachable-sink declarations separate from forbidden-sink guardrails.
- Mutation/restore lifecycle state machine and same-runner integrity latch.
- Concrete saved-original restore resolution into bounded `write_memory` and `read_memory` operations.
- Byte-comparison confirmation for post-write and restore readbacks.
- Evidence summaries with policy, step counts, states, errors, stop reason, and oracle results.
- Evidence secret redaction and large-hex digesting.
- Adapter timeout, nonzero-exit, spawn-failure, and malformed-response classifications.
- Seven-case offline/FakeTarget smoke matrix.
- Deterministic release builder, security policy, and hardening report.

### Fixed

- Corrected the inverted `forbidden_sinks` semantics from v0.1.
- Validation steps now execute before experiment steps.
- Blocked plans execute zero target steps.
- Persistent sink names remain hard-blocked even if a caller supplies an empty policy override.
- Restore steps now run after successful, failed, timed-out, or potentially partial writes.
- Restore failures no longer report as ordinary runtime failures.
- Evidence failures during restoration no longer skip remaining restore verification.
- `stop_on` conditions now terminate subsequent steps.
- Invalid `data_hex`, lengths, iterations, metadata, step args, non-finite JSON values, and programmatic risk values fail closed.
- Plan changes between validation and execution now block before target contact.
- Post-write mismatches now become runtime failures while restoration still runs.
- Restore aliases can no longer redirect restoration to a different address.
- Negative oracle outcomes no longer cause a CLI error.

### Safety

- Persistent experiments remain unconditionally blocked.
- No PS4 live experiments were performed during this release finalization.
- No v0.2 functionality is included.
