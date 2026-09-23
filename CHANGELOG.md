# Changelog

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
