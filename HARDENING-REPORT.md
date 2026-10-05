# OrbisProbe 0.1.1+hermes.2 hardening report

## Verdict

The code baseline passed its final independent code gate. Release packaging and fresh-install verification are performed by the deterministic release workflow after this document is finalized.

No PS4 or other live target was contacted. Persistent state remained hard-blocked throughout.

## Provenance

- Original received package: `orbisprobe-v0.1.zip`
- Original SHA-256: `45f22ecb9d13ffb59c849ea06e2e59218fcd9a7c6fa0883829c6549072accc3a`
- Hardened version: `0.1.1+hermes.2`
- Original package retained unchanged outside the working tree.

## Original v0.1 issues and closures

### Policy and plan gates

- **Problem:** `forbidden_sinks` was interpreted as if every forbidden sink were reachable.
  - **Fix:** separate `forbidden_sinks` guardrails from `reachable_sinks`; block only effective reachable intersections and direct forbidden step kinds.
  - **Regression:** `test_forbidden_sinks_are_guardrails_but_reachable_sinks_block`.
- **Problem:** caller-supplied empty blocked-sink policy could remove persistent protection.
  - **Fix:** immutable default persistent sinks are always unioned into the effective policy.
  - **Regression:** `test_persistent_sink_cannot_be_disabled_by_policy_override`.
- **Problem:** templates and incomplete live research chains could approach execution.
  - **Fix:** mandatory live fields, preconditions, validation steps, x86-64 dataflow fields, and template block.
- **Problem:** malformed numeric, hex, JSON, metadata, step-argument, and programmatic risk values could crash or bypass limits.
  - **Fix:** structural schema checks and strict non-negative integer/hex validation.

### Execution and exit codes

- **Problem:** CLI commands could print `ok=false` but implicitly return success.
  - **Fix:** explicit `main() -> int` mapping: `0/2/3/4`; direct module execution uses `SystemExit(main())`.
- **Problem:** a negative oracle could be confused with technical failure.
  - **Fix:** completed negative oracle remains exit `0`.
- **Problem:** plan validation was not bound to execution.
  - **Fix:** canonical serialization and required execution-time SHA-256 comparison.
- **Problem:** `stop_on` declarations were not enforced.
  - **Fix:** stop events abort subsequent experiment steps and are recorded.

### Preconditions and validation

- **Problem:** validation steps and named preconditions were only descriptive.
  - **Fix:** every live precondition requires a non-mutating validation step executed before experiment steps.
- **Problem:** mutating validation could be disguised through a flag or sink name.
  - **Fix:** mutating prefixes, flags, hard sinks, and plan-specific forbidden sinks are blocked.

### Mutation and restore

- **Problem:** restore steps were declared but never executed.
  - **Fix:** explicit lifecycle state machine and restore execution after every dispatched reversible mutation.
- **Problem:** a write error or timeout could be treated as proof that no write occurred.
  - **Fix:** state changes to `MUTATION_ATTEMPTED` before adapter dispatch returns.
- **Problem:** adapter assertions could claim mutation or restore without byte proof.
  - **Fix:** post-write and restore readbacks are compared against requested and saved-original bytes.
- **Problem:** restore aliases could reference magic adapter state or redirect the address.
  - **Fix:** Runner resolves saved-original aliases into concrete bounded write/read requests; policy binds address, length, and `from_step`.
- **Problem:** post-write mismatch could still report completion.
  - **Fix:** mismatch is runtime failure; restore still runs.
- **Problem:** restore failure could be classified below the critical level or allow later mutation.
  - **Fix:** exit `4` plus same-Runner integrity latch.

### Evidence and adapters

- **Problem:** raw evidence could contain large dumps or obvious secrets.
  - **Fix:** key-based redaction and large-hex preview/length/SHA-256 representation.
- **Problem:** evidence failure during restore could abort remaining restore steps.
  - **Fix:** evidence writes are isolated from restore control flow; missing restore evidence causes critical restore failure.
- **Problem:** adapters had no timeout and malformed responses could raise uncontrolled exceptions.
  - **Fix:** bounded timeout and structured spawn/exit/timeout/JSON errors.

## Regression matrix A-P

- A/B: forbidden versus reachable sinks — covered.
- C/D: validation execution and ordering — covered.
- E: validation cannot mutate — covered.
- F: persistent hard block independent of caller override — covered.
- G/H: restore after normal and possible partial write — covered.
- I: `stop_on` terminates later steps — covered.
- J: adapter timeout fail-closed — covered.
- K: malformed `data_hex` is plan error — covered.
- L: limits apply across validation, experiment, and restore — covered.
- M: templates are not executable — covered.
- N/O/P: blocked/runtime/restore CLI classifications — covered.

## Verification evidence

Final code-gate snapshot:

- Manifest SHA-256: `efbed8e477e139ab12a795bb64194c2d0944cbf18b186bc13ec22a1daf085255`
- Manifested files: `27`, all hashes and sizes stable before/after review.
- Pytest: `73 passed`.
- Ruff: `All checks passed!`.
- Smoke matrix: `7/7`, `all_passed=true`.
- Programmatic invalid-risk adversarial probe: string and null risks both blocked, zero executed steps, zero target calls.
- Independent final code verdict: `PASS`.

## Smoke-test matrix

1. Offline successful plan — completed.
2. Policy-blocked plan — blocked, zero target calls.
3. Adapter nonzero exit — runtime failure.
4. Adapter timeout — runtime failure.
5. Reversible write with successful restore — completed and restored confirmed.
6. Possible partial write plus runtime failure and successful restore — runtime failure and restored confirmed.
7. Restore failure — critical restore failure.

## Remaining technical risks

- No real PS4 transport or live target was tested in this release.
- Adapter truthfulness remains an external trust boundary.
- Evidence is fsynced but not signed or hash-chained.
- Cross-process evidence writers are not serialized.
- A process/host crash or target loss can still prevent restore.
- The compact Markdown report summarizes events but does not yet generate full case files.
- `scan-memops` is a triage heuristic, not vulnerability evidence.
- Reversible kernel experiments are deliberately restricted to one bounded mutation per plan in this baseline.

These are documented boundaries, not permission to start v0.2 work automatically.
