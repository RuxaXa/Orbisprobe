# Security policy

## Authorized use only

OrbisProbe is intended for authorized research on owned or explicitly permitted systems. It does not grant authorization and it does not widen an existing scope.

## Hard safety boundaries

- Persistent experiments are never executable.
- The built-in persistent sink set cannot be removed through `Policy(blocked_sinks=set())` or another caller override.
- Template plans are not executable.
- Live plans require complete research fields, explicit preconditions, validation steps, and sink declarations.
- Validation steps cannot declare or use mutating operations.
- `write_memory` requires `reversible_kernel_ram` risk and a complete read/write/read/restore/readback sequence.
- A blocked or hash-mismatched plan performs zero target experiment steps.
- A restore/state-integrity failure latches the same Runner against subsequent mutating plans.

## Plan authorization

`validate` produces a canonical SHA-256. `run` requires that exact digest. The hash binds execution to the plan bytes after canonical parsing, but it is not a user identity, digital signature, or authorization token. Operational approval must separately bind scope, target identity, firmware, adapter, plan hash, and attempt budget.

## Adapter trust boundary

The command adapter is an external executable. OrbisProbe:

- invokes it as an argv array without a shell;
- enforces a timeout;
- requires one JSON object response;
- classifies nonzero exit, timeout, spawn failure, and malformed JSON;
- validates plan sequencing and readback values.

OrbisProbe cannot prove that an arbitrary adapter truthfully implements a step name or that a remote target returned authentic data. Adapters should be minimal, separately reviewed, hash-pinned, and restricted to the exact operations authorized by the plan.

## Restore guarantees and limits

Dispatching a write changes state to `MUTATION_ATTEMPTED` before the adapter returns. A timeout or error does not imply that no mutation occurred. Restore is attempted whenever a reversible mutation was dispatched.

`RESTORED_CONFIRMED` requires a byte-identical readback against the saved original bytes. If restore execution, readback, or restore-evidence persistence fails, the run is classified as `restore_failure` and the Runner latches.

A process crash, host power loss, adapter process failure outside the protocol, or target disappearance can still prevent restore. Reversible does not mean risk-free.

## Evidence handling

Evidence JSONL is append-only per process and each append is flushed and fsynced. Sensitive-looking key names are redacted. Large hex values are represented by preview, length, and digest.

Limitations:

- logs are not cryptographically chained or signed;
- concurrent writers are not coordinated by a cross-process lock;
- arbitrary secrets embedded in unrecognized free-text fields may not be detected;
- evidence-storage failure can only be reported through the CLI if the evidence target itself is unavailable.

Use a dedicated, access-controlled evidence directory and independently hash completed evidence packages.

## Reporting a vulnerability

Do not include live credentials, private target dumps, keys, or exploitable unpublished target details in a public report. Provide the smallest offline reproducer, affected version, plan/evidence hashes, and the violated invariant through the project's private reporting channel.
