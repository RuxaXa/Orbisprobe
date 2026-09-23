# OrbisProbe 0.2.0.dev1 — M1 offline development

> **Development tree:** this is not the frozen stable baseline. Stable remains
> `OrbisProbe 0.1.1+hermes.2` with SHA-256
> `701441e07698183f9e7604033ea15f4324599f17dcc5dbed8b271bfa88ad87ef`.
> v0.2-M1 is offline-only: no PS4 contact, no requests, and no writes.

## v0.2-M1 privilege-surface discovery

M1 adds offline-only scanners and a conservative x86-64 register-lifetime engine. Architecture and
claim boundaries are documented in [`docs/M1-ARCHITECTURE.md`](docs/M1-ARCHITECTURE.md); verified
milestone results are in [`docs/M1-REPORT.md`](docs/M1-REPORT.md).

M2-A multi-engine development is documented in
[`docs/M2A-BACKENDS.md`](docs/M2A-BACKENDS.md); its verified results and open limits are in
[`docs/M2A-REPORT.md`](docs/M2A-REPORT.md). Native Capstone, angr, and Ghidra Headless/P-code
share one backend/evidence/consensus contract; missing optional engines fail as
`BACKEND_UNAVAILABLE` without stopping the others.

```bash
orbisprobe backends --json
orbisprobe analyze-dataflow kernel.bin --backend angr --base 0x... --function 0x...
orbisprobe prove-path kernel.bin --backend angr --base 0x... --function 0x... --from 0x... --to 0x...
orbisprobe privilege-surface iommu kernel.bin --backend auto --base 0x... --json
```

```bash
orbisprobe privilege-surface svm kernel.bin --base 0xffffffffd9918000
orbisprobe privilege-surface iommu kernel.bin --base 0xffffffffd9918000
orbisprobe privilege-surface secure kernel.bin --base 0xffffffffd9918000
orbisprobe privilege-surface memctl kernel.bin --base 0xffffffffd9918000
orbisprobe privilege-surface all kernel.bin --base 0xffffffffd9918000 --json
```

Outputs contain structured surfaces, evidence, confidence, boundary types, ranked candidates,
research graphs, and open proof chains. Pattern hits remain triage evidence and never become findings
without a closed source→validation→boundary→consumer→observable chain.

OrbisProbe is an evidence-driven experiment harness for authorized PS4/Orbis security research. It sits between Hermes and offline artifacts or an explicitly supplied target adapter.

This release is the hardened baseline derived from the original `orbisprobe-v0.1.zip`. It is not a blind fuzzer and it does not contain a PS4 transport.

## Control model

```text
discover -> rank -> prove preconditions -> canonical plan -> policy gate
         -> execute -> observe -> restore -> classify -> minimize -> report
```

Hermes owns hypothesis formation, reverse-engineering interpretation, prioritization, and result classification. OrbisProbe owns canonical plans, safety gates, preconditions, bounded execution, raw evidence, restore sequencing, oracles, and run history.

No live mutation should be improvised outside a validated, hash-bound OrbisProbe plan when it can be expressed as an experiment.

## Status and boundaries

- Development version: `0.2.0.dev1`
- Python: `>=3.11`
- Capstone: pinned to `5.0.9`
- Persistent experiments: always blocked
- Persistent sink names: hard-blocked even if a caller tries to clear policy overrides
- Real PS4 live experiments: not performed during finalization
- Template plans: never executable

See [SECURITY.md](SECURITY.md) for the trust boundary and [HARDENING-REPORT.md](HARDENING-REPORT.md) for evidence and remaining risks.

## Install

Using `uv` avoids a system `ensurepip` dependency:

```bash
uv venv .venv --python python3
uv pip install --python .venv/bin/python .
```

For development tests:

```bash
uv pip install --python .venv/bin/python pytest
.venv/bin/python -m pytest -q
ruff check .
PYTHONPATH=. .venv/bin/python scripts/run_smoke_matrix.py
```

## Mandatory research-plan structure

Every live research plan must contain this chain:

```text
hypothesis
-> controlled_input
-> validation
-> consumer
-> expected_effect
-> observable
-> risk
-> experiment
```

For security-relevant x86-64 dataflows, set:

```json
"metadata": {
  "security_relevant_x86_64_dataflow": true,
  "x86_64_dataflow": {
    "definition": "...",
    "overwrite_history": "...",
    "call_clobber_analysis": "...",
    "consumer": "..."
  }
}
```

The required analysis order is:

```text
definition -> overwrite history -> call-clobber analysis -> consumer
```

Live plans also require named preconditions, a non-mutating `check_precondition` step for each precondition, explicit forbidden sinks, and a declared reachable-sink set.

## Validate and run a plan

Validation emits the canonical plan and its SHA-256:

```bash
orbisprobe validate experiment.json --max-risk active_request > validated-plan.json
```

Extract the digest without requiring `jq`:

```bash
PLAN_SHA="$($PWD/.venv/bin/python -c 'import json; print(json.load(open("validated-plan.json"))["plan_sha256"])')"
```

Run only the exact validated plan:

```bash
orbisprobe run experiment.json \
  --max-risk active_request \
  --plan-sha256 "$PLAN_SHA" \
  --adapter '/absolute/path/to/adapter --fixed-arg' \
  --evidence evidence.jsonl
```

A plan changed after validation is blocked before any target step executes.

## CLI exit-code contract

- `0` — command or experiment technically completed. A negative oracle remains exit `0`.
- `2` — invalid plan or policy block. No experiment target step executes.
- `3` — runtime execution failure, including adapter timeout, nonzero adapter exit, malformed response, target failure, or unexpected execution failure.
- `4` — restore or state-integrity failure. This is critical; the same `Runner` latches against later mutating experiments.

Ordinary `scan-memops` or `report` input failures return nonzero.

## Risk classes

1. `offline`
2. `read_only`
3. `volatile_user`
4. `volatile_shared`
5. `reversible_kernel_ram`
6. `active_request`
7. `persistent` — always blocked

Hard-blocked sinks include Flash/NOR/FSL, SNVS/Syscon/NVS/NVRAM writes, key provisioning, firmware/update commits, bootloader writes, page-table/code-page writes, eFuse/OTP, and generic persistent state.

`forbidden_sinks` are guardrails; they are not automatically treated as reachable. A direct step naming a forbidden sink is nevertheless blocked. Only declared reachable sinks intersecting the effective hard-block list trigger the reachable-sink policy error.

## Reversible kernel-RAM contract

A reversible write plan must statically describe:

```text
original-byte read
-> write request
-> post-write readback
-> restore request
-> restore readback
```

The original read and post-write readback must match the write address and byte length. Restore aliases must reference the original-read step and cannot redirect the address.

Internally the lifecycle distinguishes:

- `NOT_MUTATED`
- `MUTATION_ATTEMPTED`
- `MUTATED_CONFIRMED`
- `RESTORE_ATTEMPTED`
- `RESTORED_CONFIRMED`
- `RESTORE_FAILED`

Dispatching a mutating target step immediately means `MUTATION_ATTEMPTED`, even if the adapter subsequently times out or reports failure. Restore is still attempted. Mutation and restore confirmation come from byte readback comparisons, not adapter assertions alone.

## Evidence

Each run records append-only JSONL events containing:

- canonical plan SHA-256 and expected SHA-256;
- effective policy configuration and policy errors;
- exit classification;
- validation, experiment, and restore step counts;
- mutation, restore, and lifecycle states;
- stop reason;
- adapter errors/timeouts;
- oracle results.

Blocked runs record `executed_steps = 0`. Secrets are redacted by key name. Large `data_hex` values are replaced by a short preview, byte length, and SHA-256.

Evidence-storage failure before execution prevents target contact. Evidence failure after mutation cannot bypass restore; failure to persist the restore chain results in the critical restore-failure classification.

## Adapter contract

The adapter receives one JSON object on stdin:

```json
{"kind":"read_memory","args":{"address":"0x1000","length":16}}
```

It must return one JSON object on stdout:

```json
{"ok":true,"address":"0x1000","data_hex":"00112233445566778899aabbccddeeff"}
```

The adapter runs without `shell=True`, has a default 30-second timeout, and is a trust boundary. OrbisProbe validates structure and sequencing but cannot prove that a third-party adapter truthfully implements a named operation.

## Components

- `schema.py` — typed plan vocabulary and canonical serialization
- `policy.py` — risk, sink, limit, precondition, and restore-sequence gates
- `runner.py` — lifecycle state machine, execution, restore, and oracles
- `evidence.py` — append-only, fsynced, sanitized JSONL evidence
- `targets/offline.py` — offline file reads and hashes
- `targets/command_adapter.py` — bounded external JSON bridge
- `analyzers/memop_scan.py` — x86-64 dynamic-size callsite triage
- `report.py` — compact evidence-log inventory report
- `scripts/run_smoke_matrix.py` — seven-case offline/FakeTarget acceptance matrix
- `scripts/build_release.py` — deterministic source ZIP builder

## Examples

- `examples/offline_hash.json`
- `examples/offline_smoke.json`
- `examples/live_ab_template.json`
- `examples/reversible_kernel_ram_template.json`
- `examples/x86_64_dataflow_template.json`

Live examples are intentionally marked `template_only` and fail validation until copied, fully materialized, and explicitly cleared.
