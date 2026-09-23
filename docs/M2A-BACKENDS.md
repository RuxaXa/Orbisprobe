# OrbisProbe M2-A multi-engine backend architecture

## Scope

M2-A runs only in the v0.2 development tree. The frozen `0.1.1+hermes.2` experiment engine remains unchanged. M2-A is offline-only and adds no PS4 transport, target calls, or mutation path.

OrbisProbe remains the orchestrator, policy/evidence layer, candidate graph, planner, and classifier. External engines emit atomic evidence; they cannot create `SurfaceFinding` objects or assign final status.

## Backend contract

`orbisprobe.backends.base.AnalysisBackend` provides:

- `availability()`
- `version()`
- `analyze_function()`
- `recover_cfg()`
- `trace_value()`
- `find_definitions()`
- `find_consumers()`
- `resolve_call_arguments()`
- `evaluate_branch_constraints()`
- `analyze_memory_access()`
- `export_evidence()`

Capabilities are independently declared: `CFG`, `SSA`, `DATAFLOW`, `SYMBOLIC`, `TAINT`, `EMULATION`, `CALLGRAPH`, `MEMORY_MODEL`, `DECOMPILER`, and `HEADLESS`.

Statuses are fail-closed: `COMPLETED`, `BACKEND_UNAVAILABLE`, `ANALYSIS_INCOMPLETE`, `TIMEOUT`, `RESOURCE_LIMIT`, `PARTIAL`, and `ERROR`.

Backend evidence accepts only atomic `SUPPORTED`, `INFERRED`, `UNKNOWN`, or `DISPROVED` confidence. A backend attempting to inject `CONFIRMED` is rejected.

## Implemented backends

### Native Capstone

Independence family: `capstone-native`.

The core dependency is pinned to the Capstone distribution `5.0.9`. The upstream Python module
still exposes the stale internal string `capstone.__version__ == 5.0.7`; OrbisProbe therefore uses
the installed distribution metadata (`importlib.metadata.version("capstone")`) as the reproducible
backend version and cache identity. A regression test requires `5.0.9`.

- bounded disassembly;
- M1 register-lifetime dataflow;
- definition, propagation, overwrite, call-clobber, and consumer events;
- basic CFG/call and memory-access inventory.

It does not solve path constraints or full call arguments and returns `ANALYSIS_INCOMPLETE` for those operations.

### angr

Independence family: `angr-vex`.

The core does not import angr. It invokes a fixed JSON worker through a separate Python environment with `shell=False`.

- raw AMD64 blob loading with explicit base and entry;
- bounded CFGFast regions;
- VEX facts;
- angr ReachingDefinitions and dependency edges;
- Claripy symbolic register values and branch constraints;
- per-instruction bounded exploration;
- function-range pruning;
- state and step ceilings.

Development environment:

```text
.backend-envs/angr
angr==9.2.184
pycparser==2.22
```

`pycparser==2.22` is intentional: pycparser 3.0 broke angr 9.2.184 import during M2-A bring-up.

Install as an optional dependency or isolated worker environment:

```bash
uv venv --python 3.12 .backend-envs/angr
uv pip install --python .backend-envs/angr/bin/python 'angr==9.2.184' 'pycparser==2.22'
```

Configure a non-default interpreter with `ORBISPROBE_ANGR_PYTHON`.

### Ghidra Headless/P-code

Independence family: `ghidra-pcode`.

Ghidra is external, not a Python dependency. M2-A uses `analyzeHeadless`, `BinaryLoader`, explicit AMD64 base, GCC compiler spec, a temporary project, and the fixed `OrbisProbeExport.java` post-script.

The exporter returns:

- function identity and extent;
- instructions and basic-block seeds;
- call targets and xrefs;
- normalized P-code operations;
- definitions and consumers;
- `LOAD`/`STORE` memory accesses;
- parameters and stack variables;
- decompiler C output.

Every analysis result carries one explicit mode:

- `FULL_ANALYSIS`: normal Ghidra autoanalysis completed before export;
- `BOUNDED_ANALYSIS`: large raw image loaded with `-noanalysis`, then the target function was
  explicitly disassembled/defined and its target instructions, P-code, calls, register varnodes,
  stack memory operations, and decompiler output were verified;
- `PARTIAL_ANALYSIS`: timeout, nonzero exit, item ceiling, malformed/truncated output, or another
  incomplete condition.

Each report also carries `effective_capabilities`. Partial results never vote in consensus. M2-A
does not advertise Ghidra SSA because the current exporter does not provide claim-specific SSA
lifetime proof.

Configure non-default paths with `ORBISPROBE_GHIDRA_HOME` and `ORBISPROBE_JAVA_HOME`.

### Binary Ninja

Binary Ninja is not installed and no valid license was detected. It remains optional and reports `BACKEND_UNAVAILABLE`. No license bypass or compatibility shim exists.

## Consensus

Claims are grouped by exact `(kind, subject, canonical value)` over one binary/base/operation cache context.

- one independence family: `SUPPORTED`;
- two independent static families: `STRONGLY_SUPPORTED`;
- static plus symbolic agreement: `STRONGLY_SUPPORTED`;
- static plus independently collected real-target runtime evidence may become `CONFIRMED` in the consensus layer only;
- conflicting complete values: `EVIDENCE_CONFLICT`;
- support plus refutation of the same value: `EVIDENCE_CONFLICT` with no majority vote;
- unanimous complete refutation: `DISPROVED`;
- incomplete/error/timeout/unavailable results do not vote;
- two frontends sharing one semantic engine count once.

Backend evidence may only declare the source classes `static`, `symbolic`, `inferred`,
`unattributed`, or `fixture`. `runtime_real` is reserved for OrbisProbe's own runtime-collection
channel and is rejected at the backend ingestion boundary, so an external engine process can never
promote a claim to `CONFIRMED` by labelling its own output as runtime evidence.

`runtime_real` is additionally honoured only from OrbisProbe's own runtime adapters
(`RUNTIME_CHANNELS`); a runtime claim arriving from any other adapter identity is ignored for
promotion and recorded as an unknown on the claim. Evidence `address` values must be integers or
`null`; every other type is rejected at construction and at the serialized ingestion boundary.

Evidence whose value is not strict-JSON representable (for example `NaN`) is excluded from voting
and reported in `excluded_evidence` instead of aborting the consensus step.

Register-sensitive claims for `rbx`, `rbp`, `r12`–`r15`, stack slots, and other registers retain a second-source unknown when another independent backend is available but did not corroborate the lifetime.

## Cache

Cache keys bind:

- binary SHA-256;
- backend and version;
- OrbisProbe version;
- base address;
- operation;
- all analysis parameters;
- all resource limits;
- a SHA-256 fingerprint of the OrbisProbe backend adapter plus its worker/scripts.

Entries are atomically written with restrictive permissions and HMAC-SHA256 authenticated with a
per-cache-root 256-bit integrity key stored as mode `0600`. Invalid JSON, signature failure, wrong
request material, wrong backend identity/version, or a different binary/base/version is a miss.
Adapter, angr worker, and Ghidra script changes invalidate cached results. This protects the cache
from accidental corruption and file-only injection; a process already running as the same OS user
remains outside the cache trust boundary.

## Resource and sandbox model

Every backend receives timeout, memory, state, step, function, and graph limits.

- subprocess argv only; never shell interpolation;
- fixed worker/script paths;
- canonical input path validation;
- strict typed/schema validation of every external JSON payload, including nested P-code,
  instruction, call, and memory item fields, plus rejection of non-finite JSON constants;
- one failing backend is isolated: a raising adapter becomes a structured `ERROR` result and the
  remaining engines still run, cache, and produce consensus. This covers adapter construction,
  availability probing, cache fingerprinting, argument coercion, and the analysis call itself;
- per-run secure temporary Ghidra project;
- process-group kill on Ghidra timeout;
- angr address-space memory ceiling and core-dump disable;
- 16 MiB worker/Ghidra JSON output ceiling;
- strict top-level/type/schema validation for angr and Ghidra JSON;
- analyzed bytes are never executed by the host.

Limit exhaustion returns structured status and partial evidence instead of hanging OrbisProbe.

## Register-lifetime model

The Native register-lifetime engine models the SysV AMD64 caller-saved/callee-saved split. It
invalidates caller-saved provenance at a `call` and assumes an unknown callee preserves callee-saved
registers; `syscall`/`sysenter`/`int` clobber `rcx`/`r11` and are **not** modelled. Both limitations
are surfaced as explicit unknowns on the analysis result and make `proof_complete` false, so the
assumption is never presented as a completed proof.

## CLI

```bash
orbisprobe backends --json
orbisprobe analyze-dataflow IMAGE --backend angr --base BASE --function ADDRESS ...
orbisprobe prove-path IMAGE --backend angr --base BASE --function ADDRESS --from A --to B
orbisprobe privilege-surface iommu IMAGE --backend auto --base BASE --json
```

`--backend auto` orders native, angr, and Ghidra. Missing engines do not stop other engines. Multi-engine output is attached to each surface without changing its M1 classification automatically.

## M2-A exclusions

- Triton, Qiling, and the generic function harness are M2-B.
- AFL++ harness generation is M2-C.
- No live PS4 execution is part of M2-A.
- No backend output alone is runtime proof.
