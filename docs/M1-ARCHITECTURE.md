# OrbisProbe v0.2-M1 architecture

## Scope

M1 is an offline-only privilege-surface discovery layer above the frozen `0.1.1+hermes.2` experiment engine. It introduces no PS4 transport, target requests, MMIO, or writes. Existing plan hashing, persistent-state hard-blocks, restore semantics, evidence handling, and CLI exit contracts remain in place.

## Evidence chain

Every promoted surface is represented against:

```text
controlled source
-> validation
-> privilege boundary
-> privileged consumer
-> observable effect
```

An absent link is recorded in `unknowns` and `open_chains`. A decoded instruction, string, constant, or structure pattern is evidence, not a vulnerability finding.

## Modules

### Binary image

`orbisprobe.analysis.binary.BinaryImage`

- hashes the immutable input;
- requires an explicit architecture and load base;
- disassembles in the VA domain;
- bounds-checks addresses and ranges;
- localizes raw candidates but promotes only decoded instructions;
- tolerates empty and truncated images.

### Dataflow lifetime

`orbisprobe.analysis.dataflow.DataflowAnalyzer`

- records definitions, propagation, consumers, overwrites, call clobbers, and unresolved merges;
- normalizes x86-64 register aliases;
- invalidates SysV caller-saved registers after calls;
- preserves callee-saved provenance until an observed overwrite;
- marks conditional merges incomplete until CFG/phi reconstruction exists.

Security-relevant automatic claims must not exceed the returned proof completeness.

### Surface model

`orbisprobe.surfaces.model.SurfaceFinding` contains:

- `surface_id`
- `surface_type`
- `binary`
- `architecture`
- `function`
- `address`
- `source`
- `validation`
- `boundary`
- `consumer`
- `observable`
- `confidence`
- `evidence`
- `unknowns`

It also carries status, candidate priority, score, classification, and open chains. IDs are deterministic over binary identity, location, type, and evidence.

### Research graph

Nodes:

- function
- object
- field
- buffer
- mapping
- descriptor
- hardware endpoint

Edges:

- reads
- writes
- validates
- maps
- submits
- copies
- aliases
- consumes
- calls

The M1 graph supports deterministic serialization and bounded path queries such as controlled field to DMA endpoint.

### Candidate ranking

Ranking is triage only:

- P1: host-closed controlled primitive
- P2: host-closed validation gap
- P3: cross-processor/secure candidate
- P4: structural anomaly only

Inputs are controllability, validation gap, privilege distance, consumer confidence, observable quality, reproducibility, and persistent risk. Ranking never changes a surface status into a vulnerability verdict.

## Scanner tracks

### SVM/HV

Candidate localization covers decoded:

- VMRUN, VMMCALL, VMLOAD, VMSAVE
- STGI, CLGI, SKINIT, INVLPGA
- EFER, VM_CR, IGNNE, SMM_CTL, VM_HSAVE_PA and SVM key MSRs

MSR attribution stops on ECX overwrite or a call-clobber. Generic EFER access does not prove `EFER.SVME`. Classification remains `SVM-CAPABILITY-ONLY` until an SVME/HSAVE initialization sequence is locally supported. `SVM-ACTIVE-SUBSYSTEM` is not emitted by M1.

### IOMMU/DMA

M1 inventories:

- GPUVM/map/unmap/IOVA/GPUVA strings as raw metadata anchors;
- DMAC, device-table, domain, ring, doorbell, and invalidation strings;
- decoded immediates for `0xa70`, `0xc0000000`, and mapping flag `0x61`;
- decoded `+0xa70` structure displacements;
- actual memory writes near research constants.

Promotion requires independent evidence categories. String hits are not treated as function names without xrefs. M1 does not yet decode device tables or close source-to-hardware dataflow, so current results remain P4/UNKNOWN.

### SAMU/secure

Within one bounded function window, the structural matcher requires:

- decoded `0x80` descriptor-size/stride evidence;
- all tags 7, 8, and 9;
- `+8` and `+0x10` accesses sharing a base-register context.

A cross-processor candidate additionally requires the same base to show repeated reads at `+0x28`, `+0x30`, and `+0x38` with a call between read sets. Function windows are not combined. Candidate windows are capped; hitting the cap is reported diagnostically.

### Memory controller

M1 recognizes decoded:

- PCI configuration ports `0xCF8/0xCFC`;
- IN/OUT operations while DX provenance remains valid;
- Family-16h `SYSCFG`, `TOP_MEM`, and `TOP_MEM2` MSR accesses while ECX provenance remains valid.

Calls and register overwrites terminate attribution. Results remain offline address-map/config candidates, never authorization for register writes.

## Regression fixtures

- `P2-1 0x631ad0`: immutable length `0xA8`, index domain `{0,1}`, destination slot `0xC0`; verdict `SAFE-INVARIANT`.
- `CASE-003`: host descriptor `0x80`, tags 7/8/9, `+8`, `+0x10`, repeated mutable reads; expected cross-processor candidate with secure semantics and exploitability unknown.

The getter-only, dead-slot, and Tag-0xF differential fixtures are explicitly deferred beyond M1.

## CLI

```bash
orbisprobe privilege-surface svm IMAGE --base BASE
orbisprobe privilege-surface iommu IMAGE --base BASE
orbisprobe privilege-surface secure IMAGE --base BASE
orbisprobe privilege-surface memctl IMAGE --base BASE
orbisprobe privilege-surface all IMAGE --base BASE --json
```

JSON includes binary provenance, per-track classifications, surfaces, candidates, open chains, graphs, and diagnostics.

## M1 limitations

- no full CFG/function recovery;
- no phi reconstruction;
- no string-to-code xref resolution yet;
- no device-table/domain decoder;
- no VMCB parser;
- no active-hypervisor claim;
- secure candidate-window cap may omit later candidates;
- no live integration.
