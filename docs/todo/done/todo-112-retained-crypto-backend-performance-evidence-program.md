# TODO 112: Retained Crypto Backend Performance Evidence Program

## Scope
- retained backend benchmarks
- AEGIS width-family evidence
- MORUS retained-path evidence
- hardware-profile-specific performance proof

## Problem Statement
- Retained X4/X8 backends are now honest and internal.
- The next reviewer question is:
  - are they worth keeping?

## Desired End State
- There is concrete evidence for why retained X4/X8 and MORUS paths remain in-tree.
- The answer is based on measured behavior, not only architecture preference.

## Current Truth Snapshot
- Planner selection is documented and tested.
- Runtime telemetry is improving, but benchmark evidence is still the missing half.

## Architecture Gap
- Retained complexity is currently justified mainly by architecture and capability.
- It should also be justified by measured performance.

## Execution Plan

### Phase 1: Benchmark Harness Inventory
- Review existing microbench and crypto benchmark tooling.

### Phase 2: Width-Family Benchmarking
- Benchmark:
  - `Aegis128L`
  - `Aegis128X4`
  - `Aegis128X8`
- Across:
  - short payloads
  - mid payloads
  - large payloads
  - relevant x86_64 hardware profiles
  - relevant aarch64 hardware profiles where available

### Phase 3: MORUS Evidence
- Benchmark retained MORUS paths against realistic payload classes and compare to retained AEGIS selection where meaningful.

### Phase 4: Decision Record
- Document when retained backends are materially justified and when they are merely historical baggage.

## Acceptance Criteria
- [x] Benchmark evidence exists for retained width backends.
- [x] MORUS retained-path cost/value is measured.
- [x] Docs can justify why retained machine-room complexity remains.

## Validation Matrix
- benchmark harness runs
- benchmark output summaries
- docs sync

## Final Status
- Completed.
- Added a dedicated retained-backend evidence path:
  - `examples/crypto_backend_bench.rs`
  - `scripts/benchmarks/suites/bench-retained-crypto-backends.sh`
- Bench-only backend construction now exists for:
  - `Aegis128L`
  - `Aegis128X4`
  - `Aegis128X8`
  - `Morus1280_128`
- The evidence suite records:
  - hardware profile
  - per-backend throughput
  - per-size winning backend
- Canonical documentation now points at the retained-backend evidence harness instead of relying only on architecture claims.
