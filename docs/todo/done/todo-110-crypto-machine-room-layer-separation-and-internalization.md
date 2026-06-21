# TODO 110: Crypto Machine-Room Layer Separation and Internalization

## Scope
- contract layer
- planner/selection layer
- backend adapter layer
- raw primitive/SIMD machine room

## Problem Statement
- The crypto surface is already much smaller and more honest.
- The remaining reviewer cost comes from density:
  - too much retained machine room remains concentrated in large files and broad logical neighborhoods.

## Desired End State
- The retained crypto story is structured in clear internal layers:
  - product contract
  - planner/hardware selection
  - backend adapters
  - raw primitive machine room
- Internal layering is easier to review without widening public API.

## Current Truth Snapshot
- Product contract is narrow and documented honestly.
- Planner SSOT is retained.
- Internal width backends are already internalized.

## Architecture Gap
- The gap is internal layering clarity, not external contract shape.

## Execution Plan

### Phase 1: Internal Layer Audit
- Identify where contract-level, planner-level, adapter-level, and raw-machine-room code are still interleaved.

### Phase 2: Internal Boundary Tightening
- Move or group retained helpers so the codebase reads in layers.
- Do not create cosmetic fragmentation.
- Prefer moves only where they reduce real review cost.

### Phase 3: Test and Review Sync
- Ensure proof surfaces still target the public contract and planner boundaries, not raw internals.

## Acceptance Criteria
- [x] Internal crypto layers are more explicit.
- [x] Public contract does not widen.
- [x] Planner and backend machine room read as separate concerns.

## Validation Matrix
- `cargo check`
- `cargo clippy --all-targets --all-features -- -W clippy::all`
- retained crypto/security/property suites

## Final Status
- Completed.
- `src/crypto.rs` now separates the retained data-plane AEAD build path into:
  - plan resolution
  - AEGIS backend adapter construction
  - MORUS backend adapter construction
  - thin orchestration in `build_data_aead(...)`
- The public contract stays unchanged:
  - `Aegis128L`
  - `Morus1280_128`
- Internal machine-room backends remain retained and internal:
  - `Aegis128X4`
  - `Aegis128X8`
