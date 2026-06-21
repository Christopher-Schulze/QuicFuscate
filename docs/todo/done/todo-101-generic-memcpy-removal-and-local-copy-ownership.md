# TODO 101: Generic memcpy Removal and Local Copy Ownership

## Scope
- remove generic `memcpy_fast(...)`
- remove broad optimize-owned copy backends
- keep copy specialization only where a real owner and benchmark story exists

## Problem Statement
- A generic custom `memcpy` surface is difficult to justify unless it has a very narrow workload and a measured win.
- The repository already removed most broad copy/prefetch wrappers, but the remaining generic core still reads like an attempted global improvement over compiler/libc behavior.

## Desired End State
- No broad generic copy-acceleration contract in `src/optimize.rs`.
- Direct slice copy is the default truth.
- Any retained special copy path is:
  - owner-local
  - workload-specific
  - benchmark-justified

## Current Truth Snapshot
- Earlier cleanup removed broad wrapper layers and many generic copy callsites.
- The remaining reviewer-sensitive residue is the generic `SimdDispatch::memcpy_fast(...)` machinery and its AVX copy backends.
- This is now a local cleanup and ownership task, not a whole-architecture transport rewrite.

## Architecture Gap
- The code still says "there is a general-purpose fast memcpy service."
- The intended end architecture says:
  - generic copy belongs to normal compiler/libc behavior
  - special copy belongs to the owner of the exact hot path

## Execution Plan

### Phase 1: Remaining User Inventory
- Identify every remaining direct or indirect user of `memcpy_fast(...)`.
- Classify each one as:
  - direct slice copy
  - owner-local retained helper
  - dead / removable

### Phase 2: Generic Core Removal
- Remove `SimdDispatch::memcpy_fast(...)` and the broad AVX copy backends from the optimize surface.
- Replace each remaining user with direct copy or a local owner helper.

### Phase 3: Owner-Local Justification
- Where a retained owner-local copy helper remains, make its purpose explicit by name and local comments/tests.
- Keep no generic copy abstraction without a real measured reason.

## Acceptance Criteria
- [x] `memcpy_fast(...)` is gone from the broad optimize surface.
- [x] Direct copies or owner-local helpers replace the remaining users cleanly.
- [x] No generic "faster than libc/compiler" copy story remains in product/runtime docs.

## Validation Matrix
- `cargo check`
- `cargo clippy --all-targets --all-features -- -W clippy::all`
- targeted tests for any affected retained owner path

## Notes
- This is not anti-performance cleanup.
- It is a move from broad speculative optimization to owner-local measurable optimization.
- Validation completed with:
  - `cargo check`
  - `cargo clippy --all-targets --all-features -- -W clippy::all`
