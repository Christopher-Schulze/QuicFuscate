# TODO 104: Retained Custom Data-Plane Crypto Contract and Backend Boundary

## Scope
- explicit retained custom data-plane crypto truth
- product contract vs internal backend machine room
- planner/hardware SSOT
- review-facing honesty about retained custom crypto

## Problem Statement
- The product-facing crypto posture is cleaner, but one final architectural truth must be made explicit and internally consistent:
  - QuicFuscate intentionally retains its own data-plane crypto machine room.
- This includes:
  - `Aegis128L`
  - `Morus1280_128`
  - internal `Aegis128X4`
  - internal `Aegis128X8`
- The repo should not imply that this is "not own crypto" while these retained backends remain part of the real runtime.

## Desired End State
- One honest crypto reading model:
  - product contract is narrow
  - planner and hardware detection are the SSOT
  - retained custom backends are internal machine room
  - the repository is explicit that this is retained custom data-plane crypto, not a pure external-lib-only posture

## Current Truth Snapshot
- Product posture is already narrowed to `Aegis128L` and `Morus1280_128`.
- `Aegis128X4` / `Aegis128X8` are already internal machine-room backends.
- Planner and hardware detection are already centralized.
- Differential and unsafe hardening work is already in much better shape than before.

## Architecture Gap
- The technical architecture is close.
- The remaining gap is explicit contract honesty and consistent everywhere-wording:
  - what is product contract
  - what is retained internal backend machinery
  - what role, if any, external crates play as runtime providers versus reference oracles

## Execution Plan

### Phase 1: Contract Tightening
- Tighten docs, comments, and review material so the retained custom crypto truth is stated directly.
- Ensure public API and canonical docs do not expose backend internals as product suites.

### Phase 2: Backend Boundary Audit
- Re-audit the retained AEGIS width backends and MORUS path for any remaining overly visible helper/module surface.
- Keep the machine room internal and the contract small.

### Phase 3: Reference/Oracle Position
- Decide and document the role of external crates:
  - runtime replacement
  - differential oracle
  - benchmark/reference only
- Make that choice explicit rather than implicit.

### Phase 4: Proof Surface Completion
- Add any missing backend-boundary or differential checks needed for the retained X4/X8 machine room and MORUS contract.

## Acceptance Criteria
- [x] The repo explicitly states that retained custom data-plane crypto remains.
- [x] Product contract stays narrow while backend machine room stays internal.
- [x] External-crate role is documented honestly.
- [x] Review materials point directly to the strongest backend and parity proof surfaces.

## Validation Matrix
- `cargo check`
- `cargo clippy --all-targets --all-features -- -W clippy::all`
- retained crypto/security suites
- relevant property/fuzz targets
- runtime guardrails

## Final Status
- `src/crypto.rs` module header now states the retained custom data-plane crypto boundary directly.
- README and `docs/DOCUMENTATION.md` now say the same thing:
  - product contract stays `Aegis128L` / `Morus1280_128`
  - `Aegis128X4` / `Aegis128X8` remain internal planner-selected machine room
  - external crates are baseline/reference oracles where available, not canonical runtime providers
- `src/optimize/crypto/mod.rs` no longer re-exports AEGIS/MORUS runtime types through an unnecessary secondary optimize-facing namespace.
- Primary retained proof surfaces are now explicitly pointed to:
  - `scripts/tests/rust/rt-security-suite.rs`
  - `scripts/tests/rust/rt-property-suite.rs`
  - `scripts/tests/fuzz/fuzz_targets/crypto_operations.rs`
  - `scripts/tests/rust/rt-baseline-oracles.rs`
- Validation:
  - `cargo check`
  - `cargo test --features rust-tests --test rt-security-suite`
  - `cargo clippy --all-targets --all-features -- -W clippy::all`
