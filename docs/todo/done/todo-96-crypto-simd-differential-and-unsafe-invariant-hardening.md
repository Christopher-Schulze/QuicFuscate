# TODO 96: Crypto/SIMD Differential and Unsafe Invariant Hardening

## Scope
- crypto backend parity
- SIMD backend equivalence
- unsafe invariant clarity and proof
- fuzz/property hardening

## Problem Statement
- The visible crypto/SIMD surface is much smaller, but trust still depends on proving that the retained backends and unsafe paths are equivalent and well-bounded.
- The remaining concern is not broad architecture drift, but confidence.

## Desired End State
- Strong backend equivalence across:
  - `Aegis128L`
  - `Aegis128X4`
  - `Aegis128X8`
  - retained scalar/SIMD helper paths
- Unsafe assumptions are explicit and local.
- Property and fuzz coverage directly target the retained hot paths.

## Execution Plan

### Phase 1: Differential Inventory
- Map the retained backend families and unsafe boundaries.
- Identify missing parity combinations.

### Phase 2: Test Expansion
- Add differential tests for:
  - AEGIS width variants
  - scalar vs SIMD parity
  - retained packet-protection / transport hot paths where useful
- Public-contract differential coverage is now started on the external test surfaces:
  - `scripts/tests/rust/rt-security-suite.rs`
  - `scripts/tests/rust/rt-property-suite.rs`
  - `scripts/tests/fuzz/fuzz_targets/crypto_operations.rs`
- These now cover the public `install_data_aead_config(...)` + `select_data_aead(...)` path for:
  - `aegis-128l`
  - `aegis`
  - `aegis-128x4`
  - `aegis-128x8`
  while asserting one consistent public `Aegis128L` contract.
- The retained public `morus` contract is now also exercised explicitly:
  - roundtrip in `scripts/tests/rust/rt-security-suite.rs`
  - property coverage in `scripts/tests/rust/rt-property-suite.rs`
  - fuzz target selection in `scripts/tests/fuzz/fuzz_targets/crypto_operations.rs`
- This new differential layer is already validated with:
  - `cargo test --features rust-tests --test rt-security-suite`
  - `cargo test --features rust-tests --test rt-property-suite`
  - `cargo check`
  - `cargo clippy --all-targets --all-features -- -W clippy::all`

### Phase 3: Unsafe Invariant Tightening
- Make retained unsafe invariants explicit where they are still easy to mistrust.
- Prefer local comments and local test coverage over broad documentation prose.
- First concrete owner-boundary reduction is already in:
  - `src/crypto.rs`
  - `prefetch_morus_buffer(...)` is now a safe local helper that contains its internal prefetch call instead of remaining an unnecessary outward-facing `unsafe fn`.
- Second concrete owner-boundary reduction is now also in:
  - `src/simd.rs`
  - retained rust-tests parity hooks for x86 ACK/header SIMD are now safe wrappers instead of outward-facing `pub unsafe` entrypoints
  - the internal x86 SIMD calls remain unsafe inside the owner-local wrapper
- The retained x86 ACK/header SIMD helper modules are now also parent-owned only:
  - `src/simd/x86_ack.rs`
  - `src/simd/x86_header.rs`
  - the modules are no longer crate-visible helper namespaces
  - the retained parity surface stays at the safe `simd` root hooks
- Third concrete owner-boundary reduction is now also in:
  - `src/simd.rs`
  - retained ARM QPACK SIMD wrappers (`qpack_encode_neon`, `qpack_decode_neon`, `qpack_encode_sve2`, `qpack_decode_sve2`) are now safe owner-boundary wrappers
  - the architecture-specific implementation call remains unsafe only inside the local wrapper
- Fourth concrete owner-boundary reduction is now also in:
  - `src/simd/arm_varint.rs`
  - retained ARM varint SIMD wrappers (`encode_varint_neon`, `encode_varint_sve2`, `decode_varint_neon`, `decode_varint_sve2`) are now safe owner-boundary wrappers
  - the architecture-specific implementation call remains unsafe only inside the local wrapper
- Fifth concrete owner-boundary reduction is now also in:
  - `src/optimize.rs`
  - `optimize::prefetch(...)` is now a safe owner-boundary helper with internal unsafe contained locally
  - `optimize::numa::move_to_node(...)` is now a safe owner-boundary helper with internal unsafe contained locally
- The retained owner-local prefetch paths in transport, crypto, and FEC no longer require outer unsafe callsites:
  - `src/transport/uring.rs`
  - `src/transport/udpfast.rs`
  - `src/transport/xdp.rs`
  - `src/crypto.rs`
  - `src/fec.rs`
- A direct seam scan now confirms there are no remaining `pub(crate) unsafe fn` or `pub unsafe fn` seams in:
  - `src/crypto.rs`
  - `src/simd.rs`
  - `src/simd/`
  - `src/optimize.rs`

### Phase 4: Fuzz/Property Reinforcement
- Extend fuzz/property coverage to the exact retained backend and packet surfaces.

## Acceptance Criteria
- [x] Public retained data-AEAD alias backends have explicit parity coverage.
- [x] Major retained public crypto backends now have explicit contract coverage beyond the AEGIS alias family.
- [x] Retained wrapper-level unsafe assumptions are localized to owner boundaries instead of exposed as broad crate-visible helper seams.
- [x] Fuzz/property coverage is stronger on the retained hot paths.
- [x] Remaining unsafe surface is concentrated in deep internal machine-room intrinsics.

## Validation Status
- `cargo test --features rust-tests --test rt-security-suite`
- `cargo test --features rust-tests --test rt-property-suite`
- `cargo test --features rust-tests --test rt-header-validate-parity`
- `cargo test --features rust-tests --test rt-ack-merge-parity`
- `cargo test qpack_neon_matches_scalar --lib`
- `cargo test arm_varint --lib`
- `cargo test --features rust-tests --test rt-transport-connection`
- `cargo check`
- `cargo clippy --all-targets --all-features -- -W clippy::all`
- Current result:
  - all green
  - x86-only parity binaries on this macOS/aarch64 host finish as expected with `0 tests`
  - direct seam scan over retained crypto/SIMD/optimize owner files is clean

## Validation Matrix
- targeted crypto and transport rust-tests
- fuzz targets that can run locally
- `cargo check`
- `cargo clippy --all-targets --all-features -- -W clippy::all`

## Notes
- This is trust hardening, not a new crypto feature program.
- The retained unsafe surface is now deep internal machine-room territory, not broad wrapper-level API exposure.
