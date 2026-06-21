# TODO 109: Unsafe Invariant Annotation and Boundary Hardening

## Scope
- retained unsafe crypto machine room
- retained unsafe SIMD machine room
- reviewer-facing local safety explanations
- boundary hardening without widening public surface

## Problem Statement
- The visible unsafe surface has already been reduced sharply.
- The remaining reviewer pain is not broad exposure anymore.
- It is local auditability:
  - why a given unsafe block is valid
  - which invariants are required
  - where feature-gating, alignment, and bounds are enforced

## Desired End State
- The retained unsafe hotspots are locally understandable.
- Wrapper-level safe boundaries remain the default.
- Unsafe reasoning is documented where it matters, not as broad prose elsewhere.

## Current Truth Snapshot
- Broad public unsafe exposure is already heavily reduced.
- Remaining unsafe is concentrated in:
  - retained crypto backends
  - retained SIMD backends
  - feature-gated machine-room internals

## Architecture Gap
- The gap is review-time clarity, not API shape.
- Reviewers still have to infer too much from surrounding code when reading retained unsafe hotspots.

## Execution Plan

### Phase 1: Hotspot Inventory
- Identify the retained unsafe hotspots that still matter for runtime:
  - AEGIS width backends
  - MORUS SIMD paths
  - retained SIMD helpers used by runtime or parity paths

### Phase 2: Local SAFETY Contracts
- Add precise local SAFETY comments to the real hotspots only.
- Document:
  - feature preconditions
  - pointer validity
  - length/alignment assumptions
  - why the boundary wrapper is sufficient

### Phase 3: Boundary Tightening
- Where a remaining wrapper-level `unsafe` can become safe without hiding real invariants, do so.
- Keep raw machine-room internals internal.

### Phase 4: Review Map Sync
- Ensure the reviewer/audit docs point to these retained hotspots and their invariants.

## Acceptance Criteria
- [x] Retained unsafe hotspots have local invariant explanations.
- [x] No unnecessary wrapper-level unsafe exposure remains.
- [x] Review docs can point to the retained hotspot list directly.

## Validation Matrix
- `cargo check`
- `cargo clippy --all-targets --all-features -- -W clippy::all`
- retained parity/security tests that touch the affected backends

## Final Status
- Added local SAFETY reasoning at the retained safe-boundary wrappers that reviewers actually encounter first:
  - `src/simd.rs`
    - `canonical_ack_blocks_avx2_for_rust_tests(...)`
    - `canonical_ack_blocks_avx512_for_rust_tests(...)`
    - `validate_header_avx512_for_rust_tests(...)`
    - `validate_header_sse2_for_rust_tests(...)`
  - `src/crypto.rs`
    - `aes128_encrypt_block_fast(...)` x86_64 AESNI branch
    - `aes128_encrypt_block_fast(...)` aarch64 crypto/NEON branch
    - retained MORUS dispatch wrappers and backend-entry wrappers:
      - SSE2
      - SSSE3
      - SSE4.1
      - SSE4.2
- The retained wrapper-level unsafe boundaries now state:
  - which runtime feature gating guarantees the backend choice
  - that the wrapper only forwards borrowed inputs
  - that raw-pointer or target-feature assumptions stay encapsulated in the inner machine room
- Validation:
  - `cargo test --features rust-tests --test rt-header-validate-parity`
  - `cargo test --features rust-tests --test rt-ack-merge-parity`
  - `cargo test --features rust-tests test_morus_native_vs_optimized_matrix --lib`
  - `cargo clippy --all-targets --all-features -- -W clippy::all`
- Result:
  - all green
