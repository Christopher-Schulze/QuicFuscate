# TODO 103: Non-Security Random Simplification and Canonical RNG Boundary

## Scope
- secure RNG truth stays in `src/rng.rs`
- simplify or quarantine `src/optimize/random.rs`
- remove unnecessary custom AES-DRBG complexity from normal runtime thinking

## Problem Statement
- The secure RNG boundary is already correct, but `src/optimize/random.rs` still contains a relatively large custom random machine room.
- That is easy to criticize, especially where the remaining runtime value is only heuristic, non-security, or benchmark-oriented.

## Desired End State
- One simple canonical security truth:
  - secure randomness comes only from `src/rng.rs`
- One simple non-security truth:
  - fast runtime randomness is clearly non-security and uses the simplest defensible mechanism that meets the need
- Any retained custom AES-DRBG logic is either gone or tightly quarantined to test/bench/internal-only scope.

## Current Truth Snapshot
- `src/rng.rs` is already the canonical secure RNG owner.
- The old security ambiguity around `optimize/random` is already resolved.
- The remaining work is simplification, not emergency security repair.

## Architecture Gap
- The code still says "we have a fairly sophisticated custom random subsystem."
- The intended final architecture says:
  - one canonical secure RNG boundary
  - one much smaller non-security random story

## Execution Plan

### Phase 1: Use-Site Inventory
- Audit every productive use of `src/optimize/random.rs`.
- Classify each one as:
  - security-critical
  - non-security runtime
  - test/bench
  - dead / removable

### Phase 2: Simplification
- Replace retained non-security runtime use with a simpler seeded PRNG story if it satisfies the workload.
- Remove or quarantine custom AES-CTR DRBG paths that no longer justify their complexity.

### Phase 3: Truth and Review Sync
- Make the final non-security random story explicit in docs and review materials.
- Ensure no stale wording suggests `optimize/random` is part of the canonical secure path.

## Acceptance Criteria
- [x] `src/rng.rs` remains the only canonical secure RNG boundary.
- [x] Retained `optimize/random` runtime usage is simpler and clearly non-security scoped.
- [x] Unnecessary custom AES-DRBG complexity is removed or quarantined.
- [x] Docs and review materials tell the simplified truth consistently.

## Validation Matrix
- `cargo check`
- `cargo clippy --all-targets --all-features -- -W clippy::all`
- targeted tests for affected random consumers
- guardrail checks that protect the secure RNG boundary

## Final Status
- `src/optimize/random.rs` now uses a secure-seeded per-thread `StdRng` for retained non-security helpers:
  - `random_u64()`
  - `random_array_u32(...)`
  - `shuffle(...)`
- The previous custom AES-CTR DRBG machine room and architecture-specific random-array/shuffle backends were removed from the retained helper story.
- `src/rng.rs` remains the canonical secure RNG owner.
- `rt-random-aes-ctr.rs` now proves the retained AArch64 optimize-random helper contract instead of asserting an internal AES-CTR telemetry detail.
- Runtime guardrails and canonical docs now describe `accelerate::random` as a secure-seeded non-security/test-only helper surface, not as a retained AES-CTR fast path.
