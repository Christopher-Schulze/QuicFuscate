# TODO 67: AArch64 Secure RNG Contract Mismatch (Completed)

## Scope
- `src/optimize/random.rs`
- `src/rng.rs`

## Problem Statement (Historical Audit Evidence, 2026-03-05)
- `random_bytes_secure()` used to claim secure semantics.
- On AArch64 that old contract was misleading because a custom AES-CTR DRBG path existed outside the canonical runtime RNG story.

## Objectives
- Make RNG naming and behavior honest on AArch64.

## Work Breakdown
- [x] Decide whether the custom DRBG remains and under what non-security name/contract. [x] 2026-03-08
- [x] Align the old secure alias problem with canonical RNG policy by removing the misleading alias and keeping only non-security helper naming. [x] 2026-03-08
- [x] Add or confirm explicit AArch64 contract tests. [x] 2026-03-08

## Acceptance Criteria
- [x] No misleading secure RNG contract remains on AArch64. [x] 2026-03-08

## Progress Notes
- 2026-03-05: Created from deep forensic review.
- 2026-03-08: Verified that the old `random_bytes_secure()` contract is already gone, `accelerate::random` is documented as compat/test-only, and the retained AArch64 AES-CTR helper path only backs `rust-tests`/test helper surfaces such as `random_u64()` and `random_array_u32()`.
- 2026-03-08: Confirmed explicit AArch64 contract coverage in `scripts/tests/rust/rt-random-aes-ctr.rs` and widened the runtime guardrail so this coverage cannot silently disappear.
