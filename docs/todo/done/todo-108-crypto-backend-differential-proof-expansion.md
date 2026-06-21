# TODO 108: Crypto Backend Differential Proof Expansion

## Scope
- retained AEAD backend equivalence
- AEGIS width-family proof expansion
- MORUS scalar versus SIMD parity expansion
- adversarial nonce/AAD/tag mismatch coverage

## Problem Statement
- The retained custom data-plane crypto story is now honest and bounded, but the strongest remaining reviewer question is:
  - do the retained backend variants behave identically under broad input coverage?
- Current tests are already meaningful, but they still read like a strong engineering baseline rather than an exhaustive retained-backend proof layer.

## Desired End State
- AEGIS and MORUS retained backend families have a visibly stronger differential proof surface.
- The repo can point to broad backend-equivalence checks instead of only representative parity tests.
- Width selection remains an internal performance detail, not a semantic behavior fork.

## Current Truth Snapshot
- Product contract is narrow:
  - `Aegis128L`
  - `Morus1280_128`
- Internal retained backends exist:
  - `Aegis128X4`
  - `Aegis128X8`
- Current proof surfaces already include:
  - `scripts/tests/rust/rt-security-suite.rs`
  - `scripts/tests/rust/rt-property-suite.rs`
  - `scripts/tests/fuzz/fuzz_targets/crypto_operations.rs`
  - retained parity tests inside `src/crypto.rs`

## Architecture Gap
- The gap is no longer contract drift.
- The gap is proof depth:
  - broader randomized length matrices
  - more cross-backend equivalence
  - more adversarial negative-path verification

## Execution Plan

### Phase 1: AEGIS Family Expansion
- Expand differential checks between:
  - `Aegis128L`
  - `Aegis128X4`
  - `Aegis128X8`
- Cover:
  - short payloads
  - mid payloads
  - large payloads
  - varied AAD lengths
  - repeated random corpora

### Phase 2: MORUS Backend Expansion
- Expand scalar versus SIMD checks for MORUS.
- Add larger randomized corpora and more edge-length coverage.

### Phase 3: Adversarial Matrix
- Add explicit mismatch tests for:
  - modified ciphertext
  - modified tag
  - modified AAD
  - modified nonce
  - cross-open attempts between families/backends where meaningful

### Phase 4: Property/Fuzz Tightening
- Extend property and fuzz coverage to ensure retained backend families are exercised through the public contract, not only internal helpers.

## Acceptance Criteria
- [x] AEGIS retained backend family has broader equivalence coverage.
- [x] MORUS retained backend family has broader scalar/SIMD equivalence coverage.
- [x] Negative-path mutation matrix is visibly stronger.
- [x] Public-contract differential tests remain green under `rust-tests`.

## Validation Matrix
- `cargo test --features rust-tests --test rt-security-suite`
- `cargo test --features rust-tests --test rt-property-suite`
- relevant lib crypto tests
- crypto fuzz target sanity checks

## Final Status
- Expanded the retained AEGIS backend proof in `src/crypto.rs`:
  - `aegis_x_variants_match_ciphertext_and_tag_across_matrix`
  - now checks ciphertext and tag equality, not only roundtrip, across:
    - multiple nonce seeds
    - multiple AAD lengths
    - multiple payload lengths
- Expanded the retained MORUS proof in `src/crypto.rs`:
  - `test_morus_native_vs_optimized_matrix`
  - now checks:
    - native ciphertext equality versus optimized ciphertext
    - native tag equality versus optimized tag
    - cross-open compatibility in both directions
    - length/AAD/nonce matrix coverage
- Expanded the public-contract property layer in `scripts/tests/rust/rt-property-suite.rs`:
  - `prop_data_aead_alias_ciphertext_matches_public_contract`
  - proves that public AEGIS aliases do not just roundtrip, but emit identical ciphertext/tag bytes relative to the canonical `Aegis128L` contract
- Validation:
  - `cargo test --features rust-tests aegis_x_variants_match_ciphertext_and_tag_across_matrix --lib`
  - `cargo test --features rust-tests test_morus_native_vs_optimized_matrix --lib`
  - `cargo test --features rust-tests --test rt-property-suite prop_data_aead_alias_ciphertext_matches_public_contract`
  - `cargo test --features rust-tests --test rt-security-suite`
  - `cargo clippy --all-targets --all-features -- -W clippy::all`
- Result:
  - all green
