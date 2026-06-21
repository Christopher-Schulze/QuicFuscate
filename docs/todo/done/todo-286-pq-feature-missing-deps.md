# TODO-286: PQ Feature Flag Missing Crate Dependencies

## Problem
`src/crypto/pq.rs` references `pqcrypto_kyber` and `pqcrypto_traits` crates that are NOT listed in Cargo.toml. Building with `--features pq` would fail at compile time.

The `pq` feature is correctly gated behind `#[cfg(feature = "pq")]` so default builds are unaffected, but the feature flag exists in Cargo.toml without the dependencies to back it.

## Source
AI Model Review (GLM-5) - verified correct.

## Location
- `Cargo.toml:123` - `pq = []` (empty feature, no deps)
- `src/crypto/pq.rs` - references unresolved crates

## Fix
Either add the PQ crate dependencies as optional deps wired to the `pq` feature, or add a clear comment that PQ is a placeholder for future work.

## Acceptance Criteria
- `pq` feature either compiles correctly OR is clearly documented as placeholder
- No misleading feature flag
