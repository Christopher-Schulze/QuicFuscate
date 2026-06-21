# TODO-260: Split Monolithic Source Files into Focused Submodules

## Severity: MEDIUM

## Context
Several source files exceed reasonable single-file sizes:
- `fec.rs`: ~9030 lines
- `crypto.rs`: ~9811 lines
- `stealth.rs`: ~5839 lines
- `optimize.rs`: ~5245 lines
- `transport/connection.rs`: ~3143 lines
- `main.rs`: ~2195 lines

While not a bug, this significantly impacts maintainability, code review speed, and merge conflict frequency.

## Desired Outcome
- Split each monolithic file into focused submodules with clear ownership boundaries.
- Example: `fec.rs` -> `fec/mod.rs`, `fec/codec.rs`, `fec/controller.rs`, `fec/simd.rs`
- Example: `crypto.rs` -> `crypto/mod.rs`, `crypto/aegis.rs`, `crypto/morus.rs`, `crypto/aes_gcm.rs`, `crypto/chacha.rs`
- Maintain public API surface (re-exports from mod.rs).
- Prioritize by impact: crypto.rs and fec.rs first (most reviews, most changes).

## Files
- `src/fec.rs`, `src/crypto.rs`, `src/stealth.rs`, `src/optimize.rs`
- `src/transport/connection.rs`, `src/main.rs`

## Completion Criteria
- No single source file exceeds ~2000 lines.
- Module boundaries align with logical responsibilities.
- All tests pass, public API unchanged.
