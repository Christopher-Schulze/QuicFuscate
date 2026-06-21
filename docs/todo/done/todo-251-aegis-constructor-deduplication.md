# TODO-251: Deduplicate Aegis128L/X4/X8 Constructors

## Severity: LOW

## Context
`src/crypto.rs:546-554` (Aegis128L), `563-571` (Aegis128X4), `580-588` (Aegis128X8) have byte-for-byte identical `new()` implementations: copy key, copy IV, return Self. This is classic copy-paste code.

## Desired Outcome
- Extract the common initialization logic into a shared macro, generic function, or trait default implementation.
- Maintain the separate struct types (they serve different SIMD widths) but share the constructor logic.

## Files
- `src/crypto.rs` (lines ~546-590)

## Completion Criteria
- No duplicated constructor code across AEGIS variants.
- All existing tests continue to pass.
- `cargo test` passes, clippy clean.
