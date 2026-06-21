# TODO-253: Deduplicate Hex Encoding Logic

## Severity: LOW

## Context
Hex byte encoding appears in two separate locations:
1. `src/implementations/server/admin_http.rs:188` - `push_hex_byte()` as a named function
2. `src/rng.rs:39` - identical logic inline in `secure_hex()`

Both convert a byte to two hex characters using the same nibble-shift approach.

## Desired Outcome
- Extract hex encoding into a single shared utility function (e.g., in `src/optimize/string.rs` or `src/env_utils.rs`).
- Replace both call sites with the shared function.

## Files
- `src/implementations/server/admin_http.rs` (~line 188)
- `src/rng.rs` (~line 39)

## Completion Criteria
- Single source of truth for hex byte encoding.
- `cargo test` passes, clippy clean.
