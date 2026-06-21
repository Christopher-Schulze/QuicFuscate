# TODO-255: Fix //? Doc Comment Typo in stealth.rs

## Severity: LOW

## Context
`src/stealth.rs:36` has a `//? ` comment instead of `///` or `//!`. This is a typo that breaks the rustdoc chain at that point, causing documentation to be truncated in generated docs.

## Desired Outcome
- Fix `//? ` to the correct doc comment style (`///` for item docs or `//!` for module docs).
- Scan for any other `//? ` typos across the codebase.

## Files
- `src/stealth.rs` (line ~36)

## Completion Criteria
- No `//? ` typos in the codebase.
- `cargo doc` generates complete documentation for stealth.rs.
- `cargo test` passes, clippy clean.
