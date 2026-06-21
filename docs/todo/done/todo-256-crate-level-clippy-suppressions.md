# TODO-256: Audit Crate-Level Clippy Suppressions

## Severity: MEDIUM

## Context
`src/lib.rs:14` has `#![allow(clippy::too_many_arguments)]` applied globally to the entire crate. This suppresses the lint for every function in every module, hiding legitimate cases where function signatures should be refactored. Global suppressions should be replaced with targeted per-function `#[allow(...)]` where justified.

## Desired Outcome
- Remove the crate-level `#![allow(clippy::too_many_arguments)]`.
- For functions that legitimately need many arguments, add per-function `#[allow(clippy::too_many_arguments)]` with a comment explaining why.
- For functions that could be refactored (e.g., by introducing a config struct), refactor them.

## Files
- `src/lib.rs` (line ~14)
- Multiple files with functions that currently rely on the global suppression

## Completion Criteria
- No crate-level clippy suppressions unless absolutely unavoidable.
- Per-function suppressions are justified with comments.
- `cargo clippy -- -D warnings` passes.
