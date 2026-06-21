# TODO-259: Comment Hygiene - Remove Remnants and Fix Language Inconsistency

## Severity: LOW

## Context
Two issues:
1. `src/lib.rs:170-175` contains explanatory comments about removed modules ("integration module removed", "tests module was removed during consolidation"). These are post-refactor noise.
2. `src/core.rs:1067` has a German comment `// Persona QPACK Index-Policy setzen` in otherwise English-only Rust source code.

## Desired Outcome
- Remove commented-out module references in lib.rs.
- Translate or remove the German comment in core.rs.
- Quick scan for any other stale module comments or non-English comments in src/.

## Files
- `src/lib.rs` (lines ~170-175)
- `src/core.rs` (line ~1067)

## Completion Criteria
- No stale "removed during X" comments in active source files.
- All comments in src/ are in English.
- `cargo test` passes, clippy clean.
