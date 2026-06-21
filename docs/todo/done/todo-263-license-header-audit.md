# TODO-263: Reconcile License Headers Across Source Files

## Severity: LOW

## Context
`src/core.rs:1-30` contains a BSD-3-Clause license header, while `Cargo.toml` declares `license = "MIT"` and `docs/LICENSE` is MIT. This legal inconsistency could confuse contributors and create licensing ambiguity.

## Desired Outcome
- Decide on a single canonical license (MIT or BSD-3-Clause).
- Audit all source files for license headers; make them consistent.
- If BSD-3-Clause header in core.rs is from a fork/upstream: add attribution comment and clarify dual-licensing if needed.

## Files
- `src/core.rs` (lines ~1-30)
- `Cargo.toml` (license field)
- `docs/LICENSE`
- Any other files with license headers

## Completion Criteria
- All license headers match the canonical project license.
- No legal ambiguity between Cargo.toml, LICENSE file, and source headers.
