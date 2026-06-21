# TODO-252: Remove Duplicate runtime_cc_algorithm() Function

## Severity: LOW

## Context
`src/main.rs:1444-1455` contains a standalone `runtime_cc_algorithm()` function that performs the exact same match as `impl From<CcAlgorithm>` at lines ~695-705. Both convert a CLI-parsed congestion control enum to the transport-layer enum. This is pure duplication.

## Desired Outcome
- Remove `runtime_cc_algorithm()` and replace all call sites with `.into()` or `From::from()`.
- Keep the single canonical `From<CcAlgorithm>` impl.

## Files
- `src/main.rs` (lines ~695-705, ~1444-1455)

## Completion Criteria
- Only one conversion path between CLI CC enum and transport CC enum.
- `cargo test` passes, clippy clean.
