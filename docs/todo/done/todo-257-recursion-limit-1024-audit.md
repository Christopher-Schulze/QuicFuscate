# TODO-257: Audit and Reduce recursion_limit = "1024"

## Severity: LOW

## Context
`src/lib.rs:16` sets `#![recursion_limit = "1024"]`, which is 8x the default of 128. This is undocumented - no comment explains which macro or type expansion requires this. High recursion limits can mask deeply nested macro expansions that should be simplified.

## Desired Outcome
- Identify which macro(s) or type(s) require the elevated recursion limit.
- Reduce the limit to the minimum necessary value.
- Add a comment documenting the reason (e.g., "Required by X macro expansion in Y module").

## Files
- `src/lib.rs` (line ~16)

## Completion Criteria
- recursion_limit is set to the minimum required value (or removed if default suffices).
- A comment documents the reason for any non-default value.
- `cargo build` succeeds with the reduced limit.
