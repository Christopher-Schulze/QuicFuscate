# TODO-206: Clippy Debt and Code-Hygiene Elimination

## Status
**COMPLETED - 2026-03-17**

## Severity
**HIGH**

## Context
The current workspace fails strict Clippy on real issues: dead state, outdated style, API usage that mismatches the declared toolchain baseline, and small hygiene problems that undermine a no-warning standard.

## Objective
Eliminate the current Clippy failures and adjacent hygiene debt so the repository meets a strict no-warning bar on the selected stable Rust baseline.

## Current Known Failure Classes
- dead `pending_path_challenges` state in `src/transport/connection.rs`
- `needless_return` in `src/core.rs`
- `identity_op` in `src/implementations/server/admin_http.rs`
- incompatible helper usage relative to the old baseline in `src/fec.rs`, `src/optimize.rs`, and `src/implementations/server/accept.rs`

## Detailed Work Plan
1. Reproduce the full Clippy failure set on the chosen stable baseline.
2. Fix all currently known failures.
3. Sweep adjacent local code for nearby hygiene debt revealed by those edits.
4. Re-run strict Clippy until the workspace is clean.
5. Update documentation that previously overclaimed the Clippy state.

## Tracking Checklist
- [x] Failure inventory captured.
- [x] Dead-code issue resolved or correctly integrated.
- [x] Style/hygiene issues fixed.
- [x] Toolchain-compatibility issues resolved.
- [x] Strict Clippy rerun green.

## Completion Notes
- Removed the dead migration-path field and the nearby hygiene issues that were breaking strict Clippy.
- Aligned the codebase with the selected Rust `1.93.0` baseline instead of carrying stale 1.80-era compatibility friction.
- Re-ran strict Clippy successfully on the full workspace.

## Acceptance Criteria
- `cargo clippy --workspace --all-targets -- -D warnings` passes.
- No current known Clippy failure remains unresolved.
- Docs do not overstate code-quality status.

## Dependencies
- TODO-204
- TODO-205
- TODO-212

## Affected Files
- `src/core.rs`
- `src/fec.rs`
- `src/implementations/server/accept.rs`
- `src/implementations/server/admin_http.rs`
- `src/optimize.rs`
- `src/transport/connection.rs`
