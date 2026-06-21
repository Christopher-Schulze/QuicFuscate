# TODO 53: FEC/SIMD Dead-Code Resolution (Completed)

## Scope
- Remaining dead-code suppression hotspots and dead-code candidates in:
  - `src/fec.rs`
  - `src/simd.rs`

## Problem Statement (Historical Audit Evidence, 2026-03-05)
- Repository-wide dead-code suppressions were mostly cleaned from runtime modules, but the last concentrated cluster then remained in:
  - `src/fec.rs`
  - `src/simd.rs`
- These modules are highly feature/arch dependent, so blind removal would have been risky and could have broken non-host targets.

## Objectives
- Classify each remaining suppression as one of:
  - required for cross-target/cross-feature builds,
  - test-only and should be moved under `#[cfg(test)]`,
  - dead and removable.
- Remove broad suppressions where possible and replace with precise `cfg_attr` guards.
- Keep behavior unchanged for active runtime paths.

## Work Breakdown
### A. Evidence and Classification
- [x] Build a line-by-line suppression inventory for `fec.rs` and `simd.rs` with callsite evidence. [x] 2026-03-05
- [x] Resolve and remove `fec.rs` suppression items by deleting dead fields/methods after callsite verification. [x] 2026-03-05
- [x] Tag remaining `simd.rs` suppression surface as `narrow` and convert to explicit target-scoped handling. [x] 2026-03-05

### B. Refactor and Cleanup
- [x] Replace/remove broad suppressions in `fec.rs` by removing dead code and preserving active paths. [x] 2026-03-05
- [x] Replace module-level `simd.rs` suppression with target/feature/test-localized attributes. [x] 2026-03-05
- [x] Move test-only `simd` helpers into test-local or target-local scopes where possible, without widening runtime claims. [x] 2026-03-05
- [x] Re-scan `simd` for a final provably dead cluster and keep only narrow cross-target/test allowances where removal is not fully proven. [x] 2026-03-08

### C. Validation
- [x] Run `cargo check` and strict clippy after each logical cleanup chunk. [x] 2026-03-08
- [x] Run `scripts/tests/audits/audit-runtime-guardrails.sh` and `scripts/tests/audits/audit-all-comprehensive.sh` after cleanup. [x] 2026-03-08
- [x] Add/adjust tests when a removed/narrowed item had implicit behavior coupling. [x] 2026-03-05

## Acceptance Criteria
- [x] No broad module-level dead-code suppression remains in active runtime modules unless justified and documented. [x] 2026-03-08
- [x] `fec.rs`/`simd.rs` suppressions are minimized and explicitly justified. [x] 2026-03-08
- [x] Audit scripts and checks pass without new warnings/regressions (except known unsafe-volume warning). [x] 2026-03-08

## Deliverables
- [x] Classification matrix (keep/narrow/remove) linked to file/line references. [x] 2026-03-05
- [x] Refactor commits for narrowed/removed suppressions. [x] 2026-03-08
- [x] Updated audit evidence in docs/todo progress notes. [x] 2026-03-08

## Progress Notes
- 2026-03-05: Created from post-cleanup residual scan to isolate remaining dead-code suppression debt.
- 2026-03-05: `fec.rs` cluster cleaned; `cargo check` and comprehensive audits pass after removal.
- 2026-03-05: `simd.rs` module-level suppression removed; backend dispatch and telemetry matches were narrowed with explicit target cfg guards, including `hmac_sha256` backend counters.
- 2026-03-08: Final re-scan found no additional provably dead `simd` runtime cluster worth blind removal. The remaining narrow allowances stay tied to test-only or cross-target seams, and the runtime guardrail now also watches `src/fec.rs` and `src/simd.rs` for broad module-level `dead_code` regression.
