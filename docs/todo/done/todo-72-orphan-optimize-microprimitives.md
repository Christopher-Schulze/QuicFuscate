# TODO 72: Orphan Optimize Microprimitives

## Scope
- `src/optimize/memory.rs`
- `src/optimize/string.rs`
- related public optimize surfaces

## Problem Statement (Audit Evidence, 2026-03-05)
- Public micro-optimization helpers exist with no real runtime call sites found in repo scan.
  - Evidence: `src/optimize/memory.rs:14`
  - Evidence: `src/optimize/string.rs:10`

## Objectives
- Eliminate orphan public microprimitives.

## Work Breakdown
- [x] Inventory each orphan microprimitive and verify non-usage.
- [x] Decide integration, quarantine, rename, or removal per symbol.
- [x] Add guardrails for future orphan helper exports.

## Acceptance Criteria
- [x] No public microprimitive remains without an explicit runtime/test owner.

## Progress Notes
- 2026-03-05: Created from deep forensic review.
- 2026-03-08: Re-verified the remaining public memory/string microprimitives and confirmed they now have explicit owners:
  - `optimize::string::string_contains(...)` has a real runtime owner in `src/stealth.rs`
  - `base64_encode(...)` / `base64_decode(...)` are already gated to `cfg(any(test, feature = "rust-tests"))` and are used by explicit rust parity/selfcheck tests
  - `transpose_matrix(...)` and `LockFreeRingBuffer` are already gated to `cfg(any(test, feature = "rust-tests"))` and are used by explicit rust parity tests
- 2026-03-08: Tightened inline comments in `src/optimize/string.rs` and `src/optimize/memory.rs` so the retained runtime-vs-rust-tests ownership is explicit.
- 2026-03-08: Added an audit guardrail that fails if these memory/string microprimitives lose their explicit runtime or rust-tests owner classification.
