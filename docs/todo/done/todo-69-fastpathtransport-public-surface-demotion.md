# TODO 69: `FastPathTransport` Public Surface Demotion

## Scope
- `src/transport/xdp.rs`
- `src/main.rs`

## Problem Statement (Audit Evidence, 2026-03-05)
- `FastPathTransport` is a large public transport abstraction.
  - Evidence: `src/transport/xdp.rs:809`
- Real non-test usage is essentially compat smoke only.
  - Evidence: `src/main.rs:1555`

## Objectives
- Make `FastPathTransport` support state match reality.

## Work Breakdown
- [x] Reclassify `FastPathTransport` as canonical, compat-only, or test-only.
- [x] Adjust visibility/exports/docs accordingly.
- [x] Keep only the necessary compat/test coverage if it is not canonical.

## Acceptance Criteria
- [x] `FastPathTransport` no longer looks more production-active than it is.

## Progress Notes
- 2026-03-05: Created from deep forensic review.
- 2026-03-08: Re-verified the original audit evidence and confirmed the public-surface part is already resolved: `FastPathTransport` is private to `src/transport/xdp.rs` and real non-test usage is limited to compat smoke routing.
- 2026-03-08: Tightened the code comment on `FastPathTransport` to state its real role explicitly: compatibility-only shim for xdp smoke and local module tests.
- 2026-03-08: Added an audit guardrail that fails if `FastPathTransport` regains a public, crate-visible, or module-exported type declaration.
