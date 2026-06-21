# TODO 74: Auth Failure Metrics Rewiring

## Scope
- `src/main.rs`
- `src/implementations/server/metrics.rs`
- related telemetry/metrics surfaces

## Problem Statement (Audit Evidence, 2026-03-05)
- Live QKey auth failures increment telemetry and rejection counters.
  - Evidence: `src/main.rs:3398`-`:3400`, `:3482`-`:3484`
- Exported `auth_failed` metric story is not updated accordingly.
  - Evidence: `src/main.rs:2614`

## Objectives
- Make auth-failure observability truthful.

## Work Breakdown
- [x] Map all auth-failure events to metrics producers.
- [x] Rewire missing counter updates.
- [x] Add regression coverage for exported auth-failure metrics.

## Acceptance Criteria
- [x] Auth-failure metrics reflect actual runtime auth-failure events.

## Progress Notes
- 2026-03-05: Created from deep forensic review.
- 2026-03-08: Consolidated QKey auth rejection counting behind `record_qkey_auth_rejection(...)`. Initial-auth reject paths, live HTTP/3 auth rejects, and QKey auth timeouts now share the same exported-metrics producer chain. Added regression tests for direct exported metric increments and the timeout path.
- 2026-03-08: Validation completed cleanly with `cargo test --lib qkey_auth` and `cargo clippy --all-targets --all-features -- -W clippy::all`.
