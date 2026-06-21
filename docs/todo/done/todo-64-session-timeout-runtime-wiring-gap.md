# TODO 64: Session Timeout Runtime Wiring Gap

## Scope
- `src/implementations/server/session.rs`
- `src/implementations/server/mod.rs`
- `src/main.rs`

## Problem Statement (Audit Evidence, 2026-03-05)
- Session expiration logic exists.
  - Evidence: `src/implementations/server/session.rs:94`-`:102`, `:198`
- No real runtime path calls session cleanup.
- Standalone path separately implements QKey auth timeout logic.
  - Evidence: `src/main.rs:3470`-`:3494`

## Objectives
- Make session timeout/cleanup a real runtime behavior.
- Clarify relationship between session timeout and auth timeout.

## Work Breakdown
- [x] Wire session cleanup into the canonical server lifecycle.
- [x] Decide how auth timeout and session timeout interact.
- [x] Add tests for timeout-triggered cleanup.

## Acceptance Criteria
- [x] Session timeout is no longer dormant infrastructure.
- [x] Timeout semantics are explicit and tested.

## Progress Notes
- 2026-03-05: Created from deep forensic review.
- 2026-03-08: The original audit finding is now stale. Canonical standalone housekeeping already calls `LiveServerState::reap_expired_sessions(...)`, which removes expired shared-domain sessions, closes matching live connections, clears auth state, prunes snapshots, and updates active metrics.
- 2026-03-08: Timeout semantics are now explicit in the task contract:
  - session timeout is the long-lived shared-domain session expiry driven by `client_timeout_secs`
  - QKey auth timeout is a short pre-auth gate (`QKEY_AUTH_TIMEOUT`) for unauthenticated handshakes
  - auth timeout closes the unauthenticated connection first; shared session cleanup then follows through the normal runtime reconcile/expiry lifecycle
- 2026-03-08: Added runtime-lifecycle regression coverage in `src/implementations/server/mod.rs`:
  - `test_housekeeping_tick_reaps_expired_sessions_from_runtime_lifecycle`
