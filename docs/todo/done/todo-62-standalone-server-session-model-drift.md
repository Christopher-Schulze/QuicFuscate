# TODO 62: Standalone Server Session Model Drift

## Scope
- `src/main.rs`
- `src/implementations/server/session.rs`
- `src/implementations/server/ip_pool.rs`
- `src/implementations/server/mod.rs`

## Problem Statement (Audit Evidence, 2026-03-05)
- Standalone server keeps raw live-client maps and auth state instead of using the server-domain session/IP/limit model.
  - Evidence: `src/main.rs:2920`-`:3498`
- Embedded server runtime uses `SessionManager`, `IpPool`, and `ConnectionLimiter`.
  - Evidence: `src/implementations/server/mod.rs:858`-`:920`

## Objectives
- Remove the existence of two different server-domain models.
- Ensure standalone and embedded server paths share one lifecycle model.

## Work Breakdown
- [x] Inventory all standalone-only client/session state.
- [x] Map each piece onto the canonical server-domain model.
- [x] Refactor until the standalone path no longer bypasses session/IP/limit ownership.

## Acceptance Criteria
- [x] There is no parallel standalone-only server session model.
- [x] Session/IP/limit semantics are shared across entrypoints.

## Progress Notes
- 2026-03-05: Created from deep forensic review.
- 2026-03-06: `LiveServerState` now owns a `LiveServerDomain` backed by `SessionManager`, `IpPool`, and `ConnectionLimiter`, and standalone live accepts now register session/IP/limit state instead of bypassing the server-domain model completely.
- 2026-03-06: Live path rebind, closed-client cleanup, admin kick cleanup, and `clients_active` sync now update the shared standalone domain state rather than only the raw live-client map.
- 2026-03-06: Standalone live traffic now records per-session send/receive stats through `SessionStats`, reducing drift between standalone traffic accounting and the embedded `ServerRuntime` session world.
- 2026-03-06: `ServerRuntime::accept_client` and `ServerRuntime::remove_client` now use the same shared domain helper logic as `LiveServerDomain`, so standalone and embedded server entrypoints no longer maintain separate accept/remove invariants.
- 2026-03-06: Session-expiry removal now uses the same shared domain removal path for standalone and embedded server flows; standalone housekeeping closes expired live connections and clears auth/snapshot state while embedded `ServerRuntime::reap_expired_sessions()` reuses the same domain cleanup helper.
- 2026-03-06: Standalone admin snapshots now ingest shared session ownership from `LiveServerDomain`, so control-plane identity and kick semantics resolve through the same session model as the runtime instead of bypassing it with raw `SocketAddr` strings.
- 2026-03-06: Embedded `ServerRuntime` now owns a `SharedServerDomain` wrapper instead of carrying separate session/IP/connection-limiter fields, reducing structural drift between embedded and standalone runtime ownership even further.
- 2026-03-06: `LiveServerDomain` now wraps `SharedServerDomain` instead of keeping its own standalone-only session/IP/limiter storage, so both server entrypaths sit on the same concrete domain-owner type.
- 2026-03-08: Standalone packet rate limiting moved under `SharedServerDomain` as `PacketRateLimiterDomain`, so `LiveServerState` no longer carries a separate standalone-only limiter owner or prune timer.
- 2026-03-08: Remote removal, remote rebind, and expiry cleanup now clear packet-rate-limit IP state through the shared domain owner, removing the last remaining standalone-only live-domain cleanup path.
- 2026-03-08: Added `test_live_server_domain_remove_remote_clears_packet_rate_limit_ip_state`, fixing the new shared-domain packet-rate-limit cleanup contract with regression coverage.
