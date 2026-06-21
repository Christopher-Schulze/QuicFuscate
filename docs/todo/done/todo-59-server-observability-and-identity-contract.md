# TODO 59: Server Observability and Identity Contract

## Scope
- Server metrics, identity, and admin/control-plane contract across:
  - `src/main.rs`
  - `src/engine/engine.rs`
  - `src/implementations/server/metrics.rs`
  - `src/implementations/server/admin.rs`
  - `src/implementations/server/mod.rs`
  - `src/implementations/server/session.rs`

## Problem Statement (Audit Evidence, 2026-03-05)
- Exported server metrics do not fully reflect real runtime events.
  - `ServerRuntime` bytes/packets stats are read by engine but not meaningfully updated.
  - QKey auth failures update telemetry and `connections_rejected`, but not `metrics.auth_failed`.
  - Evidence: `src/engine/engine.rs:811`-`:820`; `src/implementations/server/mod.rs:899`-`:900`; `src/main.rs:3398`-`:3400`; `src/main.rs:3482`-`:3484`
- Admin identity still uses `SocketAddr` strings, while embedded server logic exposes `SessionId`.
  - Evidence: `src/implementations/server/admin.rs:85`, `:118`; `src/main.rs:3031`; `src/implementations/server/session.rs:11`; `src/implementations/server/mod.rs:908`

## Objectives
- Make server metrics truthful and runtime-owned.
- Unify admin/client identity across server entrypoints.
- Ensure exported observability matches canonical server behavior.

## Work Breakdown
### A. Metrics Truthfulness
- [x] Inventory all server metrics and map them to real runtime event owners.
- [x] Fix stale/dead metrics surfaces or explicitly retire them.
- [x] Ensure auth failures, traffic counters, and disconnects increment one canonical metrics story.

### B. Identity Contract
- [x] Decide canonical client identity across server/admin surfaces.
- [x] Align list/kick/status/admin actions to that identity.

### C. Engine/Standalone Alignment
- [x] Ensure embedded engine stats and standalone server stats describe the same model or are clearly separated.
- [x] Remove or document metrics that cannot be truthful until runtime unification is done.

### D. Validation
- [x] Add regression tests for auth-failure counters, traffic counters, and admin identity semantics.
- [x] Add audit checks for stale exported metrics without event producers.

## Acceptance Criteria
- [x] Exported server metrics correspond to real runtime events.
- [x] Admin identity is canonical and not entrypoint-specific.
- [x] Engine/server observability surfaces no longer tell conflicting stories.

## Deliverables
- [x] Server observability map.
- [x] Unified identity contract for admin/control plane.
- [x] Regression coverage for metrics and identity semantics.

## Progress Notes
- 2026-03-05: Created from deep review after server lifecycle audit exposed stale metrics and identity drift.
- 2026-03-06: Admin-visible client projection now prefers `session:<id>` when the live server domain has a backing session, and `LiveServerState::kick_client(...)` can resolve `ClientIdentity::Session(...)` back to the live remote address through the shared session domain. This removes the old standalone `remote:<addr>`-only admin identity contract from the canonical CLI server path.
- 2026-03-08: Closed the first metrics-truth seam in the standalone server runtime. `src/implementations/server/metrics.rs` now has an explicit `connections_accepted` counter and a canonical `record_connection_accepted()` producer. The live runtime accept path in `src/implementations/server/mod.rs` now increments that counter together with `clients_total`, and admin status / metrics JSON now expose the same accepted/rejected/auth-failed story instead of projecting only a partial subset.
- 2026-03-08: Continued the same standalone metrics-owner cleanup by moving accepted/rejected/rate-limited and ingress/egress packet accounting behind `Metrics` methods instead of raw atomic mutation spread across `src/implementations/server/mod.rs`. This narrows the remaining TODO 59 gap to higher-level surface alignment instead of low-level counter ownership drift.
- 2026-03-08: Closed the next engine observability seam in `src/engine/engine.rs`. When the engine runs in server mode and has standalone `server_metrics`, it no longer projects RTT/loss from global transport instrumentation. Those fields are now reset to `0` in server mode until a truthful server-owned producer exists, and a regression test locks that behavior in place.
- 2026-03-08: Aligned the remaining standalone/global observability split for reject/auth/rate/traffic producers. `src/implementations/server/metrics.rs` now mirrors `record_connection_rejected()`, `record_auth_failure()`, `record_rate_limited()`, `record_ingress_datagram(...)`, and `record_egress_datagram(...)` into `crate::instrumentation::global()` so standalone metrics and global instrumentation no longer tell conflicting stories for those event families.
- 2026-03-08: Added regression coverage in `src/implementations/server/metrics.rs` for that mirror contract. The new test asserts that standalone runtime metric producers increase the corresponding global reject/auth/rate/traffic counters, preventing drift from reappearing silently.
- 2026-03-08: Removed the last accepted-connection ownership drift in `src/instrumentation.rs` by making `server.client_connected()` purely lifecycle-oriented again. `connections_accepted` remains a dedicated accept event, guarded by a new runtime audit check and a focused regression test. TODO 59 is complete.
