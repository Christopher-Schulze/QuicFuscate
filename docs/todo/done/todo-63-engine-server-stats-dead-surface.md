# TODO 63: Engine Server Stats Dead Surface

## Scope
- `src/engine/engine.rs`
- `src/implementations/server/mod.rs`

## Problem Statement (Audit Evidence, 2026-03-05)
- Engine refreshes embedded server byte/packet stats.
  - Evidence: `src/engine/engine.rs:811`-`:820`
- Embedded `ServerRuntime` does not meaningfully produce those counters today.
  - Evidence: `src/implementations/server/mod.rs:899`-`:900`

## Objectives
- Make engine server stats truthful.
- Remove dead exported stat surfaces.

## Work Breakdown
- [x] Inventory all `ServerRuntime` counters read by engine.
- [x] Add real producers or retire dead counters.
- [x] Add tests for stat truth under server activity.

## Acceptance Criteria
- [x] No dead/stale server byte/packet counters remain exposed through engine.

## Progress Notes
- 2026-03-05: Created from deep forensic review.
- 2026-03-08: The original audit finding is now stale. `EngineMode::Server` runs the real headless standalone server runtime and projects server-mode bytes/packets/active-client stats from runtime-owned `implementations/server::Metrics`.
- 2026-03-08: `refresh_stats()` already retired the false server-side RTT/loss projection by forcing those fields to `0` until real server-owned producers exist.
- 2026-03-08: Added regression coverage in `src/engine/engine.rs` proving that server-mode stats are sourced from runtime-owned server metrics producers (`record_ingress_datagram(...)` / `record_egress_datagram(...)`) instead of the global transport client path.
