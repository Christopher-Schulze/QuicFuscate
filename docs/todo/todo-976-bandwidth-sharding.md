# TODO-976 - Per-client bandwidth admission mutex sharding

Status: DONE (local + Omega aarch64 Linux)

## Problem

`admit_session_bandwidth` ran once per forwarded packet on the server
data path and took the `SessionManager` **write** lock:

```rust
let decision = sessions.write().check_bandwidth(session_id, direction, bytes);
```

`check_bandwidth` needed `&mut self` only because `bandwidth_manager`
lives inside `SessionManager` and `check()` mutates the target client's
token bucket + quota counters. The write lock serialized every inbound
datagram across ALL sessions on the server - the same guard also
blocked concurrent `get_by_remote_addr` lookups on the TUN sink path.

## Fix

`PerClientBandwidthManager.clients` changed from
`HashMap<u64, ClientBandwidthEntry>` to
`HashMap<u64, Mutex<ClientBandwidthEntry>>`:

- `check(&self)` - shared map lookup + per-client mutex; only traffic
  of the same session serializes. Denial audit emission moved after the
  entry lock is released (it previously ran inside the global write
  lock).
- `stats(&self)` - locks the entry briefly to snapshot counters.
- `add_client` / `remove_client` / `update_client_policy` /
  `reset_client_quota` keep `&mut self` - session lifecycle is a cold
  path still covered by `sessions.write()`.

`SessionManager::check_bandwidth` is now `&self`; all callsites moved
from `sessions.write()` to `sessions.read()`:

- `live_auth.rs` `admit_session_bandwidth` (per-datagram admission)
- `tun_path.rs` batch drain guard (comment updated: read guard covers
  stats + token-bucket checks)
- `tun_path.rs` fast-path guard

## Files

- `src/implementations/server/bandwidth.rs` - per-entry mutex, &self check/stats
- `src/implementations/server/session.rs` - check_bandwidth signature
- `src/implementations/server/live_auth.rs` - read-guard admission
- `src/implementations/server/tun_path.rs` - two read-guard downgrades

## Verification

- `cargo test --lib bandwidth` - 36/36
- `cargo test --lib implementations::server::` - 549/549
- clippy/fmt clean
- Omega: bandwidth 36/36 native aarch64 Linux (release)
- Commit: b7e10f9
