# TODO-952 — Server live state: `ConnectionId` keys instead of `Vec<u8>` conn_id allocs

## Status
DONE

## Problem
`acquire_runtime_client_with` runs for **every inbound datagram** on the
server, and the `Entry::Occupied` arm built `conn_id` via
`source_id().as_ref().to_vec()` — a heap allocation per packet. The same
`to_vec` pattern appeared on connect (Vacant arm + `qkey_auth.insert`),
idle-check, revoke, admin-kick, closed-pending sweep, and session-timeout
paths — all because `qkey_auth` was keyed `HashMap<Vec<u8>, QKeyAuthState>`
and `LiveClientRuntime.conn_id` was an owned `Vec<u8>`.

`qf_transport_types::ConnectionId` already exists for exactly this purpose:
`Copy`, 21 bytes inline (`[u8; 20] + len`), zero heap — its doc comment even
states it "avoids heap allocation for every packet's connection identifiers".

## Solution
- `ConnectionId` gains `impl Borrow<[u8]>` so `HashMap<ConnectionId, _>`
  keeps working with existing `&[u8]` lookups (`get`/`get_mut`/`remove`
  take `&Q where K: Borrow<Q>`).
- `qkey_auth` key type: `Vec<u8>` → `ConnectionId`.
- `LiveClientRuntime.conn_id`: `Vec<u8>` → `ConnectionId` (Copy — the
  per-datagram `to_vec` is gone entirely, not just cheaper).
- `LiveClientDatagramResult.auth_result` / `remove_auth_conn_id` and
  `commit_qkey_auth_result` / `handle_qkey_auth` signatures carry
  `ConnectionId` end to end — auth bookkeeping paths are alloc-free too.
- `qkey_datagram_auth_result` builds `ConnectionId::from_ref` instead of
  `to_vec`; all `insert` sites pass `*conn.source_id()` directly.
- Test sites updated (`*source_id()`, `ConnectionId::from_ref`).

## Verification
- `cargo check --all-targets` clean locally and on Omega.
- `cargo clippy --lib --all-targets` clean both platforms.
- qkey tests **129/129**, live_state 4/4, qf-transport-types 43/43 on Omega.

## Files
- `crates/qf-transport-types/src/lib.rs` — `Borrow<[u8]>` impl.
- `src/implementations/server/live_state.rs` — map key + `conn_id` field +
  all `to_vec` sites.
- `src/implementations/server/live_state/qkey_auth.rs` — `ConnectionId`
  through timeout/commit/handle paths.
- `src/implementations/server/live_auth.rs` — map param, result struct,
  `qkey_datagram_auth_result`, `reconcile_live_clients` retain.
- `src/implementations/server/tests_inline/` — test sites.
