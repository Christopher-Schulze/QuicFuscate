# TODO-953 - Acquire path: O(clients) DCID parse -> slice+memcmp; triple session lock -> one

## Status
DONE

## Problem
Two per-datagram costs on `acquire_runtime_client_with` (runs for every
inbound server datagram):

1. `handle_incoming_path_update` -> `find_live_client_by_dcid`: for any
   datagram from an unregistered source address, the code iterated **all
   clients** and called `parse_header` per client - O(clients) header parses
   plus **2 Vec allocations per client** (`dcid`/`scid` `to_vec` inside
   `parse_header`). Spoofed-source datagrams turn this into an amplification
   vector: one packet -> N parses + 2N allocs.

2. The `Entry::Occupied` arm fetched `assigned_ips`, `session_id`, and
   `session_stats` via three separate domain accessors - each taking
   `sessions.read()` -> **3 RwLock acquisitions + 5 map lookups per datagram**.
   `existing_assigned_ips` was additionally fetched before the match arm and
   discarded unused on the `Vacant` (new-connection) path.

## Solution
- `find_live_client_by_dcid`: server SCIDs are always `MAX_CONN_ID_LEN`
  (20 B random at accept), so the wire DCID is sliced out directly -
  short header: `buf[1..21]`; long header: wire `dcid_len` field - zero
  allocations, zero parses. The client scan is now a plain memcmp.
- `LiveServerDomain::session_view_by_remote`: one `sessions.read()` guard
  yields `(SessionId, Arc<SessionStats>, AssignedClientIps)` - the session
  is fetched once and projected twice. Semantics preserved: `session_id`
  can still be `Some` while the session row is absent.
- The triple fetch moved inside the `Occupied` arm, so `Vacant` no longer
  pays for a lookup it never used.
- Dead `assigned_ips_by_remote` accessor removed.

## Verification
- `cargo check --all-targets` clean locally and on Omega.
- `cargo clippy --lib --all-targets` clean.
- qkey 129/129, live_state 4/4 on both platforms.

## Files
- `src/implementations/server/live_auth.rs` - slice-based DCID extraction.
- `src/implementations/server/live_state/domain.rs` - `session_view_by_remote`.
- `src/implementations/server/live_state.rs` - Occupied arm uses it.
