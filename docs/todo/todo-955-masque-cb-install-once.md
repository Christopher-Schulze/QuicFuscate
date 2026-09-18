# TODO-955 — MASQUE datagram sink: install once instead of rebind per datagram

## Status
DONE

## Problem
On TUN-enabled server connections, `process_live_server_client_datagram`
**re-installed** the MASQUE→TUN datagram callback on every inbound datagram —
by design, because the `'static` closure captured the current `auth_gate`.
Cost per datagram:

- `Arc::new(AtomicBool)` for the gate
- ~13 `Arc::clone`s for captured dependencies
- `Arc::new(Mutex::new(Box::new(closure)))` — three allocations
- Drop of the previous callback → ~16 atomic decrements

≈45 atomic ops + 4 allocs per inbound datagram on the VPN hot path.

Additionally, `LiveClientRuntime.qkey_auth` cloned the whole
`QKeyAuthState` (2 `String`s + policies) per datagram just to read `authed`
and `expected_token_sha256` — which was itself cloned into `Option<String>`.

## Solution
- `QuicFuscateConnection` gains two persistent holders:
  `masque_datagram_auth_gate: Arc<AtomicBool>` and
  `masque_logical_addr: Arc<Mutex<SocketAddr>>`, with `set_*`/`get`
  accessors. Per pass: one atomic store + one mutex store.
- The callback is now installed once (`has_masque_datagram_cb` guard);
  captures are all stable Arcs (`sessions`, `metrics`, `tun` family,
  `dns_*`, `forwarding_policy`, `fanout_queue`, `fingerprint_profile` —
  frozen per connection persona).
- Inside the callback, `logical_addr` is read from the persistent cell and
  `(session_id, assigned_ips)` resolved fresh via
  `sessions.get_by_remote_addr` — strictly fresher than the old rebind
  (per-invocation instead of per-pass) and correct across migration commits
  and session rebinds. The `read()` guard drops before
  `admit_session_bandwidth` takes `write()` — no upgrade deadlock.
- `LiveClientRuntime.qkey_auth: Option<QKeyAuthState>` →
  `Option<&'a QKeyAuthState>` — the per-datagram state clone (2 String
  allocs + policies) is gone; `expected_token_sha256` is passed as
  `Option<&str>` (another 64-byte alloc gone).

## Verification
- `cargo check --all-targets` + `cargo clippy --lib --all-targets` clean on
  macOS and Omega (Linux).
- qkey 129/129, live_state 4/4, masque 47/47, connection 326/326.

## Files
- `src/core/connection.rs` — two persistent fields + init.
- `src/core/connection/h3_runtime.rs` — gate/addr accessors.
- `src/implementations/server/live_state.rs` — `Option<&'a QKeyAuthState>`.
- `src/implementations/server/live_auth.rs` — once-install block,
  in-callback session resolution, `&str` token, persistent gate.
