# TODO-975 - MASQUE per-packet alloc/copy/lock elimination (uplink + downlink)

Status: DONE (local; Omega verification pending)

## Problem

Two independent per-packet overheads sat on the MASQUE VPN data paths:

1. Uplink: `send_masque_udp_payload` cloned `self.host_header` (String)
   on every call:

```rust
let host = self.host_header.clone();
let Some(sid) = self.ensure_masque_tunnel(&host)? else { ... };
```

   The clone existed only to escape a borrow conflict - `host` was used
   solely inside the cold tunnel-establishment path (`format!("{}:443",
   host)`), so every tunneled packet paid a heap alloc for nothing.

2. Downlink: `drain_masque_datagrams` copied every received datagram out
   of the shared `masque_recv_buffer` scratch into a drain `Vec` because
   `dispatch_bound_masque_payload` needed `&mut Vec<u8>` for ingress
   normalization (Darwin/MacOS persona can expand TCP option space by up
   to 24 bytes; wire bound is 40).

3. Downlink lock: `masque_logical_addr` was an
   `Arc<Mutex<SocketAddr>>` locked once per inbound MASQUE datagram in
   the TUN sink callback, although it only changes on migration
   commits.

## Fix

### Uplink

`ensure_masque_tunnel` / `ensure_masque_tunnel_with_requirement` lost
their redundant `host: &str` parameter - all three call sites always
passed `self.host_header`, which the functions now read internally at
the single point of use. String clone removed per uplink packet at
`send_masque_udp_payload`, `ensure_masque_tunnel_for_send`, and
`begin_masque_control_tunnel`.

### Downlink

- `masque_recv_buffer` is allocated with `MASQUE_RECV_HEADROOM` (40 =
  on-wire TCP data-offset option bound) spare bytes; a new
  `masque_recv_capacity` field bounds what `dgram_recv` may fill.
- `try_recv_masque_datagram` returns `(flow_id, offset, payload_len)`
  indices into the scratch instead of copying into a caller `Vec`.
- `masque_recv_region(offset)` exposes `&mut buf[offset..]` - payload
  plus headroom - to the dispatch layer.
- `dispatch_bound_masque_payload` signature changed to
  `(payload: &mut [u8], payload_len)`; the TunIp branch calls
  `normalize_tunnel_ingress_with_capacity` (already used by the pooled-
  block path) and hands `&payload[..outcome.packet_len]` to callbacks.
  Wire semantics identical: the headroom covers the same expansion the
  Vec `reserve_exact` provided.
- Capsule-carried DATAGRAM payloads (`handle_masque_capsule_event`,
  capsule type 0x00) extend their tail once by 40 bytes before dispatch
  - same normalization guarantee, amortized, on a low-frequency path.
- `masque_try_recv_datagram` (test-only) rebuilds the owned Vec from
  the returned indices.

Per inbound MASQUE datagram the payload memcpy is gone; the packet is
normalized in place inside the receive scratch and dispatched as a
slice into the TUN callback.

### Downlink lock

`masque_logical_addr` became `Arc<arc_swap::ArcSwap<SocketAddr>>` - the
same lock-free pattern already used for `crypto_1rtt` and the isolation
IP sets. The TUN sink callback now does one atomic `load()` instead of
mutex lock/unlock per datagram; `set_masque_logical_addr` stores a new
pointee on migration commits.

## Files

- `src/core/connection.rs` - ensure_masque_tunnel* signature + internal host read, ArcSwap field
- `src/core/connection/h3_runtime.rs` - dispatch signature, drain loop, capsule caller, send_masque_udp_payload, lock-free addr accessors
- `src/implementations/server/live_auth.rs` - TUN sink callback atomic load
- `src/transport/h3/connection.rs` - MASQUE_RECV_HEADROOM const, masque_recv_capacity field, buffer sizing
- `src/transport/h3/connection/masque_and_webtransport.rs` - index-returning try_recv + region accessor
- `src/transport/h3.rs` - pub(crate) re-export of the headroom const
- `src/transport/connection/lifecycle.rs` - test-gated wrapper rebuild
- `src/core/connection/tests.rs`, `src/transport/h3/connection/tests.rs` - call-site + buffer assertion updates

## Verification

- `cargo check --lib` / `--tests` / `--features rust-tests` clean
- `cargo test --lib masque` - 47/47
- `cargo test --lib -- transport::h3::connection::tests` - 93/93
- clippy clean, fmt clean
- Commits: e3666a0 (alloc+copy), 2cece98 (ArcSwap lock removal)
