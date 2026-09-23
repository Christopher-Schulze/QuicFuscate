---
id: TODO-994
title: TODO-994 — GSO EMSGSIZE marks the peer path permanently
status: DONE
created: 2026-09-19
---

# TODO-994 — GSO EMSGSIZE marks the peer path permanently

## Context

Server-side UDP_GSO emission (`live_auth.rs`, `tun_path.rs`) probed GSO runs
with no memory across flushes: `gso_ok` reset on every call, and the TUN
fanout never remembered a failure at all. On a route whose payload ceiling
is below the probed/fallback segment cap (e.g. an IPv6 path with MTU 1280
against the 1472 unconnected-socket fallback), every flush paid one doomed
`sendmsg` + EMSGSIZE + per-packet fallback for the connection's whole life.

## Implementation

- `src/core/connection.rs`: new `#[cfg(target_os = "linux")] pub(crate)
  udp_gso_path_blocked: bool` on `QuicFuscateConnection` — path MTU is a
  route property, so the block is connection-lifetime, matching the
  per-peer scope of `live_state.clients`.
- `live_auth.rs` (per-connection emit): GSO run planning is skipped once
  `conn.udp_gso_path_blocked`; an `EMSGSIZE` (`raw_os_error`) from
  `send_udp_segment` sets it. Transient errors (ENOBUFS/EAGAIN) do not
  block.
- `tun_path.rs` (TUN fanout): run planning is skipped for staged spans whose
  target's connection is blocked; EMSGSIZE marks
  `clients.get_mut(&target).udp_gso_path_blocked`. Failed runs still fall
  through to the sequential per-packet tail, so nothing is dropped.

## Verification

- `cargo check --lib --bin quicfuscate` (macOS, field cfg'd out): clean.
- `cargo check --release --bin quicfuscate` on Omega (Linux, live path):
  clean.
- Existing `plan_gso_run` tests unchanged (gate lives in callers, not the
  planner). Behavioral exercise needs a real sub-1500-MTU route; the flag
  logic is a straight gate/set on `raw_os_error() == Some(EMSGSIZE)`.

## Notes

- Client-side TX (connected socket) already probes the real route MTU via
  `IP_MTU`/`IPV6_MTU` (TODO-988 gate), so the block can only trigger on the
  server's unconnected socket where route lookup is unavailable.
