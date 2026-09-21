---
id: TODO-948
title: MASQUE datagram path: reused scratch instead of per-datagram Vec
status: DONE
created: 2026-09-18
---

# TODO-948 - MASQUE datagram path: reused scratch instead of per-datagram Vec

## Status
DONE

## Problem
Two heap allocations + copies per MASQUE datagram on the VPN dataplane:

- `send_masque_datagram` built `Vec::with_capacity(9 + len)` to prepend the
  Flow-ID varint - a fresh allocation for every uplink/downlink packet.
- `try_recv_masque_datagram` returned `(flow_id, payload.to_vec())` - a fresh
  `Vec` for every received MASQUE datagram, although callers only mutate the
  payload in place during dispatch.

## Solution
- `H3Connection::masque_send_scratch: Vec<u8>` - `send_masque_datagram`
  clears and extends the reused buffer (varint + payload). Allocation once;
  the framing copy stays (the DATAGRAM queue needs contiguous bytes).
- `try_recv_masque_datagram(conn, out: &mut Vec<u8>)` - the caller owns the
  payload buffer. The poll loop (`poll_masque_datagrams`) keeps one `payload`
  Vec across the whole drain; capacity is retained, `to_vec` is gone.
  `masque_try_recv_datagram` (test helper) wraps the new signature and keeps
  returning owned `Vec<u8>`.

## Verification
- `cargo check --all-targets` clean locally and on Omega (aarch64/Linux).
- `cargo clippy --lib --all-targets` clean; `cargo fmt` applied.
- Local: 47/47 masque + 115/115 h3 tests. Omega native: 47/47 masque.

## Files
- `src/transport/h3/connection.rs` - `masque_send_scratch` field.
- `src/transport/h3/connection/masque_and_webtransport.rs`
- `src/transport/connection/lifecycle.rs` - test-helper wrapper.
- `src/core/connection/h3_runtime.rs` - drain-loop scratch.
