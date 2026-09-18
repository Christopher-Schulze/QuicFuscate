# TODO-946 - `send_with_info`: raw datagrams emit directly from the caller buffer

## Status
DONE

## Problem
`send_with_info` sent **every** wire datagram through the pooled-block ->
`FecPacket` -> `outgoing_fec_packets` queue -> `write_to(buf)` pipeline:

1. `PooledBlock::new(pool)` checkout per generated packet.
2. `conn.send` writes the datagram into the block.
3. `FecPacket::from_pooled_blocks` wraps the block (ownership + `pool()` Arc
   clone for the return path).
4. `push_back` then immediately `front().write_to(buf)` + `pop_front` - one
   copy of the whole datagram out of the block into the caller buffer.
5. Block returns to the pool on drop.

Per emitted raw datagram that is: 1 pool checkout + 1 whole-packet copy +
1 block free + VecDeque push/front/pop - all pure overhead when the packet is
emitted immediately, which is the common case (no stealth deferral, no FEC
burst retention).

## Solution
`send_with_info_raw` handles the `wire_profile.is_none()` branch when the
outgoing queue is empty:

- `conn.send(buf)` writes the wire datagram **straight into the caller's
  buffer** - zero copies, zero pool traffic, zero queue ops.
- `process_outgoing_packet` runs on `buf[..write]` (it only reads the length;
  the payload is never mutated).
- Only when `compute_outbound_stealth_release` actually defers emission does
  the path pay the same cost as before: the bytes are materialized into a
  `PooledBlock`, wrapped in an `FecPacket`, and queued - identical structure
  to the old code, so deferred ordering and `next_packet_release` semantics
  are unchanged.

## Correctness invariants preserved
- **Ordering**: the direct path is gated on
  `outgoing_fec_packets.is_empty()`. When `path_control_pending` skips the
  early queue flush, queued packets may remain - those keep the ordered
  push/pop emission through the pooled path (a direct emit could otherwise
  reorder ahead of retained datagrams).
- **Buffer contract**: `conn.send` caps output at the caller buffer length the
  same way it did at the pool-block length; datagram size is bounded by the
  transport MTU well below both. Callers pass >=64 KiB buffers or flat-staging
  windows; a sub-MTU buffer fails `BufferTooShort` either way.
- **Deferral**: `established && !send_info.path_control` gates jitter +
  release exactly as the pooled path; a deferred packet lands in the same
  queue shape (`wire_meta: None`, `seq = packet_id`).
- **Telemetry**: `observe_wire_send(true, write, write)` matches
  `telemetry_shape()` for `wire_meta: None` (`(true, data_len)`).
- **Pacing**: `record_paced_packet` is called with the emitted wire length.
- `packet_id_counter` increments once per generated packet on both the emit
  and the deferral branch, as before.

## Rejected alternatives
- Predicting "no delay will fire" before `conn.send` (e.g. a
  `shaping_may_delay()` predicate): delay sources (realtime choker, flow
  shaper, escalation flag, transport jitter) can't be exhaustively
  pre-queried cheaply, and a wrong prediction loses a sealed datagram.
- Skipping the `FecPacket` wrap but keeping the queue: saves deque ops only;
  the dominant cost (block -> buf copy) stays.

## Verification
- `cargo check --lib` clean; `cargo clippy --lib` clean; `cargo fmt` applied.
- `cargo test --lib connection`: **326/326** pass locally (covers send,
  stealth deferral, FEC queue ordering, path-control, pacing).

## Files
- `src/core/connection/send.rs`
