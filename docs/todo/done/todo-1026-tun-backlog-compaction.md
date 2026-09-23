---
id: TODO-1026
title: TUN uplink backlog retains sent slots until fully drained (Vec + cursor)
severity: LOW
phase: L
priority: P3
status: DONE
created: 2026-09-21
depends_on: [TODO-1021]
---

# TODO-1026: Compact or ring-buffer the client TUN backpressure backlog

## Context

The standalone client parks unsent uplink frames in
`tun_backpressure_frame` as `(Vec<TunPacket>, cursor)`. Sends consume
from `cursor`; new arrivals append at the end. Sent slots
(`vec[0..cursor]`) are only released when the backlog is fully drained
and the whole `Vec` is replaced/dropped.

Memory stays bounded (cap = `TUN_PACKET_QUEUE_CAPACITY` *unsent*
frames, counted from `len - cursor`), so this is not a leak. But under
sustained backpressure the `Vec` keeps both dead sent slots and live
ones, growing capacity to `cursor + cap`, and each `TunPacket` holds a
pooled block that is only returned at send-or-drop - the dead slots
have already returned theirs, so the overhead is just `Vec` capacity
plus cursor bookkeeping. Still: a steady-state drip (backpressure that
never quite empties) retains dead prefix slots indefinitely and makes
the "unsent" arithmetic carry the cursor everywhere.

## Objective

Cheap fix, in order of preference:

1. **Periodic compaction**: when `cursor` exceeds a threshold (e.g.
   512 or half the vec), `drain(..cursor)` once - O(cursor) copy but
   rare and bounded.
2. **`VecDeque` + `pop_front`**: natural fit, no cursor; loses
   contiguous-slice access (irrelevant - frames are consumed
   individually).
3. Keep as-is with a documented justification if measurement shows
   full-drain happens often enough in practice (the 140 M saturation
   run drained to `dgram_queue=0` every cycle, suggesting the backlog
   empties regularly and dead slots never accumulate long).

Measure first: instrument or reason about how often the backlog fully
drains under realistic backpressure; pick (3) if drains are frequent,
(1) if not.

## Acceptance

- Dead sent slots cannot outlive a bounded window under drip-feed
  backpressure, OR the current behavior is measured and documented as
  sufficient.
- FIFO order and the `TUN_PACKET_QUEUE_CAPACITY` unsent bound are
  unchanged; `tun_drops` accounting identical.

## Implementation (2026-09-21)

Option 1. `compact_tun_backlog` in `src/main/runtime.rs` drains the
sent prefix when `cursor >= 64` (and clears the backlog when the
cursor consumes the vec). Both `drain_client_tun_uplink` and
`drain_client_tun_uplink_fd` compact after a parked remainder
survives a send pass. Unsent admission still uses `len - cursor`
against `TUN_PACKET_QUEUE_CAPACITY`.

Tests (`cargo test --bin quicfuscate compact_tun_backlog`): small
cursor stays put, threshold drain keeps the live tail, exhausted
cursor drops the backlog.
