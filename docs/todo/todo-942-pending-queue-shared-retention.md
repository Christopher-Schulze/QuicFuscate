---
id: TODO-942
title: Pending TUN downlink queue: retain the pooled `TunPacket` block
status: DONE
created: 2026-09-18
---

# TODO-942 - Pending TUN downlink queue: retain the pooled `TunPacket` block

## Status
DONE

## Problem
`PendingTunDownlink.packet` was a `Vec<u8>`. When a server TUN downlink could
not be delivered immediately (transport `DgramQueueFull`, bandwidth
scheduler, shared-capacity deferral), the enqueue path copied the frame out
of the `TunPacket`'s pooled block via `packet.to_vec()` - one heap allocation
+ copy + eventual free per queued frame, per target. Fan-out routes multiply
that by target count.

## Solution
`PendingTunPacket` - a two-variant payload owner in
`live_state/runtime_support.rs`:

- `Owned(Vec<u8>)` - sources that already hold heap bytes (client fan-out,
  tests). No cost change.
- `Shared(SharedFecBuffer, usize)` - the TUN reader's pool block moved behind
  an `Arc`. `clone()` is an Arc bump, so enqueueing the same frame for
  additional DRR targets shares the block; it returns to its memory pool
  when the last queued clone drops.

Supporting pieces:

- `SharedFecBuffer::from_pooled_block` (qf-fec) adopts a `PooledBlock`'s
  checked-out `AlignedBox` + pool handle - the same ownership transfer the
  FEC send path already performs.
- `TunPacket::into_block()` yields the owned `PooledBlock`
  (`TunPacket::for_test` added for the new coverage).
- `process_server_tun_packet` now takes the `TunPacket` **by value**.
  `retain_tun_frame` converts it lazily on the *first* enqueue: frames that
  send directly never pay for retention, and `packet_slice`/`frame` borrows
  keep the read phase and direct-send path allocation-free.
- Byte accounting is unchanged: `PendingTunPacket::len()` feeds every
  existing `entry.packet.len()` callsite; `as_slice()` feeds
  `send_masque_downlink`.
- `enqueue`/`enqueue_pending_tun_downlink` keep `Vec<u8>` params (test-only
  callers) and wrap `Owned` internally; `enqueue_scheduled_tun_downlink` and
  `enqueue_with_accounting` take `PendingTunPacket`.

## Correctness notes
- Queue accounting (`entries`, `bytes`, DRR deficit, per-target cap) is
  driven by `packet.len()` - identical values for both variants.
- A `Shared` block held in the queue stays checked out until dropped -
  bounded by `MAX_PENDING_TUN_DOWNLINKS`/`_BYTES`; the pool allocates cold
  blocks on demand, so no exhaustion deadlock (same reasoning as TODO-940).
- `bandwidth_accounted`, `queued_at` expiry, `requeue_front`, `rebind_target`,
  `discard_target` semantics are untouched.

## Verification
- `cargo check --all-targets` clean locally and on Omega (aarch64/Linux).
- `cargo clippy --lib --all-targets` clean; `cargo fmt` applied.
- New test `pending_tun_downlinks_share_retained_pool_block`: enqueues the
  same frame for two sessions, asserts payload equality, byte accounting
  (2 entries / 8 bytes), and `strong_count == 2` on both popped entries.
- Omega native: 5/5 `pending_tun` tests, 59/59 `tun` tests;
  local: 594/594 server suite, 84/84 qf-fec.

## Files
- `crates/qf-fec/src/codecs.rs`
- `src/interface.rs`
- `src/implementations/server/live_state/runtime_support.rs`
- `src/implementations/server/live_state.rs`
- `src/implementations/server/tun_path.rs`
- `src/implementations/server/tests_inline/network_and_fanout.rs`
