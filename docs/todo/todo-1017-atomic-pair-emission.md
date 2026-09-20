---
id: TODO-1017
title: Atomic pair emission for bounded bulk reorder swaps
severity: MEDIUM
phase: M
priority: P1
status: OPEN
created: 2026-09-21
depends_on: [TODO-1015, TODO-1016]
---

# TODO-1017: Atomic pair emission for bounded bulk reorder swaps

## Context (measured on Omega, TODO-1016 cycle)

The gather-timer deferral model (TODO-1016) plus bounded adjacent bulk
swap + `was_displaced` guard (TODO-1015) reached 37.4 Mbit/s uplink with
reorder active vs 59.9 Mbit/s with reorder off (uTLS + `JITTER_US=5000`,
60 M offered). Two measured residuals remain:

- **~62% of the reorder-off ceiling.** Every adjacent swap costs one
  emit slot: the displaced head emits one drain tick later instead of
  in the same tick, halving train emission under dense bulk.
- **~1.5% residual QUIC loss.** A displaced head that waits one loop
  slot can still cross QUIC's time-threshold loss detection on fast
  links.

## Objective

Emit both datagrams of a swap atomically (same drain tick, ideally one
write batch) so a permutation never costs an emit slot and a displaced
head never waits.

## Design options (evaluate, then implement the winner)

1. **Pair-emit in the drain path.** When `pick_reorder_emit_index`
   selects a swap, the drain produces *both* packets in one pass:
   swapped order, two sends inside the same drain budget. The
   `was_displaced` flag becomes unnecessary for scheduling (the pair is
   atomic) but stays as the invariant marker.
   - Touchpoints: `pick_reorder_emit_index`
     (`src/core/connection/send.rs` ~L142), `emit_ripe_or_yield`,
     `produce_one_queued` drain budget accounting (~L729),
     `OutgoingFecPacket.was_displaced` (`types.rs`).
   - Effect: swap costs zero extra slots; displaced-head wait vanishes.
2. **GSO segment-level permutation.** Coalesce the pair into one GSO
   super-buffer with segments in permuted order - wire sees reorder,
   the socket sees one sendmsg. Strictly stronger (one syscall per
   pair) but couples the reorder logic to the GSO segmentation path
   (`src/transport/xdp` fastpath / `send_segmented_compat`), which today
   segments contiguous composed datagrams, not queue entries.
   - Decide after option 1 lands whether the remaining syscall overhead
     justifies the coupling.

## Constraints

- Non-bulk traffic keeps strict FIFO (control/ACK ordering is
  QUIC-load-bearing).
- Displacement invariant `<= 1` must survive: an emitted pair must never
  strand a third packet behind both members.
- Drain budget semantics unchanged (batch <= 32, jitter/pacer-free for
  members); a pair counts as its two members against the budget.
- Zero-copy path (`zero_copy_dgram`) must not gain an extra copy for
  the pair emit.

## Acceptance

- Unit tests: pair emits atomically in swapped order; displaced-head
  invariant still holds when the head is part of a pair; non-bulk FIFO
  untouched; budget accounting counts both members.
- Omega uplink (uTLS + `JITTER_US=5000`, 60 M offered): >= 80% of the
  no-stealth baseline (closes TODO-1016's acceptance), residual QUIC
  loss < 0.5%.
- `send_yield_counts` diagnostics keep working; add a pair-emit counter
  if the pick/pair distinction stays observable.
