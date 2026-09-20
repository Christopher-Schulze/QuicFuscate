---
id: TODO-1018
title: Sliding-window (convolutional) FEC coding window - close block-boundary coverage gap
severity: MEDIUM
phase: L
priority: P2
status: OPEN
created: 2026-09-21
depends_on: [TODO-1011]
---

# TODO-1018: Sliding-window FEC - close the block-boundary coverage gap

## Context

Spawned from TODO-1011 item 4 (convolutional/overlapping generations,
rQUIC / RFC 8681 RLC direction). The gap analysis is written there;
summary:

- Today: each coding lane's window grows monotonically to `k`, then
  `clear_window()` hard-resets (`adaptive_controller.rs` ~L282/L504,
  `fountain_codes.rs` ~L302, `interleaved.rs` ~L105). Packets right
  after a reset have zero repair coverage until the next
  `stream_every` tick - a burst landing exactly on a window boundary
  sees unprotected packets.
- Sliding-window design: the coding window advances per packet (FIFO
  evict), so coverage is phase-independent and repair latency is
  bounded by ~1/rate instead of distance-to-block-end (today up to
  `k`/lane packets before a loss is even repairable in block mode).

## Objective

Replace the hard-reset window with a constant-width sliding window so
every emitted repair covers the most recent `w` sources and no source
is ever uncovered.

## Implementation sketch (from the TODO-1011 analysis, verified anchors)

1. **Encoder**: add `evict_prefix(m)` to `FountainEncoder`
   (`fountain_codes.rs`) that drops the oldest `m` sources once the
   window exceeds target `w`. `evict_oldest_symbol` (~L513) already
   implements the per-symbol eviction primitive - the new API applies
   it bounded, keeps `symbols` ordered, and updates the window base
   counter. `adaptive_controller.rs` block path swaps `clear_window()`
   for `evict_prefix(packets_in_window() - w)` after emitting a repair.
2. **Wire identity**: the repair header must carry the window base so
   decoders can bound the equation set - today the identity encodes
   block idx via `REPAIR_LANE_BITS` (`interleaved.rs` ~L13/L97). Sliding
   windows need a base-source field in the coded identity; check
   whether the existing seq space absorbs it or a flag/format rev is
   required (wire-compat decision required: versioned flag vs new
   header layout).
3. **Decoder**: `decoder8`/`decoder16` unknowns are source-id keyed,
   not generation-aligned, so overlapping equations are already
   representable - work is bounding/staleness (drop equations whose
   window no longer intersects live sources) plus gap detection on the
   interleaved side staying correct.
4. **Streaming mode** (`emit_streaming_repair`) already encodes over
   current window contents - it inherits the slide for free once the
   window policy changes.

## Constraints

- Wire format change must be versioned/negotiated like Repair-ACK was
  (flag bit + strict reject), never silently reinterpreted.
- `packets_in_window`/`clear_window` semantics are load-bearing for the
  adaptive controller's k-decision - keep the API honest or migrate
  call sites atomically.
- No repair-rate regression on the `fec_decode16_elimination` bench.

## Acceptance

- A loss burst straddling a former block boundary is repairable (unit
  test: sources spanning the old reset edge recover through one
  sliding-window repair).
- Coverage invariant: at every emit, the coded window covers the last
  `w` sources - pinned by a property-style test over randomized emit
  schedules.
- qf-fec suite + `zero_copy_dgram` build green; no measurable repair
  overhead regression.
