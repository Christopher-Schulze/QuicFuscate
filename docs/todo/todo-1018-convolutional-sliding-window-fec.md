---
id: TODO-1018
title: Sliding-window (convolutional) FEC coding window - close block-boundary coverage gap
severity: MEDIUM
phase: L
priority: P2
status: DONE (Streaming GF8 scope)
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

## Implementation status (landed)

Implemented for the Streaming GF8 family only (the scope the coverage
gap actually hurts); fountain stays block-mode - it has no boundary
emit tied to `stream_every` and its seed-identity wire format would
need a separate revision.

- **Wire**: `FLAG_SLIDING` (bit 2) added to `KNOWN_FLAGS` - peers
  without the flag strict-reject via `UnsupportedFlags`. `sliding` is
  legal only on non-systematic `StreamingGf8` packets; `validate()`
  rejects every other combination. `WirePacketMeta::sliding_cover_start()`
  computes the earliest covered lane source from anchor/depth/block_k.
- **Encoder** (`codecs.rs`): `Encoder::new_sliding` - window never
  clears, `take_packet` evicts the oldest source once full. Repairs
  right-align the coefficient row (`coeff[k-wlen+j]` pairs `window[j]`,
  position `k-1` = the anchor = newest retained source) and zero the
  unused prefix in the packet itself, so the row is self-describing on
  non-wire paths too.
- **Controller**: streaming mode skips the boundary block-emit and
  `clear_window()`; `window_complete` keeps its bookkeeping meaning.
  `emit_streaming_repair` cycles `stream_idx mod n` so the flat repair
  ordinal stays under the per-lane capacity `validate()` enforces while
  each equation stays unique via its anchor. Transition commit no longer
  waits for an aligned boundary that does not exist in sliding mode.
- **Decoder** (`decoders.rs`, `decoder8.rs`): unified anchor-relative
  mapping `sid = base - (k-1-j)*depth` - the old depth==1 fast path
  underflowed for anchors < k-1 and mapped positions onto phantom sid 0.
  `sliding_anchor_is_valid` judges validity against the lowest *nonzero*
  coefficient instead of the full span, so short early-stream rows are
  admitted. `known_source`/`pending_covers`/`seed_known_source` are
  exposed through DecoderVariant -> LazyDecoder -> InterleavedDecoder.
- **Receiver** (`receiver.rs`): `ReceiveShared` holds a receiver-global
  delivered set with horizon pruning (bounded by `RECEIVE_WINDOW_LIMIT`)
  so a source recovered by a sibling window's equation emits exactly
  once. On a sliding repair the window seeds the pre-window lane sources
  it covers out of retained sibling decoders; a systematic packet
  arriving after a covering repair is propagated into the next retained
  window (`propagate_source_to_next_window`) and seeded decoders drain
  immediately so recoveries are not stranded.
- **Lazy layer** (`lazy.rs`): sliding repairs flush when they straddle
  the coverage frontier (`cover_start <= seen_max < anchor`) - provably
  covering unseen sources at the delivery edge. The old
  missing-tail-count threshold stranded burst tails (each flush
  recovered part of the tail while the threshold stayed). Repairs
  anchored far past the frontier stay in the bounded pending ring so the
  inner equation set cannot grow unbounded. Recovered sources fold into
  seen tracking in `get_result`, so deep bursts admit the next
  straddling repair each round.
- **Sender** (`send.rs`): repairs are tagged `sliding` under
  StreamingGf8 and carry their *anchor's* window (a lane anchor may sit
  one aligned window behind the newest source when lanes lag).

## Verified

- New tests in `receiver.rs` test module: sliding metadata round-trip +
  validation, cross-aligned-window recovery, interleaved cross-window
  lane recovery, trailing-window coverage bound, randomized emit
  schedule burst recovery.
- `test_streaming_tetrys_*` / `rank_progression` regression suite green
  (1768 lib + 104 qf-fec tests).
- clippy `-D warnings`, fmt clean.

## Remaining

- Fountain family still block-mode (separate wire revision needed).
- `fec_decode16_elimination` bench unchanged - GF8 path only; no
  repair-rate regression expected but not benched.
