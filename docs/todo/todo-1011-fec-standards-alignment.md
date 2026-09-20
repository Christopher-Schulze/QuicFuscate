---
id: TODO-1011
title: FEC standards alignment - NWCRG RLC window, application-tailored gating, repair feedback
severity: MEDIUM
phase: M
priority: P2
status: OPEN
created: 2026-09-19
depends_on: []
---

# TODO-1011: FEC maximal-effectiveness alignment

## Objective
Standing FEC task: align qf-fec with what the 2024-2026 literature +
IETF/IRTF direction shows as effective, and squeeze remaining overhead.

## Findings to evaluate

1. **Application-tailored activation (QUIRL, TNET 2024)** - first QUIC-FEC
   work with real-network wins: FEC only for latency-sensitive data,
   retransmission otherwise; tail latency improved without hurting
   loss-free paths. Our Kalman-adaptive controller already scales
   redundancy by observed loss; check whether per-stream/per-priority
   gating (protect latency-critical streams only, bulk flows rely on
   retransmission) buys more efficiency than global adaptation.

2. **Sliding-window RLC standardization (draft-roca-nwcrg-rlc-fec-scheme-
   for-quic, Coding4QUIC framework)** - TinyMT32-seeded coefficients,
   sliding encoding window, negotiated via transport parameters. Our RLNC
   already does windowed coding; aligning coefficient generation/wire
   metadata with the draft would future-proof interop and let us reuse
   their analysis. Worth a diff-review of our `fountain_codes`/`variants`
   coefficient PRNG vs TinyMT32 design rationale.

3. **Repair-ACK feedback (draft-zheng-quic-fec-extension)** - receiver
   tells sender which sources FEC recovered; sender suppresses redundant
   retransmission and can count the loss for CC (pairs with TODO-1006).
   Check whether our wire receiver can report recovered source IDs back
   cheaply (small side-channel or folded into ACK-adjacent metadata).

4. **Convolutional/overlapping generations (rQUIC)** - overlap coding
   windows so repair capacity spreads uniformly instead of block-aligned;
   rQUIC reports latency gains vs block codes under burst loss. Our
   interleaved/streaming-burst variants may already approximate this -
   document the gap analysis rather than assume.

5. **Unequal protection** - draft-zheng recommends selecting which data
   gets FEC (not equal protection of everything). Our policy layer has
   per-epoch profiles; confirm latency-sensitive classes (control, early
   handshake completion, TUN-encapsulated DNS/ICMP) get protection while
   bulk doesn't.

## Implementation plan (per item, with code anchors)

1. QUIRL-style gating - `crates/qf-fec/src/policy.rs`, `src/fec/`:
   check whether the policy layer can express per-traffic-class protection
   (control/TUN-encapsulated DNS+ICMP/early data = protected; bulk =
   retransmission). The Kalman controller adapts redundancy globally; the
   gap is *selective* protection, not adaptive strength. Deliverable:
   per-class protection map in the policy + controller hook.

2. NWCRG RLC diff-review - `crates/qf-fec/src/seed.rs`,
   `fountain_codes.rs`: compare our coefficient-PRNG/window metadata vs
   draft-roca's TinyMT32 + sliding-window design. Deliverable: written
   divergence rationale (or alignment patch if their design is strictly
   better).

3. Repair-ACK feedback - `crates/qf-fec/src/receiver.rs` already knows
   recovered `global_id`s (`emit_recovered`). Add a `recovered_ids()`
   report consumable by the connection layer; sender-side consumption is
   shared with TODO-1006 option (a). Deliverable: the reporting side +
   wire-format proposal; sender accounting lands with 1006.

4. Convolutional gap analysis - `crates/qf-fec/src/interleaved.rs`,
   `variants.rs`: document where our interleaved/streaming-burst overlaps
   with rQUIC's overlapping-generation coding and where it differs
   (block-boundary repair gaps). Deliverable: gap note; new code only if
   the gap is real.

5. Unequal protection - `crates/qf-fec/src/policy.rs`,
   `src/fec/internal.rs`: confirm which classes currently get FEC; the
   draft-zheng guidance is *selective* protection, so this pairs with
   item 1's per-class map.

## Acceptance
- Written adopt/adapt/reject per item with code references.
- Any adopted mechanism becomes its own implementation TODO.
- Regression: `fec_decode16_elimination` bench and qf-fec suite stay green.

## Implementation status (2026-09)

REJECTED-BY-DESIGN - NWCRG/TinyMT32 wire seed: QuicFuscate already does the
stronger variant. `seed.rs::derive_fountain_seed` derives the fountain PRNG
seed via HKDF from the QUIC 1-RTT secret (nothing on the wire, both
endpoints regenerate identical symbol sets), and `fountain_codes.rs`
expands it with splitmix64 - strictly better than the draft's TinyMT32
seeded-coefficient transport, which exists to put a seed on the wire. No
interop pressure exists (custom data plane), so there is nothing to align
*to*; the note stays for auditability.

OPEN: QUIRL per-class gating needs a traffic-class concept the FEC path
does not have yet (`manager.rs`/`policy.rs` treat traffic globally); the
Repair-ACK wire-format question (coupled to TODO-1006) remains.

ANALYZED (2026-09) - convolutional/overlapping-window gap vs `interleaved.rs`:

Current design: `InterleavedEncoder` splits sources round-robin across
`depth` lanes (<=8), each lane an `EncoderVariant` with block-aligned
windows. The block path (`adaptive_controller.rs` ~L256) emits repairs when
`packets_in_window() >= k`, then `clear_window()` hard-resets the lane. The
Streaming mode already encodes on the fly: `emit_streaming_repair` calls
`generate_repair_packet` every `stream_every` packets over the *current*
window contents (`FountainEncoder::generate_symbol_into` mixes whatever
`symbols` holds), so repairs are not block-locked.

Real gap vs convolutional/sliding-window (RFC 8681 RLC, rQUIC):
- Ours: the window grows monotonically to k, then a hard reset. A repair
  emitted early covers few sources (efficient), late repairs cover up to k.
  The reset edge creates a coverage gap: packets right after `clear_window`
  have zero repair coverage until the next `stream_every` tick - a burst
  landing exactly on a window boundary sees unprotected packets.
- Sliding-window: the coding window advances per packet (FIFO evict), so
  coverage is phase-independent and repair-latency is bounded by ~1/rate,
  not by distance-to-block-end (ours: up to k/d lane packets = k wire
  packets before a loss is even repairable in block mode).

Design option if adopted: replace `clear_window` at k with
`evict_prefix(m)` on the fountain encoder (drop the oldest m sources once
the window exceeds target w), keeping a constant-width sliding window.
Decoder side already tracks per-source ids (`decoder8/16` unknowns are
source-id keyed, not generation aligned), so overlapping equations are
representable; the wire format needs the window base carried in the repair
header so decoders can bound the equation set. Sized as a separate
implementation TODO - it touches encoder windowing, decoder equation
scoping, and the wire identity (`REPAIR_LANE_BITS` layout) simultaneously.
