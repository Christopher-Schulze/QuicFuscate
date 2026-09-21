---
id: TODO-1011
title: FEC standards alignment - NWCRG RLC window, application-tailored gating, repair feedback
severity: MEDIUM
phase: M
priority: P2
status: DONE
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
   DONE (2026-09-21): implemented end-to-end - see the Repair-ACK section
   below for wire format, consumption semantics, and test coverage.

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

3. Repair-ACK feedback - DONE (2026-09-21): reporting side, wire format,
   and sender-side CC accounting all landed. Details in the Repair-ACK
   section below.

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

IMPLEMENTED (2026-09-20) - items 1 + 5: QUIRL-style unequal protection.

Design decision: class gating happens at *packet granularity* via the
existing framed/unframed wire dichotomy - no wire-format change needed
(the receiver routes unframed packets past the FEC decoder already, the
path-control bypass established that precedent). `DatagramClass` travels
from payload classification to the emit gate:

- `crates/qf-transport-types`: `DatagramClass::{Protected, Bulk}` +
  `SendInfo::bulk_only` (packet's application payload is exclusively bulk
  datagrams - any coalesced control/stream content keeps it framed).
- `src/transport/h3/connection/masque_classify.rs`:
  `classify_tunneled_payload` parses the inner IP packet per datagram.
  TCP segments >128 B payload = Bulk; SYN/FIN/RST and small segments stay
  Protected. UDP payloads >384 B = Bulk; port-53 and small datagrams stay
  Protected. ICMP, IPv4 fragments, IPv6 extension headers, truncated or
  non-IP payloads always stay Protected (classification only ever removes
  redundancy where it is provably redundant).
- `src/transport/connection`: `DatagramSendEntry` carries the class on the
  send queue (both `zero_copy_dgram` variants);
  `dgram_send_parts_classified` feeds it from `send_masque_datagram`;
  `maybe_stage_one_datagram_frame` returns the staged class; the packet
  composer sets `SendInfo::bulk_only`.
- `src/core/connection/send.rs`: `strip_framing_headroom` (formerly
  `bypass_fec_for_path_control`) emits `path_control || bulk_only` packets
  unframed. Bulk packets keep stealth scheduling, normal queue position
  (push_back, not the path-control front jump), and consume no
  `fec_tx_sequence` slot - the systematic wire sequence stays dense, so
  interleaved-decoder gap detection is unaffected.

Why this satisfies QUIRL: QUIC DATAGRAM frames are never retransmitted
(RFC 9221), so "rely on retransmission" means the *inner* protocol - TCP
bulk inside the tunnel retransmits end-to-end; spending outer FEC repair
on it pays for protection the inner stack duplicates. Protected classes
keep full framing + repair. Items 2-4 unchanged: NWCRG rejected-by-design
(stronger HKDF seed already shipped), Repair-ACK landed 2026-09-21
(see section below; its wire format is independent of class gating).

Verified on Omega (2026-09-20, `tun-e2e-netns.sh` + ready-hook): with 3%
netem loss on both underlay veths, a 15 s iperf3 TCP run through the
tunnel produced wire mix framed=9705 / unframed=22589 (~70% of wire
packets carried no FEC framing - the bulk class in action) while ICMP
echo stayed framed and the tunnel passed 5/5 pings both directions with
clean routing/firewall teardown. Unit coverage: `masque_classify` table
tests plus `bulk_class_datagram_marks_packet_bulk_only_for_fec_gating`,
`bulk_class_loses_bulk_only_when_control_coalesces`, and
`bulk_only_strips_framing_headroom_and_disables_fec`; all green under
default and `zero_copy_dgram` builds.

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
scoping, and the wire identity (`REPAIR_LANE_BITS` layout)
simultaneously. Spawned as **TODO-1018**
(docs/todo/todo-1018-convolutional-sliding-window-fec.md).

## Repair-ACK implementation (item 3, DONE 2026-09-21; closes TODO-1006 option (a))

Wire format (`crates/qf-fec/src/wire.rs`): the report reuses the standard
32-byte FEC header with dedicated `FLAG_REPAIR_ACK` (bit 1, registered in
`KNOWN_FLAGS`). Payload = u16 count + up to `MAX_REPAIR_ACK_ENTRIES` (64)
entries of `REPAIR_ACK_ENTRY_LEN` (10 B: u64 global wire id + u16 payload
len) => worst case 674 B, always MTU-bounded. `parse_packet` rejects it
with `WireError::RepairAckFrame` so the decoder can never confuse it with
a coded packet; `is_repair_ack`/`write_repair_ack`/`parse_repair_ack` are
re-exported through `src/fec/wire.rs`.

Receiver side (`crates/qf-fec/src/receiver.rs`): `emit_recovered` enqueues
a `RepairAckEntry { id, payload_len }` into a bounded `pending_recovered`
deque (`RECOVERED_REPORT_CAP` = 1024, oldest dropped on overflow).
`receive_borrowed` tracks `last_rx_epoch`; `has_pending_recovered`,
`drain_recovered`, and `last_rx_epoch` expose the queue.

Sender side: `QuicFuscateConnection::enqueue_repair_ack_report`
(`src/core/connection/send.rs`) drains the queue into one report datagram,
front-queues it as `wire_meta: None` + `is_systematic: false` + non-bulk +
`congestion_controlled: false` (emits raw, consumes no `fec_tx_sequence`
slot, reorder permutation never displaces it, `telemetry_shape` no longer
counts it as source payload). Best-effort like an ACK - a lost report is
covered by the next recovery burst.

Consumption (`src/core/connection.rs`): all three framed receive paths
(`recv_on_path`, `recv_on_path_mut`, `recv_pooled_block_on_path`) check
`is_repair_ack` before the decoder and hand off to `consume_repair_ack`,
which validates the report epoch against the active `fec_tx_profile`
(stale epochs increment `FEC_REPAIR_ACK_STALE` and are dropped) and calls
`Connection::record_fec_wire_loss` per entry. That hook routes through
`recovery.on_loss_packet(0, payload_len, now)` - the PN-less loss path -
so the CC's configured `fec_on_lost` callback increments the adaptive
feedback counters exactly once (no manual counter writes; verified by
test). Wire truth now reaches CC for losses FEC masked.

Telemetry (`crates/qf-telemetry`): `FEC_REPAIR_ACK_ENTRIES_SENT`,
`FEC_REPAIR_ACK_ENTRIES_RECEIVED`, `FEC_REPAIR_ACK_STALE`, exported as
`quicfuscate_fec_repair_ack_entries_{sent,received}_total` and
`quicfuscate_fec_repair_ack_stale_total`.

Tests: wire round-trip/reject cases in `qf-fec::wire`, receiver
pending/drain/epoch tracking in `qf-fec::receiver`, and core round-trip +
stale-epoch drop in `core::connection::tests`
(`repair_ack_round_trip_reports_masked_wire_loss_to_cc`,
`repair_ack_stale_epoch_is_dropped`). 1767 lib tests green, clippy clean,
`zero_copy_dgram` build verified.

## Closure (2026-09-21)

All five findings have a written verdict and a home:

1. QUIRL unequal protection - landed (packet-class Bulk/Protected).
2. NWCRG/TinyMT32 wire seed - rejected-by-design (HKDF + splitmix64).
3. Repair-ACK - landed (closes TODO-1006 option (a)).
4. Convolutional/sliding window - landed as TODO-1018 (Streaming GF8).
5. Unequal protection - same as item 1.

This standing track has no remaining adopt/adapt work.
