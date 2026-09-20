---
id: TODO-1016
title: Deferral drain serializes emission under per-packet stealth deferral
severity: HIGH
phase: L
priority: P1
status: PARTIAL
created: 2026-09-20
depends_on: []
blocks: [TODO-1015]
---

# TODO-1016: Deferral drain serializes emission under per-packet stealth deferral

## Objective
Under `stealth_timing` every congestion-controlled packet pays a per-packet
deferral (transport jitter and/or stealth release). The drain then emits at
most one packet per client event-loop tick, collapsing the standalone TUN
datapath to ~200-420 pkt/s (~1.8-4 Mbit/s) instead of baseline ~74 Mbit/s.
Reproduce on Omega: `QUICFUSCATE_STEALTH_JITTER_US=1` + uTLS + iperf uplink.

## Measured evidence (Omega, 2026-09-20, iperf3 10-12s uplink through TUN)
- baseline `--no-utls`, no stealth timing: 74.3 Mbit/s, p50 wire IAT 236 us
- uTLS + `JITTER_US=0`: 55.7-76.5 Mbit/s (uTLS padding, no deferral)
- uTLS + `JITTER_US=1`, original code: 1.88 Mbit/s, ~187 pkt/s
- housekeeping floor 5ms -> deadline-aware (2.1x): 3.98 Mbit/s
- shared windows + batch materialization (16/call): 16.0 Mbit/s
- produce-while-held + DEFER_QUEUE_CAP: 16.7 Mbit/s but 1455 TCP retransmits
- UDP 60M offered, produced-held packets: 13.7 Mbit/s / 75% loss
  (held packets count in-flight from `conn.send` -> PTO-spurious loss)
- UDP 60M, drain inversion (no in-window production): 5.8 Mbit/s / 0% loss
  (honest in-flight but wake-bound: sub-us windows yield O(1) packets/cycle)
- UDP 60M, window timers + unbounded reorder permutation: 12.8 Mbit/s /
  77% loss / ~24% QUIC loss - permutation displaced datagrams >=3
  positions -> packet-threshold loss detection -> cwnd churn
- UDP 60M, window timers + naive adjacent swap: 37.8 Mbit/s / 4.2% QUIC
  loss - displaced head could slip behind freshly produced datagrams
- UDP 60M, window timers + `was_displaced` guard (final): **37.4 Mbit/s /
  1.5% QUIC loss** - reorder stays active and QUIC-safe
- UDP 60M, reorder pick disabled entirely (isolation): 59.9 Mbit/s / 0%
- veth link counters: TX==RX, 0 drops; kernel UDP error counters all zero;
  GSO super-packets (~33 segments) make pcap counts unreliable
- wire-order permutation is the *only* measured loss source; every other
  pipeline stage was verified drop-free on this path

## Root cause chain (fully diagnosed)
1. `conn.send()` produces at most one datagram per call; a deferred packet
   returned `Ok(0)` and broke the caller's flush loop early.
2. `client_housekeeping_delay` floored every wait at 5 ms regardless of
   armed deadlines (fixed: deadline-aware wake, 1 ms CPU floor).
3. Per-packet hold deadlines ripened staggered -> one packet per wake.
4. Produced-and-held packets occupy QUIC's in-flight window from
   `conn.send()` time: holds past ~PTO read as spurious loss (~38%
   measured), collapsing cwnd and the delivery-rate pacer.
5. The unbounded ChameleonFlow permutation itself trips QUIC's
   packet-threshold loss detection (k=3) - reordering the carrier's own
   packet stream is loss-visible, unlike tunnel-level reorder.

## Implemented (current state)
- **Gather-timer windows replace packet holds.** `reorder_window_tick`
  and `stealth_window_tick` arm `bulk_window_release` /
  `stealth_window_release` instead of marking packets held. The opener
  rides out unheld as the train head; `deferral_window_open` stalls
  production so the transport's own datagram queue gathers the backlog
  as honest backpressure (no in-flight inflation, zero PTO loss from
  deferral itself).
- **Budgeted drain phase.** The first produce past a window edge consumes
  it and arms `burst_draining` + `drain_budget` (capped at 32, from
  backlog). Drain members skip their jitter draw and the delivery-rate
  pacer (a paced batch would sit past PTO); the budget bounds each train
  and hands cadence back to the window cycle.
- **`Done` disambiguation.** `conn.send` returning `Done` only ends the
  drain when `dgram_send_queue_len()==0` AND the outgoing queue is empty -
  congestion-blocked `Done` with backlog keeps the drain armed.
- **Bounded reorder (ChameleonFlow-safe).** `pick_reorder_emit_index`
  only ever swaps the adjacent bulk pair (50% coin) and marks the
  displaced head `was_displaced`; a displaced head emits unconditionally
  next, so wire-order displacement is exactly one position - below the
  packet-loss threshold while still breaking FIFO order on the wire.
  Non-bulk traffic keeps strict FIFO.
- **Deadline merge.** `next_outbound_release_deadline` merges pacer +
  both window edges; `next_send_deadline` surfaces them to the runtime so
  the loop wakes at the edge, not at a fixed tick.
- **`next_packet_release` / `hold_until` machinery removed** - superseded
  by the gather-timer model.
- Diagnostics: `send_yield_counts` [window, pacer, held, done,
  drain_emits, drain_entries] surface per-cause yield reasons in the
  client stats line.
- Tests (52 core-connection tests green): window ticks arm timers not
  holds, edge consumes+drains, displaced-head invariant, deadline merge,
  empty-backlog drain end.

## Remaining work (moved to follow-up TODOs, 2026-09-21)
- Residual ~37.4/59.9 Mbit/s gap vs reorder-off + residual ~1.5% QUIC
  loss: each swapped head pays one emit slot and displaced heads
  waiting one loop slot can cross time-threshold on fast links.
  Improvement path and acceptance moved to **TODO-1017** (atomic pair
  emission / GSO segment-level permutation).
- Standalone TUN -> io_driver migration decision moved to **TODO-1020**
  (study-scoped, written verdict is the deliverable).
- Acceptance carried to TODO-1017: uTLS + `JITTER_US=5000` uplink >=
  80% of the no-stealth baseline on Omega (currently ~62%), ping RTT
  overhead bounded and documented.

## State reconciliation (2026-09-21)

Both follow-ups closed: TODO-1017 (atomic pair emission, swap-on-join)
and TODO-1020 (io_driver verdict: STAY) are done, and the scheduling
defect they surfaced - the backpressured park path spinning the select
loop - is fixed in TODO-1021 (done, Omega-verified). The 80%-of-
baseline acceptance remains formally open: reorder windows currently
cannot arm under a committed wire-FEC profile (TODO-1022), so the
reorder-active revalidation could not run yet. This file's scheduler
redesign itself is landed and verified.
