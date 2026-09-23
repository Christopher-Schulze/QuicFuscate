---
id: TODO-1015
title: ChameleonFlow-style bounded reorder window for bulk datagrams
severity: MEDIUM
phase: L
priority: P2
status: DONE
created: 2026-09-20
depends_on: [TODO-1011]
---

# TODO-1015: Bounded reorder window on bulk datagrams

## Objective
Full ChameleonFlow (MLCIPR 2025) variant: instead of buying chaff bytes,
redistribute real packets across a small time window to destroy train
structure (burst lengths, direction alternation) that WF classifiers
extract. Reported literature numbers: WF accuracy 96.3% -> 35.8% at 8.7%
bandwidth / 11.2% latency overhead - far cheaper than padding defenses.

Density rule half already landed (padding rate halves under dense
ACK-clocked traffic). This TODO is the reorder-window remainder, scoped
by the design study in
`docs/todo/done/todo-1010-stealth-shaping-research-track.md`.

## Implementation plan

1. Window placement: in the send drain after packet compose
   (`src/transport/connection/send.rs` -> `src/core/connection/send.rs`).
   Packet numbers are allocated at compose time, so reordering composed
   packets is wire-legal (send order need not equal PN order).
2. Eligibility: only `DatagramClass::Bulk` entries (TODO-1011) enter the
   window - their inner protocol (TCP) tolerates reorder/delay. ACK,
   control, handshake, and `Protected` datagrams always bypass.
3. Mechanics: bounded delay queue (W ~ 5-15 ms max hold, k ~ 8 packets
   max depth). Flush triggers: window expiry, depth reached, or any
   bypass-class packet emitting (flush first to keep relative order of
   protected traffic). Emission order within a flush: seed-permuted
   (per-connection seed, NOT deployment seed - see TODO-1014 boundary).
4. Interactions to verify: io_uring multishot drain and the sendmmsg
   batch tail must not just move the burst signature one layer down -
   flush should ride the normal batch emit, not a separate syscall path.
5. Success metric: train-structure entropy gain at <= 2 ms median added
   latency on bulk packets; zero added latency on protected classes;
   bandwidth overhead ~0 (no new bytes).

## Risks
- Holding bulk packets interacts with inner-TCP RTT estimation; cap the
  hold below typical tunnel RTT contribution and never hold retransmits
  (inner TCP already numbers them - reordering adds nothing).
- A fixed window size is itself a signal; W should jitter per flush
  (reuse the per-connection seed).

## Acceptance
- Window only delays Bulk-classified traffic (asserted by unit test
  feeding mixed-class entries).
- Omega e2e: bulk TCP throughput within noise of baseline; protected
  ping RTT unchanged; wire capture shows reordered PN sequences on bulk
  bursts.

## Implementation status (2026-09-20)

PARTIAL - implemented as a shared batch window inside the existing
`outgoing_fec_packets` queue rather than a separate delay queue:

- `OutgoingFecPacket.hold_until` carries the release marker; entries
  with `None` are always ripe, so control/ACK/framed traffic bypasses
  held bulk packets naturally.
- `reorder_hold_for` draws ONE shared window deadline per burst
  (`bulk_window_release`, uniform 0..=3 ms): every bulk packet queued
  inside the open window carries the same `hold_until`, so they ripen
  together and leave in a single permuted batch. Per-packet staggered
  holds were rejected - they serialize emission into one wake per
  packet under the loop-tick-bound drain (see TODO-1016).
- Burst detection is time-based (`REORDER_BURST_WINDOW` = 10 ms via
  `last_bulk_queued`), not queue-based: TUN datagrams arrive one per
  send call, so a queue-depth test alone would never detect a train.
  Train heads after a quiet gap pass unheld.
- The hold engages only when transport stealth timing is active
  (`stealth_timing_enabled && !external_pacing`), so performance mode
  is unaffected.
- `pick_reorder_emit_index` drains: first ripe entry wins (strict FIFO
  for non-bulk), a >=2 ripe bulk run is emitted permuted - composed
  packet numbers no longer mirror wire order inside a train.
- Drain-starvation fix: `emit_ripe_or_yield` emits an already-ripe
  queued packet when a new datagram gets deferred, instead of yielding
  empty - deferred bulk cannot starve the drain to one packet/tick.
- `next_packet_release` merge (min of pending deadlines) instead of
  overwrite; stealth-released packets carry `hold_until = release_at`
  so the reorder-aware drain respects stealth deferral.
- `earliest_reorder_hold` merges into `next_send_deadline`.

Tests (all in `src/core/connection/tests.rs`):
`reorder_window_permutates_ripe_bulk_run`, `reorder_window_non_bulk_
bypasses_held_bulk`, `reorder_window_yields_until_earliest_hold`,
`reorder_hold_skips_lone_bulk_and_disabled_stealth`,
`reorder_window_time_window_marks_burst_trains` (train head unheld,
follower inside 10ms window held, new head after quiet gap unheld).
Verified under default and `zero_copy_dgram` feature sets.

## Omega e2e findings (2026-09-20)

- Mechanism confirmed live: uTLS + `QUICFUSCATE_STEALTH_JITTER_US=1`
  produced 4676 window draws / ~4700 wire packets during iperf uplink.
- Wire-level reordering itself cannot be proven by tcpdump (packet
  numbers are encrypted); permutation correctness is unit-tested.
- Throughput parity could NOT be shown: the standalone client's
  deferral drain serializes ALL per-packet deferrals (stealth jitter
  AND bulk holds alike) to ~1 packet per loop tick
  (`CLIENT_HOUSEKEEPING_ACTIVE` 5 ms floor; ~2.4 ms observed with a
  1 ms floor patch). uTLS + jitter=1us collapsed to 1.88 Mbit/s vs
  74.3 Mbit/s baseline - the same collapse occurs with jitter alone,
  so it is a pre-existing drain limit, tracked as TODO-1016.
- Consequence: windowed reorder works mechanically, but its wire-level
  benefit on the standalone TUN path is bounded by the drain tick
  (~1 packet per window under sustained load). The io_driver runtime
  (deadline-driven, 1ms-capable) is the right carrier for the full
  effect; revisit wire evidence after TODO-1016.

OPEN: atomic pair emission to lift reorder throughput toward the
reorder-off ceiling - tracked with full plan + acceptance as
**TODO-1017** (docs/todo/done/todo-1017-atomic-pair-emission.md).

## Architecture update (2026-09-20, TODO-1016 cycle)

The design moved from per-packet holds to gather timers: produced-and-
held packets inflate QUIC's in-flight clock into spurious PTO loss.
`reorder_window_tick` now arms `bulk_window_release`; the opener emits
as train head, production stalls while the window is open, and the edge
arms the budgeted drain that emits permuted.

Permutation itself was isolated as the last loss source: unbounded
picks displace datagrams >=3 positions and trip QUIC's packet-threshold
loss detection (measured ~24% QUIC loss, 12.8 Mbit/s). The pick is now
bounded: only the adjacent bulk pair swaps (50% coin) and the displaced
head is marked `was_displaced` so it emits unconditionally next -
displacement <= 1, QUIC-safe at 1.5% loss / 37.4 Mbit/s. Tests updated
to the timer semantics plus `reorder_displaced_head_emits_next_
unconditionally`.

## State reconciliation (2026-09-21)

The "remaining lift" chain closed: atomic pair emission landed in
TODO-1017 (done), the scheduler defect behind the ~38% kernel-TUN
loss was root-caused to the backpressured park path and fixed in
TODO-1021 (done, `qtun0 TX dropped`=0 at 60 M and 140 M offered).
TODO-1022 Option A landed: framed systematic sources now tick the
gather window on the wire-FEC path; repairs are forced non-bulk and
pre-paired so they never arm or swap. Unit test
`reorder_window_tick_arms_under_committed_wire_fec` is green. The
>=80%-of-baseline Omega revalidation failed on 2026-09-21 after
the `--no-utls` knob fix actually armed the window: UDP 60 M
reorder-off recv 59.982 Mbit/s / 0% loss vs reorder-on
(`JITTER_US=5000`) recv 30.602 Mbit/s / 43.94% loss
(`tun_drops=36381`, `qtun0 TX dropped=0`, `yield_window=9440`,
`drain_entries=1422`). Kernel drops stay gone; the remaining
cut is userspace `tun_drops` under the gather-window cadence.
Window arming itself is proven (also under committed FEC,
TODO-1022).

## Pressure-aware arming (2026-09-21)

Root cause of the 51% cut: after a 32-packet drain the next produce
re-armed a 5 ms stealth window while `dgram_send_queue` still held
the leftover train. Each stall parked more TUN frames into the
userspace backlog until `tun_drops` matched iperf loss.

Landed in `src/core/connection/send.rs`:

- Skip a fresh reorder/stealth window while
  `dgram_send_queue_len() >= WINDOW_PRESSURE_DEPTH` (16) or the
  shared quiet phase is open.
- Stealth window edges now call `open_quiet_phase` (same 0-20 ms
  draw as reorder) so JITTER_US=5000 cannot punch through the FIFO
  gap.
- `DRAIN_BUDGET_MAX` 32 -> 128; `refresh_drain_budget` refills from
  the remaining transport queue when pressure remains.
- `maybe_abort_window_under_pressure` consumes an open window at
  256 queued datagrams and arms the drain.

Tests: `deferral_window_skips_arm_under_dgram_pressure`,
`stealth_window_edge_opens_shared_quiet_phase`,
`drain_budget_refills_under_dgram_pressure`,
`open_window_aborts_when_dgram_queue_hits_abort_depth`.

Omega 80% revalidation (2026-09-21, `udp60-off-1015` / `udp60-on-1015`):

| variant | recv Mbit/s | iperf loss | qtun0 TX dropped |
|---|---|---|---|
| `JITTER_US=0` | 59.999 | 0 / 82660 | 0 |
| `JITTER_US=5000` | 59.986 | 1 / 82644 (0.001%) | 0 |

99.98% of baseline. Window arming proven live via `reorder_window: bulk window +Nus` on the on-run. Gate closed.
