---
id: TODO-1017
title: Atomic pair emission for bounded bulk reorder swaps
severity: MEDIUM
phase: M
priority: P1
status: PARTIAL
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

## Implementation (landed)

**Option chosen: swap-on-join** - stronger than the planned drain-path
pair-emit. `pair_swap_on_join` (`src/core/connection/send.rs`) runs when
a bulk datagram is pushed into `outgoing_fec_packets`: with a fair coin
it swaps the new tail with the bulk entry directly ahead, then marks
both `paired`. Because the queue order itself carries the permutation,
emission is plain FIFO (`next_emit_index` -> front) and a swapped pair
always travels inside one sendmmsg/GSO flush batch - atomically, with
zero emit-slot cost and no displaced-head wait. The `paired` flag
replaces `was_displaced`: both members are marked at swap time, so no
member can swap again and every displacement stays <= 1 (below QUIC's
packet-threshold k = 3). Non-bulk/control entries are never swappable,
so control FIFO is preserved even mid-queue.

**Quiet phase added** (same TODO, second commit half): the window edge
now draws `reorder_quiet_until = now + uniform(0..REORDER_QUIET_MAX_US)`
(20 ms ceiling, ~10 ms mean) and `reorder_window_tick` refuses to arm a
new gather window while it lasts. Rationale: ChameleonFlow reorders
*occasional* trains inside an otherwise FIFO stream - previously every
sustained train could re-arm a window one tick after the drain. Duty
cycle is now bounded to ~13%.

## Measurements (Omega, uTLS + `JITTER_US=5000`, 60 M offered)

| variant                              | Mbit/s | iperf loss | QUIC loss |
|--------------------------------------|--------|------------|-----------|
| reorder off (control)                | 59.9   | 0%         | 0%        |
| pick-time swap + was_displaced guard | 37.4   | 36%        | 1.50%     |
| swap-on-join (atomic pair)           | 35.9   | 38%        | 1.47%     |
| + quiet phase                        | 35.8   | 39%        | 1.52%     |
| + quiet phase, offered 30 M          | 30.0   | 0%         | -         |

**The atomicity hypothesis is falsified for throughput**: the emit-slot
cost was not the limiter. Counter forensics from the quiet-phase run:

- `qtun0 TX dropped = 21421` vs iperf `21393/55057 lost` - the loss is
  ~100% **kernel TUN-queue drops**: the fd reader stops consuming the
  moment `dgram_send_queue` backpressure parks a frame
  (`tun_backpressure_frame`), and the kernel ring overflows.
- `send_polls = 918k` vs `send_datagrams = 33.7k`: ~96% of `conn.send`
  calls produce nothing (`yield_window` ~392k, `yield_done` ~492k).
  On the contended single-core VM the yield spin plus ingest/emission
  contention caps the sustained chain rate at ~3.4-3.7k pkt/s
  (~35-39 Mbit/s); offered 5.5k/s overflows the 1024-entry dgram queue,
  backpressure parks the TUN read, kernel drops follow.
- `UDPRATE=30M` control: 27576/27576 delivered, 0% loss, zero qtun0
  drops - the chain is clean below its rate ceiling.
- `cwnd` pinned at ~14720 (initial window); `drain_entries` ~1044 (~80
  drains/s), `drain_emits` ~6022 - drains emit ~6 datagrams each, so
  the windows were never the dominant emitter.

## Root cause (revised)

The reorder feature is not throughput-limited by swap mechanics or
window frequency. It is limited by the **client runtime's poll-spin
scheduling under emission gaps** on CPU-starved hardware: every window
stall turns into busy `conn.send` polls while the TUN arm competes for
the same loop, and once the queue saturates the backpressure path parks
fd reads long enough for the kernel to drop at line rate. This is a
runtime-scheduling problem, not a reorder-algorithm problem.

## Acceptance status

- [x] Unit tests: `reorder_paired_member_never_swaps_twice`,
  `reorder_quiet_phase_blocks_immediate_rearming` (53/53
  core-connection green).
- [ ] Omega uplink >= 80% of baseline: **not met** (35.8/59.9 = 60%).
- [ ] Residual QUIC loss < 0.5%: **not met** (1.5%, dominated by burst
  server-delay > PTO, not by displacement).

## Follow-up (the real levers, in order)

1. **TODO-1020 study gains weight**: the io_driver runtime's
   deadline-driven loop + fd-based ingest may not share this
   spin/backpressure profile. The migration verdict must now also
   compare the TUN-ingest backpressure path
   (`drain_client_tun_uplink_fd` vs `enqueue_tun_datagram`).
2. **Standalone-runtime scheduling fix** (new task candidate): during an
   open deferral window the produce path should yield a real `Done`
   (or the runtime should skip re-polling until `next_send_deadline`)
   instead of burning `conn.send` polls; and the tun-notify self-loop
   must not pump the dgram queue past its cap while emission is
   stalled - the fd's kernel queue is the intended overflow buffer.
3. **GSO segment-level permutation** stays the optional stronger form
   of pair emission (one sendmsg per pair); only worth it after the
   runtime bottleneck is gone.

## Constraints (kept)

- Non-bulk traffic keeps strict FIFO (control/ACK ordering is
  QUIC-load-bearing).
- Displacement invariant `<= 1` must survive: an emitted pair must never
  strand a third packet behind both members.
- Drain budget semantics unchanged (batch <= 32, jitter/pacer-free for
  members); a pair counts as its two members against the budget.
- Zero-copy path (`zero_copy_dgram`) must not gain an extra copy for
  the pair emit.

## State reconciliation (2026-09-21)

All three follow-up levers resolved: (1) TODO-1020 verdict STAY -
io_driver would not change the measured profile; (2) the standalone
scheduling fix landed as TODO-1021 (drain-into-bounded-backlog under
backpressure; Omega: `qtun0 TX dropped`=0 at both 60 M and 140 M
offered, `send_polls`/`send_datagrams` 27x -> 1.7x); (3) GSO segment-
level permutation remains optional/unscheduled. Residual: reorder
windows cannot arm under committed wire FEC (TODO-1022), which blocks
the reorder-active revalidation - mechanism here is done and tested.
