---
id: TODO-1016
title: Deferral drain serializes emission under per-packet stealth deferral
severity: HIGH
phase: L
priority: P1
status: OPEN
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
The same collapse occurs without any reorder hold (jitter alone), so this is
a pre-existing drain limitation, not a TODO-1015 regression.

## Measured evidence (Omega, 2026-09-20, iperf3 12s uplink through TUN)
- baseline `--no-utls`, no stealth timing: 74.3 Mbit/s, p50 wire IAT 236 us
- uTLS + `JITTER_US=0`: 55.7 Mbit/s (uTLS padding overhead, no deferral)
- uTLS + `JITTER_US=1`: 1.88 Mbit/s, p50 IAT 6.3 ms, ~187 pkt/s
- uTLS + `JITTER_US=5000`: 1.72 Mbit/s (identical collapse)
- uTLS + `JITTER_US=1` + housekeeping floor patched 5ms -> 1ms (Omega-only):
  4.08 Mbit/s, p50 IAT 2.36 ms - floor is a contributor, not the only limit

## Root cause analysis
1. `conn.send()` produces at most one datagram per call; a deferred packet
   returns `Ok(0)` which breaks the caller's flush loop early.
2. `client_housekeeping_delay` floors every active-tick wait at
   `CLIENT_HOUSEKEEPING_ACTIVE = 5ms`
   (`src/main/runtime.rs`), so any armed send deadline wakes no sooner than
   ~5ms regardless of how close the deadline is.
3. Per-packet deadlines ripen staggered: each wake frees only the packets
   whose deadline already passed, so emission rate converges to one packet
   per loop tick.
4. The standalone `quicfuscate client --tun` path uses this housekeeping
   loop. The `io_driver` path already merges `next_send_deadline` into its
   TUN-read wait with 1ms capability and is the better long-term owner.

## Done so far
- `emit_ripe_or_yield` in `core/connection/send.rs`: a newly deferred
  datagram now emits an already-ripe queued packet instead of yielding
  empty (keeps the drain alive at flush rate).
- Stealth-released packets carry `hold_until = release_at` so the
  reorder-aware drain cannot emit them early.
- `next_packet_release` merge (min of pending deadlines) instead of
  overwrite - a hold-only packet no longer erases an earlier wake.
- `client_housekeeping_delay` honors an armed send deadline in both the
  active and idle branch: wake at the deadline with a 1 ms CPU guard
  (`CLIENT_HOUSEKEEPING_DEADLINE_FLOOR`) instead of the flat 5 ms floor.
  Omega re-measurement (uTLS + `JITTER_US=1`, iperf uplink):
  1.88 -> 3.98 Mbit/s (2.1x), ~460 pkt/s.

## Remaining work
- The residual ~2.4 ms wake tick bounds the drain to ~1 packet per wake
  (~420-460 pkt/s): `conn.send()` returns one datagram per call and a
  deferred packet ends the flush early whenever nothing is ripe yet.
  Options: drain-loop the queued deferral batch inside one send call,
  or batch the materialize step so one wake converts >1 queued datagram.
- An 8 ms shared window did NOT help (2.07 Mbit/s): bulk arrival rate
  under the tick-bound drain is too thin to fill windows - the limit is
  the drain, not the window size. Kept 3 ms window (acceptance <=2 ms).
- Decide whether the standalone TUN path should migrate to the io_driver
  runtime instead of growing its own scheduler.
- Acceptance: uTLS + `JITTER_US=5000` uplink >= 80% of the no-stealth
  baseline on Omega, ping RTT overhead bounded and documented.
