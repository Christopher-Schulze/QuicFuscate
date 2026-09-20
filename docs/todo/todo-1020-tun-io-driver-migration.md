---
id: TODO-1020
title: Decide whether the standalone TUN client migrates to the io_driver runtime
severity: LOW
phase: L
priority: P3
status: OPEN
created: 2026-09-21
depends_on: [TODO-1016]
---

# TODO-1020: Standalone TUN client -> io_driver migration decision

## Context

Carried over from TODO-1016 "Remaining work": the standalone client's
`select!` loop (`src/implementations/client/client.rs`) grew its own
scheduler - housekeeping tick, deadline waits, yield bookkeeping. The
`io_driver` runtime (`src/implementations/client/io_driver/`) already
exists as the deadline-driven, event-based carrier used elsewhere and
was identified during TODO-1015 as "the right carrier for the full
effect" of windowed reorder.

The gather-timer model (TODO-1016) removed the worst serialization
(~1 packet per wake), so this is no longer a throughput blocker - it
is a convergence decision: two scheduler implementations with
overlapping responsibility.

## Objective

Decide: migrate the standalone TUN path onto `io_driver` or document
why the bespoke loop stays. Deliverable is a written verdict with the
cost/benefit table - implementation TODO only if the verdict is
"migrate".

## Questions the study must answer

1. Does `io_driver` express everything the standalone loop needs:
   TUN-fd readiness, socket readiness, armed deadline waits
   (`next_send_deadline`), housekeeping cadence, signal/shutdown
   handling? List any missing primitive concretely.
2. What does the standalone loop gain: finer wake granularity than the
   housekeeping floor, unified deadline handling, less bespoke yield
   bookkeeping? Quantify against post-TODO-1016 behavior (drain epochs
   already emit batches; is the remaining gap scheduler-caused at
   all?).
3. **TUN-ingest backpressure profile** (added from TODO-1017 findings):
   Omega measured ~38-44% uplink loss at 60 M offered with reorder
   active - ~100% kernel TUN-queue drops (`qtun0 TX dropped`). The
   standalone path parks fd reads the moment `dgram_send_queue` (1024)
   backpressures (`drain_client_tun_uplink_fd` ->
   `tun_backpressure_frame`), while the loop keeps burning `conn.send`
   polls (~96% empty yields). Compare against io_driver's
   `enqueue_tun_datagram` (flush-before-sleep retry,
   `io_driver/runtime.rs` ~L608): does its ingest stop pulling the fd
   earlier/later, does its loop spin the same way under emission gaps,
   and does the measured rate ceiling (~3.4-3.7k pkt/s on Omega's
   single-core) change?
4. Migration cost: which code moves, what tests cover the loop today,
   what e2e coverage (`tun-e2e-netns.sh`) verifies parity.

## Acceptance

- Written verdict in this file (migrate / stay / partial - e.g. adopt
  only the deadline-wait primitive).
- If migrate: spawn a scoped implementation TODO with the mapped
  code moves and the parity test plan.
- If stay: the duplicated-responsibility rationale is recorded so the
  question does not get re-litigated every cycle.
