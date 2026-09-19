---
id: TODO-998
title: Isolate ack_sent_byte_accounting benchmark from connection setup
severity: LOW
phase: S
priority: P2
status: DONE
created: 2026-11-18
depends_on: []
---

# TODO-998: Isolate ack_sent_byte_accounting From Connection Setup

## Objective
`bench_ack_sent_byte_accounting` ran `bench_paired_1rtt_connections()` plus
`bench_seed_sent_bytes_by_pn()` inside `b.iter`, so the measured quantity was
dominated by full connection pairing + seeding rather than the ACK accounting
it claimed to measure. The published per-packet cost was ~90% setup noise.

## Evidence (before, Apple Silicon)
- 32_inflight_ack_all: 42.0 us -> isolated: 4.16 us (130 ns/acked packet)
- 1024_inflight_ack_all: 87.4 us -> isolated: 28.2 us (28 ns/packet)
- 10240_inflight_ack_all: 506 us -> isolated: 291.6 us (28 ns/packet)

## Implementation
- All three bench shapes (`ack_all`, `ack_half`, `ack_sparse`) moved to
  `iter_batched` with `BatchSize::SmallInput`; pairing + seeding run in the
  untimed setup closure, matching the `connection_1rtt_stealth_compare`
  convention already used in this file.

## Result
The honest cost of `on_ack_received` + `apply_ack_outcome` is ~28-130 ns per
acknowledged packet across realistic and adversarial inflight windows - the
SentRing drain and scratch-vector reuse are already efficient; no production
change was needed. Regression-gate value of this metric is now real instead
of measuring handshake+seeding noise.

## Acceptance
- Bench compiles and runs green; all cells report isolated timings.
- No `performance_baseline.json` key covers this group, so no stored gate
  value was invalidated by the measurement correction.

## Deviations
None.
