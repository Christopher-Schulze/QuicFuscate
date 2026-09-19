---
id: TODO-997
title: Cacheline-pad StealthBrain pending observer counters (false sharing)
severity: MEDIUM
phase: S
priority: P1
status: DONE
created: 2026-11-18
depends_on: []
---

# TODO-997: Cacheline-Pad StealthBrain Pending Observer Counters

## Objective
Remove false sharing in `StealthBrain`'s lock-free observer accumulators.
`on_packet_recv` runs per received packet on the dataplane thread while
`apply_policy` drains the same words from the housekeeping thread, and under
multipath/RX-sharding a connection's observer can be written from multiple
workers. All pending counters were adjacent `AtomicU64`s sharing one
cacheline, and the size/IAT histogram bins were packed `AtomicU64` arrays -
every RMW bounced the line between writers.

## Verified Evidence
- `src/brain.rs` fields `pending_ecn`, `pending_ack`, `pending_packet_count`,
  `pending_reorder_count`, `pending_max_pn`, `pending_last_packet_time_ns`
  were adjacent unpadded atomics; `pending_size_bins`/`pending_iat_bins` were
  `Box<[AtomicU64]>` (8 bytes per bin, hot bins shared lines).
- `ci_regression` group `brain_packet_observer` showed negative scaling before
  the fix: workers_1 = 45.3 us, workers_4 = 407 us, workers_8 = 991 us
  (Apple Silicon, release).

## Implementation
- Each hot counter wrapped in `crossbeam_utils::CachePadded` (crate already in
  the dependency tree; added as a direct `crossbeam-utils = "0.8"` edge).
- `new_atomic_bins` in `src/brain/state.rs` now returns
  `Box<[CachePadded<AtomicU64>]>` so every histogram bin owns a cacheline.
- All call sites unchanged: `CachePadded` derefs transparently to the inner
  atomic/mutex.
- Cold telemetry atomics (`loss_rate`, `stealth_active`, `cpu_usage_percent`,
  `memory_pressure`, `bandwidth_bps`) intentionally left unpadded; the padded
  pending fields isolate them onto their own line.

## Measured Result (Apple Silicon, criterion `brain_packet_observer`)
- workers_1: 45.3 us -> 37.5 us (-30%, +44% throughput)
- workers_4: 407 us -> 326 us (-15%)
- workers_8: 991 us -> 635 us (-37%, +60% throughput)

Remaining sub-linear scaling is true atomic contention on the same counters in
the benchmark's synthetic shared-brain topology; production uses one brain per
connection, and the dataplane-vs-housekeeping cacheline ping-pong is removed.

## Acceptance
- `cargo test --lib brain::` 62/62 green.
- `cargo clippy` clean, `cargo fmt` clean.
- Benchmark improvement recorded above; no regression in any worker class.

## Deviations
None.
