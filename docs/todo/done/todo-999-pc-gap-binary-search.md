---
id: TODO-999
title: Binary-search the persistent-congestion gap probe
severity: LOW
phase: S
priority: P2
status: DONE
created: 2026-11-18
depends_on: []
---

# TODO-999: Binary-Search the Persistent-Congestion Gap Probe

## Objective
`finish_ack_loss_accounting` probed `newly_acked.iter().any(|a| prev <
a.sent_at < pkt.sent_at)` once per loss-run candidate - O(lost x acked). With
the 16384-packet retained cap, an adversarial loss+ACK batch could force
~2.7e8 comparisons on the packet-processing path.

## Implementation
- New `acked_times_scratch: Vec<Instant>` reused across ACK frames (same
  scratch discipline as `acked_scratch`/`lost_scratch`).
- Filled lazily on the first gap probe (`pc_window.end.is_some()`), sorted
  once, then each lost packet resolves `acked_between` via
  `partition_point` - O(lost x log acked) total.
- Semantics preserved exactly: `partition_point(|t| *t <= prev)` returns the
  first element strictly greater than `prev`; comparing it against
  `pkt.sent_at` reproduces the strict open-interval `any()` query including
  timestamp ties.

## Acceptance
- `cargo test -p qf-transport-recovery` 50/50 green; all 7
  persistent-congestion tests pass, including
  `ack_inside_loss_run_invalidates_persistent_congestion` and
  `reordered_ack_for_prior_lost_packet_breaks_persistent_congestion` which
  directly exercise the replaced probe.
- `cargo clippy -p qf-transport-recovery` clean.
- Root recovery-filtered suite 47/47 green.

## Deviations
None.
