---
id: TODO-544
title: Complete RFC loss detection and network proof
severity: CRITICAL
phase: S
priority: P0
status: OPEN
created: 2026-07-22
depends_on: [TODO-463]
---

# TODO-544: Complete RFC Loss Detection and Network Proof

## Why

Recovery tracks correct RTT EWMA, but PTO uses one rather than four RTTVAR. Time and RACK helpers do not own sent-packet state or declare losses, no event timer is wired, BBR receives no variance, Reno has no delivery-rate pacing, and all network/performance claims are unproven.

## Acceptance

- Reconcile the exact recovery algorithm with current primary QUIC standards before editing and keep TCP RACK concepts only where valid for QUIC.
- Correct PTO and implement one connection/recovery sent-packet owner with packet-threshold, time-threshold, reordering, ACK-range, and timer semantics.
- Expose the earliest loss/PTO deadline to every production event loop and prove cancellation/rescheduling across ACK, loss, migration, and shutdown.
- Propagate required RTT variance to BBR behavior and add bounded Reno delivery-rate pacing only with correctness and regression evidence.
- Prove 5% loss latency, 10% reordering spurious retransmissions, jitter behavior, high-BDP Reno throughput, 100-packet scan cost, and memory bounds against explicit baselines.
- Pass local Rust gates, native CI, privileged Omega netem proof, documentation/MAP/TODO truth, and preserve protected UI files.

## Completion Gates

- Standards gate: every implemented packet/time threshold, PTO, ACK range, RTT, reordering, timer, cancellation, and migration rule maps to current primary QUIC recovery requirements.
- State-machine gate: deterministic clock tests prove one canonical sent-packet owner, earliest-deadline exposure, ACK/loss/PTO transitions, CC propagation, shutdown cancellation, and bounded memory/scan cost.
- Network and performance gate: controlled 5% loss, 10% reordering, jitter, high-BDP Reno, and 100-packet matrices meet recorded latency, spurious-retransmission, throughput, CPU, and memory thresholds.
- Release gate: local Rust gates, native CI, exact-artifact privileged Omega netem proof, SHA-256, teardown/residue inspection, protected UI diff, and owning-doc updates all pass.

## Sub-Tasks

- [ ] Verify current RFC requirements and map packet/recovery/event-loop ownership.
- [ ] Design one sent-packet and timer state machine with bounded scans.
- [ ] Implement correctness, CC propagation, and deterministic units.
- [ ] Execute benchmark and privileged netem comparisons.
- [ ] Flush documentation and close only with exact evidence.

## Notes

- Created from TODO-463 reconciliation. RFC 9002 remains authoritative for QUIC; RFC 8985 may inform but not override it.

## Deviations

None.
