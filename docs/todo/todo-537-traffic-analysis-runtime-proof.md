---
id: TODO-537
title: Complete timer-owned traffic-analysis defense proof
severity: CRITICAL
phase: S
priority: P0
status: OPEN
created: 2026-07-22
depends_on: [TODO-455, TODO-521]
---

# TODO-537: Complete Timer-Owned Traffic-Analysis Defense Proof

## Why

Full-padding and encrypted chaff paths exist, but chaff is polled only when the caller invokes send. There is no idle wakeup, soft stop, constant-rate queue, bandwidth warning, per-QKey/escalation policy, or packet-capture proof.

## Acceptance

- Give constant-rate and idle chaff one lifecycle-owned timer integrated with connection timeout/wakeup handling; ACK-only traffic must remain protocol-correct.
- Implement bounded queueing, real-data priority, congestion deferral, idle soft-stop, ramp-down, shutdown cancellation, and explicit bandwidth-cost warnings.
- Apply authorized QKey and escalation policy only after authentication without weakening global safety bounds.
- Prove full-padding exact wire sizes, 10 PPS idle chaff, 100 PPS constant cadence, sequential protected packet numbers, congestion behavior, and combined 10-second capture criteria.
- Pass local Rust gates, native CI, Omega packet-capture proof, documentation/MAP/TODO truth, and preserve protected UI files.

## Sub-Tasks

- [ ] Map send, timeout, pacing, QKey, escalation, and shutdown ownership.
- [ ] Design one timer/queue state machine with bounded cost.
- [ ] Implement source, property, integration, and capture tests.
- [ ] Execute local, native, and Omega evidence.
- [ ] Flush documentation and close only with exact evidence.

## Notes

- Created from TODO-455 reconciliation. QUIC datagrams remain path-MTU bounded; TLS-record-size blending is outside scope.

## Deviations

None.
