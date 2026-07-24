---
id: TODO-537
title: Complete timer-owned traffic-analysis defense proof
severity: CRITICAL
phase: S
priority: P0
status: OPEN
created: 2026-07-22
depends_on: [TODO-455, TODO-544]
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

## Completion Gates

- Ownership gate: one transport scheduler owns deadlines, bounded pending state, idle/ramp phases, authorization, cancellation, and wakeup integration without competing pacing or recovery timers.
- Protocol gate: deterministic tests prove ACK-only correctness, sequential protected packet numbers, congestion deferral, real-data priority, shutdown cancellation, authenticated policy, and MTU-bounded exact sizes.
- Capture gate: exact-artifact traces individually prove 10 PPS idle chaff, 100 PPS constant cadence, combined 10-second criteria, warning behavior, and bounded CPU/bandwidth cost.
- Release gate: local Rust gates, native CI, Omega capture proof, SHA-256, teardown/residue inspection, protected UI diff, and owning-doc updates all pass.

## Sub-Tasks

- [x] Map send, timeout, pacing, QKey, escalation, and shutdown ownership.
- [ ] Finalize one timer/queue state machine with bounded cost against the completed recovery and multipath contracts.
- [ ] Implement source, property, integration, and capture tests.
- [ ] Execute local, native, and Omega evidence.
- [ ] Flush documentation and close only with exact evidence.

## Notes

- Created from TODO-455 reconciliation. QUIC datagrams remain path-MTU bounded; TLS-record-size blending is outside scope.
- Verified ownership gap: both live runtimes wake on fixed 5 ms housekeeping ticks, but `Connection::timeout()` exposes only a constant 30-second idle window. `ChaffGenerator` advances only inside `Connection::send()`, and its standalone Tokio interval is unused, so an idle connection has no lifecycle-owned emission deadline.
- Verified send-path gap: chaff has no pending-slot state, soft stop, ramp-down, or shutdown cancellation. ACK-only congestion bypass can currently be converted into an ack-eliciting chaff packet, and the configured size limit exceeds the path-MTU boundary.
- Verified policy gap: traffic-analysis setters are test-only and are not mapped through Engine or standalone TOML runtime configuration. QKey stealth/FEC overrides are selected from the unauthenticated Initial identifier before the encrypted HTTP/3 possession proof; traffic-analysis authorization must not repeat that boundary error.
- Target design: one transport-owned `TrafficAnalysisScheduler` holds the effective mode, active and idle cadence, one bounded pending slot, real-traffic timestamp, idle/ramp phase, next deadline, and cancellation state. Runtime wakeups call an explicit timer transition; `send()` only consumes scheduler state, prioritizes real or ACK-only packets, and emits chaff only when congestion permits. Core exposes the deadline and timer transition to both event loops. Global configuration remains bounded independently; any QKey or Intelligent escalation upgrade is stored pending and becomes effective only after authenticated authorization.
- The draft ownership map is retained, but final design and implementation wait for TODO-544 and TODO-533 so this task consumes stable recovery and migration contracts instead of creating a parallel timer owner. Multipath (TODO-532) was scrapped by owner decision; traffic-analysis defense operates on the single active path.
- Primary surfaces: `src/transport/config.rs`, `src/transport/connection.rs`, `src/transport.rs`, `src/stealth/mod.rs`, `src/core.rs`, and both live runtime loops in `src/main.rs`.
- Evidence bundle: retain configured/effective authorization, scheduler state/deadlines, packet-number and wire-size traces, cadence distributions, congestion/real-data priority outcomes, CPU/bandwidth cost, artifact SHA-256, capture files, and teardown residue.

## Deviations

None.
