---
id: TODO-532
title: Complete negotiated multipath wire and data-plane runtime
severity: CRITICAL
phase: S
priority: P0
status: OPEN
created: 2026-07-22
depends_on: [TODO-449, TODO-521]
---

# TODO-532: Complete Negotiated Multipath Wire and Data-Plane Runtime

## Why

`PathState`, `PathManager`, and `PathScheduler` model isolated multipath behavior, but `Connection` never owns or invokes them. There is no negotiated multipath wire contract, per-path packet-number/recovery state, production scheduler, standby failover, or bonded runtime evidence.

## Acceptance

- Define and implement one standards-tracked negotiated multipath contract, including transport parameters, path lifecycle frames, peer validation, and downgrade behavior.
- Give each active path independent packet-number, AEAD nonce, RTT, recovery, congestion, loss, byte-counter, and anti-amplification state without nonce reuse.
- Wire selectable lowest-RTT, configured-weight, redundant, and primary-with-standby strategies into the production send path; keep disabled mode byte-for-byte behaviorally compatible.
- Prove simultaneous dual-path transfer, per-path accounting, loss isolation, no-disconnect failover under 100 ms, and at least 1.5x aggregate throughput on controlled WiFi/LTE-like paths.
- Add exhaustive failable units for frame codecs, negotiation, all strategies, state transitions, manager operations, nonce vectors, and failure handling.
- Pass local Rust gates, native CI, privileged Omega dual-interface proof, documentation/MAP/TODO truth, and preserve protected UI files.

## Sub-Tasks

- [ ] Verify the current IETF multipath draft and select the exact wire contract before editing.
- [ ] Design per-path state ownership and connection integration.
- [ ] Implement negotiation, codecs, scheduling, recovery, and failover atomically.
- [ ] Add unit, integration, performance, and privileged network proofs.
- [ ] Flush documentation and close only with exact evidence.

## Notes

- Created from TODO-449 reconciliation. Existing path and scheduler helpers may be retained only where they match the selected wire/runtime contract.

## Deviations

None.
