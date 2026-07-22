---
id: TODO-534
title: Complete DPLPMTUD bounds, TUN coupling, and runtime proof
severity: CRITICAL
phase: S
priority: P0
status: OPEN
created: 2026-07-22
depends_on: [TODO-451, TODO-521]
---

# TODO-534: Complete DPLPMTUD Bounds, TUN Coupling, and Runtime Proof

## Why

Production sends are clamped by confirmed PMTU and ACK/loss logic drives padded probes, but discovery is fixed to 1280-1400, disabled-mode semantics are ambiguous, TUN MTU never follows the path, and no privileged black-hole or 1500-byte evidence exists.

## Acceptance

- Expose validated minimum, maximum, probe interval, and black-hole timeout policy while retaining safe protocol floors and peer maximum UDP payload clamping.
- Reach and prove 1400 within five probes and 1500 within three probes on matching paths; keep disabled behavior explicitly fixed and regression-tested.
- Make probe ACK/loss attribution robust to unrelated ACK traffic and prove all search, complete, black-hole, recovery, and periodic re-probe transitions.
- Propagate effective MTU changes through the client TUN lifecycle without transient oversized packets or route disruption.
- Prove transfer recovery after dropping packets above 1280 and measure the retained 1500-versus-1200 throughput criterion.
- Pass local Rust gates, native CI, privileged Omega netem/TUN proof, documentation/MAP/TODO truth, and preserve protected UI files.

## Sub-Tasks

- [ ] Audit config, packet sizing, ACK/loss attribution, and TUN ownership.
- [ ] Define bounded policy and MTU-change propagation.
- [ ] Implement state-machine, integration, and property tests.
- [ ] Execute privileged black-hole, re-probe, and throughput proof.
- [ ] Flush documentation and close only with exact evidence.

## Notes

- Created from TODO-451 reconciliation. Binary search remains canonical; a parallel common-MTU table is outside scope.

## Deviations

None.
