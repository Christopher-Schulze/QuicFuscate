---
id: TODO-535
title: Prove CUBIC conformance, fairness, and loss performance
severity: CRITICAL
phase: S
priority: P0
status: OPEN
created: 2026-07-22
depends_on: [TODO-452, TODO-521]
---

# TODO-535: Prove CUBIC Conformance, Fairness, and Loss Performance

## Why

CUBIC is selected through config, integrated into recovery and stealth shaping, and covered by algorithm-path units. Independent RFC vectors, the required K precision and memory bound, Reno coexistence, and real loss performance remain unproven.

## Acceptance

- Verify the implementation against current RFC 9438 and RFC 9406 requirements and independent published vectors; correct any algorithmic mismatch in production code.
- Prove cubic window and K calculations with less than 1e-6 relative error across boundary and large-window cases.
- Assert CUBIC controller memory overhead over Reno remains below 200 bytes on supported architectures.
- On a controlled shared bottleneck, prove CUBIC plus Reno Jain fairness above 0.8 without starvation.
- Under controlled 5% random loss, prove CUBIC throughput remains above 50% of its loss-free baseline and report comparison methodology.
- Retain explicit paced CUBIC as the canonical QuicFuscate contract and prove stealth wrapping plus all other CC regressions.
- Pass local Rust gates, native CI, Omega network proof, documentation/MAP/TODO truth, and preserve protected UI files.

## Sub-Tasks

- [ ] Reconcile implementation math and HyStart behavior with primary RFC sources.
- [ ] Add independent precision, conformance, size, and regression tests.
- [ ] Build deterministic fairness and loss experiments.
- [ ] Execute local, native, and Omega evidence.
- [ ] Flush documentation and close only with exact evidence.

## Notes

- Created from TODO-452 reconciliation. Returning no pacing rate is superseded by the canonical recovery pacing contract.

## Deviations

None.
