---
id: TODO-540
title: Complete sustained DDoS policy and live proof
severity: CRITICAL
phase: S
priority: P0
status: OPEN
created: 2026-07-22
depends_on: [TODO-459, TODO-521]
---

# TODO-540: Complete Sustained DDoS Policy and Live Proof

## Why

Global and per-IP token buckets, GeoIP, blacklist sync, and an EWMA helper exist in production. The detector does not implement sustained activation/clear windows, current PPS sampling is not interval-correct, enhanced mode does not enforce QUIC Retry, and configuration and evidence remain fragmented.

## Acceptance

- Implement interval-correct PPS sampling and sustained activation/clear state with configurable thresholds and monotonic timing.
- Apply one coherent enhanced policy to per-IP limits and standards-compliant QUIC Retry while preserving global caps and legitimate established traffic.
- Expose one validated DDoS configuration and explicit disable semantics for every component.
- Persist and load last-known-good blacklist cache atomically with size, format, URL, timeout, and failure bounds.
- Prove positive GeoIP lookup, external blacklist, exact burst/steady/global limits, activation/clear timing, Retry behavior, normal-traffic false positives, and recovery under a controlled flood.
- Pass local Rust gates, native CI, privileged Omega traffic proof, documentation/MAP/TODO truth, and preserve protected UI files.

## Sub-Tasks

- [ ] Audit accept ordering, PPS math, detector state, retry support, and configuration.
- [ ] Design unified bounded policy and cache durability.
- [ ] Implement state, Retry integration, metrics, and deterministic tests.
- [ ] Execute controlled local/native/Omega flood proof.
- [ ] Flush documentation and close only with exact evidence.

## Notes

- Created from TODO-459 reconciliation. External feeds remain optional and fail open to the last-known-good local set, never to unbounded network input.

## Deviations

None.
