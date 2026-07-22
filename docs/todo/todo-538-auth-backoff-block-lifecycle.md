---
id: TODO-538
title: Complete QKey auth backoff and block lifecycle
severity: CRITICAL
phase: S
priority: P0
status: OPEN
created: 2026-07-22
depends_on: [TODO-456, TODO-521]
---

# TODO-538: Complete QKey Auth Backoff and Block Lifecycle

## Why

The live server rejects an IP after ten recent failed initial QKey lookups, but policy is hard-coded and has no exponential backoff, explicit block lifecycle, distinct rejection reasons, periodic pruning, or dedicated metrics.

## Acceptance

- Define one bounded configurable per-IP attempt, consecutive-failure, exponential-backoff, block-duration, and idle-prune state machine.
- Check policy before expensive QKey work, record every terminal result exactly once, and keep successful clients and unrelated IPs isolated.
- Expose distinct rate-limited and blocked outcomes plus dedicated metrics without revealing credential validity.
- Prove the exact 100-attempt, second-IP, backoff schedule, expiry, periodic prune, memory bound, and process-level rejection behavior.
- Pass local Rust gates, native CI, Omega auth-flood proof, documentation/MAP/TODO truth, and preserve protected UI files.

## Sub-Tasks

- [ ] Map every initial and post-handshake auth terminal path.
- [ ] Design typed policy, config, outcomes, metrics, and cleanup ownership.
- [ ] Implement exact units and process integration tests.
- [ ] Execute local, native, and Omega evidence.
- [ ] Flush documentation and close only with exact evidence.

## Notes

- Created from TODO-456 reconciliation. Preserve TODO-520's single encrypted bearer protocol.

## Deviations

None.
