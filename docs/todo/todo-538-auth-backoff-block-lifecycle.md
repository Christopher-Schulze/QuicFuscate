---
id: TODO-538
title: Complete QKey auth backoff and block lifecycle
severity: CRITICAL
phase: S
priority: P0
status: OPEN
created: 2026-07-22
depends_on: [TODO-456]
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

## Completion Gates

- State-machine gate: exact unit vectors cover configured thresholds, exponential schedule, cap, expiry, success reset, disable semantics, and monotonic-time behavior.
- Isolation gate: process tests prove one terminal record per attempt, early rejection before expensive work, distinct non-oracular outcomes, unrelated-IP isolation, and successful-client continuity.
- Resource gate: the 100-attempt and sustained-cardinality matrices prove periodic prune, explicit memory bounds, bounded CPU, metrics, audit outcomes, and no attacker-controlled leak.
- Release gate: local Rust gates, native CI, exact-artifact Omega auth-flood proof, SHA-256, cleanup, protected UI diff, and owning-doc updates all pass.

## Sub-Tasks

- [ ] Map every initial and post-handshake auth terminal path.
- [ ] Design typed policy, config, outcomes, metrics, and cleanup ownership.
- [ ] Implement exact units and process integration tests.
- [ ] Execute local, native, and Omega evidence.
- [ ] Flush documentation and close only with exact evidence.

## Notes

- Created from TODO-456 reconciliation. Preserve TODO-520's single encrypted bearer protocol.
- Primary surfaces: `src/implementations/server/limits.rs`, `src/implementations/server/accept.rs`, `src/implementations/server/mod.rs`, `src/implementations/server/metrics.rs`, and `config/server-linux.default.toml`.
- Scope lock: one monotonic in-memory policy owner covers initial and post-handshake terminal results without becoming a credential oracle. Do not alter the QKey wire protocol, add persistent IP surveillance, or duplicate the broader DDoS owner from TODO-540.
- Evidence bundle: record configuration precedence, deterministic clock vectors, outcome/audit/metric counts, expensive-work bypass proof, cardinality and prune bounds, CPU/memory results, artifact hash, flood inputs, successful-client continuity, and cleanup.

## Deviations

None.
