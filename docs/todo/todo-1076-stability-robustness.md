---
id: TODO-1076
title: Stability and robustness cluster
severity: MED
phase: M
priority: P1
status: OPEN
created: 2026-09-22
depends_on: []
---

# TODO-1076: Stability and robustness

## Why

Feature work outran soak work. Reconnect chains, fallback paths, mode
transitions, multi-hop lifecycle, and error classification all have unit
coverage but limited sustained-load evidence. This cluster finds and fixes
the failures that only show up over time and under faults.

## Scope

- Reconnect/fallback chains: outer-hop fallback, UDP-blocked path
  (TODO-1063), standby promotion, migration rollback (TODO-1056).
- Mode transitions: FEC on/off, stealth image switches, private-AEAD
  activation/deactivation paths.
- Multi-hop circuit lifecycle: hop churn, mid-circuit failure, teardown
  ordering.
- TUN/MASQUE lifecycle: routing ownership, crash/restart residue (the e2e
  already proves part of this — extend it).
- Resource release under error paths: leaks, unjoined workers, lingering
  namespaces/sockets.
- Error classification: user-facing errors map to the real cause; nothing
  collapses into "connection failed".

## Methodology

- Repeated Omega netns e2e runs (N≥10) including crash/restart cycles.
- Impaired-link runs: netem loss/jitter/reorder while cycling reconnects.
- Session churn: rapid connect/disconnect loops with resource-delta checks
  (fds, memory, worker threads before/after).
- Targeted fault injection where a path lacks a failure test.
- Every found leak/deadlock/misclassification lands its own fix commit —
  find and fix, never find and file-away.

## Acceptance

- [ ] e2e soak evidence committed (run count, failures observed, fixes).
- [ ] Resource-delta check shows no net growth across churn.
- [ ] Error-classification table for the top failure modes committed.

## Risks

- Time: soak runs are wall-clock-heavy on single-core Omega — batch them
  overnight-style rather than blocking the session.

## Rollback

Fixes are independent commits; a destabilizing fix reverts alone.
