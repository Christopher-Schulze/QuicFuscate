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
- Every confirmed leak/deadlock/misclassification becomes a linked task with
  reproducer, owner, fix and verification. Do not bury a separate defect in
  a generic soak commit.

## Acceptance

- [ ] For each declared scenario above, record at least ten completed native
      runs at one revision with seed, commands, impairment profile, exit
      status, failure transcript and artifact path; run the supported direct,
      shared-edge and multi-hop variants only after their carrier gates pass.
      An unavailable carrier remains an explicit dependency, not a skipped
      success.
- [ ] For at least 100 connect/disconnect cycles, compare fd, worker,
      namespace, route and firewall ownership before/after; require zero
      residual owned resources and no upward memory trend after warmup.
      State the sampling interval and tolerated allocator/cache fluctuation
      before running.
- [ ] Classify every observed failure into stable user-visible causes;
      include at least timeout, authentication rejection, certificate/ECH
      rejection, transport loss, path migration, and local resource failure.
      Each discovered defect has a linked task and a failing real-path test.

## Risks

- Time: soak runs are wall-clock-heavy on single-core Omega — batch them
  overnight-style rather than blocking the session.

## Rollback

Fixes are independent commits; a destabilizing fix reverts alone.
