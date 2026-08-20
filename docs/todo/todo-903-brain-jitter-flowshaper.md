---
id: TODO-903
title: Brain jitter gate and FlowShaper tuning
severity: MEDIUM
phase: S
priority: P2
status: QUEUED
created: 2026-08-21
depends_on: []
---

# TODO-903: Brain Jitter Gate and FlowShaper Tuning

## Objective
Fix `src/transport/connection/send.rs:206-227` jitter gate hitting ALL packets inc ACK-only, and `stealth/manager.rs:649-653` uniform [1500,3000]us delay per datagram.

## Verified Evidence
- `send.rs:206-227` `TimingGate` applied to every packet.
- `manager.rs:649-653` `FlowShaper` uniform delay.
- `brain.rs:606` EnvSnapshot per ACK already covered by TODO-894.

## Acceptance
- Jitter only on data packets, not ACK-only.
- FlowShaper uses adaptive delay based on CE ratio, not uniform.
- `scripts/tests/suites/test-performance-regression.sh --only latency` unchanged.

## Out of Scope
- No probe detection change.

## Deviations
None.
