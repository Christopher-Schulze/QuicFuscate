---
id: TODO-902
title: io_uring TX triple-copy and channel1 fix
severity: MEDIUM
phase: S
priority: P1
status: QUEUED
created: 2026-08-21
depends_on: []
---

# TODO-902: io_uring TX Triple-Copy and Channel1 Fix

## Objective
Fix `src/optimize/uring_batch.rs:543-546,904-927` triple-copy (pool->temp Vec->iovec copy) + `channel(1)` (1 request in flight) + `Sleep(1ms)` polling in io_uring TX path. Use ownership transfer and `submit_and_wait` with channel depth >=8.

## Verified Evidence
- `uring_batch.rs:543-546` copies payload via temp Vec before iovec.
- `worker.rs:41` channel depth 1 limits to 1 request in flight.
- Polling via `Sleep(1ms)` instead of `AsyncFd` on CQ.

## Acceptance
- Zero-copy: pool block directly as iovec, no temp Vec.
- Channel depth 8, `submit_and_wait` event-driven.
- `cargo bench --bench ci_regression -- uring` shows 2x throughput.

## Out of Scope
- No io_uring RX change (already zero-copy at recv.rs:411-437).

## Deviations
None.
