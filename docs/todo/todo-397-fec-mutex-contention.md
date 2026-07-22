---
id: TODO-397
title: FEC encoder/decoder mutex contention
severity: MEDIUM
phase: B
priority: P2
status: SCRAP
superseded_by: TODO-417
created: 2026-06-05
resolved: 2026-07-22
---

# TODO-397: FEC Mutex Contention Reduction

> **Note (2026-07-23):** This task is **superseded by TODO-417** (Hot-Path-Lock-Elimination), which bundles TODO-396 + TODO-397 + TODO-398 into a single coordinated change with profiling validation. Do not implement this task separately.

## Problem

`AdaptiveFec` uses `Arc<Mutex<InterleavedEncoder>>`, `Arc<Mutex<InterleavedDecoder>>`, `Arc<Mutex<ModeManager>>`. `std::sync::Mutex` on every send/receive. Rest of stack prefers `parking_lot`.

## Acceptance

- No `std::sync::Mutex` on FEC hot path OR documented single-thread ownership with `&mut AdaptiveFec`
- Send+receive concurrency test if MT path retained
- FEC simulation tests pass

## Fix Plan

1. Option A: `parking_lot::Mutex` drop-in
2. Option B: move FEC ownership into connection thread (no Arc)
3. Measure contention with stress test

## Files

- `src/fec/mod.rs`
- `src/core.rs`
