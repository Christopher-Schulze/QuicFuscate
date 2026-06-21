---
id: TODO-408
title: Fix VNNI aggregate_congestion heap allocs
severity: LOW
phase: B
priority: P3
status: DONE
created: 2026-06-05
resolved: 2026-07-23
---

# TODO-408: Fix VNNI `aggregate_congestion` Heap Allocations

## Problem

`optimize::transport::aggregate_congestion` VNNI path (~113-123) allocates `Vec::with_capacity` per sample chunk in telemetry path called from `core::update_state`.

## Acceptance

- Zero heap alloc per `aggregate_congestion` call on hot telemetry path
- Use stack arrays or in-place gather
- optimize/transport tests pass

## Fix Plan

1. Replace per-chunk Vec with fixed-size stack buffer `[u32; 4]` or similar
2. Verify SIMD output unchanged vs scalar

## Files

- `src/optimize/transport.rs`
