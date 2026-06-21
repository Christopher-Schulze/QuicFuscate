---
id: TODO-384
title: "Add inline tests for optimize/iter.rs (626 LOC, 0 inline)"
severity: "MEDIUM (coverage)"
phase: legacy
priority: legacy
status: SCRAP
created: 2026-03-27
backfilled: 2026-07-23
scrap_reason: "Coverage-gap per module — replaced by single cargo-tarpaulin baseline run"
---

# TODO-384: Add inline tests for optimize/iter.rs (626 LOC, 0 inline)


## Problem
`src/optimize/iter.rs` at 626 LOC has 0 inline tests. Only 6 external tests exist
across rt-iter-reductions.rs (3) and rt-iter-reduction-telemetry.rs (3).

The module provides iterator acceleration with SIMD-optimized reductions (sum, min,
max, product) and parallel chunk processing.

## Fix Plan
Target: +10-15 inline tests:
1. Sum reduction: empty, single, power-of-two, non-aligned lengths (4 tests)
2. Min/max: empty, single, negative values, all-same (4 tests)
3. Chunk processing: small inputs, exact alignment, remainder handling (3 tests)
4. Edge cases: zero-length, single-element, very large (3 tests)

## Files to Modify
- src/optimize/iter.rs (add #[cfg(test)] module)