---
id: TODO-385
title: "Add external tests for optimize/unsafe.rs (1511 LOC, 11 inline only)"
severity: "MEDIUM (coverage)"
phase: legacy
priority: legacy
status: SCRAP
created: 2026-03-27
backfilled: 2026-07-23
scrap_reason: "Coverage-gap per module — replaced by single cargo-tarpaulin baseline run"
---

# TODO-385: Add external tests for optimize/unsafe.rs (1511 LOC, 11 inline only)


## Problem
`src/optimize/unsafe.rs` at 1511 LOC has 11 inline tests and 0 external tests.
Contains unsafe memory operations (non-temporal stores, prefetch, raw pointer
manipulation). Coverage ratio ~7 tests/1000 LOC.

## Fix Plan
Target: +8-10 tests covering:
1. Non-temporal store: correctness with various alignments (2 tests)
2. Prefetch: does not corrupt data, no-op on unsupported (2 tests)
3. Raw pointer operations: bounds checking, alignment (3 tests)
4. MIRI compatibility: run existing tests under MIRI if possible (verification)

## Files to Modify
- src/optimize/unsafe.rs (extend #[cfg(test)] module)