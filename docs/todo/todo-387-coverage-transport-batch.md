---
id: TODO-387
title: "Add inline tests for transport/batch.rs (383 LOC, 0 inline)"
severity: "MEDIUM (coverage)"
phase: legacy
priority: legacy
status: SCRAP
created: 2026-03-27
backfilled: 2026-07-23
scrap_reason: "Coverage-gap per module — replaced by single cargo-tarpaulin baseline run"
---

# TODO-387: Add inline tests for transport/batch.rs (383 LOC, 0 inline)


## Problem
`src/transport/batch.rs` at 383 LOC has 0 inline tests. The 3 external tests in
rt-transport-batch-processor.rs are thin (2 are Linux-only).

Batch I/O is critical for performance - it handles sendmmsg/recvmmsg batching.

## Fix Plan
Target: +6-8 inline tests:
1. BatchProcessor construction: default config, custom config (2 tests)
2. Batch sizing: calculation, limits, edge cases (2 tests)
3. Message preparation: iovec setup, header formatting (2 tests)
4. Platform detection: Linux vs fallback behavior (2 tests)

## Files to Modify
- src/transport/batch.rs (add #[cfg(test)] module)