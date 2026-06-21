---
id: TODO-388
title: "Add tests for client/subsystems.rs (61 LOC, 0 tests)"
severity: "LOW (coverage)"
phase: legacy
priority: legacy
status: SCRAP
created: 2026-03-27
backfilled: 2026-07-23
scrap_reason: "Coverage-gap per module — replaced by single cargo-tarpaulin baseline run"
---

# TODO-388: Add tests for client/subsystems.rs (61 LOC, 0 tests)


## Problem
`src/implementations/client/subsystems.rs` at 61 LOC has 0 tests from any source.
While small, it coordinates client subsystem initialization.

## Fix Plan
Target: +2-3 tests:
1. Subsystem registry: creation, lookup
2. Lifecycle: init, shutdown ordering

## Files to Modify
- src/implementations/client/subsystems.rs (add #[cfg(test)] module)