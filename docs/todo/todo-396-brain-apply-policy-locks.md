---
id: TODO-396
title: Brain apply_policy lock coalescing
severity: MEDIUM
phase: B
priority: P2
status: SUPERSEDED
superseded_by: TODO-417
created: 2026-06-05
---

# TODO-396: Brain `apply_policy` Lock Coalescing

> **Note (2026-07-23):** This task is **superseded by TODO-417** (Hot-Path-Lock-Elimination), which bundles TODO-396 + TODO-397 + TODO-398 into a single coordinated change with profiling validation. Do not implement this task separately.

## Problem

`StealthBrain::apply_policy` (~612-1128) acquires `self.st.write()` up to 5 times per ACK emission. Histogram vectors reallocated via `.collect()` on hot path.

## Acceptance

- Single write lock scope per `apply_policy` call (or split read/write phases explicitly)
- Reuse histogram buffers where possible
- Brain unit tests pass
- Policy outputs identical for fixed sensor inputs (snapshot test)

## Fix Plan

1. Audit all `st.write()` sites in `apply_policy`
2. Coalesce mutations into one guarded block
3. Pre-allocate or pool histogram scratch buffers

## Files

- `src/brain.rs`
- `src/transport/connection.rs` (ACK trigger site)

## Note

Do not reduce Brain sophistication; only reduce overhead.
