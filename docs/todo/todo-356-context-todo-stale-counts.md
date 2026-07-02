---
id: TODO-356
title: "Update stale test counts in retired local worklog and todo.md"
severity: "MODERATE"
phase: legacy
priority: legacy
status: DEFERRED
created: 2026-03-27
backfilled: 2026-07-23
defer_reason: "Local worklog files were removed; docs/todo.md is the active task truth."
---

# TODO-356: Update stale test counts in retired local worklog and todo.md


## Problem
- Retired local worklog lines used stale test counts before the worklog files were removed.
- `docs/todo.md` line 5 says "852 Rust lib tests, 1522 total" - same stale count

## Fix Plan
1. Do not recreate retired local worklog files.
2. Keep `docs/todo.md` as the task-status truth.
3. Verify no active docs still depend on removed worklog files.

## Files to Modify
- docs/todo.md
