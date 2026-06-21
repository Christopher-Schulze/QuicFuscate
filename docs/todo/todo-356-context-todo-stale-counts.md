---
id: TODO-356
title: "Update stale test counts in context.md and todo.md"
severity: "MODERATE"
phase: legacy
priority: legacy
status: DEFERRED
created: 2026-03-27
backfilled: 2026-07-23
defer_reason: "Docs hygiene — stale counts, kosmetisch"
---

# TODO-356: Update stale test counts in context.md and todo.md


## Problem
- `docs/context.md` line 107 says "852 lib tests" - should be 916 (Session 40 added +64)
- `docs/context.md` line 111 says "Total: 1522 tests" - should be ~1587 (916+360+273+38)
- `docs/context.md` line 149 says "852 Rust lib tests GREEN" - same stale count
- `docs/context.md` line 124 references Session 39 as most recent - Session 40 exists
- `docs/todo.md` line 5 says "852 Rust lib tests, 1522 total" - same stale count

## Fix Plan
1. Read context.md, find all instances of "852" and "1522"
2. Replace with 916 and 1587 respectively
3. Update "Session 39" reference to "Session 40"
4. Update todo.md line 5 header with correct counts
5. Verify no other stale counts exist

## Files to Modify
- docs/context.md
- docs/todo.md