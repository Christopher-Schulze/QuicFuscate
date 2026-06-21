---
id: TODO-374
title: "Add tests for admin use-anchor-sync.ts"
severity: "LOW"
phase: legacy
priority: legacy
status: SCRAP
created: 2026-03-27
backfilled: 2026-07-23
scrap_reason: "UI test gap — OFF LIMITS per AGENTS.md"
---

# TODO-374: Add tests for admin use-anchor-sync.ts


## Problem
`apps/svelte-admin/src/lib/use-anchor-sync.ts` has DOM position tracking logic with
ResizeObserver and scroll/resize event listeners. Zero test coverage.

## Fix Plan
1. Create `scripts/tests/frontend/web-admin/unit/use-anchor-sync.test.ts`
2. Mock ResizeObserver and DOM elements
3. Test: position calculation, cleanup on destroy, resize/scroll handlers
4. Target: 3-5 tests

## Files to Create
- scripts/tests/frontend/web-admin/unit/use-anchor-sync.test.ts