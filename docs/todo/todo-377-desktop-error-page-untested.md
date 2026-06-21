---
id: TODO-377
title: "Add test for desktop +error.svelte page"
severity: "LOW"
phase: legacy
priority: legacy
status: SCRAP
created: 2026-03-27
backfilled: 2026-07-23
scrap_reason: "UI test gap — OFF LIMITS per AGENTS.md"
---

# TODO-377: Add test for desktop +error.svelte page


## Problem
`apps/svelte-desktop/src/routes/+error.svelte` has no test.
The equivalent web-admin error page IS tested at
`scripts/tests/frontend/web-admin/unit/src/routes/error-page.test.ts`.

## Fix Plan
1. Create `scripts/tests/frontend/desktop/unit/src/routes/error-page.test.ts`
2. Mirror the web-admin error page test structure
3. Test: renders error message, shows retry/reload actions
4. Target: 3-4 tests

## Files to Create
- scripts/tests/frontend/desktop/unit/src/routes/error-page.test.ts