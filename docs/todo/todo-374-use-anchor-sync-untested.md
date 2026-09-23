---
id: TODO-374
title: "Add tests for admin use-anchor-sync.ts"
severity: "LOW"
phase: legacy
priority: legacy
status: OPEN
created: 2026-03-27
backfilled: 2026-07-23
reopened: 2026-09-24
schema_exception: missing_depends_on
---

# TODO-374: Add tests for admin use-anchor-sync.ts

## Current execution gate (2026-09-24)

The former UI exclusion no longer applies. The existing
`scripts/tests/frontend/web-admin/unit/use-anchor-sync.test.ts` proves
initial position, window resize, listener cleanup, and observer disconnect.
It does not fire the registered capturing scroll listener or an actual
`ResizeObserver` callback, and does not assert that main-element observation
is registered. Extend that same test file with real `useAnchorSync` calls and
controlled browser-boundary events: scroll and observer callbacks must
recompute from changed DOMRects, while teardown must stop both paths and
disconnect exactly the owned observations. Keep the production helper and
existing test family; pass the focused test and Admin unit/check gates.


## Historical problem (2026-03-27)
`apps/svelte-admin/src/lib/use-anchor-sync.ts` has DOM position tracking logic with
ResizeObserver and scroll/resize event listeners. Zero test coverage.

## Historical fix plan
1. Create `scripts/tests/frontend/web-admin/unit/use-anchor-sync.test.ts`
2. Mock ResizeObserver and DOM elements
3. Test: position calculation, cleanup on destroy, resize/scroll handlers
4. Target: 3-5 tests

## Historical files to create
- scripts/tests/frontend/web-admin/unit/use-anchor-sync.test.ts
