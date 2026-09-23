---
id: TODO-377
title: "Add test for desktop +error.svelte page"
severity: "LOW"
phase: legacy
priority: legacy
status: OPEN
created: 2026-03-27
backfilled: 2026-07-23
reopened: 2026-09-24
schema_exception: missing_depends_on
---

# TODO-377: Add test for desktop +error.svelte page

## Current execution gate (2026-09-24)

The former UI exclusion no longer applies. The existing
`scripts/tests/frontend/desktop/unit/src/routes/error-page.test.ts` covers
error rendering and button presence. The separate FatalErrorScreen test
exercises its callback, but no test clicks the route's Try Again action and
proves its own hash reset plus reload wiring. Extend the route test with an
observable browser-location boundary and one click through the rendered
component. Preserve the separate shared-component test. Assert that the
route action fires once and does not run during render, and retain error
string/status checks. Pass the focused test and Desktop unit/check gates;
TODO-1141 separately owns the current inventory-floor mismatch.


## Historical problem (2026-03-27)
`apps/svelte-desktop/src/routes/+error.svelte` has no test.
The equivalent web-admin error page IS tested at
`scripts/tests/frontend/web-admin/unit/src/routes/error-page.test.ts`.

## Historical fix plan
1. Create `scripts/tests/frontend/desktop/unit/src/routes/error-page.test.ts`
2. Mirror the web-admin error page test structure
3. Test: renders error message, shows retry/reload actions
4. Target: 3-4 tests

## Historical files to create
- scripts/tests/frontend/desktop/unit/src/routes/error-page.test.ts
