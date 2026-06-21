# TODO-197: Svelte Admin/Desktop Contract and End-to-End Coverage

## Status
**COMPLETED**

## Severity
**HIGH**

## Context
Current frontend validation still reflects the old React world and misses real Svelte-era failure paths:

- frontend CI still checks the React apps
- admin contract tests use a dummy handler that masks the registry-backed QKey issue
- Svelte UI flows lack final Playwright or end-to-end proof for the actual shipped path
- some React-era tests will become obsolete after the cutover

The repository needs tests that match the real Svelte-first product workflow.

## Root Cause
The migration delivered UI code faster than its validation stack. Test ownership never moved fully from React references to the real Svelte surfaces.

## Fix Plan
1. Replace React frontend CI jobs with Svelte CI jobs.
2. Update admin HTTP contract coverage to use real runtime-backed behavior where practical.
3. Add Svelte admin Playwright coverage for:
   - login
   - config save/reset
   - QKey issue/revoke and one-time copy semantics
   - admin password change
4. Add Svelte desktop coverage for:
   - tunnel add/edit/import
   - QKey import
   - state save
5. Remove or archive obsolete React-specific tests after cutover.

## Acceptance Criteria
- Svelte apps have the primary frontend CI coverage.
- Contract tests no longer give false confidence for QKey listing semantics.
- Critical user flows are covered end-to-end on the Svelte path.
- Obsolete React-only tests are removed from active CI.

## Dependencies
- TODO-191 and TODO-192 for Svelte-first pipeline truth
- TODO-193 and TODO-194 for stable contract behavior

## Affected Files
- `.github/workflows/ci.yml`
- `scripts/tests/frontend/**/*`
- `scripts/tests/rust/rt-admin-http-contract.rs`
- `scripts/tests/rust/integration/qkey_auth_integration.rs`
- `apps/svelte-admin/**/*`
- `apps/svelte-desktop/**/*`

## Progress Notes (2026-03-16)
- Completed in this pass:
  - admin HTTP contract coverage was already aligned earlier for metadata-only `/api/qkeys`
  - Svelte package-owned Playwright configs now exist in:
    - `apps/svelte-admin/playwright.config.ts`
    - `apps/svelte-desktop/playwright.config.ts`
  - active unit coverage now imports Svelte product code instead of React helpers
- Current validation truth:
  - the remaining Svelte admin residuals were closed:
    - QKey issue/revoke metadata flow
    - logging mode dirty-state and no-log behavior
    - settings credential-update dialog coverage
  - the remaining Svelte desktop residuals were closed:
    - dialog centering/layout contract
    - toolbar/action accessibility names
    - smoke path log-level trigger contract
  - `cd apps/svelte-admin && bun run test:e2e` is green
  - `cd apps/svelte-desktop && bun run test:e2e` is green

## Progress Notes (2026-03-17)
- Re-ran contract-sensitive desktop and admin frontend validation after the parity/hardening sweep:
  - the narrowed fatal-error capture fix kept the desktop Playwright suites green after shell hardening
  - admin sidebar/ripple polish kept navigation and app-shell contracts green
