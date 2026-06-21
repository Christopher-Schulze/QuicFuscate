---
description: Manual UI E2E run for web-admin to close remaining checklist items.
---

# Web Admin UI E2E Run

## Context
API checks are green. Remaining gaps are manual UI flows that require a real browser session.

## Desired Outcome
Complete the UI portion of `docs/todo/web-admin-e2e.md` with evidence of success or explicit blockers.

## Scope
- Login flow and auth toasts
- Status dashboard loading and empty states
- Clients list, kick, block, unblock flows
- Configuration edits and reload confirmation
- QKey generation and copy
- Metrics view refresh and error handling
- Logs view empty state and refresh
- Shutdown confirm

## Dependencies
- `docs/todo/web-admin-e2e.md`
- Live admin server: `--admin-web` with valid credentials
- Browser with cache cleared

## Work Items
- [x] Run UI checks and record results in `docs/todo/web-admin-e2e.md` (blocked items documented). OK 2026-01-31
- [x] Capture any blockers and open follow-up TODOs if needed. OK 2026-01-31

## Follow-up Run (pending)
- [x] Re-run UI checklist after QKey token enforcement changes and confirm all UI checks again. OK 2026-02-12 (`bun run test:e2e` 56/56)
- [x] Record any new blockers or regressions and link them in `docs/todo.md`. OK 2026-02-12 (no new blockers)

## Acceptance Criteria
- All UI checklist items in `docs/todo/web-admin-e2e.md` are marked complete or blocked with a clear reason.
