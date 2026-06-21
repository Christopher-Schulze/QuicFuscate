# Release Task: UI Async UX Consistency (Desktop + Web Admin)

## Scope
- Ensure async interactions are consistent, readable, and non-jittery across both React frontends.

## Requested Focus
- Loading states for all async operations.
- Optimistic updates where they reduce perceived latency safely.
- Keyboard shortcut policy tracking.

## Current State
- Several loading/error components already exist.
- Remaining risk is drift: per-view behavior can still differ (loading, revalidation, optimistic rollback semantics).
- Keyboard shortcuts need explicit policy alignment with product decisions before expanding.
- Progress on 2026-02-12:
  - Web admin IP access control now uses optimistic block/unblock transitions with rollback on failure.
  - Pending actions are tracked per IP, action buttons are disabled while in-flight, and server poll reconciliation preserves optimistic state to prevent UI jitter.

## Async Coverage Matrix (current)
### Web Admin UI
- Dashboard:
  - Status/clients/metrics/blocked polling -> loading + error banner + manual refresh.
  - IP block/unblock -> optimistic update + rollback + per-IP pending lock.
- Configuration:
  - Save/reset -> loading + disabled states + validation errors.
- QKeys:
  - Generate/revoke/copy/list refresh -> loading + error + non-reentrant buttons.
- Settings:
  - Change username/password + refresh -> loading + inline validation + error banner.
- Logs:
  - Mode updates + fetch -> loading + error + empty-state handling.

### Desktop UI
- Tunnel connect/disconnect:
  - Busy states, confirm on disconnect, failure rollback, and error propagation tested.
- QKey import/edit:
  - Validation failures and parser failures covered; invalid payload rollback verified.
- Persistence:
  - Debounced save/load hydration behavior validated by unit tests.
- Toast/error boundary:
  - Render and fallback behavior covered by unit tests.

## Keyboard Shortcut Policy
- Global app-level keyboard shortcuts are intentionally disabled for v1.
- Allowed keyboard actions are only local form interactions (for example Enter in login field) and accessibility keyboard navigation.
- Any future global shortcut reintroduction requires:
  - explicit product approval,
  - collision review (browser/OS),
  - dedicated test coverage.

## Plan
1. Build an async interaction matrix by view/action for both apps.
2. Mark each action as:
   - pessimistic update,
   - optimistic with rollback,
   - optimistic without rollback (forbidden).
3. Standardize UX contract:
   - pending indicators,
   - disable rules,
   - retry affordances,
   - error banner/toast behavior.
4. Keyboard shortcuts:
   - document allowed set and forbidden contexts,
   - add tests only for approved shortcuts.

## Acceptance Criteria
- No async action is missing loading/error handling.
- Every optimistic action has rollback path and test.
- Shortcut behavior is policy-driven and test-covered.

## Completion Status
- Loading/error coverage: complete for critical async surfaces (web admin + desktop).
- Optimistic updates: complete for IP access control with rollback.
- Shortcut policy: defined and enforced (no global shortcuts in v1).
- Test evidence:
  - `cd archive/apps/web-admin-ui && bun run test:unit` (includes async helper coverage)
  - `cd apps/tauri && bun run test:unit` (59 tests passing)

## Deliverables
- Matrix doc with implemented status.
- UI tests for high-risk async paths.
- Updated docs for user-visible behavior.
