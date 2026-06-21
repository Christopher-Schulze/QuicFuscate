# TODO-158: Split configuration.tsx Monolith into Focused Components

## Status
**DOCUMENTED - part of UI Revamp (todo-190)**

## Severity
**HIGH**

## Context
The file `archive/apps/web-admin-ui/src/views/configuration.tsx` is a 65.5KB monolith containing multiple unrelated configuration domains in a single component. This violates single-responsibility principle, makes the file extremely difficult to maintain, review, and test. It combines QKey management, IP firewall rules, admin settings, and password change functionality all in one file.

- `archive/apps/web-admin-ui/src/views/configuration.tsx`: 65.5KB single file
- Contains: QKey management UI, IP access control/firewall rules, admin settings panel, password change form
- Each domain has its own state, API calls, validation logic, and UI

## Root Cause
The configuration view started small and grew organically as features were added. Each new configuration domain was appended to the existing file rather than being extracted into its own component. No refactoring threshold was enforced.

## Fix Plan
1. Analyze the current `configuration.tsx` to identify natural component boundaries:
   - QKey management (list, add, revoke, rotate)
   - IP access control (allowlist/blocklist, CIDR rules)
   - Admin settings (general server configuration)
   - Password change (current/new password form)
2. Create new component files:
   - `archive/apps/web-admin-ui/src/views/config/QKeyPanel.tsx` (< 10KB)
   - `archive/apps/web-admin-ui/src/views/config/IpAccessControlPanel.tsx` (< 10KB)
   - `archive/apps/web-admin-ui/src/views/config/AdminSettingsPanel.tsx` (< 10KB)
   - `archive/apps/web-admin-ui/src/views/config/PasswordChangePanel.tsx` (< 10KB)
3. Extract shared types and utilities into:
   - `archive/apps/web-admin-ui/src/views/config/types.ts`
   - `archive/apps/web-admin-ui/src/views/config/api.ts` (shared API calls)
4. Refactor `configuration.tsx` into a thin orchestrator that imports and renders the panels (likely with tabs or sections)
5. Move state management into each panel component (colocate state with UI)
6. Update all imports and routes
7. Run all E2E and unit tests

## Acceptance Criteria
- No single component file exceeds 15KB
- `configuration.tsx` is a thin orchestrator (< 5KB) that composes the panels
- Each panel is independently testable
- All existing functionality preserved (no feature regression)
- All E2E tests pass
- All unit tests pass or are updated to test individual panels

## Dependencies
- None - purely a refactoring task
- Should be done before or in coordination with todo-157 (HeroUI to Shadcn migration)

## Affected Files
- `archive/apps/web-admin-ui/src/views/configuration.tsx` (refactor to orchestrator)
- `archive/apps/web-admin-ui/src/views/config/QKeyPanel.tsx` (new)
- `archive/apps/web-admin-ui/src/views/config/IpAccessControlPanel.tsx` (new)
- `archive/apps/web-admin-ui/src/views/config/AdminSettingsPanel.tsx` (new)
- `archive/apps/web-admin-ui/src/views/config/PasswordChangePanel.tsx` (new)
- `archive/apps/web-admin-ui/src/views/config/types.ts` (new, shared types)
- `archive/apps/web-admin-ui/src/views/config/api.ts` (new, shared API calls)
- `scripts/tests/frontend/web-admin/e2e/app.pw.ts` (may need import updates)
