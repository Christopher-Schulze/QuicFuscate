# TODO-228: Frontend Utility Deduplication Sweep

## Severity: HIGH

## Problem

Multiple utility functions are copy-pasted identically across frontend components:

### svelte-admin (3 issues)

**syncAnchor() + ResizeObserver - 3x duplicated (~85 lines)**
- `apps/svelte-admin/src/lib/components/views/DashboardView.svelte:46-75`
- `apps/svelte-admin/src/lib/components/views/ConfigurationView.svelte:62-91`
- `apps/svelte-admin/src/lib/components/views/LogsView.svelte:68-97`
- Identical logic: calculates x/y from action button position, sets up ResizeObserver, registers event listeners

**isAuthError() - 5x duplicated (10 lines)**
- `AdminSettingsPanel.svelte:26`
- `QKeyPanel.svelte:71`
- `DashboardView.svelte:28`
- `ConfigurationView.svelte:34`
- `LogsView.svelte:18`
- Identical: `e instanceof ApiError && e.status === 401`

### svelte-desktop (1 issue)

**QKey dialog helpers - 5 functions duplicated (2x each)**
- `ImportQKeyDialog.svelte`: extractQKey (25-29), normalizeUtf8 (31-33), handlePaste (69-74), handlePastePointerDown (76-79), handlePasteClick (81-84)
- `EditQKeyDialog.svelte`: extractQKey (27-31), normalizeUtf8 (33-35), handlePaste (64-69), handlePastePointerDown (71-74), handlePasteClick (76-79)
- All functions are character-for-character identical

## Fix

### svelte-admin
1. Extract `syncAnchor()` + ResizeObserver setup to `$lib/utils/anchor-sync.svelte.ts` as a reusable Svelte 5 effect helper
2. Move `isAuthError()` to `$lib/api.ts` (where ApiError is already defined) and import in all 5 locations
3. Remove inline implementations from all views/panels

### svelte-desktop
4. Extract `extractQKey()`, `normalizeUtf8()`, `handlePaste*()` to `$lib/qkey-utils.ts`
5. Import shared functions in both QKey dialog components

## Affected Files

- `apps/svelte-admin/src/lib/components/views/DashboardView.svelte`
- `apps/svelte-admin/src/lib/components/views/ConfigurationView.svelte`
- `apps/svelte-admin/src/lib/components/views/LogsView.svelte`
- `apps/svelte-admin/src/lib/components/panels/AdminSettingsPanel.svelte`
- `apps/svelte-admin/src/lib/components/panels/QKeyPanel.svelte`
- `apps/svelte-admin/src/lib/api.ts`
- `apps/svelte-desktop/src/lib/components/tunnel/ImportQKeyDialog.svelte`
- `apps/svelte-desktop/src/lib/components/tunnel/EditQKeyDialog.svelte`
- New: `apps/svelte-admin/src/lib/utils/anchor-sync.svelte.ts`
- New: `apps/svelte-desktop/src/lib/qkey-utils.ts`

## Verification

- `bun run check` passes in both apps
- `bun run test:unit` passes in both apps
- Visual verification: anchor positioning, auth error handling, QKey paste still work
