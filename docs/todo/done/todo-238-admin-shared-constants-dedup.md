# TODO-238: Admin Shared Constants Deduplication

## Severity: LOW

## Problem

Three sets of constants are duplicated across svelte-admin components:

### 1. Glass-Pill Inline Styles (4x duplicated, ~44 lines)
Identical inline `style=` blocks for glass/pill styling in:
- `Sidebar.svelte:129-139`
- `LogsView.svelte:350-360`
- `PillToggle.svelte:32-40`
- `Segmented.svelte:32-40`

All use identical: `background: rgba(255,255,255,0.65)`, `backdrop-filter: blur(24px) saturate(200%)`, `border: 1px solid rgba(255,255,255,0.60)`, `box-shadow: inset...`

### 2. RIPPLE_DELAY_MS = 88 (2x duplicated)
- `AdminSettingsPanel.svelte:24`
- `QKeyPanel.svelte:69`

### 3. MAX_USERNAME_CHARS / MAX_PASSWORD_CHARS (2x duplicated)
- `LoginModal.svelte:22-23`: `MAX_USERNAME_CHARS = 64`, `MAX_PASSWORD_CHARS = 256`
- `AdminSettingsPanel.svelte:22-23`: identical values

## Fix

1. Extract glass-pill styles to `packages/theme/` as CSS custom properties or a shared Tailwind plugin
2. Move `RIPPLE_DELAY_MS` to `packages/ui/` constants (shared across all apps)
3. Move `MAX_USERNAME_CHARS` / `MAX_PASSWORD_CHARS` to `$lib/types.ts` or `$lib/api.ts` as exported constants
4. Import from shared locations in all components

## Affected Files

- `apps/svelte-admin/src/lib/components/layout/Sidebar.svelte`
- `apps/svelte-admin/src/lib/components/views/LogsView.svelte`
- `apps/svelte-admin/src/lib/components/ui/PillToggle.svelte`
- `apps/svelte-admin/src/lib/components/ui/Segmented.svelte`
- `apps/svelte-admin/src/lib/components/panels/AdminSettingsPanel.svelte`
- `apps/svelte-admin/src/lib/components/panels/QKeyPanel.svelte`
- `apps/svelte-admin/src/lib/components/LoginModal.svelte`

## Verification

- `bun run check` passes
- `bun run test:unit` passes
- Visual: glass pill styling unchanged
