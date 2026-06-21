# TODO-233: Frontend Cosmetic Debt Sweep

## Severity: LOW

## Problem

Several minor frontend issues found during external audit:

### 1. German Text in English UI
`apps/svelte-admin/src/lib/components/views/LogsView.svelte:402`:
```html
<div ...>Zero-Log Privacy Modus</div>
```
Should be "Zero-Log Privacy Mode" (English UI).

### 2. Deprecated Svelte 5 `|local` Modifier
`apps/svelte-admin/src/lib/components/panels/QKeyPanel.svelte`:
```svelte
<div transition:slide|local={{ duration: 280, easing: cubicOut }}>
```
The `|local` modifier is deprecated in Svelte 5. Remove it - Svelte 5 transitions are local by default.

### 3. Duplicate Type Definitions
- `apps/svelte-admin/src/lib/blocked-ips.ts:2`: `export type PendingBlockedIpAction = "block" | "unblock";`
- `apps/svelte-admin/src/lib/types.ts:49`: `export type PendingIpAction = "block" | "unblock";`
Two identical types with different names. Consolidate to one.

### 4. Hardcoded Version String
`apps/svelte-admin/src/lib/components/views/AboutView.svelte:8`:
```svelte
<AboutContent version="v0.2.0" logoSrc={appLogo} />
```
Version should come from package.json or a build-time constant, not hardcoded.

## Fix

1. Change "Modus" to "Mode" in LogsView.svelte:402
2. Remove `|local` from QKeyPanel.svelte transition
3. Delete `PendingBlockedIpAction` in blocked-ips.ts, use `PendingIpAction` from types.ts everywhere
4. Import version from package.json or inject via Vite define

## Affected Files

- `apps/svelte-admin/src/lib/components/views/LogsView.svelte`
- `apps/svelte-admin/src/lib/components/panels/QKeyPanel.svelte`
- `apps/svelte-admin/src/lib/blocked-ips.ts`
- `apps/svelte-admin/src/lib/types.ts`
- `apps/svelte-admin/src/lib/components/views/AboutView.svelte`

## Verification

- `bun run check` passes
- `bun run test:unit` passes
- Visual: no German text visible, transitions still work
