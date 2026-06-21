# TODO-279: syncAnchor() Pattern Duplicated 3x in Svelte Admin

## Severity: MEDIUM

## Source
Cross-model forensic audit (2026-03-22). Found by Mimo V2 Pro, verified in 3 files.

## Problem
Identical ~30-line pattern copied verbatim in:
1. `apps/svelte-admin/src/lib/components/views/DashboardView.svelte` (lines 42-71)
2. `apps/svelte-admin/src/lib/components/views/ConfigurationView.svelte` (lines 58-87)
3. `apps/svelte-admin/src/lib/components/views/LogsView.svelte` (lines 64-93)

Pattern includes: `syncAnchor()` function + `$effect()` with ResizeObserver + scroll/resize listeners + cleanup.

## Fix
Extract to `apps/svelte-admin/src/lib/use-action-anchor.svelte.ts`:
```typescript
export function useActionAnchor(getEl: () => HTMLElement | null) {
  // shared syncAnchor + $effect + ResizeObserver logic
}
```

Replace 3 copy-paste blocks with single import.

## Verification
- `bun run check` GREEN in svelte-admin
- `bun run test:unit` GREEN
- Toast anchor positioning still works in all 3 views
