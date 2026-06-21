# TODO-243: Frontend Dead Code and Scaffolding Cleanup

## Severity: LOW

## Problem

Three categories of dead/scaffolding code across both frontend apps:

### 1. formatPercent() Unused (Desktop)
`apps/svelte-desktop/src/lib/format.ts:50-53` defines `formatPercent()` but it is never imported or called anywhere in the desktop app.

### 2. Empty Barrel index.ts (Both Apps)
- `apps/svelte-desktop/src/lib/index.ts` - contains only a comment, no exports
- `apps/svelte-admin/src/lib/index.ts` - same, only a comment

These are SvelteKit scaffolding files that serve no purpose.

### 3. app.d.ts All Interfaces Commented Out (Both Apps)
- `apps/svelte-desktop/src/app.d.ts` - all interfaces commented out (template code)
- `apps/svelte-admin/src/app.d.ts` - same

These files contain only commented-out SvelteKit template interfaces that were never customized.

## Fix

1. Remove `formatPercent()` from `apps/svelte-desktop/src/lib/format.ts`
2. Delete or leave `index.ts` files (SvelteKit may require them to exist, even empty)
3. Either populate `app.d.ts` with actual type augmentations or uncomment and fill in the interfaces if SvelteKit needs them

## Affected Files

- `apps/svelte-desktop/src/lib/format.ts`
- `apps/svelte-desktop/src/lib/index.ts`
- `apps/svelte-admin/src/lib/index.ts`
- `apps/svelte-desktop/src/app.d.ts`
- `apps/svelte-admin/src/app.d.ts`

## Verification

- `bun run check` passes in both apps
- `bun run test:unit` passes in both apps
