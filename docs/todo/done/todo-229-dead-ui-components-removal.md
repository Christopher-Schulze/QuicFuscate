# TODO-229: Dead UI Components Removal (PillToggle, Segmented)

## Severity: LOW

## Problem

Two UI components in `apps/svelte-admin/src/lib/components/ui/` have zero imports or usages anywhere in the svelte-admin codebase:

- `PillToggle.svelte` - never imported, never used in any view or panel
- `Segmented.svelte` - never imported, never used in any view or panel

These are dead code that was likely created during initial component scaffolding but never integrated into any view.

## Fix

1. Delete `apps/svelte-admin/src/lib/components/ui/PillToggle.svelte`
2. Delete `apps/svelte-admin/src/lib/components/ui/Segmented.svelte`
3. Remove any test files for these components (if they exist)
4. Update MAP.md to remove these files from the tree

## Affected Files

- `apps/svelte-admin/src/lib/components/ui/PillToggle.svelte` (DELETE)
- `apps/svelte-admin/src/lib/components/ui/Segmented.svelte` (DELETE)

## Verification

- `bun run check` passes
- `bun run test:unit` passes
- Grep confirms zero references remain
