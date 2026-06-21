---
id: TODO-366
title: "Extract duplicated Switch.svelte and Select.svelte to packages/ui"
severity: "MODERATE"
phase: legacy
priority: legacy
status: DONE
created: 2026-03-27
backfilled: 2026-07-23
---

# TODO-366: Extract duplicated Switch.svelte and Select.svelte to packages/ui


## Problem
`Switch.svelte` and `Select.svelte` exist in BOTH apps with ~80% identical code:
- `apps/svelte-desktop/src/lib/components/ui/Switch.svelte`
- `apps/svelte-admin/src/lib/components/ui/Switch.svelte`
- `apps/svelte-desktop/src/lib/components/ui/Select.svelte`
- `apps/svelte-admin/src/lib/components/ui/Select.svelte`

### Switch differences:
- Animation: desktop uses duration-200, admin uses duration-260 with different easing
- Props: desktop has optional checked/onchange, admin has required props
- Both wrap the same bits-ui Switch primitive with glass styling

### Select differences:
- Admin has maxHeight prop, desktop has disabled prop
- Different cn import paths ($lib/format vs @quicfuscate/ui)
- Both wrap bits-ui Select with dropdown and glass styling

## Fix Plan
1. Create `packages/ui/Switch.svelte` - unified version with superset of all props
2. Create `packages/ui/Select.svelte` - unified version with superset of all props
3. Export from `packages/ui/index.ts`
4. Update both apps to import from `@quicfuscate/ui`
5. Delete the app-specific versions
6. Update all tests to import from new location
7. Run both test suites to verify

## Files to Modify
- packages/ui/Switch.svelte (new)
- packages/ui/Select.svelte (new)
- packages/ui/index.ts
- apps/svelte-desktop/src/lib/components/ui/ (delete Switch, Select)
- apps/svelte-admin/src/lib/components/ui/ (delete Switch, Select)
- All test files importing these components