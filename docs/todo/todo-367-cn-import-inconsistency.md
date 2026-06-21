---
id: TODO-367
title: "Fix cn() import inconsistency between desktop and admin"
severity: "MODERATE"
phase: legacy
priority: legacy
status: DONE
created: 2026-03-27
backfilled: 2026-07-23
---

# TODO-367: Fix cn() import inconsistency between desktop and admin


## Problem
The `cn()` utility (class name merger using clsx + tailwind-merge) exists in two places:
- `packages/ui/cn.ts` - the shared package version
- `apps/svelte-desktop/src/lib/format.ts` - a local copy

Desktop components import cn from `$lib/format`, while admin components import from
`@quicfuscate/ui`. This means:
- Two copies of the same function exist
- If the shared version changes, desktop won't pick it up
- Inconsistent import paths confuse developers

## Fix Plan
1. Verify `packages/ui/cn.ts` and `apps/svelte-desktop/src/lib/format.ts` cn() are identical
2. Remove cn() from desktop's format.ts (keep other format utilities)
3. Update all desktop component imports: `$lib/format` -> `@quicfuscate/ui` for cn
4. Run desktop test suite to verify
5. If format.ts becomes empty after cn removal, consider whether other exports remain

## Files to Modify
- apps/svelte-desktop/src/lib/format.ts (remove cn export)
- All desktop components that import cn from $lib/format