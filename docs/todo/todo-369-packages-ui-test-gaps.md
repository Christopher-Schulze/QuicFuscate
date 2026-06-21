---
id: TODO-369
title: "Add tests for 5 untested packages/ui components + 2 utilities"
severity: "MODERATE"
phase: legacy
priority: legacy
status: SCRAP
created: 2026-03-27
backfilled: 2026-07-23
scrap_reason: "UI test gaps — OFF LIMITS per AGENTS.md"
---

# TODO-369: Add tests for 5 untested packages/ui components + 2 utilities


## Problem
`packages/ui/` has 9 testable files but only 4 have tests (44% coverage).

### Untested components:
1. `GlassCard.svelte` - glass-morphism card wrapper
2. `Skeleton.svelte` - loading placeholder
3. `SettingRow.svelte` - label+control layout row
4. `ConfirmDialog.svelte` - confirmation dialog with accept/cancel
5. `AboutContent.svelte` - shared about page content

### Untested utilities:
6. `ripple.ts` - Svelte action for material ripple effect (DOM manipulation)
7. `use-copy-feedback.svelte.ts` - clipboard copy with timer feedback state

### Already tested:
- cn.ts (shared-ui/unit/cn.test.ts)
- toast-store.svelte.ts (shared-ui/unit/toast-store.test.ts)
- Toast.svelte (via desktop test tree)
- ErrorBoundary.svelte (via admin test tree)

## Fix Plan
1. Create test files under `scripts/tests/frontend/shared-ui/unit/`
2. For each component: test rendering, props, user interactions, a11y attributes
3. For ripple.ts: test the Svelte action (element receives ripple on click)
4. For use-copy-feedback: test copy state transitions and timer behavior
5. Target: 3-5 tests per component, 2-3 per utility

## Files to Create
- scripts/tests/frontend/shared-ui/unit/glass-card.test.ts
- scripts/tests/frontend/shared-ui/unit/skeleton.test.ts
- scripts/tests/frontend/shared-ui/unit/setting-row.test.ts
- scripts/tests/frontend/shared-ui/unit/confirm-dialog.test.ts
- scripts/tests/frontend/shared-ui/unit/about-content.test.ts
- scripts/tests/frontend/shared-ui/unit/ripple.test.ts
- scripts/tests/frontend/shared-ui/unit/use-copy-feedback.test.ts