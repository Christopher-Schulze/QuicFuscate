---
id: TODO-368
title: "Move fatal-error-screen.test.ts to correct directory"
severity: "LOW"
phase: legacy
priority: legacy
status: DONE
created: 2026-03-27
backfilled: 2026-07-23
---

# TODO-368: Move fatal-error-screen.test.ts to correct directory


## Problem
`scripts/tests/frontend/desktop/unit/src/components/fatal-error-screen.test.ts`
is at `src/components/` level, but the source component it tests is at
`src/lib/components/ui/FatalErrorScreen.svelte`.

Convention: test directory structure mirrors source directory structure.
All other UI component tests are at `src/components/ui/*.test.ts`.

## Fix Plan
1. Move `fatal-error-screen.test.ts` from `src/components/` to `src/components/ui/`
2. Update the relative import path (from `../../testing-library` to `../../../testing-library`)
3. Update the source component import path (adjust depth)
4. Run test to verify

## Files to Modify
- scripts/tests/frontend/desktop/unit/src/components/fatal-error-screen.test.ts (move)