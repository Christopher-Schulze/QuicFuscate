---
id: TODO-373
title: "Add tests for desktop clipboard.ts"
severity: "LOW"
phase: legacy
priority: legacy
status: SCRAP
created: 2026-03-27
backfilled: 2026-07-23
scrap_reason: "UI test gap — OFF LIMITS per AGENTS.md"
---

# TODO-373: Add tests for desktop clipboard.ts


## Problem
`apps/svelte-desktop/src/lib/clipboard.ts` has multi-strategy branching logic with
zero test coverage:
- Tauri native invoke strategy
- navigator.clipboard.readText() fallback
- WebKit clipboard API fallback
- Dev bridge strategy

Each strategy has error handling and fallback behavior that should be tested.

## Fix Plan
1. Create `scripts/tests/frontend/desktop/unit/src/lib/clipboard.test.ts`
2. Mock Tauri invoke, navigator.clipboard, and webkit APIs
3. Test: each strategy succeeds, fallback chain when primary fails, error handling
4. Target: 5-8 tests

## Files to Create
- scripts/tests/frontend/desktop/unit/src/lib/clipboard.test.ts