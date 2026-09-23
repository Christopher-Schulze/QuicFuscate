---
id: TODO-373
title: "Add tests for desktop clipboard.ts"
severity: "LOW"
phase: legacy
priority: legacy
status: OPEN
created: 2026-03-27
backfilled: 2026-07-23
reopened: 2026-09-24
schema_exception: missing_depends_on
---

# TODO-373: Add tests for desktop clipboard.ts

## Current execution gate (2026-09-24)

The former UI exclusion no longer applies. The existing
`scripts/tests/frontend/desktop/unit/src/lib/clipboard.test.ts` covers
browser fallback and error results but explicitly does not execute a
successful `commands.clipboardReadText()` call. Current production code uses
the generated Specta command binding in
`apps/svelte-desktop/src/lib/clipboard.ts`, not the dynamic import described
by the old test comment. Keep the existing real-path tests and add failable
coverage for native success, native failure followed by navigator fallback,
empty native result, WebKit browser guard, and development bridge admission.
Mock only the external command/browser boundary; invoke the real exported
`readClipboardTextDirect` function in every test. Verify the binding's actual
signature and result shape before editing. Pass the focused tests and the
Desktop unit/check gates; reconcile the stale test comment. TODO-1141 owns the
separate Desktop inventory-floor mismatch.


## Historical problem (2026-03-27)
`apps/svelte-desktop/src/lib/clipboard.ts` has multi-strategy branching logic with
zero test coverage:
- Tauri native invoke strategy
- navigator.clipboard.readText() fallback
- WebKit clipboard API fallback
- Dev bridge strategy

Each strategy has error handling and fallback behavior that should be tested.

## Historical fix plan
1. Create `scripts/tests/frontend/desktop/unit/src/lib/clipboard.test.ts`
2. Mock Tauri invoke, navigator.clipboard, and webkit APIs
3. Test: each strategy succeeds, fallback chain when primary fails, error handling
4. Target: 5-8 tests

## Historical files to create
- scripts/tests/frontend/desktop/unit/src/lib/clipboard.test.ts
