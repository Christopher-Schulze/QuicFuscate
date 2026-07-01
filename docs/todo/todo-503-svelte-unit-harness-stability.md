---
id: TODO-503
title: Svelte unit harness stability
severity: MEDIUM
phase: "R"
priority: P1
status: DONE
created: 2026-07-01
depends_on: [TODO-192, TODO-197, TODO-472]
---

# TODO-503: Svelte Unit Harness Stability

## Context

The active Svelte admin and desktop app checks were type-clean, and the Tauri
native backend compiled, but full `test:unit` runs timed out under the current
Bun/Vitest/Svelte dependency set. Single focused tests passed, which proved the
component behavior was not the root cause. The failure mode was harness-level:
the full suite started too many Vite/Svelte transforms concurrently, causing
ordinary 5-second test timeouts under worker contention.

The desktop setup also waited for a timer in a global `afterEach`, which is
fragile when individual tests enable fake timers. That can block cleanup if a
test-specific timer reset does not run before the global hook.

## Desired Outcome

- Keep the active Svelte admin and desktop unit suites repeatable.
- Preserve real component behavior and assertions.
- Do not modify UI components, visual styles, assets, copy, layout, or
  animations.
- Keep tests deterministic under Bun `1.3.14` and Vitest `4.1.0`.
- Preserve the existing Tauri native backend check path.

## Implementation

- Updated `apps/svelte-admin/vitest.config.ts` and
  `apps/svelte-desktop/vitest.config.ts` to run unit test files without file
  parallelism and with a single worker.
- Raised the harness timeout to 15 seconds so slow local transforms do not
  masquerade as product regressions.
- Updated the web-admin and desktop unit setup hooks to clean up Svelte Testing
  Library state and restore real timers after each test.
- Removed the desktop setup's fake-timer-sensitive 32ms cleanup wait and
  replaced it with a real-timer zero-delay tick after timers are restored.

## Verification

| Command | Result |
|---------|--------|
| `cd apps/svelte-admin && bun run check` | PASS, 0 errors, 0 warnings |
| `cd apps/svelte-admin && bun run test:unit` | PASS, 24 files, 279 tests |
| `cd apps/svelte-admin && bun run build` | PASS |
| `cd apps/svelte-desktop && bun run check` | PASS, 0 errors, 0 warnings |
| `cd apps/svelte-desktop && bun run test:unit` | PASS, 30 files, 368 tests |
| `cd apps/svelte-desktop && bun run build` | PASS |
| `cd apps/tauri/src-tauri && cargo check` | PASS |

## Notes

This task deliberately changed only test harness configuration and setup code.
No frontend source component, style, asset, animation, route, or copy was
modified.
