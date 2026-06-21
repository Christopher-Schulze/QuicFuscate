# TODO-245: Desktop Runtime Bugs - logCursor and throughputSamples

## Severity: MEDIUM

## Problem

Two runtime behavior issues in `apps/svelte-desktop/src/lib/stores/tauri-bridge.svelte.ts`:

### 1. logCursor Not Reset on Log Clear
- **Location**: `tauri-bridge.svelte.ts:152` (logCursor variable), line ~292 (engineLogsClear function)
- **Issue**: When `engineLogsClear()` is called, it clears the displayed logs but does NOT reset `logCursor` to 0
- **Effect**: After clearing, the next log fetch uses the old cursor value. The backend may return no logs (cursor past current position) or skip logs that were written between clear and next fetch
- **Expected**: `logCursor` should be reset to 0 when logs are cleared so the next fetch starts fresh

### 2. throughputSamples Accumulation on Tunnel Churn
- **Location**: `tauri-bridge.svelte.ts:157` (throughputSamples object), line ~217 (cleanup)
- **Issue**: `throughputSamples` is a closure-scoped object keyed by tunnel ID. There IS cleanup code (line 217: `delete throughputSamples[id]`) when a tunnel becomes inactive, but:
  - Cleanup only happens during the stats polling interval
  - If tunnels are rapidly created/deleted between poll intervals, entries accumulate
  - The object grows unbounded if tunnel IDs are never reused
- **Severity**: Minor memory leak under tunnel churn; negligible for normal usage (1-5 tunnels)

## Fix

### logCursor
1. In `engineLogsClear()`: add `logCursor = 0;` after clearing the log array
2. Add a test: clear logs -> verify next fetch returns fresh logs from position 0

### throughputSamples
3. Add immediate cleanup in tunnel delete handler (not just poll-based)
4. Or: cap `throughputSamples` object to a maximum number of entries (e.g. 100)

## Affected Files

- `apps/svelte-desktop/src/lib/stores/tauri-bridge.svelte.ts`

## Verification

- Manual test: clear logs -> new logs appear correctly
- `bun run test:unit` passes
- No memory growth visible in DevTools after repeated tunnel create/delete
