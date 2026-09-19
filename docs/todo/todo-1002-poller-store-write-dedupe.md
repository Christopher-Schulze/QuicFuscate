# TODO-1002 — Dedupe engine-poller store writes (render churn + e2e stability)

## Status

DONE — 2026-09-19.

## Context

The desktop bridge polls the engine on three intervals in `startEnginePollers`
(`apps/svelte-desktop/src/lib/stores/tauri-bridge.svelte.ts`):

- `pollStatus` every 500 ms — rebuilt `setTunnelStates(next)` as a fresh object
  on every tick.
- `pollStats` every 900 ms — rebuilt the per-tunnel stats entry and the
  throughput record (`setThroughput`) unconditionally.
- `pollLogs` every 350 ms — already deduped (early return on empty responses).

Svelte `$state` dedupes primitive writes but always notifies on object writes,
so ~3 store notifications per second re-rendered every subscriber even when the
polled values were identical. `TunnelList` subscribes to tunnel state and the
bits-ui `Dialog.Portal` re-mounts its content on those re-render cycles, which
replays the `animate-in zoom-in-95` entrance animation. In Playwright the click
actionability check (same bounding box across two frames) therefore raced the
500 ms remount loop: `element is not stable` / `element was detached from the
DOM` until the 60 s timeout expired. This was the recurring
`full-ui.pw.ts` "create tunnel" flake (~50% of CI runs, unrelated to the code
under test).

## Change

Write-site dedupe inside the bridge (store layer untouched):

- `flatRecordEqual` guards `setTunnelStates(next)` against the current map.
- `tunnelStatsEqual` (+ `hopStatsEqual`) guards `updateTunnelStats` against the
  existing per-tunnel entry — field-wise compare including `hops`.
- `throughputRecordEqual` guards `setThroughput` per `{downBps, upBps}` entry.
- `setActiveTunnelId` needs no guard (primitive; Svelte dedupes already).
- `pollLogs` keeps its existing early-return dedupe.

Semantics preserved: writes still land whenever any value changes; only
identical-payload ticks are skipped. In production this removes ~3 render-tree
patches per second while idle; in browser/e2e mode the render tree goes fully
idle between real events.

## Verification

- New unit test `does not rewrite stores when polled values are unchanged`
  asserts object-identity stability (`toBe`) across 3 s of identical poll
  payloads after the first write.
- `tauri-bridge-polling.test.ts`: 6/6 green.
- Full desktop unit suite: 38 files / 454 tests green; `svelte-check` 0/0.
- frontend-e2e flake remediation verified by CI (browser-mode stores stay
  identical-valued under the mock engine, so no portal remount loop).

## Files

- `apps/svelte-desktop/src/lib/stores/tauri-bridge.svelte.ts`
- `scripts/tests/frontend/desktop/unit/src/tauri-bridge-polling.test.ts`
