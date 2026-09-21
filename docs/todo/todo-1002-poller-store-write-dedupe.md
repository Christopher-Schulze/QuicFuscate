---
id: TODO-1002
title: TODO-1002 — Dedupe engine-poller store writes (render churn)
status: DONE
created: 2026-09-19
---

# TODO-1002 — Dedupe engine-poller store writes (render churn)

## Status

DONE — 2026-09-19 (dedupe). E2E causal claim corrected below.

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
polled values were identical.

## Correction (2026-09-19, post-merge)

The original write-up attributed the recurring `full-ui.pw.ts` "create tunnel"
flake (`element is not stable` / `detached from the DOM` for the full 60 s) to
this churn. That attribution was wrong: `startEnginePollers` returns early on
`!isTauri()`, so in the browser-mode E2E no pollers run at all — no store
writes happen between real events, and the flake re-occurred on `5ca5dda` with
the dedupe already merged.

Revised mechanism: the "Create Tunnel" submit button lives inside a
`bits-ui` dialog with `animate-in zoom-in-95 duration-200`; its bounding box
moves during the entrance animation, and on contended CI runners Playwright's
actionability check (same bounding box across two frames) races that motion.
`expectSettledDialog` now waits for `getAnimations({subtree:true}).finished`
before interacting with dialog content, and CI uploads `test-results/` on e2e
failure for post-mortem evidence. The dedupe remains correct and valuable for
the real Tauri-mode render churn (~3 object writes/sec while idle removed);
it is simply not the E2E fix it was initially believed to be.

## Change

Write-site dedupe inside the bridge (store layer untouched):

- `flatRecordEqual` guards `setTunnelStates(next)` against the current map.
- `tunnelStatsEqual` (+ `hopStatsEqual`) guards `updateTunnelStats` against the
  existing per-tunnel entry — field-wise compare including `hops`.
- `throughputRecordEqual` guards `setThroughput` per `{downBps, upBps}` entry.
- `setActiveTunnelId` needs no guard (primitive; Svelte dedupes already).
- `pollLogs` keeps its existing early-return dedupe.

Semantics preserved: writes still land whenever any value changes; only
identical-payload ticks are skipped. In production (Tauri) this removes ~3
render-tree patches per second while idle.

## Verification

- New unit test `does not rewrite stores when polled values are unchanged`
  asserts object-identity stability (`toBe`) across 3 s of identical poll
  payloads after the first write.
- `tauri-bridge-polling.test.ts`: 6/6 green.
- Full desktop unit suite: 38 files / 454 tests green; `svelte-check` 0/0.
- E2E hardening: `expectSettledDialog` waits for dialog-subtree animations to
  finish; `full-ui.pw.ts` 15/15 green locally (Chromium v1208), including under
  6x CPU throttle where the button bbox was sampled stable across 90 rAF
  frames.

## Files

- `apps/svelte-desktop/src/lib/stores/tauri-bridge.svelte.ts`
- `scripts/tests/frontend/desktop/unit/src/tauri-bridge-polling.test.ts`
- `scripts/tests/frontend/desktop/e2e/full-ui.pw.ts` (settle-aware dialog waits)
- `.github/workflows/ci.yml` (e2e failure artifact upload)
