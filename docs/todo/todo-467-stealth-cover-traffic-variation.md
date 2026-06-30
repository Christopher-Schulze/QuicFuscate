---
id: TODO-467
title: Randomized cover traffic and server-push variation
severity: HIGH
phase: K
priority: P1
status: DONE
created: 2026-06-30
depends_on:
  - TODO-466
---

# TODO-467: Randomized cover traffic and server-push variation

## Goal

Keep cover traffic useful while removing deterministic patterns. Server Push cover must vary by
persona, escalation level, resource plan, timing, payload sizes, MIME mix, and burst shape.

## Current State

- Cover PINGs, cover stream injection, and Server Push Cover Traffic exist.
- Server Push cover is valuable as an H3-level signal, but deterministic push plans are fingerprintable.
- Modern browser reality makes HTTP/3 Server Push uncommon, so it must not be a loud default.

## Problem

A static server-push resource list or fixed burst interval is easy to learn and classify. Cover
traffic that repeats perfectly can make the tunnel more identifiable than no cover traffic.

## Implementation Plan

1. Read the H3 server push generation signatures and event flow before editing.
2. Add a cover-plan generator with bounded randomness:
   - resource count range per mode/escalation level;
   - randomized order;
   - realistic MIME mix by persona;
   - varied path names and base paths;
   - varied payload sizes within strict bandwidth caps;
   - cache-control/header variation consistent with the persona;
   - jittered burst interval.
3. Gate Server Push cover by mode:
   - Performance: off;
   - Intelligent level 0: off or near-zero;
   - Stealth: rare/light randomized bursts;
   - Anti-DPI/escalated Intelligent: stronger randomized bursts.
4. Keep cover PING and cover stream injection coordinated with server-push bursts to avoid obvious
   periodic stacks.
5. Add deterministic-seed test hooks if needed, but no production determinism.
6. Add tests proving variation while preserving bounds.

## Files To Inspect

- `src/transport/h3.rs`
- `src/stealth/mod.rs`
- `src/stealth/tests.rs`
- `src/core.rs`
- `src/brain.rs`
- `src/optimize/telemetry.rs`

## Acceptance Criteria

- Server Push cover no longer emits the same resource plan every burst.
- Variation is bounded and testable: no unbounded bandwidth spikes, no invalid H3 events, no invalid
  headers.
- Mode defaults match TODO-466.
- Tests prove:
  - repeated bursts vary under normal randomness;
  - generated payload sizes remain inside configured caps;
  - disabled modes emit no server-push cover;
  - escalation increases cover intensity without changing persona identity.

## Implementation Result

- `src/transport/h3.rs` now builds seed-varied server-push resource plans with bounded count, path selection, and size jitter.
- `StealthManager::server_push_cover_active` remains the single owner that suppresses the regular cover scheduler while server-push cover is active.
- Focused tests: `stealth_cover_resource_plan_varies_by_seed_with_bounds` plus existing server-push state tests.

## Non-Goals

- Do not delete Server Push cover.
- Do not make Server Push a universal default.
- Do not change UI.
