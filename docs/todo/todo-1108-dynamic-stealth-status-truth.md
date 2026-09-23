---
id: TODO-1108
title: Display dynamic stealth status without inventing performance state
severity: LOW
phase: M
priority: P2
status: OPEN
created: 2026-09-23
depends_on: [TODO-1100]
---

# TODO-1108: Truthful dynamic stealth status

## Why and evidence

`apps/svelte-desktop/src/lib/components/tunnel/TunnelStats.svelte`
sets `stealthDisplayRaw` to `performance` whenever the selected QKey
policy and `stats.stealthMode` both equal `dynamic`. The Tauri stats field
comes from `engine.active_stealth_mode()` and falls back to
`engine.stealth_mode()`. The former traverses
`ClientConnection::stealth_mode`, `QuicFuscateConnection::stealth_mode`,
and `StealthManager::mode()`, which returns `self.config.mode`. It is the
configured connection mode, not the Brain's current escalation level or
the frozen `dynamic_wire_image`. A live dynamic session is therefore
labeled `performance` even when its committed image or active repair/
Reality hints differ. The UI contains no backend evidence for that label.
The existing policy-display test deliberately passes through arbitrary
unknown strings; TODO-1100 owns canonical mode validation and migration.

## Target contract

- Display the selected and actual configured connection policy as
  `dynamic` whenever the backend reports `Dynamic`. Do not infer
  `performance` from a missing or unchanged escalation signal. Preserve
  a clear no-live-stats state rather than fabricating a runtime level.
- If the product needs an effective-activity indicator, expose only the
  already owned connection-local facts: committed wire image and Brain
  escalation/repair/Reality state, each named distinctly. Add a minimal
  typed IPC field only after checking existing telemetry; do not create a
  parallel stealth-mode enum or imply that mid-session packet shape changes.
- Apply TODO-1100's shared QKey parser before display. Historical aliases
  have canonical labels, while an invalid explicit mode is visible as an
  error, not displayed as a valid policy or silently mapped to `dynamic`.

## Implementation and proof

- [ ] Trace `TunnelStats` policy and stats inputs, Tauri `stealth_mode`,
      Engine/connection/manager mode accessors, committed `dynamic_wire_image`
      and `IntelligentLevelHints` lifecycle. Decide whether the UI needs a
      separate activity indicator or just the verified policy label.
- [ ] Remove the unconditional `dynamic -> performance` projection. If an
      activity indicator is justified, add one narrow validated status
      projection from the existing connection owner through Tauri and IPC;
      keep policy and activity fields separate and stable during reconnect.
- [ ] Add failable desktop component/IPC cases for dynamic with no stats,
      dynamic at escalation level zero and nonzero, fixed performance,
      fixed stealth, reconnection and invalid imported QKey values. Assert
      the displayed label matches source facts, not an inferred preset.
- [ ] Run the desktop typecheck/component tests and inspect the rendered
      status for each state; update product documentation only if it
      currently promises an effective live mode that the API cannot report.

## Acceptance

- Zero `dynamic` sessions are labeled `performance` solely because the
  current mode enum says `Dynamic`; any displayed live activity is backed
  by a named connection-local fact and remains correct after reconnect.
- Canonical QKey mode labels and error states match TODO-1100, and the
  desktop tests fail if the false projection is reintroduced.
