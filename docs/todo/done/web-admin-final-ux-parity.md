---
description: Final UX and parity sweep for web-admin before manual E2E.
---

# Web Admin Final UX + Parity Sweep

## Context
Before manual UI testing, complete remaining UX consistency items and prevent double-submit on sensitive actions.

## Desired Outcome
Actions have safe loading/disabled states, labels match server semantics, and UX messaging is consistent across views.

## Scope
- Header actions (reload, shutdown).
- Client actions (kick, block, unblock).
- QKey generation error handling for empty responses.
- Label alignment for server semantics.

## Dependencies
- Legacy Dioxus sources live under `archive/unused code/apps-web-admin-dioxus/`:
  - `archive/unused code/apps-web-admin-dioxus/src/app.rs`
  - `archive/unused code/apps-web-admin-dioxus/src/views/clients.rs`
  - `archive/unused code/apps-web-admin-dioxus/src/components/header.rs`
  - `archive/unused code/apps-web-admin-dioxus/src/views/qkey.rs`
  - `archive/unused code/apps-web-admin-dioxus/assets/styles.css`

## Work Items
- [x] Add loading/disabled states for reload and shutdown actions.
- [x] Add loading/disabled states for kick/block/unblock to avoid double-submit.
- [x] Treat empty QKey responses as errors with toast and inline error.
- [x] Align header label from "Stop" to "Shutdown".

## Acceptance Criteria
- No action can be triggered twice while an API call is in-flight.
- Labels reflect server semantics ("Shutdown").
- QKey errors are surfaced when the backend returns an empty key.

## Status
- Complete. OK 2026-01-31
