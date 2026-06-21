---
description: Replace web-admin loading spinners with a minimal, non-distracting indicator.
---

# Web Admin Loading Indicator

## Context
The current ring spinner is visually noisy and distracts from core data. Replace it with a minimal indicator that never overwhelms the page.

## Desired Outcome
All loading states use a consistent 3-dot pulse indicator that is subtle, compact, and never scales to large arcs or rings.

## Scope
- Web-admin UI loading states for dashboard, clients, config, metrics, logs, and keys.
- Shared loading component and CSS.

## Dependencies
- Legacy Dioxus sources live under `archive/unused code/apps-web-admin-dioxus/`:
  - `archive/unused code/apps-web-admin-dioxus/src/components/loading.rs`
  - `archive/unused code/apps-web-admin-dioxus/src/views/*.rs`
  - `archive/unused code/apps-web-admin-dioxus/assets/styles.css`
- `scripts/build-web-admin.sh`

## Work Items
- [x] Remove spinner ring markup from all loading states.
- [x] Implement `LoadingDots` component and wire it into views.
- [x] Add CSS for the dot pulse and remove spinner ring styles.
- [x] Rebuild assets into `assets/web-admin/`.

## Acceptance Criteria
- No circular or ring spinner is rendered anywhere.
- All loading states show the 3-dot pulse and a text label.
- Assets updated via build script without errors.

## Status
- Complete. OK 2026-01-31
