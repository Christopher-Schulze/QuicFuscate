# Web Admin Auth + Config + QKey Cleanup

## Context
User requested session-cookie login only, no bearer token UI, consolidated configuration controls, consistent QKey prefixing, and removal of noisy loading or notification visuals.

## Objectives
- Enforce session-cookie login flow in the UI (username + password only).
- Consolidate configuration controls on the Configuration page:
  - Stealth profiles: off, performance, stealth, anti-dpi, manual, auto (intelligent).
  - FEC is on or off only.
  - Crypto is informational only and always auto-selected.
  - Transport controls: MTU, congestion control, pacing, spin bit.
  - Connection controls: 0-RTT, migration, retry.
- QKey UI consistency:
  - Always display the `QKey-` prefix (including list entries).
  - Remove redundant key generation affordances.
- UI polish:
  - Remove top-of-page notification bars.
  - Replace the current loading spinner with a minimal, stable indicator.

## Files and Surfaces
- Legacy Dioxus sources live under `archive/unused code/apps-web-admin-dioxus/`:
  - `archive/unused code/apps-web-admin-dioxus/src/app.rs`
  - `archive/unused code/apps-web-admin-dioxus/src/views/qkey.rs`
  - `archive/unused code/apps-web-admin-dioxus/src/views/stealth.rs`
  - `archive/unused code/apps-web-admin-dioxus/src/components/loading.rs`
  - `archive/unused code/apps-web-admin-dioxus/assets/styles.css`

## Plan
1. App state and QKey normalization
   - Normalize QKey values from `/api/qkeys` before display.
   - Remove the demo notification bar from the top-level layout.
2. Stealth profiles
   - Ensure the UI label reads Auto while keeping the `intelligent` value internally.
   - Keep normalization for legacy values (`auto`, `max`, `antidpi`).
3. Loading indicator
   - Replace ring spinner with a minimal dot-pulse spinner.
   - Update CSS animation and sizes for medium and large variants.
4. QKey UX
   - Verify prefix copy and remove redundant messaging.
5. Build and verify
   - Rebuild web-admin assets with `scripts/build-web-admin.sh`.
   - Manual check: login, config toggles, QKey generate + list prefix, loading state visuals.

## Acceptance Criteria
- No bearer token references in the UI, login is session-cookie based.
- Configuration page exposes all required controls in one place.
- QKeys always show `QKey-` prefix, both generated and listed.
- No top notification bars appear.
- Loading indicator is a minimal dot-pulse spinner.
- Web-admin assets rebuild successfully.

## Status
- Completed 2026-01-31.
