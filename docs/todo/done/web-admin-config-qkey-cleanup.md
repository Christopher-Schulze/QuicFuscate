# Web Admin Config + QKey UX Cleanup

## Context
The web admin should expose all configuration controls in one place (Stealth, FEC, Transport, Connection), while keeping Crypto auto-selected. Stealth profiles must match the supported modes (off, performance, stealth, anti-dpi, manual, intelligent) and use the requested "Auto [Intelligent]" label. QKey management should be unambiguous, always show the QKey- prefix, and avoid duplicate generate wording.

## Desired Outcome
- Configuration page is the single control surface for Stealth, FEC, Crypto, Transport, and Connection.
- Stealth profile labels are consistent with the supported modes and map to normalized config values.
- Transport defaults align with engine defaults, with pacing and spin enabled by default.
- QKey navigation and UI text reflect QKey terminology, with a single, consistent generate action.

## Dependencies
- Legacy Dioxus sources live under `archive/unused code/apps-web-admin-dioxus/`:
  - `archive/unused code/apps-web-admin-dioxus/src/views/config.rs`
  - `archive/unused code/apps-web-admin-dioxus/src/views/stealth.rs`
  - `archive/unused code/apps-web-admin-dioxus/src/views/transport.rs`
  - `archive/unused code/apps-web-admin-dioxus/src/views/connection.rs`
  - `archive/unused code/apps-web-admin-dioxus/src/views/qkey.rs`
  - `archive/unused code/apps-web-admin-dioxus/src/components/sidebar.rs`
  - `archive/unused code/apps-web-admin-dioxus/src/app.rs`

## Completion Criteria
- No separate security sub-pages are required for Stealth/FEC/Crypto.
- Stealth select includes: Off, Performance, Stealth, Anti-DPI, Manual, Auto [Intelligent].
- Transport defaults show pacing/spin enabled unless config overrides them.
- QKey UI uses consistent labels and enforces QKey- prefix.
- Web-admin assets rebuilt to `assets/web-admin/`.

## Work Items
- [x] Normalize stealth modes and labels to match the requested profile list. OK 2026-01-31
- [x] Align transport/connection defaults with engine config defaults. OK 2026-01-31
- [x] Update QKey nav label and generate button copy for clarity. OK 2026-01-31
- [x] Rebuild web-admin assets using `scripts/build-web-admin.sh`. OK 2026-01-31
