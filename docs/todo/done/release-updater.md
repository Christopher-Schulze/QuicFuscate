# Release Updater Integration Plan

## Goal
Integrate and validate desktop auto-update flow with strict signature verification and safe fallback behavior.

## Current Release Decision
- v1 ships as source-first open-source release.
- Updater implementation may be prepared, but updater must remain disabled in shipped v1 builds until signing is available.

## Scope
- Tauri updater plugin configuration.
- Release feed endpoint strategy.
- UI flow for update checks and installs.
- Failure handling and rollback guidance.

## Work Breakdown
- [x] Enable updater plugin integration path in desktop app.
- [x] Configure runtime enablement rule (`QUICFUSCATE_DESKTOP_UPDATER_ACTIVE`) and channel selection in desktop settings.
- [x] Add client UI states:
  - [x] No update available.
  - [x] Optional update available.
  - [x] Mandatory update (policy hook).
  - [x] Download/install progress.
  - [x] Signature failure hard block.
- [x] Add updater flow coverage via deterministic unit tests (`scripts/tests/frontend/desktop/unit/src/lib/updater.test.ts`).
- [x] Add runtime telemetry for update check, download, install, failure. (Deferred to signed-binary phase, 2026-02-12)

## Important Note
If release v1 is source-first without signed binaries, updater must remain disabled or hidden until signing keys and signed artifacts exist.

v1 implementation status:
- Updater plugin code path exists and is runtime-gated.
- Default remains disabled for source-first release.
- UI exposes policy and status, but production activation requires signed artifacts.

Verification snapshot:
- `cd apps/tauri && bun run test:unit` (includes `src/lib/updater.test.ts`) -> pass.
- `cd apps/tauri && bun run check` -> pass.
- `cargo test -p quicfuscate-desktop` -> pass.

## Acceptance Criteria
- Updater flow is deterministic and test-covered.
- Signature failures never install.
- Documentation clearly states enablement prerequisites.
