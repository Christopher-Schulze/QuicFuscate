# Release Final Checklist

## Goal
Single operational checklist before publishing v1.

## Code and Build
- [x] `cargo check --workspace`
- [x] `cargo clippy --workspace --all-targets -- -D warnings`
- [x] `cargo test --workspace --all-targets`
- [x] `cd archive/apps/web-admin-ui && bun run check`
- [x] `cd apps/tauri && bun run check`

## Security and Hardening
- [x] Security audit plan items complete.
- [x] Threat model documented and linked.
- [x] Deployment hardening guide complete.
- [x] Probe detection validation complete.

## Desktop Product Quality
- [x] Tray UX plan complete.
- [x] Fixed window behavior verified.
- [x] Source-first strategy reflected in UI and docs.
- [x] Updater state aligns with signing availability.

## Documentation
- [x] `docs/DOCUMENTATION.md` is current and canonical.
- [x] `docs/MAP.md` reflects current architecture and wiring.
- [x] `README.md` reflects real release model (source-first if chosen).
- [x] No historical "update from previous version" language in release docs.

## Release Package
- [x] Remove transient local artifacts from release source package.
- [x] Verify scripts output paths use `scripts/out/`.
- [x] Verify no stale/dead frontend code paths in release scope.

## Signoff
- [x] Final manual smoke pass completed.
- [x] Known limitations listed explicitly.
- [x] v1 publish decision recorded.

## Last Verification Snapshot
- Date: 2026-02-12
- Status: Build/test gates are green; `archive/apps/web-admin-ui` Playwright E2E passes `56/56`; desktop and web UI checks pass; release source package helper produced clean archive; known limitations and source-first decision are documented; final manual smoke signoff is complete.
