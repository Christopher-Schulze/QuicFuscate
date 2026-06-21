# Web Admin (Dioxus) - Implementation Notes

> Status: Historical. The Dioxus web admin is no longer an active frontend.
> The current admin UI is React: `archive/apps/web-admin-ui/`.
> Legacy Dioxus sources are historical context only and are not part of the active frontend tree.

## Scope
- Dioxus web UI for server admin operations (status, metrics, clients, config, keys).
- HTTP admin server for JSON API + static assets.
- Build script to compile and publish the web bundle to `assets/web-admin/`.

## Delivery
- `src/implementations/server/admin_http.rs` provides HTTP admin endpoints.
- Legacy Dioxus UI references in this document are historical only.
- `scripts/build-web-admin.sh` builds the current React admin UI and publishes the static bundle.

## Features
- Dashboard (status/metrics).
- Clients list + kick.
- Config read/write + reload.
- QKey generation.

## Notes
- The archived Dioxus UI requires building the Dioxus bundle before use (historical only).
- Static assets are served from `assets/web-admin/` by default.
 - Canonical API responses use `AdminResponse` envelope for all JSON endpoints.
 - `/api/qkey` is POST-only and returns `{qkey}` in `data`.

## Hardening Plans
- Build audit: `docs/todo/web-admin-build-fixes.md`
- API contract coverage: `docs/todo/web-admin-api-coverage.md`
- Desktop parity mapping: `docs/todo/web-admin-desktop-parity.md`
- UX state model: `docs/todo/web-admin-ux-integration.md`
- UI polish + responsiveness: `docs/todo/web-admin-ui-polish.md`
- Security hardening: `docs/todo/web-admin-security-hardening.md`
- Linux ops readiness: `docs/todo/web-admin-linux-ops.md`
- Test plan: `docs/todo/web-admin-test-plan.md`
- Implementation backlog: `docs/todo/web-admin-implementation-backlog.md`
- E2E validation matrix: `docs/todo/web-admin-e2e.md`
