# TODO-192: Svelte Build, CI, and Release Pipeline Truth Alignment

## Status
**COMPLETED**

## Severity
**HIGH**

## Context
The actual frontend validation and release path is inconsistent:

- CI still installs and checks the React apps
- Release/build scripts still publish the React web-admin bundle into `assets/web-admin/`
- Local launcher scripts still start the React admin and React desktop preview path
- `bun run check` is currently not green across all frontend surfaces

Even if the Svelte apps are functionally closer to the target product, they are not yet the build-certified and release-certified path.

## Root Cause
The migration focused on UI reconstruction first, while build and deployment truth remained on the original React path. Type drift and unfinished Svelte validation gaps were left unresolved.

## Fix Plan
1. Make both Svelte apps pass `bun run check` and `bun run build`.
2. Switch frontend CI jobs from React paths to Svelte paths.
3. Update release/publish scripts so `assets/web-admin/` comes from Svelte admin only.
4. Update local launcher scripts to run Svelte admin and Svelte desktop paths only.
5. Remove obsolete React-specific checks, tests, and packaging assumptions.
6. Add guardrails so React paths cannot silently re-enter CI or release automation.

## Acceptance Criteria
- `apps/svelte-admin`: `bun run check` and `bun run build` are green.
- `apps/svelte-desktop`: `bun run check` and `bun run build` are green.
- Frontend CI validates Svelte apps only.
- `assets/web-admin/` is generated from the Svelte admin build.
- No active script or workflow points to the retired live React paths; retained historical references are limited to `archive/apps/web-admin-ui` and `archive/apps/desktop/src`.

## Dependencies
- TODO-191 for final React retirement decisions
- TODO-197 for updated Svelte test coverage

## Affected Files
- `.github/workflows/ci.yml`
- `scripts/build/build-web-admin.sh`
- `scripts/utils/util-run-local-admin-web.sh`
- `scripts/utils/util-run-local-ui.sh`
- `apps/svelte-admin/package.json`
- `apps/svelte-desktop/package.json`
- `apps/svelte-admin/src/**/*`
- `apps/svelte-desktop/src/**/*`
- `.gitignore`

## Progress Notes (2026-03-16)
- Completed in this pass:
  - Svelte frontend package scripts now include `test:unit`, `test:e2e`, and `serve:codex`
  - frontend CI now runs `apps/svelte-admin` and `apps/svelte-desktop`
  - added a real `frontend-e2e` CI job for the Svelte Playwright smoke path
  - `scripts/build/build-web-admin.sh` now publishes from `apps/svelte-admin/build`
  - local run/dev scripts now launch the Svelte apps
  - `apps/svelte-admin`: `bun run check`, `bun run build`, `bun run test:unit` are green
  - `apps/svelte-desktop`: `bun run check`, `bun run build`, `bun run test:unit` are green
- Closed in the final verification pass:
  - `apps/svelte-admin`: `bun run test:e2e` is green
  - `apps/svelte-desktop`: `bun run test:e2e` is green
  - `apps/tauri`: `bun run check` and `bun run build` validate the native host wrapper against `apps/svelte-desktop`
  - `apps/tauri/src-tauri`: `cargo check` is green
