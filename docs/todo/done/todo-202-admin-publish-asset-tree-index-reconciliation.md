# TODO-202: Admin Publish Asset Tree Index Reconciliation

## Status
**COMPLETED**

## Severity
**CRITICAL**

## Context
The tracked `assets/web-admin` tree still reflects the old React-era publish layout, while the current admin bundle is produced by the SvelteKit static adapter as `index.html`, `robots.txt`, and `_app/immutable/*`. The checked-in publish truth must match the active build output.

## Objective
Replace the old tracked publish tree with the current Svelte admin publish tree and make the local index match the real shipped admin bundle.

## Scope
- Remove the old React-era tracked asset entries from the local index.
- Stage the current SvelteKit static publish output.
- Keep `scripts/build/build-web-admin.sh`, docs, and local publish truth consistent.

## Detailed Work Plan
1. Build the current Svelte admin bundle.
2. Compare tracked asset paths with produced asset paths.
3. Remove outdated tracked React-era files from the index.
4. Stage the current SvelteKit output tree.
5. Re-check the publish tree against docs and build scripts.

## Tracking Checklist
- [x] Current admin bundle rebuilt.
- [x] Old tracked React asset names identified and removed from local truth.
- [x] Current `_app/immutable/*` tree staged.
- [x] `robots.txt` and `index.html` staged.
- [x] Publish tree verified against `build-web-admin.sh` and docs.

## Acceptance Criteria
- The local index no longer tracks the old React-era vendor bundle files.
- The local index tracks the current SvelteKit publish output.
- The active docs and build scripts describe the same publish tree.

## Dependencies
- TODO-200
- TODO-201
- TODO-212

## Affected Files
- `assets/web-admin/**`
- `scripts/build/build-web-admin.sh`
- `docs/DOCUMENTATION.md`
- `docs/MAP.md`
