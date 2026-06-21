# TODO-191: Svelte Cutover and React Retirement

## Status
**COMPLETED**

## Severity
**CRITICAL**

## Context
The repository currently carries two frontend generations:

  - React reference apps in `archive/apps/web-admin-ui/` and `archive/apps/desktop/src/`
- Svelte rebuilds in `apps/svelte-admin/` and `apps/svelte-desktop/`

The forensic audit found that the Svelte apps were not yet the canonical integrated product path. CI, local runtime scripts, deployment scripts, documentation, and shipped web assets initially still pointed at the React apps. The cutover is now complete and the React source trees have been archived out of the live workflow.

## Root Cause
The Svelte rebuild was developed as a parallel replacement track, and the final cutover from "reference" to "authoritative" is now completed across version control, scripts, CI, deployment, and documentation.

## Fix Plan
1. Make the Svelte workspace state canonical and track it cleanly in git.
2. Remove React apps from all active build, serve, CI, and test workflows.
3. Archive the historical React code outside the live product tree.
4. Replace all references to React app paths in scripts, docs, and validation commands.
5. Ensure `assets/web-admin/` is produced from the Svelte admin build only.
6. Remove stale frontend duplication in repository maps and top-level guidance.

## Acceptance Criteria
- `apps/svelte-admin/` and `apps/svelte-desktop/` are the only live frontend app paths used by the repository workflow.
- No CI job, local run script, or release script builds React apps.
- No canonical document presents React as the active frontend implementation.
- React paths are explicitly archived outside the normal product workflow.
- `git status` no longer shows the Svelte workspace as an untracked parallel universe.
- The historical React sources are archived under `archive/` and are no longer part of the live workflow.

## Dependencies
- TODO-192 for pipeline/build truth
- TODO-195 for documentation truth cleanup
- TODO-197 for Svelte-only test coverage

## Affected Files
- `.github/workflows/ci.yml`
- `scripts/build/build-web-admin.sh`
- `scripts/utils/util-run-local-admin-web.sh`
- `scripts/utils/util-run-local-ui.sh`
- `README.md`
- `docs/DOCUMENTATION.md`
- `docs/MAP.md`
- `docs/todo.md`
- `archive/apps/web-admin-ui/`
- `archive/apps/desktop/src/`
- `apps/svelte-admin/`
- `apps/svelte-desktop/`
- `assets/web-admin/`

## Progress Notes (2026-03-16)
- Active workflow ownership has started moving to Svelte:
  - frontend CI now installs/checks the Svelte apps
  - local launcher/dev scripts now point to Svelte app paths
  - the web-admin publish script now builds `apps/svelte-admin`
- Active workflow truth is now closed:
  - canonical docs and verification commands point to the Svelte apps
  - Svelte admin and desktop Playwright suites are green on the package-owned paths
  - `apps/tauri` now validates as the native Tauri host around `apps/svelte-desktop`
- Remaining in this TODO:
  - decide whether the historical React source trees are deleted, archived, or retained as non-authoritative reference code outside the live workflow

## Progress Notes (2026-03-17)
- Additional post-cutover parity and hygiene sweep completed on the live Svelte path:
  - desktop selected-tunnel `Set QKey` / `Change QKey` flow is now wired and validated
  - desktop keyboard shortcuts and fatal-error recovery shell behavior are restored on the Svelte path
  - residual ripple/interactivity drift across sidebar/settings/error surfaces was closed
  - stray source artifact `apps/svelte-admin/src/lib/components/.DS_Store` was removed
- React retirement/archive was completed by archiving the historical React source trees under `archive/` and removing them from the live workflow.
