# TODO-230: svelte-desktop Build Artifacts Committed in Git

## Severity: HIGH

## Problem

`apps/svelte-desktop/build/` contains minified SvelteKit build output (JS chunks, CSS, HTML) that is tracked in the git staging area. Build artifacts should never be committed - they bloat the repository, create merge conflicts, and are reproducible from source.

Contents found:
- `_app/immutable/nodes/*.js` (minified)
- `_app/immutable/chunks/*.js` (minified)
- `_app/immutable/assets/*.css` (minified)
- `index.html`
- `_app/version.json`

## Impact

- Repository bloat: binary/minified assets in git history
- Merge conflicts on every rebuild
- Confusion: which is source of truth, source or build output?
- Different from `assets/web-admin/` which is intentionally published for the server's `--admin-web-root`

## Fix

1. Add `apps/svelte-desktop/build/` to `.gitignore`
2. Remove from git index: `git rm -r --cached apps/svelte-desktop/build/`
3. Verify the Tauri build pipeline regenerates this directory during `tauri build`

Note: Unlike `assets/web-admin/` (which is intentionally committed as the server-embedded admin UI), the desktop build output is consumed only by the Tauri bundler at build time and should not be in version control.

## Affected Files

- `.gitignore` - add exclusion
- `apps/svelte-desktop/build/` - remove from index

## Verification

- `git status` no longer shows build/ as tracked
- `bun run build` in svelte-desktop still produces output to build/
- Tauri build still works (consumes build/ at build time)
