# TODO-241: Frontend README Boilerplate Replacement

## Severity: LOW

## Problem

Both frontend apps have default SvelteKit `sv create` boilerplate READMEs with zero project-specific content:

- `apps/svelte-admin/README.md` - 12 lines of generic "Everything you need to build a Svelte project"
- `apps/svelte-desktop/README.md` - 43 lines of generic template with "Creating a project", "Developing", "Building"

Neither mentions QuicFuscate, the app's purpose, setup requirements, or architecture.

## Fix

Per CLAUDE.md rules: "No Readme files across the repo!" - these should be deleted, not rewritten.

1. Delete `apps/svelte-admin/README.md`
2. Delete `apps/svelte-desktop/README.md`
3. Project documentation lives in `docs/` per convention

## Affected Files

- `apps/svelte-admin/README.md` (DELETE)
- `apps/svelte-desktop/README.md` (DELETE)

## Verification

- `bun run check` still passes (README not referenced by build)
