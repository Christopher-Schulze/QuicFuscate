# TODO-201: Active Svelte Workspace Source Tracking and Workspace Manifest Truth

## Status
**COMPLETED**

## Severity
**CRITICAL**

## Context
The active Svelte admin, Svelte desktop, shared packages, root workspace manifest, and related helper files are part of the real local product path, yet they were not fully represented in the local Git index. This breaks repository truth and makes the workspace depend on hidden local content.

## Objective
Make the Svelte-first workspace explicit and fully tracked in the local repository state.

## Scope
- Root workspace files: `package.json`, `bun.lock`, `justfile`, and related support files.
- Svelte apps: `apps/svelte-admin` and `apps/svelte-desktop`.
- Shared packages: `packages/ui` and `packages/theme`.
- Newly introduced workflow files that the Svelte path depends on.

## Detailed Work Plan
1. Enumerate all active workspace-owned files.
2. Confirm which ones are currently missing from the index.
3. Stage the workspace manifests and lockfiles first.
4. Stage both Svelte apps and shared packages.
5. Verify that active CI, scripts, and docs refer only to locally tracked workspace content.

## Tracking Checklist
- [x] Root workspace manifests staged.
- [x] `apps/svelte-admin` staged.
- [x] `apps/svelte-desktop` staged.
- [x] `packages/ui` staged.
- [x] `packages/theme` staged.
- [x] Workspace truth cross-checked against CI and scripts.

## Acceptance Criteria
- `git ls-files` returns the active workspace paths.
- No active Svelte app or shared package remains outside the local index.
- The active workspace manifests match the real local workflow.

## Dependencies
- TODO-200
- TODO-215

## Affected Files
- `package.json`
- `bun.lock`
- `justfile`
- `apps/svelte-admin/**`
- `apps/svelte-desktop/**`
- `packages/ui/**`
- `packages/theme/**`
