# TODO-200: Local Repository Truth and Staging Alignment

## Status
**COMPLETED**

## Severity
**CRITICAL**

## Context
The current local Svelte-first repository state is the working truth, but large portions of that truth still live outside the Git index. Active source, scripts, tests, shared packages, and docs must be staged locally so the repository state stops depending on unstaged or untracked workflow-critical content.

## Objective
Create a locally authoritative repository state with all currently active files staged, no accidental omissions, no GitHub push, and no commit yet.

## Scope
- Stage every active source file that the current local workflow depends on.
- Stage updated docs, scripts, tests, shared packages, and workspace manifests.
- Leave generated caches and ignored artifacts out of the index.
- End with a controlled local index that represents the actual current codebase.

## Detailed Work Plan
1. Inventory all active modified and untracked paths.
2. Classify each path as source-of-truth, generated artifact, temporary artifact, or historical content.
3. Stage all source-of-truth files and directories.
4. Confirm that no workflow-critical active path remains untracked.
5. Confirm that no ignored/generated garbage is accidentally staged.

## Tracking Checklist
- [x] Capture a full inventory of modified and untracked paths.
- [x] Stage active frontend, backend, docs, script, and test files.
- [x] Exclude generated caches and local-only runtime debris.
- [x] Verify `git status --short` shows the intended local staged truth only.
- [x] Record the final state in `docs/context.md`.

## Acceptance Criteria
- All currently active local source-of-truth files are present in the Git index.
- No workflow-critical path remains untracked.
- No commit or push is performed.
- The local worktree/index state is explicit, controlled, and reviewable.

## Dependencies
- TODO-201
- TODO-202
- TODO-203

## Affected Files
- `apps/svelte-admin/**`
- `apps/svelte-desktop/**`
- `packages/**`
- `scripts/**`
- `src/**`
- `docs/**`
- root workspace manifests and lockfiles
