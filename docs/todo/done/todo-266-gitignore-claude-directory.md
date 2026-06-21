# TODO-266: Add .claude/ Directory to .gitignore

## Severity: LOW

## Context
The `.claude/` directory on disk contains ~10+ GB of agent worktrees and session artifacts. While not currently tracked in git (no `git add`), it is also not in `.gitignore`, meaning `git status` and other git operations may scan it, and an accidental `git add .` could track it.

## Desired Outcome
- Add `.claude/` to `.gitignore`.
- Verify no `.claude/` content is currently tracked.

## Files
- `.gitignore`

## Completion Criteria
- `.claude/` is in `.gitignore`.
- `git status` no longer shows `.claude/` as untracked.
