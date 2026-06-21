---
id: TODO-421
title: Verify GitHub contributors have no Devin/Claude co-authors
severity: HIGH
phase: legacy
priority: P0
status: DONE
created: 2026-07-23
resolved: 2026-07-23
---

# TODO-421: Verify GitHub contributors — no Devin/Claude co-authors

## Problem

Requirement: Devin and Claude must never appear as GitHub contributors or co-authors in the QuicFuscate repository.

## Checks performed

1. **GitHub API contributors** (`gh api repos/Christopher-Schulze/QuicFuscate/contributors`):
   - Result: only `Christopher-Schulze`.

2. **Git history for `Co-Authored-By` lines**:
   - `git log --all --grep="Co-Authored-By"` — empty.

3. **Git history for Devin/Claude attribution**:
   - `git log --all --grep="Devin"` — empty.
   - `git log --all --grep="Claude"` — empty.
   - `git log --all --grep="Generated with"` — empty.

## Acceptance

- [x] GitHub contributors list shows only `Christopher-Schulze`.
- [x] No commit in the repository contains a Devin/Claude co-author line or AI attribution.
- [x] Future commits must keep this state (no `Co-Authored-By`, no `Generated with Devin` lines).

## Notes

The `~/.config/devin/AGENTS.md` file created earlier was removed/reverted at the user's request; project rules are kept strictly inside the project directory (`/Users/christopher/CODE/QuicFuscate/AGENTS.md`).
