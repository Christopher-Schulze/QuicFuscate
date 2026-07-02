---
id: TODO-508
title: Canonical docs SSOT cleanup after retiring local worklog files
severity: HIGH
phase: S
priority: P0
status: OPEN
created: 2026-07-02
depends_on: [TODO-472, TODO-507]
---

# TODO-508: Canonical Docs SSOT Cleanup After Retiring Local Worklog Files

## Context

The repository retired the local ignored worklog files. Durable project truth
must now live only in tracked owning docs:

- `docs/DOCUMENTATION.md` for architecture, runtime behavior, configuration,
  operator guidance, and release truth.
- `docs/todo.md` for task index and production-readiness state.
- `docs/todo/*.md` for task-specific acceptance, plans, evidence, and
  deviations.
- `docs/MAP.md` for repository map and wiring truth.
- `README.md` for public entry-point truth.
- `AGENTS.md` for repo-local agent behavior.

There are currently uncommitted documentation edits from the worklog-retirement
pass. They must be either completed and committed or explicitly reverted before
any production-ready claim.

## Desired Outcome

- No tracked docs reference retired local worklog files or require them for
  future agent operation.
- Current release checkpoint, GitHub green runs, stable Rust policy, Docker
  scope, NAT traversal policy, and production-readiness gaps agree across
  `README.md`, `docs/DOCUMENTATION.md`, `docs/todo.md`, `docs/MAP.md`,
  `docs/CONTRIBUTING.md`, and `AGENTS.md`.
- Historical TODO detail files do not instruct future agents to write removed
  files.
- All documentation changes are committed in one focused docs commit.

## Implementation Plan

1. Inspect the uncommitted docs diff with `git diff --stat`, `git diff --name-only`,
   and focused per-file diff review.
2. Scan tracked docs for retired local worklog references using the exact
   retired filenames from `.gitignore`, without reintroducing those names into
   docs.
3. Scan tracked docs/config for old Rust/toolchain pins:
   - `rust:1.85`
   - `rust:1.93`
   - `1.93.0`
   - `1.93.1`
   - `channel = "1.93`
   - `rust-version = "1.93`
4. Scan tracked docs/config for stale manifest surface wording that must no
   longer appear as active repo truth.
5. Update `docs/DOCUMENTATION.md` release checkpoint to the latest green pushed
   commit and GitHub run IDs.
6. Update `docs/todo.md` current-state header with TODO-508 through TODO-514.
7. Update `docs/MAP.md`, `docs/CONTRIBUTING.md`, and `AGENTS.md` so they only
   point to tracked owning docs.
8. Run `bash scripts/tests/audits/audit-todo-consistency.sh`.
9. Run `git diff --check`.
10. Commit with a focused docs message and push.
11. Poll GitHub `CI`, `Clippy Matrix`, and `Release Build` for the pushed commit.

## Acceptance Criteria

- The retired local worklog reference scan over tracked docs/config returns no
  active references.
- Old Rust/toolchain pin scan returns no output.
- Stale manifest wording scan returns no output for active docs/config.
- `bash scripts/tests/audits/audit-todo-consistency.sh` passes.
- `git diff --check` passes before commit.
- Working tree is clean after commit and push.
- GitHub `CI`, `Clippy Matrix`, and `Release Build` are green for the docs commit.

## Verification Commands

| Command | Expected Result |
|---------|-----------------|
| `git status -sb` | clean after commit |
| retired local worklog reference scan over tracked docs/config | no output |
| `rg -n 'rust:1\\.85|rust:1\\.93|1\\.93\\.0|1\\.93\\.1|channel = "1\\.93|rust-version = "1\\.93|rust-version = "1\\.85' README.md docs AGENTS.md .github Cargo.toml rust-toolchain.toml Dockerfile docker-compose.yml .dockerignore` | no output |
| `bash scripts/tests/audits/audit-todo-consistency.sh` | PASS |
| `git diff --check` | PASS |
| `gh run list --branch main --limit 3` | latest three release gates success |

## Non-Goals

- Do not modify UI source, styles, assets, screenshots, animations, routes, or
  frontend behavior.
- Do not recreate retired local worklog files.
- Do not run Docker locally.
- Do not rewrite historical docs wholesale; apply surgical consistency edits.
