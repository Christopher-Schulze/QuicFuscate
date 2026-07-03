---
id: TODO-509
title: Post-clean local release gate replay
severity: HIGH
phase: S
priority: P0
status: DONE
created: 2026-07-02
depends_on: [TODO-508]
---

# TODO-509: Post-Clean Local Release Gate Replay

## Context

`cargo clean` removed the local Rust build artifacts and freed 9.5 GiB. GitHub
is green, but a production-ready claim should also have a fresh local gate
snapshot after the clean state. This must be done without starting persistent dev
servers and without changing UI visuals.

## Desired Outcome

- Local Rust, docs, app backend, and frontend validation gates pass from a clean
  build cache state.
- Disk safety is preserved: do not start heavy builds unless the Mac has enough
  free space.
- Results are recorded in the relevant tracked docs, not local worklog files.

## Implementation Plan

1. Check disk with `df -h /` before each build-heavy step.
2. If free space would fall below the project safety threshold, stop and report
   instead of building.
3. Run formatting and docs gates:
   - `cargo fmt --all -- --check`
   - `bash scripts/tests/audits/audit-todo-consistency.sh`
   - `git diff --check`
4. Run Rust gates:
   - `cargo build --lib`
   - `cargo clippy --workspace --all-targets -- -D warnings`
   - `cargo test --workspace --all-targets --features rust-tests`
5. Run app backend and frontend non-visual gates only:
   - `cd apps/svelte-admin && bun install && bun run check && bun run test:unit`
   - `cd apps/svelte-desktop && bun install && bun run check && bun run test:unit && bun run build`
   - `cd apps/tauri/src-tauri && cargo check && cargo test`
6. Do not run persistent dev servers.
7. Document exact pass/fail results in `docs/todo.md` and this TODO detail file.

## Acceptance Criteria

- All listed commands either pass or any failure is root-caused and captured as
  a new TODO with exact logs and scope.
- No generated UI bundles, snapshots, styles, assets, or frontend source changes
  are committed as part of this gate replay.
- Local `git status -sb` remains clean or only has intentional docs updates.
- GitHub remains green after any docs update commit.

## Verification Commands

| Command | Expected Result |
|---------|-----------------|
| `df -h /` | enough free space before build/test |
| `cargo fmt --all -- --check` | PASS |
| `cargo clippy --workspace --all-targets -- -D warnings` | PASS |
| `cargo test --workspace --all-targets --features rust-tests` | PASS |
| `cd apps/svelte-admin && bun run check && bun run test:unit` | PASS |
| `cd apps/svelte-desktop && bun run check && bun run test:unit && bun run build` | PASS |
| `cd apps/tauri/src-tauri && cargo check && cargo test` | PASS |

## Non-Goals

- Do not run local Docker.
- Do not change UI source or visuals.
- Do not hide flaky tests by skipping or relaxing assertions.

## Completion Evidence (2026-07-03)

All gates run from clean build cache state on macOS (Darwin 24.6.0).

- `df -h /` before build: 2.5 GiB free (tight); after APFS purgeable reclamation: up to 26 GiB free.
- `cargo fmt --all -- --check` → PASS.
- `bash scripts/tests/audits/audit-todo-consistency.sh` → PASS (160 files, 0 violations).
- `git diff --check` → PASS.
- `cargo build --lib` → PASS (1m41s from clean).
- `cargo clippy --workspace --all-targets -- -D warnings` → PASS (with `CARGO_INCREMENTAL=0` to fit disk; first attempt hit `No space left on device` on incremental cache, cleaned and retried successfully).
- `cargo test --workspace --all-targets --features rust-tests` → PASS (0 failures across all test binaries and integration tests).
- `cd apps/svelte-admin && bun install && bun run check && bun run test:unit` → PASS: svelte-check 0 errors/0 warnings; 24 test files, 279 tests passed.
- `cd apps/svelte-desktop && bun install && bun run check && bun run test:unit && bun run build` → PASS: svelte-check 0 errors/0 warnings; 30 test files, 368 tests passed; static build written to `build/`.
- `cd apps/tauri/src-tauri && cargo check && cargo test` → PASS: 29 tests passed, 0 failed.
- No UI source, style, asset, or frontend bundle changes committed.
- Local gate evidence matches green GitHub evidence for checkpoint `f1ec566`.

