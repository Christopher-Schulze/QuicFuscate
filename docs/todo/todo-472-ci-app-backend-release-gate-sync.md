---
id: TODO-472
title: CI app backend release gate synchronization
severity: HIGH
phase: R
priority: P0
status: DONE
created: 2026-06-30
depends_on:
  - TODO-215
  - TODO-217
---

# TODO-472: CI app backend release gate synchronization

## Goal

Keep repository documentation, README release guidance, and GitHub CI truth aligned with the
current production-readiness checkpoint after the app backend gate was added and verified.

## Current State

- The last fully verified release checkpoint before this documentation sync is `09cb9f2`
  (`fix: stabilize CI and app backend gates`).
- GitHub `CI` run `28461670844`, `Clippy Matrix` run `28461670906`, and `Release Build` run
  `28461670799` are green on that checkpoint.
- `.github/workflows/ci.yml` includes `app-backend-checks`, which builds the existing desktop
  Svelte bundle for Tauri context and validates `apps/tauri/src-tauri` with `cargo check` and
  `cargo test`.
- UI source, UI styles, UI assets, generated UI bundles, Docker, or deployment manifests were not
  modified for this gate.

## Problem

The live GitHub workflows were green, but the repository docs still described an older release
checkpoint, stale CI run IDs, a red Linux fastpath evidence job, and an inaccurate Windows CI
claim. That drift makes future production-readiness reviews unreliable.

## Implementation Plan

1. Update `docs/DOCUMENTATION.md` to record the current green GitHub checkpoint and app backend
   gate.
2. Update `README.md` to describe the actual Linux/macOS CI coverage and native Tauri backend
   validation.
3. Update `docs/todo.md` with the completed TODO-472 status and current-state summary.
4. Update `docs/MAP.md` so the critical wiring path inventory includes the GitHub workflow gate.
5. Verify docs-only scope, run formatting/static checks appropriate for documentation, commit, and
   push.

## Completion Criteria

- `docs/DOCUMENTATION.md` references the current `09cb9f2` checkpoint and green GitHub run IDs.
- `README.md` no longer claims Windows CI coverage that the current workflows do not provide.
- `docs/todo.md` and this detail file record TODO-472 as complete.
- No UI surfaces, frontend source files, style assets, Docker, or deployment manifest files are
  touched.
- The final commit is pushed to `origin/main`.
