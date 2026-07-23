---
id: TODO-556
title: Migrate GitHub Actions off deprecated Node.js 20 runtimes
severity: HIGH
phase: S
priority: P0
status: OPEN
created: 2026-07-23
depends_on: []
---

# TODO-556: Migrate GitHub Actions off Deprecated Node.js 20 Runtimes

## Why

Exact-commit GitHub runs for `f7af807` report that `actions/checkout@v4`, `actions/cache@v4`, and `actions/upload-artifact@v4` still target deprecated Node.js 20 and are being forced onto Node.js 24 by the runner. The warning spans CI, Clippy Matrix, Docker validation, and release workflows. Forced compatibility is not a durable production gate.

## Acceptance

- Inventory every first-party GitHub Action and version used by all repository workflows, including reusable and release-only paths.
- Select supported Node.js 24-backed action majors from official action release notes and migration guidance before editing.
- Upgrade each affected action consistently without weakening permissions, checkout depth, cache keys, artifact names, retention, missing-file behavior, signatures, or publish dependencies.
- Validate every changed input and output contract against the selected action version.
- Preserve required Linux x86_64, Linux ARM64, Windows, security, FEC, fuzz, Clippy, frontend, and release behavior.
- Keep all protected UI sources, assets, generated bundles, layouts, styling, animations, and behavior unchanged.

## Completion Gates

- Inventory gate: every workflow action reference is classified by owner, runtime, selected version, inputs, outputs, and downstream consumers.
- Static gate: workflow syntax, action-input review, TODO consistency, runtime guardrails, and repository diff integrity pass.
- Native gate: exact-commit CI, Clippy Matrix, Docker validation, and required Release Build jobs pass without any Node.js 20 deprecation annotation.
- Artifact gate: server bundles, adjacent checksums, signed Windows MSI/updater files, caches, and uploaded diagnostics retain their exact contracts.
- Truth gate: exact commit, run IDs, action versions, official migration references, artifact evidence, protected UI diff, and MAP/TODO truth are documented before closure.

## Sub-Tasks

- [ ] Inventory all workflow action references and their runtime warnings.
- [ ] Verify supported replacements from official action sources.
- [ ] Apply one consistent version migration across all workflows.
- [ ] Run static, native, artifact, and annotation-free regression gates.
- [ ] Flush documentation and close only with exact evidence.

## Notes

- The exact runner annotation names `actions/checkout@v4`, `actions/cache@v4`, and `actions/upload-artifact@v4` and states that their Node.js 20 runtime is deprecated and currently forced onto Node.js 24.
- Current affected workflow owners include `.github/workflows/ci.yml`, `.github/workflows/clippy-matrix.yml`, `.github/workflows/docker-validation.yml`, and `.github/workflows/release.yml`.
- Do not guess replacement majors from warning text. Official action repositories and release notes own the migration contract.

## Deviations

None.
