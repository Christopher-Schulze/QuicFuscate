---
id: TODO-556
title: Migrate GitHub Actions off deprecated Node.js 20 runtimes
severity: HIGH
phase: S
priority: P0
status: DONE
created: 2026-07-23
resolved: 2026-07-25
depends_on: []
---

# TODO-556: Migrate GitHub Actions off Deprecated Node.js 20 Runtimes

## Why

Exact-commit GitHub runs for `f7af807` report that `actions/checkout@v4`, `actions/cache@v4`, and `actions/upload-artifact@v4` still target deprecated Node.js 20 and are being forced onto Node.js 24 by the runner. The warning spans CI, Clippy Matrix, and release workflows. Forced compatibility is not a durable production gate.

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
- Native gate: exact-commit CI, Clippy Matrix, and required Release Build jobs pass without any Node.js 20 deprecation annotation.
- Artifact gate: server bundles, adjacent checksums, signed Windows MSI/updater files, caches, and uploaded diagnostics retain their exact contracts.
- Truth gate: exact commit, run IDs, action versions, official migration references, artifact evidence, protected UI diff, and MAP/TODO truth are documented before closure.

## Sub-Tasks

- [x] Inventory all workflow action references and their runtime warnings.
- [x] Verify supported replacements from official action sources.
- [x] Apply one consistent version migration across all workflows.
- [x] Run static, native, artifact, and annotation-free regression gates.
- [x] Flush documentation and close only with exact evidence.

## Notes

- The exact runner annotation names `actions/checkout@v4`, `actions/cache@v4`, and `actions/upload-artifact@v4` and states that their Node.js 20 runtime is deprecated and currently forced onto Node.js 24.
- Current affected workflow owners are `.github/workflows/ci.yml`, `.github/workflows/clippy-matrix.yml`, and `.github/workflows/release.yml`.
- Do not guess replacement majors from warning text. Official action repositories and release notes own the migration contract.
- Exact first-party inventory before migration: 20 `actions/checkout@v4` references, nine `actions/cache@v4` references, 12 `actions/upload-artifact@v4` references, and one `actions/download-artifact@v4` reference across the four workflow owners. Third-party setup references remain unchanged because the reported runtime defect and this task's first-party ownership boundary do not include them.
- Official releases current on 2026-07-25 select `actions/checkout@v7` (`v7.0.1`), `actions/cache@v6` (`v6.1.0`), `actions/upload-artifact@v7` (`v7.0.1`), and `actions/download-artifact@v8` (`v8.0.1`). Their official `action.yml` manifests all declare `runs.using: node24`.
- The selected manifests retain every used contract: checkout `submodules` and `fetch-depth`; cache `path`, `key`, and `restore-keys`; upload `name`, `path`, and `if-no-files-found`; download `path` plus default per-artifact extraction. No workflow permissions, cache key, artifact name, artifact path, missing-file policy, dependency edge, or release publication condition changed.
- Official migration sources: `https://github.com/actions/checkout/releases/tag/v7.0.1`, `https://github.com/actions/cache/releases/tag/v6.1.0`, `https://github.com/actions/upload-artifact/releases/tag/v7.0.1`, and `https://github.com/actions/download-artifact/releases/tag/v8.0.1`.
- Owner direction on 2026-07-25 removed the unsupported container image, Compose, and image-validation workflow surface from repository scope. Those files and their retired TODO records are deleted rather than retained as a release gate.
- Closure commit `06e60435604678bc0f7c47c633d557496654a4d8` passes CI run `30156460437`, Clippy Matrix run `30156460410`, and Release Build run `30156460404`. All 29 exact-commit check runs are successful or intentionally skipped and report zero annotations.
- The final tracked first-party inventory is 19 `actions/checkout@v7`, nine `actions/cache@v6`, 12 `actions/upload-artifact@v7`, and one `actions/download-artifact@v8` reference across the three retained workflow owners.
- Release artifact IDs are `8619280592` (Windows), `8619261608` (macOS), `8619231397` (Linux desktop), `8619153686` (ARM64 server), `8619153072` (checksums), `8619152997` (Linux binary), and `8619152872` (x86_64 server).
- Exact SHA-256 evidence: x86_64 server bundle `b9748c28be49f2621c3a5b67d19912710c69165b40b64a4f505f722c4ebba206`; ARM64 server bundle `31a966a6ce42be3adbb8e31d8f5bb9c16100a5d23be9b2dd8f6177f79cf2c727`; Linux binary `b2c93bb33970c4b61e285d635cc5e20a7dd027ff96f3eef9799b788d36f3af2c`; signed Windows MSI `a6b7c4cca7aec9ea56175997b9f9c76b5e2ba8cc784061f62aa031a873d17d5c`.
- Both server archives retain the expected binary, installer, service, default configuration, and bundled admin assets. Windows MSI, macOS DMG/app archive, Linux DEB/AppImage, updater signatures, adjacent server checksums, and checksum signature are present and non-empty. Protected UI source and asset paths have zero diff.

## Deviations

None.
