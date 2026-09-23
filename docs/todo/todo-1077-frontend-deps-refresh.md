---
id: TODO-1077
title: Frontend technical refresh (dependencies only)
severity: LOW
phase: S
priority: P3
status: OPEN
created: 2026-09-22
depends_on: []
---

# TODO-1077: Frontend dependency refresh

## Why

The operator asked for a *maximal* technical update of the frontend - current
stable dependencies, nothing more. No redesign, no feature work. TODO-805 and
TODO-749 left advisory/lockfile history; this refresh supersedes the stale
parts of both. The current repository is a root Bun workspace with one tracked
`bun.lock`; `apps/svelte-admin`, `apps/svelte-desktop`, and `packages/*` share
that resolution. `apps/tauri/src-tauri/Cargo.lock` is a separate Rust owner.

## Scope

- Root Bun workspace: inventory direct and transitive dependencies of both
  Svelte apps and shared packages, including root `package.json` overrides;
  update manifests and the one root `bun.lock` together. Keep the existing
  Bun runtime and package manager; do not introduce npm lockfiles.
- `apps/tauri/src-tauri`: update the compatible Tauri 2/plugin/Cargo dependency
  set and its own `Cargo.lock` together; verify JS and Rust plugin version
  compatibility before changing one side. Preserve the existing Specta
  release-candidate pins until a compatible replacement is proven.
- Existing checks must stay green: frontend tests, type-check, the
  request-coordinator/generation logic tests, production builds, and Tauri
  host compilation. Browser E2E gates run when a changed package affects
  browser/runtime behavior or the release gate requires them.

## Non-goals

- No new features, no UX changes, no visual redesign.
- No framework migration (Svelte/Tauri stay).
- No dependency swaps for novelty's sake — version currency only.

## Methodology

- Run read-only root `bun outdated --recursive`, `bun audit --json`, and the
  existing frontend dependency validator before edits; inspect the two Cargo
  manifests/locks and the existing Rust advisory gate. Record exact current
  and target versions only after registry and upstream compatibility checks.
- Upgrade one compatible dependency cluster at a time through Bun workspace
  manifests and root lockfile. Validate with `bun install --frozen-lockfile`
  after each committed resolution. Upgrade Rust Tauri/plugin dependencies in
  the app lockfile with the paired JS package contract checked.
- Run both app unit suites, `bun run check`, and `bun run build`; run
  Playwright E2E if browser-visible dependencies changed. Run Tauri host
  `cargo check`, focused Rust tests, the repository dependency-security gate,
  and relevant native target checks before calling the update complete.
- Reconcile every advisory as fixed, blocked by an incompatible dependency,
  or accepted with an exact unreachable-surface proof. Do not use a blanket
  ignore or upgrade major versions without testing their real integration.

## Acceptance

- [ ] Direct and transitive before/after versions, Bun root-lock and Tauri
      app-lock deltas, plugin compatibility, and advisory dispositions are
      recorded with exact source links and commands.
- [ ] Both apps' unit, typecheck, and production-build gates pass; relevant
      browser E2E and Tauri Rust/native gates pass or retain an explicit
      platform blocker. No npm lockfile or second Bun lockfile is created.
- [ ] `bun install --frozen-lockfile` and the repository dependency-security
      validator pass; no unreviewed advisory or stale override remains.

## Risks

- Major-version bumps can cascade — stop at the tier that breaks and record
  the blocker instead of rewriting the app around a library.
