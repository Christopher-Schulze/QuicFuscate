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

The operator asked for a *maximal* technical update of the frontend — current
stable dependencies, nothing more. No redesign, no feature work. TODO-805 and
TODO-749 left advisory/lockfile history; this refresh supersedes the stale
parts of both.

## Scope

- `apps/svelte-admin`: npm dependency bumps to current stable, lockfile
  regeneration, breaking-change fixes, `npm audit` remediation where a fix
  exists.
- `apps/tauri` (src-tauri): Cargo dependency bumps within compatible ranges,
  `cargo update` on the app lockfile, API drift fixes.
- Existing checks must stay green: frontend tests, type-check, the
  request-coordinator/generation logic tests, build.

## Non-goals

- No new features, no UX changes, no visual redesign.
- No framework migration (Svelte/Tauri stay).
- No dependency swaps for novelty's sake — version currency only.

## Methodology

- `npm outdated` + `cargo outdated`-style inventory first; bump majors only
  where the fix cost is bounded.
- Run the frontend test suite and a production build after each tier of
  bumps (patch tier, minor tier, major one-by-one).
- Advisory list reconciled: fixed, or documented why a transitive advisory
  has no exploit path here.

## Acceptance

- [ ] Dependency inventory (before/after) committed to this file.
- [ ] Tests + build green on the refreshed tree.
- [ ] Remaining advisories listed with justification.

## Risks

- Major-version bumps can cascade — stop at the tier that breaks and record
  the blocker instead of rewriting the app around a library.
