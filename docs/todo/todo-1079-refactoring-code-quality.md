---
id: TODO-1079
title: Refactoring and code-quality cluster
severity: LOW
phase: S
priority: P3
status: OPEN
created: 2026-09-22
depends_on: [TODO-1071]
---

# TODO-1079: Refactoring and code quality

## Why

Sustained velocity needs the codebase to stay legible. This cluster is the
home for structural cleanups that pay for themselves: clearer module
boundaries, correct feature gates, dead-path removal, shared abstractions
where duplication is proven — never cosmetic churn.

## Scope

- Module clarity: oversized files split along existing ownership seams
  (e.g. `connection/api.rs` growth), pub-surface tightening.
- Feature-gate correctness: the TODO-1070 class of bugs (unconditional code
  calling gated items) — audit other `cfg`-adjacent call sites systematically.
- Dead-path removal: unreachable config surfaces, write-only selectors
  (TODO-1069 pattern), stale compat shims (TODO-910 overlap).
- Shared abstractions: extract only where ≥2 real consumers exist.

## Non-goals

- No style-only rewrites, no mass reformatting, no renames-for-taste.
- No behavior change bundled inside a refactor commit.

## Hard gate

- A refactor lands only with: the behavior test suite green AND a TODO-1071
  baseline showing no dataplane regression where the path is hot.
- Each refactor maps all affected usages first (per AGENTS §14).

## Acceptance

- [ ] Refactor list populated with concrete targets and the proof each needs.
- [ ] Each landed refactor: green suite + no measured regression + docs
      flushed in the same commit.

## Rollback

Independent commits; revert anything that regresses or breaks consumers.
