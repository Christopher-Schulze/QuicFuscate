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
- `crates/qf-instrumentation/src/lib.rs::StealthMetrics::record_mode` has no
  repository caller. Its public `mode_auto`/`mode_max` fields still name the
  removed values, recognize only three of the six canonical modes, and are
  absent from `StealthMetrics::export`. Determine whether an external API
  consumer exists; otherwise remove these dead counters and method in place.
  If an actual consumer exists, use the one canonical typed mode and export
  truthful metrics for every supported value. Do not add another policy enum.
- Consolidation audit, linked to TODO-1075's one-entry contract: inspect
  persona/QUIC/H3/outer-header configuration, Brain/Maybenot/cover scheduling,
  FEC wrapper versus QUIC-frame placement, standard versus private AEAD
  negotiation, and desktop versus standalone QKey/config derivation. For each,
  map actual call sites and wire behavior, identify the single policy owner,
  and record whether the variants are redundant implementations or necessary
  protocol/carrier differences. Delete a variant only after a behavior and
  performance comparison proves the surviving path subsumes it; route any
  behavioral fix to its owning task instead of bundling it into a refactor.
- Rust 1.98 strict all-target `cargo clippy --all-targets --features rust-tests
  -- -D warnings` currently fails on `manual_range_patterns` at
  `scripts/tests/rust/rt-qftls-profiles.rs:10`, `manual_is_multiple_of` at
  `src/brain.rs:868`, and `identity_op` at
  `src/stealth/manager/coverage_tests.rs:183`. Update these three independent
  test expressions without changing their assertions or production behavior;
  rerun the exact command and retain the existing green root-library gate.
- `cargo check --no-default-features --locked` succeeds but emits 47 root-lib
  warnings: unused imports and dead code in
  `src/implementations/server/{limits.rs,limits/blacklist.rs,limits/ddos_policy.rs,limits/geoip.rs,ddos.rs,metrics.rs,config.rs}`
  plus an unnecessary `mut` in `runtime_admin.rs`. Map each warning to its
  intended feature and actual callers; gate feature-owned exports and
  implementations consistently or remove genuinely unreachable code. Keep
  the disabled-feature build behavior and enabled-feature public surface;
  reach zero warnings on the exact no-default build, without blanket allows.

## Non-goals

- No style-only rewrites, no mass reformatting, no renames-for-taste.
- No behavior change bundled inside a refactor commit.

## Hard gate

- A refactor lands only with: the behavior test suite green AND a TODO-1071
  baseline showing no dataplane regression where the path is hot.
- Each refactor maps all affected usages first (per AGENTS §14).

## Acceptance

- [ ] Refactor list populated with concrete targets and the proof each needs.
- [ ] Each consolidation target above has a code-backed owner/consumer map,
      retain/merge/remove verdict, migration effects, and proof gate. A
      visible mode switch alone is not evidence of duplicate implementation.
- [ ] Each landed refactor: green suite + no measured regression + docs
      flushed in the same commit.
- [ ] Mode instrumentation has one evidenced consumer and complete canonical
      semantics, or its unused public counters/method are removed with all
      references and instrumentation docs updated.

## Rollback

Independent commits; revert anything that regresses or breaks consumers.
