---
id: TODO-1001
title: Decide fate of benchmark-only SIMD sort/shuffle surface
severity: LOW
phase: S
priority: P3
status: OPEN
created: 2026-11-18
depends_on: []
---

# TODO-1001: Decide Fate of Benchmark-Only SIMD Sort/Shuffle Surface

## Verified Evidence
`ci_regression` benches `sort_simd` (`sort_u32`) and `shuffle_simd`
(`optimize::random::shuffle`) on every run, but a full-workspace caller sweep
finds zero non-test, non-bench callers:

- `qf_cpu::sort::{argsort, sort_f32, sort_u32}` - re-exported via
  `src/optimize/sort.rs`, used only by its own unit tests.
- `optimize::random::shuffle` - `data.shuffle(rng)` wrapper, no callers.

The code carries SIMD/unsafe weight (qf-cpu sort kernels) that TODO-681's
unsafe-audit budget has to justify, plus perpetual benchmark runtime for a
metric that guards a path no production code exercises.

## Options
1. Delete the orphans + their bench groups (smallest audit surface; the
   decision rule is "no caller" which is already proven).
2. Keep as sanctioned public utility surface and mark the bench groups as
   library-quality gates rather than regression guards.

Option 1 is the default recommendation: re-adding a sort helper later is
trivial, while every CI run pays for it now.

## Acceptance
- Either the functions and their `sort_simd`/`shuffle_simd` bench groups are
  removed, or a doc note pins them as intentional public API.
- `cargo bench --bench ci_regression --features benches` and `cargo test`
  remain green.

## Deviations
Recorded as OPEN decision item instead of deleting public API unilaterally.
