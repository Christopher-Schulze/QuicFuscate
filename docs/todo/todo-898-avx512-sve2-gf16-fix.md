---
id: TODO-898
title: Fix AVX512 and SVE2 GF16 carry-less reduction
severity: MEDIUM
phase: S
priority: P1
status: DONE
created: 2026-08-21
depends_on: []
---

# TODO-898: Fix AVX512 and SVE2 GF16 Carry-less Reduction

## Objective
Fix mathematically incorrect GF(16) carry-less reduction that is currently dormant but will corrupt future AVX512 dispatch.

## Verified Evidence
- `crates/qf-simd/src/galois.rs:417-419` single fold vs 4 folds (documented 200 lines later and fixed in SSE path).
- `crates/qf-fec/src/gf16.rs:360-362` uses integer mul instead of carry-less and constant `0x000B` vs `0x100B`.
- Grep verified no production caller currently (landmine), but future dispatch would silently corrupt.

## Acceptance
- AVX512 path does 4 folds as SSE does, test proves single fold is wrong.
- SVE2 kernel uses carry-less + `0x100B`.
- `cargo test -p qf-simd --features rust-tests` gf tests green.

## Out of Scope
- No GF(256) change.

## Deviations
- Miri verification attempted on nightly `aarch64-apple-darwin` with `-Zmiri-disable-isolation`. The GF16 PCLMUL differential tests (`a_single_fold_is_insufficient...`, `pclmul_reduction_matches_the_scalar_field...`) passed with **0 UB findings** before the exhaustive scalar-field comparison exceeded the 900s interpretation timeout. Miri on the AEGIS AES-block path is **platform-blocked**: `crates/qf-cpu/src/feature_detection.rs:318` calls `sysctl` via `posix_spawn` on macOS which Miri cannot emulate. Full Miri coverage requires a Linux nightly host. Commit `c51c5e3`.
