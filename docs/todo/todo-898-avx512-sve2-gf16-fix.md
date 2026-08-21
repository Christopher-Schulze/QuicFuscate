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
- **Miri FULL COVERAGE achieved on Omega (Linux aarch64, nightly):** after three UB-class fixes (`cfg(miri)` scalar gates for the AES backend, the MORUS NEON compile-time branch at `morus.rs:498`, and `state_ops.rs` keystream/process_ad NEON paths - commits `9a11f53`, `156a943`, `7f7be58`, `531164e`), the complete qf-crypto AEGIS+MORUS suite runs clean under `-Zmiri-disable-isolation`: **33 passed, 0 failed, 0 UB findings, 8671s wall** on the 1-core host. The macOS attempt had been platform-blocked by `posix_spawn` in the CPU-brand probe; Linux has no such probe. This closes the "full Miri coverage requires a Linux nightly host" gap from this file's earlier deviation note.
