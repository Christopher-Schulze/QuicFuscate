---
id: TODO-395
title: MORUS in-place seal/open on trait path
severity: HIGH
phase: B
priority: P1
status: DONE
created: 2026-06-05
---

# TODO-395: MORUS In-Place Seal/Open on Trait Path

## Problem

MORUS SIMD paths allocate via `to_vec()` and copy back in `seal_with_u64_counter` / `open_with_u64_counter` despite `encrypt_in_place` / `decrypt_in_place` existing.

## Acceptance

- No intermediate `Vec` on MORUS seal/open hot path
- SIMD inner functions write directly into caller buffer
- Morus roundtrip + forgery tests pass
- Scalar and SIMD parity tests pass

## Fix Plan

1. Refactor `encrypt_morus1280_ssse3_inner` (and NEON/AVX paths) for in-place output
2. Wire trait methods to `encrypt_in_place` / `decrypt_in_place`
3. Run crypto differential proof suite

## Files

- `src/crypto/morus.rs`
- `src/crypto/mod.rs`
