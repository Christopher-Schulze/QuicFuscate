---
id: TODO-389
title: Fix aegis128x4/x8 config override mapping
severity: HIGH
phase: A
priority: P0
status: DONE
created: 2026-06-05
---

# TODO-389: Fix `aegis128x4`/`aegis128x8` Config Override

## Problem

`install_data_aead_config()` in `src/crypto/mod.rs` maps both `aegis128x4` and `aegis128x8` to `DATA_AEAD_OVERRIDE_AEGIS_L`. Operators cannot force SIMD bulk backends via config.

## Acceptance

- `aegis128x4` sets X4 override mode
- `aegis128x8` sets X8 override mode
- `aegis128l` unchanged
- Unit test covers all three override strings
- `cargo test --features rust-tests` green for crypto config paths

## Fix Plan

1. Add `DATA_AEAD_OVERRIDE_AEGIS_X4` and `DATA_AEAD_OVERRIDE_AEGIS_X8` constants if missing
2. Fix `match` arms in `install_data_aead_config`
3. Wire override modes through `select_data_aead` / `resolve_data_aead_plan`
4. Add regression test in `crypto/mod.rs` or existing crypto tests

## Files

- `src/crypto/mod.rs`
- `src/simd.rs` (if planner needs override awareness)

## Notes

Config-only fix. No UI changes. No stealth behavior changes.
