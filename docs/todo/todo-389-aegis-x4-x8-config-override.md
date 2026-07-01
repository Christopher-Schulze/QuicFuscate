---
id: TODO-389
title: Retire aegis128x4/x8 config override mapping drift
severity: HIGH
phase: A
priority: P0
status: DONE
created: 2026-06-05
---

# TODO-389: Retire `aegis128x4`/`aegis128x8` Config Override Drift

## Problem

Earlier notes treated `aegis128x4` and `aegis128x8` as public runtime config aliases. That conflicts with the narrowed forked AEAD posture: product config selects AEAD families only (`auto`, `aegis-128l`, `morus`), while `Aegis128X4` and `Aegis128X8` are internal planner-owned implementation backends.

## Acceptance

- `aegis128x4`, `aegis-128x4`, `aegis128x8`, and `aegis-128x8` are not accepted by `CryptoConfig::validate()`
- `install_data_aead_config()` does not expose distinct X4/X8 runtime override modes
- `aegis128l` remains the public AEGIS family override
- Internal X4/X8 backend tests remain covered directly through planner/backend construction
- `cargo test --features rust-tests` is green for crypto config paths

## Fix Plan

1. Remove public/runtime X4/X8 override constants from `src/crypto/mod.rs`
2. Keep X4/X8 backend coverage through direct internal tests
3. Reject X4/X8 strings at `CryptoConfig::validate()`
4. Update docs so product-level config and internal backend names cannot drift again

## Files

- `src/crypto/mod.rs`
- `src/crypto/tests.rs`
- `src/engine/config.rs`

## Notes

Superseded by the runtime guardrail contract hardening. No UI changes. No stealth behavior changes.
