---
id: TODO-363
title: "Stealth mode env var rejects "auto" despite TOML accepting it"
severity: "MODERATE"
phase: legacy
priority: legacy
status: DONE
created: 2026-03-27
backfilled: 2026-07-23
---

# TODO-363: Stealth mode env var rejects "auto" despite TOML accepting it


## Problem
`config/quicfuscate.toml` uses `[stealth] mode = "auto"` which works via serde
(the `StealthMode::Intelligent` variant has `alias = "auto"`).

However, `apply_env_overrides()` in `src/stealth/mod.rs` (approximately line 3984)
only recognizes `"dynamic"` and `"intelligent"` string values. Setting
`QUICFUSCATE_STEALTH_MODE=auto` produces a warning:
`Unknown QUICFUSCATE_STEALTH_MODE='auto'` and the override is silently ignored.

This is a consistency gap: TOML parsing and env var parsing accept different values.

## Fix Plan
1. In `apply_env_overrides()`, add `"auto"` as an accepted alias for Intelligent mode
2. Also consider adding other serde aliases (if any) for consistency
3. Add a test: set QUICFUSCATE_STEALTH_MODE=auto, verify it maps to Intelligent

## Files to Modify
- src/stealth/mod.rs
- src/stealth/tests.rs (add test)