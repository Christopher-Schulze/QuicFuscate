---
id: TODO-379
title: "Increase test coverage for stealth/mod.rs (5496 LOC, ~7 tests/1000 LOC)"
severity: "HIGH (coverage)"
phase: legacy
priority: legacy
status: SCRAP
created: 2026-03-27
backfilled: 2026-07-23
scrap_reason: "Coverage-gap per module — replaced by single cargo-tarpaulin baseline run"
---

# TODO-379: Increase test coverage for stealth/mod.rs (5496 LOC, ~7 tests/1000 LOC)


## Problem
`src/stealth/mod.rs` is the project's core differentiator at 5496 LOC. It has 0 inline
tests and ~39 external tests across 5 files. Coverage ratio is ~7 tests/1000 LOC.

### What IS tested:
- Persona headers (rt-stealth-persona-headers.rs, 13 tests)
- Config TOML parsing (rt-stealth-config-toml.rs, 9 tests)
- Probe detection (rt-probe-detection.rs, 8 tests)
- ASCII counting (rt-stealth-ascii-count.rs, 2 tests)
- Mode matrix (integration/stealth_mode_matrix.rs, 7 tests)

### What is NOT tested:
- Traffic shaping engine (FlowShaper timing, burst control, bandwidth limits)
- TLS fingerprint mimicry (ClientHello construction, extension ordering, GREASE values)
- Protocol obfuscation (packet transformation, header rewriting)
- Intelligent mode adaptation (brain-driven policy application)
- Cover traffic injection (PING generation, stream cover data)
- Padding strategy execution (random padding, TLS-aligned padding)
- apply_env_overrides() (partial - see TODO-363)
- StealthManager lifecycle (init, update, teardown)

## Fix Plan
Target: +30-40 inline tests covering:
1. FlowShaper: timing calculations, burst window, bandwidth shaping (8 tests)
2. TLS mimicry: ClientHello field generation, extension ordering (6 tests)
3. Padding: strategy selection, size calculation, alignment (5 tests)
4. Cover traffic: injection decision, data generation, rate limiting (5 tests)
5. StealthManager: lifecycle, mode transitions, brain delta application (6 tests)
6. Config: env var overrides, invalid values, edge cases (5 tests)

## Files to Modify
- src/stealth/mod.rs (add #[cfg(test)] module)
- src/stealth/tests.rs (extend existing)