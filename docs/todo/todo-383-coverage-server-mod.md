---
id: TODO-383
title: "Increase test coverage for implementations/server/mod.rs (4511 LOC, ~4 tests/1000 LOC)"
severity: "HIGH (coverage)"
phase: legacy
priority: legacy
status: SCRAP
created: 2026-03-27
backfilled: 2026-07-23
scrap_reason: "Coverage-gap per module — replaced by single cargo-tarpaulin baseline run"
---

# TODO-383: Increase test coverage for implementations/server/mod.rs (4511 LOC, ~4 tests/1000 LOC)


## Problem
`src/implementations/server/mod.rs` at 4511 LOC has 19 inline tests and 0 external
test files. Ratio ~4 tests/1000 LOC - the lowest among large modules.

### What IS tested (inline only):
- Basic server construction
- Accept loop
- Some routing logic

### What is NOT tested:
- Session management (creation, cleanup, limits)
- Multi-client handling
- Graceful shutdown
- QKey validation at accept time
- Rate limiting integration
- Metrics collection
- Admin API integration
- TLS certificate handling

## Fix Plan
Target: +15-20 tests:
1. Session lifecycle: create, active tracking, expiry, cleanup (5 tests)
2. Accept: valid/invalid connections, backpressure (3 tests)
3. QKey: validation at accept, rotation during session (3 tests)
4. Limits: max connections, per-IP limits, rate limiting (3 tests)
5. Shutdown: graceful drain, timeout, forced (3 tests)

## Files to Modify
- src/implementations/server/mod.rs (extend #[cfg(test)] module)