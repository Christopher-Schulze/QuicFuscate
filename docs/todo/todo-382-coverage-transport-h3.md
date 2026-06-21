---
id: TODO-382
title: "Increase test coverage for transport/h3.rs (2033 LOC, ~8 tests/1000 LOC)"
severity: "HIGH (coverage)"
phase: legacy
priority: legacy
status: SCRAP
created: 2026-03-27
backfilled: 2026-07-23
scrap_reason: "Coverage-gap per module — replaced by single cargo-tarpaulin baseline run"
---

# TODO-382: Increase test coverage for transport/h3.rs (2033 LOC, ~8 tests/1000 LOC)


## Problem
`src/transport/h3.rs` at 2033 LOC has 16 inline tests and 0 external test files.

### What IS tested (inline only):
- MASQUE capsule encode/decode
- MASQUE tracking

### What is NOT tested:
- QPACK header compression/decompression
- HTTP/3 request/response framing
- Stream lifecycle (request streams, push streams, control stream)
- Settings frame exchange
- GOAWAY handling
- Error codes and connection errors
- Priority signaling

## Fix Plan
Target: +15-20 tests:
1. Create `scripts/tests/rust/rt-transport-h3.rs` as external test file
2. QPACK: encode/decode known headers, static table lookup (4 tests)
3. Framing: request/response frame roundtrip, DATA frames (4 tests)
4. Stream lifecycle: open, headers, data, trailers, close (4 tests)
5. Settings: exchange, unknown settings handling (2 tests)
6. Error handling: invalid frames, connection errors (3 tests)

## Files to Create
- scripts/tests/rust/rt-transport-h3.rs

## Files to Modify
- src/transport/h3.rs (add more inline tests)
- Cargo.toml (add [[test]] entry for rt-transport-h3)
- scripts/tests/suites/test-transport.sh (add rt-transport-h3)