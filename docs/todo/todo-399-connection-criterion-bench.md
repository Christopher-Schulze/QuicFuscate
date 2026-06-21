---
id: TODO-399
title: Criterion Connection send/recv bench
severity: HIGH
phase: C
priority: P1
status: OPEN
created: 2026-06-05
---

# TODO-399: Criterion Bench - Connection 1-RTT Send/Recv Loop

## Problem

`bench-transport.sh` only runs micro-benches (varint, header_validate). No regression coverage for real `Connection::send`/`recv` with AEAD + frames.

## Acceptance

- New criterion group `connection_loop` behind `benches` feature
- Measures 1-RTT short-header roundtrip (mock or loopback transport)
- Wired into `scripts/benchmarks/bench-ci-regression.sh` or transport suite
- Baseline saved for PR comparison (TODO-401 dependency)

## Fix Plan

1. Add `benches/connection_loop.rs` or extend `ci_regression.rs`
2. Minimal harness: establish keys, send stream frame, recv ACK path
3. Document run instructions in bench script

## Files

- `Cargo.toml` (bench target)
- `scripts/benchmarks/ci_regression.rs` or new bench file
- `scripts/benchmarks/suites/bench-transport.sh`
