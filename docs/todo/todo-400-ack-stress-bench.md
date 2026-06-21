---
id: TODO-400
title: Criterion ACK stress benchmark
severity: HIGH
phase: C
priority: P1
status: OPEN
created: 2026-06-05
---

# TODO-400: Criterion Bench - ACK Processing Under Load

## Problem

No benchmark for ACK frame handling with large `sent_bytes_by_pn` maps. TODO-394 fix needs measurable before/after.

## Acceptance

- Bench constructs N in-flight PNs (1k, 10k) and processes ACK covering subset
- Reports time per ACK frame
- Used to validate TODO-394 regression

## Fix Plan

1. Unit-level bench on ACK accounting helper or full connection with synthetic ACK
2. Parameterize N and ack range count

## Files

- `scripts/benchmarks/ci_regression.rs` or transport benches
- `src/transport/connection.rs` (test harness hooks)

## Depends

- Useful before or in parallel with TODO-394
