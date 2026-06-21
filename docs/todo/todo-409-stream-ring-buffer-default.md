---
id: TODO-409
title: stream_ring_buffer throughput profile evaluation
severity: MEDIUM
phase: A
priority: P2
status: OPEN
superseded_by: TODO-414
created: 2026-06-05
---

# TODO-409: Evaluate `stream_ring_buffer` for Throughput Builds

> **Note (2026-07-23):** This task is **superseded by TODO-414** (Streaming-FEC in Adaptiven Loop). The `stream_ring_buffer` evaluation is integrated as Step 4 of TODO-414, which will use profiling evidence from TODO-418 to decide whether to enable the feature by default. Do not implement this task separately.

## Problem

`maybe_flush_one_writable_stream` (~1599) uses `to_vec()` per STREAM frame without `stream_ring_buffer` feature (Cargo.toml default off).

## Acceptance

- Document when to enable feature (server release profile recommendation)
- OR enable by default for `server` feature with benchmark evidence
- Stream send tests pass with feature on

## Fix Plan

1. Benchmark stream throughput with/without feature (TODO-399 extension)
2. Update `config/quicfuscate.toml` comment or release build profile
3. Avoid behavior change for client unless measured win

## Files

- `Cargo.toml`
- `src/transport/connection.rs`
- `config/quicfuscate.toml`
