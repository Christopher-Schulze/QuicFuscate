---
id: TODO-402
title: Batch AEAD seal/open
severity: MEDIUM
phase: D
priority: P2
status: DONE
created: 2026-06-05
---

# TODO-402: Batch AEAD Seal/Open

## Problem

Aegis X4/X8 backends exist for SIMD bulk crypto but `Connection::send` seals one packet at a time. No batching across datagrams.

## Acceptance

- Batch API seals N packets with one SIMD dispatch where lengths align
- Fallback to single-packet path for mixed sizes
- Throughput gain measurable on TODO-399 bench

## Fix Plan

1. Queue outgoing sealed payloads until batch threshold or timer
2. Call X4/X8 batch encrypt when available
3. Integrate with io_uring send batch

## Files

- `src/crypto/aegis.rs`
- `src/transport/connection.rs`
- `src/optimize/uring_batch.rs`

## Risk

High effort. Latency vs throughput tradeoff needs tuning.
