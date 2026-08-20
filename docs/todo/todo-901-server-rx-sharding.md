---
id: TODO-901
title: Server RX batching drain and sharding
severity: HIGH
phase: S
priority: P1
status: QUEUED
created: 2026-08-21
depends_on: []
---

# TODO-901: Server RX Batching Drain and Sharding

## Objective
Shard server data path from single Tokio task (`runtime_loop.rs:155-523` all clients + TUN + admin serial) to N shards via `SO_REUSEPORT` + per-shard `recvmmsg`/`io_uring` RX with full drain.

## Verified Evidence
- `src/implementations/server/runtime_loop.rs:155-523` single task.
- `src/dns_signals.rs:1016-1033` single `recvmsg` per wakeup, no drain.
- `crates/qf-transport-udp/src/fastpath.rs:30` `MAX_BATCH_SIZE=64` already exists but not used on server RX.

## Acceptance
- N shards per client hash, each `recvmmsg` drains until `EAGAIN`.
- Ceiling linear scaling (150k -> 1M pps with 4 shards) via bench `bench-linux-send-path-decision.sh`.
- `cargo test` server tests green.

## Out of Scope
- No QUIC migration yet.

## Deviations
None.
