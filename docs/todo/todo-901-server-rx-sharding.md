---
id: TODO-901
title: Server RX batching drain and sharding
severity: HIGH
phase: S
priority: P1
status: PARTIAL
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
- Step 1 shipped (commit `456edf7`): `recv_datagram_batch` drains the kernel socket buffer until `WouldBlock` (cap 64) with one tokio wakeup per burst; the runtime loop iterates the batch through the unchanged serial stateful path, and a labeled `'batch` break keeps data-plane fault exit prompt. This removes the one-syscall-per-datagram cap but the processing itself stays single-tasked.
- Remaining for full sharding: SO_REUSEPORT N worker sockets each owning a slice of `live_state` (client maps, admission, fanout, QKey registry views), client-to-shard hashing consistent across reconnects, TUN/admin/housekeeping ownership split or delegated to shard 0, and shutdown/drain coordination across shards. That is an architecture change to `live_state` invariants and needs its own design pass plus Omega-native pps proof; it does not fit a single incremental commit alongside step 1.
