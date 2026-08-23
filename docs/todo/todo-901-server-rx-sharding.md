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

## Sharding Design Pass (2026-08-21, local - implementation requires Linux/Omega)

### Shard topology
- N worker tasks (default `N = min(available_cores, 4)`), each owning one UDP socket bound to the same port with `SO_REUSEPORT` + `SO_REUSEADDR`. The kernel hashes the 4-tuple to exactly one socket, giving consistent per-client routing without an application-level dispatcher: all datagrams of one client path (same src ip:port) always land on the same shard, which is what QUIC connection-state affinity requires. No client-hash code needed in userspace; reconnects from the same NAT mapping stay sticky.
- Each shard owns a full `Decoder16`-style pipeline slice: its own `LiveClientAcquire` admission budget (`accept_max_clients / N`), its own view into a sharded client map, and its own batch drain loop (TODO-901 step 1 helper, cap 64).

### State partitioning
- `live_state.client_snapshots` / runtime-client map becomes `ShardMap<N>`: N independent sub-maps behind per-shard locks (no cross-shard contention). Key = existing runtime client id; shard assignment derived from the same kernel hash (observable via `SO_REUSEPORT` + `getsockname` on accept? no - instead each shard only ever sees clients the kernel routed to it, so assignment is implicit by construction).
- QKey registry stays process-global behind the existing lock (read-mostly during data phase); revocation manager and retry-token manager likewise global read-shared.
- TUN downlink: single TUN fd is not shardable - shard 0 owns TUN writes; other shards hand TUN-bound payloads over a bounded crossbeam-style queue to shard 0 (backpressure via `PendingTunDownlinks` pattern already present).
- Admin actions, housekeeping tick, signal handling: shard 0 exclusively; shards 1..N run pure RX/process/TX loops with a shared shutdown barrier (`AtomicBool` + `Notify`).

### Failure and lifecycle
- A data-plane fault on any shard sets the shared fault slot and notifies all shards; every shard exits its drain loop, joins, and the runtime reports the first fault (existing `runtime_fault` contract).
- Drain-on-shutdown: each shard finishes its current batch, drops pending RX, flushes TUN queue, then exits. No partial-window commits (QUIC loss recovery absorbs the tail).

### Verification plan
1. Local: all server tests green with `N=1` (behavior identical to today).
2. Omega (aarch64 Linux): build with `io_uring` feature, run the multi-client netns suite with `N=1..4`; require exact-delivery/no-duplication contracts unchanged. **Omega now has sudo access (2026-08-23):** `ip netns`, `nft`, and `tcpdump` are all available for packet-capture evidence.
3. pps scaling: `bench-linux-send-path-decision.sh` extended with a `--shards N` knob; acceptance: >= 3x aggregate pps at N=4 vs N=1 before/after comparison on identical hardware, plus flat per-shard latency distribution. **Note:** Omega's single aarch64 core is insufficient for pps-scaling claims; the 3x-pps benchmark requires an x86_64 multi-core host.

### Risks
- Kernel hash skew: uneven client distribution across shards under few-NAT-gateway test setups (mitigation: measure per-shard counts in the bench; document skew, do not add application rebalancing).
- QUIC path migration across shards: a migrating client changes ports -> may land on a different shard. Migration handling must consult the global migration registry first (existing `reconcile_incoming_path_update`) and forward to the owning shard if found - implemented as shard-local check then global fallback lookup.

