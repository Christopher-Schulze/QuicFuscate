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
Close the remaining native performance gate for the already implemented server
RX batching and `SO_REUSEPORT` sharding. Do not add an io_uring RX variant or
change shard topology without measured evidence that the current path is the
bottleneck.

## Verified Evidence
- `src/implementations/server/runtime_impl/runtime_loop.rs` owns the
  coordinator loop; `src/implementations/server/sharding.rs::run_shard_worker`
  owns per-shard receive and bounded message draining.
- `src/implementations/server/dns_signals.rs::recv_datagram_batch` waits for
  the first datagram, then uses `recv_batch_gro`/`recvmmsg` on Linux for the
  rest of a bounded burst. Server RX does not use io_uring.
- `src/implementations/server/runtime_impl.rs::resolve_rx_shards` selects up
  to four Linux shards by default; the existing Omega N=1/N=4 live evidence
  below proves functionality, not multicore scaling.

## Acceptance
- On a named multicore Linux host, record commit, kernel, CPU topology, NIC,
  IRQ/RSS and affinity policy, offered load, packet sizes, concurrent client
  count, shard count, and the observed per-shard distribution. Compare N=1,
  N=2, and N=4 on the same server RX/TUN workload with at least five trials
  each. Report median and spread of delivered application pps, ingress/drop
  counters, CPU per delivered packet, p99 latency, and forwarding-channel
  drops. Verify the actual socket/shard count and preserve identical security
  and QUIC migration behavior under load.
- Freeze the workload and the regression tolerance before the runs. Accept
  N>1 as a default only where measured delivered pps or CPU efficiency
  improves without a material loss/latency regression. A claimed numeric
  speedup requires a paired N=1 baseline and repeated-run spread. If it does
  not improve, select the measured best shard count for that environment and
  open a separate source-grounded bottleneck task; do not invent a universal
  1M pps or 3x threshold.
- Relevant server tests and Linux N=1/N=4 live ingress, migration, teardown,
  and default-deny gates pass at the reviewed revision. A send-only or
  `udpfast` microbenchmark is not server RX evidence.

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

### Implementation design (2026-08-24, decided)

Topology: dedicated coordinator task (admin, signals, global housekeeping,
TUN read) + N uniform dataplane shard tasks (RX → process → TX), N sockets
sharing one port via `SO_REUSEPORT`. This deviates deliberately from
"shard-0 owns TUN/admin": a separate coordinator is strictly better load
distribution and keeps `ServerRuntime`'s `&mut self` admin paths on the
main task — shard-0-without-dataplane is the same role.

- `rx_shards` (server config): `0` = `min(available_parallelism, 4)`;
  `1` = legacy single-task loop, untouched; `N>1` = sharded path, Linux
  only, with graceful fallback to 1 when SO_REUSEPORT bind fails.
- `LiveServerState::shard_clone()`: each shard owns its `clients`,
  `path_candidates`, `qkey_auth`, `pending_tun_downlinks`,
  `downlink_tx_*`, `next_stats_log`; shares `domain` (Arc, already
  internally locked), `fanout_queue`, `auth_rate_limiter`,
  `revocation_manager`, `qkey_tracker`, `retry_token_manager`,
  `accept_loop` (Arc, `&self`+internal locks), `blocked_ips`,
  `qkey_registry`, `server_tun` (Arc, `write(&self)` — direct writes
  from any shard; deviates from "shard-0 owns TUN writes": fd writes are
  atomic per frame, the channel hop buys nothing).
- `ShardRouter` (`parking_lot::RwLock` inner): `addr_owner`,
  `conn_owner` (server SCID → shard, refreshed on reconcile),
  `profiles` (frozen `tunnel_ingress_profile` per addr). Lookups only
  run on local-map misses (unknown/migrated addrs) — established
  traffic hits the shard-local `clients` map first, so the lock is off
  the steady-state path.
- Migration: post-commit addrs keep hashing to the original shard →
  permanent forwarding per design (bounded `ShardMessage::Datagram`
  channel; full → drop + metric = UDP loss semantics). Pre-commit
  candidates resolve via `conn_owner` and run
  `handle_incoming_path_update` on the owner.
- TUN→client: coordinator drains `tun_rx`, classifies route (TTL/local/
  unknown ICMP stay coordinator-side), resolves `session → addr →
  owner` and posts `ShardMessage::Downlink` (packet via shared
  `PendingTunPacket::Shared` block); the owner applies conn lookup,
  MTU check (+ `PacketTooBig` ICMP), bandwidth decision and
  direct-send-or-pending with its own `PendingTunDownlinks` queue —
  semantics identical to today's per-target body.
- `drain_client_fanout`: any shard pops the shared queue, resolves
  targets via `addr_owner` and routes `Downlink{fanout}` items; the
  qkey-authed/MTU filters run owner-side.
- Session reaping: `domain.reap_expired_remotes()` is global-once on
  the coordinator; per-addr conn cleanup ships as
  `ShardMessage::ExpireRemotes` to each owner (prevents zombie conns
  when a different shard wins the reap race).
- Admin surface: `kick_client`/`revoke_qkey_now`/`shutdown_all` resolve
  targets via `addr_owner` and post `Kick`/`CloseSessions`/`Shutdown`
  commands; worker faults post into a shared fault slot observed by the
  coordinator housekeeping tick; drain completion = `router.len()==0`,
  final flush = broadcast `Shutdown` + bounded join.
- Global pruning (`auth_rate_limiter`, revocations, rate limits,
  blacklist sync, strike register) runs inside
  `run_housekeeping_tick` gated on `shard_id == 0 || unsharded`, so the
  coordinator performs it exactly once while workers skip it.
- Snapshot retain uses the router's global keyset when sharded (per-
  shard `clients` keys would drop other shards' snapshots).

### Implementation (2026-08-26)

Fully wired, compiling, 557/557 server tests green (incl. 5 new router
unit tests). Layout:

- `src/implementations/server/sharding.rs`: `ShardRouter`
  (addr/conn-id/profile ownership maps behind `parking_lot::RwLock`),
  `ShardMessage` (`Datagram`, `Downlink`, `Kick`, `CloseSessions`,
  `ExpireRemotes`, `ReloadTransport`, `Shutdown`), bounded per-shard
  channels (`SHARD_MESSAGE_CAPACITY=4096`, drain cap 64), the worker
  task `run_shard_worker` (socket RX arm + message arm + local
  housekeeping arm), and `process_shard_datagram` — the full
  blocked-IP → VN → DDoS-admission → acquire → process → reconcile →
  fanout pipeline shared by socket RX and forwarded datagrams.
  Forwarded datagrams keep *full* admission semantics on the owner
  (only the routing hop is skipped) — no admission-bypass vs legacy.
- `runtime_impl.rs`: `resolve_rx_shards` (0 → `min(parallelism,4)`,
  Linux-only, non-Linux clamps to 1 with a warn), `create_shard_sockets`
  (socket2 `SO_REUSEADDR`+`SO_REUSEPORT` per sibling; any sibling bind
  failure drops the set and falls back to one plain socket),
  `spawn_shard_workers`, `shutdown_shard_workers` (broadcast `Shutdown`
  + bounded join = `FINAL_CLOSE_FLUSH_TIMEOUT`), router-aware
  `drain_complete`/`active_client_count`, and transport-reload
  propagation via `ShardMessage::ReloadTransport` broadcast after a
  successful standalone reload.
- `live_state.rs`: `domain` is `Arc<LiveServerDomain>`;
  `shard_clone(shard_id, router)` forks local maps + scheduler config
  while sharing every global registry; coordinator fork uses the
  `COORDINATOR_SHARD_ID` sentinel (`usize::MAX`) so worker ids `0..N`
  never collide with global-housekeeping ownership. Router hooks:
  register on accept, `rebind` on validated path commit, `unregister`
  on close, `sync_conn_ids` on reconcile (retain + upsert current SCIDs
  so post-rotation migration candidates still route), `ExpireRemotes`/
  `Kick`/`CloseSessions` routed by `addr_owner`, global snapshot retain
  via `router.addr_keyset()`.
- `tun_path.rs`: `classify_server_tun_downlink` prelude (local handling,
  route classify, TTL expiry, target resolution, `ClassifiedDownlink`);
  `route_server_tun_packet` posts `Downlink` per resolved target with a
  shared `PendingTunPacket::Shared` frame (one pool block serves every
  routed target); `handle_shard_downlink` replays the identical
  per-target semantics on the owner (`Fanout` → `deliver_fanout_target`,
  `Tun` → MTU/ICMP/bandwidth/direct-or-pending). `resolve_source_profile`
  falls back to `router.profile_of` for sources owned by other shards.
- `config.rs`: `ServerConfig.rx_shards` (default 0) +
  `QUICFUSCATE_RX_SHARDS` env override. Startup-only: shard topology is
  fixed at bind time; runtime reload does not reshard.
- `metrics`: `shard_forward_dropped` counter records routing drops when
  a shard channel is full/closed (UDP loss semantics), exported to
  Prometheus.
- `run_loop`: unchanged for N=1 (`shard_router == None` → byte-identical
  select arms). When sharded, the socket-RX select arm is disabled by a
  `if !sharded` guard; admin/signals/housekeeping/TUN-notify arms are
  shared verbatim; housekeeping checks `shard_fault` alongside
  `tun_fault`; `drain_server_tun_packets` receives the router.

Deviations from the earlier sketch, all deliberate:

- Coordinator gets `usize::MAX` shard id instead of 0 — worker 0 is a
  real shard, so id-0-as-coordinator would have run global housekeeping
  twice.
- `SO_REUSEPORT` sibling failure falls back to a *plain* single bind
  (not a partially-sharded set) — simplest correct degradation.
- `accept_max_clients` is split `max(1, max/N)` per shard as a local
  bound; the global cap stays enforced by the shared `AcceptLoop`.
- Migrated connections keep hashing to their *new* 4-tuple's shard and
  are forwarded to the owner for the connection's remaining life —
  permanent per-design forwarding, not owner migration.
- `Shutdown` reason is carried through `ShardMessage::Shutdown` into
  each shard's final `force_close_and_flush`.
- `maybe_sync_blacklist`/`run_housekeeping_tick` had a `std` MutexGuard
  held across `.await` — scoped so shard worker futures stay `Send`.

### Verification status
- [x] Local macOS: `cargo check`/`clippy`/`fmt` clean; 557/557 server
  lib tests green (N=1 path unaffected; router unit tests cover
  register/rebind/unregister/wrong-shard-ignore/queue-full).
- [x] Omega (aarch64 Linux) 2026-09-19: first real compile of the
  cfg(linux) paths surfaced and fixed two errors — `SO_REUSEPORT` now
  via `qf_transport_udp::enable_reuse_port_fd` (raw `setsockopt`, same
  convention as `UDP_GRO`; `socket2::Socket::set_reuse_port` does not
  exist in 0.5.10) and a stale `live.` borrow in the cfg-gated
  sendmmsg/GSO flush. 563/563 server tests green on Linux.
- [x] Omega live N=1: `tun-e2e-netns.sh` PASS (0% loss both phases,
  graceful stop, restart-ownership proof) — legacy path byte-identical.
- [x] Omega live N=4 (`QUICFUSCATE_RX_SHARDS=4`): `tun-e2e-netns.sh`
  PASS with `server RX sharding active: 4 dataplane shards` +
  `spawned 4 dataplane shard workers` + 4 per-shard io_uring workers in
  both normal and restart phases; clean teardown, no leaked processes
  or netns. `tun-e2e-multi-client-dual-stack-netns.sh` data-plane
  phases (H3 fallback, multi-client default-deny, unicast opt-in, v6
  throughput) all pass under N=4; its only failure is the pre-existing
  single-core "1472-byte payload 15% gain" host-throughput assertion
  which fails identically at N=1 — not a sharding regression. The
  harness's UDP-socket evidence helper now aggregates SO_REUSEPORT
  sibling counters (`socket_count` field; remote-port selectors stay
  exactly-one).
- [x] Omega live N=4 lifecycle: `test-graceful-shutdown.sh` PASS —
  SIGHUP reload with `active_sessions_unchanged=2`, `ReloadTransport`
  broadcast, drain running→stopped, new-connection rejection during
  drain, client-close reconcile (2→1) via routed `ExpireRemotes`, clean
  worker close-flush + join, audit chain valid. `tun-e2e-fec-netns.sh`
  6/6 PASS under N=4 (25% netem → 9% tunnel loss; iperf3 at 10% loss)
  and `tun-e2e-traffic-analysis-netns.sh` PASS under N=4.
- [x] Post-sharding fixes found by live validation: coordinator
  housekeeping delay iterated the always-empty coordinator `clients`
  map → idle-interval pacing starved metric/session freshness under
  sharding (router-aware activity signal now paces it at the active
  rate); `test-graceful-shutdown.sh` had two stale grep patterns that
  missed the `runtime_generation=N` field added in TODO-889 (fails
  identically at N=1 — repaired, not sharding-related);
  `udp-socket-evidence.py` now aggregates SO_REUSEPORT siblings.
- [ ] Multicore native RX scaling and default-shard verdict under the
  Acceptance workload above. Omega's single core cannot supply this proof.
  Profile any bottleneck before changing worker scheduling or affinity.

### Risks
- Kernel hash skew: uneven client distribution across shards under few-NAT-gateway test setups (mitigation: measure per-shard counts in the bench; document skew, do not add application rebalancing).
- QUIC path migration across shards: a migrating client changes ports -> may land on a different shard. Migration handling must consult the global migration registry first (existing `reconcile_incoming_path_update`) and forward to the owning shard if found - implemented as shard-local check then global fallback lookup.
