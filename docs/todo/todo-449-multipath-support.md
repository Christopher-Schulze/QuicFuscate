---
id: TODO-449
title: QUIC multipath support (WiFi+LTE bonding)
severity: HIGH
phase: "J"
priority: P1
status: OPEN
created: 2026-06-30
depends_on: ["TODO-450"]
---

# TODO-449: QUIC Multipath Support (WiFi+LTE Bonding)

## Problem

The transport tracks **one path at a time**. There is no multi-path state, no
parallel path validation set, and no packet scheduling across paths. This makes
VPN bonding (e.g. WiFi + LTE simultaneously) impossible.

Evidence:

- `src/transport/connection.rs:76-78` — documented intentional limitation:
  > "The transport tracks one pending candidate path at a time rather than a full
  > multi-path validation set."
- `src/transport/connection.rs:178` — `pending_path_validation: Option<PendingPathValidation>`
  is a single `Option`, not a collection. Only one candidate path can be probed
  at any time.
- `src/transport/connection.rs:177` — `validated_paths: HashSet<(SocketAddr, SocketAddr)>`
  records validated paths but they are never used for simultaneous sending. On
  migration (`commit_path_validation`, line 680-684) the old path is abandoned:
  `self.local_addr` / `self.peer_addr` are overwritten and the single active path
  becomes the new one.
- `src/transport/connection.rs:173-174` — `cwnd` and `bytes_in_flight` are
  scalar fields on `Connection`, shared across all paths. There is no per-path
  congestion control instance.
- `src/transport/connection.rs:175` — `path_id: u64` is a single scalar, not a
  vector of active path IDs.
- `src/transport/cc/mod.rs:76-92` — `CcImpl` is a single enum instance per
  connection; there is no mechanism to instantiate one CC per path.
- `src/transport/config.rs` — no `multipath_enabled`, `multipath_strategy`, or
  path-priority configuration fields exist.

Consequence: when a user has WiFi and LTE available, the VPN can only use one at
a time. There is no bandwidth aggregation, no seamless failover without cwnd
collapse (see TODO-450), and no path-priority scheduling.

## Goal

Implement QUIC multipath per `draft-ietf-quic-multipath` so that a single
connection can simultaneously use multiple paths (e.g. WiFi + LTE), with:

- A `Vec<Path>` (or path map) replacing the single `pending_path_validation`
  slot, allowing concurrent path validation and active sending.
- Per-path congestion control: each path owns its own `CcImpl` instance, RTT
  estimate, cwnd, and bytes_in_flight.
- Packet scheduling across paths with selectable strategies: `round-robin`,
  `lowest-rtt`, `weighted`.
- Path health monitoring (per-path loss rate, RTT, capacity) and automatic
  failover when a path degrades or drops.
- Path priority / weight configuration.
- Config knobs: `multipath_enabled`, `multipath_strategy`,
  `multipath_path_weights`.

## Implementation Plan

### Step 1: Define the `Path` state structure

Create `src/transport/path.rs` containing a `Path` struct that encapsulates all
per-path state currently spread across `Connection` scalars:

```rust
pub struct Path {
    pub id: u64,
    pub local_addr: SocketAddr,
    pub peer_addr: SocketAddr,
    pub state: PathState,            // Probing | Active | Standby | Failed
    pub cc: CcImpl,                  // per-path congestion controller
    pub rtt: Duration,
    pub cwnd: usize,
    pub bytes_in_flight: usize,
    pub priority: u8,                // 0=lowest .. 255=highest
    pub weight: u32,                 // for weighted scheduling
    pub last_activity: Instant,
    pub challenge: Option<[u8; 8]>,  // PATH_CHALLENGE in flight
    pub received_bytes: usize,
    pub sent_bytes: usize,
}
```

`PathState` enum: `Probing`, `Active`, `Standby`, `Failed`.

### Step 2: Replace single-path fields on `Connection` with a path map

In `src/transport/connection.rs`:

- Replace `pending_path_validation: Option<PendingPathValidation>` (line 178)
  with `paths: Vec<Path>` (or `HashMap<u64, Path>`).
- Replace scalar `local_addr`, `peer_addr`, `path_id`, `cwnd`,
  `bytes_in_flight`, `rtt` with accessor methods that delegate to the **primary
  active path** (backward compatibility for single-path callers).
- Keep `validated_paths: HashSet<(SocketAddr, SocketAddr)` as a fast lookup for
  already-validated 4-tuples.
- Add `primary_path_id: u64` to track which path is the current primary (for
  migration / failover semantics).

### Step 3: Per-path congestion control

- Each `Path` owns a `CcImpl` created via `cc::create(algo, initial_cwnd, mss)`.
- `Recovery` must be parameterized per-path or refactored to hold per-path loss
  detection state (packet numbers are per-path in multipath QUIC — each path has
  its own packet number space per `draft-ietf-quic-multipath` §3.2).
- Update `on_packet_sent` / `on_ack` / `on_loss` dispatch in
  `connection.rs:2373-2376` to route to the correct path's CC based on the path
  the packet was sent on.

### Step 4: Packet scheduler

Create `src/transport/scheduler.rs` with a `PacketScheduler` trait:

```rust
pub trait PacketScheduler: Send {
    fn select_path(&self, paths: &[Path], bytes_to_send: usize) -> Option<u64>;
}
```

Implement three strategies:

1. **RoundRobin** — cycles through active paths in order.
2. **LowestRtt** — picks the active path with the lowest smoothed RTT that has
   cwnd budget.
3. **Weighted** — weighted round-robin using `Path::weight`, proportional to
   `weight * available_cwnd`.

The scheduler is consulted in the send path (where `compute_stealth_padding` and
`recovery.on_packet_sent` are currently called, ~line 2370-2376) to choose which
path's socket to send on.

### Step 5: Path health monitoring and failover

- Add `PathHealth` tracking per path: loss rate (from CC `loss_rate()`), RTT
  trend, consecutive PTO timeouts, bytes acked per second.
- A path transitions `Active → Standby` when loss rate exceeds a threshold
  (e.g. >25%) or no ACKs for >2×PTO.
- A path transitions `Active → Failed` when no ACKs for >3×PTO or explicit
  connection close on that path.
- On primary path failure, promote the highest-priority `Standby`/`Active` path
  to primary (this is the failover — unlike TODO-450's migration cwnd reset,
  failover to an already-active path has no cwnd collapse because that path's CC
  is already warm).

### Step 6: Configuration

In `src/transport/config.rs`:

- Add fields: `multipath_enabled: bool` (default `false`),
  `multipath_strategy: MultipathStrategy` (default `RoundRobin`),
  `multipath_path_weights: Vec<(SocketAddr, u32)>` (optional explicit weights).
- Add `MultipathStrategy` enum: `RoundRobin`, `LowestRtt`, `Weighted`.
- Add setters: `set_multipath_enabled`, `set_multipath_strategy`,
  `set_multipath_path_weights`.
- Wire into `Config::new_with_version` defaults (line 109+).

### Step 7: PATH_NEW / PATH_ABANDON frame support

Per `draft-ietf-quic-multipath`, add frame types:

- `PATH_NEW` (path_id, local_addr, peer_addr) — announce a new path to the peer.
- `PATH_ABANDON` (path_id) — signal that a path is being abandoned.
- `PATH_STATUS` (path_id, state) — bidirectional path state sync.

Add these to `src/transport/frames.rs` and handle in the frame dispatch in
`connection.rs`.

### Step 8: Integration with existing migration

The existing `initiate_path_validation` (line ~580) and
`commit_path_validation` (line ~675) logic becomes the single-path fallback when
`multipath_enabled == false`. When enabled, validated paths are added to the
`paths` vector as `Active` instead of replacing the primary.

## Files to Modify/Create

- `src/transport/path.rs` — **new**: `Path`, `PathState`, `PathHealth` structs.
- `src/transport/scheduler.rs` — **new**: `PacketScheduler` trait + 3 strategies.
- `src/transport/connection.rs` — replace single-path fields with path map;
  update send/recv/ACK/loss dispatch; update migration logic.
- `src/transport/cc/mod.rs` — allow multiple `CcImpl` instances per connection.
- `src/transport/recovery.rs` — per-path loss detection / packet number spaces.
- `src/transport/frames.rs` — `PATH_NEW`, `PATH_ABANDON`, `PATH_STATUS` frames.
- `src/transport/config.rs` — multipath config fields + setters + enum.
- `src/transport.rs` — re-export `MultipathStrategy`, `Path`, `PacketScheduler`.
- `src/transport/mod.rs` or `src/transport.rs` — module wiring for `path`,
  `scheduler`.
- Tests: `src/transport/path.rs` (unit), `src/transport/scheduler.rs` (unit),
  integration test for dual-path send + failover.

## Acceptance Criteria

- [ ] Two paths (WiFi + simulated LTE via tc-netem on two loopback aliases) can
      be active simultaneously on one connection.
- [ ] Traffic is distributed across both paths (verifiable by per-path byte
      counters in `Stats`).
- [ ] When one path drops (interface removed / 100% loss), the connection
      survives using the remaining path with no disconnect.
- [ ] `round-robin` strategy alternates packets across paths.
- [ ] `lowest-rtt` strategy preferentially uses the lower-RTT path.
- [ ] `weighted` strategy distributes bytes proportional to configured weights.
- [ ] Per-path cwnd is independent — losing packets on one path does not reduce
      cwnd on the other.
- [ ] `multipath_enabled = false` preserves current single-path behavior exactly
      (no regression in existing migration tests).
- [ ] Unit tests for `PacketScheduler` strategy selection logic.
- [ ] Unit tests for `Path` state transitions (Probing→Active→Standby→Failed).

## Resource Budget

| Scenario | Budget | Notes |
|----------|--------|-------|
| Dual-path throughput test (2× loopback) | < 60s wall time | Verify both paths carry traffic |
| Failover test (kill one path mid-transfer) | < 30s, 0 disconnects | PTO-driven detection |
| Scheduler unit tests | < 5s | All 3 strategies |
| Per-path CC independence test | < 10s | Loss on path A ≠ cwnd drop on path B |
| Memory overhead per additional path | < 8 KiB | CC state + RTT + counters |
