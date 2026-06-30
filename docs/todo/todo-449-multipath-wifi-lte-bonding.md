---
id: TODO-449
title: Multipath support (WiFi+LTE bonding)
severity: HIGH
phase: "J"
priority: P1
status: DONE
created: 2026-07-23
depends_on: ["TODO-450"]
---

# TODO-449: Multipath Support (WiFi+LTE Bonding)

## Goal
Implement QUIC multipath per `draft-ietf-quic-multipath-21` so that a single
connection can simultaneously use multiple paths (e.g. WiFi + LTE) for bandwidth
aggregation, seamless failover, and path-priority scheduling. This is the core
enabler for mobile VPN bonding — the primary QuicFuscate use case on mobile
devices where WiFi and LTE are both available.

## Current State (verified against code)

The transport is fundamentally single-path. All path state is stored as scalar
fields or single-slot `Option`s on `Connection`:

- `src/transport/connection.rs:76-78` — documented intentional limitation:
  > "The transport tracks one pending candidate path at a time rather than a full
  > multi-path validation set."
- `src/transport/connection.rs:178` — `pending_path_validation: Option<PendingPathValidation>`
  is a single `Option`, not a collection. Only one candidate path can be probed
  at any time. `begin_path_validation()` (line 575) returns `InvalidState` if a
  validation is already in progress for a different path (line 588-592).
- `src/transport/connection.rs:177` — `validated_paths: HashSet<(SocketAddr, SocketAddr)>`
  records validated 4-tuples but they are never used for simultaneous sending.
  On migration (`commit_path_validation`, line 680-684) the old path is abandoned:
  `self.local_addr` / `self.peer_addr` are overwritten and the single active path
  becomes the new one.
- `src/transport/connection.rs:173-174` — `cwnd` and `bytes_in_flight` are
  scalar fields on `Connection`, shared across all paths. There is no per-path
  congestion control instance.
- `src/transport/connection.rs:175` — `path_id: u64` is a single scalar, not a
  vector of active path IDs.
- `src/transport/connection.rs:219` — `recovery: Recovery` is a single instance
  per connection; `Recovery` wraps one `CcImpl` (line 39 of `recovery.rs`).
- `src/transport/cc/mod.rs:76-92` — `CcImpl` is a single enum instance per
  connection; there is no mechanism to instantiate one CC per path.
- `src/transport/config.rs` — no `multipath_enabled`, `multipath_strategy`, or
  path-priority configuration fields exist.
- `src/transport/frames.rs` — no `PATH_NEW`, `PATH_ABANDON`, `PATH_STATUS`, or
  `ACK_MP` frame types exist. The multipath draft requires these.
- `src/transport/recovery.rs:20-41` — `Recovery` holds a single `cc: CcImpl`,
  single `rtt`, single `loss_time`, single `pto_count`. All loss detection and
  congestion control state is per-connection, not per-path.

The existing connection migration state machine (TODO-207-212, done) provides
PATH_CHALLENGE / PATH_RESPONSE validation for a single candidate path. This is
the foundation upon which multipath builds — but it must be generalized from
single-candidate to multi-candidate.

## Problem Analysis

### The fundamental limitation
QUIC v1 (RFC 9000) supports connection migration — switching from one path to
another — but not multipath — using multiple paths simultaneously. The current
codebase implements migration only. When a path is validated via
`commit_path_validation()`, the old path is discarded and the new path becomes
the sole active path. There is no mechanism to keep both paths active and send
data across both.

### Why multipath matters for VPN bonding
A mobile VPN user with WiFi and LTE available wants to:
1. **Aggregate bandwidth** — use both interfaces simultaneously for higher
   throughput.
2. **Seamless failover** — if WiFi drops, LTE takes over with zero connection
   interruption (no re-handshake, no cwnd collapse).
3. **Lowest-latency scheduling** — send latency-sensitive packets on the path
   with lower RTT, bulk data on the higher-bandwidth path.

None of these are possible with single-path migration. Migration only switches
paths; it doesn't use them in parallel.

### draft-ietf-quic-multipath-21 key requirements
The latest draft (March 2026, submitted to IESG for publication) introduces:
- **Path identifiers**: explicit path IDs (not just 4-tuples) to create, delete,
  and manage paths. Path ID is a varint, negotiated via `initial_max_path_id`
  transport parameter.
- **Per-path packet number spaces**: each path has its own packet number space,
  preventing PN confusion across paths. The nonce is computed as
  `path_id * 2^62 + packet_number` (§2.4).
- **PATH_NEW frame**: announces a new path to the peer.
- **PATH_ABANDON frame**: signals that a path is being abandoned.
- **PATH_STATUS frame**: bidirectional path state sync (standby/available).
- **ACK_MP frame**: per-path ACK (acknowledges packets on a specific path).
- **Path challenge/response per path**: PATH_CHALLENGE and PATH_RESPONSE are
  extended to include path ID.

### Per-path congestion control
RFC 9000 §9.4 states: "Packets sent on the old path MUST NOT contribute to
congestion control or RTT estimation for the new path." For multipath, this
generalizes: each path must have its own CC instance, RTT estimate, cwnd, and
bytes_in_flight. The current single `Recovery` instance cannot support this.

### Stealth concern
Using multiple paths simultaneously means multiple source IP addresses are
visible to DPI. For high-stealth scenarios, this is a fingerprinting risk —
a single QUIC connection appearing from two different source IPs is unusual
for normal web traffic. A "single-path exposure mode" must be available where
multipath is used only for failover (not simultaneous sending), keeping the
connection looking like single-path QUIC to DPI.

## Proposed Architecture

### Path Manager
A new `PathManager` struct replaces the scattered path state on `Connection`:

```
PathManager
├── paths: Vec<Path>                    // all known paths (active + standby + probing)
├── primary_path_id: u64                // current primary path
├── path_id_counter: u64                // next path ID to assign
├── scheduler: PacketScheduler          // packet scheduling strategy
└── max_paths: usize                    // from initial_max_path_id transport param
```

Each `Path` encapsulates all per-path state:
```
Path
├── id: u64
├── local_addr: SocketAddr
├── peer_addr: SocketAddr
├── state: PathState                    // Probing | Active | Standby | Failed
├── cc: CcImpl                          // per-path congestion controller
├── rtt: Duration                       // per-path smoothed RTT
├── cwnd: usize                         // per-path congestion window
├── bytes_in_flight: usize              // per-path in-flight bytes
├── priority: u8                        // 0=lowest .. 255=highest
├── weight: u32                         // for weighted scheduling
├── last_activity: Instant
├── challenge: Option<[u8; 8]>          // PATH_CHALLENGE in flight
├── received_bytes: usize               // anti-amplification tracking
├── sent_bytes: usize
├── pkt_num_counter: u64                // per-path packet number space
├── loss_time: Option<Instant>          // per-path loss detection
└── pto_count: u32                      // per-path PTO backoff
```

### Packet Scheduler
A trait-based scheduler consulted in the send path:

```rust
pub trait PacketScheduler: Send {
    fn select_path(&self, paths: &[Path], bytes_to_send: usize) -> Option<u64>;
}
```

Strategies:
1. **LowestRtt** (default) — picks the active path with the lowest smoothed RTT
   that has cwnd budget. Best for latency-sensitive VPN traffic.
2. **RoundRobin** — cycles through active paths in order. Simple, fair.
3. **Weighted** — weighted round-robin using `Path::weight`, proportional to
   `weight * available_cwnd`. Good for explicit bandwidth ratio control.
4. **Redundant** — sends duplicate packets on all active paths. Maximum
   reliability at 2× bandwidth cost. Useful for critical control traffic.
5. **SinglePath** (stealth mode) — sends on primary path only. Multipath is
   used only for failover. No multiple source IPs visible to DPI.

### Frame Support
New frame types per draft-ietf-quic-multipath-21:
- `PATH_NEW` (type TBD): path_id, local_addr, peer_addr — announce new path.
- `PATH_ABANDON` (type TBD): path_id — abandon a path.
- `PATH_STATUS` (type TBD): path_id, status — standby/available.
- `ACK_MP` (type TBD): path_id, ack_ranges — per-path ACK.

### Transport Parameter
- `initial_max_path_id` (0x0f739bbc1b666d0d): varint, maximum path ID the
  endpoint will maintain. Default: 0 (single-path compat). Set to ≥1 for
  multipath.

## Implementation Plan

### Step 1: Define `Path` and `PathState` structures
Create `src/transport/path.rs`:
- `Path` struct with all per-path state listed above.
- `PathState` enum: `Probing`, `Active`, `Standby`, `Failed`.
- `PathHealth` tracking: loss rate, RTT trend, consecutive PTO timeouts,
  bytes acked per second.
- State transition methods: `probe()`, `activate()`, `standby()`, `fail()`.

### Step 2: Create `PathManager`
Create `src/transport/path_manager.rs`:
- `PathManager` struct holding `Vec<Path>`, primary path ID, scheduler.
- `add_path(local, peer) -> u64` — creates a new path in `Probing` state.
- `remove_path(id)` — transitions to `Failed` and removes.
- `validate_path(id)` — transitions `Probing → Active`.
- `get_path(id) -> &Path` / `get_path_mut(id) -> &mut Path`.
- `active_paths() -> impl Iterator<Item=&Path>` — paths in `Active` state.
- `promote_standby()` — promote highest-priority standby to active on failure.
- Backward compat: when `multipath_enabled == false`, `PathManager` holds
  exactly one path and delegates all scalar accessors to it.

### Step 3: Replace single-path fields on `Connection`
In `src/transport/connection.rs`:
- Replace `pending_path_validation: Option<PendingPathValidation>` (line 178)
  with `path_manager: PathManager`.
- Replace scalar `local_addr`, `peer_addr`, `path_id`, `cwnd`,
  `bytes_in_flight`, `rtt` with accessor methods that delegate to the primary
  active path (backward compatibility for single-path callers).
- Keep `validated_paths: HashSet<(SocketAddr, SocketAddr)>` as a fast lookup.
- The `Recovery` field (line 219) is replaced by per-path `Recovery` instances
  inside each `Path`.

### Step 4: Per-path congestion control and loss detection
- Each `Path` owns a `CcImpl` created via `cc::create(algo, initial_cwnd, mss)`.
- Each `Path` owns its own `Recovery`-like loss detection state (loss_time,
  pto_count, sent_packets tracking).
- Update `on_packet_sent` / `on_ack` / `on_loss` dispatch to route to the
  correct path's CC based on the path the packet was sent on.
- Per-path packet number spaces: each path has its own `next_send_pn` counter.
  The nonce for AEAD is `path_id * 2^62 + pn` per draft §2.4.

### Step 5: Packet scheduler
Create `src/transport/scheduler.rs`:
- `PacketScheduler` trait + 5 strategy implementations.
- The scheduler is consulted in the send path (where `compute_stealth_padding`
  and `recovery.on_packet_sent` are currently called, ~line 2370-2376) to
  choose which path's socket to send on.
- Scheduler selection is configurable via `Config::multipath_strategy`.

### Step 6: Multipath frames
In `src/transport/frames.rs`:
- Add `PathNew { path_id, local_addr, peer_addr }` frame.
- Add `PathAbandon { path_id }` frame.
- Add `PathStatus { path_id, status }` frame.
- Add `AckMp { path_id, ack_delay, ranges }` frame (per-path ACK).
- Wire frame encoding/decoding and handle in `connection.rs` frame dispatch.

### Step 7: Path health monitoring and failover
- `PathHealth` tracking per path: loss rate (from CC `loss_rate()`), RTT
  trend, consecutive PTO timeouts, bytes acked per second.
- A path transitions `Active → Standby` when loss rate exceeds threshold
  (e.g. >25%) or no ACKs for >2×PTO.
- A path transitions `Active → Failed` when no ACKs for >3×PTO or explicit
  `PATH_ABANDON` from peer.
- On primary path failure, promote the highest-priority `Standby`/`Active`
  path to primary. Unlike TODO-450's migration cwnd reset, failover to an
  already-active path has no cwnd collapse because that path's CC is already
  warm.

### Step 8: Configuration
In `src/transport/config.rs`:
- Add `multipath_enabled: bool` (default `false`).
- Add `multipath_strategy: MultipathStrategy` (default `LowestRtt`).
- Add `multipath_max_paths: u8` (default 2 — WiFi + LTE).
- Add `multipath_path_weights: Vec<(SocketAddr, u32)>` (optional explicit
  weights).
- Add `multipath_stealth_mode: MultipathStealthMode` (default `SinglePath`):
  `SinglePath` (stealth — failover only, no simultaneous sending),
  `MultiPath` (full multipath, multiple source IPs visible).
- Add setters and wire into `Config::new_with_version` defaults (line 109+).

### Step 9: Transport parameter negotiation
- Add `initial_max_path_id` transport parameter (0x0f739bbc1b666d0d).
- Client advertises `initial_max_path_id = 0` by default (single-path).
- When `multipath_enabled == true`, client advertises `initial_max_path_id`
  equal to `multipath_max_paths - 1`.
- Server must echo back its own `initial_max_path_id`. The effective max is
  `min(client, server)`.

### Step 10: Integration with existing migration
- The existing `initiate_path_validation` (line ~575) and
  `commit_path_validation` (line ~675) logic becomes the single-path fallback
  when `multipath_enabled == false`.
- When enabled, validated paths are added to the `PathManager` as `Active`
  instead of replacing the primary.
- `begin_path_validation` is generalized to allow concurrent validations
  (remove the `InvalidState` early return at line 588-592 when multipath is
  enabled).

## Technology Choices

### draft-ietf-quic-multipath-21 (March 2026)
The latest draft version, submitted to IESG for publication. Key changes from
earlier drafts:
- Renamed from "Multipath Extension for QUIC" to "Managing multiple paths for
  a QUIC connection".
- Path ID is now a varint, not a fixed 4-byte field.
- `initial_max_path_id` transport parameter (was `max_path_id`).
- Per-path nonce calculation: `path_id * 2^62 + pn` (§2.4).
- PATH_STATUS frame for standby/available signaling.

### Reference implementations
- **quic-go multipath**: `quic-go` has a multipath implementation based on
  earlier drafts. Good reference for scheduler design and per-path CC.
  https://github.com/quic-go/quic-go/tree/multipath
- **picoquic MP**: picoquic has a multipath implementation. Good reference for
  per-path packet number spaces and PATH_NEW/PATH_ABANDON frame handling.
  https://github.com/private-octopus/picoquic/tree/mp
- **mp-quic Linux kernel**: academic implementation, good for scheduler
  comparison (redundant scheduling, lowest-RTT, weighted).

### Scheduler design
The `LowestRtt` scheduler is chosen as default because:
- VPN traffic is often latency-sensitive (interactive shells, web browsing).
- It naturally prefers the path with lower RTT without explicit configuration.
- It avoids sending on a congested path (cwnd budget check).

The `Redundant` scheduler is included for critical control traffic (e.g.,
connection-level frames, key updates) where reliability is more important than
bandwidth efficiency.

## Stealth/Efficiency Considerations

### Stealth: multiple source IP exposure
When multipath is active, the connection sends from multiple source IP
addresses (e.g., WiFi IP + LTE IP). DPI can observe:
1. A single QUIC connection ID appearing on two different source IPs —
   unusual for normal web traffic.
2. Multiple 4-tuples for the same DCID — a strong multipath fingerprint.

**Mitigation: `SinglePath` stealth mode** (default):
- Multipath is configured but only the primary path is used for sending.
- Other paths are kept in `Standby` state, validated but not sending.
- On primary path failure, failover to a standby path is immediate (no
  re-validation needed).
- To DPI, the connection looks like single-path QUIC with migration.
- Only when stealth is explicitly disabled (`MultiPath` mode) does the
  scheduler distribute packets across paths simultaneously.

### Stealth: per-path CC fingerprint diversity
Each path can use a different CC algorithm (e.g., BBR3 on WiFi, CUBIC on LTE).
This adds traffic pattern diversity, making it harder for DPI to correlate
the two paths as the same connection. However, this is advanced and should
only be used when stealth is not a concern (the CC patterns themselves are
a fingerprint).

### Efficiency: memory overhead
Each additional path costs ~8 KiB (CC state + RTT estimator + loss detection
+ counters). For 2 paths (WiFi + LTE), this is negligible. For more paths,
the `PathManager` should enforce `max_paths` to prevent unbounded growth.

### Efficiency: scheduler overhead
The scheduler is consulted once per packet send. `LowestRtt` is O(n) in the
number of active paths — trivial for 2-4 paths. No performance concern.

### Efficiency: per-path packet number spaces
Per-path PN spaces require per-path AEAD nonce computation. The nonce is
`path_id * 2^62 + pn` instead of just `pn`. This is a single multiplication
— negligible overhead.

## Testing Plan

### Unit tests
- `Path` state transitions: Probing→Active→Standby→Failed.
- `PacketScheduler` strategy selection logic (all 5 strategies).
- `PathManager` add/remove/validate/promote operations.
- Per-path CC independence: loss on path A does not reduce cwnd on path B.
- Per-path nonce computation: `path_id * 2^62 + pn` correctness.
- Multipath frame encode/decode round-trip (PATH_NEW, PATH_ABANDON,
  PATH_STATUS, ACK_MP).
- `initial_max_path_id` transport parameter encoding.

### Integration tests
- **Dual-path throughput**: two paths (WiFi via loopback alias + LTE via
  tc-netem on another loopback alias) active simultaneously on one connection.
  Verify traffic distributed across both paths (per-path byte counters).
- **Failover**: kill one path mid-transfer. Connection survives using the
  remaining path. No disconnect, no re-handshake.
- **LowestRtt scheduling**: verify the lower-RTT path carries more packets.
- **Weighted scheduling**: verify byte distribution proportional to weights.
- **Redundant scheduling**: verify duplicate packets on both paths.
- **SinglePath stealth mode**: verify only primary path sends; standby paths
  are validated but carry no traffic. On primary failure, failover to standby.
- **Per-path CC independence**: inject 10% loss on path A; verify path B's
  cwnd is unaffected.
- **Multipath disabled regression**: `multipath_enabled = false` preserves
  current single-path behavior exactly. All existing migration tests pass.

### Performance tests
- Dual-path throughput vs single-path: expect ~1.8× improvement (not 2× due
  to per-path overhead).
- Failover latency: < 100ms from path failure to first packet on standby path
  (when standby is pre-validated).
- Scheduler overhead: < 100ns per select_path call for 4 paths.

## Files to Create/Modify

- `src/transport/path.rs` — **new**: `Path`, `PathState`, `PathHealth` structs.
- `src/transport/path_manager.rs` — **new**: `PathManager` struct, path
  lifecycle management, failover logic.
- `src/transport/scheduler.rs` — **new**: `PacketScheduler` trait + 5
  strategies (LowestRtt, RoundRobin, Weighted, Redundant, SinglePath).
- `src/transport/connection.rs` — replace single-path fields with
  `PathManager`; update send/recv/ACK/loss dispatch; update migration logic;
  generalize `begin_path_validation` for concurrent validations.
- `src/transport/cc/mod.rs` — allow multiple `CcImpl` instances per connection
  (already possible — `CcImpl` is not `Copy`, just needs to be owned by `Path`).
- `src/transport/recovery.rs` — per-path loss detection / packet number
  spaces. Either refactor `Recovery` to be per-path or move loss detection
  state into `Path`.
- `src/transport/frames.rs` — `PATH_NEW`, `PATH_ABANDON`, `PATH_STATUS`,
  `ACK_MP` frame types.
- `src/transport/config.rs` — multipath config fields + setters + enums.
- `src/transport.rs` — re-export `MultipathStrategy`, `Path`, `PathManager`,
  `PacketScheduler`; add module declarations.
- `src/transport/transport_params.rs` (or equivalent) — `initial_max_path_id`
  transport parameter.
- Tests: `src/transport/path.rs` (unit), `src/transport/scheduler.rs` (unit),
  `src/transport/path_manager.rs` (unit), integration test for dual-path
  send + failover.

## Risks & Mitigations

| Risk | Impact | Mitigation |
|------|--------|------------|
| Per-path PN spaces break existing AEAD nonce computation | High — security | Nonce = `path_id * 2^62 + pn`; audit all nonce computation sites; add test vectors |
| `PathManager` refactor breaks single-path callers | High — regression | Backward compat accessors delegate to primary path; `multipath_enabled = false` uses single-path `PathManager` with one path |
| Scheduler introduces send-path latency | Medium — performance | Scheduler is O(n) for n≤4 paths; < 100ns per call; no lock contention |
| Multipath frames confuse non-multipath peers | High — interop | Only send multipath frames when `initial_max_path_id > 0` negotiated; peers without the extension ignore unknown frames |
| Multiple source IPs leak to DPI | High — stealth | `SinglePath` stealth mode is default; multipath sending requires explicit opt-in |
| draft-ietf-quic-multipath-21 not yet RFC | Medium — stability | Draft is at IESG evaluation (final stage); wire format is stable; track any last-minute changes |
| Memory growth with many paths | Low — resource | `max_paths` config enforces upper bound; default 2 (WiFi + LTE) |
| Per-path loss detection complexity | Medium — correctness | Each path has independent loss_time, PTO, sent_packets; no cross-path loss inference |

## Completion Criteria

- [ ] Two paths (WiFi + simulated LTE via tc-netem on two loopback aliases) can
      be active simultaneously on one connection.
- [ ] Traffic is distributed across both paths (verifiable by per-path byte
      counters in `Stats`).
- [ ] When one path drops (interface removed / 100% loss), the connection
      survives using the remaining path with no disconnect.
- [ ] `lowest-rtt` strategy preferentially uses the lower-RTT path.
- [ ] `weighted` strategy distributes bytes proportional to configured weights.
- [ ] `redundant` strategy sends duplicate packets on all active paths.
- [ ] `single-path` stealth mode sends only on primary; standby paths carry no
      traffic; failover to standby is immediate on primary failure.
- [ ] Per-path cwnd is independent — losing packets on one path does not reduce
      cwnd on the other.
- [ ] `multipath_enabled = false` preserves current single-path behavior exactly
      (no regression in existing migration tests).
- [ ] `initial_max_path_id` transport parameter is negotiated correctly.
- [ ] PATH_NEW, PATH_ABANDON, PATH_STATUS, ACK_MP frames encode/decode correctly.
- [ ] Unit tests for `PacketScheduler` strategy selection logic (all 5).
- [ ] Unit tests for `Path` state transitions (Probing→Active→Standby→Failed).
- [ ] Unit tests for `PathManager` add/remove/validate/promote operations.
- [ ] Per-path nonce computation test vectors (path_id * 2^62 + pn).
- [ ] Dual-path throughput ≥ 1.5× single-path throughput.
- [ ] Failover latency < 100ms when standby path is pre-validated.
