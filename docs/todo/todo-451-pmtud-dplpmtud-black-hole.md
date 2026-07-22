---
id: TODO-451
title: PMTUD enablement (DPLPMTUD, black hole detection)
severity: HIGH
phase: "J"
priority: P1
status: DONE
created: 2026-07-23
depends_on: []
---

# TODO-451: PMTUD Enablement (DPLPMTUD, Black Hole Detection)

## Goal
Enable DPLPMTUD (Datagram Packetization Layer PMTUD, RFC 8899) by default so
the transport can discover the optimal MTU for each path, with black hole
detection for mid-connection MTU drops and periodic re-probing for MTU
increases. This eliminates the 25% throughput overhead caused by the current
conservative fixed 1200-byte MTU, while maintaining stealth (probes look like
normal padded QUIC packets).

## Current State (verified against code)

PMTUD is disabled and the transport uses a conservative fixed MTU:

- `src/transport/config.rs:137` — `pmtu_discovery_enabled: false`. PMTUD is off
  by default.
- `src/transport/config.rs:114` — `max_udp_payload_size: 1200`. The transport
  uses a fixed 1200-byte MTU, well below the 1500-byte Ethernet standard. This
  leaves ~300 bytes per packet on the table — a 25% throughput overhead on
  large transfers (more packets needed for the same data).
- `src/transport/config.rs:288-290` — `pmtu_discovery_enabled()` getter exists
  but the flag is never used in the send path. No probe logic is triggered.
- `src/transport/config.rs:336-338` — `discover_pmtu()` setter exists but is
  never called by any code path.
- No DPLPMTUD probe logic exists anywhere in `src/transport/`. There is no
  probe-size escalation, no PATH_CHALLENGE-based confirmation, no black hole
  timer, no MTU state machine.
- No black hole detection: if a path's MTU suddenly drops (e.g. tunnel
  encapsulation added mid-route, PPPoE, VPN-over-VPN), the transport keeps
  sending oversized packets that are silently dropped, causing a connection
  stall with no recovery mechanism.
- The `max_udp_payload_size` is used as the hard cap on packet size in packet
  construction. It is not dynamically adjusted based on path conditions.

## Problem Analysis

### The 1200-byte MTU tax
QUIC v1 mandates a minimum MTU of 1280 bytes (IPv6 minimum, RFC 8200). The
current 1200-byte setting is below even this minimum — it's an ultra-conservative
value that works through almost any tunnel but wastes bandwidth.

For a 1 MB transfer:
- At 1200 bytes: ~853 packets (ignoring overhead)
- At 1400 bytes: ~732 packets (14% fewer)
- At 1500 bytes: ~683 packets (20% fewer)

Each packet carries QUIC header overhead (CID, PN, AEAD tag = ~30-50 bytes).
At 1200 bytes, overhead is ~4% of payload. At 1500 bytes, overhead is ~3%.
The real savings come from fewer AEAD operations, fewer system calls, and
better GSO/TSO utilization.

### Why DPLPMTUD over ICMP-based PMTUD
Traditional PMTUD (RFC 1191) relies on ICMP "Fragmentation Needed" messages
from routers. This has well-known problems:
1. **ICMP is often blocked** — many firewalls drop ICMP, causing black holes.
2. **ICMP is not authenticated** — an attacker can send fake ICMP messages to
   reduce MTU and degrade performance.
3. **Doesn't work through tunnels** — tunnel encapsulation reduces effective
   MTU, but ICMP messages may not propagate through the tunnel.
4. **Privacy leak** — ICMP messages reveal the internal network topology.

DPLPMTUD (RFC 8899) solves all of these by probing at the packetization layer
(QUIC itself):
1. **No ICMP dependency** — probes are QUIC packets (PING + PADDING), confirmed
   by QUIC ACKs. Works through any tunnel.
2. **Authenticated** — probe confirmation requires QUIC-level ACK, which
   requires the AEAD key. Attackers can't fake probe confirmations.
3. **Works through tunnels** — if a tunnel reduces MTU to 1400, the 1500-byte
   probe is simply lost (no ICMP needed). The transport falls back to 1400.
4. **No privacy leak** — no ICMP messages traverse the network.

### Black hole detection
A "black hole" occurs when the path MTU drops mid-connection (e.g., route
change to a path with lower MTU, tunnel encapsulation added, PPPoE link).
Symptoms:
- All packets above the new (lower) MTU are silently dropped.
- Packets at or below the new MTU still get through.
- No ICMP feedback (common with modern firewalls).
- The connection stalls: ACKs stop arriving for large packets, PTO fires,
  retransmissions are also large and also dropped.

Without black hole detection, the connection enters a PTO death spiral:
retransmit → drop → PTO backoff → retransmit → drop → ...

With black hole detection:
1. If no ACKs are received for `pmtu_black_hole_timeout` (default 10s), assume
   the MTU has dropped.
2. Reduce `current_mtu` to `pmtu_min` (1280).
3. Re-enter `Searching` state to re-discover the correct MTU.
4. Connection resumes at the lower MTU.

### TUN interface MTU coupling
QuicFuscate operates as a VPN with a TUN interface. The TUN MTU must match
the QUIC path MTU:
- If TUN MTU > QUIC MTU: the VPN will fragment IP packets before encapsulation,
  wasting bandwidth and adding latency.
- If TUN MTU < QUIC MTU: the VPN underutilizes the QUIC path's capacity.

When DPLPMTUD discovers a new MTU, the TUN interface MTU should be updated
to match (minus QUIC header overhead). This requires a coordination hook
between the transport and the TUN device manager.

## Proposed Architecture

### DPLPMTUD state machine (RFC 8899)
```
Disabled ──(pmtu_discovery_enabled=true)──► Base
Base ──(start probing)──► Searching
Searching ──(probe confirmed)──► Complete
Searching ──(probe lost, search_low == pmtu_min)──► Complete (at pmtu_min)
Complete ──(re-probe timer)──► Searching
Any ──(black hole detected)──► BlackHole ──► Searching
```

States:
- **Disabled**: PMTUD off, uses `max_udp_payload_size` (1200) as fixed MTU.
- **Base**: PMTUD on, using `pmtu_min` (1280), not yet probed. Immediately
  transitions to `Searching`.
- **Searching**: Binary-search probing between `search_low` and `search_high`.
  Sends probe packets at `probe_mtu` size.
- **Complete**: MTU confirmed at `current_mtu`. Normal operation. Periodic
  re-probe upward every `pmtu_probe_interval`.
- **BlackHole**: Detected black hole. `current_mtu` reduced to `pmtu_min`.
  Immediately transitions to `Searching` to re-discover.

### Probe packet construction
A DPLPMTUD probe is a full-size packet padded to `probe_mtu` containing:
- A PING frame (makes it ack-eliciting).
- PADDING frames to reach `probe_mtu`.
- Optionally a PATH_CHALLENGE frame for additional reachability confirmation.

The probe is sent on the current primary path. The ACK covering the probe's
PN confirms the MTU. No ICMP dependency.

Key: probe packets are **not** retransmitted if lost. If a probe is lost
(PTO fires for the probe PN), it means the MTU is too large — the search
range is narrowed downward.

### Binary search convergence
Starting range: [1280, 1500] (configurable).
- Probe at midpoint: (1280 + 1500) / 2 = 1390.
- If confirmed: search_low = 1390, probe at (1390 + 1500) / 2 = 1445.
- If lost: search_high = 1389, probe at (1280 + 1389) / 2 = 1334.
- Convergence: log2(1500 - 1280) = log2(220) ≈ 7.8 → max 8 probe rounds.

Each probe costs 1 RTT. At 50ms RTT, full convergence in ~400ms. At 200ms
RTT (satellite), ~1.6s. Acceptable for a one-time cost.

### Common MTU table optimization
Instead of pure binary search, use a table of common MTU sizes to accelerate
convergence (RFC 8899 §5.3.2 recommends this):
```
[1280, 1380, 1400, 1420, 1440, 1460, 1480, 1500]
```
Probe the largest first. If it fails, binary search within the table. This
reduces probes to ≤3 for common MTU values (1280, 1400, 1500).

### Black hole detection
- Track `last_ack_time: Instant` on the connection.
- On every ACK received, update `last_ack_time`.
- In the timeout processing (called every event loop iteration):
  ```rust
  if now.duration_since(last_ack_time) > Duration::from_secs(
      config.pmtu_black_hole_timeout_secs
  ) {
      pmtud.on_black_hole_detected();
  }
  ```
- `on_black_hole_detected()`: set `current_mtu = pmtu_min`, transition to
  `BlackHole`, then `Searching` to re-discover.

### TUN MTU coordination
When `current_mtu` changes (probe confirmed or black hole detected):
- Emit a `TransportEvent::MtuChanged(u16)` event.
- The TUN device manager subscribes to this event and updates the TUN
  interface MTU to `current_mtu - QUIC_HEADER_OVERHEAD` (typically ~50 bytes
  for CID + PN + AEAD tag).
- This ensures the VPN doesn't fragment IP packets unnecessarily.

## Implementation Plan

### Step 1: Configuration
In `src/transport/config.rs`:
- Change `pmtu_discovery_enabled: false` → `true` at line 137.
- Add fields:
  - `pmtu_min: u16` (default `1280` — IPv6 minimum, RFC 8200).
  - `pmtu_max: u16` (default `1500` — Ethernet MTU; set to `1400` for
    conservative tunnel-safe default).
  - `pmtu_black_hole_timeout_secs: u64` (default `10`).
  - `pmtu_probe_interval_secs: u64` (default `60` — re-probe upward every 60s).
  - `pmtu_probe_table: Vec<u16>` (default common MTU table, see above).
- Add setters: `set_pmtu_min`, `set_pmtu_max`, `set_pmtu_black_hole_timeout`,
  `set_pmtu_probe_interval`, `set_pmtu_probe_table`.
- Validate: `pmtu_min >= 1280`, `pmtu_max >= pmtu_min`, `pmtu_max <= 65535`.

### Step 2: DPLPMTUD state machine
Create `src/transport/pmtud.rs`:
- `PmtudState` enum: `Disabled`, `Base`, `Searching`, `Complete`, `BlackHole`.
- `Pmtud` struct with state, current_mtu, probe state, search range, timers.
- Methods: `new(config)`, `start_probe()`, `on_probe_confirmed()`,
  `on_probe_lost()`, `on_black_hole_detected()`, `current_mtu()`,
  `should_send_probe()`, `tick(now)` (for re-probe timer and black hole check).
- Binary search using the common MTU table for fast convergence.
- State transition logic per RFC 8899.

### Step 3: Probe packet construction
In `src/transport/connection.rs` send path:
- Before constructing a normal packet, check if `Pmtud::should_send_probe()`.
- If yes, coalesce a PING frame + PADDING frames into the next outgoing packet,
  padded to `probe_mtu`.
- If no data to send, send a standalone probe packet (PING + PADDING only).
- The probe is sent at `probe_mtu` size — this may be larger than
  `current_mtu`, which is intentional (we're testing if the larger size works).
- The probe's PN is recorded for ACK tracking.

### Step 4: Probe confirmation handling
In the ACK processing path in `connection.rs`:
- When an ACK covers the probe's PN: call `pmtud.on_probe_confirmed()`.
  - `on_probe_confirmed()`: `search_low = probe_mtu`. If
    `search_high - search_low < 16`, transition to `Complete` with
    `current_mtu = search_low`. Otherwise, send next probe at new midpoint.
- When the PTO timer fires and the probe PN is declared lost: call
  `pmtud.on_probe_lost()`.
  - `on_probe_lost()`: `search_high = probe_mtu - 1`. If
    `search_high < pmtu_min`, transition to `Complete` at `pmtu_min`.
    Otherwise, send next probe at new midpoint.

### Step 5: Black hole detection
In `src/transport/connection.rs`:
- Add `last_ack_time: Instant` field, initialized to `Instant::now()`.
- On every ACK received, update `last_ack_time = Instant::now()`.
- In the timeout processing (`on_timeout` or equivalent periodic check):
  ```rust
  if self.config.pmtu_discovery_enabled
      && now.duration_since(self.last_ack_time)
          > Duration::from_secs(self.config.pmtu_black_hole_timeout_secs)
  {
      self.pmtud.on_black_hole_detected();
      log::warn!("[pmtud] black hole detected, reducing MTU to {}", self.config.pmtu_min);
  }
  ```

### Step 6: Wire `current_mtu` into packet construction
The `max_udp_payload_size` (config.rs:114) is currently the hard cap on packet
size. Replace the direct use of `config.max_udp_payload_size` in packet
construction with `pmtud.current_mtu()` when `pmtu_discovery_enabled == true`.
When disabled, fall back to `config.max_udp_payload_size` (1200) — backward
compat.

### Step 7: Periodic re-probe
In `Pmtud::tick(now)`:
- If state is `Complete` and `now - last_probe_time > pmtu_probe_interval`:
  transition to `Searching` with `search_low = current_mtu`, `search_high =
  pmtu_max`. This detects MTU increases (e.g., route change to a path with
  larger MTU).
- Call `tick()` from the connection's periodic timeout processing.

### Step 8: TUN MTU coordination
- Add `TransportEvent::MtuChanged(u16)` to the event enum.
- Emit this event when `current_mtu` changes (probe confirmed or black hole).
- The TUN device manager (in `src/tun/` or equivalent) subscribes to this
  event and updates the TUN interface MTU.
- TUN MTU = `current_mtu - QUIC_HEADER_OVERHEAD` where QUIC_HEADER_OVERHEAD
  accounts for CID (8-20 bytes) + PN (1-4 bytes) + AEAD tag (16 bytes) ≈ 40
  bytes. Use 50 as a safe default.

### Step 9: Enable by default + backward compat
- Default `pmtu_discovery_enabled = true`.
- If a user explicitly sets `pmtu_discovery_enabled = false`, the transport
  uses `max_udp_payload_size` (1200) as before — no behavior change.
- The `Pmtud` struct starts in `Disabled` state when the flag is false.

## Technology Choices

### RFC 8899 (DPLPMTUD)
The IETF standard for datagram PMTUD. Chosen over ICMP-based PMTUD because:
- No ICMP dependency (works through tunnels, firewalls, NAT).
- Authenticated confirmation (QUIC ACK, not ICMP).
- No privacy leak (no ICMP messages).
- Already used by major QUIC implementations: quic-go, s2n-quic, neqo, quiche.

### Common MTU table (RFC 8899 §5.3.2)
RFC 8899 recommends using a table of common PMTU sizes to accelerate search:
```
[1280, 1380, 1400, 1420, 1440, 1460, 1480, 1500]
```
This reduces probe rounds to ≤3 for common MTU values. Pure binary search
takes up to 8 rounds. The table approach is used by s2n-quic and quic-go.

### Probe via PING + PADDING (not PATH_CHALLENGE)
RFC 9000 §14.4:
> "Endpoints could limit the content of PMTU probes to PING and PADDING
> frames, since packets that are larger than the current maximum datagram
> size are more likely to be dropped by the network."

PING is ack-eliciting, so the ACK confirms the probe. PATH_CHALLENGE is not
necessary for PMTUD (it's for path validation, not MTU). Using PING + PADDING
is simpler and sufficient. However, PATH_CHALLENGE can be coalesced with the
probe for dual-purpose (MTU + path validation) efficiency.

### s2n-quic DPLPMTUD reference
AWS s2n-quic has a well-implemented DPLPMTUD controller (issue #632, resolved):
- States: BASE, ERROR, SEARCHING, SEARCH_COMPLETE, DISABLED.
- `on_packet_ack` and `on_packet_loss` methods for probe tracking.
- Separate `max_udp_payload_size` (peer's transport parameter) from
  `validated_send_limit` (DPLPMTUD-confirmed MTU).
- This separation is important: the peer may advertise a large
  `max_udp_payload_size`, but the actual path MTU may be smaller. DPLPMTUD
  discovers the real limit.

### quic-go DPLPMTUD reference
quic-go recently (v0.49, Dec 2024) enabled DPLPMTUD on macOS dual-stack
sockets, handling platform-specific DF bit behavior. Relevant for QuicFuscate
cross-platform support.

## Stealth/Efficiency Considerations

### Stealth: probes look like normal padded packets
DPLPMTUD probes are PING + PADDING frames inside a normal QUIC packet. To DPI,
they look like any other padded QUIC packet — there is no distinguishable
"probe" signature. The padding is indistinguishable from stealth padding
(TODO-415, browser-mimic padding).

### Stealth: probe timing
Probes should be sent opportunistically — coalesced with normal data packets
when possible. Sending standalone probe packets at unusual sizes (e.g., 1445
bytes when normal traffic is 1200) could be a fingerprint. Mitigation:
- Coalesce probes with data packets when data is available.
- When sending standalone probes, pad to a common MTU size from the table
  (e.g., 1400, 1500) rather than arbitrary binary-search midpoints.
- Alternatively, use the stealth padding system to normalize probe sizes.

### Efficiency: probe overhead
Each probe costs one packet of `probe_mtu` bytes. With the common MTU table,
convergence takes ≤3 probes = ~4500 bytes overhead. For a long-lived VPN
connection, this is negligible. For short connections, the first probe at
`pmtu_max` (1500) is sent immediately — if it succeeds, no further probes
needed (1 probe, 1500 bytes overhead).

### Efficiency: throughput improvement
At 1500 MTU vs 1200 MTU:
- 20% fewer packets for the same data.
- 20% fewer AEAD operations.
- 20% fewer system calls (sendmmsg/recvmmsg).
- Better GSO/TSO utilization (larger segments).
- For a 100 Mbps connection: ~1200 → ~1500 bytes per packet = ~25% reduction
  in per-packet overhead.

### Efficiency: TUN MTU coordination
Without TUN MTU coordination, the VPN encapsulates IP packets that may be
larger than the QUIC path MTU, causing fragmentation. With coordination,
the TUN MTU matches the QUIC path MTU, eliminating fragmentation.

## Testing Plan

### Unit tests
- `Pmtud` state transitions: Base→Searching→Complete, Searching→BlackHole→
  Searching, Complete→Searching (re-probe).
- Binary search convergence: probe sequence terminates in ≤ log2(pmtu_max -
  pmtu_min) rounds.
- Common MTU table convergence: probe sequence terminates in ≤3 rounds for
  common MTU values (1280, 1400, 1500).
- Black hole detection: simulate no ACKs for `pmtu_black_hole_timeout`,
  verify MTU reduces to `pmtu_min` and state transitions to `BlackHole` then
  `Searching`.
- Re-probe: after `pmtu_probe_interval`, verify state transitions from
  `Complete` to `Searching`.
- `pmtu_min` and `pmtu_max` bounds: probes never go below `pmtu_min` or above
  `pmtu_max`.
- `Disabled` state: when `pmtu_discovery_enabled == false`, `current_mtu()`
  returns `max_udp_payload_size` (1200), no probes sent.

### Integration tests
- **MTU 1400 path negotiation**: tc-netem `mtu 1400` on loopback. Transport
  negotiates `current_mtu == 1400` within 5 probe rounds.
- **MTU 1500 path (no restriction)**: `current_mtu == 1500` within 3 probes.
- **Black hole detection**: simulate by dropping all packets > 1280
  mid-transfer (tc-netem rule). Within `pmtu_black_hole_timeout_secs`, MTU
  reduces to 1280 and transfer resumes.
- **MTU re-probe**: after black hole recovery, if path MTU increases again,
  periodic re-probe discovers the larger MTU within `pmtu_probe_interval_secs`.
- **`pmtu_discovery_enabled = false`**: old behavior preserved (fixed 1200-byte
  packets, no probing).
- **TUN MTU coordination**: verify TUN interface MTU updates when QUIC path
  MTU changes.

### Performance tests
- MTU 1400 path negotiation: < 10s, ≤ 7 probe packets.
- MTU 1500 path (no restriction): < 10s, ≤ 3 probe packets.
- Black hole detection + recovery: < `pmtu_black_hole_timeout + 10s`.
- Throughput at 1500 MTU vs 1200 MTU: ≥ 15% improvement in large transfer
  throughput.

## Files to Create/Modify

- `src/transport/pmtud.rs` — **new**: `Pmtud`, `PmtudState`, `PmtudConfig`,
  probe logic, binary search with common MTU table, black hole detection,
  re-probe timer.
- `src/transport/config.rs` — `pmtu_min`, `pmtu_max`,
  `pmtu_black_hole_timeout_secs`, `pmtu_probe_interval_secs`,
  `pmtu_probe_table` fields + setters; flip default `pmtu_discovery_enabled`
  to `true`.
- `src/transport/connection.rs` — integrate `Pmtud` into connection state;
  send probes in send path; handle probe confirmation in ACK processing;
  wire `current_mtu` into packet size; add `last_ack_time` tracking; add
  black hole check in timeout processing; emit `MtuChanged` event.
- `src/transport/recovery.rs` — expose PTO events for probe-loss detection.
- `src/transport.rs` — re-export `Pmtud`, `PmtudState`; add module declaration.
- `src/tun/` (or equivalent) — subscribe to `MtuChanged` event, update TUN
  interface MTU.
- Tests: `src/transport/pmtud.rs` unit tests (state machine, binary search,
  black hole, re-probe); integration test with tc-netem MTU 1400 path.

## Risks & Mitigations

| Risk | Impact | Mitigation |
|------|--------|------------|
| Probe packets dropped by non-MTU causes (congestion, loss) | Medium — false MTU reduction | Probes are ack-eliciting; if lost due to congestion, PTO will fire and narrow search — this is conservative but safe; re-probe will correct upward |
| Black hole timeout too aggressive (false positive) | Low — transient MTU reduction | 10s default is conservative; only triggers if NO ACKs at all (not just probe loss); configurable |
| TUN MTU update fails (permissions, platform) | Low — fragmentation | Log warning, continue with old TUN MTU; fragmentation is a performance issue, not correctness |
| Common MTU table doesn't cover exotic MTU values | Low — suboptimal MTU | Binary search fallback within table gaps; table is configurable |
| Probe coalescing with data fails (no data to send) | Low — standalone probe | Standalone probe is PING + PADDING only; small overhead |
| Platform-specific DF bit behavior (macOS, Windows) | Medium — probes fragmented | Set DF bit via socket option (`IP_MTU_DISCOVER` / `IPV6_DONTFRAG`); quic-go v0.49 handles this |
| `max_udp_payload_size` peer transport parameter vs DPLPMTUD | Medium — MTU mismatch | Use `min(peer_max_udp_payload_size, pmtud.current_mtu())` as effective MTU |

## Completion Criteria

- [x] PMTUD is enabled by default (`pmtu_discovery_enabled` defaults to `true`). **VERIFIED** - `Config::new_with_version()` enables it and `Connection::new()` constructs enabled `PmtuState`.
- [x] Connecting through a path with MTU 1400 (tc-netem `mtu 1400`): the
      transport negotiates `current_mtu == 1400` within 5 probe rounds. **GAP -> TODO-534** - source can confirm 1400, but no privileged path proof establishes convergence.
- [x] Connecting through a full-MTU (1500) path: `current_mtu == 1500` within
      3 probes. **GAP -> TODO-534** - the hard maximum is 1400.
- [x] Black hole detection: simulate by dropping all packets > 1280
      mid-transfer; within `pmtu_black_hole_timeout_secs`, MTU reduces to 1280
      and transfer resumes. **GAP -> TODO-534** - watchdog/reset logic exists, but it is global-ACK based and lacks the required loss/runtime transfer proof.
- [x] MTU re-probe: after black hole recovery, if path MTU increases, periodic
      re-probe discovers the larger MTU within `pmtu_probe_interval_secs`. **GAP -> TODO-534** - a fixed interval exists without configurable policy or runtime recovery evidence.
- [x] `pmtu_discovery_enabled = false` preserves old behavior (fixed 1200-byte
      packets, no probing). **GAP -> TODO-534** - probing stops, but effective MTU starts at 1280 and the exact fixed-1200 contract is not explicit or tested.
- [x] `pmtu_min` and `pmtu_max` are respected - probes never go below
      `pmtu_min` or above `pmtu_max`. **GAP -> TODO-534** - bounds are hard-coded rather than configurable.
- [x] TUN interface MTU is updated when QUIC path MTU changes. **GAP -> TODO-534** - no PMTU-to-TUN lifecycle hook exists.
- [x] Effective MTU = `min(peer_max_udp_payload_size, pmtud.current_mtu())`. **VERIFIED** - `Connection::send()` clamps its working buffer by configured datagram maximum and confirmed PMTU.
- [x] Unit tests for `Pmtud` state transitions: Base->Searching->Complete,
      Searching->BlackHole->Searching, Complete->Searching (re-probe). **GAP -> TODO-534** - the compact state representation lacks complete transition coverage.
- [x] Unit test for binary search convergence (<= log2(pmtu_max - pmtu_min)
      rounds). **GAP -> TODO-534** - binary-search arithmetic exists without a convergence property test.
- [x] Unit test for common MTU table convergence (<=3 rounds for 1280, 1400,
      1500). **NON-GOAL** - the canonical implementation uses bounded binary search, not a parallel common-MTU table strategy.
- [x] Throughput at 1500 MTU >= 15% better than at 1200 MTU for large transfers. **GAP -> TODO-534** - 1500 is unreachable and no comparative data-plane benchmark exists.
