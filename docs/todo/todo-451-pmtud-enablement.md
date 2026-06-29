---
id: TODO-451
title: DPLPMTUD enablement and black hole detection
severity: HIGH
phase: "J"
priority: P1
status: OPEN
created: 2026-06-30
depends_on: []
---

# TODO-451: DPLPMTUD Enablement and Black Hole Detection

## Problem

Path MTU Discovery (PMTUD) is **disabled by default**, and the implementation
lacks DPLPMTUD (Datagram Packetization Layer PMTUD, RFC 8899), black hole
detection, and MTU re-probing. This means the transport cannot discover the
optimal MTU for a path and cannot react when the effective MTU drops.

Evidence:

- `src/transport/config.rs:137` — `pmtu_discovery_enabled: false`. PMTUD is off
  by default.
- `src/transport/config.rs:114` — `max_udp_payload_size: 1200`. The transport
  uses a conservative fixed 1200-byte MTU, well below the 1500-byte Ethernet
  standard. This leaves ~300 bytes per packet on the table — a 25% throughput
  overhead on large transfers.
- No DPLPMTUD probe logic exists anywhere in `src/transport/`. There is no
  probe-size escalation, no PATH_CHALLENGE-based confirmation, no black hole
  timer.
- No black hole detection: if a path's MTU suddenly drops (e.g. tunnel
  encapsulation added mid-route), the transport keeps sending oversized packets
  that are silently dropped, causing a connection stall.

## Goal

Implement RFC 8899 DPLPMTUD with black hole detection and MTU re-probing:

1. **Enable PMTUD by default** — `pmtu_discovery_enabled: true`.
2. **DPLPMTUD probing** — probe with increasing packet sizes, confirm probe
   success via PATH_CHALLENGE / PATH_RESPONSE (or ACK of the probe packet).
3. **Black hole detection** — if no ACKs are received for > `pmtu_black_hole_timeout`,
   reduce MTU to the minimum (1280) and re-probe.
4. **MTU confirmation / re-probe** — periodically re-probe upward to detect MTU
   increases (e.g. route change to a path with larger MTU).
5. **Config knobs**: `pmtu_discovery_enabled` (default true), `pmtu_min`
   (default 1280), `pmtu_max` (default 1500), `pmtu_black_hole_timeout_secs`
   (default 10).

## Implementation Plan

### Step 1: Configuration

In `src/transport/config.rs`:

- Change `pmtu_discovery_enabled: false` → `true` at line 137.
- Add fields:
  - `pmtu_min: u16` (default `1280` — IPv6 minimum, RFC 8200).
  - `pmtu_max: u16` (default `1500` — Ethernet MTU).
  - `pmtu_black_hole_timeout_secs: u64` (default `10`).
  - `pmtu_probe_interval_secs: u64` (default `60` — re-probe upward every 60s).
- Add setters: `set_pmtu_min`, `set_pmtu_max`, `set_pmtu_black_hole_timeout`,
  `set_pmtu_probe_interval`.
- Validate: `pmtu_min >= 1280`, `pmtu_max >= pmtu_min`,
  `pmtu_max <= 65535`.

### Step 2: DPLPMTUD state machine

Create `src/transport/pmtud.rs`:

```rust
pub enum PmtudState {
    Disabled,
    Base,           // Using pmtu_min, not yet probed
    Searching,      // Binary-search probing between current and pmtu_max
    Complete,       // MTU confirmed, using discovered value
    BlackHole,      // Detected black hole, reduced to pmtu_min, re-probing
}

pub struct Pmtud {
    state: PmtudState,
    current_mtu: u16,
    probe_mtu: u16,        // size of the probe packet in flight
    probe_in_flight: bool,
    probe_sent_at: Option<Instant>,
    search_low: u16,
    search_high: u16,
    last_confirmed_mtu: u16,
    last_probe_time: Instant,
    config: PmtudConfig,
}
```

The state machine:

1. `Base` → `Searching`: send first probe at `pmtu_max`.
2. `Searching`: binary search between `search_low` and `search_high`.
   - Probe confirmed (PATH_RESPONSE received or ACK for probe PN) →
     `search_low = probe_mtu`; if `search_high - search_low < 16`, transition to
     `Complete` with `current_mtu = search_low`.
   - Probe lost (PTO fires for probe packet) → `search_high = probe_mtu - 1`;
     re-probe at midpoint.
3. `Complete` → `Complete`: periodically (every `pmtu_probe_interval`) re-probe
   upward to detect MTU increase.
4. Any state → `BlackHole`: if no ACKs for `pmtu_black_hole_timeout`, set
   `current_mtu = pmtu_min`, transition to `BlackHole`, then re-enter
   `Searching`.

### Step 3: Probe packet construction

A DPLPMTUD probe is a full-size packet (padded to `probe_mtu`) containing:

- A PATH_CHALLENGE frame (8-byte random) — confirms reachability.
- A PING frame (makes it ack-eliciting).
- PADDING frames to reach `probe_mtu`.

The probe is sent on the current primary path. The PATH_RESPONSE (or ACK
covering the probe's PN) confirms the MTU.

Integrate into `src/transport/connection.rs` send path:

- Before constructing a normal packet, check if `Pmtud` wants to send a probe.
- If `probe_in_flight == false` and state is `Searching` or re-probe timer
  elapsed, coalesce the probe into the next outgoing packet (or send a
  standalone probe if no data to send).

### Step 4: Probe confirmation handling

In the ACK / PATH_RESPONSE processing path in `connection.rs`:

- When a PATH_RESPONSE matches the probe's challenge, or an ACK covers the
  probe's PN: call `pmtud.on_probe_confirmed()`.
- When the PTO timer fires and the probe PN is declared lost: call
  `pmtud.on_probe_lost()`.

### Step 5: Black hole detection

In the loss detection / PTO path (`src/transport/recovery.rs` or
`connection.rs`):

- Track `last_ack_time: Instant` on the connection.
- On every ACK received, update `last_ack_time`.
- In the timeout processing (called every event loop iteration), check:
  ```rust
  if now.duration_since(last_ack_time) > Duration::from_secs(config.pmtu_black_hole_timeout_secs) {
      pmtud.on_black_hole_detected();
  }
  ```
- `on_black_hole_detected()`: set `current_mtu = pmtu_min`, transition to
  `BlackHole`, then `Searching` to re-discover the MTU.

### Step 6: Wire `current_mtu` into packet construction

The `max_udp_payload_size` (config.rs:114) is currently the hard cap on packet
size. Replace the direct use of `config.max_udp_payload_size` in packet
construction with `pmtud.current_mtu()` when `pmtu_discovery_enabled == true`.
When disabled, fall back to `config.max_udp_payload_size` (backward compat).

### Step 7: Enable by default + backward compat

- Default `pmtu_discovery_enabled = true`.
- If a user explicitly sets `pmtu_discovery_enabled = false`, the transport uses
  `max_udp_payload_size` (1200) as before — no behavior change.
- The `Pmtud` struct starts in `Disabled` state when the flag is false.

## Files to Modify/Create

- `src/transport/pmtud.rs` — **new**: `Pmtud`, `PmtudState`, `PmtudConfig`,
  probe logic, binary search, black hole detection, re-probe timer.
- `src/transport/config.rs` — `pmtu_min`, `pmtu_max`,
  `pmtu_black_hole_timeout_secs`, `pmtu_probe_interval_secs` fields + setters;
  flip default `pmtu_discovery_enabled` to `true`.
- `src/transport/connection.rs` — integrate `Pmtud` into connection state; send
  probes in send path; handle probe confirmation in ACK/PATH_RESPONSE
  processing; wire `current_mtu` into packet size; add `last_ack_time` tracking.
- `src/transport/recovery.rs` — expose PTO events for probe-loss detection.
- `src/transport.rs` — re-export `Pmtud`, `PmtudState`; add module declaration.
- Tests: `src/transport/pmtud.rs` unit tests (state machine, binary search,
  black hole); integration test with tc-netem MTU 1400 path.

## Acceptance Criteria

- [ ] PMTUD is enabled by default (`pmtu_discovery_enabled` defaults to `true`).
- [ ] Connecting through a path with MTU 1400 (tc-netem `mtu 1400`): the
      transport negotiates `current_mtu == 1400` within 5 probe rounds.
- [ ] Connecting through a full-MTU (1500) path: `current_mtu == 1500`.
- [ ] Black hole detection: simulate by dropping all packets > 1280 mid-transfer;
      within `pmtu_black_hole_timeout_secs`, MTU reduces to 1280 and transfer
      resumes.
- [ ] MTU re-probe: after black hole recovery, if the path MTU increases again,
      the periodic re-probe discovers the larger MTU within
      `pmtu_probe_interval_secs`.
- [ ] `pmtu_discovery_enabled = false` preserves the old behavior (fixed 1200-byte
      packets, no probing).
- [ ] `pmtu_min` and `pmtu_max` are respected — probes never go below `pmtu_min`
      or above `pmtu_max`.
- [ ] Unit tests for `Pmtud` state transitions: Base→Searching→Complete,
      Searching→BlackHole→Searching, Complete→Searching (re-probe).
- [ ] Unit test for binary search convergence (probe sequence terminates in ≤
      log2(pmtu_max - pmtu_min) rounds).

## Resource Budget

| Scenario | Budget | Notes |
|----------|--------|-------|
| MTU 1400 path negotiation | < 10s, ≤ 7 probe packets | Binary search convergence |
| MTU 1500 path (no restriction) | < 10s, ≤ 3 probe packets | First probe at 1500 succeeds |
| Black hole detection + recovery | < pmtu_black_hole_timeout + 10s | Detect → reduce → resume |
| Re-probe upward | < pmtu_probe_interval + 10s | Periodic re-probe |
| State machine unit tests | < 3s | All transitions |
| Binary search convergence test | < 2s | log2(220) ≈ 8 rounds max |
