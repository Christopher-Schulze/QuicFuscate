---
id: TODO-427
title: FEC mode transition tests under active load
severity: HIGH
phase: "F"
priority: P1
status: OPEN
created: 2026-06-29
depends_on: ["TODO-423"]
---

# TODO-427: FEC Mode Transition Tests Under Active Load

## Problem

Existing mode transition tests (cross-fade, policy snapshots) test transitions in isolation —
they feed packets through `on_send` during a transition but do not verify:

1. No packet loss or duplication during transition under real transport load
2. Transition correctness when both send and receive paths transition simultaneously
3. Transition under varying packet rates (burst → idle → burst during transition)
4. Multiple rapid transitions (flapping detection and prevention)
5. Transition from every mode to every other mode (full N×N matrix)
6. Transition during QUIC handshake (Initial/Handshake packets must not be FEC-repaired)

## Goal

Verify FEC mode transitions are seamless under real load — zero packet loss, zero duplication,
correct cross-fade blending, and no flapping under rapid condition changes.

## Implementation Plan

### 1. Full N×N transition matrix test (Rust unit test)

```rust
#[test]
fn test_fec_all_mode_transitions_correct() {
    // For each (from_mode, to_mode) pair in the 9×9 matrix:
    //   1. Start FEC in from_mode
    //   2. Feed k packets to fill window
    //   3. Trigger transition to to_mode
    //   4. Feed cross_fade_packets during transition
    //   5. Feed k more packets in to_mode
    //   6. Verify: no packet lost, no duplicate, repair count blends correctly
}
```

Modes: Zero, Light, Normal, Medium, Strong, Extreme, Ultra, Streaming, Fountain (9×9 = 81 pairs)

### 2. Bidirectional transition test (Rust integration test)

```rust
#[test]
fn test_fec_bidirectional_transition_no_loss() {
    // Create client+server FEC instances
    // Both sending data simultaneously
    // Trigger mode transition on both sides at the same time
    // Verify: zero packet loss in either direction during transition
    // Verify: no repair packet collision (different stream IDs)
}
```

### 3. Transition under burst traffic test

```rust
#[test]
fn test_fec_transition_under_burst_traffic() {
    // Start in Normal mode
    // Send 100 packets (burst)
    // Trigger transition to Extreme mid-burst
    // Verify: transition handles partial window correctly
    // Verify: no packets lost during burst+transition
}
```

### 4. Transition under idle-then-burst test

```rust
#[test]
fn test_fec_transition_idle_then_burst() {
    // Start in Normal mode
    // Trigger transition to Streaming
    // Wait with no packets (idle) for transition to complete
    // Send burst of 100 packets
    // Verify: transition completed during idle, burst uses new mode
}
```

### 5. Rapid transition flapping prevention test

```rust
#[test]
fn test_fec_rapid_transitions_no_flapping() {
    // Alternate loss signal: 0% → 50% → 0% → 50% every 10 packets
    // Verify: FEC does not switch mode on every signal (hysteresis works)
    // Verify: FEC stabilizes after hysteresis window
    // Verify: mode_switches count is reasonable (< 5 for 100 packets)
}
```

### 6. Transition during QUIC handshake test (Rust integration test)

```rust
#[test]
fn test_fec_no_repair_during_handshake() {
    // Create client+server, start handshake
    // FEC is in Normal mode
    // Verify: Initial/Handshake packets are NOT FEC-repaired (they have their own retry protection)
    // Verify: FEC only activates for 1-RTT data packets
    // Verify: mode transition does not interfere with handshake completion
}
```

### 7. E2E transition test via tc-netem (`scripts/tests/fec-netem-transition.sh`)

```
# Phase 1: 0% loss for 5s → FEC in Zero/Light
# Phase 2: 20% loss for 5s → FEC escalates to Strong/Extreme (transition happens live)
# Phase 3: 0% loss for 5s → FEC de-escalates (transition happens live)
# Verify: ping through tunnel has 0% loss DURING transitions (not just before/after)
# Verify: FEC_MODE telemetry shows correct progression
```

## Files to Create
- `src/fec/transition_tests.rs` — tests 1-6
- `scripts/tests/fec-netem-transition.sh` — test 7

## Acceptance Criteria
- N×N matrix: all 81 transition pairs pass with zero loss/duplication
- Bidirectional: zero loss in either direction during simultaneous transition
- Burst: no loss during burst+transition
- Idle-then-burst: transition completes during idle, burst uses new mode
- Flapping: <5 mode switches for 100 alternating-loss packets (hysteresis effective)
- Handshake: Initial/Handshake packets never FEC-repaired, handshake completes normally
- E2E: 0% ping loss during live mode transitions (verified via tc-netem)
