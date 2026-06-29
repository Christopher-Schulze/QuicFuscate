---
id: TODO-425
title: FEC under network adversity (tc-netem loss/jitter/bandwidth/RTT simulation)
severity: HIGH
phase: "F"
priority: P1
status: OPEN
created: 2026-06-29
depends_on: ["TODO-423"]
---

# TODO-425: FEC Under Network Adversity (tc-netem Simulation)

## Problem

No existing test simulates real network adversity at the transport layer. The FEC unit tests
inject loss at the FEC module level (`on_receive` drops packets programmatically), which does
not test the interaction between FEC and:
- QUIC congestion control under loss
- QUIC PTO/retransmission under jitter
- Bandwidth-limited links (FEC overhead vs. useful throughput tradeoff)
- High-RTT links (FEC recovery latency vs. retransmission latency tradeoff)

## Goal

Build a comprehensive tc-netem adversity test suite that verifies FEC behaves intelligently
under every realistic network degradation pattern.

## Implementation Plan

### 1. Loss sweep with throughput measurement

`scripts/tests/fec-netem-loss-sweep.sh`:
```
for loss in 0 1 2 5 10 15 20 25 30 40 50; do
  tc netem loss ${loss}%
  # Run 10s iperf-like transfer through QUIC tunnel
  # Measure: useful throughput, FEC overhead, FEC mode, recovery ratio
  # Verify: FEC mode escalates correctly, throughput degrades gracefully
done
```

Key metrics per loss level:
- Useful throughput (post-FEC, excluding repair packets)
- FEC overhead ratio (repair bytes / source bytes)
- FEC mode at end of run
- Recovery ratio (recovered packets / lost packets)
- RTT impact (does FEC recovery reduce effective RTT vs. retransmission?)

### 2. Jitter sweep

`scripts/tests/fec-netem-jitter-sweep.sh`:
```
for jitter in 0 10 50 100 200 500; do
  tc netem delay 50ms ${jitter}ms 25%
  # Run transfer, measure FEC mode stability under jitter
  # Verify: FEC does not flap modes under jitter-only (no loss)
  # Verify: FEC escalates correctly under jitter+loss combined
done
```

### 3. Bandwidth limitation test

`scripts/tests/fec-netem-bandwidth.sh`:
```
for bw in 100Mbit 50Mbit 10Mbit 5Mbit 1Mbit; do
  tc tbf rate ${bw} burst 32kbit latency 400ms
  # Run transfer, measure FEC overhead vs. useful throughput
  # Verify: FEC does not waste bandwidth on low-bandwidth links
  # Verify: FEC mode downshifts to reduce overhead when bandwidth is scarce
done
```

Key insight: FEC overhead is a larger fraction of useful throughput on low-bandwidth links.
The adaptive logic should recognize bandwidth scarcity and reduce redundancy.

### 4. RTT variation test

`scripts/tests/fec-netem-rtt.sh`:
```
for rtt in 1 10 50 100 200 300; do
  tc netem delay ${rtt}ms
  # Run transfer with 5% loss + varying RTT
  # Measure: FEC recovery latency vs. QUIC retransmission latency
  # Verify: FEC recovery is faster than retransmission for high-RTT links
  # Verify: FEC value proposition increases with RTT (recovery < 1 RTT vs retransmit = 2+ RTT)
done
```

### 5. Combined adversity (worst-case real-world)

`scripts/tests/fec-netem-combined.sh`:
```
# Mobile network simulation: 100ms RTT + 10ms jitter + 5% loss + 10Mbit bandwidth
tc netem delay 100ms 10ms 25% loss 5%
tc tbf rate 10Mbit burst 32kbit latency 400ms
# Run 60s transfer, verify stable operation, no mode flapping, graceful throughput
```

### 6. Adversity recovery test

```
# Phase 1: Clean link (0% loss) for 10s → FEC should be Zero/Light
# Phase 2: Inject 20% loss for 10s → FEC should escalate to Strong/Extreme
# Phase 3: Remove loss (0%) for 10s → FEC should de-escalate back to Zero/Light
# Verify: mode transitions are smooth, no packet loss during transitions, no flapping
```

## Files to Create
- `scripts/tests/fec-netem-loss-sweep.sh`
- `scripts/tests/fec-netem-jitter-sweep.sh`
- `scripts/tests/fec-netem-bandwidth.sh`
- `scripts/tests/fec-netem-rtt.sh`
- `scripts/tests/fec-netem-combined.sh`
- `scripts/tests/fec-netem-adversity-recovery.sh`

## Acceptance Criteria
- Loss sweep: FEC mode escalates monotonically with loss level (no mode regression)
- Jitter sweep: FEC does not flap under jitter-only (mode stays stable)
- Bandwidth test: FEC overhead <30% of useful throughput on 1Mbit link
- RTT test: FEC recovery latency < 1 RTT for all RTT values
- Combined test: stable operation for 60s, no panics, no mode flapping
- Recovery test: mode de-escalation within 5s of loss removal, no flapping
- All tests pass on broderick (Linux root + tc-netem)

## Resource Efficiency Targets
| Condition | FEC Overhead Target | CPU Target | Memory Target |
|-----------|-------------------|------------|---------------|
| 0% loss   | 0% (Zero mode)    | <1%        | <1MB          |
| 5% loss   | <20%              | <5%        | <5MB          |
| 25% loss  | <60%              | <20%       | <20MB         |
| 50% loss  | <150%             | <50%       | <50MB         |
| Low BW    | <15%              | <5%        | <5MB          |
