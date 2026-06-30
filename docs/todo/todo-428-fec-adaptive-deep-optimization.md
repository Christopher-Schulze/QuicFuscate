---
id: TODO-428
title: FEC adaptive intelligence deep optimization
severity: HIGH
phase: "F"
priority: P1
status: DONE
created: 2026-06-29
depends_on: ["TODO-423", "TODO-424", "TODO-425"]
---

# TODO-428: FEC Adaptive Intelligence Deep Optimization

## Problem

The FEC adaptive logic is sophisticated (Kalman filter, CUSUM, burst variance, EMA) but has
never been validated under real network conditions. The tuning parameters (hysteresis
thresholds, switch intervals, EMA lambda, Kalman Q/R) were set by code inspection, not by
empirical optimization. Key questions:

1. **Are the mode-switch thresholds optimal?** — Does FEC escalate too early (wasting
   bandwidth on unnecessary repair) or too late (losing packets that could have been
   recovered)?

2. **Is the hysteresis window correct?** — Too small → mode flapping under oscillating loss.
   Too large → FEC stays in wrong mode too long after conditions change.

3. **Is the streaming interval adaptive enough?** — `stream_every` scales with RTT, but does
   it scale correctly with packet rate? High packet rate + high loss should emit repairs
   more frequently.

4. **Is the Kalman filter tuned correctly?** — Q (process noise) and R (measurement noise)
   determine how quickly the filter reacts to loss changes. Wrong values → either sluggish
   (reacts too slow) or jittery (overreacts to single loss events).

5. **Does FEC interact correctly with congestion control?** — FEC repair packets are
   ack-eliciting and congestion-controlled. Under heavy loss, FEC repairs compete with
   retransmissions for cwnd budget. Is this tradeoff optimal?

6. **Is the bandwidth-aware overhead control effective?** — On low-bandwidth links, FEC
   overhead is a larger fraction of useful throughput. Does the adaptive logic reduce
   redundancy when bandwidth is scarce?

## Goal

Deep-optimize the FEC adaptive intelligence based on empirical data from the tc-netem
adversity tests (TODO-425). Make FEC maximally efficient at every load level while
guaranteeing liveness under extreme conditions.

## Implementation Plan

### Phase 1: Empirical baseline (depends on TODO-425)

Run the full tc-netem adversity suite on broderick and collect:
- Mode selection accuracy per loss level (does FEC pick the right mode?)
- Recovery ratio per loss level (does FEC recover enough packets?)
- Overhead ratio per loss level (is FEC wasting bandwidth?)
- Mode switch latency (how fast does FEC react to condition changes?)
- Flapping count (how often does FEC switch back and forth?)

### Phase 2: Threshold tuning

Based on Phase 1 data, tune:
- `FecConfig.hysteresis` — minimum loss delta for mode switch
- `FecConfig.lambda` — EMA smoothing factor
- `FecConfig.kalman_q` / `kalman_r` — Kalman filter noise parameters
- `ModeManager` switch intervals (min time between up/down switches)
- `stream_every` scaling formula (packet rate + RTT + loss → interval)

Tuning method:
1. Run tc-netem loss sweep with current parameters → baseline
2. Adjust one parameter at a time → re-run → compare
3. Optimize for: (a) recovery ratio, (b) overhead ratio, (c) switch latency, (d) stability
4. Find Pareto-optimal parameter set

### Phase 3: Bandwidth-aware overhead control

Implement adaptive overhead control:
- Detect bandwidth scarcity (RTT increasing + cwnd decreasing + throughput dropping)
- Reduce FEC redundancy when bandwidth is scarce (trade recovery for throughput)
- Increase FEC redundancy when bandwidth is plentiful (trade overhead for recovery)
- Verify: on 1Mbit link with 5% loss, FEC overhead <15% of useful throughput

Implementation:
```rust
// In AdaptiveFec::on_send or apply_auto_tuning:
fn bandwidth_aware_overhead_adjustment(&mut self, rtt_trend: f32, cwnd_trend: f32, throughput_trend: f32) {
    // If all three trends are negative → bandwidth scarce → reduce red_ppm_hint
    // If all three trends are positive → bandwidth plentiful → increase red_ppm_hint
    // Clamp to safe bounds: never go below minimum redundancy for current loss level
}
```

### Phase 4: Congestion control interaction optimization

Verify and optimize FEC + QUIC congestion control interaction:
- FEC repair packets are ack-eliciting → they consume cwnd
- Under heavy loss, FEC repairs + retransmissions compete for cwnd
- Optimize: should FEC repairs be sent with lower priority than retransmissions?
- Optimize: should FEC repairs bypass congestion control in extreme loss (like ACK-only)?
- Verify: FEC does not cause congestion collapse by flooding repairs into a congested link

### Phase 5: SIMD path optimization

Based on TODO-424 benchmark data:
- Verify SIMD dispatch is optimal for each mode (GF4 for Light, GF8 for Normal, GF16 for Strong+)
- Optimize matrix multiply for common block sizes (k=4, k=8, k=16)
- Verify no SIMD dispatch overhead in Zero mode fast path
- Profile and optimize any scalar fallback that shows up in hot path

### Phase 6: Validation

Re-run full tc-netem adversity suite with optimized parameters:
- Compare recovery ratio, overhead ratio, switch latency, flapping count vs Phase 1 baseline
- Verify all acceptance criteria from TODO-425 still pass
- Verify resource efficiency targets from TODO-426 still pass
- Document final tuned parameters in `docs/DOCUMENTATION.md`

## Files to Modify
- `src/fec/mod.rs` — threshold tuning, bandwidth-aware overhead, congestion interaction
- `src/fec/internal.rs` — ModeManager switch intervals, hysteresis
- `src/brain.rs` — FEC hint integration (if bandwidth-aware control needs brain signals)
- `docs/DOCUMENTATION.md` — final tuned parameters and tuning rationale

## Acceptance Criteria
- Mode selection accuracy: >90% correct mode for each loss level (empirical)
- Recovery ratio: meets or exceeds TODO-425 thresholds at every loss level
- Overhead ratio: <20% at 5% loss, <60% at 25% loss, <150% at 50% loss
- Switch latency: <2s from condition change to mode switch
- Flapping: <3 mode switches per 10s under oscillating conditions
- Bandwidth-aware: overhead <15% on 1Mbit link, <10% on 100Kbit link
- Congestion-safe: no congestion collapse under FEC + heavy loss + limited bandwidth
- SIMD: Zero mode <5ns, Normal mode <500ns, Extreme mode <2us per packet
- All TODO-425 adversity tests pass with optimized parameters
- All TODO-426 resource tests pass with optimized parameters
- Final parameters documented with rationale

## Resource Efficiency Philosophy

The guiding principle: **FEC should be invisible when the link is clean and heroic when
the link is broken.**

| Condition | FEC Behavior | Resource Budget |
|-----------|-------------|-----------------|
| Clean link (0% loss) | Zero overhead, zero CPU | <1% CPU, <1MB RAM |
| Light loss (2%) | Minimal repair, low overhead | <5% CPU, <5MB RAM |
| Moderate loss (10%) | Active repair, moderate overhead | <15% CPU, <15MB RAM |
| Heavy loss (25%) | Aggressive repair, high overhead | <30% CPU, <30MB RAM |
| Extreme loss (50%) | Maximum repair, very high overhead | <50% CPU, <50MB RAM |
| Low bandwidth | Reduced overhead (bandwidth-aware) | <15% of link capacity |
| High bandwidth | Full repair (no bandwidth constraint) | <30% of link capacity |

In extreme loss scenarios, FEC may consume significant resources — but the link stays up.
That is the tradeoff: resources are cheap, liveness is expensive.
