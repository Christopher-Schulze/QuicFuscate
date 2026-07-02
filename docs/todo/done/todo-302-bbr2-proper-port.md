---
id: TODO-302
title: BBR2 proper port from quiche (~1000 LoC)
severity: MEDIUM
status: done
created: 2026-03-24
---

# TODO-302: BBR2 Proper Port from quiche

## Mandatory Gate

**Before marking this TODO complete, ALL of the following must be checked and updated:**
- `src/transport/cc/bbr3.rs` - BBR3 implementation (current interim BBR2 fallback)
- `src/transport/cc/bbr2.rs` - new file to create for proper BBR2 port
- `src/transport/cc/mod.rs` - CcImpl enum, dispatch, exports
- `src/transport/recovery.rs` - CcImpl enum dispatch integration
- `scripts/tests/rust/rt-cc-algorithms.rs` - CC algorithm tests (create if not exists)
- `scripts/tests/suites/test-transport.sh` - transport test suite
- `docs/DOCUMENTATION.md` - Congestion Control section
- `docs/MAP.md` - transport/cc module wiring
- `docs/todo.md` - task truth
- `docs/DOCUMENTATION.md` - durable behavior truth

No fix is complete without verifying all relevant scripts run clean and docs reflect the new implementation.

---

## Current State

### What exists today

In `src/transport/cc/bbr3.rs` there is a BBR3 implementation. The `CcImpl` enum in `src/transport/cc/mod.rs` has:

```rust
pub enum CcImpl {
    Reno(Reno),
    Bbr3(Bbr3),
}
```

When `CongestionControlAlgorithm::Bbr2` is requested, the code falls back to BBR3 with a log warning:

```rust
CongestionControlAlgorithm::Bbr2 => {
    log::info!("BBR2 requested, using BBR3 (interim fallback until BBR2 port lands)");
    CcImpl::Bbr3(Bbr3::new(config))
}
```

This is the "TODO-298 Phase 2" gap from Session 20.

### Why BBR2 matters

BBR2 (Bottleneck Bandwidth and RTT, version 2) is the production-deployed variant used by:
- Google QUIC/gQUIC connections
- Chrome + Chromium-based browsers
- quiche (Cloudflare's QUIC library) - has a well-tested BBR2 port
- quic-go (Google's Go QUIC) - has BBR2

BBR3 is still experimental/research. For maximum compatibility with real-world traffic patterns and DPI evasion (looking like a browser), BBR2 is the better default for non-experimental deployments.

### quiche BBR2 as source

The reference implementation to port is at:
`cloudflare/quiche/src/recovery/bbr2/` (Apache 2.0 license - compatible)

Key modules in quiche BBR2:
- `bbr2.rs` - main state machine (~500 lines)
- `init.rs` - startup phase
- `probe_bw.rs` - ProbeB bandwidth phase logic
- `probe_rtt.rs` - RTT probing state
- `per_ack.rs` - per-ACK update functions
- `per_loss.rs` - loss response

Total: approximately 800-1200 LoC in the full implementation.

---

## Implementation Plan

### Phase 1: Understand the interface contract

`src/transport/cc/mod.rs` defines the `CongestionController` trait:

```rust
pub trait CongestionController: Send + Sync {
    fn on_packet_sent(&mut self, bytes: usize, now: Instant);
    fn on_ack(&mut self, acked: &[AckedPacket], now: Instant, rtt: Duration);
    fn on_loss(&mut self, lost: &[LostPacket], now: Instant);
    fn congestion_window(&self) -> usize;
    fn pacing_rate(&self) -> Option<u64>;
    fn in_slow_start(&self) -> bool;
    fn can_send(&self, bytes: usize) -> bool;
}
```

BBR2 must implement this trait. Map quiche's BBR2 function signatures to our trait boundaries.

### Phase 2: Port BBR2 state machine

Create `src/transport/cc/bbr2.rs` with:

1. **State enum**:
```rust
enum BbrState {
    Startup,
    Drain,
    ProbeBw(ProbeBwPhase),
    ProbeRtt,
}

enum ProbeBwPhase {
    Down,
    Cruise,
    Refill,
    Up,
}
```

2. **Bbr2 struct** holding:
   - `state: BbrState`
   - `btl_bw: u64` (bottleneck bandwidth estimate, bytes/sec)
   - `min_rtt: Duration`
   - `min_rtt_stamp: Instant`
   - `cwnd: usize`
   - `pacing_gain: f64`
   - `cwnd_gain: f64`
   - `bw_filter: WindowedFilter<u64>` (10-RTT windowed max)
   - `round_count: u64`
   - `round_start: bool`
   - `prior_cwnd: usize`
   - Startup-specific: `full_bw: u64`, `full_bw_count: u32`
   - ProbeRtt-specific: `probe_rtt_done_stamp: Option<Instant>`

3. **Key algorithms to port**:
   - `update_btl_bw()` - bandwidth sample windowed max filter
   - `update_min_rtt()` - 10-second windowed minimum RTT
   - `check_full_pipe()` - startup exit condition (3x rounds without 25% BW growth)
   - `enter_probe_bw()` / `enter_probe_rtt()` transitions
   - `handle_restart_from_idle()` - cwnd handling after idle
   - `on_ack_arrival()` - per-packet-ack update path
   - ECN handling: `on_congestion_event()` with BBR2's multiplicative cwnd reduction

4. **Constants to preserve** (tune after benchmarking):
   ```rust
   const STARTUP_GAIN: f64 = 2.885;       // 2/ln(2)
   const DRAIN_GAIN: f64 = 1.0 / 2.885;
   const PROBE_BW_GAIN: f64 = 1.25;
   const CWND_GAIN_STARTUP: f64 = 2.0;
   const MIN_RTT_WINDOW_S: u64 = 10;
   const PROBE_RTT_DURATION_MS: u64 = 200;
   const PROBE_RTT_CWND_MIN: usize = 4;   // 4 * MSS
   ```

### Phase 3: Wire into CcImpl

In `src/transport/cc/mod.rs`:
```rust
pub enum CcImpl {
    Reno(Reno),
    Bbr2(Bbr2),   // new
    Bbr3(Bbr3),
}
```

Remove the interim fallback log and route properly:
```rust
CongestionControlAlgorithm::Bbr2 => CcImpl::Bbr2(Bbr2::new(config)),
```

### Phase 4: Tests

Create `scripts/tests/rust/rt-cc-algorithms.rs` (if not exists) or extend it with BBR2-specific tests:

1. **Startup convergence**: synthetic ACK sequence should drive state to Drain then ProbeBw within ~10 RTTs
2. **Bandwidth estimation**: verify windowed max filter converges on target BW
3. **ProbeRtt trigger**: inject 10+ seconds of stable RTTs, verify ProbeRtt state entered
4. **Loss response**: verify cwnd reduction on simulated loss events
5. **Idle restart**: verify cwnd is not inflated after a send idle period
6. **Comparison test**: BBR2 and BBR3 over synthetic 10Mbps/20ms link should both converge within 5% of BDP

---

## Files to Create/Modify

- `src/transport/cc/bbr2.rs` - **new file**, ~600-800 LoC
- `src/transport/cc/mod.rs` - add `Bbr2` variant to `CcImpl`, remove interim fallback
- `src/transport/recovery.rs` - update match dispatch for `CcImpl::Bbr2`
- `scripts/tests/rust/rt-cc-algorithms.rs` - BBR2 unit + convergence tests
- `docs/DOCUMENTATION.md` - Congestion Control section: state BBR2 is properly implemented
- `docs/MAP.md` - add bbr2.rs to transport/cc/ inventory

---

## Completion Criteria

- `cargo test --lib` 450+ passed, 0 failed
- `cargo test --features rust-tests --test rt-cc-algorithms` GREEN with BBR2 tests
- BBR2 convergence test: achieves 90%+ of target BW on synthetic link within 15 RTTs
- No interim fallback log when `CongestionControlAlgorithm::Bbr2` is selected
- `cargo clippy --workspace --all-targets -- -D warnings` GREEN
- All mandatory gate items checked and updated
