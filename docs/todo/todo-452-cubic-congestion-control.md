---
id: TODO-452
title: CUBIC congestion control (RFC 9438)
severity: HIGH
phase: "J"
priority: P1
status: OPEN
created: 2026-06-30
depends_on: []
---

# TODO-452: CUBIC Congestion Control (RFC 9438)

## Problem

The transport implements only BBR2, BBR3, and Reno congestion control. **CUBIC**
— the Linux kernel default (RFC 9438) and the most widely deployed congestion
control algorithm on the internet — is missing. This matters for two reasons:

1. **Fairness**: When QuicFuscate traffic shares a bottleneck with Linux CUBIC
   flows (the vast majority of internet traffic), BBR3 can be overly aggressive
   and starve CUBIC flows, or conversely be unfair to itself in mixed
   environments. Offering CUBIC ensures fair coexistence.
2. **Predictability**: CUBIC's behavior is well-understood and widely tested in
   production. Some deployments may prefer it over BBR for deterministic
   behavior under loss.

Evidence:

- `src/transport/cc/` — contains `bbr2.rs`, `bbr3.rs`, `reno.rs`,
  `stealth_shaper.rs`. No `cubic.rs`.
- `src/transport/cc/mod.rs:17-24` — `Algorithm` enum has `Reno`, `Bbr2`, `Bbr3`
  only. No `Cubic` variant.
- `src/transport/cc/mod.rs:76-83` — `CcImpl` enum has no `Cubic` variant.
- `src/transport/cc/mod.rs:86-92` — `create()` factory has no `Cubic` arm.
- `src/transport/cc/mod.rs:95-106` — `cc_dispatch!` macro has no `Cubic` arm.
- `src/transport.rs:210-217` — `CongestionControlAlgorithm` enum (the public
  API enum) has `Reno`, `BBR2`, `BBR3` only.
- `src/transport/config.rs:186-190` — `set_cc_algorithm_name` accepts `reno`,
  `bbr2`, `bbr3` only. Rejects everything else with `InvalidState`.

## Goal

Implement CUBIC per RFC 9438 and integrate it into the congestion control
framework as a first-class algorithm:

1. **CUBIC core**: W_max tracking, K calculation (cube root), window function
   `W(t) = C(t-K)^3 + W_max`, hybrid slow start, TCP friendliness check, fast
   convergence.
2. **CC framework integration**: add `Cubic` to `Algorithm`, `CcImpl`,
   `create()`, `cc_dispatch!`, `CongestionControlAlgorithm`, and
   `set_cc_algorithm_name`.
3. **Config**: `congestion_control = "bbr3" | "bbr2" | "reno" | "cubic"`.

## Implementation Plan

### Step 1: Implement CUBIC core in `src/transport/cc/cubic.rs`

```rust
pub struct Cubic {
    cwnd: usize,
    bytes_in_flight: usize,
    mss: usize,
    // CUBIC state
    w_max: usize,           // window size before last reduction
    k: f64,                 // time period for W_max (cube root)
    epoch_start: Option<Instant>,  // start of current CUBIC epoch
    ssthresh: usize,        // slow-start threshold
    in_slow_start: bool,
    // TCP friendliness
    tcp_cwnd: usize,        // estimated TCP Reno cwnd for friendliness
    est_start: Option<Instant>,
    // Fast convergence
    w_last_max: usize,      // previous w_max for fast convergence
    // RTT
    min_rtt: Duration,
    srtt: Duration,
    // Constants (RFC 9438 defaults)
    beta: f64,              // 0.7 (multiplicative decrease factor)
    c: f64,                 // 0.4 (CUBIC scaling constant)
    // FEC callbacks
    fec_on_sent: Option<Arc<dyn Fn(u64, usize) + Send + Sync>>,
    fec_on_lost: Option<Arc<dyn Fn(u64, usize) + Send + Sync>>,
}
```

Key algorithms:

**On loss event (`on_loss`):**
```rust
// RFC 9438 §4.1
let reduction = (cwnd as f64 * (1.0 - beta)) as usize;
w_max = cwnd;
// Fast convergence (§4.6): if w_max < w_last_max, reduce w_max further
if w_max < w_last_max {
    w_max = (w_max * (1.0 + beta) / 2.0) as usize;
}
w_last_max = w_max;
cwnd = cwnd - reduction;
ssthresh = cwnd;
in_slow_start = false;
// Compute K: K = cbrt(w_max * beta / C) * RTT
k = (w_max as f64 * beta / c).cbrt();
epoch_start = Some(now);
```

**On ACK (`on_ack`):**
```rust
if in_slow_start {
    cwnd += mss;  // exponential growth
    if cwnd >= ssthresh { in_slow_start = false; }
} else {
    // CUBIC window function: W(t) = C(t-K)^3 + W_max
    let t = epoch_start.elapsed().as_secs_f64() / srtt.as_secs_f64();
    let w_cubic = (c * (t - k).powi(3) + w_max as f64) as usize;
    // TCP friendliness (§4.4): estimate TCP Reno cwnd
    let w_tcp = tcp_friendly_cwnd(t, w_max);
    // Use max of CUBIC and TCP-friendly
    let target = w_cubic.max(w_tcp);
    cwnd = target;
}
```

**TCP friendliness (`tcp_friendly_cwnd`):**
```rust
// RFC 9438 §4.4: W_tcp(t) = w_max * (1 - beta) + 3*beta/(2-beta) * t/RTT
fn tcp_friendly_cwnd(t: f64, w_max: usize, beta: f64, rtt: Duration) -> usize {
    let t_rtt = t / rtt.as_secs_f64();
    (w_max as f64 * (1.0 - beta) + 3.0 * beta / (2.0 - beta) * t_rtt) as usize
}
```

**Hybrid slow start (§4.5):**
- Exit slow start early if RTT increases by > 8% (ACK train delay or RTT
  increase threshold), preventing overshoot.

### Step 2: Implement `CongestionController` trait for `Cubic`

Implement all trait methods from `src/transport/cc/mod.rs:30-73`:

- `on_packet_sent`, `on_ack`, `on_loss`, `on_loss_packet`, `update_rtt`,
  `cwnd`, `bytes_in_flight`, `pacing_rate`, `loss_rate`, `mss`, `send_quantum`,
  `can_send`, `set_fec_callbacks`.

CUBIC does not have an explicit pacing rate (unlike BBR), so `pacing_rate()`
returns `None` (same as Reno). Pacing is handled by the `StealthShaper` wrapper
if enabled.

### Step 3: Integrate into CC framework

In `src/transport/cc/mod.rs`:

- Add `pub mod cubic;` (line ~9).
- Add `Cubic` variant to `Algorithm` enum (line 17-24).
- Add `Cubic(cubic::Cubic)` and `StealthCubic(stealth_shaper::StealthShaper<cubic::Cubic>)` variants to `CcImpl` (line 76-83).
- Add `Algorithm::Cubic => CcImpl::Cubic(cubic::Cubic::new(initial_cwnd, mss))` to `create()` (line 86-92).
- Add `CcImpl::Cubic(cc)` and `CcImpl::StealthCubic(cc)` arms to `cc_dispatch!` macro (line 95-106).

### Step 4: Integrate into public API

In `src/transport.rs`:

- Add `Cubic` variant to `CongestionControlAlgorithm` enum (line 210-217).

In `src/transport/config.rs`:

- Add `"cubic" => CongestionControlAlgorithm::Cubic` to `set_cc_algorithm_name`
  match (line 186-190).
- Update doc comment at line 175 to include `cubic`.

### Step 5: StealthShaper compatibility

`StealthShaper<CC>` is generic over `CongestionController` (see
`src/transport/cc/stealth_shaper.rs`). Since `Cubic` implements
`CongestionController`, `StealthShaper<Cubic>` works automatically. Add the
`StealthCubic` variant to `CcImpl` and `cc_dispatch!` as noted in Step 3.

### Step 6: Tests

Unit tests in `src/transport/cc/cubic.rs`:

- `test_cubic_slow_start` — cwnd grows by MSS per ACK in slow start.
- `test_cubic_loss_reduction` — cwnd reduces by `(1 - beta)` on loss, w_max
  captured.
- `test_cubic_k_calculation` — K = cbrt(w_max * beta / C) computed correctly.
- `test_cubic_window_function` — W(t) matches expected values for known t, K,
  w_max.
- `test_cubic_tcp_friendliness` — CUBIC cwnd ≥ TCP-friendly cwnd in concave
  region.
- `test_cubic_fast_convergence` — w_max reduced further on consecutive losses.
- `test_cubic_hybrid_slow_start` — exits slow start on RTT increase > 8%.

Integration tests:

- CUBIC vs Reno fairness: two connections (one CUBIC, one Reno) on a shared
  bottleneck; verify CUBIC does not starve Reno (fairness index > 0.8 via
  Jain's index).
- CUBIC throughput vs BBR3: CUBIC should achieve comparable throughput under
  low-loss; BBR3 higher under loss.
- CUBIC under loss: 5% random loss; verify CUBIC maintains reasonable throughput
  and does not collapse.

## Files to Modify/Create

- `src/transport/cc/cubic.rs` — **new**: `Cubic` struct, CUBIC algorithm,
  `CongestionController` impl, unit tests.
- `src/transport/cc/mod.rs` — add `Cubic` to `Algorithm`, `CcImpl`, `create()`,
  `cc_dispatch!`, `CongestionController` impl for `CcImpl`.
- `src/transport.rs` — add `Cubic` to `CongestionControlAlgorithm` enum.
- `src/transport/config.rs` — add `"cubic"` to `set_cc_algorithm_name`; update
  doc comments.
- Integration tests: CUBIC fairness, CUBIC vs BBR3 throughput, CUBIC under loss.

## Acceptance Criteria

- [ ] `set_cc_algorithm_name("cubic")` succeeds and sets `Cubic` algorithm.
- [ ] CUBIC slow start: cwnd doubles per RTT until ssthresh.
- [ ] CUBIC loss response: cwnd reduces by factor `(1 - 0.7) = 0.3` (i.e., cwnd
      becomes 70% of pre-loss value); `w_max` captures pre-loss cwnd.
- [ ] CUBIC window function: `W(t) = C(t-K)^3 + W_max` computed correctly
      (verified against known test vectors).
- [ ] TCP friendliness: in the concave region, CUBIC cwnd ≥ TCP Reno estimate;
      in the convex region, CUBIC grows but TCP-friendly estimate caps growth.
- [ ] Fast convergence: on consecutive losses, `w_max` is reduced (not just
      reset to pre-loss cwnd).
- [ ] Hybrid slow start: exits slow start when RTT increases > 8%.
- [ ] CUBIC + Reno fairness: Jain's fairness index > 0.8 on shared bottleneck.
- [ ] CUBIC under 5% random loss: throughput > 50% of loss-free throughput.
- [ ] `StealthShaper<Cubic>` works (stealth shaping wraps CUBIC correctly).
- [ ] No regression in BBR2/BBR3/Reno tests.

## Resource Budget

| Scenario | Budget | Notes |
|----------|--------|-------|
| CUBIC unit tests (state machine) | < 5s | All algorithm paths |
| CUBIC vs Reno fairness (10s transfer) | < 30s | Jain's index > 0.8 |
| CUBIC vs BBR3 throughput | < 30s | Comparable under low loss |
| CUBIC under 5% loss | < 30s | > 50% of loss-free throughput |
| K calculation precision | < 1e-6 relative error | cbrt must be accurate |
| Memory overhead vs Reno | < 200 bytes | Extra CUBIC state fields |
