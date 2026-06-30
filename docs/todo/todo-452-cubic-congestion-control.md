---
id: TODO-452
title: CUBIC congestion control
severity: HIGH
phase: "J"
priority: P1
status: DONE
created: 2026-07-23
depends_on: []
---

# TODO-452: CUBIC Congestion Control

## Goal
Implement CUBIC (RFC 9438) as a first-class congestion control algorithm in the
existing CC framework, alongside BBR2, BBR3, and Reno. CUBIC is the Linux
kernel default and the most widely deployed CC algorithm on the internet.
Adding it ensures fair coexistence with CUBIC flows, provides a well-understood
deterministic behavior option, and adds traffic-pattern diversity for stealth
fingerprint resistance.

## Current State (verified against code)

The CC framework supports three algorithms with enum dispatch:

- `src/transport/cc/mod.rs:7-10` — module declarations for `bbr2`, `bbr3`,
  `reno`, `stealth_shaper`. No `cubic` module.
- `src/transport/cc/mod.rs:17-24` — `Algorithm` enum has `Reno`, `Bbr2`,
  `Bbr3` only. No `Cubic` variant.
- `src/transport/cc/mod.rs:30-73` — `CongestionController` trait defines the
  interface: `on_packet_sent`, `on_ack`, `on_loss`, `on_loss_packet`,
  `update_rtt`, `cwnd`, `bytes_in_flight`, `pacing_rate`, `loss_rate`, `mss`,
  `send_quantum`, `can_send`, `set_fec_callbacks`. CUBIC must implement all.
- `src/transport/cc/mod.rs:76-83` — `CcImpl` enum has `Reno`, `Bbr2`, `Bbr3`,
  `StealthReno`, `StealthBbr2`, `StealthBbr3`. No `Cubic` or `StealthCubic`.
- `src/transport/cc/mod.rs:86-92` — `create()` factory has no `Cubic` arm.
- `src/transport/cc/mod.rs:95-106` — `cc_dispatch!` macro has no `Cubic` arm.
- `src/transport.rs:210-217` — `CongestionControlAlgorithm` enum (public API)
  has `Reno`, `BBR2`, `BBR3` only. No `Cubic`.
- `src/transport/config.rs:111` — default CC is `BBR3`.
- `src/transport/config.rs:176-194` — `set_cc_algorithm` and
  `set_cc_algorithm_name` accept `reno`, `bbr2`, `bbr3` only. Rejects
  everything else with `InvalidState`.
- `src/transport/recovery.rs:89-135` — `set_stealth_mode()` handles wrapping
  `Bbr3`, `Bbr2`, `Reno` in `StealthShaper`. No `Cubic` handling. Must add
  `StealthCubic` wrapping.
- `src/transport/cc/reno.rs` — Reno implementation. Good reference for a
  simple AIMD CC that implements `CongestionController`. CUBIC is more complex
  but follows the same trait interface.

## Problem Analysis

### Why CUBIC matters

**1. Fairness with internet traffic**
CUBIC is the Linux kernel default (since 2.6.19, 2006). The vast majority of
internet traffic uses CUBIC. When QuicFuscate traffic (using BBR3) shares a
bottleneck with CUBIC flows, BBR3 can be overly aggressive — it ignores loss
signals that CUBIC respects, potentially starving CUBIC flows. Offering CUBIC
ensures fair coexistence in mixed environments.

**2. Deterministic behavior**
CUBIC's behavior is well-understood and widely tested in production over 15+
years. Some deployments may prefer it over BBR for deterministic behavior
under loss. BBR3's model-based approach can sometimes produce surprising
behavior (e.g., probing bandwidth by increasing sending rate, which can cause
transient loss). CUBIC's AIMD-like behavior is more predictable.

**3. Stealth: traffic pattern diversity**
BBR3 has a distinctive traffic pattern: periodic bandwidth probing (PROBE_BW
cycle with 8-phase gain sequence), min_rtt probing (PROBE_RTT phase with cwnd
floor). Some DPI systems can fingerprint BBR flows by these patterns. CUBIC
has a different pattern: cubic window growth function, loss-driven backoff.
By offering CUBIC, QuicFuscate can vary its traffic pattern to avoid BBR
fingerprinting. This is especially important for the stealth use case.

**4. Server-to-server compatibility**
For server-to-server VPN tunnels (e.g., data center interconnect), CUBIC is
the natural choice because it matches the Linux kernel default. Using CUBIC
on both ends ensures the VPN tunnel behaves like normal kernel TCP traffic,
which is important for environments where BBR is not deployed or is
prohibited.

### CUBIC algorithm overview (RFC 9438)

CUBIC uses a cubic function for window growth:
```
W(t) = C * (t - K)^3 + W_max
```
Where:
- `W(t)` = window size at time t (in packets)
- `C` = scaling constant (0.4, default)
- `t` = time since last congestion event (in seconds)
- `K` = time period to reach W_max = `cbrt(W_max * beta / C)`
- `W_max` = window size before last reduction
- `beta` = multiplicative decrease factor (0.7, default)

Key properties:
1. **Convex growth**: after a loss, W(t) grows rapidly toward W_max (convex
   region), then plateaus (concave region) before growing again.
2. **TCP friendliness**: CUBIC checks if its window would be lower than a
   TCP Reno estimate. If so, it uses the Reno estimate instead (§4.4).
3. **Fast convergence**: on consecutive losses, if the new W_max is less than
   the previous W_max, CUBIC reduces W_max further. This helps new flows
   catch up (§4.6).
4. **Hybrid slow start**: exits slow start early if RTT increases by > 8%
   (HyStart++), preventing overshoot (§4.5).

### CUBIC vs Reno vs BBR3

| Property | CUBIC | Reno | BBR3 |
|----------|-------|------|------|
| Growth function | Cubic | Linear (AIMD) | Model-based (BDP) |
| Loss response | beta=0.7 | beta=0.5 | Ignores loss (uses model) |
| RTT dependency | Yes (K depends on RTT) | Yes | Yes (min_rtt) |
| Pacing | No (optional) | No | Yes (built-in) |
| TCP friendliness | Built-in (§4.4) | N/A (is TCP) | Controversial |
| Fingerprint | Common (Linux default) | Common | Distinctive |
| Under high loss | Moderate | Poor | Good |
| Under low loss | Good | Good | Excellent |

## Proposed Architecture

### CUBIC struct
```rust
pub struct Cubic {
    cwnd: usize,
    bytes_in_flight: usize,
    mss: usize,
    // CUBIC state
    w_max: usize,           // window size before last reduction (in bytes)
    w_last_max: usize,      // previous w_max for fast convergence
    k: f64,                 // time period for W_max (in seconds)
    epoch_start: Option<Instant>,  // start of current CUBIC epoch
    ssthresh: usize,        // slow-start threshold
    in_slow_start: bool,
    // TCP friendliness
    tcp_cwnd: usize,        // estimated TCP Reno cwnd for friendliness
    est_start: Option<Instant>,
    // RTT
    min_rtt: Duration,
    srtt: Duration,
    // Constants (RFC 9438 defaults)
    beta: f64,              // 0.7 (multiplicative decrease factor)
    c: f64,                 // 0.4 (CUBIC scaling constant)
    // HyStart++ (optional, §4.5)
    hystart: bool,
    last_rtt: Duration,
    rtt_increase_threshold: f64,  // 0.08 (8%)
    // FEC callbacks
    fec_on_sent: Option<Arc<dyn Fn(u64, usize) + Send + Sync>>,
    fec_on_lost: Option<Arc<dyn Fn(u64, usize) + Send + Sync>>,
    // Loss tracking
    loss_count: u64,
    last_loss_time: Option<Instant>,
}
```

### Key algorithms

**On loss event (`on_loss` / `on_loss_packet`):**
```rust
// RFC 9438 §4.1
let old_cwnd = self.cwnd;
self.w_max = self.cwnd;

// Fast convergence (§4.6): if w_max < w_last_max, reduce w_max further
if self.w_max < self.w_last_max {
    self.w_max = (self.w_max as f64 * (1.0 + self.beta) / 2.0) as usize;
}
self.w_last_max = self.w_max;

// Multiplicative decrease: cwnd = cwnd * beta
self.cwnd = (self.cwnd as f64 * self.beta) as usize;
self.cwnd = self.cwnd.max(self.minimum_window());
self.ssthresh = self.cwnd;
self.in_slow_start = false;

// Compute K: K = cbrt(w_max * beta / C) * RTT_seconds
// Note: w_max and cwnd are in bytes, K is in seconds
let w_max_packets = self.w_max as f64 / self.mss as f64;
self.k = (w_max_packets * self.beta / self.c).cbrt();
self.epoch_start = Some(now);
self.last_loss_time = Some(now);
```

**On ACK (`on_ack`):**
```rust
if self.in_slow_start {
    // Slow start: cwnd += acked_bytes (exponential growth)
    self.cwnd += acked_bytes;
    if self.cwnd >= self.ssthresh {
        self.in_slow_start = false;
    }
    // HyStart++ check (§4.5)
    if self.hystart && self.check_hystart_exit() {
        self.in_slow_start = false;
        self.ssthresh = self.cwnd;
    }
} else {
    // Congestion avoidance: CUBIC window function
    let t = self.epoch_start.map(|s| now.duration_since(s).as_secs_f64()).unwrap_or(0.0);
    let rtt_secs = self.srtt.as_secs_f64().max(0.001);

    // W_cubic(t) = C * (t - K)^3 + W_max (in packets)
    let w_cubic_packets = self.c * (t - self.k).powi(3) + (self.w_max as f64 / self.mss as f64);
    let w_cubic = (w_cubic_packets * self.mss as f64) as usize;

    // TCP friendliness (§4.4): W_tcp(t) = w_max*(1-beta) + 3*beta/(2-beta) * t/RTT
    let t_rtt = t / rtt_secs;
    let w_tcp_packets = (self.w_max as f64 / self.mss as f64) * (1.0 - self.beta)
        + 3.0 * self.beta / (2.0 - self.beta) * t_rtt;
    let w_tcp = (w_tcp_packets * self.mss as f64) as usize;

    // Use max of CUBIC and TCP-friendly
    let target = w_cubic.max(w_tcp).max(self.cwnd);
    // Gradual increase: don't jump to target, increase by at most MSS per ACK
    if target > self.cwnd {
        let inc = (target - self.cwnd).min(self.mss);
        self.cwnd += inc;
    }
}
```

**TCP friendliness (`tcp_friendly_cwnd`):**
```rust
// RFC 9438 §4.4: W_tcp(t) = w_max * (1 - beta) + 3*beta/(2-beta) * t/RTT
fn tcp_friendly_cwnd(&self, t: f64) -> usize {
    let rtt_secs = self.srtt.as_secs_f64().max(0.001);
    let t_rtt = t / rtt_secs;
    let w_max_packets = self.w_max as f64 / self.mss as f64;
    let w_tcp_packets = w_max_packets * (1.0 - self.beta)
        + 3.0 * self.beta / (2.0 - self.beta) * t_rtt;
    (w_tcp_packets * self.mss as f64) as usize
}
```

**Hybrid slow start (HyStart++, §4.5):**
```rust
fn check_hystart_exit(&self) -> bool {
    // Exit slow start if RTT increases by > 8%
    if self.last_rtt > Duration::ZERO {
        let rtt_increase = (self.srtt.as_secs_f64() - self.last_rtt.as_secs_f64())
            / self.last_rtt.as_secs_f64();
        return rtt_increase > self.rtt_increase_threshold;
    }
    false
}
```

### Integration with CC framework
The existing CC framework uses enum dispatch (`CcImpl`) for zero-vtable
hot-path performance. CUBIC must be added to:
1. `Algorithm` enum → `Cubic` variant.
2. `CcImpl` enum → `Cubic(cubic::Cubic)` and
   `StealthCubic(stealth_shaper::StealthShaper<cubic::Cubic>)` variants.
3. `create()` factory → `Algorithm::Cubic` arm.
4. `cc_dispatch!` macro → `Cubic` and `StealthCubic` arms.
5. `CongestionControlAlgorithm` (public API) → `Cubic` variant.
6. `set_cc_algorithm_name` → `"cubic"` arm.
7. `set_stealth_mode` → `StealthCubic` wrapping logic.

## Implementation Plan

### Step 1: Implement CUBIC core in `src/transport/cc/cubic.rs`
- `Cubic` struct with all state variables listed above.
- `new(initial_cwnd: usize, mss: usize) -> Self` — initialize with RFC 9438
  defaults (beta=0.7, c=0.4, hystart=true).
- Implement all `CongestionController` trait methods.
- `on_packet_sent`: increment `bytes_in_flight`, call FEC callback.
- `on_ack`: CUBIC window growth (slow start or congestion avoidance per
  algorithm above).
- `on_loss` / `on_loss_packet`: CUBIC multiplicative decrease per algorithm
  above, call FEC callback.
- `update_rtt`: update `srtt` (EWMA), track `min_rtt`, update `last_rtt` for
  HyStart.
- `cwnd`, `bytes_in_flight`, `pacing_rate` (returns `None` — CUBIC has no
  built-in pacing), `loss_rate`, `mss`, `send_quantum`, `can_send`,
  `set_fec_callbacks`.
- `minimum_window()`: `2 * mss` (RFC 9002 minimum for QUIC).

### Step 2: Implement `CongestionController` trait for `Cubic`
Implement all trait methods from `src/transport/cc/mod.rs:30-73`. Follow the
same pattern as `reno.rs` for simple methods, add CUBIC-specific logic for
`on_ack` and `on_loss`.

### Step 3: Integrate into CC framework
In `src/transport/cc/mod.rs`:
- Add `pub mod cubic;` (line ~9).
- Add `Cubic` variant to `Algorithm` enum (line 17-24).
- Add `Cubic(cubic::Cubic)` and
  `StealthCubic(stealth_shaper::StealthShaper<cubic::Cubic>)` variants to
  `CcImpl` (line 76-83).
- Add `Algorithm::Cubic => CcImpl::Cubic(cubic::Cubic::new(initial_cwnd, mss))`
  to `create()` (line 86-92).
- Add `CcImpl::Cubic(cc)` and `CcImpl::StealthCubic(cc)` arms to
  `cc_dispatch!` macro (line 95-106).

### Step 4: Integrate into public API
In `src/transport.rs`:
- Add `Cubic` variant to `CongestionControlAlgorithm` enum (line 210-217).
- Update doc comment.

In `src/transport/config.rs`:
- Add `"cubic" => CongestionControlAlgorithm::Cubic` to
  `set_cc_algorithm_name` match (line 186-190).
- Update doc comment at line 175 to include `cubic`.

### Step 5: StealthShaper compatibility
In `src/transport/cc/stealth_shaper.rs`:
- `StealthShaper<CC>` is generic over `CongestionController`. Since `Cubic`
  implements `CongestionController`, `StealthShaper<Cubic>` works automatically.
- Add `StealthCubic` variant to `CcImpl` and `cc_dispatch!` as noted in Step 3.

In `src/transport/recovery.rs`:
- Add `Cubic` and `StealthCubic` handling to `set_stealth_mode()` (line 89-135):
  ```rust
  CcImpl::Cubic(_) if enabled => {
      let placeholder = CcImpl::Reno(cc::reno::Reno::new(self.cwnd, self.mss));
      let old = std::mem::replace(&mut self.cc, placeholder);
      if let CcImpl::Cubic(inner) = old {
          self.cc = CcImpl::StealthCubic(
              cc::stealth_shaper::StealthShaper::new(inner, profile)
          );
      }
  }
  CcImpl::StealthCubic(ref mut shaper) => {
      shaper.set_enabled(enabled);
      if enabled { shaper.set_profile(profile); }
  }
  ```

### Step 6: Add `on_path_change` support (TODO-450 dependency)
When TODO-450 is implemented, CUBIC's `on_path_change` should:
- Set `w_max = cwnd`.
- Set `ssthresh = cwnd * beta` (0.7).
- Set `cwnd = ssthresh`.
- Start new CUBIC epoch (`epoch_start = Some(now)`).
- Recompute K.

### Step 7: Tests
Unit tests in `src/transport/cc/cubic.rs`:
- `test_cubic_slow_start` — cwnd grows by acked_bytes per ACK in slow start.
- `test_cubic_loss_reduction` — cwnd reduces by factor beta (0.7) on loss;
  w_max captures pre-loss cwnd.
- `test_cubic_k_calculation` — K = cbrt(w_max * beta / C) computed correctly.
- `test_cubic_window_function` — W(t) matches expected values for known t,
  K, w_max.
- `test_cubic_tcp_friendliness` — CUBIC cwnd ≥ TCP-friendly cwnd in concave
  region.
- `test_cubic_fast_convergence` — w_max reduced further on consecutive losses
  when w_max < w_last_max.
- `test_cubic_hybrid_slow_start` — exits slow start on RTT increase > 8%.
- `test_cubic_minimum_window` — cwnd never goes below 2 * MSS.
- `test_cubic_congestion_avoidance_growth` — cwnd grows per cubic function in
  congestion avoidance.

Integration tests:
- CUBIC vs Reno fairness: two connections (one CUBIC, one Reno) on a shared
  bottleneck; verify CUBIC does not starve Reno (Jain's fairness index > 0.8).
- CUBIC throughput vs BBR3: CUBIC should achieve comparable throughput under
  low-loss; BBR3 higher under loss.
- CUBIC under 5% random loss: verify CUBIC maintains reasonable throughput
  and does not collapse.
- CUBIC + StealthShaper: verify stealth shaping wraps CUBIC correctly.
- `set_cc_algorithm_name("cubic")` succeeds and sets CUBIC algorithm.

## Technology Choices

### RFC 9438 (CUBIC)
The IETF standard for CUBIC, published 2023. Replaces the earlier RFC 8312
(draft-ietf-tcpm-rfc8312bis). Key changes from RFC 8312:
- Clarified TCP friendliness formula.
- Added HyStart++ as recommended slow-start exit.
- Defined per-ACK window increment (not just per-RTT).
- Specified CUBIC in bytes (not packets) for QUIC compatibility.

### Reference implementations
- **Cloudflare quiche**: `quiche/src/recovery/congestion/cubic.rs` — CUBIC
  implementation based on draft-ietf-tcpm-rfc8312bis. Uses `libm::cbrt` for
  cube root. Good reference for the core algorithm.
  https://github.com/cloudflare/quiche/blob/master/quiche/src/recovery/congestion/cubic.rs
- **Mozilla neqo**: `neqo-transport/src/cc/cubic.rs` — CUBIC implementation
  based on RFC 9438. Notable: diverges from RFC 9438 for QUIC minimum cwnd
  (2*SMSS instead of 1*SMSS per RFC 9002). Good reference for QUIC-specific
  adaptations.
  https://github.com/mozilla/neqo/blob/main/neqo-transport/src/cc/cubic.rs
- **quinn**: `quinn-proto/src/congestion/cubic.rs` — CUBIC implementation
  with configurable `CubicConfig`. Uses `CubicState` for the math (W_cubic,
  W_est, K). Good reference for clean separation of math and state.
  https://docs.rs/quinn-proto/latest/src/quinn_proto/congestion/cubic.rs.html
- **oxiquic-transport**: CUBIC (RFC 9438) as default CC, with BBR v2 and
  NewReno. Uses `CongestionController` dispatch enum (similar to QuicFuscate's
  `CcImpl`). Good reference for enum-dispatch integration.

### Cube root computation
CUBIC requires computing `K = cbrt(w_max * beta / C)`. Options:
1. `f64::cbrt()` — standard library, available since Rust 1.0. Accurate and
   fast (hardware-accelerated on x86 with SSE/AVX).
2. `libm::cbrt()` — used by quiche for `no_std` compatibility. Not needed for
   QuicFuscate (we use `std`).

Use `f64::cbrt()` — it's in the standard library and hardware-accelerated.

### HyStart++ (RFC 9406)
HyStart++ is the recommended slow-start exit algorithm for CUBIC (RFC 9438
§4.5 references it). It improves on the original HyStart by:
- Using ACK train delay AND RTT increase for exit decision.
- Adding a bounded exit threshold to prevent premature exit.
- Ensuring minimum number of RTTs in slow start before exit.

Implementing HyStart++ is optional but recommended for production quality.

## Stealth/Efficiency Considerations

### Stealth: traffic pattern diversity
BBR3 has a distinctive traffic pattern:
- 8-phase PROBE_BW cycle with gain sequence [1.25, 0.75, 1.0, 1.0, 1.0, 1.0,
  1.0, 1.0] — periodic bandwidth probing.
- PROBE_RTT phase: cwnd floor to 4 packets for ~200ms every 10s — very
  distinctive pattern.

Some DPI systems can fingerprint BBR flows by these patterns. CUBIC has a
fundamentally different pattern:
- Cubic window growth: W(t) = C(t-K)^3 + W_max — smooth cubic curve.
- Loss-driven backoff: cwnd * 0.7 on loss — no periodic probing.
- No PROBE_RTT equivalent — no periodic cwnd floor.

By offering CUBIC, QuicFuscate can vary its traffic pattern. The `Brain`
system (intelligent stealth runtime) can select CUBIC when BBR fingerprinting
is detected, or randomly alternate between CUBIC and BBR3 to prevent
fingerprint stability.

### Stealth: CUBIC + StealthShaper
The `StealthShaper` wrapper (existing) injects browser-profile-specific
pacing jitter and gain shaping. It works with any `CongestionController`.
`StealthShaper<Cubic>` wraps CUBIC to make its traffic pattern match a
browser's TCP CUBIC pattern (Chrome on Linux, Safari on iOS, etc.). This is
more accurate than `StealthShaper<BBR3>` because most browsers actually use
CUBIC, not BBR.

### Efficiency: CUBIC vs BBR3 performance
- **Under low loss (< 1%)**: CUBIC and BBR3 achieve similar throughput.
  CUBIC's cubic growth function fills the pipe efficiently.
- **Under moderate loss (1-5%)**: BBR3 outperforms CUBIC because BBR3 ignores
  loss signals and uses its bandwidth model. CUBIC backs off on each loss.
- **Under high loss (> 5%)**: BBR3 significantly outperforms CUBIC. CUBIC
  may collapse if loss is frequent.
- **RTT fairness**: CUBIC is more RTT-fair than BBR3. BBR3 can be unfair to
  high-RTT flows because it probes bandwidth more aggressively. CUBIC's
  growth function is RTT-independent in the convex region.

### Efficiency: no built-in pacing
CUBIC does not have a built-in pacing rate (unlike BBR3). `pacing_rate()`
returns `None`. Pacing is handled by the `StealthShaper` wrapper if enabled,
or by the kernel's packet scheduler if not. Without pacing, CUBIC may send
bursts (cwnd worth of packets at once), which can cause bufferbloat. The
`send_quantum` method limits burst size to `min(cwnd, 3 * mss)`.

## Testing Plan

### Unit tests
- `test_cubic_slow_start` — cwnd grows by acked_bytes per ACK in slow start.
- `test_cubic_slow_start_exit` — exits slow start when cwnd >= ssthresh.
- `test_cubic_loss_reduction` — cwnd reduces by factor 0.7 on loss; w_max
  captures pre-loss cwnd; ssthresh = new cwnd; in_slow_start = false.
- `test_cubic_k_calculation` — K = cbrt(w_max * beta / C) computed correctly
  for known w_max values.
- `test_cubic_window_function` — W(t) = C(t-K)^3 + W_max matches expected
  values for known t, K, w_max (test with t < K, t = K, t > K).
- `test_cubic_tcp_friendliness` — in concave region, CUBIC cwnd ≥ TCP-friendly
  cwnd; in convex region, TCP-friendly cwnd may exceed CUBIC cwnd.
- `test_cubic_fast_convergence` — on consecutive losses where w_max <
  w_last_max, w_max is reduced further (w_max * (1 + beta) / 2).
- `test_cubic_hybrid_slow_start` — exits slow start when RTT increases > 8%.
- `test_cubic_minimum_window` — cwnd never goes below 2 * MSS even after
  repeated losses.
- `test_cubic_congestion_avoidance_growth` — cwnd grows per cubic function;
  verify growth rate is correct for known t values.
- `test_cubic_pacing_rate_none` — `pacing_rate()` returns `None`.
- `test_cubic_send_quantum` — `send_quantum()` returns `min(cwnd, 3 * mss)`.
- `test_cubic_fec_callbacks` — FEC callbacks are called on send and loss.

### Integration tests
- **CUBIC vs Reno fairness**: two connections (one CUBIC, one Reno) on a
  shared bottleneck (tc-netem). Verify Jain's fairness index > 0.8.
- **CUBIC throughput vs BBR3**: under low loss, CUBIC throughput ≥ 80% of
  BBR3 throughput. Under 5% loss, BBR3 throughput ≥ 150% of CUBIC.
- **CUBIC under 5% random loss**: throughput > 50% of loss-free throughput.
- **CUBIC + StealthShaper**: verify stealth shaping wraps CUBIC correctly;
  pacing jitter is applied; browser profile is respected.
- **`set_cc_algorithm_name("cubic")`**: succeeds, sets CUBIC algorithm,
  `cc_algorithm()` returns `Cubic`.
- **No regression**: BBR2/BBR3/Reno tests still pass.

### Performance tests
- CUBIC unit tests (state machine): < 5s.
- CUBIC vs Reno fairness (10s transfer): < 30s.
- CUBIC vs BBR3 throughput: < 30s.
- CUBIC under 5% loss: < 30s.
- K calculation precision: < 1e-6 relative error (cbrt must be accurate).
- Memory overhead vs Reno: < 200 bytes (extra CUBIC state fields).

## Files to Create/Modify

- `src/transport/cc/cubic.rs` — **new**: `Cubic` struct, CUBIC algorithm
  (RFC 9438), `CongestionController` impl, HyStart++ (optional), unit tests.
- `src/transport/cc/mod.rs` — add `pub mod cubic`; add `Cubic` to `Algorithm`,
  `CcImpl`, `create()`, `cc_dispatch!`.
- `src/transport.rs` — add `Cubic` to `CongestionControlAlgorithm` enum.
- `src/transport/config.rs` — add `"cubic"` to `set_cc_algorithm_name`; update
  doc comments.
- `src/transport/recovery.rs` — add `Cubic` and `StealthCubic` handling to
  `set_stealth_mode()`.
- `src/transport/cc/stealth_shaper.rs` — verify `StealthShaper<Cubic>` works
  (generic over `CongestionController`, should work automatically).
- Integration tests: CUBIC fairness, CUBIC vs BBR3 throughput, CUBIC under
  loss, CUBIC + StealthShaper.

## Risks & Mitigations

| Risk | Impact | Mitigation |
|------|--------|------------|
| CUBIC math errors (cbrt, cubic function) | High — correctness | Use `f64::cbrt()` (std lib); test against known values from RFC 9438 appendix |
| TCP friendliness formula incorrect | Medium — fairness | Test against Reno on shared bottleneck; verify Jain's index > 0.8 |
| HyStart++ premature slow-start exit | Low — performance | Make HyStart configurable (on/off); default on but can be disabled |
| `StealthShaper<Cubic>` not working | Medium — stealth | `StealthShaper` is generic over `CongestionController`; verify with unit test; add `StealthCubic` to `CcImpl` |
| CUBIC collapses under high loss | Low — expected behavior | CUBIC is known to underperform BBR3 under high loss; document this; users can choose BBR3 for lossy paths |
| `cc_dispatch!` macro expansion grows | Low — compile time | Adding 2 more arms (Cubic, StealthCubic) is trivial; macro is small |
| CUBIC cwnd in bytes vs packets confusion | Medium — correctness | All cwnd values in bytes (consistent with Reno/BBR3); convert to packets only for K computation and W(t) formula |

## Completion Criteria

- [ ] `set_cc_algorithm_name("cubic")` succeeds and sets `Cubic` algorithm.
- [ ] `cc_algorithm()` returns `Cubic` after setting.
- [ ] CUBIC slow start: cwnd grows by acked_bytes per ACK until ssthresh.
- [ ] CUBIC loss response: cwnd reduces by factor 0.7 (beta); `w_max` captures
      pre-loss cwnd; `ssthresh = new_cwnd`; exits slow start.
- [ ] CUBIC window function: `W(t) = C(t-K)^3 + W_max` computed correctly
      (verified against known test vectors from RFC 9438).
- [ ] TCP friendliness: in concave region, CUBIC cwnd ≥ TCP Reno estimate.
- [ ] Fast convergence: on consecutive losses with `w_max < w_last_max`,
      `w_max` is reduced further.
- [ ] Hybrid slow start: exits slow start when RTT increases > 8%.
- [ ] Minimum window: cwnd never goes below 2 * MSS.
- [ ] `pacing_rate()` returns `None` (CUBIC has no built-in pacing).
- [ ] CUBIC + Reno fairness: Jain's fairness index > 0.8 on shared bottleneck.
- [ ] CUBIC under 5% random loss: throughput > 50% of loss-free throughput.
- [ ] `StealthShaper<Cubic>` works (stealth shaping wraps CUBIC correctly).
- [ ] `set_stealth_mode(true, profile)` wraps CUBIC in `StealthCubic`.
- [ ] No regression in BBR2/BBR3/Reno tests.
- [ ] Unit tests for all CUBIC algorithm paths (slow start, loss, K, W(t),
      TCP friendliness, fast convergence, HyStart, minimum window).
- [ ] K calculation precision: < 1e-6 relative error.
- [ ] Memory overhead vs Reno: < 200 bytes extra.
