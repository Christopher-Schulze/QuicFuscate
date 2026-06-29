---
id: TODO-463
title: "Loss detection improvements: time-based loss, RACK, RTT variance, Reno bandwidth estimation"
severity: MEDIUM
phase: "J"
priority: P2
status: OPEN
created: 2026-06-30
depends_on: []
---

# TODO-463: Loss Detection Improvements — Time-Based Loss, RACK, RTT Variance, Reno Bandwidth Estimation

## Problem

Loss detection in `src/transport/recovery.rs` has four gaps that cause
slower loss detection on lossy links and suboptimal retransmission timing.

### 1. No explicit time-based loss detection (only PTO-based)

`src/transport/recovery.rs:217-223` — the only loss deadline is the PTO
(probe timeout) deadline:

```rust
pub fn pto_deadline(&self, now: Instant) -> Instant {
    let base = Duration::from_millis(200);
    let pto = self.rtt.saturating_mul(2) + base;
    let backoff = 1u32 << self.pto_count.min(8);
    now + pto * backoff
}
```

There is no time-based loss detection (RFC 9002 §6.1): if packet N is
acked and packet N-1 was sent more than `loss_delay` ago, packet N-1
should be declared lost immediately — without waiting for PTO. The
current code only declares losses via explicit `on_loss_packet` calls
driven by ACK gaps; packets lost without a later ACK covering their range
wait until PTO fires, which on lossy links means multi-RTT stalls.

### 2. No RACK (RFC 8985) implementation

There is no RACK (Recent Acknowledgment) logic. RACK tracks the highest
acked packet number and its send time; any unacked packet sent before
`highest_acked_send_time - RACK_RTT` is declared lost. RACK detects
losses that ACK-gap-based detection misses (e.g. tail losses, reordering
events) and is especially effective on paths with reordering. A grep for
`rack` / `RACK` across `src/transport/` returns no results.

### 3. No RTT variance tracking (only min/avg in BBR)

`src/transport/recovery.rs:206-210` — RTT is stored as a single smoothed
value:

```rust
pub fn update_rtt(&mut self, rtt: Duration) {
    self.rtt = rtt;
    self.cc.update_rtt(rtt);
}
```

The BBR implementations (BBR2/BBR3 in `src/transport/cc/`) track min and
avg RTT but **no variance / stddev / EWMA variance**. Without variance,
BBR's probe timing and the PTO `loss_delay` cannot adapt to jittery
paths: a path with high RTT variance needs a larger `loss_delay` to avoid
spurious retransmissions, while a low-variance path can use a tighter
`loss_delay` for faster loss detection.

### 4. No explicit bandwidth estimation for Reno

The Reno CC (`src/transport/cc/reno.rs`) relies on ACK clocking only —
it grows cwnd via AIMD but has no delivery-rate / bandwidth estimate.
On high-BDP (bandwidth-delay product) links, pure ACK-clocking Reno
underperforms because it cannot pace bursts to the estimated bottleneck
rate, leading to burst-induced loss and underutilization. BBR has
bandwidth estimation; Reno does not.

## Goal

- **Time-based loss detection**: declare a packet lost when a later
  packet is acked and the unacked packet was sent > `loss_delay` ago,
  where `loss_delay = max(SRTT/4, 1ms)`.
- **RACK (RFC 8985)**: track the highest acked packet number + send time;
  declare unacked packets sent before `highest_acked_send_time - RACK_RTT`
  lost.
- **RTT variance**: add EWMA variance (and/or stddev) to RTT estimates in
  BBR2/BBR3 and the `Recovery` struct; use it to scale `loss_delay` and
  PTO.
- **Reno bandwidth estimation**: add simple delivery-rate tracking to
  Reno so it can pace to the estimated bottleneck rate on high-BDP links.
- Net effect: losses detected faster (RACK + time-based), fewer spurious
  retransmissions on jittery paths (variance-aware `loss_delay`), and
  improved Reno throughput on high-BDP links.

## Implementation Plan

### Step 1: Time-based loss detection

**File:** `src/transport/recovery.rs`

Add a sent-packet tracker and a time-based loss check. The `Recovery`
struct already has `loss_time: Option<Instant>` (line 32); wire it up:

```rust
pub struct SentPacket {
    pub pkt_num: u64,
    pub sent_bytes: usize,
    pub sent_time: Instant,
    pub ack_eliciting: bool,
}

// In Recovery:
pub sent_packets: Vec<SentPacket>,   // or a ring buffer keyed by pkt_num

pub fn on_packet_sent(&mut self, pkt_num: u64, sent_bytes: usize, now: Instant) {
    self.cc.on_packet_sent(pkt_num, sent_bytes, now);
    self.sent_packets.push(SentPacket {
        pkt_num, sent_bytes, sent_time: now, ack_eliciting: sent_bytes > 0,
    });
    self.sync_from_cc();
}
```

Add a time-based loss detection function called on each ACK event:

```rust
/// RFC 9002 §6.1 time-based loss detection. Declares packets lost if
/// they were sent more than `loss_delay` before the largest acked
/// packet's send time.
fn detect_time_based_losses(&mut self, largest_acked: u64, now: Instant) {
    let loss_delay = self.loss_delay();
    let largest_sent_time = self.sent_packets.iter()
        .find(|p| p.pkt_num == largest_acked)
        .map(|p| p.sent_time);
    if let Some(largest_t) = largest_sent_time {
        let threshold = largest_t - loss_delay;
        let mut newly_lost = Vec::new();
        self.sent_packets.retain(|p| {
            if p.pkt_num < largest_acked && p.sent_time <= threshold && p.ack_eliciting {
                newly_lost.push(p.clone());
                false
            } else {
                true
            }
        });
        for p in newly_lost {
            self.on_loss_packet(p.pkt_num, p.sent_bytes, now);
        }
    }
}

fn loss_delay(&self) -> Duration {
    let var = self.rtt_var;                 // from Step 3
    let quarter = self.rtt / 4;
    let computed = quarter + var;
    computed.max(Duration::from_millis(1))
}
```

### Step 2: RACK (RFC 8985)

**File:** `src/transport/recovery.rs`

Add RACK state and logic:

```rust
// In Recovery:
pub rack_xmit_ts: Option<Instant>,   // send time of highest acked packet
pub rack_rtt: Duration,              // RACK_RTT (max of SRTT and min RTT)
pub rack_fack: u64,                  // highest acked packet number

pub fn on_ack(&mut self, acked_bytes: usize, largest_acked: u64, now: Instant) {
    // ... existing CC update ...
    // Update RACK state.
    if let Some(p) = self.sent_packets.iter().find(|p| p.pkt_num == largest_acked) {
        self.rack_xmit_ts = Some(p.sent_time);
        self.rack_fack = largest_acked;
        self.rack_rtt = self.rtt.max(self.min_rtt);
    }
    // RACK loss detection: any unacked packet sent before
    // (rack_xmit_ts - rack_rtt) is declared lost.
    if let Some(xmit_ts) = self.rack_xmit_ts {
        let threshold = xmit_ts.saturating_sub(self.rack_rtt);
        let mut newly_lost = Vec::new();
        self.sent_packets.retain(|p| {
            if p.pkt_num < self.rack_fack && p.sent_time <= threshold && p.ack_eliciting {
                newly_lost.push(p.clone());
                false
            } else {
                true
            }
        });
        for p in newly_lost {
            self.on_loss_packet(p.pkt_num, p.sent_bytes, now);
        }
    }
    // Time-based loss detection (Step 1) — run after RACK.
    self.detect_time_based_losses(largest_acked, now);
}
```

Note: RACK and time-based loss detection are complementary; RACK catches
tail/reorder losses, time-based catches the general case. Both remove
packets from `sent_packets` and call `on_loss_packet`.

### Step 3: RTT variance (EWMA variance)

**File:** `src/transport/recovery.rs`, `src/transport/cc/bbr2.rs`,
`src/transport/cc/bbr3.rs`

Add an EWMA RTT variance to `Recovery`:

```rust
pub rtt_var: Duration,   // EWMA of |RTT - SRTT|
pub min_rtt: Duration,

pub fn update_rtt(&mut self, rtt: Duration) {
    // EWMA variance: var = (1 - alpha) * var + alpha * |rtt - srtt|
    let alpha = 0.125; // same as RFC 6298 SRTT weight
    let delta = if rtt > self.rtt { rtt - self.rtt } else { self.rtt - rtt };
    self.rtt_var = (self.rtt_var * (1.0 - alpha)) + (delta * alpha);
    // Update SRTT (existing).
    self.rtt = rtt;
    self.min_rtt = self.min_rtt.min(rtt);
    self.cc.update_rtt(rtt);
    // Propagate variance to BBR.
    self.cc.update_rtt_var(self.rtt_var);
}
```

In BBR2/BBR3, add an `update_rtt_var` method on the `CongestionController`
trait (default no-op for Reno) and use the variance to scale the probe
interval and the `loss_delay`. This makes BBR probing adaptive to jitter.

### Step 4: Reno bandwidth estimation (delivery-rate tracking)

**File:** `src/transport/cc/reno.rs`

Add a simple delivery-rate estimator to Reno:

```rust
pub struct Reno {
    // ... existing fields ...
    delivery_rate: u64,         // bytes/sec estimate
    delivered: u64,             // total bytes delivered (acked)
    delivered_ts: Instant,      // last delivery-rate sample time
    max_bw: u64,                // max observed delivery rate (for pacing)
}

impl Reno {
    pub fn on_ack(&mut self, acked_bytes: usize, now: Instant) {
        // ... existing AIMD cwnd logic ...
        // Delivery-rate sample.
        self.delivered += acked_bytes as u64;
        let elapsed = now.saturating_duration_since(self.delivered_ts);
        if elapsed >= Duration::from_millis(10) {
            let rate = (self.delivered as u128 * 1_000_000_000 / elapsed.as_nanos()) as u64;
            self.delivery_rate = rate;
            self.max_bw = self.max_bw.max(rate);
            self.delivered = 0;
            self.delivered_ts = now;
        }
    }

    pub fn pacing_rate(&self) -> Option<u64> {
        if self.max_bw > 0 { Some(self.max_bw) } else { None }
    }
}
```

This gives Reno a `pacing_rate()` (already in the `CongestionController`
trait) so the pacer can smooth bursts to the estimated bottleneck rate on
high-BDP links, reducing burst-induced loss.

### Step 5: Wire `on_ack` to pass `largest_acked`

**File:** `src/transport/connection.rs` (the ACK processing path)

The current `Recovery::on_ack(&mut self, acked_bytes, now)` signature
(line 182) does not receive the largest acked packet number. Update the
call site in `connection.rs` to pass `largest_acked` so RACK and
time-based loss detection have the information they need. Update the
`CongestionController::on_ack` trait if necessary (or pass
`largest_acked` only to the `Recovery`-level loss logic, not the CC).

### Step 6: Tests

**File:** `src/transport/recovery.rs` (inline tests),
`tests/loss_detection_test.rs` (new)

- **Time-based loss**: send packets 1,2,3; ACK packet 3 after > SRTT/4;
  assert packet 1 is declared lost via time-based detection (without
  waiting for PTO).
- **RACK**: send packets 1,2,3 with reordering; ACK 3 then 2; assert
  packet 1 is declared lost via RACK (sent before `rack_xmit_ts -
  rack_rtt`).
- **RTT variance**: feed a sequence of RTT samples with high variance;
  assert `rtt_var` grows; feed low-variance samples; assert `rtt_var`
  shrinks; assert `loss_delay` scales with variance.
- **Reno bandwidth**: send a burst, ACK at a steady rate; assert
  `reno.pacing_rate()` converges to the ACK rate; assert pacing reduces
  burst-induced loss on a high-BDP simulation.
- **Integration (tc netem)**: on a loopback with `tc netem loss 5%`,
  compare loss-detection latency before/after: RACK + time-based should
  detect losses faster than PTO-only.

## Files to Modify/Create

- `src/transport/recovery.rs` — `SentPacket` struct, `sent_packets`
  tracker, `detect_time_based_losses`, `loss_delay`, RACK state
  (`rack_xmit_ts`, `rack_rtt`, `rack_fack`) + RACK loss detection, RTT
  variance (`rtt_var`, `min_rtt`), updated `on_ack`/`on_packet_sent`/
  `update_rtt`.
- `src/transport/cc/bbr2.rs`, `src/transport/cc/bbr3.rs` —
  `update_rtt_var` impl; use variance to scale probe interval.
- `src/transport/cc/reno.rs` — delivery-rate tracking (`delivery_rate`,
  `delivered`, `delivered_ts`, `max_bw`), `pacing_rate()` impl.
- `src/transport/cc/mod.rs` — add `update_rtt_var` to
  `CongestionController` trait (default no-op).
- `src/transport/connection.rs` — pass `largest_acked` to
  `Recovery::on_ack`.
- `tests/loss_detection_test.rs` — **new**: time-based, RACK, variance,
  Reno bandwidth, tc netem integration.

## Acceptance Criteria

- [ ] Time-based loss detection declares a packet lost when a later
      packet is acked and the unacked packet was sent > `loss_delay`
      ago, where `loss_delay = max(SRTT/4 + RTT_var, 1ms)`.
- [ ] RACK tracks the highest acked packet number + send time and
      declares unacked packets sent before `rack_xmit_ts - rack_rtt`
      lost.
- [ ] RTT variance (EWMA) is tracked in `Recovery` and propagated to
      BBR2/BBR3; `loss_delay` scales with variance.
- [ ] Reno tracks delivery rate and exposes a non-zero `pacing_rate()`
      after steady ACKs.
- [ ] On a `tc netem loss 5%` loopback, loss-detection latency is lower
      with RACK + time-based detection than with PTO-only (measured).
- [ ] RTT variance improves BBR probing on jittery paths (no spurious
      retransmissions when variance is high).
- [ ] Reno bandwidth estimation improves throughput on a high-BDP
      simulation (measured vs. ACK-clocking-only baseline).
- [ ] `Recovery::on_ack` receives `largest_acked` from the connection
      layer.
- [ ] `cargo test` passes with all new tests green; `cargo Clippy`
      reports no new warnings.
- [ ] No regression in existing recovery/CC unit tests.

## Resource Budget

| Scenario | Budget | Notes |
|----------|--------|-------|
| Time-based loss check per ACK | < 5 µs | Linear scan of sent_packets (bounded by cwnd/MSS) |
| RACK loss check per ACK | < 5 µs | Same scan, merged with time-based |
| RTT variance EWMA update | < 100 ns | Two arithmetic ops |
| Reno delivery-rate sample | < 100 ns | One division per 10ms window |
| tc netem integration test | < 60s | 5% loss loopback, 1000 packets |
| High-BDP Reno throughput test | < 30s | Simulated 100 Mbps / 200 ms RTT |
| Sent-packet tracker memory | ~cwnd/MSS entries | Ring buffer to bound memory |
