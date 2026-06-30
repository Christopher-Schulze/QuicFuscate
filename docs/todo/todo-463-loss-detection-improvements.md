---
id: TODO-463
title: "Loss detection improvements: time-based loss, RACK, RTT variance, Reno bandwidth estimation"
severity: HIGH
phase: "J"
priority: P2
status: DONE
created: 2026-07-23
depends_on: [TODO-452]
---

# TODO-463: Loss Detection Improvements — Time-Based Loss, RACK, RTT Variance, Reno Bandwidth Estimation

## Goal

Upgrade QUIC loss detection from the current PTO-only + packet-threshold approach to a
multi-strategy loss detection system implementing RFC 9002 §6.1 time-based loss detection,
RFC 8985 RACK-TLP (Recent Acknowledgment + Tail Loss Probe), EWMA RTT variance tracking,
and Reno delivery-rate estimation for CUBIC compatibility. This will reduce spurious
retransmissions on jittery paths, detect losses faster on lossy links (especially tail
losses and reordering events), and improve Reno throughput on high-BDP links — all without
regressing BBR3 performance.

## Current State (verified against code)

### Loss detection: PTO + packet-threshold only

- **`src/transport/recovery.rs:217-223`** — `pto_deadline()`: the only loss deadline is
  the PTO (probe timeout):
  ```rust
  pub fn pto_deadline(&self, now: Instant) -> Instant {
      let base = Duration::from_millis(200);
      let pto = self.rtt.saturating_mul(2) + base;
      let backoff = 1u32 << self.pto_count.min(8);
      now + pto * backoff
  }
  ```
  This is a simplified PTO — it does not include `max_ack_delay` (RFC 9002 §6.2.1:
  `PTO = smoothed_rtt + max(4*rttvar, kGranularity) + max_ack_delay`). The `rttvar`
  term is missing entirely because RTT variance is not tracked.

- **`src/transport/recovery.rs:199-204`** — `on_loss_packet()`: records a loss event
  and increments `pto_count`, but does not perform time-based or RACK loss detection.
  Losses are only declared by the caller (`connection.rs`).

- **`src/transport/connection.rs:3550-3614`** — `account_sent_bytes_for_ack_ranges_with_delay()`:
  This is the **only** loss detection path. It uses a **packet threshold** of 3
  (line 3560: `let packet_threshold = 3u64;`):
  ```rust
  if largest_acked >= packet_threshold {
      let loss_cutoff = largest_acked - packet_threshold;
      let lost: Vec<(u64, (usize, Instant))> = self
          .sent_packets_by_pn
          .range(..=loss_cutoff)
          .map(|(&pn, &info)| (pn, info))
          .collect();
  ```
  Any packet with PN < `largest_acked - 3` is declared lost. This is the RFC 9002 §6.1.1
  packet threshold approach. There is **no time-based loss detection** (§6.1.2): a packet
  is not declared lost based on how long ago it was sent, only based on how many later
  packets have been acked.

- **`src/transport/connection.rs:229`** — `sent_packets_by_pn: BTreeMap<u64, (usize, Instant)>`:
  Tracks sent packets by PN with bytes and send time. The send time is used only for RTT
  sampling (line 3575-3576), not for time-based loss detection.

### RTT tracking: single smoothed value, no variance

- **`src/transport/recovery.rs:206-210`** — `update_rtt()`: stores a single RTT value:
  ```rust
  pub fn update_rtt(&mut self, rtt: Duration) {
      self self.rtt = rtt;
      self.cc.update_rtt(rtt);
  }
  ```
  This is **not** an EWMA smoothed RTT (SRTT) — it replaces the value entirely on each
  sample. RFC 6298 / RFC 9002 §5.1 specifies `SRTT = (1 - α) * SRTT + α * R` where
  α = 0.125. The current code does not smooth at all — it uses the latest sample directly.

- **`src/transport/cc/bbr3.rs:295-301`** — BBR3 `update_rtt()`: tracks `min_rtt` but no
  variance:
  ```rust
  fn update_rtt(&mut self, rtt: Duration) {
      self.rtt = rtt;
      if rtt < self.min_rtt {
          self.min_rtt = rtt;
          self.probe_rtt_min_stamp = Instant::now();
      }
  }
  ```
  No `rtt_var`, no EWMA, no stddev. BBR3's ProbeRTT timing uses a fixed 10-second window
  (`MIN_RTT_WIN`, line 22) and 200ms duration (`PROBE_RTT_DURATION`, line 23) — these
  do not adapt to RTT variance.

- **`src/transport/cc/reno.rs:99-101`** — Reno `update_rtt()`: single value, no smoothing:
  ```rust
  fn update_rtt(&mut self, rtt: Duration) {
      self.rtt = rtt;
  }
  ```

- **`src/transport/cc/bbr2.rs:127-131`** — BBR2 has RTT tracking fields but also no
  variance: `min_rtt`, `rtt` only.

### No RACK implementation

A grep for `rack` / `RACK` across `src/transport/` returns **no results**. There is no
RACK (Recent Acknowledgment) logic — no tracking of highest acked packet number + send
time, no time-based loss declaration from RACK, no TLP (Tail Loss Probe) generation.

### No Reno bandwidth estimation

- **`src/transport/cc/reno.rs:111-114`** — `pacing_rate()` returns `None`:
  ```rust
  fn pacing_rate(&self) -> Option<u64> {
      // Reno does not pace; return None to let the caller send at line rate
      None
  }
  ```
  Reno has no delivery-rate tracking, no bandwidth estimate, no pacing. On high-BDP
  links, this leads to burst-induced loss because Reno sends at line rate without
  pacing to the bottleneck bandwidth.

### CongestionController trait

- **`src/transport/cc/mod.rs:30-73`** — `CongestionController` trait: has `update_rtt`
  but no `update_rtt_var`. The `on_ack` method takes `(acked_bytes, now)` but does not
  receive `largest_acked` — RACK needs this information.

## Problem Analysis

### 1. No time-based loss detection (RFC 9002 §6.1.2)

The current code only declares losses via packet threshold (PN < largest_acked - 3).
RFC 9002 §6.1.2 specifies that a packet should also be declared lost if it was sent
more than `loss_delay` ago, where `loss_delay = max(kTimeThreshold * SRTT, kGranularity)`
and `kTimeThreshold = 9/8`. Without time-based loss detection:

- **Tail losses**: If the last 1-2 packets in a flight are lost, there may not be 3
  later acked packets to trigger the packet threshold. The lost packets wait until PTO
  fires, causing multi-RTT stalls.
- **Reordering**: If packets are reordered by >3 positions, the packet threshold
  falsely declares them lost, causing spurious retransmissions.
- **Lossy links**: On links with 5% random loss, packet-threshold-only detection is
  either too aggressive (false positives at 3) or too slow (waiting for PTO).

### 2. No RACK (RFC 8985)

RACK-TLP has been the **default** loss detection algorithm in Linux TCP since 2018
and was published as RFC 8985 in February 2021. The Linux kernel has since **removed**
the obsolete RFC 3517/RFC 6675 loss recovery code entirely (2024 commit), making RACK
the only supported algorithm. RACK detects losses by time: if a packet sent later has
been acked, any unacked packet sent before `latest_acked_send_time - RACK_RTT` is
declared lost. This is more accurate than packet counting because:

- **Tail loss detection**: RACK catches tail losses that packet-threshold misses.
- **Reordering resilience**: RACK's reordering window (`reo_wnd = min_RTT / 4`)
  adapts to the path's reordering behavior.
- **Lost retransmission detection**: RACK detects lost retransmissions (a retransmitted
  packet that is itself lost) — packet-threshold cannot do this.
- **Application-limited flights**: RACK works correctly when the sender is
  application-limited (not filling the cwnd), where packet-threshold is unreliable.

### 3. No RTT variance (RFC 6298 / RFC 9002 §5.1)

RFC 9002 §5.1 specifies both SRTT (smoothed RTT) and RTTVAR (RTT variation):
```
SRTT = (1 - α) * SRTT + α * R       (α = 0.125)
RTTVAR = (1 - β) * RTTVAR + β * |SRTT - R|   (β = 0.25)
```
The PTO formula (RFC 9002 §6.2.1) explicitly uses RTTVAR:
```
PTO = smoothed_rtt + max(4 * rttvar, kGranularity) + max_ack_delay
```
Without RTTVAR:
- PTO is too aggressive on jittery paths (low RTT variance → short PTO → spurious
  retransmissions).
- PTO is too conservative on stable paths (high RTT variance estimate → long PTO →
  slow loss detection).
- BBR3's ProbeRTT interval is fixed at 10 seconds regardless of path stability.

The current `update_rtt` (line 207) **replaces** the RTT entirely instead of EWMA
smoothing. This means a single noisy sample (e.g., a delayed ACK) can inflate the RTT
instantly, causing PTO to fire prematurely.

### 4. No Reno bandwidth estimation

Reno (`src/transport/cc/reno.rs`) relies on ACK clocking only — it grows cwnd via AIMD
but has no delivery-rate / bandwidth estimate. `pacing_rate()` returns `None`, so the
pacer sends at line rate. On high-BDP links (e.g., 100 Mbps / 200ms RTT = 2.5 MB BDP):

- Without pacing, Reno sends bursts of `cwnd` bytes at line rate, overwhelming
  intermediate routers and causing burst-induced loss.
- With bandwidth estimation and pacing, Reno can smooth bursts to the estimated
  bottleneck rate, reducing loss and improving throughput.
- BBR3 already has bandwidth estimation (`btlbw` field, delivery-rate tracking in
  `bbr3_on_ack`). Reno needs a simpler version for CUBIC compatibility (TODO-452).

## Proposed Architecture

```
┌──────────────────────────────────────────────────────────────────────────┐
│                    Multi-Strategy Loss Detection                          │
│                                                                          │
│  ┌─────────────────┐  ┌─────────────────┐  ┌────────────────────────┐   │
│  │ Packet Threshold │  │ Time-Based Loss │  │ RACK (RFC 8985)        │   │
│  │ (existing)       │  │ (RFC 9002 §6.1) │  │                        │   │
│  │                  │  │                 │  │ rack_xmit_ts           │   │
│  │ PN < la - 3      │  │ sent_time <     │  │ rack_rtt               │   │
│  │                  │  │ la_time -       │  │ rack_fack              │   │
│  │                  │  │ loss_delay      │  │ reo_wnd = min_rtt/4    │   │
│  └────────┬────────┘  └────────┬────────┘  └───────────┬────────────┘   │
│           │                    │                       │                │
│           ▼                    ▼                       ▼                │
│  ┌──────────────────────────────────────────────────────────────────┐   │
│  │           Loss Detection Coordinator (in Recovery)               │   │
│  │                                                                  │   │
│  │  on_ack(acked_bytes, largest_acked, now):                        │   │
│  │    1. Update SRTT + RTTVAR (EWMA)                                │   │
│  │    2. Update RACK state (rack_xmit_ts, rack_fack, rack_rtt)     │   │
│  │    3. Run packet-threshold loss detection (existing)             │   │
│  │    4. Run time-based loss detection (new)                        │   │
│  │    5. Run RACK loss detection (new)                              │   │
│  │    6. Update CC (on_ack)                                         │   │
│  │    7. Schedule loss detection timer if unacked packets remain    │   │
│  └──────────────────────────────────────────────────────────────────┘   │
│                                                                          │
│  ┌─────────────────┐  ┌──────────────────────────────────────────┐     │
│  │ RTT Tracker     │  │ Reno Bandwidth Estimator                 │     │
│  │                 │  │                                          │     │
│  │ srtt: EWMA      │  │ delivery_rate: bytes/sec                 │     │
│  │ rtt_var: EWMA   │  │ max_bw: max observed rate                │     │
│  │ min_rtt: min    │  │ pacing_rate() = Some(max_bw)             │     │
│  └─────────────────┘  └──────────────────────────────────────────┘     │
└──────────────────────────────────────────────────────────────────────────┘
```

## Implementation Plan

### Step 1: RTT variance (EWMA SRTT + RTTVAR)

**File:** `src/transport/recovery.rs`

Replace the current `update_rtt` with proper EWMA smoothing per RFC 6298 / RFC 9002 §5.1:

```rust
// New fields in Recovery:
pub srtt: Duration,       // Smoothed RTT (EWMA, α = 0.125)
pub rtt_var: Duration,    // RTT variation (EWMA, β = 0.25)
pub min_rtt: Duration,    // Minimum observed RTT
pub first_rtt_sample: bool, // true until first real RTT sample

pub fn update_rtt(&mut self, rtt_sample: Duration) {
    if rtt_sample == Duration::ZERO {
        return; // Ignore zero samples (no valid measurement)
    }
    if self.first_rtt_sample {
        // First sample: SRTT = R, RTTVAR = R/2 (RFC 6298 §2.2)
        self.srtt = rtt_sample;
        self.rtt_var = rtt_sample / 2;
        self.min_rtt = rtt_sample;
        self.first_rtt_sample = false;
    } else {
        // RTTVAR = (1 - β) * RTTVAR + β * |SRTT - R|  (β = 0.25)
        let alpha = 0.125;
        let beta = 0.25;
        let delta = if self.srtt > rtt_sample {
            self.srtt - rtt_sample
        } else {
            rtt_sample - self.srtt
        };
        self.rtt_var = Duration::from_secs_f64(
            (1.0 - beta) * self.rtt_var.as_secs_f64() + beta * delta.as_secs_f64()
        );
        // SRTT = (1 - α) * SRTT + α * R  (α = 0.125)
        self.srtt = Duration::from_secs_f64(
            (1.0 - alpha) * self.srtt.as_secs_f64() + alpha * rtt_sample.as_secs_f64()
        );
        self.min_rtt = self.min_rtt.min(rtt_sample);
    }
    // Keep self.rtt as alias for srtt (backward compat with existing code)
    self.rtt = self.srtt;
    // Propagate to CC
    self.cc.update_rtt(self.srtt);
    self.cc.update_rtt_var(self.rtt_var);
}
```

Add `update_rtt_var` to the `CongestionController` trait (default no-op):

```rust
// In CongestionController trait:
fn update_rtt_var(&mut self, rtt_var: Duration) {}
```

### Step 2: Fix PTO formula to use RTT variance

**File:** `src/transport/recovery.rs`

Update `pto_deadline` to match RFC 9002 §6.2.1:

```rust
pub fn pto_deadline(&self, now: Instant) -> Instant {
    let k_granularity = Duration::from_millis(1);
    let rttvar_term = std::cmp::max(self.rtt_var * 4, k_granularity);
    let pto = self.srtt + rttvar_term + self.max_ack_delay;
    let backoff = 1u32 << self.pto_count.min(8);
    now + pto * backoff
}
```

Add `max_ack_delay: Duration` field to `Recovery` (default 25ms from config).

### Step 3: Time-based loss detection

**File:** `src/transport/recovery.rs`

Add a sent-packet tracker and time-based loss detection:

```rust
pub struct SentPacket {
    pub pkt_num: u64,
    pub sent_bytes: usize,
    pub sent_time: Instant,
    pub ack_eliciting: bool,
}

// In Recovery:
pub sent_packets: VecDeque<SentPacket>,  // ordered by pkt_num

/// RFC 9002 §6.1.2 time-based loss detection.
/// Declares packets lost if they were sent more than `loss_delay` before
/// the largest acked packet's send time.
fn detect_time_based_losses(&mut self, largest_acked: u64, largest_acked_sent_time: Instant, now: Instant) {
    let loss_delay = self.loss_delay();
    let threshold = largest_acked_sent_time.saturating_sub(loss_delay);
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

/// loss_delay = max(kTimeThreshold * SRTT, kGranularity)
/// kTimeThreshold = 9/8 (RFC 9002 §6.1.2)
fn loss_delay(&self) -> Duration {
    let k_granularity = Duration::from_millis(1);
    let k_time_threshold = 1.125; // 9/8
    let computed = Duration::from_secs_f64(
        k_time_threshold * self.srtt.as_secs_f64()
    );
    std::cmp::max(computed, k_granularity)
}
```

### Step 4: RACK (RFC 8985)

**File:** `src/transport/recovery.rs`

Add RACK state and loss detection:

```rust
// In Recovery:
pub rack_xmit_ts: Option<Instant>,   // Send time of highest acked packet
pub rack_rtt: Duration,              // RACK_RTT = max(SRTT, min_RTT) + reo_wnd
pub rack_fack: u64,                  // Highest acked packet number (RACK.FACK)
pub rack_reo_wnd: Duration,          // Reordering window (min_RTT / 4)

fn update_rack(&mut self, largest_acked: u64, largest_acked_sent_time: Instant) {
    // Update RACK state (RFC 8985 §7.2)
    if self.rack_xmit_ts.map_or(true, |ts| largest_acked_sent_time > ts) {
        self.rack_xmit_ts = Some(largest_acked_sent_time);
        self.rack_fack = largest_acked;
        // RACK.RTT = now - xmit_ts (time since the highest acked was sent)
        let rack_rtt_sample = Instant::now().saturating_duration_since(largest_acked_sent_time);
        self.rack_rtt = std::cmp::max(rack_rtt_sample, self.min_rtt);
        // Reordering window: min_RTT / 4 (RFC 8985 §7.2)
        // Can be made static via rack_reo_wnd_static flag
        self.rack_reo_wnd = self.min_rtt / 4;
    }
}

fn detect_rack_losses(&mut self, now: Instant) {
    if let Some(xmit_ts) = self.rack_xmit_ts {
        let threshold = xmit_ts.saturating_sub(self.rack_rtt + self.rack_reo_wnd);
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
}
```

### Step 5: Unified on_ack with largest_acked

**File:** `src/transport/recovery.rs`, `src/transport/connection.rs`

Update `Recovery::on_ack` to accept `largest_acked` and `largest_acked_sent_time`:

```rust
pub fn on_ack_with_loss_detection(
    &mut self,
    acked_bytes: usize,
    largest_acked: u64,
    largest_acked_sent_time: Instant,
    now: Instant,
) {
    // 1. Update RACK state
    self.update_rack(largest_acked, largest_acked_sent_time);
    // 2. Packet-threshold loss detection (existing, move from connection.rs)
    // 3. Time-based loss detection
    self.detect_time_based_losses(largest_acked, largest_acked_sent_time, now);
    // 4. RACK loss detection
    self.detect_rack_losses(now);
    // 5. Update CC
    self.cc.on_ack(acked_bytes, now);
    self.sync_from_cc();
}
```

In `connection.rs:3550-3614` (`account_sent_bytes_for_ack_ranges_with_delay`):
- Move the packet-threshold loss detection from connection.rs into Recovery.
- Pass `largest_acked` and `largest_acked_sent_time` to the new
  `on_ack_with_loss_detection`.
- The `sent_packets_by_pn` BTreeMap in connection.rs should be replaced by or synced
  with the `sent_packets` VecDeque in Recovery to avoid duplicate tracking.

### Step 6: Loss detection timer

**File:** `src/transport/recovery.rs`

Add a loss detection timer that fires when time-based loss detection should run
(RFC 9002 §6.1.2):

```rust
pub fn loss_detection_deadline(&self, now: Instant) -> Option<Instant> {
    if self.sent_packets.is_empty() {
        return None;
    }
    // The earliest loss time is the send time of the oldest unacked packet + loss_delay
    let oldest = self.sent_packets.front()?;
    let loss_time = oldest.sent_time + self.loss_delay();
    if loss_time > now {
        Some(loss_time)
    } else {
        Some(now) // Fire immediately
    }
}
```

The event loop should call `on_loss_detection_timeout()` when this timer fires, which
runs time-based + RACK loss detection on all unacked packets.

### Step 7: Reno bandwidth estimation

**File:** `src/transport/cc/reno.rs`

Add delivery-rate tracking to Reno:

```rust
pub struct Reno {
    // ... existing fields ...
    delivery_rate: u64,         // Current delivery rate estimate (bytes/sec)
    delivered: u64,             // Total bytes delivered (acked)
    delivered_time: Instant,    // Last delivery-rate sample time
    max_bw: u64,                // Max observed delivery rate (for pacing)
}

impl CongestionController for Reno {
    fn on_ack(&mut self, acked_bytes: usize, now: Instant) {
        // ... existing AIMD cwnd logic (unchanged) ...

        // Delivery-rate sample
        self.delivered += acked_bytes as u64;
        let elapsed = now.saturating_duration_since(self.delivered_time);
        if elapsed >= Duration::from_millis(10) {
            let rate = (self.delivered as u128 * 1_000_000_000 / elapsed.as_nanos()) as u64;
            self.delivery_rate = rate;
            self.max_bw = self.max_bw.max(rate);
            self.delivered = 0;
            self.delivered_time = now;
        }
    }

    fn pacing_rate(&self) -> Option<u64> {
        if self.max_bw > 0 { Some(self.max_bw) } else { None }
    }
}
```

This gives Reno a non-zero `pacing_rate()` after steady ACKs, enabling the pacer to
smooth bursts to the estimated bottleneck rate on high-BDP links.

### Step 8: BBR3 RTT variance integration

**File:** `src/transport/cc/bbr3.rs`

Use RTT variance to adapt ProbeRTT interval:

```rust
fn update_rtt_var(&mut self, rtt_var: Duration) {
    self.rtt_var = rtt_var;
    // Adapt ProbeRTT window: high-variance paths need longer windows
    // to avoid probing too frequently on jittery paths.
    let base_window = MIN_RTT_WIN; // 10 seconds
    let variance_factor = (rtt_var.as_secs_f64() / self.min_rtt.as_secs_f64()).min(2.0);
    self.probe_rtt_window = Duration::from_secs_f64(
        base_window.as_secs_f64() * (1.0 + variance_factor * 0.5)
    );
}
```

This makes BBR3's ProbeRTT adaptive: stable paths (low variance) probe every 10 seconds,
jittery paths (high variance) probe less frequently to avoid spurious min_rtt updates.

## Technology Choices

### RACK-TLP (RFC 8985) over RFC 6675

**Choice**: Implement RACK-TLP (RFC 8985) as the primary loss detection algorithm,
superseding the packet-threshold-only approach.

**Rationale**: Linux TCP has made RACK-TLP the default since 2018 and **removed** RFC
6675 code entirely in 2024. RACK-TLP offers "much better performance in the common
cases of tail drops, lost retransmissions, and reordering" (Linux commit message).
RFC 8985 was published as a Standards Track RFC in February 2021 and is the recommended
approach for QUIC loss detection as well (RFC 9002 §6.1 references time-based detection
which is the core RACK concept).

### EWMA SRTT/RTTVAR (RFC 6298) over raw samples

**Choice**: Implement proper EWMA SRTT and RTTVAR per RFC 6298 / RFC 9002 §5.1.

**Rationale**: The current code replaces RTT entirely on each sample, which makes PTO
unstable — a single noisy sample can trigger premature PTO. EWMA smoothing (α = 0.125
for SRTT, β = 0.25 for RTTVAR) is the standard approach used by every major TCP/QUIC
implementation (Linux, quic-go, Google's quiche, Cloudflare's quiche).

### Sent-packet tracker: VecDeque vs. BTreeMap

**Choice**: Replace the `BTreeMap<u64, (usize, Instant)>` in connection.rs with a
`VecDeque<SentPacket>` in Recovery (ordered by insertion = PN order).

**Rationale**: BTreeMap has O(log n) insert/remove and poor cache locality. VecDeque
has O(1) push_back/pop_front and excellent cache locality. Since packets are sent in
PN order and acked/lost in roughly PN order, a VecDeque is the optimal data structure.
The BTreeMap in connection.rs can be removed once Recovery owns the sent-packet tracker.

### Reno delivery-rate: simple windowed estimator

**Choice**: Simple 10ms-windowed delivery-rate estimator for Reno (not BBR-style
max-filter).

**Rationale**: Reno is a conservative baseline CC. A simple estimator (bytes acked /
elapsed time over 10ms windows, tracking the max) is sufficient for pacing. BBR's
sophisticated max-filter bandwidth estimation is overkill for Reno and would blur the
distinction between Reno and BBR3. The goal is CUBIC compatibility (TODO-452), not
BBR-level performance.

## Stealth/Efficiency Considerations

### BBR3 performance preservation

- **Must not regress BBR3**: BBR3 already has delivery-rate tracking and its own loss
  detection logic. The new RACK/time-based loss detection runs **alongside** BBR3's
  existing logic, not replacing it. BBR3's `on_loss_packet` is still called for actual
  losses; RACK/time-based detection just finds losses faster.
- **RTT variance for BBR3**: The `update_rtt_var` method allows BBR3 to adapt ProbeRTT
  timing. This is an enhancement, not a regression — BBR3's existing behavior is
  preserved when `rtt_var` is zero (default).
- **No new allocations in hot path**: The `sent_packets` VecDeque is pre-allocated with
  capacity = `cwnd / MSS`. Loss detection scans are O(n) where n = in-flight packets,
  bounded by cwnd/MSS (typically 10-100 entries).

### Stealth interaction

- **Loss detection and cover traffic**: Faster loss detection means faster retransmission,
  which changes the traffic pattern. In constant-rate mode (TODO-455), retransmissions
  are indistinguishable from chaff (same size, same interval). In non-constant-rate
  mode, retransmissions create additional packets that could be a traffic analysis
  signal. RACK reduces spurious retransmissions (fewer false positives), which is
  beneficial for stealth.
- **RTT variance and timing obfuscation**: The `FlowShaper` adds jitter to packet
  timing, which increases RTT variance. The new RTT variance tracking will account for
  this — `loss_delay` will be larger when jitter is active, preventing false loss
  detection caused by artificial timing perturbation. This is a **positive interaction**:
  stealth jitter is automatically accounted for by variance-aware loss detection.

### Performance targets

- **Loss detection scan per ACK**: < 5µs (VecDeque linear scan, bounded by cwnd/MSS).
- **RACK update per ACK**: < 100ns (two comparisons, one assignment).
- **RTT variance EWMA**: < 100ns (two arithmetic ops, two Duration conversions).
- **Reno delivery-rate sample**: < 100ns (one division per 10ms window).
- **No regression in BBR3 throughput**: BBR3's cwnd/pacing decisions are unchanged;
  only loss detection timing improves.

## Testing Plan

### Unit tests

1. **EWMA SRTT smoothing**: Feed RTT samples [100ms, 100ms, 200ms, 100ms]. Assert
   SRTT converges toward ~112ms (EWMA with α=0.125), not jumps to 200ms.
2. **RTT variance tracking**: Feed RTT samples with high variance [50ms, 150ms, 50ms,
   150ms]. Assert `rtt_var` grows. Feed low-variance [100ms, 101ms, 100ms, 101ms].
   Assert `rtt_var` shrinks.
3. **PTO formula with variance**: With SRTT=100ms, RTTVAR=10ms, max_ack_delay=25ms:
   PTO = 100ms + max(40ms, 1ms) + 25ms = 165ms. Assert `pto_deadline` returns
   now + 165ms (with pto_count=0).
4. **Time-based loss detection**: Send packets 1,2,3 at t=0. ACK packet 3 at t=200ms
   (SRTT=100ms, loss_delay=112ms). Assert packet 1 (sent at t=0, threshold = 200ms -
   112ms = 88ms, packet 1 sent at 0ms < 88ms) is declared lost via time-based
   detection — without waiting for PTO.
5. **RACK loss detection**: Send packets 1,2,3 at t=0,10,20ms. ACK packet 3 at t=120ms
   (RACK_RTT = 120-20 = 100ms, reo_wnd = min_rtt/4 = 25ms, threshold = 20ms - 100ms -
   25ms = -105ms → all packets before 3 sent before threshold). Assert packets 1,2 are
   declared lost via RACK.
6. **RACK reordering resilience**: Send packets 1,2,3,4,5. ACK 5, then 3, then 1
   (reordering). Assert RACK does not declare 2,3,4 lost (they were acked). Assert
   RACK does not spuriously declare losses due to reordering.
7. **Reno bandwidth estimation**: Send a burst of 10 packets (1200 bytes each). ACK
   at steady 10ms intervals. After 100ms, assert `reno.pacing_rate()` returns
   ~120000 bytes/sec (1200 * 10 / 0.1s). Assert `max_bw` tracks the maximum.
8. **Reno pacing_rate() non-None**: After steady ACKs, assert `pacing_rate()` returns
   `Some(rate)` instead of `None`.
9. **Loss detection timer**: With unacked packets, assert `loss_detection_deadline()`
   returns `Some(oldest_sent_time + loss_delay)`. With no unacked packets, assert
   `None`.
10. **BBR3 no regression**: Run existing BBR3 tests. Assert all pass unchanged.
11. **First RTT sample**: On first `update_rtt` call, assert SRTT = sample, RTTVAR =
    sample/2 (RFC 6298 §2.2 initialization).
12. **Zero RTT sample ignored**: `update_rtt(Duration::ZERO)` should be a no-op.

### Integration tests

13. **tc netem loss 5%**: On a loopback with `tc netem loss 5%`, send 1000 packets.
    Compare loss-detection latency (time from packet loss to retransmission) before
    and after: RACK + time-based should detect losses faster than PTO-only. Measure
    median and P99 latency.
14. **tc netem reorder 10%**: On a loopback with `tc netem delay 50ms reorder 10%`,
    verify RACK does not spuriously declare reordered packets lost. Compare spurious
    retransmission count before/after.
15. **High-BDP Reno throughput**: Simulate 100 Mbps / 200ms RTT link. Compare Reno
    throughput with and without bandwidth estimation + pacing. Assert throughput
    improves by > 20% with pacing.
16. **BBR3 + RACK interaction**: Run BBR3 with RACK loss detection on a lossy link.
    Assert BBR3 cwnd/pacing decisions are not disrupted by RACK. Assert loss detection
    is faster than PTO-only.

### Performance tests

17. **Loss detection scan benchmark**: Benchmark `detect_time_based_losses` +
    `detect_rack_losses` on 100 in-flight packets. Assert < 5µs per ACK.
18. **RTT variance update benchmark**: Benchmark `update_rtt` with variance. Assert
    < 100ns per call.
19. **Sent-packet tracker memory**: Assert `sent_packets` VecDeque capacity is bounded
    by `cwnd / MSS` (typically 10-100 entries, ~1-8 KB).

## Files to Create/Modify

- `src/transport/recovery.rs` — `SentPacket` struct, `sent_packets` VecDeque tracker,
  EWMA SRTT/RTTVAR (`srtt`, `rtt_var`, `min_rtt`, `first_rtt_sample`), `loss_delay()`,
  `detect_time_based_losses()`, RACK state (`rack_xmit_ts`, `rack_rtt`, `rack_fack`,
  `rack_reo_wnd`), `update_rack()`, `detect_rack_losses()`, `loss_detection_deadline()`,
  `on_ack_with_loss_detection()`, fixed `pto_deadline()` with RTTVAR + max_ack_delay.
- `src/transport/cc/mod.rs` — add `update_rtt_var` to `CongestionController` trait
  (default no-op); add to `CcImpl` enum dispatch.
- `src/transport/cc/bbr3.rs` — `update_rtt_var` impl; adaptive ProbeRTT window.
- `src/transport/cc/bbr2.rs` — `update_rtt_var` impl; use variance if applicable.
- `src/transport/cc/reno.rs` — delivery-rate tracking (`delivery_rate`, `delivered`,
  `delivered_time`, `max_bw`), non-None `pacing_rate()` impl.
- `src/transport/connection.rs` — move packet-threshold loss detection from
  `account_sent_bytes_for_ack_ranges_with_delay` into Recovery; pass `largest_acked`
  and `largest_acked_sent_time` to `on_ack_with_loss_detection`; remove or sync
  `sent_packets_by_pn` BTreeMap with Recovery's `sent_packets` VecDeque.
- `tests/loss_detection_test.rs` — **new**: time-based, RACK, variance, Reno bandwidth,
  tc netem integration tests.

## Risks & Mitigations

| Risk | Severity | Mitigation |
|------|----------|------------|
| RACK false positives on extreme reordering | MEDIUM | Reordering window (`reo_wnd = min_rTT / 4`) provides buffer. Can be made static via config flag (RFC 8985 §7.2). |
| BBR3 performance regression from RACK | HIGH | RACK runs alongside BBR3, not replacing it. BBR3's cwnd/pacing decisions are unchanged. Extensive BBR3 regression tests. |
| EWMA SRTT initialization on first sample | LOW | RFC 6298 §2.2 initialization: SRTT = R, RTTVAR = R/2. Tested explicitly. |
| sent_packets VecDeque unbounded growth | MEDIUM | Capacity bounded by cwnd/MSS. Remove acked/lost packets on every ACK. Add assert in debug mode. |
| Duplicate tracking (BTreeMap + VecDeque) | MEDIUM | Migrate sent-packet tracking from connection.rs BTreeMap to Recovery VecDeque. Remove BTreeMap after migration. |
| Reno pacing_rate() changes existing behavior | LOW | Existing code checks `pacing_rate().is_some()` — Reno returning Some instead of None enables pacing. This is the intended improvement. Existing tests that assert None need updating. |
| max_ack_delay not configured | LOW | Default to 25ms from Config (`max_ack_delay` field already exists in config.rs:122). |
| Loss detection timer not wired to event loop | MEDIUM | `loss_detection_deadline()` returns Option<Instant>. Event loop must call `on_loss_detection_timeout()` when it fires. This is a wiring task, not a logic risk. |

## Completion Criteria

- [ ] EWMA SRTT and RTTVAR are tracked per RFC 6298 / RFC 9002 §5.1 (α=0.125, β=0.25).
- [ ] First RTT sample initializes SRTT = R, RTTVAR = R/2 (RFC 6298 §2.2).
- [ ] PTO formula uses `SRTT + max(4*RTTVAR, kGranularity) + max_ack_delay` (RFC 9002
      §6.2.1).
- [ ] Time-based loss detection declares a packet lost when a later packet is acked
      and the unacked packet was sent > `loss_delay` ago, where
      `loss_delay = max(9/8 * SRTT, 1ms)` (RFC 9002 §6.1.2).
- [ ] RACK tracks the highest acked packet number + send time and declares unacked
      packets sent before `rack_xmit_ts - rack_rtt - reo_wnd` lost (RFC 8985).
- [ ] RACK reordering window = `min_RTT / 4` (configurable to static).
- [ ] RTT variance is propagated to BBR2/BBR3 via `update_rtt_var`.
- [ ] BBR3 ProbeRTT window adapts to RTT variance (longer window on jittery paths).
- [ ] Reno tracks delivery rate and exposes a non-None `pacing_rate()` after steady
      ACKs.
- [ ] `Recovery::on_ack` receives `largest_acked` and `largest_acked_sent_time` from
      the connection layer.
- [ ] Loss detection timer (`loss_detection_deadline`) is available for event loop
      integration.
- [ ] On a `tc netem loss 5%` loopback, loss-detection latency is lower with RACK +
      time-based detection than with PTO-only (measured).
- [ ] On a `tc netem reorder 10%` loopback, spurious retransmissions are fewer with
      RACK than with packet-threshold-only (measured).
- [ ] RTT variance improves BBR probing on jittery paths (no spurious retransmissions
      when variance is high).
- [ ] Reno bandwidth estimation improves throughput on a high-BDP simulation by > 20%
      (measured vs. ACK-clocking-only baseline).
- [ ] No regression in existing recovery/CC/BBR3 unit tests.
- [ ] Loss detection scan per ACK is < 5µs for 100 in-flight packets.
- [ ] `cargo test` passes with all new tests green; `cargo clippy` reports no new
      warnings.
