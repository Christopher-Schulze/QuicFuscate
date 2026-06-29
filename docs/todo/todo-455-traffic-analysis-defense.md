---
id: TODO-455
title: Traffic analysis defense (full padding, chaffing, constant-rate)
severity: HIGH
phase: "J"
priority: P2
status: OPEN
created: 2026-06-30
depends_on: ["TODO-416"]
---

# TODO-455: Traffic Analysis Defense (Full Padding, Chaffing, Constant-Rate)

## Problem

The current traffic-analysis defenses are **rate-limited and incomplete**. Not
all packets are padded, timing jitter is probabilistic, there is no chaffing
(dummy traffic), and no constant-rate mode. A sophisticated adversary performing
traffic analysis (packet size distribution, inter-packet timing, flow volume
fingerprinting) can still distinguish QuicFuscate traffic from cover traffic.

Evidence:

- `src/transport/connection.rs:2382-2394` — `compute_stealth_padding`:
  ```rust
  pub(crate) fn compute_stealth_padding(&self, cur_pt_len: usize, budget: usize) -> usize {
      if !self.config.stealth_padding_enabled {
          return 0;
      }
      let padding_rate = self.config.stealth_padding_rate;
      if padding_rate < 100 {
          let roll = crate::transport::rand::rand_u64_uniform(100) as u8;
          if roll >= padding_rate {
              return 0;
          }
      }
  ```
  At `padding_rate < 100`, a random roll determines whether padding is applied.
  This means a fraction of packets are **not padded** — their true size leaks
  information about the payload.

- `src/transport/config.rs:82-83` — `stealth_padding_rate: u8` (0-100%). Only
  at 100% is every packet padded. The default is 100 (line 161), but the
  gradual escalation system (TODO-416) may reduce it.

- `src/transport/config.rs:88` — `stealth_timing_rate: u8` (0-100%). Timing
  jitter is applied probabilistically. At < 100%, some packets have no jitter,
  leaking true timing.

- No chaffing: there is no mechanism to inject dummy packets (packets with no
  real payload, only padding) at a configurable rate. The adversary can detect
  "silent periods" (no packets = no data) vs "active periods" (packets = data
  being sent), which is a powerful traffic analysis signal.

- No constant-rate mode: there is no mode where the transport sends packets at
  a fixed interval regardless of whether data is available. Without this, the
  adversary can distinguish idle from active by packet timing gaps.

- `src/transport/cc/stealth_shaper.rs` — implements pacing jitter and gain
  shaping for browser-profile mimicry, but this is timing perturbation, not
  constant-rate emission or chaffing.

## Goal

Implement comprehensive traffic analysis defense with three new modes:

1. **Full padding mode** — every packet padded to a configurable fixed size
   (`padding_size`). No probabilistic skipping. Eliminates size-based traffic
   analysis.
2. **Chaffing** — inject dummy packets (padding-only, no payload) at a
   configurable rate (`chaff_rate_pps`). Fills silent periods so the adversary
   cannot distinguish idle from active.
3. **Constant-rate mode** — send packets at a fixed interval
   (`constant_rate_pps`) regardless of data availability. If no data is queued,
   send a chaff packet. Eliminates timing-based traffic analysis.
4. **Traffic shaping** — buffer outgoing data and release at a fixed rate,
   smoothing burst patterns.

Config: `padding_mode = "off" | "rate-limited" | "full"`, `padding_size`,
`chaff_rate_pps`, `constant_rate_pps`.

## Implementation Plan

### Step 1: Padding mode enum and config

In `src/transport/config.rs`:

- Add `PaddingMode` enum:
  ```rust
  pub enum PaddingMode {
      Off,           // No padding at all
      RateLimited,   // Current behavior (probabilistic, stealth_padding_rate)
      Full,          // Every packet padded to padding_size
  }
  ```
- Add fields:
  - `padding_mode: PaddingMode` (default `RateLimited` — backward compat).
  - `padding_size: usize` (default `1400` — target padded size in bytes).
  - `chaff_rate_pps: u32` (default `0` — disabled; packets per second of dummy
    traffic).
  - `constant_rate_pps: u32` (default `0` — disabled; packets per second
    target).
  - `constant_rate_buffer_ms: u32` (default `100` — shaping buffer depth).
- Add setters: `set_padding_mode`, `set_padding_size`, `set_chaff_rate`,
  `set_constant_rate`, `set_constant_rate_buffer`.
- Preserve existing `stealth_padding_enabled` / `stealth_padding_rate` for
  `RateLimited` mode backward compatibility.

### Step 2: Full padding mode in `compute_stealth_padding`

In `src/transport/connection.rs:2382`, update `compute_stealth_padding`:

```rust
pub(crate) fn compute_stealth_padding(&self, cur_pt_len: usize, budget: usize) -> usize {
    match self.config.padding_mode {
        PaddingMode::Off => 0,
        PaddingMode::RateLimited => {
            // Existing logic (lines 2383-2394)
            if !self.config.stealth_padding_enabled { return 0; }
            let padding_rate = self.config.stealth_padding_rate;
            if padding_rate < 100 {
                let roll = crate::transport::rand::rand_u64_uniform(100) as u8;
                if roll >= padding_rate { return 0; }
            }
            // ... existing padding size computation ...
        }
        PaddingMode::Full => {
            // Pad every packet to padding_size, no exceptions.
            let target = self.config.padding_size.min(cur_pt_len + budget);
            if target > cur_pt_len {
                target - cur_pt_len
            } else {
                0
            }
        }
    }
}
```

In `Full` mode: every packet is padded to `padding_size` (or the budget-limited
maximum). No random roll, no skipping. The packet size is constant.

### Step 3: Chaffing (dummy packet injection)

Create `src/transport/chaff.rs`:

```rust
pub struct ChaffGenerator {
    rate_pps: u32,
    last_chaff: Instant,
    rng: SmallRng,
}

impl ChaffGenerator {
    pub fn new(rate_pps: u32) -> Self { ... }

    /// Returns true if a chaff packet should be sent now (based on rate).
    pub fn should_chaff(&mut self, now: Instant) -> bool {
        let interval = Duration::from_nanos(1_000_000_000 / self.rate_pps.max(1));
        now.duration_since(self.last_chaff) >= interval
    }

    /// Generate a dummy packet: PADDING frame only, padded to padding_size.
    /// Contains no stream data, no ACK-eliciting frames (except PING for
    /// reliability if configured).
    pub fn generate_chaff_packet(&mut self, padding_size: usize) -> Vec<u8> {
        self.last_chaff = Instant::now();
        // Construct a packet with PADDING frame(s) to reach padding_size.
        // Optionally include a PING frame to make it ack-eliciting (so the
        // peer ACKs it and the packet looks "real" in both directions).
        ...
    }
}
```

Integrate into the connection's send path (`connection.rs`):

- After sending real data packets, check `chaff_generator.should_chaff(now)`.
- If true and there's cwnd budget: send a chaff packet.
- Chaff packets are NOT counted against flow control (they carry no stream
  data).
- Chaff packets ARE counted against congestion control (they consume bandwidth
  — this is the cost of chaffing).
- Chaff packets use the same encryption, header format, and padding as real
  packets — indistinguishable to an outside observer.

### Step 4: Constant-rate mode (traffic shaping)

Create `src/transport/traffic_shaper.rs`:

```rust
pub struct TrafficShaper {
    target_rate_pps: u32,
    interval: Duration,           // 1 / target_rate_pps
    next_send_time: Instant,
    buffer: VecDeque<Vec<u8>>,    // buffered outgoing packets
    buffer_depth: Duration,       // max buffer time (constant_rate_buffer_ms)
}

impl TrafficShaper {
    pub fn enqueue(&mut self, packet: Vec<u8>, now: Instant) {
        self.buffer.push_back(packet);
    }

    /// Returns packets that should be sent now to maintain constant rate.
    /// If buffer is empty and constant-rate is active, returns a chaff packet.
    pub fn dequeue_ready(&mut self, now: Instant) -> Vec<Vec<u8>> {
        let mut ready = Vec::new();
        while now >= self.next_send_time {
            if let Some(pkt) = self.buffer.pop_front() {
                ready.push(pkt);
            } else if self.target_rate_pps > 0 {
                // No real data — emit chaff to maintain constant rate.
                ready.push(self.generate_chaff());
            }
            self.next_send_time += self.interval;
        }
        ready
    }
}
```

When `constant_rate_pps > 0`:

- All outgoing packets are enqueued in the `TrafficShaper` instead of sent
  immediately.
- The shaper releases one packet per `interval` (= 1 / `constant_rate_pps`).
- If no real data is buffered, a chaff packet is emitted.
- Result: constant inter-packet interval regardless of application data rate.
- Buffer depth (`constant_rate_buffer_ms`) limits latency: if buffer overflows,
  drop oldest non-ack-eliciting packets (or chaff) first.

Integrate into `connection.rs` send path:

- Replace direct `socket.send_to()` calls with `shaper.enqueue()` +
  `shaper.dequeue_ready()` when constant-rate is active.
- The shaper's `dequeue_ready` is called on every event loop wakeup / timeout.

### Step 5: Interaction with congestion control

- Chaff packets and constant-rate emissions consume cwnd. If cwnd is
  exhausted, chaff packets are deferred (not sent) — CC has priority.
- This means under congestion, the effective chaff/constant rate drops. This is
  acceptable: the adversary sees reduced rate (which could leak congestion
  state), but the alternative (ignoring CC) would cause more harm.
- Document this tradeoff in the config doc comments.

### Step 6: Interaction with stealth shaper

The `StealthShaper` (`src/transport/cc/stealth_shaper.rs`) applies pacing jitter
for browser-profile mimicry. When constant-rate mode is active:

- The `TrafficShaper` controls inter-packet timing, not the `StealthShaper`.
- Disable `StealthShaper` pacing jitter when constant-rate is active (they
  conflict — constant-rate wants fixed intervals, stealth shaper wants jitter).
- Or: apply stealth jitter on top of constant-rate intervals (jitter around the
  fixed interval). Make this configurable.

### Step 7: Integration and config validation

- `padding_mode = Full` + `chaff_rate_pps > 0` + `constant_rate_pps > 0` is the
  strongest defense (constant size, constant rate, no silent periods).
- Validate config combinations:
  - `padding_mode = Full` requires `padding_size >= 1280` (don't pad below IPv6
    minimum).
  - `constant_rate_pps` must be achievable given `padding_size` and link
    bandwidth (warn if `constant_rate_pps * padding_size > estimated_bandwidth`).
  - `chaff_rate_pps` and `constant_rate_pps` are mutually exclusive in intent
    (constant-rate already fills gaps), but both can be set — chaff rate is
    ignored when constant-rate is active.

## Files to Modify/Create

- `src/transport/chaff.rs` — **new**: `ChaffGenerator`, dummy packet
  generation.
- `src/transport/traffic_shaper.rs` — **new**: `TrafficShaper`, constant-rate
  emission, buffering.
- `src/transport/config.rs` — `PaddingMode` enum, `padding_mode`,
  `padding_size`, `chaff_rate_pps`, `constant_rate_pps`,
  `constant_rate_buffer_ms` fields + setters + validation.
- `src/transport/connection.rs` — update `compute_stealth_padding` for `Full`
  mode; integrate `ChaffGenerator` and `TrafficShaper` into send path.
- `src/transport/cc/stealth_shaper.rs` — conditional jitter disable when
  constant-rate is active.
- `src/transport.rs` — re-export `PaddingMode`, `ChaffGenerator`,
  `TrafficShaper`; add module declarations.
- Tests: full padding verification, chaff packet verification, constant-rate
  timing verification, tcpdump-based integration test.

## Acceptance Criteria

- [ ] **Full padding mode**: every packet is padded to `padding_size`. Verified
      by capturing traffic with `tcpdump` / `wireshark` — all packets have
      identical UDP payload length (±0 bytes).
- [ ] **Rate-limited mode** (existing): unchanged behavior, no regression.
- [ ] **Off mode**: no padding applied, packets have natural sizes.
- [ ] **Chaffing**: with `chaff_rate_pps = 10`, dummy packets are injected at
      ~10 packets/sec during idle periods. Verified by tcpdump — packets present
      even when no application data is sent.
- [ ] Chaff packets are indistinguishable from real packets (same size, same
      encryption, same header structure) to an outside observer.
- [ ] **Constant-rate mode**: with `constant_rate_pps = 100`, inter-packet
      intervals are constant at ~10ms (±1ms jitter). Verified by tcpdump
      timestamp analysis.
- [ ] Constant-rate mode emits chaff during idle periods (no silent gaps).
- [ ] Chaff and constant-rate packets respect congestion control (not sent when
      cwnd is exhausted).
- [ ] `padding_size` is respected in full mode — all packets are exactly
      `padding_size` bytes (or budget-limited maximum, documented).
- [ ] Config validation: `padding_size < 1280` in full mode returns an error.
- [ ] No regression in existing stealth padding / timing tests.
- [ ] Integration test: capture 10s of traffic in full+chaff+constant-rate mode,
      verify: (a) all packets same size, (b) no inter-packet gap > 2× target
      interval, (c) packets present during idle.

## Resource Budget

| Scenario | Budget | Notes |
|----------|--------|-------|
| Full padding verification (tcpdump, 1000 packets) | < 10s | All same size |
| Chaff verification (10s idle capture) | < 15s | ≥ 100 chaff packets at 10 pps |
| Constant-rate verification (10s capture) | < 15s | Inter-packet interval = 10ms ± 1ms |
| Combined mode (full + chaff + constant) | < 20s | All criteria simultaneously |
| Bandwidth overhead (chaff 10 pps, 1400B) | ~140 KB/s | Acceptable for defense |
| Bandwidth overhead (constant 100 pps, 1400B) | ~1.4 MB/s | Higher cost, stronger defense |
| Shaper buffer memory | < 1 MiB | constant_rate_buffer_ms * rate |
| Unit tests (padding, chaff, shaper) | < 5s | All modes |
