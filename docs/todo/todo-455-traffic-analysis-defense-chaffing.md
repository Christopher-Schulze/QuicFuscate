---
id: TODO-455
title: "Traffic analysis defense: chaffing, constant rates, full padding"
severity: HIGH
phase: "J"
priority: P2
status: DONE
created: 2026-07-23
depends_on: [TODO-416]
---

# TODO-455: Traffic Analysis Defense (Chaffing, Constant Rates, Full Padding)

## Goal

Implement comprehensive traffic analysis defense with three complementary modes that
eliminate size-based, timing-based, and volume-based traffic analysis vectors: (1) Full
padding mode that pads ALL packets to a fixed target size, (2) Chaffing that injects
dummy packets indistinguishable from real traffic to fill timing gaps, and (3)
Constant-rate mode that sends at a fixed interval regardless of actual data availability.
All three modes must be configurable per-connection or per-QKey policy and must integrate
seamlessly with the existing stealth escalation system without regressing BBR3 performance.

## Current State (verified against code)

### Existing padding infrastructure

The codebase has a sophisticated but **probabilistic** padding system — not all packets
are padded, and padding sizes vary rather than being constant:

- **`src/transport/config.rs:74-92`** — Stealth padding config fields:
  - `stealth_padding_enabled: bool` (line 78) — master toggle
  - `stealth_padding_strategy: u8` (line 79) — strategy ID (1=Random, 2=Fixed, 3=Adaptive, 4=BrowserMimic, 5=PacketNormalize)
  - `stealth_padding_max_size: usize` (line 80) — max padding bytes
  - `stealth_normalize_target_size: usize` (line 81) — target size for PacketNormalize strategy
  - `stealth_padding_rate: u8` (line 83) — 0-100% fraction of packets that receive padding
  - `stealth_timing_enabled: bool` (line 85) — timing jitter toggle
  - `stealth_timing_max_jitter_us: u32` (line 86) — max jitter in microseconds
  - `stealth_timing_rate: u8` (line 88) — 0-100% fraction of packets with jitter

- **`src/transport/connection.rs:2382-2436`** — `compute_stealth_padding()`:
  At `padding_rate < 100`, a random roll (`rand_u64_uniform(100)`) determines whether
  padding is applied. This means a fraction of packets are **not padded** — their true
  size leaks payload information. Strategy 5 (PacketNormalize) is the closest to full
  padding but is still gated by the `stealth_padding_enabled` flag and rate.

- **`src/transport/connection.rs:1846-1884`** — `maybe_apply_stealth_padding()`:
  Called in the 1-RTT send path (line 2337). Strategy 5 (PacketNormalize) pads to
  `stealth_normalize_target_size` but only when `stealth_padding_enabled` is true.

### Existing timing/cover traffic infrastructure

- **`src/stealth/mod.rs:2767-2873`** — `FlowShaper`: applies jitter (min/max microseconds)
  to packet timing. Has `StealthPacketClass::Dummy` enum variant but dummy packet
  generation is **not implemented** — the `_enable_dummy_retransmits` parameter is
  prefixed with underscore (line 2800), indicating it is unused.

- **`src/stealth/mod.rs:4304-4307`** — `CoverTrafficScheduler`: exists but is only
  initialized when `enable_http3_masquerading` is true (line 4411), with a fixed 5-second
  interval. This is HTTP/3-level cover traffic, not QUIC-level chaffing.

- **`src/stealth/mod.rs:3242-3245`** — `enable_cover_ping` and `cover_ping_interval_ms`:
  periodic PING frame emission for keepalive patterns. This is a single frame coalesced
  into the next packet, not standalone dummy packets.

- **`src/stealth/mod.rs:123-165`** — `RateChoker`: token-bucket rate limiter for
  smoothing observable bitrate. This shapes existing traffic but does not inject dummy
  traffic or enforce constant-rate emission.

- **`src/transport/cc/stealth_shaper.rs`** — `StealthShaper`: wraps CC algorithms to
  inject browser-profile-specific pacing jitter and gain shaping. This is timing
  perturbation, not constant-rate emission or chaffing.

### Key gap: no chaffing, no constant-rate mode

There is **no mechanism** to:
1. Inject standalone dummy packets (PADDING-only QUIC packets with no stream data) at
   a configurable rate to fill timing gaps.
2. Send packets at a fixed interval regardless of data availability (constant-rate mode).
3. Pad every single packet to a fixed size with no probabilistic skipping (full padding).

The `FlowShaper` has a `Dummy` packet class but no generation logic. The
`CoverTrafficScheduler` operates at the HTTP/3 layer with 5-second intervals — far too
sparse for traffic analysis defense. The `RateChoker` shapes but does not inject.

## Problem Analysis

### Traffic analysis vectors

A sophisticated adversary performing traffic analysis can extract information from three
orthogonal signal domains:

1. **Packet size distribution** — Different application activities produce different
   packet size patterns (e.g., web browsing has many small packets, file downloads have
   many large packets). Even with encryption, the size distribution is observable. The
   current probabilistic padding (`padding_rate < 100`) leaks true sizes for unpadded
   packets. Research confirms that padding-only defenses are insufficient against modern
   deep-learning classifiers (DF, RF, Laserbeak) which achieve >90% accuracy on
   unpadded traffic.

2. **Inter-packet timing / on-off pattern** — The adversary can detect "silent periods"
   (no packets = idle/no data) vs "active periods" (packets = data being sent). This
   on/off pattern is a powerful signal. The current system has no chaffing to fill
   silent periods. `FlowShaper` adds jitter to existing packets but does not inject
   packets during idle periods.

3. **Flow volume / bandwidth analysis** — The adversary can measure total bytes per
   time window to infer activity type. The `RateChoker` can smooth this but does not
   maintain a constant rate — it only caps the maximum. There is no mode that sends at
   a fixed rate regardless of actual traffic, which would make the flow volume constant.

### Why existing defenses are insufficient

- **Probabilistic padding** (`padding_rate < 100`): At 50% rate, half the packets have
  true sizes. The adversary can statistically separate padded from unpadded packets and
  reconstruct the size distribution from the unpadded subset.

- **Jitter only** (`FlowShaper`): Adding random delay to existing packets perturbs
  timing but does not eliminate the on/off pattern. The adversary still sees gaps.

- **HTTP/3 cover traffic** (`CoverTrafficScheduler`): 5-second interval is far too
  sparse. Traffic analysis operates at millisecond timescales. A 5-second gap is itself
  a signal.

- **PING-based cover** (`enable_cover_ping`): A single PING frame coalesced into the
  next real packet does not create standalone dummy packets. The adversary sees no
  additional packets — just a slightly larger real packet.

### Research context

The **Maybenot framework** (ACM WPES 2023, v2.2.2 Sept 2025) is the state-of-the-art
traffic analysis defense framework for encrypted protocols. It uses probabilistic state
machines that trigger padding and blocking actions. Key insights from Maybenot:

- Defenses must operate at the **encrypted protocol layer** (QUIC PADDING frames), not
  the application layer — QuicFuscate already has this capability via `Frame::Padding`.
- **Blocking** (delaying real traffic to match a target pattern) is as important as
  padding — but it adds latency. Constant-rate mode is a form of blocking.
- **State machine**-based defenses are more effective than fixed-rate defenses because
  they can adapt to traffic patterns. However, fixed-rate (constant-rate) is the
  strongest defense and the simplest to verify.

**ChameleonFlow** (IEEE 2025) achieves 35.8% classifier accuracy (from 96.3%) with only
8.7% bandwidth overhead by leveraging QUIC stream multiplexing — but requires application
cooperation. Our approach (padding + chaffing + constant-rate) is transport-layer-only
and does not require application changes.

**Tamaraw** (PoPETS 2026) is a constant-rate defense that achieves 45-51% accuracy under
infinite training, confirming that constant-rate is the gold standard but has non-zero
information leakage from the "soft stop" condition. Our design should include a soft-stop
mechanism (gradually reduce chaff when idle for extended periods to avoid infinite
bandwidth waste).

## Proposed Architecture

### Three-mode traffic analysis defense

```
┌─────────────────────────────────────────────────────────────────────┐
│                    TrafficAnalysisDefense                            │
│                                                                     │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────────┐     │
│  │ FullPadding │  │  Chaffing   │  │   ConstantRateShaper    │     │
│  │  Mode       │  │  Generator  │  │                         │     │
│  │             │  │             │  │  target_interval ────── │     │
│  │ pad ALL     │  │ inject      │  │  next_send_time ─────── │     │
│  │ packets to  │  │ dummy pkts  │  │  buffer: VecDeque       │     │
│  │ target_size │  │ at rate_pps │  │  chaff_if_empty ─────── │     │
│  └──────┬──────┘  └──────┬──────┘  └──────────┬──────────────┘     │
│         │                │                    │                     │
│         ▼                ▼                    ▼                     │
│  compute_stealth_   send_path hook      send_path redirect         │
│  padding()          (post-send)         (pre-send buffer)          │
│                                                                     │
│  Config: padding_mode, padding_size, chaff_rate_pps,               │
│          constant_rate_pps, constant_rate_buffer_ms                │
└─────────────────────────────────────────────────────────────────────┘
```

### Mode 1: Full Padding

Every outgoing 1-RTT packet is padded to `padding_size` bytes (total packet size,
including header + AEAD tag). No probabilistic skipping. No random roll. The packet
size on the wire is constant, eliminating size-based traffic analysis entirely.

This extends the existing `PacketNormalize` strategy (strategy 5) but makes it the
exclusive mode — no rate gating, no fallback to other strategies. When `padding_mode =
Full`, `compute_stealth_padding` unconditionally pads to `padding_size`.

**TLS record size blending**: Optionally pad to common TLS record sizes (16384, 4096,
1500) to make QUIC packets indistinguishable from HTTPS TLS records at the size level.
This is important when the QUIC traffic is disguised as HTTPS (via TLS Cover). Config
option: `padding_blend_tls = true` uses 16384 as the target (or the nearest multiple of
the MTU that fits).

### Mode 2: Chaffing

Inject standalone dummy packets at a configurable rate (`chaff_rate_pps`). A chaff
packet is a QUIC 1-RTT packet containing only PADDING frames (and optionally a PING
frame for ack-eliciting behavior). It is encrypted with the same 1-RTT keys, uses the
same header format, and is padded to the same `padding_size` as real packets.

**Critical requirement**: chaff packets must be **indistinguishable** from real packets
to an outside observer:
- Same encryption (1-RTT AEAD + header protection)
- Same size distribution (padded to `padding_size` in full padding mode, or same
  size distribution as real packets in other modes)
- Same timing characteristics (same jitter, same pacing)
- Same connection ID format

**Chaff scheduling**: The `ChaffGenerator` tracks the last packet send time. When the
elapsed time since the last send exceeds `1 / chaff_rate_pps`, a chaff packet is
generated and sent (if cwnd budget allows). This fills timing gaps without requiring
constant-rate emission.

**Ack-eliciting chaff**: Optionally include a PING frame in chaff packets so the peer
ACKs them, generating bidirectional traffic. This makes the chaff pattern symmetric
(matching real HTTP/3 request-response patterns). Config: `chack_ack_eliciting = true`
(default: true). Non-ack-eliciting chaff is cheaper but creates asymmetric traffic.

**Soft-stop**: After `chaff_idle_timeout_ms` (default: 30000) of no real traffic,
gradually reduce chaff rate to zero over `chaff_ramp_down_ms` (default: 5000). This
prevents infinite bandwidth waste during extended idle periods while still covering
short pauses.

### Mode 3: Constant-Rate Mode

Send packets at a fixed interval (`constant_rate_pps`) regardless of data availability.
If data is queued, send it; if not, send chaff. This eliminates both timing-based and
volume-based traffic analysis — the adversary sees a constant stream of identical-size
packets at fixed intervals.

**TrafficShaper**: All outgoing packets are enqueued in a `TrafficShaper` buffer instead
of being sent immediately. The shaper releases one packet per `interval = 1 /
constant_rate_pps`. If the buffer is empty, a chaff packet is emitted.

**Buffer depth**: `constant_rate_buffer_ms` limits maximum latency. If the buffer
overflows, drop oldest non-ack-eliciting packets (or chaff) first. ACK-only packets
bypass the shaper (RFC 9002 §7.2 — ACKs must not be congestion-controlled or delayed).

**Bandwidth cost warning**: Constant-rate mode at 100 pps with 1400-byte packets
consumes ~1.4 MB/s (11.2 Mbps) of bandwidth — potentially doubling actual usage. This
mode must be **opt-in only** with explicit user confirmation. The config validator
should warn when `constant_rate_pps * padding_size > estimated_bandwidth * 0.5`.

## Implementation Plan

### Step 1: Config structures and PaddingMode enum

**File:** `src/transport/config.rs`

Add `PaddingMode` enum and new config fields:

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub enum PaddingMode {
    Off,         // No padding at all
    RateLimited, // Current behavior (probabilistic, stealth_padding_rate)
    Full,        // Every packet padded to padding_size — no exceptions
}

// New Config fields:
pub(crate) padding_mode: PaddingMode,              // default: RateLimited (backward compat)
pub(crate) padding_size: usize,                    // default: 1400 (target padded size)
pub(crate) padding_blend_tls: bool,                // default: false (blend with TLS record sizes)
pub(crate) chaff_rate_pps: u32,                    // default: 0 (disabled)
pub(crate) chaff_ack_eliciting: bool,              // default: true
pub(crate) chaff_idle_timeout_ms: u64,             // default: 30000
pub(crate) chaff_ramp_down_ms: u64,                // default: 5000
pub(crate) constant_rate_pps: u32,                 // default: 0 (disabled)
pub(crate) constant_rate_buffer_ms: u32,           // default: 100
```

Add setters and validation. Preserve existing `stealth_padding_enabled` /
`stealth_padding_rate` for `RateLimited` mode backward compatibility.

### Step 2: Full padding in compute_stealth_padding

**File:** `src/transport/connection.rs:2382`

Update `compute_stealth_padding` to dispatch on `padding_mode`:

```rust
pub(crate) fn compute_stealth_padding(&self, cur_pt_len: usize, budget: usize) -> usize {
    match self.config.padding_mode {
        PaddingMode::Off => 0,
        PaddingMode::RateLimited => {
            // Existing logic (lines 2383-2435) — unchanged
        }
        PaddingMode::Full => {
            let target = if self.config.padding_blend_tls {
                // Blend with common TLS record sizes: pick nearest fit
                self.tls_blended_target(cur_pt_len, budget)
            } else {
                self.config.padding_size
            };
            let target = target.min(cur_pt_len + budget);
            if target > cur_pt_len { target - cur_pt_len } else { 0 }
        }
    }
}
```

In `Full` mode: no random roll, no rate gating. Every packet is padded to
`padding_size` (or the budget-limited maximum). The `maybe_apply_stealth_padding`
function (line 1846) already handles the mechanics — just bypass the rate check.

### Step 3: ChaffGenerator module

**File:** `src/transport/chaff.rs` (new)

```rust
pub struct ChaffGenerator {
    rate_pps: u32,
    last_chaff: Instant,
    last_real_traffic: Instant,
    ack_eliciting: bool,
    idle_timeout: Duration,
    ramp_down: Duration,
    current_rate_scale: f32,  // 1.0 = full rate, 0.0 = stopped (ramp-down)
    rng: SmallRng,
}

impl ChaffGenerator {
    pub fn new(rate_pps: u32, ack_eliciting: bool, idle_timeout: Duration, ramp_down: Duration) -> Self;

    /// Returns true if a chaff packet should be sent now.
    /// Accounts for soft-stop ramp-down during extended idle.
    pub fn should_chaff(&mut self, now: Instant, has_real_traffic: bool) -> bool;

    /// Record that a real packet was sent (resets idle timer).
    pub fn record_real_traffic(&mut self, now: Instant);

    /// Generate a chaff packet buffer: PADDING frame(s) + optional PING.
    /// Returns the plaintext to be sealed as a 1-RTT packet.
    pub fn generate_chaff(&mut self, padding_size: usize) -> Vec<u8>;
}
```

Integrate into `Connection::send` path: after sending real data, check
`chaff_generator.should_chaff()`. If true and cwnd budget allows, construct and send
a chaff packet using the same `seal_short_header_packet` path.

### Step 4: TrafficShaper for constant-rate mode

**File:** `src/transport/traffic_shaper.rs` (new)

```rust
pub struct TrafficShaper {
    target_interval: Duration,
    next_send_time: Instant,
    buffer: VecDeque<ShapedPacket>,
    max_buffer_depth: Duration,
    chaff_generator: Option<ChaffGenerator>,
}

struct ShapedPacket {
    data: Vec<u8>,       // sealed packet ready to send
    ack_eliciting: bool,
    timestamp: Instant,
}

impl TrafficShaper {
    pub fn new(rate_pps: u32, buffer_ms: u32, chaff: Option<ChaffGenerator>) -> Self;

    /// Enqueue a sealed packet for shaped transmission.
    pub fn enqueue(&mut self, packet: Vec<u8>, ack_eliciting: bool, now: Instant);

    /// Dequeue packets ready to send at the current time.
    /// If buffer is empty and constant-rate is active, returns a chaff packet.
    /// ACK-only packets bypass the shaper entirely (caller handles separately).
    pub fn dequeue_ready(&mut self, now: Instant) -> Vec<ShapedPacket>;
}
```

When `constant_rate_pps > 0`: the connection's send path enqueues sealed packets into
the `TrafficShaper` instead of returning them directly. The event loop calls
`dequeue_ready` on each wakeup/timeout to release packets at the target interval.

### Step 5: Stealth shaper interaction

**File:** `src/transport/cc/stealth_shaper.rs`

When constant-rate mode is active:
- The `TrafficShaper` controls inter-packet timing, not the `StealthShaper`.
- Disable `StealthShaper` pacing jitter when constant-rate is active (they conflict —
  constant-rate wants fixed intervals, stealth shaper adds jitter).
- Alternatively: apply stealth jitter on top of constant-rate intervals (jitter around
  the fixed interval). Make this configurable: `constant_rate_jitter = true/false`.

### Step 6: Per-QKey policy integration

**File:** `src/implementations/server/qkey_registry.rs`, `src/engine/config.rs`

Allow QKey entries to specify traffic analysis defense policy:

```toml
[qkey.traffic_analysis]
padding_mode = "full"
padding_size = 1400
chaff_rate_pps = 10
constant_rate_pps = 0  # opt-in only
```

When a QKey with traffic analysis policy is used, the connection inherits the policy
at handshake completion. This allows different clients/sessions to have different
defense levels.

### Step 7: Config validation

Validate config combinations at startup:
- `padding_mode = Full` requires `padding_size >= 1280` (don't pad below IPv6 minimum).
- `constant_rate_pps * padding_size` must not exceed 50% of estimated bandwidth (warn).
- `chaff_rate_pps` and `constant_rate_pps` are not mutually exclusive but chaff rate is
  ignored when constant-rate is active (constant-rate already fills gaps).
- `padding_blend_tls = true` requires `padding_size` to be a multiple of the MTU or a
  standard TLS record size (16384, 4096, 1500, 1400).

## Technology Choices

### Maybenot-inspired state machine (future evolution)

The **Maybenot framework** (Rust crate v2.2.2, Sept 2025) provides probabilistic state
machines for traffic analysis defenses. While our initial implementation uses fixed-rate
modes (simpler, verifiable), the architecture should be designed to accommodate
Maybenot-style state machines in the future:

- The `ChaffGenerator` and `TrafficShaper` should expose hooks for a state machine
  to override scheduling decisions.
- The `should_chaff()` and `dequeue_ready()` methods could delegate to a
  `DefenseStrategy` trait that defaults to fixed-rate but could be backed by a
  Maybenot machine.

**Rationale**: Fixed-rate is the strongest defense but the most expensive. Maybenot
machines can achieve similar protection with lower overhead by adapting to traffic
patterns. Starting with fixed-rate gives us a verifiable baseline; evolving to
Maybenot-style adaptive defenses is a natural progression.

### QUIC PADDING frames (not application-layer padding)

Use QUIC `Frame::Padding` (already implemented in `src/transport/frames.rs`) for all
padding. This is transport-layer padding that is transparent to the application and
does not require application cooperation. This is the approach recommended by RFC 9000
§19.1 and used by Maybenot, ChameleonFlow, and the KTH research on QUIC traffic analysis
defense.

### Incremental checksum for TUN-layer padding (not needed)

Padding is applied at the QUIC layer (before AEAD encryption), not at the IP/TUN layer.
No checksum recomputation is needed — the AEAD tag covers the padded plaintext.

## Stealth/Efficiency Considerations

### Stealth integration

- **Full padding + TLS Cover**: When `padding_blend_tls = true`, pad to TLS record
  sizes (16384, 4096) so QUIC packets match HTTPS TLS record sizes. This is critical
  when using TLS Cover to disguise QUIC as HTTPS — the packet sizes must match.
- **Chaffing + cover PING**: The existing `enable_cover_ping` mechanism can be
  subsumed by chaffing. When chaffing is active with `chaff_ack_eliciting = true`,
  cover PINGs are redundant (chaff already generates bidirectional traffic).
- **Constant-rate + StealthShaper**: Constant-rate mode overrides StealthShaper pacing.
  The StealthShaper's browser-profile jitter should be disabled or applied as a small
  perturbation on top of the constant interval.
- **Escalation system (TODO-416)**: The `runtime_padding_rate` and
  `runtime_timing_rate` atomic overrides should interact with the new modes:
  - At escalation level 0: `padding_mode = RateLimited`, no chaffing.
  - At escalation level 1: `padding_mode = RateLimited` with 50% rate, low chaffing.
  - At escalation level 2: `padding_mode = Full`, full chaffing, optional constant-rate.

### Performance considerations

- **Full padding**: Adds `padding_size - payload_size` bytes per packet. At 1400-byte
  target with 100-byte payloads, this is 14x overhead for small packets. For typical
  web traffic (mix of small and large), expect 2-3x bandwidth increase. CPU cost is
  negligible (PADDING frames are zero-filled, AEAD encrypts the padding at the same
  cost as real data).
- **Chaffing at 10 pps**: ~140 KB/s overhead (10 * 1400 bytes). Acceptable for defense.
- **Constant-rate at 100 pps**: ~1.4 MB/s (11.2 Mbps) overhead. **Doubles bandwidth**
  for typical traffic. Must be opt-in only with explicit warning.
- **TrafficShaper buffer**: `constant_rate_buffer_ms * rate` bytes of memory. At 100ms
  buffer and 100 pps with 1400-byte packets: 14 KB — negligible.
- **Chaff packet generation**: No allocation in hot path — reuse a pre-allocated buffer
  with PADDING frame template. The `generate_chaff` method fills a static buffer.
- **AEAD cost**: Chaff packets are encrypted with the same 1-RTT keys. At 10 pps, this
  is 10 additional AEAD operations per second — negligible on modern hardware.

## Testing Plan

### Unit tests

1. **Full padding verification**: Send 100 packets with various payload sizes (1B,
   100B, 500B, 1000B, 1400B) in `Full` mode with `padding_size = 1400`. Assert all
   packets have exactly 1400 bytes total (header + payload + padding + AEAD tag).
2. **Rate-limited mode regression**: Verify existing probabilistic padding behavior is
   unchanged when `padding_mode = RateLimited`.
3. **Off mode**: Verify no padding is applied when `padding_mode = Off`.
4. **ChaffGenerator timing**: Set `chaff_rate_pps = 10`, advance time by 100ms, assert
   `should_chaff()` returns true. Advance by 50ms, assert false. Advance by 50ms more,
   assert true.
5. **Chaff packet indistinguishability**: Generate a chaff packet and a real packet
   with the same `padding_size`. Assert both have identical total size. Assert chaff
   packet contains only PADDING (and optionally PING) frames after decryption.
6. **Chaff soft-stop**: Set `chaff_idle_timeout_ms = 1000`, `chaff_ramp_down_ms = 500`.
   No real traffic for 1500ms. Assert `should_chaff()` returns false (ramp-down
   completed). Send real traffic, assert chaff resumes.
7. **TrafficShaper constant rate**: Set `constant_rate_pps = 100`. Enqueue 50 packets.
   Assert `dequeue_ready` returns 1 packet per 10ms interval. After buffer empties,
   assert chaff packets are returned.
8. **TrafficShaper buffer overflow**: Set `constant_rate_buffer_ms = 10`, enqueue 100
   packets at once. Assert oldest non-ack-eliciting packets are dropped.
9. **ACK bypass**: ACK-only packets must bypass the TrafficShaper entirely.
10. **TLS blend**: With `padding_blend_tls = true`, assert padded sizes match TLS
    record sizes (16384, 4096, 1500, 1400).

### Integration tests

11. **tcpdump capture (full padding)**: Capture 10s of traffic in `Full` mode. Verify
    all UDP payloads have identical length (±0 bytes).
12. **tcpdump capture (chaffing)**: Capture 10s of traffic with `chaff_rate_pps = 10`
    during idle (no app data). Verify ≥ 100 chaff packets present at ~10 pps.
13. **tcpdump capture (constant-rate)**: Capture 10s with `constant_rate_pps = 100`.
    Verify inter-packet intervals are ~10ms (±1ms jitter). Verify packets present
    during idle.
14. **Combined mode**: Full + chaff + constant-rate simultaneously. Verify all criteria
    hold simultaneously.
15. **Congestion control respect**: Under simulated congestion (cwnd exhausted), verify
    chaff and constant-rate packets are deferred, not sent.

### Performance tests

16. **Throughput impact**: Measure throughput with and without full padding. Assert
    < 5% CPU overhead (padding is zero-fill, AEAD is the same cost).
17. **Chaff bandwidth overhead**: Measure bandwidth with `chaff_rate_pps = 10`. Assert
    overhead is ~140 KB/s as predicted.
18. **Constant-rate bandwidth**: Measure with `constant_rate_pps = 100`. Assert ~1.4
    MB/s overhead. Assert throughput warning is logged.

## Files to Create/Modify

- `src/transport/chaff.rs` — **new**: `ChaffGenerator`, dummy packet generation,
  soft-stop ramp-down logic.
- `src/transport/traffic_shaper.rs` — **new**: `TrafficShaper`, constant-rate
  emission, buffering, chaff-when-empty.
- `src/transport/config.rs` — `PaddingMode` enum, `padding_mode`, `padding_size`,
  `padding_blend_tls`, `chaff_rate_pps`, `chaff_ack_eliciting`,
  `chaff_idle_timeout_ms`, `chaff_ramp_down_ms`, `constant_rate_pps`,
  `constant_rate_buffer_ms` fields + setters + validation.
- `src/transport/connection.rs` — update `compute_stealth_padding` for `Full` mode;
  integrate `ChaffGenerator` into send path; integrate `TrafficShaper` when
  constant-rate is active; add `tls_blended_target` helper.
- `src/transport/cc/stealth_shaper.rs` — conditional jitter disable when
  constant-rate is active.
- `src/transport.rs` — re-export `PaddingMode`, `ChaffGenerator`, `TrafficShaper`;
  add module declarations.
- `src/engine/config.rs` — per-QKey traffic analysis policy fields + TOML parsing.
- `src/implementations/server/qkey_registry.rs` — QKey traffic analysis policy
  storage and application.
- `src/stealth/mod.rs` — wire escalation levels to new modes; subsume cover PING
  when chaffing is active.
- Tests: inline unit tests in `chaff.rs`, `traffic_shaper.rs`, `connection.rs`;
  integration test script for tcpdump-based verification.

## Risks & Mitigations

| Risk | Severity | Mitigation |
|------|----------|------------|
| Constant-rate mode doubles bandwidth | HIGH | Opt-in only, explicit warning, `constant_rate_pps * padding_size` validation against estimated bandwidth |
| Chaff packets consume cwnd, starving real traffic | MEDIUM | Chaff is deferred when cwnd is exhausted; CC has priority. Document tradeoff. |
| TrafficShaper adds latency to real traffic | MEDIUM | `constant_rate_buffer_ms` limits max latency (default 100ms). ACK-only packets bypass shaper. |
| Full padding wastes bandwidth on small packets | LOW | 14x overhead for 100B packets, but typical web traffic is 2-3x. Acceptable for defense mode. |
| Chaff packets detectable by packet number gap analysis | MEDIUM | Chaff uses the same PN space as real packets (sequential PNs). No gap. |
| Soft-stop leaves a detectable pattern (rate ramp-down) | LOW | Ramp-down is gradual (5s default). Adversary sees decreasing rate, not a hard stop. |
| Maybenot integration complexity (future) | LOW | Architecture designed for extensibility via `DefenseStrategy` trait. Not in initial scope. |
| Existing cover PING conflicts with chaffing | LOW | When chaffing is active with `chaff_ack_eliciting = true`, disable cover PING automatically. |

## Completion Criteria

- [ ] `PaddingMode` enum supports `Off`, `RateLimited`, `Full` with config validation.
- [ ] **Full padding mode**: every 1-RTT packet is padded to `padding_size`. Verified
      by tcpdump — all packets have identical UDP payload length (±0 bytes).
- [ ] **Rate-limited mode** (existing): unchanged behavior, no regression.
- [ ] **Off mode**: no padding applied, packets have natural sizes.
- [ ] **Chaffing**: with `chaff_rate_pps = 10`, dummy packets injected at ~10 pps
      during idle. Verified by tcpdump — packets present during idle.
- [ ] Chaff packets are indistinguishable from real packets (same size, same
      encryption, same header structure, sequential packet numbers).
- [ ] Chaff soft-stop: after `chaff_idle_timeout_ms` of no real traffic, chaff rate
      ramps down to zero over `chaff_ramp_down_ms`.
- [ ] **Constant-rate mode**: with `constant_rate_pps = 100`, inter-packet intervals
      are ~10ms (±1ms). Chaff emitted during idle. ACK-only packets bypass shaper.
- [ ] Constant-rate mode is opt-in only with bandwidth warning.
- [ ] Chaff and constant-rate packets respect congestion control (deferred when cwnd
      exhausted).
- [ ] TLS blend mode: `padding_blend_tls = true` pads to standard TLS record sizes.
- [ ] Per-QKey traffic analysis policy is applied at handshake completion.
- [ ] Escalation system (TODO-416) wires to new modes (level 0 = RateLimited, level 2
      = Full + chaffing).
- [ ] No regression in existing stealth padding / timing / CC tests.
- [ ] `cargo test` passes; `cargo clippy` reports no new warnings.
- [ ] Integration test: 10s capture in full+chaff+constant-rate mode verifies (a) all
      packets same size, (b) no inter-packet gap > 2× target interval, (c) packets
      present during idle.
