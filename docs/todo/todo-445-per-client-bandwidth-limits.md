---
id: TODO-445
title: "Per-client bandwidth limits, traffic quotas, and fairness scheduling"
severity: HIGH
phase: "I"
priority: P1
status: OPEN
created: 2026-07-23
depends_on: []
---

# TODO-445: Per-Client Bandwidth Limits, Traffic Quotas, and Fairness

## Goal
Implement per-session token bucket bandwidth limiting (bytes/sec with burst), per-client traffic quotas (daily/monthly byte limits with configurable exceed action), weighted fair queuing between competing clients, and admin API endpoints for real-time per-client limit management. Enforcement occurs at the server TUN write path (downlink) and via QUIC flow control. Per-client overrides are configurable via QKey policy. Rate limiting must not create detectable traffic patterns that compromise stealth.

## Current State (verified against code)

### Session tracking without enforcement
`src/implementations/server/session.rs:40-49` — `Session` struct tracks sessions but has no rate limiting:
```rust
pub struct Session {
    id: SessionId,
    remote_addr: SocketAddr,
    client_ip: Ipv4Addr,
    client_ipv6: Option<Ipv6Addr>,
    created_at: Instant,
    timeout: Duration,
    stats: Arc<SessionStats>,
}
```

`SessionStats` (`src/implementations/server/session.rs:52-58`) records counters but never enforces:
```rust
pub struct SessionStats {
    pub bytes_sent: AtomicU64,
    pub bytes_received: AtomicU64,
    pub packets_sent: AtomicU64,
    pub packets_received: AtomicU64,
}
```
`record_sent()` and `record_received()` (lines 65-72) blindly increment — observability-only, not enforcement.

### Existing rate limiter is packet-rate, not bandwidth
`src/implementations/server/limits.rs:7-16` — `RateLimitConfig` limits PPS, not bytes/sec:
```rust
pub struct RateLimitConfig {
    pub max_pps: u64,       // packets per second
    pub max_bps: u64,       // bytes per second (0 = unlimited)
    pub refill_interval: Duration,
}
```
Default (`limits.rs:18-26`): `max_pps: 10_000, max_bps: 0` (unlimited bandwidth).

`TokenBucket` (`limits.rs:75-134`) is a simple integer bucket — no burst/capacity separation, no sub-second precision. `RateLimiter` (`limits.rs:137-141`) uses `HashMap<RateLimitKey, TokenBucket>` keyed by `Session(u64)` or `Ip(IpAddr)`.

The `rate_limiter` feature (`mod.rs:829-970`) provides `PacketRateLimiterDomain` that limits packet rate per IP on the incoming datagram path — a DoS protection mechanism, not bandwidth shaping. It does not:
- Limit bytes per second per client (bandwidth)
- Support burst sizes separate from steady-state rate
- Track cumulative usage for quota enforcement
- Apply to the server-to-client (downlink) send path
- Support per-client configuration overrides

### No traffic quotas
No daily/monthly quota system exists. A single client can consume unlimited bandwidth indefinitely.

### No fairness
When multiple clients are active, the server sends packets first-come-first-served. No weighted fair queueing, no round-robin, no deficit-based scheduling.

### QKeyRecord has policy override fields
`src/implementations/server/qkey_registry.rs:138-153` — `QKeyRecord` has `stealth` and `fec` override fields but no bandwidth/quota fields:
```rust
pub struct QKeyRecord {
    pub id: String,
    pub name: Option<String>,
    pub token_sha256: String,
    pub stealth: Option<String>,
    pub fec: Option<String>,
    pub created_at: u64,
    // ... no bandwidth_limit, no quota fields
}
```

## Problem Analysis

For a production VPN, bandwidth management is critical:
1. **One abusive client can saturate the server's uplink** — degrading service for all other clients. Without per-client limits, there is no protection.
2. **No quota enforcement** — a client can transfer unlimited data, potentially incurring bandwidth costs for the operator.
3. **No fairness** — a high-bandwidth client can starve low-bandwidth clients. Without fair scheduling, the server's uplink is distributed greedily.
4. **No per-client customization** — premium clients could get higher limits, but there is no mechanism to configure per-client overrides.
5. **Stealth concern** — naive rate limiting (drop packets above threshold) creates a detectable traffic pattern. The limiter must smooth traffic to avoid sharp rate changes that an observer could correlate with rate limiting.

## Proposed Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│                  Bandwidth Management Architecture                │
│                                                                   │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐              │
│  │ Client A    │  │ Client B    │  │ Client C    │              │
│  │ 10 Mbit/s   │  │ Unlimited   │  │ 5 Mbit/s    │              │
│  │ 100MB/day   │  │             │  │ 50MB/day    │              │
│  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘              │
│         │                │                │                      │
│         ▼                ▼                ▼                      │
│  ┌──────────────────────────────────────────────────────┐       │
│  │              FairScheduler (DRR)                      │       │
│  │  Weighted round-robin: distributes uplink fairly     │       │
│  └──────────────────────┬───────────────────────────────┘       │
│                         │                                         │
│                         ▼                                         │
│  ┌──────────────────────────────────────────────────────┐       │
│  │         Per-Session Enforcement                       │       │
│  │  1. QuotaTracker.check() → block/throttle/disconnect │       │
│  │  2. TokenBucket.try_consume(bytes) → allow/drop      │       │
│  │  3. Send packet to client                            │       │
│  └──────────────────────────────────────────────────────┘       │
│                                                                   │
│  Config: BandwidthConfig (global defaults)                       │
│  Override: QKeyRecord (per-key policy)                           │
│  Admin API: GET/POST /api/clients/<ip>/bandwidth                 │
└──────────────────────────────────────────────────────────────────┘
```

## Implementation Plan

### Step 1: Lock-free token bucket for bandwidth
Create `src/implementations/server/bandwidth.rs`:

```rust
use std::sync::atomic::{AtomicU64, Ordering};

/// Lock-free token bucket for per-session bandwidth limiting.
/// Tokens are replenished at `rate` bytes/sec, up to `burst` bytes.
/// Uses fixed-point arithmetic (tokens × 1000) for sub-byte precision.
pub struct TokenBucket {
    rate: u64,                          // bytes/sec
    burst: u64,                         // max burst in bytes
    tokens: AtomicU64,                  // current tokens × 1000
    last_refill: AtomicU64,             // monotonic nanos
}

impl TokenBucket {
    pub fn new(rate: u64, burst: u64) -> Self {
        let now = monotonic_nanos();
        Self {
            rate,
            burst,
            tokens: AtomicU64::new(burst * 1000),  // Start full
            last_refill: AtomicU64::new(now),
        }
    }

    /// Try to consume `bytes` tokens. Returns true if allowed.
    pub fn try_consume(&self, bytes: u64) -> bool {
        let now = monotonic_nanos();
        let last = self.last_refill.load(Ordering::Relaxed);
        let elapsed_ns = now.saturating_sub(last);
        let replenish = (elapsed_ns as u128 * self.rate as u128 / 1_000_000_000) as u64;
        let replenish_milli = replenish * 1000;

        loop {
            let current = self.tokens.load(Ordering::Relaxed);
            let new_tokens = (current + replenish_milli).min(self.burst * 1000);
            let needed = bytes * 1000;

            if new_tokens < needed {
                let _ = self.last_refill.compare_exchange(
                    last, now, Ordering::Relaxed, Ordering::Relaxed);
                return false;
            }

            let after = new_tokens - needed;
            match self.tokens.compare_exchange(
                current, after, Ordering::Relaxed, Ordering::Relaxed) {
                Ok(_) => {
                    let _ = self.last_refill.compare_exchange(
                        last, now, Ordering::Relaxed, Ordering::Relaxed);
                    return true;
                }
                Err(_) => continue,
            }
        }
    }
}
```

### Step 2: Per-session quota tracker
```rust
pub struct QuotaTracker {
    daily_limit: AtomicU64,       // bytes (0 = unlimited)
    monthly_limit: AtomicU64,     // bytes (0 = unlimited)
    daily_used: AtomicU64,
    monthly_used: AtomicU64,
    last_daily_reset: AtomicU64,  // epoch secs
    last_monthly_reset: AtomicU64,
    blocked: AtomicBool,
}

pub enum QuotaStatus { Allowed, DailyExceeded, MonthlyExceeded }

impl QuotaTracker {
    pub fn record_traffic(&self, bytes: u64) -> QuotaStatus {
        self.maybe_reset();
        let daily = self.daily_used.fetch_add(bytes, Ordering::Relaxed) + bytes;
        let monthly = self.monthly_used.fetch_add(bytes, Ordering::Relaxed) + bytes;
        // Check limits, set blocked flag if exceeded
        // ...
    }
}
```

### Step 3: Add bandwidth state to Session
Extend `Session` (`src/implementations/server/session.rs:40-49`):
```rust
pub struct Session {
    // ... existing fields ...
    downlink_limiter: Option<TokenBucket>,
    quota_tracker: QuotaTracker,
}
```

### Step 4: Enforce in server send path
In the TUN→client forwarding loop (`src/implementations/server/mod.rs`, ~line 4125):
```rust
// Before sending a packet to a client:
if session.quota_tracker.is_blocked() { continue; }
let status = session.quota_tracker.record_traffic(pkt.len() as u64);
if status != QuotaStatus::Allowed { continue; }
if let Some(limiter) = &session.downlink_limiter {
    if !limiter.try_consume(pkt.len() as u64) { continue; }
}
send_packet_to_client(pkt, session);
```

### Step 5: Configuration
Add `BandwidthConfig` to `src/engine/config.rs`:
```rust
pub struct BandwidthConfig {
    pub per_client_rate_limit_bps: u64,      // 0 = unlimited
    pub per_client_burst_bytes: u64,         // 0 = no burst
    pub per_client_quota_mb_daily: u64,      // 0 = unlimited
    pub per_client_quota_mb_monthly: u64,    // 0 = unlimited
    pub quota_exceeded_action: QuotaAction,  // Block | Throttle | Disconnect
}
```

```toml
# config/server-linux.default.toml
[bandwidth]
per_client_rate_limit_bps = 0          # 0 = unlimited, 10000000 = 10 Mbit
per_client_burst_bytes = 0             # 0 = no burst, 1048576 = 1 MB burst
per_client_quota_mb_daily = 0          # 0 = unlimited
per_client_quota_mb_monthly = 0        # 0 = unlimited
quota_exceeded_action = "block"        # "block" | "throttle" | "disconnect"
```

### Step 6: Per-client override via QKey policy
Add bandwidth fields to `QKeyRecord` (`src/implementations/server/qkey_registry.rs:138-153`):
```rust
pub struct QKeyRecord {
    // ... existing fields ...
    pub bandwidth_limit_bps: Option<u64>,
    pub bandwidth_burst_bytes: Option<u64>,
    pub quota_daily_mb: Option<u64>,
    pub quota_monthly_mb: Option<u64>,
}
```
When a session is created, the QKey's per-key overrides take precedence over global `BandwidthConfig` defaults.

### Step 7: Admin API endpoints
Add to `src/implementations/server/admin_http.rs`:
```
GET  /api/clients/<ip>/bandwidth    → current limits + usage
POST /api/clients/<ip>/bandwidth    → set per-client rate/burst/quota
GET  /api/clients/<ip>/quota        → daily/monthly usage + status
POST /api/clients/<ip>/quota/reset  → reset quota counters
GET  /api/bandwidth/stats           → aggregate bandwidth stats
```

### Step 8: Fairness scheduling (Deficit Round Robin)
```rust
pub struct FairScheduler {
    clients: Vec<(SessionId, u64)>,  // (id, weight)
    current_index: usize,
    deficit: Vec<i64>,
}

impl FairScheduler {
    /// DRR: each client accumulates deficit per round.
    /// A client can send if deficit >= packet_size.
    pub fn next(&mut self, quantum: u64) -> Option<SessionId> { ... }
}
```
Applied in the TUN→client forwarding loop when multiple clients have pending packets.

## Technology Choices

| Choice | Selection | Rationale |
|--------|-----------|-----------|
| Token bucket algorithm | Lock-free CAS-based (AtomicU64) | < 50ns per check; no mutex contention; sub-byte precision via fixed-point |
| Quota tracking | AtomicU64 counters with periodic reset | Lock-free; reset at UTC midnight (daily) / 1st of month (monthly) |
| Fair scheduling | Deficit Round Robin (DRR) | O(1) per packet; fair allocation with weights; simple implementation |
| Quota exceed action | Configurable: Block / Throttle / Disconnect | Block = drop packets, keep session; Throttle = reduce to minimum bandwidth; Disconnect = terminate session |
| Per-client override | QKeyRecord fields + Admin API | QKey policy for static config; Admin API for runtime changes |
| Alternative considered: HTB/qdisc (kernel-level) | Rejected | Would require tc commands; not portable; userspace token bucket is simpler and sufficient |

## Stealth/Efficiency Considerations

- **Rate limiting must not create detectable patterns**: Naive drop-based limiting creates sharp traffic bursts (send at full speed, then stop when tokens depleted). To avoid this:
  - Use a large enough burst size (default 1 MB) to smooth short-term traffic
  - Consider traffic shaping (delay packets slightly) vs traffic policing (drop packets) — shaping is stealthier but adds latency
  - The token bucket naturally smooths traffic: tokens replenish continuously, so the effective rate is `rate` bytes/sec averaged over time
- **No hot-path allocation**: Token bucket check is < 50ns (2 atomic ops). Quota check is < 30ns (1 atomic fetch_add + compare). No heap allocation on the per-packet path.
- **Per-session memory**: ~128 bytes (TokenBucket 32B + QuotaTracker ~96B). For 1000 clients: ~128 KB total — negligible.
- **Fair scheduler overhead**: DRR scan is O(n) where n = active clients. For 100 clients: < 100ns per scheduling decision.
- **Stealth mode interaction**: When stealth mode is active, avoid aggressive rate limiting that could create traffic analysis artifacts. The limiter should be configured with generous burst sizes in stealth mode.
- **QUIC flow control integration**: In addition to the TUN write path, QUIC's built-in flow control can be used to limit downlink bandwidth by adjusting `max_data` per stream. This is a complementary mechanism that works at the transport layer.

## Testing Plan

### Unit tests
- `test_token_bucket_replenish` — tokens replenish at correct rate over time
- `test_token_bucket_consume` — consumption decrements tokens correctly
- `test_token_bucket_burst` — initial burst exceeds steady-state rate, then settles
- `test_token_bucket_overflow` — tokens saturate at burst capacity
- `test_token_bucket_concurrent` — concurrent `try_consume` calls are safe (no data races)
- `test_quota_tracker_daily_reset` — daily counter resets at UTC midnight
- `test_quota_tracker_monthly_reset` — monthly counter resets on 1st of month
- `test_quota_tracker_block` — blocked flag set when daily limit exceeded
- `test_quota_tracker_throttle` — throttle action reduces bandwidth to minimum
- `test_quota_tracker_disconnect` — disconnect action triggers session termination
- `test_fair_scheduler_equal_weights` — 3 clients with equal weight get ~equal bandwidth
- `test_fair_scheduler_weighted` — clients with weights 1:2:1 get ~10/20/10 Mbit

### Integration tests
- `test_bandwidth_limit_10mbit` — iperf throughput ≤ 10 Mbit/s (±5% tolerance) with `per_client_rate_limit_bps = 10_000_000`
- `test_bandwidth_unlimited` — iperf throughput not constrained when `per_client_rate_limit_bps = 0`
- `test_bandwidth_burst_1mb` — initial burst exceeds 10 Mbit briefly, then settles
- `test_quota_daily_100mb` — after 100 MB transfer, further packets blocked
- `test_quota_reset_via_api` — `POST /api/clients/<ip>/quota/reset` resets counters
- `test_admin_api_get_bandwidth` — `GET /api/clients/<ip>/bandwidth` returns limits + usage
- `test_admin_api_set_bandwidth` — `POST /api/clients/<ip>/bandwidth` updates limits in real-time
- `test_fair_scheduler_3_clients` — 3 clients with equal weight on 30 Mbit uplink: each gets ~10 Mbit (±10%)
- `test_qkey_override_bandwidth` — QKey with `bandwidth_limit_bps` override takes precedence over global default
- `test_no_memory_leak` — token bucket and quota tracker cleaned up on session removal

## Files to Create/Modify

| File | Action | Description |
|------|--------|-------------|
| `src/implementations/server/bandwidth.rs` | Create | `TokenBucket`, `QuotaTracker`, `FairScheduler`, `QuotaStatus`, `QuotaAction` |
| `src/implementations/server/session.rs:40-49` | Modify | Add `downlink_limiter: Option<TokenBucket>` and `quota_tracker: QuotaTracker` to `Session` |
| `src/implementations/server/session.rs:124-247` | Modify | Add methods to `SessionManager` for bandwidth/quota lookup and per-client override |
| `src/implementations/server/mod.rs:~4125` | Modify | Enforce rate limit + quota in TUN→client send path |
| `src/implementations/server/admin_http.rs:~2759` | Modify | Add bandwidth/quota API endpoints |
| `src/implementations/server/qkey_registry.rs:138-153` | Modify | Add `bandwidth_limit_bps`, `bandwidth_burst_bytes`, `quota_daily_mb`, `quota_monthly_mb` to `QKeyRecord` |
| `src/engine/config.rs` | Modify | Add `BandwidthConfig` struct |
| `config/server-linux.default.toml` | Modify | Add `[bandwidth]` section |
| `docs/DOCUMENTATION.md` | Modify | Document bandwidth limits, quotas, admin API, QKey overrides |

## Risks & Mitigations

| Risk | Severity | Mitigation |
|------|----------|------------|
| Token bucket CAS contention under high load | Medium | Use `Ordering::Relaxed` for most operations; contention is unlikely since each session has its own bucket |
| Quota counter drift due to `fetch_add` non-atomic check | Low | Counters are approximate; exact enforcement is not required for quotas |
| Fair scheduler starvation | Low | DRR guarantees fairness by construction; deficit accumulates for idle clients |
| Rate limiting creates detectable traffic patterns | Medium | Use generous burst sizes; consider traffic shaping (delay) vs policing (drop); test with traffic analysis tools |
| Per-client override not applied on session creation | Medium | Apply QKey overrides in `parse_live_server_initial_auth` when creating `QKeyAuthState` |
| Admin API changes not taking effect without restart | Medium | Store overrides in `HashMap<Ipv4Addr, ClientBandwidthOverride>`; apply on next packet |
| Memory leak on session removal | Low | Token bucket and quota tracker are owned by `Session`; dropped when session is removed |

## Completion Criteria

- [ ] Client with `per_client_rate_limit_bps = 10_000_000`: iperf throughput ≤ 10 Mbit/s (±5%)
- [ ] Client with `per_client_rate_limit_bps = 0`: throughput not constrained
- [ ] Client with `per_client_burst_bytes = 1_048_576`: initial burst exceeds rate, then settles
- [ ] Client with `per_client_quota_mb_daily = 100`: after 100 MB, packets blocked (or throttled/disconnected)
- [ ] Quota resets at UTC midnight (daily) and 1st of month (monthly)
- [ ] Admin API `GET /api/clients/<ip>/bandwidth` returns current limits + usage
- [ ] Admin API `POST /api/clients/<ip>/bandwidth` updates limits in real-time (no restart)
- [ ] Admin API `POST /api/clients/<ip>/quota/reset` resets counters to zero
- [ ] Fair scheduler: 3 equal-weight clients on 30 Mbit uplink → each gets ~10 Mbit (±10%)
- [ ] Fair scheduler: 3 clients (weights 1:2:1) on 40 Mbit uplink → 10/20/10 Mbit
- [ ] QKey override takes precedence over global default
- [ ] No memory leak: bandwidth state cleaned up on session removal
- [ ] `cargo clippy --lib -D warnings` is clean
- [ ] Unit tests pass: token bucket correctness, quota tracker, fair scheduler
