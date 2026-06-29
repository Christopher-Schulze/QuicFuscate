---
id: TODO-445
title: Per-client bandwidth limits, traffic quotas, and fairness
severity: HIGH
phase: "I"
priority: P1
status: OPEN
created: 2026-06-30
depends_on: []
---

# TODO-445: Per-Client Bandwidth Limits, Traffic Quotas, and Fairness

## Problem

The server tracks sessions (`src/implementations/server/session.rs:124-247`) and
records byte/packet counters via `SessionStats` (lines 51-73), but there is
**no per-session rate limiting, no traffic quota enforcement, and no fairness
mechanism**.

### Session tracking without limits

`SessionManager` (`src/implementations/server/session.rs:124-129`) is a pure
lookup structure:

```rust
pub struct SessionManager {
    sessions: HashMap<SessionId, Session>,
    by_client_ip: HashMap<Ipv4Addr, SessionId>,
    by_remote_addr: HashMap<SocketAddr, SessionId>,
    max_sessions: usize,
}
```

`SessionStats` (`src/implementations/server/session.rs:51-57`) records counters
but never enforces anything:

```rust
pub struct SessionStats {
    pub bytes_sent: AtomicU64,
    pub bytes_received: AtomicU64,
    pub packets_sent: AtomicU64,
    pub packets_received: AtomicU64,
}
```

The `record_sent()` and `record_received()` methods (lines 64-72) blindly
increment counters — they are observability-only, not enforcement.

### Existing rate limiter is packet-rate, not bandwidth

The `rate_limiter` feature (`src/implementations/server/mod.rs:829-970`) provides
a `PacketRateLimiterDomain` that limits **packet rate per IP** (packets/sec),
not bandwidth (bytes/sec). It operates on the incoming datagram path
(`allow_incoming_datagram`, line 952) and rejects packets above the rate limit.
This is a DoS protection mechanism, not a bandwidth shaping tool. It does not:

- Limit bytes per second per client (bandwidth)
- Support burst sizes
- Track cumulative usage for quota enforcement
- Apply to the server-to-client (downlink) send path
- Support per-client configuration overrides

### No traffic quotas

There is no daily/monthly traffic quota system. A single client can consume
unlimited bandwidth indefinitely. For a production VPN, this is a critical
operational gap — one abusive client can saturate the server's uplink and
degrade service for all other clients.

### No fairness

When multiple clients are active, the server sends packets on a first-come-
first-served basis. There is no weighted fair queueing, no round-robin, no
deficit-based scheduling. A high-bandwidth client can starve low-bandwidth
clients.

## Goal

1. **Per-session token bucket rate limiting** — each client gets a configurable
   bandwidth limit (bytes/sec) with a burst size, enforced in the server send
   path before TUN write.

2. **Per-client traffic quotas** — daily and monthly byte quotas. When exceeded,
   the client is blocked (session terminated or throttled to a configurable
   minimum).

3. **Admin API** — set per-client limits, view real-time usage, view quota
   status.

4. **Fairness** — when multiple clients compete for server uplink bandwidth,
   distribute it fairly (weighted round-robin or deficit-based scheduling).

## Implementation Plan

### Step 1: Token bucket rate limiter

Create a lock-free token bucket implementation:

```rust
// src/implementations/server/bandwidth.rs (new file)

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

/// Lock-free token bucket for per-session bandwidth limiting.
/// Tokens are replenished at `rate` bytes/sec, up to `burst` bytes.
pub struct TokenBucket {
    /// Replenish rate in bytes/sec.
    rate: u64,
    /// Maximum burst size in bytes.
    burst: u64,
    /// Current token count (fixed-point: tokens * 1000 for sub-byte precision).
    tokens: AtomicU64,
    /// Last replenish timestamp (nanos since some epoch).
    last_refill: AtomicU64,
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

    /// Try to consume `bytes` tokens. Returns true if allowed, false if rate-limited.
    pub fn try_consume(&self, bytes: u64) -> bool {
        let now = monotonic_nanos();
        let last = self.last_refill.load(Ordering::Relaxed);
        let elapsed_ns = now.saturating_sub(last);

        // Replenish: add (elapsed_ns * rate) / 1_000_000_000 tokens
        let replenish = (elapsed_ns as u128 * self.rate as u128 / 1_000_000_000) as u64;
        let replenish_milli = replenish * 1000;

        // CAS loop: update tokens and last_refill atomically
        loop {
            let current = self.tokens.load(Ordering::Relaxed);
            let new_tokens = (current + replenish_milli).min(self.burst * 1000);
            let needed = bytes * 1000;

            if new_tokens < needed {
                // Not enough tokens — rate limited
                // Try to update last_refill anyway (so we don't over-replenish next time)
                let _ = self.last_refill.compare_exchange(
                    last, now, Ordering::Relaxed, Ordering::Relaxed
                );
                return false;
            }

            let after_consume = new_tokens - needed;
            match self.tokens.compare_exchange(
                current, after_consume, Ordering::Relaxed, Ordering::Relaxed
            ) {
                Ok(_) => {
                    let _ = self.last_refill.compare_exchange(
                        last, now, Ordering::Relaxed, Ordering::Relaxed
                    );
                    return true;
                }
                Err(_) => continue,  // Retry CAS
            }
        }
    }
}

fn monotonic_nanos() -> u64 {
    use std::time::SystemTime;
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0)
}
```

### Step 2: Per-session bandwidth state

Add bandwidth limiting state to `Session`:

```rust
// src/implementations/server/session.rs

pub struct Session {
    id: SessionId,
    remote_addr: SocketAddr,
    client_ip: Ipv4Addr,
    created_at: Instant,
    timeout: Duration,
    stats: Arc<SessionStats>,
    // NEW: per-session bandwidth limiter (downlink: server → client)
    downlink_limiter: Option<TokenBucket>,
    // NEW: per-session quota tracker
    quota_tracker: QuotaTracker,
}

/// Per-client traffic quota tracker.
pub struct QuotaTracker {
    /// Daily quota in bytes (0 = unlimited).
    daily_limit: AtomicU64,
    /// Monthly quota in bytes (0 = unlimited).
    monthly_limit: AtomicU64,
    /// Bytes sent today (resets at UTC midnight).
    daily_used: AtomicU64,
    /// Bytes sent this month (resets on 1st of month).
    monthly_used: AtomicU64,
    /// Timestamp of last daily reset (UTC midnight).
    last_daily_reset: AtomicU64,
    /// Timestamp of last monthly reset.
    last_monthly_reset: AtomicU64,
    /// Whether client is currently quota-blocked.
    blocked: AtomicBool,
}

impl QuotaTracker {
    pub fn record_traffic(&self, bytes: u64) -> QuotaStatus {
        self.maybe_reset();
        let daily = self.daily_used.fetch_add(bytes, Ordering::Relaxed) + bytes;
        let monthly = self.monthly_used.fetch_add(bytes, Ordering::Relaxed) + bytes;

        let daily_limit = self.daily_limit.load(Ordering::Relaxed);
        let monthly_limit = self.monthly_limit.load(Ordering::Relaxed);

        if daily_limit > 0 && daily >= daily_limit {
            self.blocked.store(true, Ordering::Relaxed);
            return QuotaStatus::DailyExceeded;
        }
        if monthly_limit > 0 && monthly >= monthly_limit {
            self.blocked.store(true, Ordering::Relaxed);
            return QuotaStatus::MonthlyExceeded;
        }
        QuotaStatus::Allowed
    }

    pub fn is_blocked(&self) -> bool {
        self.blocked.load(Ordering::Relaxed)
    }
}

pub enum QuotaStatus {
    Allowed,
    DailyExceeded,
    MonthlyExceeded,
}
```

### Step 3: Enforce in server send path

In the server run-loop where packets are forwarded from TUN to clients
(`src/implementations/server/mod.rs`, the TUN→client send path ~line 4125),
check the rate limiter and quota before sending:

```rust
// Before sending a packet to a client:
let session = session_manager.get_by_client_ip(client_ip);
if let Some(session) = session {
    // 1. Check quota
    if session.quota_tracker.is_blocked() {
        metrics.record_quota_blocked();
        continue;  // Drop packet
    }
    let quota_status = session.quota_tracker.record_traffic(pkt.len() as u64);
    if quota_status != QuotaStatus::Allowed {
        metrics.record_quota_blocked();
        // Optionally: notify client, close session
        continue;
    }

    // 2. Check bandwidth limit (token bucket)
    if let Some(limiter) = &session.downlink_limiter {
        if !limiter.try_consume(pkt.len() as u64) {
            metrics.record_rate_limited();
            continue;  // Drop packet (or queue for later)
        }
    }

    // 3. Send the packet
    send_packet_to_client(pkt, session);
}
```

### Step 4: Configuration

Add per-client bandwidth and quota config to `src/engine/config.rs`:

```rust
pub struct BandwidthConfig {
    /// Default per-client rate limit in bytes/sec (0 = unlimited).
    pub per_client_rate_limit_bps: u64,
    /// Default per-client burst size in bytes (0 = no burst).
    pub per_client_burst_bytes: u64,
    /// Default daily quota per client in MB (0 = unlimited).
    pub per_client_quota_mb_daily: u64,
    /// Default monthly quota per client in MB (0 = unlimited).
    pub per_client_quota_mb_monthly: u64,
    /// Whether to terminate session on quota exceeded (true) or throttle (false).
    pub quota_exceeded_action: QuotaAction,
}

pub enum QuotaAction {
    Block,     // Drop all packets, keep session alive
    Throttle,  // Reduce to minimum bandwidth (e.g., 100 KB/s)
    Disconnect,// Terminate the session
}

impl Default for BandwidthConfig {
    fn default() -> Self {
        Self {
            per_client_rate_limit_bps: 0,        // Unlimited by default
            per_client_burst_bytes: 0,           // No burst
            per_client_quota_mb_daily: 0,        // Unlimited
            per_client_quota_mb_monthly: 0,      // Unlimited
            quota_exceeded_action: QuotaAction::Block,
        }
    }
}
```

Config file (`config/server-linux.default.toml`):

```toml
[bandwidth]
per_client_rate_limit_bps = 0          # 0 = unlimited, 10000000 = 10 Mbit
per_client_burst_bytes = 0             # 0 = no burst, 1048576 = 1 MB burst
per_client_quota_mb_daily = 0          # 0 = unlimited
per_client_quota_mb_monthly = 0        # 0 = unlimited
quota_exceeded_action = "block"        # "block" | "throttle" | "disconnect"
```

### Step 5: Per-client override via Admin API

Add Admin API endpoints for per-client limit management:

```
GET  /api/clients/<ip>/bandwidth    → current limits + usage
POST /api/clients/<ip>/bandwidth    → set per-client rate/burst/quota
GET  /api/clients/<ip>/quota        → daily/monthly usage + status
POST /api/clients/<ip>/quota/reset  → reset quota counters
GET  /api/bandwidth/stats           → aggregate bandwidth stats
```

Implementation in `src/implementations/server/admin_http.rs`:

```rust
// Add to route matching (around line 2759)
("GET", path) if path.starts_with("/api/clients/") && path.ends_with("/bandwidth") => {
    let ip = extract_client_ip(path);
    admin_json_response(&handler.handle_get_client_bandwidth(ip))
}
("POST", path) if path.starts_with("/api/clients/") && path.ends_with("/bandwidth") => {
    let ip = extract_client_ip(path);
    let payload: BandwidthPayload = serde_json::from_slice(&req.body)?;
    admin_json_response(&handler.handle_set_client_bandwidth(ip, payload))
}
```

Per-client overrides stored in a `HashMap<Ipv4Addr, ClientBandwidthOverride>`:

```rust
pub struct ClientBandwidthOverride {
    rate_limit_bps: Option<u64>,
    burst_bytes: Option<u64>,
    daily_quota_mb: Option<u64>,
    monthly_quota_mb: Option<u64>,
}
```

### Step 6: Fairness scheduling

When the server has packets to send to multiple clients, use a weighted
round-robin scheduler to distribute uplink bandwidth fairly:

```rust
// src/implementations/server/bandwidth.rs

/// Weighted round-robin scheduler for fair bandwidth distribution.
pub struct FairScheduler {
    clients: Vec<(SessionId, u64)>,  // (id, weight)
    current_index: usize,
    deficit: Vec<i64>,
}

impl FairScheduler {
    /// Get the next client that should receive a packet.
    /// Returns None if no clients are eligible.
    pub fn next(&mut self, quantum: u64) -> Option<SessionId> {
        // Deficit round-robin (DRR) algorithm:
        // Each client accumulates deficit per round.
        // A client can send if deficit >= packet_size.
        // ...
    }
}
```

This is applied in the TUN→client forwarding loop when multiple clients have
pending packets.

## Files to Modify/Create

- `src/implementations/server/bandwidth.rs` (new) — `TokenBucket`, `QuotaTracker`,
  `FairScheduler`, `BandwidthConfig`, `ClientBandwidthOverride`
- `src/implementations/server/session.rs:39-120` — add `downlink_limiter` and
  `quota_tracker` fields to `Session`, add `QuotaTracker` struct
- `src/implementations/server/session.rs:124-247` — add methods to
  `SessionManager` for bandwidth/quota lookup and per-client override
- `src/implementations/server/mod.rs:~4125` — enforce rate limit + quota in
  TUN→client send path
- `src/implementations/server/admin_http.rs:~2759` — add bandwidth/quota API
  endpoints
- `src/engine/config.rs` — add `BandwidthConfig` struct
- `config/server-linux.default.toml` — add `[bandwidth]` section
- `docs/DOCUMENTATION.md` — document bandwidth limits, quotas, admin API

## Acceptance Criteria

- Client A with `per_client_rate_limit_bps = 10_000_000` (10 Mbit): iperf
  throughput measures ≤ 10 Mbit/s (±5% tolerance)
- Client B with `per_client_rate_limit_bps = 0` (unlimited): iperf throughput
  is not constrained by the limiter
- Client A with `per_client_burst_bytes = 1_048_576` (1 MB): initial burst
  exceeds 10 Mbit briefly, then settles to 10 Mbit
- Client with `per_client_quota_mb_daily = 100`: after transferring 100 MB,
  further packets are blocked (or throttled/disconnected per config)
- Quota resets at UTC midnight (daily) and 1st of month (monthly)
- Admin API `GET /api/clients/<ip>/bandwidth` returns current limits + usage
- Admin API `POST /api/clients/<ip>/bandwidth` updates limits in real-time
  (takes effect without restart)
- Admin API `POST /api/clients/<ip>/quota/reset` resets counters to zero
- Fair scheduler: with 3 clients (equal weight) and 30 Mbit server uplink,
  each client gets ~10 Mbit (±10% tolerance)
- Fair scheduler: with 3 clients (weights 1:2:1) and 40 Mbit uplink, clients
  get ~10/20/10 Mbit respectively
- No memory leak: token bucket and quota tracker are cleaned up on session
  removal
- `cargo clippy --lib -D warnings` is clean
- Unit tests: token bucket correctness (replenish, consume, burst, overflow)
- Unit tests: quota tracker (daily/monthly reset, block/throttle/disconnect)

## Resource Budget

| Scenario | Budget | Notes |
|----------|--------|-------|
| Token bucket check (per packet) | < 50ns | Atomic CAS, no lock |
| Quota check (per packet) | < 30ns | Atomic fetch_add + compare |
| Per-session memory | ~128 bytes | TokenBucket (32B) + QuotaTracker (~96B) |
| Fair scheduler decision | < 100ns | DRR scan over client list |
| Admin API response | < 1ms | HashMap lookup + JSON serialization |
| 1000 concurrent clients | < 128KB | 1000 × 128B bandwidth state |
