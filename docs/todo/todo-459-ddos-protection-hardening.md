---
id: TODO-459
title: "DDoS protection hardening (rate limits, burst, GeoIP, blacklist sync, challenge-response)"
severity: HIGH
phase: "I"
priority: P1
status: DONE
created: 2026-07-23
depends_on: []
---

# TODO-459: DDoS Protection Hardening

## Goal
Harden the server against DDoS attacks by lowering the default per-IP rate limit from 10,000 to 1,000 PPS, adding burst size configuration, implementing a global server-wide rate cap, adding anomaly detection (EWMA-based spike detection), GeoIP blocking via MaxMindDB, external blacklist synchronization (AbuseIPDB-style), and QUIC retry token challenge-response for suspicious IPs. All features must be configurable and must not block legitimate users during a DDoS attack.

## Current State (verified against code)

### Default rate limit is 10,000 PPS per IP
`src/implementations/server/limits.rs:18-26`:
```rust
impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            max_pps: 10_000,
            max_bps: 0, // Unlimited
            refill_interval: Duration::from_secs(1),
        }
    }
}
```
10,000 PPS per IP means a botnet of 1,000 IPs can send 10 million PPS — enough to saturate a 10 Gbps link.

### TokenBucket has no burst/capacity separation
`src/implementations/server/limits.rs:75-93`:
```rust
struct TokenBucket {
    tokens: u64,
    max_tokens: u64,      // = burst = steady-state rate (no separation)
    last_refill: Instant,
    last_seen: Instant,
    refill_rate: u64,     // = max_tokens (same as capacity)
    refill_interval: Duration,
}
```
The bucket starts full at `max_pps` tokens. The first second after a new IP appears, it can send all 10,000 packets instantly (a burst). There is no separate `burst_size` config.

### No global rate limiter
`RateLimiter` (`limits.rs:137-141`) only limits per-session and per-IP. No server-wide PPS cap. An attacker with many IPs can exhaust CPU/bandwidth even if each IP is under the per-IP limit.

### No anomaly detection
No code tracks rolling average PPS or triggers enhanced limiting when a spike is detected. The server reacts identically at 100 PPS and 100,000 PPS.

### No GeoIP blocking
No `maxminddb` dependency, no GeoIP database loading, no country-based filtering.

### No external blacklist sync
No code fetches AbuseIPDB, Spamhaus, or any threat-intelligence feed.

### No challenge-response
When rate limit is exceeded, the server drops packets (`check_packet_key` returns `false`). No QUIC retry token mechanism to force client reachability proof.

### Accept loop exists
`src/implementations/server/mod.rs:34-37` — `AcceptLoop`, `AcceptConfig`, `AcceptDecision`, `IpConnectionTracker` are imported from the `accept` module. The accept loop manages per-IP connection tracking and rate limiting. `LiveServerState` (`mod.rs:2091-2096`) holds `auth_rate_limiter`.

### Auth rate limiter exists
`src/implementations/server/mod.rs:2095` — `AuthRateLimiter` limits auth attempts per IP. This is separate from the packet rate limiter.

## Problem Analysis

A production VPN server exposed to the public internet is a prime DDoS target. The current protections are insufficient:

1. **10,000 PPS per IP is too high**: A single botnet of 1,000 IPs sends 10M PPS — saturating any server.
2. **No burst control**: New IPs can burst all tokens instantly, creating micro-floods.
3. **No global cap**: Many IPs each under per-IP limit can still overwhelm the server.
4. **No anomaly detection**: The server can't distinguish normal traffic from a DDoS attack.
5. **No GeoIP**: Can't block traffic from countries known for attack origination.
6. **No blacklist**: Can't preemptively block known malicious IPs from threat intelligence feeds.
7. **No anti-spoofing**: SYN flood with spoofed source IPs can't be mitigated without retry tokens.

## Proposed Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│                  DDoS Protection Pipeline                         │
│                                                                   │
│  Incoming UDP Packet                                              │
│         │                                                         │
│         ▼                                                         │
│  ┌──────────────────┐                                            │
│  │ 1. Global Rate   │──── drop if server-wide PPS > cap          │
│  │    Limiter       │     (default 50,000 PPS)                   │
│  └────────┬─────────┘                                            │
│           │                                                       │
│           ▼                                                       │
│  ┌──────────────────┐                                            │
│  │ 2. GeoIP Blocker │──── drop if country in blocked list        │
│  │    (MaxMindDB)   │     (configurable country list)            │
│  └────────┬─────────┘                                            │
│           │                                                       │
│           ▼                                                       │
│  ┌──────────────────┐                                            │
│  │ 3. Blacklist     │──── drop if IP in external blacklist       │
│  │    Sync          │     (AbuseIPDB, hourly sync)               │
│  └────────┬─────────┘                                            │
│           │                                                       │
│           ▼                                                       │
│  ┌──────────────────┐                                            │
│  │ 4. DDoS Detector │──── if spike detected:                     │
│  │    (EWMA)        │     • halve per-IP limits                  │
│  └────────┬─────────┘     • enable QUIC retry tokens             │
│           │                                                       │
│           ▼                                                       │
│  ┌──────────────────┐                                            │
│  │ 5. Per-IP Rate   │──── drop if PPS > limit (× multiplier)     │
│  │    Limiter       │     (default 1,000 PPS, burst 100)         │
│  └────────┬─────────┘                                            │
│           │                                                       │
│           ▼                                                       │
│  ┌──────────────────┐                                            │
│  │ 6. Per-Session   │──── existing per-session limiting          │
│  │    Limiter       │                                            │
│  └──────────────────┘                                            │
└──────────────────────────────────────────────────────────────────┘
```

## Implementation Plan

### Step 1: Lower default PPS and add burst size
`src/implementations/server/limits.rs:18-26`:
```rust
Self {
    max_pps: 1_000,       // Down from 10,000
    max_bps: 0,
    burst_size: 100,      // NEW: initial burst capacity
    refill_interval: Duration::from_secs(1),
}
```
Modify `TokenBucket` to separate burst capacity from refill rate:
```rust
struct TokenBucket {
    tokens: f64,
    capacity: f64,    // burst size (max tokens)
    refill_rate: f64, // tokens per second
    last_refill: Instant,
}
```

### Step 2: Global rate limiter
```rust
pub struct GlobalRateLimiter {
    bucket: parking_lot::Mutex<TokenBucket>,
}
impl GlobalRateLimiter {
    pub fn new(max_pps: u64) -> Self { ... }
    pub fn check(&self) -> bool { ... }
}
```
Add to server state. Call before per-IP checks in the packet acceptance path.

### Step 3: DDoS detection (EWMA spike detection)
Create `src/implementations/server/ddos_detector.rs`:
```rust
pub struct DdosDetector {
    /// EWMA of PPS (exponentially weighted moving average)
    ewma_pps: parking_lot::Mutex<f64>,
    /// Current PPS sample
    current_pps: AtomicU64,
    /// Whether enhanced limiting is active
    enhanced: AtomicBool,
    /// When enhanced mode was activated
    activated_at: parking_lot::Mutex<Option<Instant>>,
    /// Spike multiplier threshold (default 5.0)
    spike_multiplier: f64,
    /// Spike duration threshold (default 10s)
    spike_duration_secs: u64,
}
impl DdosDetector {
    pub fn record_pps(&self, pps: u64) { ... }
    /// Returns true if PPS > spike_multiplier × EWMA for spike_duration_secs
    pub fn is_ddos_active(&self) -> bool { ... }
    /// Returns 0.5 when active, 1.0 otherwise
    pub fn limit_multiplier(&self) -> f64 { ... }
}
```
A background task records PPS every second. When `is_ddos_active()` returns true:
1. Set `enhanced = true`
2. Halve effective per-IP limits (multiply `max_pps` by 0.5)
3. Enable QUIC retry tokens
4. Log warning and increment `ddos_detected_total`

Enhanced mode auto-clears when PPS drops below 2× average for 30s.

### Step 4: GeoIP blocking
Add `maxminddb = "0.28"` to `Cargo.toml` (with `mmap` feature).
Create `src/implementations/server/geoip.rs`:
```rust
pub struct GeoIpBlocker {
    reader: Option<maxminddb::Reader<Vec<u8>>>,
    blocked_countries: HashSet<String>,
}
impl GeoIpBlocker {
    pub fn new(db_path: Option<&Path>, blocked: HashSet<String>) -> Self { ... }
    pub fn is_blocked(&self, ip: IpAddr) -> bool { ... }
}
```
Config: `geoip_db_path`, `geoip_blocked_countries` (comma-separated ISO codes, e.g. `"CN,RU,KP"`).

### Step 5: External blacklist sync
Create `src/implementations/server/blacklist.rs`:
```rust
pub struct BlacklistSync {
    blocked_ips: parking_lot::RwLock<HashSet<IpAddr>>,
    sync_url: Option<String>,
    sync_interval: Duration,
}
impl BlacklistSync {
    pub fn is_blocked(&self, ip: IpAddr) -> bool { ... }
    pub async fn sync(&self) -> Result<(), BlacklistError> { ... }
}
```
- Format: one IP per line (plain text, compatible with AbuseIPDB CSV export)
- Background `tokio::spawn` task calls `sync()` every `blacklist_sync_interval_secs` (default 3600s)
- On startup, load cached local copy (`/var/lib/quicfuscate/blacklist.cache`)

### Step 6: QUIC retry token challenge-response
In `src/qftls.rs`, enable `use_retry(true)` when DDoS detection is active:
- Forces client to do a retry round trip (server sends retry token, client echoes it)
- Proves source IP is reachable (anti-spoofing)
- When DDoS mode clears, disable retry to avoid latency overhead

### Step 7: Configuration
Add `DdosProtectionConfig` to `src/engine/config.rs`:
```rust
pub struct DdosProtectionConfig {
    pub enabled: bool,
    pub global_rate_limit_pps: u64,           // default 50,000
    pub per_ip_burst_size: u64,               // default 100
    pub ddos_detection_enabled: bool,         // default true
    pub ddos_spike_multiplier: f64,           // default 5.0
    pub ddos_spike_duration_secs: u64,        // default 10
    pub geoip_db_path: Option<PathBuf>,
    pub geoip_blocked_countries: Vec<String>,
    pub blacklist_sync_url: Option<String>,
    pub blacklist_sync_interval_secs: u64,    // default 3600
    pub blacklist_cache_path: PathBuf,
    pub retry_token_on_ddos: bool,            // default true
}
```
All fields overridable via env vars: `QUICFUSCATE_DDOS_*`, `QUICFUSCATE_GEOIP_*`, `QUICFUSCATE_BLACKLIST_*`.

### Step 8: Wire into server
In `src/implementations/server/mod.rs`, add to server state: `global_rate_limiter`, `ddos_detector`, `geoip_blocker`, `blacklist_sync`. In the packet acceptance path:
1. `global_rate_limiter.check()` → drop if false
2. `geoip_blocker.is_blocked(src_ip)` → drop if true
3. `blacklist_sync.is_blocked(src_ip)` → drop if true
4. `ddos_detector.is_ddos_active()` → if true, apply `limit_multiplier()` to per-IP checks, enable retry tokens
5. Existing `rate_limiter.check_packet_ip(src_ip)` with adjusted limit

Spawn background tasks for blacklist sync and DDoS detector sampling on server start.

## Technology Choices

| Choice | Selection | Rationale |
|--------|-----------|-----------|
| GeoIP database | `maxminddb` crate v0.28.1 (with `mmap` feature) | 25M downloads; maintained by oschwald; mmap for zero-copy; GeoLite2-Country is free |
| DDoS detection | EWMA (exponentially weighted moving average) | O(1) memory; responsive to changes; standard for anomaly detection |
| Blacklist format | Plain text (one IP per line) | Compatible with AbuseIPDB CSV export; simple to parse; no JSON dependency |
| Blacklist sync | `reqwest` HTTP GET (already a dependency) | Fetch hourly; cache locally; background tokio task |
| QUIC retry tokens | `quinn`/transport layer `use_retry(true)` | Standard QUIC anti-spoofing mechanism (RFC 9000 Section 8.1); no custom protocol needed |
| Token bucket | f64-based with capacity/refill_rate separation | Decouples burst from steady-state rate; sub-integer precision |
| Alternative: eBPF/XDP for DDoS | Considered for Phase II | Kernel-level filtering before userspace; zero CPU overhead; but requires Linux 5.x+ and root |

## Stealth/Efficiency Considerations

- **Per-packet overhead**: GlobalRateLimiter check < 100ns (single token bucket under Mutex). GeoIpBlocker < 5µs (MaxMindDB mmap'd lookup). BlacklistSync < 100ns (HashSet under RwLock read). DdosDetector < 50ns (AtomicBool load). Total overhead < 6µs per packet — negligible.
- **Background task overhead**: Blacklist sync runs hourly (~100ms HTTP fetch). DDoS detector sampling runs every second (< 200ns VecDeque push). Neither impacts the hot path.
- **MaxMindDB memory**: GeoLite2-Country is ~6MB, mmap'd (not loaded into heap). Shared between all lookups.
- **Blacklist memory**: ~50MB for 1M IPs (HashSet<IpAddr> × ~50 bytes/entry). Configurable cache size limit.
- **Stealth interaction**: DDoS protection must not interfere with stealth mode. QUIC retry tokens add 1 RTT to connection setup — only enabled during active DDoS, disabled otherwise. GeoIP blocking is static (no traffic analysis impact). Blacklist is static (no traffic analysis impact).
- **False positive risk**: Legitimate users behind NAT share an IP. Per-IP rate limiting may block legitimate users during high traffic. Mitigation: burst size allows initial burst; global limit is generous (50,000 PPS); DDoS detection uses EWMA (not absolute threshold) to avoid false positives.
- **QUIC retry token stealth**: Retry tokens are a standard QUIC feature (RFC 9000). They don't reveal that DDoS protection is active — they look like normal QUIC retry behavior. An observer can't distinguish "server under DDoS" from "server with retry enabled by policy."

## Testing Plan

### Unit tests
- `test_token_bucket_burst_capacity` — bucket starts at `burst_size` tokens, refills at `max_pps` rate
- `test_token_bucket_burst_then_steady` — initial burst exceeds rate, then settles to `max_pps`
- `test_global_rate_limiter` — 60,000 PPS across 100 IPs (600 each, under per-IP limit) → global limiter drops above 50,000
- `test_ddos_detector_spike` — feed 100 PPS for 60s, then 1,000 PPS for 10s → `is_ddos_active()` returns true; `limit_multiplier()` returns 0.5
- `test_ddos_detector_auto_clear` — after spike, feed 150 PPS for 30s → `is_ddos_active()` returns false
- `test_ddos_detector_no_false_positive` — gradual increase from 100 to 500 PPS over 60s → `is_ddos_active()` returns false
- `test_geoip_blocker` — load test MaxMindDB, block "XX", check `is_blocked` for IP mapped to "XX" returns true, "YY" returns false
- `test_geoip_no_database` — with `db_path = None`, `is_blocked` always returns false (graceful degradation)
- `test_blacklist_sync` — mock HTTP server returns 3 IPs, `sync()` fetches, `is_blocked` returns true for those IPs
- `test_blacklist_cache_load` — load cached file on startup before first sync

### Integration tests
- `test_10000_pps_single_ip_blocked` — 10,000 PPS from one IP with default config (1,000 PPS limit) → only 1,100 accepted (1,000 + 100 burst)
- `test_global_limit_triggers` — send 60,000 PPS across 100 IPs → global limiter drops above 50,000
- `test_ddos_detection_activates` — simulate traffic spike → enhanced mode activates, per-IP limits halved
- `test_ddos_detection_clears` — after spike subsides → enhanced mode clears, limits restored
- `test_retry_token_on_ddos` — when DDoS mode active, new connections require retry token
- `test_geoip_blocks_country` — connection from blocked country IP is rejected
- `test_blacklist_blocks_ip` — connection from blacklisted IP is rejected
- `test_legitimate_user_not_blocked` — normal traffic patterns are not blocked by DDoS protection
- `test_all_features_disabled` — with `enabled = false`, all DDoS protection is bypassed

## Files to Create/Modify

| File | Action | Description |
|------|--------|-------------|
| `Cargo.toml` | Modify | Add `maxminddb = { version = "0.28", features = ["mmap"] }` |
| `src/implementations/server/limits.rs:18-26, 75-134` | Modify | Lower default PPS to 1,000; add `burst_size` to `RateLimitConfig`; modify `TokenBucket` for burst/capacity separation; add `GlobalRateLimiter` |
| `src/implementations/server/ddos_detector.rs` | Create | `DdosDetector` with EWMA, spike detection, enhanced mode, auto-clear |
| `src/implementations/server/geoip.rs` | Create | `GeoIpBlocker` with MaxMindDB lookup, country blocking |
| `src/implementations/server/blacklist.rs` | Create | `BlacklistSync` with HTTP fetch, local cache, background task |
| `src/implementations/server/mod.rs` | Modify | Wire all components into packet acceptance path; spawn background tasks |
| `src/qftls.rs` | Modify | Enable/disable QUIC retry tokens based on DDoS mode |
| `src/engine/config.rs` | Modify | Add `DdosProtectionConfig` struct and env var parsing |
| `config/server-linux.default.toml` | Modify | Add `[ddos_protection]` section |
| `tests/ddos_protection_test.rs` | Create | Integration tests for all DDoS protection features |

## Risks & Mitigations

| Risk | Severity | Mitigation |
|------|----------|------------|
| False positive: legitimate users blocked during high traffic | High | Burst size allows initial burst; EWMA detection avoids sudden triggers; global limit is generous; auto-clear restores limits |
| MaxMindDB database not present | Medium | Graceful degradation: `is_blocked` returns false when no database loaded; log warning |
| Blacklist sync fails (network error) | Low | Retry with backoff; use cached local copy; log warning but don't block traffic |
| QUIC retry tokens add latency for all clients | Medium | Only enabled during active DDoS; auto-disabled when spike clears; document trade-off |
| Blacklist HashSet memory growth | Medium | Configurable max size; LRU eviction when exceeded; default 1M IPs (~50MB) |
| EWMA parameters misconfigured | Low | Sensible defaults (spike_multiplier=5.0, duration=10s); configurable; document tuning guide |
| GeoIP database outdated | Low | Document update schedule (MaxMind updates GeoLite2 monthly); log database age on load |
| DDoS detector background task panics | Low | `tokio::spawn` with error logging; task is non-critical (server continues without detection) |

## Completion Criteria

- [ ] Default per-IP PPS is 1,000 (down from 10,000)
- [ ] `RateLimitConfig` has a `burst_size` field (default 100); `TokenBucket` separates burst capacity from refill rate
- [ ] `GlobalRateLimiter` caps server-wide PPS (default 50,000)
- [ ] `DdosDetector` triggers enhanced mode when PPS > 5× EWMA for 10s; auto-clears when PPS < 2× EWMA for 30s
- [ ] Enhanced mode halves per-IP limits and enables QUIC retry tokens
- [ ] `GeoIpBlocker` blocks configured countries using a MaxMindDB database
- [ ] `GeoIpBlocker` gracefully degrades when no database is present
- [ ] `BlacklistSync` fetches an external blacklist hourly and caches locally; blocks blacklisted IPs
- [ ] All features are configurable via `DdosProtectionConfig` and env vars; all can be disabled
- [ ] Test: 10,000 PPS from one IP is blocked (only 1,100 accepted)
- [ ] Test: global limit triggers at server level
- [ ] Test: GeoIP blocks configured countries
- [ ] Test: blacklist sync fetches and applies
- [ ] Test: DDoS detection activates and clears correctly
- [ ] Test: burst size allows initial burst then enforces steady rate
- [ ] Test: legitimate users are not blocked during normal traffic
- [ ] `cargo test` passes with all new tests green
- [ ] `cargo clippy` reports no new warnings
