---
id: TODO-459
title: "DDoS protection hardening (rate limits, burst, GeoIP, blacklist sync, challenge-response)"
severity: HIGH
phase: "I"
priority: P1
status: OPEN
created: 2026-06-30
depends_on: []
---

# TODO-459: DDoS protection hardening

## Problem

The current DDoS protection is insufficient for a production server
exposed to the public internet. The default rate limit is 10,000 PPS
per IP (`src/implementations/server/limits.rs:21`), which is far too
high to mitigate a DDoS attack. There is no burst size control, no
global (server-wide) rate limit, no DDoS detection/anomaly detection,
no GeoIP blocking, no external blacklist synchronization, and no
challenge-response mechanism for suspicious traffic.

### Evidence

1. `RateLimitConfig::default` (`limits.rs:18-26`):
   ```rust
   Self {
       max_pps: 10_000,
       max_bps: 0, // Unlimited
       refill_interval: Duration::from_secs(1),
   }
   ```
   10,000 PPS per IP means a single botnet of 1,000 IPs can send 10
   million PPS to the server — enough to saturate a 10 Gbps link.

2. `TokenBucket` (`limits.rs`, used by `RateLimiter`) has no burst
   limit. The bucket starts full at `max_pps` tokens, so the first
   second after a new IP appears, it can send all 10,000 packets
   instantly (a burst). There is no separate `burst_size` config.

3. `RateLimiter` (`limits.rs:137-227`) only limits per-session and
   per-IP. There is no global rate limiter that caps total server-wide
   PPS regardless of source IP. An attacker with many IPs can exhaust
   the server's CPU/bandwidth even if each IP is under the per-IP
   limit.

4. No anomaly detection: there is no code that tracks the rolling
   average PPS and triggers enhanced limiting when a spike is
   detected. The server reacts the same way at 100 PPS and 100,000
   PPS.

5. No GeoIP blocking: there is no `maxminddb` dependency, no GeoIP
   database loading, and no country-based filtering. An operator
   cannot block traffic from specific countries.

6. No external blacklist sync: there is no code that fetches
   AbuseIPDB, Spamhaus, or any other threat-intelligence feed. The
   server has no way to preemptively block known malicious IPs.

7. No challenge-response: when a rate limit is exceeded, the server
   simply drops packets (`check_packet_key` returns `false`). There
   is no QUIC retry token mechanism to force the client to prove
   reachability (anti-spoofing) before accepting new connections under
   load.

## Goal

- Default per-IP PPS lowered from 10,000 to **1,000**.
- Per-IP **burst size** config (token bucket starts at `burst_size`
  tokens, refills at `max_pps` rate; default burst = 100).
- **Global rate limit**: server-wide PPS cap (default 50,000),
  configurable via `global_rate_limit_pps`.
- **DDoS detection**: rolling average PPS tracked; if PPS exceeds 5×
  the average for 10 seconds, trigger enhanced limiting (halve all
  per-IP limits, enable QUIC retry tokens).
- **GeoIP blocking**: load a MaxMindDB GeoIP2 database, block
  configurable countries (`geoip_blocked_countries`).
- **External blacklist sync**: fetch an AbuseIPDB-style blacklist
  hourly, cache locally, reject connections from blacklisted IPs.
- **Challenge-response**: when rate limit is exceeded or DDoS
  detection is active, require a QUIC retry token before accepting new
  connections (anti-spoofing, forces client to prove reachability).
- All features are configurable and can be disabled.
- Tests prove: 10,000 PPS from a single IP is blocked, global limit
  triggers at the server level, GeoIP blocks configured countries,
  blacklist sync fetches and applies.

## Implementation Plan

### Step 1: Lower default PPS and add burst size config

**File:** `src/implementations/server/limits.rs`

- Change `RateLimitConfig::default` (line 18-26):
  ```rust
  Self {
      max_pps: 1_000,
      max_bps: 0,
      burst_size: 100,
      refill_interval: Duration::from_secs(1),
  }
  ```
- Add `burst_size: u64` field to `RateLimitConfig`.
- Modify `TokenBucket::new` to accept an initial `capacity` (burst)
  separate from the refill rate:
  ```rust
  pub struct TokenBucket {
      tokens: f64,
      capacity: f64,   // burst size (max tokens)
      refill_rate: f64, // tokens per second
      last_refill: Instant,
  }
  ```
  The bucket refills at `refill_rate` but can hold at most `capacity`
  tokens. This decouples burst from steady-state rate.

### Step 2: Add global rate limiter

**File:** `src/implementations/server/limits.rs`

- Add a `GlobalRateLimiter` struct:
  ```rust
  pub struct GlobalRateLimiter {
      bucket: parking_lot::Mutex<TokenBucket>,
  }
  impl GlobalRateLimiter {
      pub fn new(max_pps: u64) -> Self { ... }
      pub fn check(&self) -> bool { ... }
  }
  ```
- Add `global_rate_limiter: GlobalRateLimiter` to the server state.
- In the packet acceptance path (before per-IP/per-session checks),
  call `global_rate_limiter.check()`. If false, drop the packet and
  increment a `global_rate_limit_hit` counter.

### Step 3: Add DDoS detection (traffic spike)

**File:** `src/implementations/server/limits.rs` (or a new
`src/implementations/server/ddos_detector.rs`)

- Add a `DdosDetector` struct:
  ```rust
  pub struct DdosDetector {
      /// Rolling PPS samples (one per second, ring buffer of 60).
      samples: parking_lot::Mutex<VecDeque<u64>>,
      /// Whether enhanced limiting is currently active.
      enhanced: parking_lot::atomic::AtomicBool,
      /// Timestamp when enhanced mode was activated.
      activated_at: parking_lot::Mutex<Option<Instant>>,
  }
  impl DdosDetector {
      pub fn record_pps(&self, pps: u64) { ... }
      /// Returns true if PPS > 5× rolling average for 10s.
      pub fn is_ddos_active(&self) -> bool { ... }
      /// Returns the multiplier to apply to per-IP limits (0.5 when
      /// active, 1.0 otherwise).
      pub fn limit_multiplier(&self) -> f64 { ... }
  }
  ```
- A background task (or the existing idle-prune loop) calls
  `record_pps(current_pps)` every second. `current_pps` is obtained
  from the instrumentation counters (packets received in the last
  second).
- When `is_ddos_active()` returns true, the server:
  1. Sets `enhanced = true`.
  2. Halves effective per-IP limits (multiplies `max_pps` by 0.5).
  3. Enables QUIC retry tokens (Step 6).
  4. Logs a warning and increments `ddos_detected_total`.
- Enhanced mode auto-clears when PPS drops below 2× average for 30s.

### Step 4: Add GeoIP blocking

**File:** `Cargo.toml`, `src/implementations/server/geoip.rs` (new)

- Add `maxminddb = "0.2"` to `Cargo.toml`.
- Create `src/implementations/server/geoip.rs`:
  ```rust
  pub struct GeoIpBlocker {
      reader: Option<maxminddb::Reader<Vec<u8>>>,
      blocked_countries: HashSet<String>,
  }
  impl GeoIpBlocker {
      pub fn new(db_path: Option<&Path>, blocked: HashSet<String>) -> Self { ... }
      pub fn is_blocked(&self, ip: IpAddr) -> bool {
          // Lookup country for ip; return true if in blocked set.
      }
  }
  ```
- Add `geoip_blocker: GeoIpBlocker` to the server state.
- In the connection acceptance path, call
  `geoip_blocker.is_blocked(remote_addr.ip())`. If true, reject the
  connection and increment `geoip_blocked_total`.
- Config: `geoip_db_path` (path to MaxMindDB file),
  `geoip_blocked_countries` (comma-separated ISO country codes, e.g.
  `"CN,RU,KP"`).

### Step 5: Add external blacklist sync

**File:** `src/implementations/server/blacklist.rs` (new)

- Create a `BlacklistSync` struct:
  ```rust
  pub struct BlacklistSync {
      blocked_ips: parking_lot::RwLock<HashSet<IpAddr>>,
      sync_url: Option<String>,
      sync_interval: Duration,
      last_sync: parking_lot::Mutex<Option<Instant>>,
  }
  impl BlacklistSync {
      pub fn new(url: Option<String>, interval: Duration) -> Self { ... }
      pub fn is_blocked(&self, ip: IpAddr) -> bool { ... }
      /// Fetch the blacklist from `sync_url`, parse IPs, update the
      /// set. Runs in a background tokio task.
      pub async fn sync(&self) -> Result<(), BlacklistError> { ... }
  }
  ```
- The blacklist format is one IP per line (plain text, compatible with
  AbuseIPDB's CSV export filtered to the `ipAddress` column, or a
  simple IP list).
- A background `tokio::spawn` task calls `sync()` every
  `blacklist_sync_interval_secs` (default 3600s = 1 hour).
- On startup, load a cached local copy
  (`/var/lib/quicfuscate/blacklist.cache`) so the server has a
  blacklist before the first sync completes.
- In the connection acceptance path, call
  `blacklist.is_blocked(remote_addr.ip())`. If true, reject and
  increment `blacklist_blocked_total`.
- Config: `blacklist_sync_url`, `blacklist_sync_interval_secs`,
  `blacklist_cache_path`.

### Step 6: Add QUIC retry token challenge-response

**File:** `src/implementations/server/mod.rs`, `src/qftls.rs`

- Enable QUIC retry tokens (anti-spoofing) when DDoS detection is
  active or per-IP rate limit is exceeded:
  - In the QUIC server config, enable `use_retry(true)` when enhanced
    mode is active. This forces the client to do a retry round trip
    (server sends a retry token, client must echo it in a new Initial
    packet), proving the client's source IP is reachable and not
    spoofed.
  - When DDoS mode clears, disable retry (`use_retry(false)`) to
    avoid the latency overhead for legitimate clients.
- Alternatively, implement a custom challenge at the application
  layer: if a new connection's IP is near its rate limit, send a
  challenge nonce and require the client to echo it before processing
  any further packets. This avoids QUIC-level retry for all clients.

### Step 7: Add configuration

**File:** `src/engine/config.rs`

- Add a `DdosProtectionConfig` struct:
  ```rust
  pub struct DdosProtectionConfig {
      pub enabled: bool,
      pub global_rate_limit_pps: u64,
      pub per_ip_burst_size: u64,
      pub ddos_detection_enabled: bool,
      pub ddos_spike_multiplier: f64,    // default 5.0
      pub ddos_spike_duration_secs: u64, // default 10
      pub geoip_db_path: Option<PathBuf>,
      pub geoip_blocked_countries: Vec<String>,
      pub blacklist_sync_url: Option<String>,
      pub blacklist_sync_interval_secs: u64,
      pub blacklist_cache_path: PathBuf,
      pub retry_token_on_ddos: bool,
  }
  ```
- Defaults: `enabled = true`, `global_rate_limit_pps = 50_000`,
  `per_ip_burst_size = 100`, `ddos_detection_enabled = true`,
  `blacklist_sync_interval_secs = 3600`.
- All fields are overridable via env vars:
  `QUICFUSCATE_DDOS_PROTECTION_ENABLED`,
  `QUICFUSCATE_GLOBAL_RATE_LIMIT_PPS`,
  `QUICFUSCATE_GEOIP_BLOCKED_COUNTRIES`,
  `QUICFUSCATE_BLACKLIST_SYNC_URL`, etc.

### Step 8: Wire all components into the server

**File:** `src/implementations/server/mod.rs`

- Add fields to the server state: `global_rate_limiter`,
  `ddos_detector`, `geoip_blocker`, `blacklist_sync`.
- In the packet acceptance path (the function that receives a UDP
  datagram and decides whether to process it):
  1. `global_rate_limiter.check()` → if false, drop.
  2. `geoip_blocker.is_blocked(src_ip)` → if true, drop.
  3. `blacklist_sync.is_blocked(src_ip)` → if true, drop.
  4. `ddos_detector.is_ddos_active()` → if true, apply
     `limit_multiplier()` to per-IP checks and enable retry tokens.
  5. Existing `rate_limiter.check_packet_ip(src_ip)` with adjusted
     limit.
- Spawn the blacklist sync background task on server start.
- Spawn the DDoS detector sampling task (records PPS every second).

### Step 9: Tests

**File:** `tests/ddos_protection_test.rs` (new),
`src/implementations/server/limits.rs` (inline tests),
`src/implementations/server/ddos_detector.rs` (inline tests)

- Test: 10,000 PPS from a single IP with default config (1,000 PPS
  limit) → only 1,000 + 100 burst are accepted; rest are dropped.
- Test: global rate limit — send 60,000 PPS across 100 IPs (600 PPS
  each, under per-IP limit) → global limiter drops packets above
  50,000 PPS server-wide.
- Test: DDoS detection — feed `DdosDetector` samples: 100 PPS average
  for 60s, then 1,000 PPS for 10s → `is_ddos_active()` returns true;
  `limit_multiplier()` returns 0.5.
- Test: DDoS auto-clear — after spike, feed 150 PPS for 30s →
  `is_ddos_active()` returns false.
- Test: GeoIP blocking — load a test MaxMindDB, block country "XX",
  check `is_blocked` for an IP mapped to "XX" returns true, for "YY"
  returns false.
- Test: blacklist sync — mock HTTP server returns a list of 3 IPs,
  `sync()` fetches and `is_blocked` returns true for those IPs.
- Test: retry token — when DDoS mode is active, new connections
  require a retry token (verify via QUIC handshake inspection or
  connection rejection).
- Test: burst size — new IP can send `burst_size` packets instantly,
  then is limited to `max_pps` steady-state.

## Files to Modify/Create

- `Cargo.toml` — add `maxminddb` dep
- `src/implementations/server/limits.rs` — lower default PPS, add
  `burst_size` to `RateLimitConfig`, add `GlobalRateLimiter`, modify
  `TokenBucket` for burst/capacity separation
- `src/implementations/server/ddos_detector.rs` — **new**:
  `DdosDetector` with rolling average, spike detection, enhanced mode
- `src/implementations/server/geoip.rs` — **new**: `GeoIpBlocker` with
  MaxMindDB lookup
- `src/implementations/server/blacklist.rs` — **new**: `BlacklistSync`
  with HTTP fetch, local cache, background task
- `src/implementations/server/mod.rs` — wire all components into the
  packet acceptance path; spawn background tasks
- `src/qftls.rs` — enable/disable QUIC retry tokens based on DDoS mode
- `src/engine/config.rs` — add `DdosProtectionConfig` struct and env
  var parsing
- `tests/ddos_protection_test.rs` — **new**: integration tests for
  all DDoS protection features

## Acceptance Criteria

- [ ] Default per-IP PPS is 1,000 (down from 10,000).
- [ ] `RateLimitConfig` has a `burst_size` field (default 100);
      `TokenBucket` separates burst capacity from refill rate.
- [ ] `GlobalRateLimiter` caps server-wide PPS (default 50,000).
- [ ] `DdosDetector` triggers enhanced mode when PPS > 5× average for
      10s; auto-clears when PPS < 2× average for 30s.
- [ ] Enhanced mode halves per-IP limits and enables QUIC retry
      tokens.
- [ ] `GeoIpBlocker` blocks configured countries using a MaxMindDB
      database.
- [ ] `BlacklistSync` fetches an external blacklist hourly and caches
      locally; blocks blacklisted IPs.
- [ ] All features are configurable via `DdosProtectionConfig` and env
      vars; all can be disabled.
- [ ] Test: 10,000 PPS from one IP is blocked (only 1,100 accepted).
- [ ] Test: global limit triggers at server level.
- [ ] Test: GeoIP blocks configured countries.
- [ ] Test: blacklist sync fetches and applies.
- [ ] Test: DDoS detection activates and clears correctly.
- [ ] Test: burst size allows initial burst then enforces steady
      rate.
- [ ] `cargo test` passes with all new tests green.
- [ ] `cargo clippy` reports no new warnings.

## Resource Budget

| Scenario | Budget | Notes |
|----------|--------|-------|
| `GlobalRateLimiter::check` per packet | < 100 ns | Single token bucket under `Mutex`; no HashMap |
| `GeoIpBlocker::is_blocked` per connection | < 5 µs | MaxMindDB lookup (mmap'd, O(log n)) |
| `BlacklistSync::is_blocked` per connection | < 100 ns | `HashSet<IpAddr>` lookup under `RwLock` read |
| `DdosDetector::record_pps` per second | < 200 ns | `VecDeque::push_back` under `Mutex` |
| `DdosDetector::is_ddos_active` per packet | < 50 ns | `AtomicBool::load` |
| Blacklist sync HTTP fetch | ~100 ms | One per hour; background task |
| MaxMindDB file (GeoLite2-Country) | ~6 MB | mmap'd; not loaded into heap |
| Blacklist cache file | ~1-10 MB | Depends on feed size |
| Memory for `DdosDetector` | ~500 bytes | 60 × `u64` ring buffer |
| Memory for blacklist `HashSet` | ~50 MB | 1M IPs × ~50 bytes/entry |
