---
id: TODO-456
title: "Auth-specific rate limiting for QKey brute-force protection"
severity: HIGH
phase: "H"
priority: P1
status: OPEN
created: 2026-06-30
depends_on: []
---

# TODO-456: Auth-specific rate limiting for QKey brute-force protection

## Problem

The server has a general `PacketRateLimiter`
(`src/implementations/server/limits.rs:137-227`) and a
`ConnectionLimiter` per IP (`limits.rs:230-265`, default
`DEFAULT_MAX_CONNECTIONS_PER_IP`), but there is **no rate limiting on
authentication attempts**. QKey authentication happens in
`src/implementations/server/mod.rs` around line 1699
(`close_live_client_for_qkey_auth_failure`) and in
`src/implementations/server/qkey_registry.rs`
(`token_matches_hash`, `validate_token` at line 150).

### Evidence

1. `RateLimiter::check_packet_ip` (`limits.rs:165-167`) only throttles
   raw packet rate per IP — it has no concept of "auth attempt" and no
   exponential backoff.
2. `ConnectionLimiter::check` (`limits.rs:242-244`) caps concurrent
   connections per IP but does not limit repeated auth handshakes on a
   single connection or rapid reconnections after auth failure.
3. The QKey auth check path (`mod.rs:1691-1696`) calls
   `token_matches_hash(provided, expected.trim())` and returns either
   `QKeyHeaderAuthOutcome::Authenticated` or
   `QKeyHeaderAuthOutcome::Reject`. On reject,
   `close_live_client_for_qkey_auth_failure` (`mod.rs:1699-1709`)
   closes the QUIC connection with reason `b"invalid_qkey_auth"` — but
   nothing prevents the same IP from immediately reconnecting and
   retrying with a different token.
4. `QKeyRegistry::insert_with_ttl` (`qkey_registry.rs:154-179`) stores
   `token_sha256` (a SHA-256 hash of the token). SHA-256 of a short
   QKey token is brute-forceable offline, but online brute-force is
   also wide open because each attempt costs the attacker only a single
   QUIC handshake.

An attacker can brute-force QKey tokens without any throttling: send
thousands of auth attempts per second from a single IP (or a botnet
across IPs), each trying a different candidate token. With no
exponential backoff and no IP blocking, the only cost is bandwidth.

## Goal

- Per-IP auth rate limiting: max N auth attempts per minute (default
  10), configurable via `QUICFUSCATE_AUTH_RATE_LIMIT_PER_MIN` env var.
- Exponential backoff on repeated failures: 1s, 2s, 4s, 8s, 16s, 32s,
  60s cap.
- Auth failure tracking: `HashMap<IpAddr, AuthFailureTracker>` with
  consecutive failure count, last failure timestamp, and current
  backoff duration.
- Automatic IP blocking after N consecutive failures (default 5):
  blocked IPs are rejected at the connection-accept stage before any
  QKey processing.
- All state is bounded and pruned (idle entries expire after a
  configurable window, default 15 minutes).
- Tests prove that 100 rapid auth attempts from the same IP result in
  only the first 10 succeeding, the rest being rate-limited, and the IP
  being blocked after 5 consecutive failures.

## Implementation Plan

### Step 1: Define `AuthFailureTracker` and `AuthRateLimiter` structs

**File:** `src/implementations/server/limits.rs`

- Add a new struct after `ConnectionLimiter` (line 265):
  ```rust
  /// Tracks authentication failures for a single IP address.
  #[derive(Clone, Debug)]
  pub struct AuthFailureTracker {
      /// Consecutive auth failure count.
      pub consecutive_failures: u32,
      /// Timestamp of the last auth attempt (success or failure).
      pub last_attempt: Instant,
      /// Current backoff duration applied after the latest failure.
      pub current_backoff: Duration,
      /// Whether this IP is currently blocked.
      pub blocked: bool,
      /// Timestamp when the block expires (if blocked).
      pub blocked_until: Option<Instant>,
  }

  impl AuthFailureTracker {
      pub fn new() -> Self { ... }

      /// Backoff schedule: 1s, 2s, 4s, 8s, 16s, 32s, 60s cap.
      pub fn next_backoff(&self) -> Duration {
          let secs = 1u64 << self.consecutive_failures.min(6);
          Duration::from_secs(secs.min(60))
      }

      /// Record a failure: increment count, set backoff, block if
      /// threshold reached.
      pub fn record_failure(&mut self, block_threshold: u32) { ... }

      /// Record a success: reset consecutive count and backoff.
      pub fn record_success(&mut self) { ... }

      /// Returns true if this IP is currently blocked (block window
      /// not yet expired).
      pub fn is_blocked(&self, now: Instant) -> bool { ... }
  }

  /// Rate limiter for authentication attempts, keyed by IP.
  pub struct AuthRateLimiter {
      config: AuthRateLimitConfig,
      failures: parking_lot::Mutex<HashMap<IpAddr, AuthFailureTracker>>,
  }

  #[derive(Clone, Debug)]
  pub struct AuthRateLimitConfig {
      /// Max auth attempts per minute per IP.
      pub max_attempts_per_min: u32,
      /// Consecutive failures before IP is blocked.
      pub block_threshold: u32,
      /// How long a block lasts before the IP may retry.
      pub block_duration: Duration,
      /// Idle window after which a tracker entry is pruned.
      pub idle_prune_window: Duration,
  }

  impl Default for AuthRateLimitConfig {
      fn default() -> Self {
          Self {
              max_attempts_per_min: 10,
              block_threshold: 5,
              block_duration: Duration::from_secs(60),
              idle_prune_window: Duration::from_secs(900),
          }
      }
  }
  ```

### Step 2: Implement `AuthRateLimiter` methods

**File:** `src/implementations/server/limits.rs`

- `AuthRateLimiter::new(config: AuthRateLimitConfig) -> Self`
- `AuthRateLimiter::check_attempt(&self, ip: IpAddr) -> AuthCheckResult`
  - Returns `AuthCheckResult::Allowed`, `AuthCheckResult::RateLimited`,
    or `AuthCheckResult::Blocked`.
  - On `Allowed`: the caller proceeds with the auth check and must call
    `record_result` afterward.
  - On `RateLimited`: the attempt count for the current minute window
    has been exceeded; reject without touching the failure tracker.
  - On `Blocked`: the IP is in a block window; reject immediately.
- `AuthRateLimiter::record_result(&self, ip: IpAddr, success: bool)`
  - On success: `AuthFailureTracker::record_success`.
  - On failure: `AuthFailureTracker::record_failure(block_threshold)`.
    If `consecutive_failures >= block_threshold`, set `blocked = true`
    and `blocked_until = now + block_duration`.
- `AuthRateLimiter::prune_idle(&self)` — remove entries whose
  `last_attempt` is older than `idle_prune_window`.
- Use a sliding 1-minute window for the per-minute attempt count:
  store a `Vec<Instant>` of recent attempt timestamps in the tracker
  (or a small ring buffer) and count entries within the last 60s.

### Step 3: Parse env var configuration

**File:** `src/implementations/server/limits.rs`

- Add a `from_env` constructor or a `parse_auth_rate_limit_env`
  function (mirroring the existing `parse_rate_limit_env_u64` at line
  28):
  ```rust
  #[cfg(feature = "rate_limiter")]
  fn parse_auth_rate_limit_env() -> AuthRateLimitConfig {
      let mut cfg = AuthRateLimitConfig::default();
      if let Ok(v) = std::env::var("QUICFUSCATE_AUTH_RATE_LIMIT_PER_MIN") {
          if let Ok(n) = v.parse::<u32>() {
              cfg.max_attempts_per_min = n;
          }
      }
      // Also parse QUICFUSCATE_AUTH_BLOCK_THRESHOLD,
      // QUICFUSCATE_AUTH_BLOCK_DURATION_SECS if present.
      cfg
  }
  ```

### Step 4: Wire `AuthRateLimiter` into the server

**File:** `src/implementations/server/mod.rs`

- Add an `auth_rate_limiter: AuthRateLimiter` field to the server
  state struct (the struct that holds `rate_limiter` and
  `connection_limiter`).
- Initialize it in the server constructor using
  `AuthRateLimitConfig::default()` or `parse_auth_rate_limit_env()`.
- In the QKey auth check path (around `mod.rs:1691-1696`, where
  `token_matches_hash` is called):
  1. Before calling `token_matches_hash`, call
     `auth_rate_limiter.check_attempt(remote_addr.ip())`.
  2. If `RateLimited`: close the connection with reason
     `b"auth_rate_limited"` and do **not** call `token_matches_hash`.
  3. If `Blocked`: close the connection with reason
     `b"auth_blocked"` and do **not** call `token_matches_hash`.
  4. If `Allowed`: proceed with the existing auth check. After
     `token_matches_hash` returns, call
     `auth_rate_limiter.record_result(remote_addr.ip(), success)`.
- In `close_live_client_for_qkey_auth_failure` (`mod.rs:1699-1709`),
  ensure `record_result(ip, false)` is called before closing the
  connection (or rely on the caller to do so — pick one location and
  document it).
- Add a periodic `auth_rate_limiter.prune_idle()` call alongside the
  existing `rate_limiter.prune_idle()` call in the server's idle
  cleanup loop.

### Step 5: Add instrumentation

**File:** `src/instrumentation/mod.rs` (or wherever `rate_limit_hit`
is defined)

- Add counters: `auth_rate_limited_total`,
  `auth_blocked_total`, `auth_failures_total`.
- Increment them in the `RateLimited` and `Blocked` branches of the
  auth check path.

### Step 6: Tests

**File:** `src/implementations/server/limits.rs` (inline `tests`
module), `tests/auth_rate_limit_test.rs` (new)

- Unit test (`limits.rs`): `AuthFailureTracker::next_backoff` returns
  1s, 2s, 4s, 8s, 16s, 32s, 60s, 60s for failure counts 0-7.
- Unit test: `record_failure` increments `consecutive_failures` and
  sets `blocked = true` when reaching `block_threshold`.
- Unit test: `record_success` resets `consecutive_failures` to 0 and
  `current_backoff` to 0.
- Unit test: `is_blocked` returns `false` after `block_duration`
  elapses.
- Unit test: `check_attempt` returns `Allowed` for the first
  `max_attempts_per_min` calls, then `RateLimited` for subsequent
  calls within the same minute.
- Integration test (`tests/auth_rate_limit_test.rs`): Simulate 100
  rapid auth attempts from the same IP. Verify:
  - First 10 attempts return `Allowed`.
  - Attempts 11-100 return `RateLimited`.
  - After 5 consecutive failures (interleaved with allowed attempts
    that then fail), the IP returns `Blocked`.
- Integration test: a different IP is unaffected by another IP's
  failures.
- Integration test: after `block_duration` elapses, the IP is
  unblocked and may attempt again (but with the backoff still
  applied).

## Files to Modify/Create

- `src/implementations/server/limits.rs` — add `AuthFailureTracker`,
  `AuthRateLimiter`, `AuthRateLimitConfig`, env var parsing, inline
  unit tests
- `src/implementations/server/mod.rs` — wire `AuthRateLimiter` into
  the QKey auth check path and the server state struct; add prune call
- `src/instrumentation/mod.rs` — add `auth_rate_limited_total`,
  `auth_blocked_total`, `auth_failures_total` counters
- `tests/auth_rate_limit_test.rs` — **new**: integration tests for
  rate limiting, backoff, and IP blocking

## Acceptance Criteria

- [ ] `AuthRateLimiter` struct exists in `limits.rs` with
      `check_attempt`, `record_result`, and `prune_idle` methods.
- [ ] `AuthFailureTracker` implements exponential backoff (1s, 2s, 4s,
      8s, 16s, 32s, 60s cap).
- [ ] Default config: 10 attempts/min, block after 5 consecutive
      failures, 60s block duration, 15min idle prune.
- [ ] `QUICFUSCATE_AUTH_RATE_LIMIT_PER_MIN` env var overrides the
      per-minute attempt limit.
- [ ] QKey auth check path in `mod.rs` calls `check_attempt` before
      `token_matches_hash` and `record_result` after.
- [ ] Rate-limited and blocked connections are closed with distinct
      reasons (`b"auth_rate_limited"`, `b"auth_blocked"`).
- [ ] Idle tracker entries are pruned periodically.
- [ ] Instrumentation counters increment on rate-limit and block
      events.
- [ ] Test: 100 rapid auth attempts from one IP → first 10 allowed,
      rest rate-limited, IP blocked after 5 consecutive failures.
- [ ] Test: a second IP is unaffected by the first IP's failures.
- [ ] Test: IP is unblocked after `block_duration` elapses.
- [ ] `cargo test` passes with all new tests green.
- [ ] `cargo clippy` reports no new warnings.

## Resource Budget

| Scenario | Budget | Notes |
|----------|--------|-------|
| `check_attempt` per auth | < 500 ns | HashMap lookup + sliding window count under `parking_lot::Mutex` |
| `record_result` per auth | < 500 ns | HashMap entry update + backoff computation |
| `prune_idle` per cycle | < 50 µs | `HashMap::retain` over ~1000 entries; runs every 60s |
| Memory per tracked IP | ~80 bytes | `AuthFailureTracker` + `Vec<Instant>` ring buffer (10 slots) |
| Max tracked IPs | bounded by `idle_prune_window` | Untracked IPs pay zero cost |
