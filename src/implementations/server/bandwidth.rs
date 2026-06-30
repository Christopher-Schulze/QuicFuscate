//! Per-client bandwidth limits and quotas.
//!
//! This module provides byte-oriented (not packet-oriented) rate limiting and
//! quota tracking on a per-client basis. It complements `limits.rs`, which
//! caps packet/byte rates globally and per-IP; here the granularity is the
//! individual authenticated client (identified by a string client ID), and the
//! unit is bytes per second with an optional total-transfer quota per billing
//! period.
//!
//! # Components
//!
//! - [`BandwidthLimiter`]: a token bucket refilled at `refill_rate_bps` bytes
//!   per second, capped at `capacity_bytes` (burst). `check` consumes tokens.
//! - [`QuotaTracker`]: tracks cumulative bytes transferred against a
//!   `quota_limit_bytes` budget that resets every `reset_interval`.
//! - [`PerClientBandwidthManager`]: maps a client ID to its limiter + quota,
//!   applying default limits to previously-unseen clients and allowing
//!   per-client overrides.

use std::collections::HashMap;
use std::time::{Duration, Instant};

// ---------------------------------------------------------------------------
// BandwidthLimiter — per-client token bucket for bytes/sec.
//
// Mirrors the `TokenBucket` in `limits.rs` but is byte-oriented and exposes a
// public API. The bucket starts full at `capacity_bytes`, allowing an initial
// burst, then refills continuously at `refill_rate_bps` up to the capacity.
// ---------------------------------------------------------------------------

/// Per-client byte-rate token bucket.
///
/// `capacity_bytes` is the burst size (the bucket starts full); `refill_rate_bps`
/// is the sustained refill rate in bytes per second. `check` consumes tokens and
/// returns `false` when insufficient tokens are available.
pub struct BandwidthLimiter {
    /// Burst capacity (max tokens the bucket can hold).
    capacity_bytes: u64,
    /// Sustained refill rate in bytes per second.
    refill_rate_bps: u64,
    /// Current token count.
    tokens: u64,
    /// Monotonic timestamp of the last refill.
    last_refill: Instant,
}

impl BandwidthLimiter {
    /// Create a new limiter.
    ///
    /// `rate_bps` is the sustained bytes-per-second rate; `burst_bytes` is the
    /// burst capacity (the bucket starts full). A `rate_bps` or `burst_bytes` of
    /// `0` disables the limiter (all sends are allowed).
    pub fn new(rate_bps: u64, burst_bytes: u64) -> Self {
        Self {
            capacity_bytes: burst_bytes,
            refill_rate_bps: rate_bps,
            tokens: burst_bytes,
            last_refill: Instant::now(),
        }
    }

    /// Whether this limiter is disabled (rate or burst is zero).
    ///
    /// A disabled limiter permits all traffic without consuming tokens.
    #[inline]
    pub fn is_disabled(&self) -> bool {
        self.refill_rate_bps == 0 || self.capacity_bytes == 0
    }

    /// Check whether `bytes` can be sent, decrementing tokens if so.
    ///
    /// Refills the bucket based on elapsed time before checking. Returns `true`
    /// if the send is allowed (and tokens are consumed), `false` otherwise.
    /// A disabled limiter always returns `true` without consuming tokens.
    pub fn check(&mut self, bytes: usize) -> bool {
        if self.is_disabled() {
            return true;
        }

        self.refill();

        if self.tokens >= bytes as u64 {
            self.tokens -= bytes as u64;
            true
        } else {
            false
        }
    }

    /// Add tokens based on elapsed time, capped at capacity.
    ///
    /// Computes the refill as `refill_rate_bps × elapsed_seconds` using u128
    /// arithmetic to avoid overflow for large idle gaps, then saturates at
    /// `capacity_bytes`.
    pub fn refill(&mut self) {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_refill);

        if elapsed.is_zero() {
            return;
        }

        // refill = rate_bps × elapsed_ns / 1e9, computed in u128 to avoid overflow.
        let refill =
            (self.refill_rate_bps as u128).saturating_mul(elapsed.as_nanos()) / 1_000_000_000;

        let refill = if refill > u64::MAX as u128 { u64::MAX } else { refill as u64 };

        self.tokens = self.tokens.saturating_add(refill).min(self.capacity_bytes);
        self.last_refill = now;
    }

    /// Configured burst capacity (bytes).
    pub fn capacity_bytes(&self) -> u64 {
        self.capacity_bytes
    }

    /// Configured sustained refill rate (bytes per second).
    pub fn refill_rate_bps(&self) -> u64 {
        self.refill_rate_bps
    }

    /// Current available tokens (best-effort snapshot, for metrics/tests).
    pub fn available_tokens(&self) -> u64 {
        self.tokens
    }
}

// ---------------------------------------------------------------------------
// QuotaTracker — cumulative byte budget per billing period.
//
// Tracks total bytes transferred against a `quota_limit_bytes` budget that
// resets every `reset_interval`. `record` returns `false` when recording the
// bytes would exceed the quota (the bytes are NOT recorded in that case). A
// `quota_limit_bytes` of `0` means unlimited.
// ---------------------------------------------------------------------------

/// Cumulative transfer quota with periodic reset.
///
/// `quota_limit_bytes` is the total bytes allowed per `reset_interval`. A limit
/// of `0` disables the quota (unlimited). `record` accumulates bytes and
/// returns `false` if the addition would exceed the limit; `check_and_reset`
/// zeroes the counter when the interval has elapsed.
pub struct QuotaTracker {
    /// Total bytes allowed per billing period (0 = unlimited).
    quota_limit_bytes: u64,
    /// Bytes consumed in the current billing period.
    used_bytes: u64,
    /// Duration of a billing period.
    reset_interval: Duration,
    /// Start time of the current billing period.
    last_reset: Instant,
}

impl QuotaTracker {
    /// Create a new quota tracker.
    ///
    /// `quota_limit_bytes` of `0` means unlimited (no quota enforcement).
    pub fn new(quota_limit_bytes: u64, reset_interval: Duration) -> Self {
        Self { quota_limit_bytes, used_bytes: 0, reset_interval, last_reset: Instant::now() }
    }

    /// Whether this quota tracker is disabled (limit is zero).
    #[inline]
    pub fn is_disabled(&self) -> bool {
        self.quota_limit_bytes == 0
    }

    /// Record `bytes` against the quota.
    ///
    /// Returns `false` if recording the bytes would exceed the quota; in that
    /// case the bytes are **not** recorded. A disabled quota always returns
    /// `true` without accumulating.
    pub fn record(&mut self, bytes: u64) -> bool {
        if self.is_disabled() {
            return true;
        }

        match self.used_bytes.checked_add(bytes) {
            Some(total) if total <= self.quota_limit_bytes => {
                self.used_bytes = total;
                true
            }
            _ => false,
        }
    }

    /// Reset the used-bytes counter if the billing interval has elapsed.
    pub fn check_and_reset(&mut self) {
        if self.reset_interval.is_zero() {
            return;
        }

        let now = Instant::now();
        if now.duration_since(self.last_reset) >= self.reset_interval {
            self.used_bytes = 0;
            self.last_reset = now;
        }
    }

    /// Remaining bytes in the current billing period.
    ///
    /// Returns `u64::MAX` when the quota is disabled (unlimited).
    pub fn remaining(&self) -> u64 {
        if self.is_disabled() {
            u64::MAX
        } else {
            self.quota_limit_bytes.saturating_sub(self.used_bytes)
        }
    }

    /// Configured quota limit (bytes per billing period).
    pub fn quota_limit_bytes(&self) -> u64 {
        self.quota_limit_bytes
    }

    /// Bytes consumed in the current billing period.
    pub fn used_bytes(&self) -> u64 {
        self.used_bytes
    }
}

// ---------------------------------------------------------------------------
// PerClientBandwidthManager — client ID → limiter + quota.
//
// Holds default rate/burst/quota/interval settings and a per-client map. A
// previously-unseen client is lazily initialised with the defaults; explicit
// overrides can be applied via `set_client_limit` / `set_client_quota`.
// ---------------------------------------------------------------------------

/// Per-client bandwidth + quota state.
struct ClientBandwidthEntry {
    limiter: BandwidthLimiter,
    quota: QuotaTracker,
}

/// Snapshot of a client's bandwidth configuration and quota usage.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BandwidthStats {
    /// Sustained refill rate (bytes per second).
    pub rate_bps: u64,
    /// Burst capacity (bytes).
    pub burst_bytes: u64,
    /// Quota limit per billing period (bytes; 0 = unlimited).
    pub quota_limit_bytes: u64,
    /// Bytes consumed in the current billing period.
    pub quota_used_bytes: u64,
    /// Remaining bytes in the current billing period (`u64::MAX` if unlimited).
    pub quota_remaining_bytes: u64,
}

/// Per-client bandwidth limiter and quota tracker.
///
/// Maintains a map of client ID → [`BandwidthLimiter`] + [`QuotaTracker`].
/// Clients not yet seen are lazily initialised with the default settings
/// supplied at construction; per-client overrides are applied via
/// [`set_client_limit`](Self::set_client_limit) and
/// [`set_client_quota`](Self::set_client_quota).
pub struct PerClientBandwidthManager {
    clients: HashMap<String, ClientBandwidthEntry>,
    default_rate_bps: u64,
    default_burst_bytes: u64,
    default_quota_bytes: u64,
    default_reset_interval: Duration,
}

impl PerClientBandwidthManager {
    /// Create a new manager with the given default settings.
    ///
    /// Every previously-unseen client is initialised with these defaults when
    /// first checked via [`check_send`](Self::check_send).
    pub fn new(
        default_rate_bps: u64,
        default_burst_bytes: u64,
        default_quota: u64,
        reset_interval: Duration,
    ) -> Self {
        Self {
            clients: HashMap::new(),
            default_rate_bps,
            default_burst_bytes,
            default_quota_bytes: default_quota,
            default_reset_interval: reset_interval,
        }
    }

    /// Ensure a client entry exists, initialising it with the defaults if needed.
    fn entry_or_default(&mut self, client_id: &str) -> &mut ClientBandwidthEntry {
        self.clients.entry(client_id.to_string()).or_insert_with(|| ClientBandwidthEntry {
            limiter: BandwidthLimiter::new(self.default_rate_bps, self.default_burst_bytes),
            quota: QuotaTracker::new(self.default_quota_bytes, self.default_reset_interval),
        })
    }

    /// Override the rate limit (bytes/sec + burst) for a specific client.
    ///
    /// Replaces the client's [`BandwidthLimiter`] with a fresh bucket starting
    /// full at `burst_bytes`. If the client had no entry, one is created.
    pub fn set_client_limit(&mut self, client_id: &str, rate_bps: u64, burst_bytes: u64) {
        let entry = self.entry_or_default(client_id);
        entry.limiter = BandwidthLimiter::new(rate_bps, burst_bytes);
    }

    /// Override the quota limit for a specific client.
    ///
    /// Replaces the client's [`QuotaTracker`], resetting the used-bytes counter
    /// and the billing-period clock. If the client had no entry, one is created.
    pub fn set_client_quota(&mut self, client_id: &str, quota_bytes: u64) {
        let reset_interval = self.default_reset_interval;
        let entry = self.entry_or_default(client_id);
        entry.quota = QuotaTracker::new(quota_bytes, reset_interval);
    }

    /// Check whether `bytes` may be sent for `client_id`.
    ///
    /// Applies both the per-client rate limit (token bucket) and the per-client
    /// quota. The quota counter is only incremented when the rate-limit check
    /// passes **and** the quota check passes. Returns `true` only when both
    /// checks succeed.
    pub fn check_send(&mut self, client_id: &str, bytes: usize) -> bool {
        let entry = self.entry_or_default(client_id);

        // Reset the quota counter if the billing period has elapsed.
        entry.quota.check_and_reset();

        // Rate-limit first: if the token bucket rejects, do not touch the quota.
        if !entry.limiter.check(bytes) {
            return false;
        }

        // Quota second: only record on success so a rejected send does not
        // consume the client's byte budget.
        entry.quota.record(bytes as u64)
    }

    /// Snapshot of a client's bandwidth configuration and quota usage.
    ///
    /// Returns `None` if the client has no entry (never seen and no overrides
    /// applied).
    pub fn stats(&self, client_id: &str) -> Option<BandwidthStats> {
        let entry = self.clients.get(client_id)?;
        Some(BandwidthStats {
            rate_bps: entry.limiter.refill_rate_bps(),
            burst_bytes: entry.limiter.capacity_bytes(),
            quota_limit_bytes: entry.quota.quota_limit_bytes(),
            quota_used_bytes: entry.quota.used_bytes(),
            quota_remaining_bytes: entry.quota.remaining(),
        })
    }

    /// Remove a client's bandwidth/quota state (e.g. on session teardown).
    pub fn remove_client(&mut self, client_id: &str) {
        self.clients.remove(client_id);
    }

    /// Number of clients currently tracked.
    pub fn len(&self) -> usize {
        self.clients.len()
    }

    /// Whether no clients are currently tracked.
    pub fn is_empty(&self) -> bool {
        self.clients.is_empty()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // --- BandwidthLimiter --------------------------------------------------

    #[test]
    fn test_limiter_starts_full() {
        let mut limiter = BandwidthLimiter::new(1_000, 10_000);
        // Bucket starts full at capacity, so a send up to capacity is allowed.
        assert!(limiter.check(10_000));
        assert_eq!(limiter.available_tokens(), 0);
    }

    #[test]
    fn test_limiter_rejects_when_empty() {
        let mut limiter = BandwidthLimiter::new(1_000, 1_000);
        // Drain the bucket.
        assert!(limiter.check(1_000));
        // No tokens left and no time has elapsed → rejected.
        assert!(!limiter.check(1));
    }

    #[test]
    fn test_limiter_refill_logic() {
        let mut limiter = BandwidthLimiter::new(1_000, 1_000);
        // Drain completely.
        assert!(limiter.check(1_000));
        assert_eq!(limiter.available_tokens(), 0);

        // Simulate time passing by manually advancing the last_refill into the
        // past so that ~1 second of refill accrues.
        limiter.last_refill = Instant::now() - Duration::from_secs(1);
        limiter.refill();
        // After 1s at 1000 bps, 1000 tokens should be available (capped at
        // capacity).
        assert_eq!(limiter.available_tokens(), 1_000);
    }

    #[test]
    fn test_limiter_refill_capped_at_capacity() {
        let mut limiter = BandwidthLimiter::new(1_000, 500);
        // Drain.
        assert!(limiter.check(500));
        assert_eq!(limiter.available_tokens(), 0);

        // Simulate a very long idle period — refill must saturate at capacity.
        limiter.last_refill = Instant::now() - Duration::from_secs(60);
        limiter.refill();
        assert_eq!(limiter.available_tokens(), 500);
    }

    #[test]
    fn test_limiter_partial_refill_allows_partial_send() {
        let mut limiter = BandwidthLimiter::new(1_000, 1_000);
        // Drain.
        assert!(limiter.check(1_000));

        // 500ms of refill → 500 tokens.
        limiter.last_refill = Instant::now() - Duration::from_millis(500);
        limiter.refill();
        assert_eq!(limiter.available_tokens(), 500);

        // 500 bytes allowed, 501 rejected.
        assert!(limiter.check(500));
        assert!(!limiter.check(1));
    }

    #[test]
    fn test_limiter_disabled_allows_everything() {
        let mut limiter = BandwidthLimiter::new(0, 0);
        assert!(limiter.is_disabled());
        // A huge send is still allowed and consumes no tokens.
        assert!(limiter.check(u64::MAX as usize));
        assert_eq!(limiter.available_tokens(), 0);
    }

    // --- QuotaTracker ------------------------------------------------------

    #[test]
    fn test_quota_record_within_limit() {
        let mut quota = QuotaTracker::new(10_000, Duration::from_secs(3600));
        assert!(quota.record(4_000));
        assert_eq!(quota.used_bytes(), 4_000);
        assert!(quota.record(6_000));
        assert_eq!(quota.used_bytes(), 10_000);
        assert_eq!(quota.remaining(), 0);
    }

    #[test]
    fn test_quota_exceeded_rejected() {
        let mut quota = QuotaTracker::new(10_000, Duration::from_secs(3600));
        assert!(quota.record(9_000));
        // 2000 more would exceed 10_000 → rejected, and not recorded.
        assert!(!quota.record(2_000));
        assert_eq!(quota.used_bytes(), 9_000);
        assert_eq!(quota.remaining(), 1_000);
    }

    #[test]
    fn test_quota_reset_after_interval() {
        let mut quota = QuotaTracker::new(10_000, Duration::from_millis(50));
        assert!(quota.record(10_000));
        assert_eq!(quota.remaining(), 0);

        // Interval not yet elapsed → no reset.
        quota.check_and_reset();
        assert_eq!(quota.used_bytes(), 10_000);

        // Wait for the interval to elapse.
        std::thread::sleep(Duration::from_millis(60));
        quota.check_and_reset();
        assert_eq!(quota.used_bytes(), 0);
        assert_eq!(quota.remaining(), 10_000);
    }

    #[test]
    fn test_quota_disabled_unlimited() {
        let mut quota = QuotaTracker::new(0, Duration::from_secs(3600));
        assert!(quota.is_disabled());
        assert!(quota.record(u64::MAX));
        assert_eq!(quota.remaining(), u64::MAX);
    }

    #[test]
    fn test_quota_overflow_protection() {
        let mut quota = QuotaTracker::new(10_000, Duration::from_secs(3600));
        assert!(quota.record(5_000));
        // A huge addition that would overflow u64 → rejected, not recorded.
        assert!(!quota.record(u64::MAX));
        assert_eq!(quota.used_bytes(), 5_000);
    }

    // --- PerClientBandwidthManager ----------------------------------------

    #[test]
    fn test_manager_defaults_for_new_client() {
        let mut mgr = PerClientBandwidthManager::new(1_000, 1_000, 10_000, Duration::from_secs(60));

        // A previously-unseen client gets the default rate limit.
        assert!(mgr.check_send("alice", 1_000));
        // Bucket now empty → next send rejected.
        assert!(!mgr.check_send("alice", 1));

        let stats = mgr.stats("alice").unwrap();
        assert_eq!(stats.rate_bps, 1_000);
        assert_eq!(stats.burst_bytes, 1_000);
        assert_eq!(stats.quota_limit_bytes, 10_000);
        assert_eq!(stats.quota_used_bytes, 1_000);
        assert_eq!(stats.quota_remaining_bytes, 9_000);
    }

    #[test]
    fn test_manager_per_client_isolation() {
        let mut mgr = PerClientBandwidthManager::new(1_000, 1_000, 10_000, Duration::from_secs(60));

        // Drain alice's bucket.
        assert!(mgr.check_send("alice", 1_000));
        assert!(!mgr.check_send("alice", 1));

        // Bob has an independent bucket — still full.
        assert!(mgr.check_send("bob", 1_000));

        // Alice's quota reflects only alice's usage.
        let alice = mgr.stats("alice").unwrap();
        let bob = mgr.stats("bob").unwrap();
        assert_eq!(alice.quota_used_bytes, 1_000);
        assert_eq!(bob.quota_used_bytes, 1_000);
    }

    #[test]
    fn test_manager_set_client_limit_override() {
        let mut mgr = PerClientBandwidthManager::new(1_000, 1_000, 10_000, Duration::from_secs(60));

        // Give alice a higher rate and burst.
        mgr.set_client_limit("alice", 10_000, 10_000);

        // Default client is capped at 1000; alice can send 10_000.
        assert!(!mgr.check_send("bob", 1_001));
        assert!(mgr.check_send("alice", 10_000));

        let stats = mgr.stats("alice").unwrap();
        assert_eq!(stats.rate_bps, 10_000);
        assert_eq!(stats.burst_bytes, 10_000);
    }

    #[test]
    fn test_manager_set_client_quota_override() {
        let mut mgr = PerClientBandwidthManager::new(1_000, 1_000, 10_000, Duration::from_secs(60));

        // Give alice a tiny quota.
        mgr.set_client_quota("alice", 500);

        // Rate limit allows 1000, but quota caps at 500.
        assert!(mgr.check_send("alice", 500));
        // Next send: rate bucket has 500 tokens left, quota has 0 → rejected.
        assert!(!mgr.check_send("alice", 500));

        let stats = mgr.stats("alice").unwrap();
        assert_eq!(stats.quota_limit_bytes, 500);
        assert_eq!(stats.quota_used_bytes, 500);
        assert_eq!(stats.quota_remaining_bytes, 0);
    }

    #[test]
    fn test_manager_quota_exceeded_blocks_send() {
        let mut mgr =
            PerClientBandwidthManager::new(1_000_000, 1_000_000, 1_000, Duration::from_secs(60));

        // Exhaust the quota (rate limit is generous).
        assert!(mgr.check_send("alice", 1_000));
        // Quota exhausted → further sends rejected even though rate tokens remain.
        assert!(!mgr.check_send("alice", 1));

        let stats = mgr.stats("alice").unwrap();
        assert_eq!(stats.quota_used_bytes, 1_000);
        assert_eq!(stats.quota_remaining_bytes, 0);
    }

    #[test]
    fn test_manager_rate_rejected_does_not_consume_quota() {
        let mut mgr = PerClientBandwidthManager::new(1_000, 1_000, 10_000, Duration::from_secs(60));

        // Drain the rate bucket (1_000 bytes). Quota is 10_000 so this is fine.
        assert!(mgr.check_send("alice", 1_000));

        // This send is rejected by the rate limiter (bucket empty). The quota
        // must NOT be decremented.
        assert!(!mgr.check_send("alice", 1_000));

        let stats = mgr.stats("alice").unwrap();
        assert_eq!(stats.quota_used_bytes, 1_000);
        assert_eq!(stats.quota_remaining_bytes, 9_000);
    }

    #[test]
    fn test_manager_stats_unknown_client() {
        let mgr = PerClientBandwidthManager::new(1_000, 1_000, 10_000, Duration::from_secs(60));
        assert!(mgr.stats("nobody").is_none());
    }

    #[test]
    fn test_manager_remove_client() {
        let mut mgr = PerClientBandwidthManager::new(1_000, 1_000, 10_000, Duration::from_secs(60));
        mgr.check_send("alice", 100);
        assert_eq!(mgr.len(), 1);

        mgr.remove_client("alice");
        assert_eq!(mgr.len(), 0);
        assert!(mgr.stats("alice").is_none());

        // Re-checking recreates the entry with fresh defaults.
        mgr.check_send("alice", 100);
        let stats = mgr.stats("alice").unwrap();
        assert_eq!(stats.quota_used_bytes, 100);
    }

    #[test]
    fn test_manager_disabled_defaults_allow_all() {
        let mut mgr = PerClientBandwidthManager::new(0, 0, 0, Duration::from_secs(60));
        // Everything disabled → all sends allowed, no quota consumed.
        assert!(mgr.check_send("alice", u64::MAX as usize));
        let stats = mgr.stats("alice").unwrap();
        assert_eq!(stats.quota_used_bytes, 0);
        assert_eq!(stats.quota_remaining_bytes, u64::MAX);
    }
}
