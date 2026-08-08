//! Per-client bandwidth limits and quotas.
//!
//! This module provides byte-oriented (not packet-oriented) rate limiting and
//! quota tracking on a per-client basis. It complements `limits.rs`, which
//! caps packet/byte rates globally and per-IP; here the granularity is the
//! individual authenticated session, and the unit is bytes per second with
//! optional UTC daily and monthly transfer quotas.
//!
//! # Components
//!
//! - [`BandwidthLimiter`]: a token bucket refilled at `refill_rate_bps` bytes
//!   per second, capped at `capacity_bytes` (burst). `check` consumes tokens.
//! - [`QuotaTracker`]: tracks cumulative bytes against one UTC calendar period.
//! - [`PerClientBandwidthManager`]: owns independent uplink/downlink buckets and
//!   shared quotas for every explicitly registered authenticated session.

use std::collections::HashMap;
use std::time::{Instant, SystemTime};

use crate::time_source::ProtocolClock;

const SECONDS_PER_DAY: u64 = 86_400;
const DENIAL_AUDIT_INTERVAL: std::time::Duration = std::time::Duration::from_secs(60);

/// Effective per-session bandwidth, quota, and scheduling policy.
#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub struct BandwidthPolicy {
    /// Sustained rate per direction in bytes per second. Zero disables rate limiting.
    pub rate_bytes_per_second: u64,
    /// Initial and maximum burst per direction in bytes. Zero disables rate limiting.
    pub burst_bytes: u64,
    /// Combined uplink plus downlink quota per UTC day. Zero means unlimited.
    pub daily_quota_bytes: u64,
    /// Combined uplink plus downlink quota per UTC calendar month. Zero means unlimited.
    pub monthly_quota_bytes: u64,
    /// Deficit-round-robin weight. Higher values receive proportionally more service.
    pub weight: u16,
}

impl BandwidthPolicy {
    pub const MAX_WEIGHT: u16 = 1_000;

    pub fn validate(&self) -> Result<(), String> {
        if (self.rate_bytes_per_second == 0) != (self.burst_bytes == 0) {
            return Err(
                "bandwidth rate_bytes_per_second and burst_bytes must both be zero or nonzero"
                    .to_string(),
            );
        }
        if self.weight == 0 || self.weight > Self::MAX_WEIGHT {
            return Err(format!("bandwidth weight must be between 1 and {}", Self::MAX_WEIGHT));
        }
        Ok(())
    }
}

impl Default for BandwidthPolicy {
    fn default() -> Self {
        Self {
            rate_bytes_per_second: 0,
            burst_bytes: 0,
            daily_quota_bytes: 0,
            monthly_quota_bytes: 0,
            weight: 1,
        }
    }
}

/// Direction whose independently paced byte bucket is being charged.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BandwidthDirection {
    Uplink,
    Downlink,
}

impl BandwidthDirection {
    fn index(self) -> usize {
        match self {
            Self::Uplink => 0,
            Self::Downlink => 1,
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Uplink => "uplink",
            Self::Downlink => "downlink",
        }
    }
}

/// Exact admission outcome exported to runtime metrics and audit.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BandwidthDecision {
    Allowed,
    RateLimited,
    DailyQuotaExceeded,
    MonthlyQuotaExceeded,
    /// The wall clock was invalid, so quota admission fails closed.
    ClockUnavailable,
}

impl BandwidthDecision {
    fn as_str(self) -> &'static str {
        match self {
            Self::Allowed => "allowed",
            Self::RateLimited => "rate_limited",
            Self::DailyQuotaExceeded => "daily_quota_exceeded",
            Self::MonthlyQuotaExceeded => "monthly_quota_exceeded",
            Self::ClockUnavailable => "clock_unavailable",
        }
    }
}

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
#[derive(Debug)]
pub struct BandwidthLimiter {
    /// Burst capacity (max tokens the bucket can hold).
    capacity_bytes: u64,
    /// Sustained refill rate in bytes per second.
    refill_rate_bps: u64,
    /// Current token count.
    tokens: u64,
    /// Monotonic timestamp of the last refill.
    last_refill: Instant,
    /// Clock owning refill progression for this limiter.
    clock: ProtocolClock,
}

impl BandwidthLimiter {
    /// Create a new limiter.
    ///
    /// `rate_bps` is the sustained bytes-per-second rate; `burst_bytes` is the
    /// burst capacity (the bucket starts full). A `rate_bps` or `burst_bytes` of
    /// `0` disables the limiter (all sends are allowed).
    pub fn new(rate_bps: u64, burst_bytes: u64) -> Self {
        Self::new_with_clock(rate_bps, burst_bytes, &ProtocolClock::default())
    }

    /// Create a limiter bound to an explicit protocol clock.
    pub fn new_with_clock(rate_bps: u64, burst_bytes: u64, clock: &ProtocolClock) -> Self {
        Self {
            capacity_bytes: burst_bytes,
            refill_rate_bps: rate_bps,
            tokens: burst_bytes,
            last_refill: clock.now(),
            clock: clock.clone(),
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

    /// Return a reservation that could not be delivered.
    pub(crate) fn refund(&mut self, bytes: usize) {
        if self.is_disabled() {
            return;
        }
        self.tokens = self.tokens.saturating_add(bytes as u64).min(self.capacity_bytes);
    }

    /// Add tokens based on elapsed time, capped at capacity.
    ///
    /// Computes the refill as `refill_rate_bps × elapsed_seconds` using u128
    /// arithmetic to avoid overflow for large idle gaps, then saturates at
    /// `capacity_bytes`.
    pub fn refill(&mut self) {
        let now = self.clock.now();
        let elapsed = self.clock.elapsed_since(self.last_refill);

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
// Tracks total bytes transferred against a `quota_limit_bytes` budget for one
// deterministic UTC calendar period. `record` rejects without accounting when
// the addition would exceed the quota. Zero means unlimited.
// ---------------------------------------------------------------------------

/// Cumulative transfer quota with periodic reset.
///
/// A limit of `0` disables the quota. `record` accumulates bytes and returns
/// `false` if the addition would exceed the limit; `check_and_reset` resets
/// only after advancing into a later UTC calendar period.
pub struct QuotaTracker {
    /// Total bytes allowed per billing period (0 = unlimited).
    quota_limit_bytes: u64,
    /// Bytes consumed in the current billing period.
    used_bytes: u64,
    period: QuotaPeriod,
    period_index: i64,
    /// Clock owning billing-period selection for this tracker.
    clock: ProtocolClock,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum QuotaPeriod {
    Daily,
    Monthly,
}

impl QuotaTracker {
    pub fn new(
        quota_limit_bytes: u64,
        period: QuotaPeriod,
    ) -> Result<Self, crate::time_source::WallClockError> {
        Self::new_with_clock(quota_limit_bytes, period, &ProtocolClock::default())
    }

    /// Create a quota tracker bound to an explicit protocol clock.
    pub fn new_with_clock(
        quota_limit_bytes: u64,
        period: QuotaPeriod,
        clock: &ProtocolClock,
    ) -> Result<Self, crate::time_source::WallClockError> {
        Self::new_at_with_clock(quota_limit_bytes, period, clock.now_system(), clock)
    }

    #[allow(dead_code)]
    fn new_at(
        quota_limit_bytes: u64,
        period: QuotaPeriod,
        now: SystemTime,
    ) -> Result<Self, crate::time_source::WallClockError> {
        Self::new_at_with_clock(quota_limit_bytes, period, now, &ProtocolClock::default())
    }

    fn new_at_with_clock(
        quota_limit_bytes: u64,
        period: QuotaPeriod,
        now: SystemTime,
        clock: &ProtocolClock,
    ) -> Result<Self, crate::time_source::WallClockError> {
        Ok(Self {
            quota_limit_bytes,
            used_bytes: 0,
            period,
            period_index: quota_period_index(now, period)?,
            clock: clock.clone(),
        })
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
    pub fn check_and_reset(&mut self) -> Result<(), crate::time_source::WallClockError> {
        self.check_and_reset_at(self.clock.now_system())
    }

    fn check_and_reset_at(
        &mut self,
        now: SystemTime,
    ) -> Result<(), crate::time_source::WallClockError> {
        let period_index = quota_period_index(now, self.period)?;
        if period_index > self.period_index {
            self.used_bytes = 0;
            self.period_index = period_index;
        }
        Ok(())
    }

    fn can_record(&self, bytes: u64) -> bool {
        self.is_disabled()
            || self
                .used_bytes
                .checked_add(bytes)
                .is_some_and(|total| total <= self.quota_limit_bytes)
    }

    pub fn reset(&mut self) -> Result<(), crate::time_source::WallClockError> {
        self.reset_at(self.clock.now_system())?;
        Ok(())
    }

    fn reset_at(&mut self, now: SystemTime) -> Result<(), crate::time_source::WallClockError> {
        let period_index = quota_period_index(now, self.period)?;
        self.used_bytes = 0;
        self.period_index = period_index;
        Ok(())
    }

    fn set_limit(&mut self, quota_limit_bytes: u64) {
        self.quota_limit_bytes = quota_limit_bytes;
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

fn quota_period_index(
    now: SystemTime,
    period: QuotaPeriod,
) -> Result<i64, crate::time_source::WallClockError> {
    let epoch_seconds = crate::time_source::unix_epoch_seconds(now)?;
    let epoch_days = (epoch_seconds / SECONDS_PER_DAY)
        .try_into()
        .map_err(|_| crate::time_source::WallClockError::CalendarOverflow)?;
    match period {
        QuotaPeriod::Daily => Ok(epoch_days),
        QuotaPeriod::Monthly => {
            let (year, month) = utc_year_month_from_epoch_days(epoch_days);
            year.checked_mul(12)
                .and_then(|value| value.checked_add(i64::from(month)))
                .and_then(|value| value.checked_sub(1))
                .ok_or(crate::time_source::WallClockError::CalendarOverflow)
        }
    }
}

fn utc_year_month_from_epoch_days(epoch_days: i64) -> (i64, u32) {
    let shifted = epoch_days + 719_468;
    let era = if shifted >= 0 { shifted } else { shifted - 146_096 } / 146_097;
    let day_of_era = shifted - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let mut year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_prime = (5 * day_of_year + 2) / 153;
    let month = month_prime + if month_prime < 10 { 3 } else { -9 };
    year += if month <= 2 { 1 } else { 0 };
    (year, month as u32)
}

// ---------------------------------------------------------------------------
// PerClientBandwidthManager — client ID → limiter + quota.
//
// Holds one validated default policy and explicitly registered session state.
// ---------------------------------------------------------------------------

/// Per-client bandwidth + quota state.
struct ClientBandwidthEntry {
    policy: BandwidthPolicy,
    uplink_limiter: BandwidthLimiter,
    downlink_limiter: BandwidthLimiter,
    daily_quota: QuotaTracker,
    monthly_quota: QuotaTracker,
    last_audited_denial: [Option<(BandwidthDecision, Instant)>; 2],
}

/// Snapshot of a client's bandwidth configuration and quota usage.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct BandwidthStats {
    pub policy: BandwidthPolicy,
    pub uplink_available_bytes: u64,
    pub downlink_available_bytes: u64,
    pub daily_used_bytes: u64,
    pub daily_remaining_bytes: u64,
    pub monthly_used_bytes: u64,
    pub monthly_remaining_bytes: u64,
}

/// Per-client bandwidth limiter and quota tracker.
///
/// Missing sessions fail closed. Live policy updates replace both directional
/// buckets while preserving already-accounted quota usage.
pub struct PerClientBandwidthManager {
    clients: HashMap<String, ClientBandwidthEntry>,
    default_policy: BandwidthPolicy,
    /// Clock shared by all per-client rate, quota, and audit state.
    clock: ProtocolClock,
}

impl PerClientBandwidthManager {
    pub fn new(default_policy: BandwidthPolicy) -> Result<Self, String> {
        Self::new_with_clock(default_policy, &ProtocolClock::default())
    }

    /// Create a manager bound to an explicit protocol clock.
    pub fn new_with_clock(
        default_policy: BandwidthPolicy,
        clock: &ProtocolClock,
    ) -> Result<Self, String> {
        default_policy.validate()?;
        Ok(Self { clients: HashMap::new(), default_policy, clock: clock.clone() })
    }

    /// Create a manager with the compile-time validated default policy.
    pub fn with_default_policy_with_clock(clock: &ProtocolClock) -> Self {
        Self {
            clients: HashMap::new(),
            default_policy: BandwidthPolicy::default(),
            clock: clock.clone(),
        }
    }

    fn entry_from_policy(
        policy: BandwidthPolicy,
        clock: &ProtocolClock,
    ) -> Result<ClientBandwidthEntry, crate::time_source::WallClockError> {
        Ok(ClientBandwidthEntry {
            uplink_limiter: BandwidthLimiter::new_with_clock(
                policy.rate_bytes_per_second,
                policy.burst_bytes,
                clock,
            ),
            downlink_limiter: BandwidthLimiter::new_with_clock(
                policy.rate_bytes_per_second,
                policy.burst_bytes,
                clock,
            ),
            daily_quota: QuotaTracker::new_with_clock(
                policy.daily_quota_bytes,
                QuotaPeriod::Daily,
                clock,
            )?,
            monthly_quota: QuotaTracker::new_with_clock(
                policy.monthly_quota_bytes,
                QuotaPeriod::Monthly,
                clock,
            )?,
            last_audited_denial: [None; 2],
            policy,
        })
    }

    pub fn add_client(
        &mut self,
        client_id: &str,
        policy_override: Option<BandwidthPolicy>,
    ) -> Result<(), String> {
        let policy = policy_override.unwrap_or_else(|| self.default_policy.clone());
        policy.validate()?;
        if self.clients.contains_key(client_id) {
            return Err("bandwidth client already registered".to_string());
        }
        let entry = Self::entry_from_policy(policy, &self.clock)
            .map_err(|error| format!("bandwidth wall-clock error: {error}"))?;
        self.clients.insert(client_id.to_string(), entry);
        Ok(())
    }

    pub fn update_client_policy(
        &mut self,
        client_id: &str,
        policy: BandwidthPolicy,
    ) -> Result<(), String> {
        policy.validate()?;
        let Some(entry) = self.clients.get_mut(client_id) else {
            return Err("bandwidth client not found".to_string());
        };
        entry.uplink_limiter = BandwidthLimiter::new_with_clock(
            policy.rate_bytes_per_second,
            policy.burst_bytes,
            &self.clock,
        );
        entry.downlink_limiter = BandwidthLimiter::new_with_clock(
            policy.rate_bytes_per_second,
            policy.burst_bytes,
            &self.clock,
        );
        entry.daily_quota.set_limit(policy.daily_quota_bytes);
        entry.monthly_quota.set_limit(policy.monthly_quota_bytes);
        entry.policy = policy;
        Ok(())
    }

    pub fn check(
        &mut self,
        client_id: &str,
        direction: BandwidthDirection,
        bytes: usize,
    ) -> BandwidthDecision {
        let Some(entry) = self.clients.get_mut(client_id) else {
            return BandwidthDecision::RateLimited;
        };
        let clock_available = entry.daily_quota.check_and_reset().is_ok()
            && entry.monthly_quota.check_and_reset().is_ok();
        let accounted_bytes = bytes as u64;
        let decision = if !clock_available {
            BandwidthDecision::ClockUnavailable
        } else if !entry.daily_quota.can_record(accounted_bytes) {
            BandwidthDecision::DailyQuotaExceeded
        } else if !entry.monthly_quota.can_record(accounted_bytes) {
            BandwidthDecision::MonthlyQuotaExceeded
        } else {
            let limiter = match direction {
                BandwidthDirection::Uplink => &mut entry.uplink_limiter,
                BandwidthDirection::Downlink => &mut entry.downlink_limiter,
            };
            if limiter.check(bytes) {
                let daily_recorded = entry.daily_quota.record(accounted_bytes);
                let monthly_recorded = entry.monthly_quota.record(accounted_bytes);
                debug_assert!(daily_recorded && monthly_recorded);
                BandwidthDecision::Allowed
            } else {
                BandwidthDecision::RateLimited
            }
        };
        let now = self.clock.now();
        let audit_slot = &mut entry.last_audited_denial[direction.index()];
        let should_audit = decision != BandwidthDecision::Allowed
            && audit_slot.is_none_or(|(previous, last)| {
                previous != decision || self.clock.elapsed_since(last) >= DENIAL_AUDIT_INTERVAL
            });
        if should_audit {
            *audit_slot = Some((decision, now));
        }
        if should_audit {
            crate::audit::audit_typed(
                crate::audit::AuditEventType::AdminAction,
                crate::audit::AuditSeverity::Warning,
                None,
                Some(client_id),
                crate::audit::AuditContext {
                    actor: crate::audit::AuditActor::System,
                    target: crate::audit::AuditTarget::Client,
                    outcome: crate::audit::AuditOutcome::Denied,
                    reason: Some(decision.as_str()),
                },
                &format!("Per-session bandwidth policy denied {} traffic", direction.as_str()),
            );
        }
        decision
    }

    /// Snapshot of a client's bandwidth configuration and quota usage.
    ///
    /// Returns `None` if the client has no entry (never seen and no overrides
    /// applied).
    pub fn stats(&self, client_id: &str) -> Option<BandwidthStats> {
        let entry = self.clients.get(client_id)?;
        Some(BandwidthStats {
            policy: entry.policy.clone(),
            uplink_available_bytes: entry.uplink_limiter.available_tokens(),
            downlink_available_bytes: entry.downlink_limiter.available_tokens(),
            daily_used_bytes: entry.daily_quota.used_bytes(),
            daily_remaining_bytes: entry.daily_quota.remaining(),
            monthly_used_bytes: entry.monthly_quota.used_bytes(),
            monthly_remaining_bytes: entry.monthly_quota.remaining(),
        })
    }

    pub fn reset_client_quota(
        &mut self,
        client_id: &str,
    ) -> Result<bool, crate::time_source::WallClockError> {
        let Some(entry) = self.clients.get_mut(client_id) else {
            return Ok(false);
        };
        let now = self.clock.now_system();
        entry.daily_quota.reset_at(now)?;
        entry.monthly_quota.reset_at(now)?;
        Ok(true)
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
    use std::time::{Duration, UNIX_EPOCH};

    // --- BandwidthLimiter --------------------------------------------------

    #[test]
    fn test_limiter_starts_full() {
        let mut limiter = BandwidthLimiter::new(1_000, 10_000);
        // Bucket starts full at capacity, so a send up to capacity is allowed.
        assert!(limiter.check(10_000));
        assert_eq!(limiter.available_tokens(), 0);
    }

    #[test]
    fn explicit_clock_drives_bandwidth_refill_and_daily_quota_reset() {
        let source = crate::time_source::test_support::ManualTimeSource::new(
            Instant::now(),
            UNIX_EPOCH + Duration::from_secs(86_400),
        );
        let clock = ProtocolClock::from_source(source.clone());
        let mut limiter = BandwidthLimiter::new_with_clock(10, 10, &clock);
        assert!(limiter.check(10));
        assert!(!limiter.check(1));

        source.advance(Duration::from_secs(1));
        assert!(limiter.check(10));

        let mut quota = QuotaTracker::new_with_clock(10, QuotaPeriod::Daily, &clock)
            .expect("valid epoch clock");
        assert!(quota.record(10));
        assert_eq!(quota.remaining(), 0);
        source.advance(Duration::from_secs(86_400));
        quota.check_and_reset().expect("valid epoch clock");
        assert_eq!(quota.remaining(), 10);
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

    #[test]
    fn limiter_refund_restores_only_the_reserved_capacity() {
        let mut limiter = BandwidthLimiter::new(1_000, 1_000);
        assert!(limiter.check(600));
        limiter.refund(600);
        assert_eq!(limiter.available_tokens(), 1_000);
        limiter.refund(1_000);
        assert_eq!(limiter.available_tokens(), 1_000);
    }

    // --- QuotaTracker ------------------------------------------------------

    #[test]
    fn test_quota_record_within_limit() {
        let mut quota = QuotaTracker::new(10_000, QuotaPeriod::Daily).expect("valid epoch clock");
        assert!(quota.record(4_000));
        assert_eq!(quota.used_bytes(), 4_000);
        assert!(quota.record(6_000));
        assert_eq!(quota.used_bytes(), 10_000);
        assert_eq!(quota.remaining(), 0);
    }

    #[test]
    fn test_quota_exceeded_rejected() {
        let mut quota = QuotaTracker::new(10_000, QuotaPeriod::Daily).expect("valid epoch clock");
        assert!(quota.record(9_000));
        // 2000 more would exceed 10_000 → rejected, and not recorded.
        assert!(!quota.record(2_000));
        assert_eq!(quota.used_bytes(), 9_000);
        assert_eq!(quota.remaining(), 1_000);
    }

    #[test]
    fn daily_quota_resets_at_utc_midnight_not_elapsed_duration() {
        let start = UNIX_EPOCH + Duration::from_secs(20_000 * SECONDS_PER_DAY + 86_399);
        let mut quota = QuotaTracker::new_at(10_000, QuotaPeriod::Daily, start).unwrap();
        assert!(quota.record(10_000));
        quota.check_and_reset_at(start).unwrap();
        assert_eq!(quota.used_bytes(), 10_000);
        quota.check_and_reset_at(start + Duration::from_secs(1)).unwrap();
        assert_eq!(quota.used_bytes(), 0);
        assert_eq!(quota.remaining(), 10_000);
    }

    #[test]
    fn monthly_quota_resets_on_first_utc_day_and_ignores_clock_rollback() {
        let january_31_2024 = UNIX_EPOCH + Duration::from_secs(19_753 * SECONDS_PER_DAY + 86_399);
        let february_1_2024 = january_31_2024 + Duration::from_secs(1);
        let mut quota =
            QuotaTracker::new_at(10_000, QuotaPeriod::Monthly, january_31_2024).unwrap();
        assert!(quota.record(10_000));
        quota.check_and_reset_at(january_31_2024 - Duration::from_secs(SECONDS_PER_DAY)).unwrap();
        assert_eq!(quota.used_bytes(), 10_000);
        quota.check_and_reset_at(february_1_2024).unwrap();
        assert_eq!(quota.used_bytes(), 0);
    }

    #[test]
    fn quota_disabled_and_overflow_are_bounded() {
        let mut unlimited = QuotaTracker::new(0, QuotaPeriod::Monthly).expect("valid epoch clock");
        assert!(unlimited.record(u64::MAX));
        assert_eq!(unlimited.remaining(), u64::MAX);

        let mut bounded = QuotaTracker::new(10_000, QuotaPeriod::Daily).expect("valid epoch clock");
        assert!(bounded.record(5_000));
        assert!(!bounded.record(u64::MAX));
        assert_eq!(bounded.used_bytes(), 5_000);
    }

    #[test]
    fn quota_rejects_pre_epoch_clock_without_selecting_epoch_zero() {
        let source = crate::time_source::test_support::ManualTimeSource::new(
            Instant::now(),
            UNIX_EPOCH.checked_sub(Duration::from_secs(1)).unwrap(),
        );
        let clock = ProtocolClock::from_source(source);
        assert!(matches!(
            QuotaTracker::new_with_clock(10, QuotaPeriod::Daily, &clock),
            Err(crate::time_source::WallClockError::BeforeUnixEpoch)
        ));

        let mut manager =
            PerClientBandwidthManager::new_with_clock(policy(1_000, 1_000, 10, 10), &clock)
                .expect("policy is valid before client admission");
        assert!(manager.add_client("pre-epoch", None).is_err());
    }

    // --- PerClientBandwidthManager ----------------------------------------

    fn policy(rate: u64, burst: u64, daily: u64, monthly: u64) -> BandwidthPolicy {
        BandwidthPolicy {
            rate_bytes_per_second: rate,
            burst_bytes: burst,
            daily_quota_bytes: daily,
            monthly_quota_bytes: monthly,
            weight: 1,
        }
    }

    #[test]
    fn manager_requires_explicit_session_ownership() {
        let mut manager = PerClientBandwidthManager::new(policy(1_000, 1_000, 10_000, 20_000))
            .expect("valid policy");
        assert_eq!(
            manager.check("missing", BandwidthDirection::Uplink, 1),
            BandwidthDecision::RateLimited
        );
        manager.add_client("alice", None).expect("add session");
        assert_eq!(
            manager.check("alice", BandwidthDirection::Uplink, 1_000),
            BandwidthDecision::Allowed
        );
        assert_eq!(
            manager.check("alice", BandwidthDirection::Uplink, 1),
            BandwidthDecision::RateLimited
        );
    }

    #[test]
    fn duplicate_session_registration_is_rejected_without_replacing_state() {
        let mut manager =
            PerClientBandwidthManager::new(policy(1_000, 1_000, 10_000, 20_000)).unwrap();
        manager.add_client("alice", None).unwrap();
        assert_eq!(
            manager.check("alice", BandwidthDirection::Uplink, 500),
            BandwidthDecision::Allowed
        );

        assert!(manager.add_client("alice", Some(policy(2_000, 2_000, 30_000, 40_000))).is_err());
        let stats = manager.stats("alice").unwrap();
        assert_eq!(stats.policy, policy(1_000, 1_000, 10_000, 20_000));
        assert_eq!(stats.daily_used_bytes, 500);
    }

    #[test]
    fn manager_keeps_uplink_and_downlink_rate_buckets_independent() {
        let mut manager =
            PerClientBandwidthManager::new(policy(1_000, 1_000, 10_000, 20_000)).unwrap();
        manager.add_client("alice", None).unwrap();
        assert_eq!(
            manager.check("alice", BandwidthDirection::Uplink, 1_000),
            BandwidthDecision::Allowed
        );
        assert_eq!(
            manager.check("alice", BandwidthDirection::Downlink, 1_000),
            BandwidthDecision::Allowed
        );
        assert_eq!(manager.stats("alice").unwrap().daily_used_bytes, 2_000);
    }

    #[test]
    fn ten_megabit_policy_uses_exact_byte_rate_and_burst() {
        const TEN_MEGABIT_BYTES_PER_SECOND: u64 = 10_000_000 / 8;
        let mut manager = PerClientBandwidthManager::new(policy(
            TEN_MEGABIT_BYTES_PER_SECOND,
            TEN_MEGABIT_BYTES_PER_SECOND,
            0,
            0,
        ))
        .unwrap();
        manager.add_client("client", None).unwrap();
        assert_eq!(
            manager.check(
                "client",
                BandwidthDirection::Uplink,
                TEN_MEGABIT_BYTES_PER_SECOND as usize,
            ),
            BandwidthDecision::Allowed
        );
        assert_eq!(
            manager.check(
                "client",
                BandwidthDirection::Uplink,
                TEN_MEGABIT_BYTES_PER_SECOND as usize + 1,
            ),
            BandwidthDecision::RateLimited
        );
    }

    #[test]
    fn three_clients_have_no_rate_or_quota_coupling() {
        let mut manager =
            PerClientBandwidthManager::new(policy(1_000, 1_000, 1_000, 2_000)).unwrap();
        for client in ["one", "two", "three"] {
            manager.add_client(client, None).unwrap();
            assert_eq!(
                manager.check(client, BandwidthDirection::Uplink, 1_000),
                BandwidthDecision::Allowed
            );
        }
        for client in ["one", "two", "three"] {
            assert_eq!(manager.stats(client).unwrap().daily_used_bytes, 1_000);
        }
    }

    #[test]
    fn daily_and_monthly_quota_outcomes_are_distinct() {
        let mut daily = PerClientBandwidthManager::new(policy(10_000, 10_000, 500, 5_000)).unwrap();
        daily.add_client("alice", None).unwrap();
        assert_eq!(
            daily.check("alice", BandwidthDirection::Uplink, 500),
            BandwidthDecision::Allowed
        );
        assert_eq!(
            daily.check("alice", BandwidthDirection::Downlink, 1),
            BandwidthDecision::DailyQuotaExceeded
        );

        let mut monthly = PerClientBandwidthManager::new(policy(10_000, 10_000, 0, 500)).unwrap();
        monthly.add_client("alice", None).unwrap();
        assert_eq!(
            monthly.check("alice", BandwidthDirection::Uplink, 500),
            BandwidthDecision::Allowed
        );
        assert_eq!(
            monthly.check("alice", BandwidthDirection::Downlink, 1),
            BandwidthDecision::MonthlyQuotaExceeded
        );
    }

    #[test]
    fn rejected_rate_does_not_consume_shared_quota() {
        let mut manager =
            PerClientBandwidthManager::new(policy(1_000, 1_000, 10_000, 20_000)).unwrap();
        manager.add_client("alice", None).unwrap();
        assert_eq!(
            manager.check("alice", BandwidthDirection::Uplink, 1_000),
            BandwidthDecision::Allowed
        );
        assert_eq!(
            manager.check("alice", BandwidthDirection::Uplink, 1),
            BandwidthDecision::RateLimited
        );
        assert_eq!(manager.stats("alice").unwrap().daily_used_bytes, 1_000);
    }

    #[test]
    fn live_policy_update_preserves_usage_until_explicit_reset() {
        let mut manager =
            PerClientBandwidthManager::new(policy(10_000, 10_000, 10_000, 20_000)).unwrap();
        manager.add_client("alice", None).unwrap();
        assert_eq!(
            manager.check("alice", BandwidthDirection::Uplink, 1_000),
            BandwidthDecision::Allowed
        );
        manager.update_client_policy("alice", policy(20_000, 20_000, 2_000, 3_000)).unwrap();
        assert_eq!(manager.stats("alice").unwrap().daily_used_bytes, 1_000);
        assert!(manager.reset_client_quota("alice").expect("reset quota"));
        assert_eq!(manager.stats("alice").unwrap().daily_used_bytes, 0);
    }

    #[test]
    fn invalid_policy_is_rejected() {
        assert!(PerClientBandwidthManager::new(policy(1_000, 0, 0, 0)).is_err());
        let mut invalid_weight = policy(0, 0, 0, 0);
        invalid_weight.weight = 0;
        assert!(PerClientBandwidthManager::new(invalid_weight).is_err());
    }

    #[test]
    fn default_policy_constructor_is_infallible_and_validated() {
        let manager =
            PerClientBandwidthManager::with_default_policy_with_clock(&ProtocolClock::default());
        assert_eq!(manager.default_policy, BandwidthPolicy::default());
        assert!(manager.default_policy.validate().is_ok());
    }

    #[test]
    fn remove_client_erases_the_only_session_entry() {
        let mut manager = PerClientBandwidthManager::new(BandwidthPolicy::default()).unwrap();
        manager.add_client("alice", None).unwrap();
        assert_eq!(manager.len(), 1);
        manager.remove_client("alice");
        assert!(manager.is_empty());
        assert!(manager.stats("alice").is_none());
    }
}
