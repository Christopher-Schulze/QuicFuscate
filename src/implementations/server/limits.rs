//! Rate limiting and connection limiting for the server.

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicU8, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::time_source::ProtocolClock;

/// Default global server-wide packet rate cap (packets per second across all IPs).
pub const DEFAULT_GLOBAL_RATE_LIMIT_PPS: u64 = 50_000;
/// Default sustained packet rate per source.
///
/// This must leave headroom above normal tunnel packet rates so the abuse
/// control cannot manufacture transport loss under legitimate throughput.
pub const DEFAULT_PER_SOURCE_RATE_LIMIT_PPS: u64 = 10_000;
const MAX_BLACKLIST_CA_BUNDLE_BYTES: u64 = 1024 * 1024;
/// Absolute maximum feed and serialized-cache body size.
pub const MAX_BLACKLIST_BODY_BYTES: usize = 16 * 1024 * 1024;
/// Absolute maximum number of unique blocked addresses retained per feed.
pub const MAX_BLACKLIST_ENTRIES: usize = 250_000;
/// Absolute maximum TTL for an externally synchronized address.
pub const MAX_BLACKLIST_TTL_SECS: u64 = 7 * 24 * 60 * 60;
/// Absolute maximum interval between external synchronization attempts.
pub const MAX_BLACKLIST_SYNC_INTERVAL_SECS: u64 = 7 * 24 * 60 * 60;
/// Absolute maximum HTTPS request duration.
pub const MAX_BLACKLIST_REQUEST_TIMEOUT_SECS: u64 = 300;

mod rate_limit;
#[cfg(feature = "rate_limiter")]
pub use rate_limit::load_rate_limit_config_from_env;
#[cfg(test)]
use rate_limit::TokenBucket;
pub use rate_limit::{ConnectionLimiter, RateLimitConfig, RateLimiter};

/// Bounded QKey authentication abuse-policy configuration.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthPolicyConfig {
    /// Disable all per-IP state and admission delays.
    pub enabled: bool,
    /// First consecutive failure that schedules exponential backoff.
    pub backoff_after_failures: u32,
    /// Initial exponential-backoff duration.
    pub backoff_base: Duration,
    /// Maximum exponential-backoff duration.
    pub backoff_max: Duration,
    /// Consecutive failure that enters the explicit blocked state.
    pub block_after_failures: u32,
    /// Duration of the explicit blocked state.
    pub block_duration: Duration,
    /// Remove inactive per-IP state after this duration.
    pub idle_timeout: Duration,
    /// Minimum interval between full-map idle-prune passes.
    pub prune_interval: Duration,
    /// Hard bound for attacker-controlled per-IP state.
    pub max_tracked_ips: usize,
    /// Hard bound for concurrent in-flight attempts from one IP.
    pub max_pending_attempts_per_ip: usize,
}

impl Default for AuthPolicyConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            backoff_after_failures: 3,
            backoff_base: Duration::from_millis(250),
            backoff_max: Duration::from_secs(8),
            block_after_failures: 10,
            block_duration: Duration::from_secs(300),
            idle_timeout: Duration::from_secs(900),
            prune_interval: Duration::from_secs(30),
            max_tracked_ips: 65_536,
            max_pending_attempts_per_ip: 4,
        }
    }
}

impl AuthPolicyConfig {
    pub fn validate(&self) -> Result<(), String> {
        if self.backoff_after_failures == 0 {
            return Err("auth backoff threshold must be at least 1".to_string());
        }
        if self.block_after_failures <= self.backoff_after_failures {
            return Err("auth block threshold must exceed the backoff threshold".to_string());
        }
        if self.backoff_base.is_zero() {
            return Err("auth backoff base must be greater than zero".to_string());
        }
        if self.backoff_max < self.backoff_base {
            return Err("auth backoff maximum must not be below the base".to_string());
        }
        if self.block_duration.is_zero()
            || self.idle_timeout.is_zero()
            || self.prune_interval.is_zero()
        {
            return Err(
                "auth block, idle, and prune durations must be greater than zero".to_string()
            );
        }
        if self.max_tracked_ips == 0 || self.max_pending_attempts_per_ip == 0 {
            return Err("auth state and pending-attempt bounds must be at least 1".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct AuthAttempt {
    id: u64,
    ip: IpAddr,
    tracked: bool,
}

impl AuthAttempt {
    #[cfg(test)]
    pub(crate) fn ip(self) -> IpAddr {
        self.ip
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum AuthAdmission {
    Allowed(AuthAttempt),
    Backoff { retry_after: Duration },
    Blocked { retry_after: Duration },
    StateCapacity,
    PendingCapacity,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum AuthTerminal {
    Succeeded,
    Failed,
    Abandoned,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum AuthCompletion {
    Succeeded,
    Failed,
    FailedWithBackoff { delay: Duration },
    FailedAndBlocked { duration: Duration },
    Abandoned,
    Duplicate,
    Disabled,
}

#[derive(Debug)]
struct AuthIpState {
    consecutive_failures: u32,
    active_attempts: HashSet<u64>,
    backoff_until: Option<Duration>,
    blocked_until: Option<Duration>,
    last_seen: Duration,
}

impl AuthIpState {
    fn new(now: Duration) -> Self {
        Self {
            consecutive_failures: 0,
            active_attempts: HashSet::new(),
            backoff_until: None,
            blocked_until: None,
            last_seen: now,
        }
    }

    fn reset_expired_block(&mut self, now: Duration) {
        if self.blocked_until.is_some_and(|until| now >= until) {
            self.consecutive_failures = 0;
            self.backoff_until = None;
            self.blocked_until = None;
        }
    }
}

/// Monotonic, bounded per-IP QKey authentication policy.
pub(crate) struct AuthRateLimiter {
    config: AuthPolicyConfig,
    anchor: Instant,
    clock: ProtocolClock,
    last_now: Duration,
    next_prune: Duration,
    next_attempt_id: u64,
    states: HashMap<IpAddr, AuthIpState>,
}

impl AuthRateLimiter {
    #[allow(dead_code)]
    pub(crate) fn new(config: AuthPolicyConfig) -> Self {
        Self::new_with_clock(config, &ProtocolClock::default())
    }

    pub(crate) fn new_with_clock(config: AuthPolicyConfig, clock: &ProtocolClock) -> Self {
        Self {
            config,
            anchor: clock.now(),
            clock: clock.clone(),
            last_now: Duration::ZERO,
            next_prune: Duration::ZERO,
            next_attempt_id: 1,
            states: HashMap::new(),
        }
    }

    pub(crate) fn begin(&mut self, ip: IpAddr) -> AuthAdmission {
        self.begin_at(ip, self.clock.elapsed_since(self.anchor))
    }

    pub(crate) fn complete(
        &mut self,
        attempt: AuthAttempt,
        terminal: AuthTerminal,
    ) -> AuthCompletion {
        self.complete_at(attempt, terminal, self.clock.elapsed_since(self.anchor))
    }

    pub(crate) fn prune_if_due(&mut self) -> usize {
        self.prune_if_due_at(self.clock.elapsed_since(self.anchor))
    }

    pub(crate) fn tracked_ips(&self) -> usize {
        self.states.len()
    }

    fn normalize_now(&mut self, now: Duration) -> Duration {
        self.last_now = self.last_now.max(now);
        self.last_now
    }

    fn begin_at(&mut self, ip: IpAddr, now: Duration) -> AuthAdmission {
        let now = self.normalize_now(now);
        if !self.config.enabled {
            return AuthAdmission::Allowed(AuthAttempt { id: 0, ip, tracked: false });
        }

        self.prune_if_due_at(now);
        if !self.states.contains_key(&ip) && self.states.len() >= self.config.max_tracked_ips {
            self.prune_idle_at(now);
            if self.states.len() >= self.config.max_tracked_ips {
                return AuthAdmission::StateCapacity;
            }
        }

        let state = self.states.entry(ip).or_insert_with(|| AuthIpState::new(now));
        state.last_seen = now;
        state.reset_expired_block(now);
        if let Some(until) = state.blocked_until.filter(|until| *until > now) {
            return AuthAdmission::Blocked { retry_after: until.saturating_sub(now) };
        }
        if let Some(until) = state.backoff_until.filter(|until| *until > now) {
            return AuthAdmission::Backoff { retry_after: until.saturating_sub(now) };
        }
        state.backoff_until = None;
        if state.active_attempts.len() >= self.config.max_pending_attempts_per_ip {
            return AuthAdmission::PendingCapacity;
        }

        let id = self.next_attempt_id;
        self.next_attempt_id = self.next_attempt_id.wrapping_add(1).max(1);
        state.active_attempts.insert(id);
        AuthAdmission::Allowed(AuthAttempt { id, ip, tracked: true })
    }

    fn complete_at(
        &mut self,
        attempt: AuthAttempt,
        terminal: AuthTerminal,
        now: Duration,
    ) -> AuthCompletion {
        let now = self.normalize_now(now);
        if !attempt.tracked {
            return AuthCompletion::Disabled;
        }
        let Some(state) = self.states.get_mut(&attempt.ip) else {
            return AuthCompletion::Duplicate;
        };
        if !state.active_attempts.remove(&attempt.id) {
            return AuthCompletion::Duplicate;
        }
        state.last_seen = now;

        match terminal {
            AuthTerminal::Succeeded => {
                state.consecutive_failures = 0;
                state.backoff_until = None;
                state.blocked_until = None;
                if state.active_attempts.is_empty() {
                    self.states.remove(&attempt.ip);
                }
                AuthCompletion::Succeeded
            }
            AuthTerminal::Abandoned => {
                if state.active_attempts.is_empty() && state.consecutive_failures == 0 {
                    self.states.remove(&attempt.ip);
                }
                AuthCompletion::Abandoned
            }
            AuthTerminal::Failed => {
                state.consecutive_failures = state.consecutive_failures.saturating_add(1);
                if state.consecutive_failures >= self.config.block_after_failures {
                    state.backoff_until = None;
                    state.blocked_until = Some(now.saturating_add(self.config.block_duration));
                    return AuthCompletion::FailedAndBlocked {
                        duration: self.config.block_duration,
                    };
                }
                if state.consecutive_failures >= self.config.backoff_after_failures {
                    let exponent = state.consecutive_failures - self.config.backoff_after_failures;
                    let multiplier = 1u32.checked_shl(exponent.min(31)).unwrap_or(u32::MAX);
                    let delay = self
                        .config
                        .backoff_base
                        .checked_mul(multiplier)
                        .unwrap_or(self.config.backoff_max)
                        .min(self.config.backoff_max);
                    state.backoff_until = Some(now.saturating_add(delay));
                    return AuthCompletion::FailedWithBackoff { delay };
                }
                AuthCompletion::Failed
            }
        }
    }

    fn prune_if_due_at(&mut self, now: Duration) -> usize {
        let now = self.normalize_now(now);
        if now < self.next_prune {
            return 0;
        }
        self.next_prune = now.saturating_add(self.config.prune_interval);
        self.prune_idle_at(now)
    }

    fn prune_idle_at(&mut self, now: Duration) -> usize {
        let before = self.states.len();
        let idle_timeout = self.config.idle_timeout;
        self.states.retain(|_, state| {
            state.reset_expired_block(now);
            !state.active_attempts.is_empty()
                || state.blocked_until.is_some_and(|until| until > now)
                || state.backoff_until.is_some_and(|until| until > now)
                || now.saturating_sub(state.last_seen) < idle_timeout
        });
        before.saturating_sub(self.states.len())
    }
}

// ---------------------------------------------------------------------------
// Global rate limiter — server-wide PPS cap across ALL IPs.
//
// Prevents total server overload when many IPs each stay under the per-IP
// limit but their aggregate traffic saturates the host. Implemented with
// `AtomicU64` counters and a lock-free CAS refill loop so the hot path
// performs no heap allocations and no mutex contention.
// ---------------------------------------------------------------------------

/// Global, server-wide token-bucket rate limiter.
///
/// Tracks the total packet rate across every source IP. A single shared
/// bucket caps aggregate ingress; when it is exhausted every new packet is
/// dropped regardless of origin. The bucket refills continuously at
/// `refill_per_sec` up to `capacity` (burst) tokens.
pub struct GlobalRateLimiter {
    /// Current token count.
    tokens: AtomicU64,
    /// Monotonic timestamp (nanoseconds since `anchor`) of the last refill.
    last_refill_ns: AtomicU64,
    /// Burst capacity (max tokens the bucket can hold).
    capacity: u64,
    /// Sustained refill rate in tokens per second.
    refill_per_sec: u64,
    /// Anchor instant used to derive a stable monotonic nanosecond clock.
    anchor: Instant,
    /// Clock owning the anchor domain.
    clock: ProtocolClock,
    /// Total packets accepted (for PPS estimation by the DDoS detector).
    pub(crate) accepted: AtomicU64,
    /// Timestamp (ns since anchor) of the last PPS snapshot.
    last_pps_ns: AtomicU64,
    /// Accepted-packet total captured by the last PPS snapshot.
    last_pps_accepted: AtomicU64,
    /// Whether the first PPS baseline has been captured.
    pps_initialized: AtomicBool,
    /// Last computed PPS snapshot.
    last_pps: AtomicU64,
}

impl GlobalRateLimiter {
    /// Create a new global rate limiter.
    ///
    /// `refill_per_sec` is the sustained server-wide PPS cap; `capacity` is the
    /// burst size (defaults to `2 × refill_per_sec` when 0).
    pub fn new(refill_per_sec: u64, capacity: u64) -> Self {
        Self::new_with_clock(refill_per_sec, capacity, &ProtocolClock::default())
    }

    /// Create a global limiter bound to an explicit protocol clock.
    pub fn new_with_clock(refill_per_sec: u64, capacity: u64, clock: &ProtocolClock) -> Self {
        let cap = if capacity == 0 { refill_per_sec.saturating_mul(2) } else { capacity };
        let anchor = clock.now();
        Self {
            tokens: AtomicU64::new(cap),
            last_refill_ns: AtomicU64::new(0),
            capacity: cap,
            refill_per_sec,
            anchor,
            clock: clock.clone(),
            accepted: AtomicU64::new(0),
            last_pps_ns: AtomicU64::new(0),
            last_pps_accepted: AtomicU64::new(0),
            pps_initialized: AtomicBool::new(false),
            last_pps: AtomicU64::new(0),
        }
    }

    /// Create a limiter with the default global cap (50,000 PPS).
    pub fn with_default_cap() -> Self {
        Self::new(DEFAULT_GLOBAL_RATE_LIMIT_PPS, 0)
    }

    /// Create the default global limiter with an explicit protocol clock.
    pub fn with_default_cap_with_clock(clock: &ProtocolClock) -> Self {
        Self::new_with_clock(DEFAULT_GLOBAL_RATE_LIMIT_PPS, 0, clock)
    }

    #[inline]
    fn now_ns(&self) -> u64 {
        self.clock.elapsed_since(self.anchor).as_nanos() as u64
    }

    /// Check whether one packet is allowed under the global cap.
    ///
    /// Lock-free: refills via a CAS on `last_refill_ns` (only the winning
    /// thread applies the refill), then consumes one token via a CAS loop.
    /// No heap allocation, no mutex.
    pub fn check(&self) -> bool {
        self.check_at(self.now_ns())
    }

    fn check_at(&self, now: u64) -> bool {
        let last = self.last_refill_ns.load(Ordering::Relaxed);
        if now > last {
            let elapsed = now - last;
            // u128 multiply avoids overflow for very large idle gaps.
            let refill = ((elapsed as u128) * (self.refill_per_sec as u128) / 1_000_000_000) as u64;
            if refill > 0 {
                // Claim the refill slot: only the thread that wins this CAS
                // applies the token top-up, preventing double-refill races.
                if self
                    .last_refill_ns
                    .compare_exchange(last, now, Ordering::Relaxed, Ordering::Relaxed)
                    .is_ok()
                {
                    let mut cur = self.tokens.load(Ordering::Relaxed);
                    loop {
                        let new = cur.saturating_add(refill).min(self.capacity);
                        match self.tokens.compare_exchange(
                            cur,
                            new,
                            Ordering::Relaxed,
                            Ordering::Relaxed,
                        ) {
                            Ok(_) => break,
                            Err(actual) => cur = actual,
                        }
                    }
                }
            }
        }

        // Consume one token.
        let mut cur = self.tokens.load(Ordering::Relaxed);
        loop {
            if cur == 0 {
                return false;
            }
            match self.tokens.compare_exchange(cur, cur - 1, Ordering::Relaxed, Ordering::Relaxed) {
                Ok(_) => {
                    self.accepted.fetch_add(1, Ordering::Relaxed);
                    return true;
                }
                Err(actual) => cur = actual,
            }
        }
    }

    /// Current available tokens (best-effort snapshot, for metrics/tests).
    pub fn available_tokens(&self) -> u64 {
        self.tokens.load(Ordering::Relaxed)
    }

    /// Configured sustained refill rate (tokens/sec).
    pub fn refill_per_sec(&self) -> u64 {
        self.refill_per_sec
    }

    /// Configured burst capacity.
    pub fn capacity(&self) -> u64 {
        self.capacity
    }

    /// Estimated current packets-per-second rate (TODO-459). Computes a
    /// snapshot from the total accepted-packet counter and the elapsed time
    /// since the last snapshot. Best-effort; safe to call from any thread.
    pub fn current_pps(&self) -> u64 {
        let total = self.accepted.load(Ordering::Relaxed);
        self.sample_pps_at(self.now_ns(), total)
    }

    fn sample_pps_at(&self, now_ns: u64, accepted_total: u64) -> u64 {
        if !self.pps_initialized.swap(true, Ordering::AcqRel) {
            self.last_pps_ns.store(now_ns, Ordering::Relaxed);
            self.last_pps_accepted.store(accepted_total, Ordering::Relaxed);
            self.last_pps.store(0, Ordering::Relaxed);
            return 0;
        }

        let last_ns = self.last_pps_ns.swap(now_ns, Ordering::AcqRel);
        let last_total = self.last_pps_accepted.swap(accepted_total, Ordering::AcqRel);
        let elapsed_ns = now_ns.saturating_sub(last_ns);
        if elapsed_ns == 0 {
            return self.last_pps.load(Ordering::Relaxed);
        }

        let accepted_delta = accepted_total.saturating_sub(last_total);
        let pps = (accepted_delta as u128 * 1_000_000_000 / elapsed_ns as u128)
            .min(u64::MAX as u128) as u64;
        self.last_pps.store(pps, Ordering::Relaxed);
        pps
    }
}

// ---------------------------------------------------------------------------
// EWMA-based anomaly detection.
//
// Tracks an exponentially-weighted moving average of the observed packet
// rate. When the current rate exceeds `spike_multiplier × EWMA`, an anomaly
// is flagged and callers can apply stricter per-IP limiting (e.g. halve the
// per-IP limit). The EWMA is stored as an `f64` behind an `AtomicU64` (bit
// pattern) so the hot path stays lock-free and allocation-free.
// ---------------------------------------------------------------------------

/// Default EWMA smoothing factor (α). Higher α reacts faster to changes.
pub const DEFAULT_EWMA_ALPHA: f64 = 0.1;
/// Default spike multiplier: current rate must exceed 3× the EWMA.
pub const DEFAULT_SPIKE_MULTIPLIER: f64 = 3.0;

/// Validated sustained-anomaly and enhanced-admission policy.
#[derive(Clone, Debug, PartialEq)]
pub struct DdosPolicyConfig {
    pub enabled: bool,
    pub sample_interval: Duration,
    pub activation_window: Duration,
    pub clear_window: Duration,
    pub ewma_alpha: f64,
    pub spike_multiplier: f64,
    pub clear_factor: f64,
    pub enhanced_packet_cost: u64,
    pub retry_enabled: bool,
    pub retry_token_lifetime: Duration,
}

impl Default for DdosPolicyConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            sample_interval: Duration::from_secs(1),
            activation_window: Duration::from_secs(5),
            clear_window: Duration::from_secs(15),
            ewma_alpha: DEFAULT_EWMA_ALPHA,
            spike_multiplier: DEFAULT_SPIKE_MULTIPLIER,
            clear_factor: 1.5,
            enhanced_packet_cost: 2,
            retry_enabled: true,
            retry_token_lifetime: Duration::from_secs(10),
        }
    }
}

impl DdosPolicyConfig {
    pub fn validate(&self) -> Result<(), String> {
        if self.sample_interval.is_zero()
            || self.activation_window.is_zero()
            || self.clear_window.is_zero()
            || self.retry_token_lifetime.is_zero()
        {
            return Err(
                "DDoS sample, activation, clear, and Retry-token durations must be greater than zero"
                    .to_string(),
            );
        }
        if !self.ewma_alpha.is_finite() || self.ewma_alpha <= 0.0 || self.ewma_alpha > 1.0 {
            return Err("DDoS EWMA alpha must be finite and within (0, 1]".to_string());
        }
        if !self.spike_multiplier.is_finite() || self.spike_multiplier <= 1.0 {
            return Err("DDoS spike multiplier must be finite and greater than 1".to_string());
        }
        if !self.clear_factor.is_finite()
            || self.clear_factor <= 0.0
            || self.clear_factor >= self.spike_multiplier
        {
            return Err(
                "DDoS clear factor must be finite, greater than zero, and below the spike multiplier"
                    .to_string(),
            );
        }
        if self.enhanced_packet_cost < 2 {
            return Err("DDoS enhanced packet cost must be at least 2".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DdosTransition {
    Unchanged,
    Activated,
    Cleared,
}

#[derive(Debug, Default)]
struct AnomalyTimingState {
    last_now: Duration,
    activation_since: Option<Duration>,
    activation_baseline: f64,
    clear_since: Option<Duration>,
}

/// EWMA-based DDoS/anomaly detector.
///
/// A background sampler calls `record_pps` with the observed PPS each tick.
/// `is_anomaly` reports whether a sustained spike is currently active. New
/// traffic then consumes the validated enhanced per-IP token cost until the
/// rate remains below the frozen pre-spike baseline threshold for the clear
/// window.
#[allow(dead_code)] // public API for admin tooling / future wiring
pub struct EwmaAnomalyDetector {
    /// EWMA of PPS, stored as `f64::to_bits`.
    ewma_pps: AtomicU64,
    /// Most recent PPS sample.
    current_pps: AtomicU64,
    /// Whether enhanced (stricter) limiting is currently active.
    anomaly_active: AtomicBool,
    config: DdosPolicyConfig,
    anchor: Instant,
    clock: ProtocolClock,
    timing: parking_lot::Mutex<AnomalyTimingState>,
}

#[allow(dead_code)] // public API for admin tooling / future wiring
impl EwmaAnomalyDetector {
    /// Create a detector with the given smoothing and spike threshold.
    pub fn new(alpha: f64, spike_multiplier: f64) -> Self {
        Self::new_with_clock(alpha, spike_multiplier, &ProtocolClock::default())
    }

    /// Create a detector bound to an explicit protocol clock.
    ///
    /// This legacy infallible API accepts arbitrary parameters. Validation is
    /// retained by [`Self::with_config_and_clock`]; the narrow disposition
    /// preserves the established API for callers that have already validated
    /// their configuration.
    #[allow(clippy::expect_used)]
    pub fn new_with_clock(alpha: f64, spike_multiplier: f64, clock: &ProtocolClock) -> Self {
        let config =
            DdosPolicyConfig { ewma_alpha: alpha, spike_multiplier, ..DdosPolicyConfig::default() };
        Self::with_config_and_clock(config, clock)
            .expect("legacy DDoS detector parameters must be valid")
    }

    pub fn with_config(config: DdosPolicyConfig) -> Result<Self, String> {
        Self::with_config_and_clock(config, &ProtocolClock::default())
    }

    pub fn with_config_and_clock(
        config: DdosPolicyConfig,
        clock: &ProtocolClock,
    ) -> Result<Self, String> {
        config.validate()?;
        Ok(Self {
            ewma_pps: AtomicU64::new(0f64.to_bits()),
            current_pps: AtomicU64::new(0),
            anomaly_active: AtomicBool::new(false),
            config,
            anchor: clock.now(),
            clock: clock.clone(),
            timing: parking_lot::Mutex::new(AnomalyTimingState::default()),
        })
    }

    /// Create a detector with sensible defaults (α=0.1, spike=3×).
    #[allow(clippy::expect_used)]
    pub fn with_defaults() -> Self {
        Self::with_config(DdosPolicyConfig::default()).expect("default DDoS policy must be valid")
    }

    /// Record an observed PPS sample at the detector's monotonic clock.
    pub fn record_pps(&self, pps: u64) -> DdosTransition {
        self.record_pps_at(pps, self.clock.elapsed_since(self.anchor))
    }

    /// Record a deterministic monotonic sample.
    pub fn record_pps_at(&self, pps: u64, now: Duration) -> DdosTransition {
        self.current_pps.store(pps, Ordering::Relaxed);

        let prev_ewma = f64::from_bits(self.ewma_pps.load(Ordering::Relaxed));

        let mut prev_bits = self.ewma_pps.load(Ordering::Relaxed);
        loop {
            let prev = f64::from_bits(prev_bits);
            let next = if prev == 0.0 {
                pps as f64
            } else {
                self.config.ewma_alpha * pps as f64 + (1.0 - self.config.ewma_alpha) * prev
            };
            let next_bits = next.to_bits();
            match self.ewma_pps.compare_exchange(
                prev_bits,
                next_bits,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(actual) => prev_bits = actual,
            }
        }

        let mut timing = self.timing.lock();
        timing.last_now = timing.last_now.max(now);
        let now = timing.last_now;
        if !self.config.enabled {
            let was_active = self.anomaly_active.swap(false, Ordering::AcqRel);
            timing.activation_since = None;
            timing.clear_since = None;
            timing.activation_baseline = 0.0;
            return if was_active { DdosTransition::Cleared } else { DdosTransition::Unchanged };
        }

        if self.anomaly_active.load(Ordering::Acquire) {
            let clear_threshold = self.config.clear_factor * timing.activation_baseline;
            if pps as f64 <= clear_threshold {
                let clear_since = *timing.clear_since.get_or_insert(now);
                if now.saturating_sub(clear_since) >= self.config.clear_window {
                    self.anomaly_active.store(false, Ordering::Release);
                    timing.activation_since = None;
                    timing.clear_since = None;
                    timing.activation_baseline = 0.0;
                    return DdosTransition::Cleared;
                }
            } else {
                timing.clear_since = None;
            }
            return DdosTransition::Unchanged;
        }

        let baseline =
            if timing.activation_since.is_some() { timing.activation_baseline } else { prev_ewma };
        let spike = baseline > 0.0 && pps as f64 > self.config.spike_multiplier * baseline;
        if !spike {
            timing.activation_since = None;
            timing.activation_baseline = 0.0;
            return DdosTransition::Unchanged;
        }

        if timing.activation_since.is_none() {
            timing.activation_since = Some(now);
            timing.activation_baseline = prev_ewma;
        }
        let activation_since = timing.activation_since.unwrap_or(now);
        if now.saturating_sub(activation_since) >= self.config.activation_window {
            self.anomaly_active.store(true, Ordering::Release);
            timing.clear_since = None;
            return DdosTransition::Activated;
        }
        DdosTransition::Unchanged
    }

    pub fn sample_interval(&self) -> Duration {
        self.config.sample_interval
    }

    pub fn enhanced_packet_cost(&self) -> u64 {
        if self.is_anomaly() {
            self.config.enhanced_packet_cost
        } else {
            1
        }
    }

    /// Whether a traffic anomaly (spike) is currently active.
    pub fn is_anomaly(&self) -> bool {
        self.anomaly_active.load(Ordering::Relaxed)
    }

    /// Per-IP limit multiplier to apply. Returns `0.5` while an anomaly is
    /// active (halving per-IP limits) and `1.0` otherwise.
    pub fn limit_multiplier(&self) -> f64 {
        if self.is_anomaly() {
            0.5
        } else {
            1.0
        }
    }

    /// Current EWMA value (best-effort snapshot).
    pub fn ewma(&self) -> f64 {
        f64::from_bits(self.ewma_pps.load(Ordering::Relaxed))
    }

    /// Most recent PPS sample.
    pub fn current_pps(&self) -> u64 {
        self.current_pps.load(Ordering::Relaxed)
    }

    /// Force-clear the anomaly flag (for tests / manual reset).
    pub fn clear(&self) {
        self.anomaly_active.store(false, Ordering::Relaxed);
        let mut timing = self.timing.lock();
        timing.activation_since = None;
        timing.clear_since = None;
        timing.activation_baseline = 0.0;
    }
}

// ---------------------------------------------------------------------------
// GeoIP blocking.
//
// Uses the `maxminddb` crate to look up the country of an IP address in a
// MaxMindDB GeoLite2 (or GeoIP2) country database. IPs mapping to a blocked
// country are rejected. A configured database is a startup dependency: the
// server must not silently continue with an inactive policy.
// ---------------------------------------------------------------------------

/// Configuration for GeoIP-based country blocking.
#[derive(Clone, Debug, Default)]
pub struct GeoIpConfig {
    /// Path to a MaxMindDB GeoLite2 (or equivalent) country database.
    pub db_path: Option<PathBuf>,
    /// ISO country codes to block (e.g. "CN", "RU", "KP").
    pub blocked_countries: HashSet<String>,
}

impl GeoIpConfig {
    /// Validate the activation contract without touching the database.
    pub fn validate(&self) -> Result<(), GeoIpError> {
        match (self.db_path.is_some(), self.blocked_countries.is_empty()) {
            (false, true) => return Ok(()),
            (false, false) => return Err(GeoIpError::DatabasePathRequired),
            (true, true) => return Err(GeoIpError::BlockedCountriesRequired),
            (true, false) => {}
        }

        for country in &self.blocked_countries {
            if country.len() != 2 || !country.bytes().all(|byte| byte.is_ascii_uppercase()) {
                return Err(GeoIpError::InvalidCountryCode(country.clone()));
            }
        }
        Ok(())
    }

    /// Whether both a database path and at least one blocked country are configured.
    pub fn is_enabled(&self) -> bool {
        self.db_path.is_some() && !self.blocked_countries.is_empty()
    }
}

/// Actual GeoIP activation state exposed by runtime status and metrics.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum GeoIpStatus {
    Disabled = 0,
    Active = 1,
    Failed = 2,
}

impl GeoIpStatus {
    /// Stable status label for logs, JSON, and Prometheus labels.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Disabled => "disabled",
            Self::Active => "active",
            Self::Failed => "failed",
        }
    }
}

/// Typed startup failures for configured GeoIP activation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum GeoIpError {
    /// A country policy was configured without a database path.
    DatabasePathRequired,
    /// A database path was configured without at least one country code.
    BlockedCountriesRequired,
    /// A country code is not an uppercase ISO 3166-1 alpha-2 code.
    InvalidCountryCode(String),
    /// The configured path does not exist.
    MissingDatabase(PathBuf),
    /// The database file exists but is empty.
    EmptyDatabase(PathBuf),
    /// The database path cannot be read or is not a regular file.
    UnreadableDatabase { path: PathBuf, reason: String },
    /// The MaxMind database is malformed or failed full structural verification.
    InvalidDatabase { path: PathBuf, reason: String },
    /// The database is valid MaxMind data but is not a country database.
    UnsupportedDatabase { path: PathBuf, database_type: String },
}

impl std::fmt::Display for GeoIpError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::DatabasePathRequired => {
                formatter.write_str("GeoIP blocked countries require a database path")
            }
            Self::BlockedCountriesRequired => {
                formatter.write_str("GeoIP database path requires at least one blocked country")
            }
            Self::InvalidCountryCode(code) => write!(
                formatter,
                "invalid GeoIP country code {code:?}; expected uppercase ISO 3166-1 alpha-2"
            ),
            Self::MissingDatabase(path) => {
                write!(formatter, "GeoIP database is missing: {}", path.display())
            }
            Self::EmptyDatabase(path) => {
                write!(formatter, "GeoIP database is empty: {}", path.display())
            }
            Self::UnreadableDatabase { path, reason } => write!(
                formatter,
                "GeoIP database is unreadable at {}: {reason}",
                path.display()
            ),
            Self::InvalidDatabase { path, reason } => write!(
                formatter,
                "GeoIP database is invalid at {}: {reason}",
                path.display()
            ),
            Self::UnsupportedDatabase { path, database_type } => write!(
                formatter,
                "GeoIP database at {} has unsupported type {database_type:?}; expected a country database",
                path.display()
            ),
        }
    }
}

impl std::error::Error for GeoIpError {}

/// Bounded lookup/decode failures after a database was activated.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum GeoIpLookupError {
    /// The MaxMind search tree could not resolve the source address.
    Lookup { ip: IpAddr, reason: String },
    /// The matched record could not be decoded as a country record.
    Decode { ip: IpAddr, reason: String },
    /// A matched record had no country payload or ISO code.
    MissingCountryRecord { ip: IpAddr },
}

impl std::fmt::Display for GeoIpLookupError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Lookup { ip, reason } => {
                write!(formatter, "GeoIP lookup failed for {ip}: {reason}")
            }
            Self::Decode { ip, reason } => {
                write!(formatter, "GeoIP decode failed for {ip}: {reason}")
            }
            Self::MissingCountryRecord { ip } => {
                write!(formatter, "GeoIP record for {ip} has no country ISO code")
            }
        }
    }
}

impl std::error::Error for GeoIpLookupError {}

/// GeoIP-based source-IP blocker.
///
/// Loads and fully verifies a MaxMindDB country database during construction
/// and performs bounded lookups per IP. When no policy is configured, the
/// blocker is disabled and lookup is a zero-cost allow path.
pub struct GeoIpBlocker {
    config: GeoIpConfig,
    reader: Option<maxminddb::Reader<Vec<u8>>>,
}

impl GeoIpBlocker {
    /// Validate and activate a blocker from the given config.
    pub fn try_new(config: GeoIpConfig) -> Result<Self, GeoIpError> {
        config.validate()?;
        let Some(path) = config.db_path.as_ref() else {
            return Ok(Self { config, reader: None });
        };

        let metadata = std::fs::metadata(path).map_err(|error| {
            if error.kind() == std::io::ErrorKind::NotFound {
                GeoIpError::MissingDatabase(path.clone())
            } else {
                GeoIpError::UnreadableDatabase { path: path.clone(), reason: error.to_string() }
            }
        })?;
        if !metadata.is_file() {
            return Err(GeoIpError::UnreadableDatabase {
                path: path.clone(),
                reason: "path is not a regular file".to_string(),
            });
        }
        if metadata.len() == 0 {
            return Err(GeoIpError::EmptyDatabase(path.clone()));
        }

        let reader = maxminddb::Reader::open_readfile(path)
            .map_err(|error| map_geoip_database_error(path, error))?;
        reader.verify().map_err(|error| GeoIpError::InvalidDatabase {
            path: path.clone(),
            reason: error.to_string(),
        })?;
        let database_type = reader.metadata().database_type.clone();
        if !database_type.to_ascii_lowercase().contains("country") {
            return Err(GeoIpError::UnsupportedDatabase { path: path.clone(), database_type });
        }

        log::info!(
            "GeoIP: active country database loaded from {} with {} blocked countries",
            path.display(),
            config.blocked_countries.len()
        );
        Ok(Self { config, reader: Some(reader) })
    }

    /// Create a blocker with no database and no blocked countries (no-op).
    pub fn disabled() -> Self {
        Self { config: GeoIpConfig::default(), reader: None }
    }

    /// Whether the country database was actually loaded and verified.
    pub fn is_enabled(&self) -> bool {
        self.reader.is_some()
    }

    /// Return the actual loaded-policy state.
    pub fn status(&self) -> GeoIpStatus {
        if self.is_enabled() {
            GeoIpStatus::Active
        } else {
            GeoIpStatus::Disabled
        }
    }

    /// Evaluate one source address. Lookup/decode failures are returned so the
    /// admission caller can drop the packet and record explicit telemetry.
    pub fn lookup(&self, ip: IpAddr) -> Result<bool, GeoIpLookupError> {
        let Some(reader) = self.reader.as_ref() else {
            return Ok(false);
        };

        let lookup_result = reader
            .lookup(ip)
            .map_err(|error| GeoIpLookupError::Lookup { ip, reason: error.to_string() })?;
        if !lookup_result.has_data() {
            return Ok(false);
        }
        let country = lookup_result
            .decode::<maxminddb::geoip2::Country>()
            .map_err(|error| GeoIpLookupError::Decode { ip, reason: error.to_string() })?
            .ok_or(GeoIpLookupError::MissingCountryRecord { ip })?;
        let Some(iso_code) = country.country.iso_code else {
            return Err(GeoIpLookupError::MissingCountryRecord { ip });
        };
        Ok(self.config.blocked_countries.contains(iso_code))
    }

    /// Returns `true` if the IP maps to a blocked country. A lookup failure is
    /// fail-closed for callers that cannot carry typed error telemetry.
    pub fn is_blocked(&self, ip: IpAddr) -> bool {
        self.lookup(ip).unwrap_or(true)
    }

    /// Borrow the configured blocked-country set.
    pub fn blocked_countries(&self) -> &HashSet<String> {
        &self.config.blocked_countries
    }
}

fn map_geoip_database_error(
    path: &std::path::Path,
    error: maxminddb::MaxMindDbError,
) -> GeoIpError {
    match error {
        maxminddb::MaxMindDbError::Io(error) if error.kind() == std::io::ErrorKind::NotFound => {
            GeoIpError::MissingDatabase(path.to_path_buf())
        }
        maxminddb::MaxMindDbError::Io(error) => {
            GeoIpError::UnreadableDatabase { path: path.to_path_buf(), reason: error.to_string() }
        }
        error => {
            GeoIpError::InvalidDatabase { path: path.to_path_buf(), reason: error.to_string() }
        }
    }
}

// ---------------------------------------------------------------------------
// Blacklist sync.
//
// Maintains a set of blocked IPs with per-entry TTL. Supports synchronization
// from external threat-intelligence feeds (plain-text IP lists, one per line).
// Lookups are O(1) under an RwLock read.
// ---------------------------------------------------------------------------

/// Error type for blacklist synchronization operations.
#[derive(Debug)]
pub enum BlacklistError {
    /// No sync URL configured.
    NoSyncUrl,
    /// Synchronization was cancelled by the owning runtime.
    Cancelled,
    /// HTTP fetch failed.
    FetchError(String),
    /// Bounded cache read or write failed.
    CacheError(String),
    /// The wall clock could not provide a valid epoch timestamp.
    Clock(crate::time_source::WallClockError),
    /// Configuration or feed content violated the bounded contract.
    InvalidData(String),
}

impl std::fmt::Display for BlacklistError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoSyncUrl => write!(f, "no blacklist sync URL configured"),
            Self::Cancelled => write!(f, "blacklist synchronization cancelled"),
            Self::FetchError(s) => write!(f, "blacklist fetch error: {s}"),
            Self::CacheError(s) => write!(f, "blacklist cache error: {s}"),
            Self::Clock(error) => write!(f, "blacklist wall-clock error: {error}"),
            Self::InvalidData(s) => write!(f, "invalid blacklist data: {s}"),
        }
    }
}

impl std::error::Error for BlacklistError {}

const BLACKLIST_SYNC_PHASE_FETCHING: u8 = 0;
const BLACKLIST_SYNC_PHASE_PUBLISHING: u8 = 1;
const BLACKLIST_SYNC_PHASE_FINISHED: u8 = 2;
const BLACKLIST_SYNC_PHASE_CANCELLED: u8 = 3;

/// Cancellation and publication-commit ownership shared by the runtime and
/// the blocking blacklist worker.
pub(crate) struct BlacklistSyncControl {
    cancel_requested: AtomicBool,
    phase: AtomicU8,
    cache_commit: parking_lot::Mutex<()>,
}

impl BlacklistSyncControl {
    pub(crate) fn new() -> Self {
        Self {
            cancel_requested: AtomicBool::new(false),
            phase: AtomicU8::new(BLACKLIST_SYNC_PHASE_FETCHING),
            cache_commit: parking_lot::Mutex::new(()),
        }
    }

    pub(crate) fn request_cancel(&self) {
        self.cancel_requested.store(true, Ordering::Release);
    }

    pub(crate) fn is_cancelled(&self) -> bool {
        self.cancel_requested.load(Ordering::Acquire)
            || self.phase.load(Ordering::Acquire) == BLACKLIST_SYNC_PHASE_CANCELLED
    }

    pub(crate) fn begin_publication(&self) -> bool {
        if self.is_cancelled() {
            return false;
        }
        if self
            .phase
            .compare_exchange(
                BLACKLIST_SYNC_PHASE_FETCHING,
                BLACKLIST_SYNC_PHASE_PUBLISHING,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_err()
        {
            return false;
        }
        if self.cancel_requested.load(Ordering::Acquire) {
            self.phase.store(BLACKLIST_SYNC_PHASE_CANCELLED, Ordering::Release);
            return false;
        }
        true
    }

    pub(crate) fn cancel_before_publication(&self) -> bool {
        self.request_cancel();
        match self.phase.compare_exchange(
            BLACKLIST_SYNC_PHASE_FETCHING,
            BLACKLIST_SYNC_PHASE_CANCELLED,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) | Err(BLACKLIST_SYNC_PHASE_CANCELLED) => true,
            Err(BLACKLIST_SYNC_PHASE_PUBLISHING) | Err(BLACKLIST_SYNC_PHASE_FINISHED) => false,
            Err(_) => false,
        }
    }

    pub(crate) fn publication_in_flight(&self) -> bool {
        self.phase.load(Ordering::Acquire) == BLACKLIST_SYNC_PHASE_PUBLISHING
    }

    pub(crate) fn finish(&self) {
        self.phase.store(BLACKLIST_SYNC_PHASE_FINISHED, Ordering::Release);
    }

    pub(crate) fn synchronize_publication_commit(&self) {
        drop(self.cache_commit.lock());
    }

    fn commit_publication<F>(&self, commit: F) -> std::io::Result<bool>
    where
        F: FnOnce() -> std::io::Result<()>,
    {
        let _commit = self.cache_commit.lock();
        if self.is_cancelled() {
            return Ok(false);
        }
        commit()?;
        Ok(true)
    }
}

fn load_blacklist_ca_bundle(
    path: &std::path::Path,
) -> Result<Vec<reqwest::Certificate>, BlacklistError> {
    let metadata = std::fs::metadata(path).map_err(|error| {
        BlacklistError::InvalidData(format!(
            "blacklist CA bundle metadata {}: {error}",
            path.display()
        ))
    })?;
    if !metadata.is_file() || metadata.len() == 0 {
        return Err(BlacklistError::InvalidData(format!(
            "blacklist CA bundle must be a non-empty regular file: {}",
            path.display()
        )));
    }
    if metadata.len() > MAX_BLACKLIST_CA_BUNDLE_BYTES {
        return Err(BlacklistError::InvalidData(format!(
            "blacklist CA bundle exceeds {MAX_BLACKLIST_CA_BUNDLE_BYTES} bytes: {}",
            path.display()
        )));
    }
    let pem = std::fs::read(path).map_err(|error| {
        BlacklistError::InvalidData(format!("blacklist CA bundle read {}: {error}", path.display()))
    })?;
    if pem.len() as u64 > MAX_BLACKLIST_CA_BUNDLE_BYTES {
        return Err(BlacklistError::InvalidData(format!(
            "blacklist CA bundle exceeds {MAX_BLACKLIST_CA_BUNDLE_BYTES} bytes after read: {}",
            path.display()
        )));
    }
    let certificates = reqwest::Certificate::from_pem_bundle(&pem).map_err(|error| {
        BlacklistError::InvalidData(format!(
            "blacklist CA bundle parse {}: {error}",
            path.display()
        ))
    })?;
    if certificates.is_empty() {
        return Err(BlacklistError::InvalidData(format!(
            "blacklist CA bundle contains no certificates: {}",
            path.display()
        )));
    }
    Ok(certificates)
}

/// External blacklist synchronizer with TTL-based expiry.
///
/// Tracks blocked IPs in a `HashMap<IpAddr, Instant>` (IP → expiry). Entries
/// auto-expire past their TTL; `prune_expired` reclaims memory. The `sync`
/// method fetches a plain-text IP list (one IP per line, lines starting with
/// `#` are comments) from the configured URL and replaces the blocked set.
pub struct BlacklistSync {
    blocked: Arc<parking_lot::RwLock<HashMap<IpAddr, Instant>>>,
    default_ttl: Duration,
    sync_url: Option<String>,
    sync_interval: Duration,
    request_timeout: Duration,
    max_body_bytes: usize,
    max_entries: usize,
    cache_path: Option<PathBuf>,
    custom_ca_certificates: Vec<reqwest::Certificate>,
    clock: ProtocolClock,
}

impl BlacklistSync {
    /// Create a new blacklist synchronizer.
    pub fn new(default_ttl: Duration, sync_url: Option<String>, sync_interval: Duration) -> Self {
        Self::new_with_clock(default_ttl, sync_url, sync_interval, &ProtocolClock::default())
    }

    /// Create a blacklist synchronizer bound to an explicit protocol clock.
    ///
    /// The legacy constructor supplies fixed validated bounds and keeps the
    /// original infallible API. Call [`Self::new_bounded_with_clock`] when the
    /// caller needs typed validation errors.
    #[allow(clippy::expect_used)]
    pub fn new_with_clock(
        default_ttl: Duration,
        sync_url: Option<String>,
        sync_interval: Duration,
        clock: &ProtocolClock,
    ) -> Self {
        Self::new_bounded_with_clock(
            default_ttl,
            sync_url,
            sync_interval,
            Duration::from_secs(30),
            MAX_BLACKLIST_BODY_BYTES,
            MAX_BLACKLIST_ENTRIES,
            None,
            clock,
        )
        .expect("legacy blacklist defaults must be valid")
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new_bounded(
        default_ttl: Duration,
        sync_url: Option<String>,
        sync_interval: Duration,
        request_timeout: Duration,
        max_body_bytes: usize,
        max_entries: usize,
        cache_path: Option<PathBuf>,
    ) -> Result<Self, BlacklistError> {
        Self::new_bounded_with_clock(
            default_ttl,
            sync_url,
            sync_interval,
            request_timeout,
            max_body_bytes,
            max_entries,
            cache_path,
            &ProtocolClock::default(),
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new_bounded_with_clock(
        default_ttl: Duration,
        sync_url: Option<String>,
        sync_interval: Duration,
        request_timeout: Duration,
        max_body_bytes: usize,
        max_entries: usize,
        cache_path: Option<PathBuf>,
        clock: &ProtocolClock,
    ) -> Result<Self, BlacklistError> {
        Self::new_bounded_with_ca_and_clock(
            default_ttl,
            sync_url,
            sync_interval,
            request_timeout,
            max_body_bytes,
            max_entries,
            cache_path,
            None,
            clock,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new_bounded_with_ca(
        default_ttl: Duration,
        sync_url: Option<String>,
        sync_interval: Duration,
        request_timeout: Duration,
        max_body_bytes: usize,
        max_entries: usize,
        cache_path: Option<PathBuf>,
        custom_ca_path: Option<PathBuf>,
    ) -> Result<Self, BlacklistError> {
        Self::new_bounded_with_ca_and_clock(
            default_ttl,
            sync_url,
            sync_interval,
            request_timeout,
            max_body_bytes,
            max_entries,
            cache_path,
            custom_ca_path,
            &ProtocolClock::default(),
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new_bounded_with_ca_and_clock(
        default_ttl: Duration,
        sync_url: Option<String>,
        sync_interval: Duration,
        request_timeout: Duration,
        max_body_bytes: usize,
        max_entries: usize,
        cache_path: Option<PathBuf>,
        custom_ca_path: Option<PathBuf>,
        clock: &ProtocolClock,
    ) -> Result<Self, BlacklistError> {
        if default_ttl.is_zero()
            || sync_interval.is_zero()
            || request_timeout.is_zero()
            || max_body_bytes == 0
            || max_entries == 0
        {
            return Err(BlacklistError::InvalidData(
                "TTL, sync interval, timeout, body cap, and entry cap must be nonzero".to_string(),
            ));
        }
        if default_ttl > Duration::from_secs(MAX_BLACKLIST_TTL_SECS) {
            return Err(BlacklistError::InvalidData(format!(
                "TTL exceeds {MAX_BLACKLIST_TTL_SECS} seconds"
            )));
        }
        if sync_interval > Duration::from_secs(MAX_BLACKLIST_SYNC_INTERVAL_SECS) {
            return Err(BlacklistError::InvalidData(format!(
                "sync interval exceeds {MAX_BLACKLIST_SYNC_INTERVAL_SECS} seconds"
            )));
        }
        if request_timeout > Duration::from_secs(MAX_BLACKLIST_REQUEST_TIMEOUT_SECS) {
            return Err(BlacklistError::InvalidData(format!(
                "request timeout exceeds {MAX_BLACKLIST_REQUEST_TIMEOUT_SECS} seconds"
            )));
        }
        if max_body_bytes > MAX_BLACKLIST_BODY_BYTES {
            return Err(BlacklistError::InvalidData(format!(
                "body cap exceeds {MAX_BLACKLIST_BODY_BYTES} bytes"
            )));
        }
        if max_entries > MAX_BLACKLIST_ENTRIES {
            return Err(BlacklistError::InvalidData(format!(
                "entry cap exceeds {MAX_BLACKLIST_ENTRIES} entries"
            )));
        }
        if sync_url.as_ref().is_some_and(|url| !url.starts_with("https://")) {
            return Err(BlacklistError::InvalidData(
                "blacklist sync URL must use HTTPS".to_string(),
            ));
        }
        let custom_ca_certificates = match custom_ca_path {
            Some(path) => load_blacklist_ca_bundle(&path)?,
            None => Vec::new(),
        };
        let synchronizer = Self {
            blocked: Arc::new(parking_lot::RwLock::new(HashMap::new())),
            default_ttl,
            sync_url,
            sync_interval,
            request_timeout,
            max_body_bytes,
            max_entries,
            cache_path,
            custom_ca_certificates,
            clock: clock.clone(),
        };
        if let Err(error) = synchronizer.load_cache() {
            log::warn!("Blacklist cache ignored: {error}");
        }
        Ok(synchronizer)
    }

    /// Create a synchronizer with no feed configured (manual blocking only).
    pub fn manual_only(default_ttl: Duration) -> Self {
        Self::manual_only_with_clock(default_ttl, &ProtocolClock::default())
    }

    /// Create a manual-only synchronizer with an explicit protocol clock.
    pub fn manual_only_with_clock(default_ttl: Duration, clock: &ProtocolClock) -> Self {
        Self::new_with_clock(default_ttl, None, Duration::from_secs(3600), clock)
    }

    /// Whether an IP is currently blocked (and not expired).
    pub fn is_blocked(&self, ip: IpAddr) -> bool {
        let now = self.clock.now();
        let guard = self.blocked.read();
        match guard.get(&ip) {
            Some(expiry) => *expiry > now,
            None => false,
        }
    }

    /// Add an IP to the blacklist with the default TTL.
    pub fn add(&self, ip: IpAddr) {
        self.add_with_ttl(ip, self.default_ttl);
    }

    /// Add an IP to the blacklist with a custom TTL.
    pub fn add_with_ttl(&self, ip: IpAddr, ttl: Duration) {
        let ttl = ttl.min(Duration::from_secs(MAX_BLACKLIST_TTL_SECS));
        let now = self.clock.now();
        let expiry = now.checked_add(ttl).unwrap_or(now);
        self.blocked.write().insert(ip, expiry);
    }

    /// Remove an IP from the blacklist.
    pub fn remove(&self, ip: IpAddr) {
        self.blocked.write().remove(&ip);
    }

    /// Replace the entire blocked set from an external feed (bulk sync).
    /// Each entry is seeded with the default TTL.
    pub fn replace_list(&self, ips: &[IpAddr]) {
        replace_blacklist_entries(&self.blocked, self.default_ttl, ips, &self.clock);
    }

    /// Number of currently-blocked (non-expired) IPs.
    pub fn len(&self) -> usize {
        let now = self.clock.now();
        self.blocked.read().values().filter(|e| **e > now).count()
    }

    /// Whether the blacklist is empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Prune expired entries to bound memory.
    pub fn prune_expired(&self) {
        let now = self.clock.now();
        self.blocked.write().retain(|_, expiry| *expiry > now);
    }

    /// Configured sync interval.
    pub fn sync_interval(&self) -> Duration {
        self.sync_interval
    }

    /// Whether an external sync URL is configured.
    pub fn has_sync_url(&self) -> bool {
        self.sync_url.is_some()
    }

    /// Synchronize the blacklist from the external feed.
    ///
    /// Fetches a plain-text IP list (one IP per line; lines starting with `#`
    /// or empty lines are ignored) from the configured URL via HTTPS and
    /// replaces the blocked set. Each entry is seeded with the default TTL.
    ///
    /// The response body is capped at the configured bound, which is itself
    /// validated against `MAX_BLACKLIST_BODY_BYTES`. Both the `Content-Length`
    /// header and the actual byte count are checked.
    ///
    /// Async because the server's housekeeping loop runs inside a Tokio
    /// runtime; using the async `reqwest::Client` avoids the
    /// "Cannot start a runtime from within a runtime" panic that
    /// `reqwest::blocking` triggers under Tokio. Callers outside an async
    /// context should wrap this in `tokio::task::spawn_blocking` + a
    /// `Runtime::block_on`, or use a dedicated runtime.
    pub async fn sync(&self) -> Result<usize, BlacklistError> {
        let control = Arc::new(BlacklistSyncControl::new());
        let result = self.sync_with_cancel(Arc::clone(&control)).await;
        control.finish();
        result
    }

    /// Synchronize the feed while honoring the owning worker's cancellation flag.
    pub(crate) async fn sync_with_cancel(
        &self,
        cancellation: Arc<BlacklistSyncControl>,
    ) -> Result<usize, BlacklistError> {
        let url = match &self.sync_url {
            Some(u) => u.clone(),
            None => return Err(BlacklistError::NoSyncUrl),
        };
        if cancellation.is_cancelled() {
            return Err(BlacklistError::Cancelled);
        }

        let mut client_builder = reqwest::Client::builder()
            .timeout(self.request_timeout)
            .https_only(true)
            .redirect(reqwest::redirect::Policy::limited(3))
            .user_agent("quicfuscate-blacklist-sync/1.0");
        for certificate in &self.custom_ca_certificates {
            client_builder = client_builder.add_root_certificate(certificate.clone());
        }
        let client = client_builder
            .build()
            .map_err(|e| BlacklistError::FetchError(format!("client build: {e}")))?;

        let mut response = client
            .get(&url)
            .send()
            .await
            .map_err(|e| BlacklistError::FetchError(format!("request: {e}")))?;

        if !response.status().is_success() {
            return Err(BlacklistError::FetchError(format!(
                "HTTP {} from {}",
                response.status(),
                url
            )));
        }

        // Pre-check Content-Length if the server provided it. A feed larger
        // than the cap is rejected before any body bytes are buffered.
        if let Some(len) = response.content_length() {
            if len > self.max_body_bytes as u64 {
                return Err(BlacklistError::FetchError(format!(
                    "feed body too large: Content-Length {len} > {} bytes",
                    self.max_body_bytes
                )));
            }
        }

        let mut body = Vec::with_capacity(
            response.content_length().unwrap_or(0).min(self.max_body_bytes as u64) as usize,
        );
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|error| BlacklistError::FetchError(format!("body read: {error}")))?
        {
            if cancellation.is_cancelled() {
                return Err(BlacklistError::Cancelled);
            }
            if body.len().saturating_add(chunk.len()) > self.max_body_bytes {
                return Err(BlacklistError::FetchError(format!(
                    "feed body exceeds {} bytes",
                    self.max_body_bytes
                )));
            }
            body.extend_from_slice(&chunk);
        }

        if !cancellation.begin_publication() {
            return Err(BlacklistError::Cancelled);
        }

        let max_body_bytes = self.max_body_bytes;
        let max_entries = self.max_entries;
        let default_ttl = self.default_ttl;
        let cache_path = self.cache_path.clone();
        let blocked = Arc::clone(&self.blocked);
        let clock = self.clock.clone();
        let cancellation_for_blocking = Arc::clone(&cancellation);
        let ips = tokio::task::spawn_blocking(move || {
            if cancellation_for_blocking.is_cancelled() {
                return Err(BlacklistError::Cancelled);
            }
            let ips = parse_blacklist_feed(&body, max_body_bytes, max_entries)?;
            if cancellation_for_blocking.is_cancelled() {
                return Err(BlacklistError::Cancelled);
            }
            publish_blacklist_feed(
                cache_path.as_deref(),
                default_ttl,
                max_body_bytes,
                &ips,
                &clock,
                &blocked,
                &cancellation_for_blocking,
            )?;
            Ok(ips.len())
        })
        .await
        .map_err(|error| BlacklistError::CacheError(format!("blocking publication: {error}")))??;

        let count = ips;
        log::info!("Blacklist sync: loaded {count} IPs from {url}");
        Ok(count)
    }

    #[cfg(test)]
    fn parse_feed(&self, body: &[u8]) -> Result<Vec<IpAddr>, BlacklistError> {
        parse_blacklist_feed(body, self.max_body_bytes, self.max_entries)
    }

    #[cfg(test)]
    fn apply_feed(&self, body: &[u8]) -> Result<usize, BlacklistError> {
        let ips = self.parse_feed(body)?;
        let count = ips.len();
        self.persist_cache(&ips)?;
        self.replace_list(&ips);
        Ok(count)
    }

    fn load_cache(&self) -> Result<usize, BlacklistError> {
        let Some(path) = self.cache_path.as_ref() else {
            return Ok(0);
        };
        let metadata = match std::fs::metadata(path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(0),
            Err(error) => {
                return Err(BlacklistError::CacheError(format!(
                    "metadata {}: {error}",
                    path.display()
                )))
            }
        };
        if metadata.len() > self.max_body_bytes as u64 {
            return Err(BlacklistError::CacheError(format!(
                "{} exceeds {} bytes",
                path.display(),
                self.max_body_bytes
            )));
        }
        let bytes = std::fs::read(path)
            .map_err(|error| BlacklistError::CacheError(format!("read: {error}")))?;
        let cache: BlacklistCache = serde_json::from_slice(&bytes)
            .map_err(|error| BlacklistError::CacheError(format!("parse: {error}")))?;
        if cache.version != 1 || cache.ips.len() > self.max_entries {
            return Err(BlacklistError::CacheError(
                "unsupported version or entry bound exceeded".to_string(),
            ));
        }
        let now = crate::time_source::unix_epoch_seconds(self.clock.now_system())
            .map_err(BlacklistError::Clock)?;
        if cache.expires_at_secs <= now {
            return Err(BlacklistError::CacheError("cache is stale".to_string()));
        }
        if cache.expires_at_secs.saturating_sub(now) > MAX_BLACKLIST_TTL_SECS {
            return Err(BlacklistError::CacheError("cache TTL exceeds absolute bound".to_string()));
        }
        let mut unique: HashSet<IpAddr> = cache.ips.into_iter().collect();
        if unique.len() > self.max_entries {
            return Err(BlacklistError::CacheError("cache entry bound exceeded".to_string()));
        }
        let remaining = Duration::from_secs(cache.expires_at_secs - now);
        let now = self.clock.now();
        let expiry = now.checked_add(remaining).unwrap_or(now);
        let count = unique.len();
        self.blocked.write().extend(unique.drain().map(|ip| (ip, expiry)));
        log::info!("Blacklist cache: loaded {count} entries from {}", path.display());
        Ok(count)
    }

    #[cfg(test)]
    fn persist_cache(&self, ips: &[IpAddr]) -> Result<(), BlacklistError> {
        persist_blacklist_cache(
            self.cache_path.as_deref(),
            self.default_ttl,
            self.max_body_bytes,
            ips,
            &self.clock,
        )
    }
}

fn parse_blacklist_feed(
    body: &[u8],
    max_body_bytes: usize,
    max_entries: usize,
) -> Result<Vec<IpAddr>, BlacklistError> {
    if body.len() > max_body_bytes {
        return Err(BlacklistError::InvalidData(format!(
            "feed body exceeds {max_body_bytes} bytes"
        )));
    }
    let body_text = std::str::from_utf8(body)
        .map_err(|error| BlacklistError::InvalidData(format!("feed is not UTF-8: {error}")))?;
    let mut unique = HashSet::new();
    for (line_index, line) in body_text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let ip_str = line.split('#').next().unwrap_or(line).trim();
        let ip = ip_str.parse::<IpAddr>().map_err(|error| {
            BlacklistError::InvalidData(format!(
                "line {} is not an IP address: {error}",
                line_index + 1
            ))
        })?;
        unique.insert(ip);
        if unique.len() > max_entries {
            return Err(BlacklistError::InvalidData(format!(
                "feed exceeds {max_entries} unique entries"
            )));
        }
    }

    let mut ips: Vec<IpAddr> = unique.into_iter().collect();
    ips.sort();
    Ok(ips)
}

fn replace_blacklist_entries(
    blocked: &parking_lot::RwLock<HashMap<IpAddr, Instant>>,
    default_ttl: Duration,
    ips: &[IpAddr],
    clock: &ProtocolClock,
) {
    let now = clock.now();
    let expiry = now.checked_add(default_ttl).unwrap_or(now);
    let mut guard = blocked.write();
    guard.clear();
    guard.reserve(ips.len());
    for ip in ips {
        guard.insert(*ip, expiry);
    }
}

#[cfg(test)]
fn persist_blacklist_cache(
    path: Option<&std::path::Path>,
    default_ttl: Duration,
    max_body_bytes: usize,
    ips: &[IpAddr],
    clock: &ProtocolClock,
) -> Result<(), BlacklistError> {
    let Some(path) = path else {
        return Ok(());
    };
    let bytes = serialize_blacklist_cache(default_ttl, max_body_bytes, ips, clock)?;
    crate::implementations::server::fsutil::atomic_write_file(
        path,
        &bytes,
        Some(0o600),
        "server::blacklist_cache_tmp_nonce",
    )
    .map_err(|error| BlacklistError::CacheError(format!("atomic write: {error}")))
}

fn publish_blacklist_feed(
    path: Option<&std::path::Path>,
    default_ttl: Duration,
    max_body_bytes: usize,
    ips: &[IpAddr],
    clock: &ProtocolClock,
    blocked: &parking_lot::RwLock<HashMap<IpAddr, Instant>>,
    control: &BlacklistSyncControl,
) -> Result<(), BlacklistError> {
    let committed = if let Some(path) = path {
        let bytes = serialize_blacklist_cache(default_ttl, max_body_bytes, ips, clock)?;
        crate::implementations::server::fsutil::atomic_write_file_with_commit(
            path,
            &bytes,
            Some(0o600),
            "server::blacklist_cache_tmp_nonce",
            |temporary_path, destination_path| {
                control.commit_publication(|| {
                    std::fs::rename(temporary_path, destination_path)?;
                    replace_blacklist_entries(blocked, default_ttl, ips, clock);
                    Ok(())
                })
            },
        )
        .map_err(|error| BlacklistError::CacheError(format!("atomic write: {error}")))?
    } else {
        control
            .commit_publication(|| {
                replace_blacklist_entries(blocked, default_ttl, ips, clock);
                Ok(())
            })
            .map_err(|error| BlacklistError::CacheError(format!("publication: {error}")))?
    };
    if committed {
        Ok(())
    } else {
        Err(BlacklistError::Cancelled)
    }
}

fn serialize_blacklist_cache(
    default_ttl: Duration,
    max_body_bytes: usize,
    ips: &[IpAddr],
    clock: &ProtocolClock,
) -> Result<Vec<u8>, BlacklistError> {
    let now_secs = crate::time_source::unix_epoch_seconds(clock.now_system())
        .map_err(BlacklistError::Clock)?;
    let expires_at_secs = now_secs.checked_add(default_ttl.as_secs()).ok_or_else(|| {
        BlacklistError::CacheError("cache expiry exceeds Unix seconds".to_string())
    })?;
    let cache = BlacklistCache { version: 1, expires_at_secs, ips: ips.to_vec() };
    let bytes = serde_json::to_vec(&cache)
        .map_err(|error| BlacklistError::CacheError(format!("serialize: {error}")))?;
    if bytes.len() > max_body_bytes {
        return Err(BlacklistError::CacheError(format!(
            "serialized cache exceeds {max_body_bytes} bytes"
        )));
    }
    Ok(bytes)
}

#[derive(serde::Deserialize, serde::Serialize)]
struct BlacklistCache {
    version: u8,
    expires_at_secs: u64,
    ips: Vec<IpAddr>,
}

#[cfg(test)]
fn current_epoch_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests;
