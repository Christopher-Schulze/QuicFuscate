//! Rate limiting and connection limiting for the server.

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

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

/// Rate limit configuration.
#[derive(Clone, Debug)]
pub struct RateLimitConfig {
    /// Maximum packets per second per client (sustained rate).
    pub max_pps: u64,
    /// Maximum bytes per second per client (0 = unlimited).
    pub max_bps: u64,
    /// Bucket refill interval.
    pub refill_interval: Duration,
    /// Burst capacity (max tokens the bucket can hold). 0 = use 2× `max_pps`.
    ///
    /// This decouples the initial burst from the steady-state refill rate so a
    /// newly-seen IP cannot dump an entire second of quota instantaneously.
    pub burst_size: u64,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            max_pps: DEFAULT_PER_SOURCE_RATE_LIMIT_PPS,
            max_bps: 0, // Unlimited
            refill_interval: Duration::from_secs(1),
            burst_size: 0, // 0 => resolve to 2× max_pps (see `effective_burst`)
        }
    }
}

impl RateLimitConfig {
    /// Resolve the effective burst capacity. A `burst_size` of 0 means "use the
    /// default 2× sustained rate", which keeps the config backward-compatible
    /// while still separating burst from steady-state.
    #[inline]
    pub fn effective_burst(&self) -> u64 {
        if self.burst_size == 0 {
            self.max_pps.saturating_mul(2)
        } else {
            self.burst_size
        }
    }

    /// Derive the byte bucket's initial capacity from the packet-equivalent burst.
    ///
    /// `burst_size` is expressed in packet tokens, so the byte bucket uses the
    /// same burst duration at the configured average packet size:
    /// `ceil(max_bps * effective_burst / max_pps)`. The refill interval remains
    /// the shared refill cadence and intentionally does not multiply this
    /// initial capacity. `None` represents a zero packet rate or a result that
    /// cannot be represented as a `u64`; callers fail closed in that case.
    fn byte_burst_capacity(&self) -> Option<u64> {
        if self.max_bps == 0 {
            return Some(0);
        }
        if self.max_pps == 0 {
            return None;
        }

        let numerator = u128::from(self.max_bps).checked_mul(u128::from(self.effective_burst()))?;
        let capacity = numerator.div_ceil(u128::from(self.max_pps));
        capacity.try_into().ok()
    }
}

#[cfg(feature = "rate_limiter")]
fn parse_rate_limit_env_u64(key: &str) -> Option<u64> {
    match std::env::var(key) {
        Ok(raw) => match raw.trim().parse::<u64>() {
            Ok(v) => Some(v),
            Err(e) => {
                log::warn!("Invalid {}='{}': {}", key, raw, e);
                None
            }
        },
        Err(_) => None,
    }
}

#[cfg(feature = "rate_limiter")]
pub fn load_rate_limit_config_from_env() -> RateLimitConfig {
    let mut cfg = RateLimitConfig::default();

    if let Some(v) = parse_rate_limit_env_u64("QUICFUSCATE_RATE_LIMIT_PPS") {
        if v == 0 {
            log::warn!("Ignoring QUICFUSCATE_RATE_LIMIT_PPS=0 (must be >= 1)");
        } else {
            cfg.max_pps = v;
        }
    }
    if let Some(v) = parse_rate_limit_env_u64("QUICFUSCATE_RATE_LIMIT_BPS") {
        cfg.max_bps = v;
    }
    if let Some(v) = parse_rate_limit_env_u64("QUICFUSCATE_RATE_LIMIT_BURST") {
        cfg.burst_size = v;
    }
    if let Some(ms) = parse_rate_limit_env_u64("QUICFUSCATE_RATE_LIMIT_REFILL_MS") {
        if ms == 0 {
            log::warn!("Ignoring QUICFUSCATE_RATE_LIMIT_REFILL_MS=0 (must be >= 1)");
        } else {
            cfg.refill_interval = Duration::from_millis(ms);
        }
    }

    log::info!(
        "Server rate limiter config: max_pps={}, max_bps={}, burst={}, refill_ms={}",
        cfg.max_pps,
        cfg.max_bps,
        cfg.effective_burst(),
        cfg.refill_interval.as_millis()
    );

    cfg
}

/// Token bucket for rate limiting.
///
/// `capacity` (the burst size) is decoupled from `refill_rate` (the sustained
/// rate per `refill_interval`). The bucket starts full at `capacity` tokens,
/// allowing an initial burst, then refills at the sustained rate.
struct TokenBucket {
    tokens: u64,
    capacity: u64,
    last_refill: Instant,
    last_seen: Instant,
    refill_rate: u64,
    refill_interval: Duration,
}

impl TokenBucket {
    fn new(capacity: u64, refill_rate: u64, refill_interval: Duration) -> Self {
        Self::new_at(capacity, refill_rate, refill_interval, Instant::now())
    }

    fn new_at(capacity: u64, refill_rate: u64, refill_interval: Duration, now: Instant) -> Self {
        Self {
            tokens: capacity,
            capacity,
            last_refill: now,
            last_seen: now,
            refill_rate,
            refill_interval,
        }
    }

    fn consume(&mut self, amount: u64) -> bool {
        self.consume_at(amount, Instant::now())
    }

    fn consume_at(&mut self, amount: u64, now: Instant) -> bool {
        self.last_seen = now;
        self.refill(now);

        if self.tokens >= amount {
            self.tokens -= amount;
            true
        } else {
            false
        }
    }

    fn refill(&mut self, now: Instant) {
        let elapsed = now.saturating_duration_since(self.last_refill);

        if elapsed >= self.refill_interval {
            let refill_interval_us = self.refill_interval.as_micros();
            let refill_amount = {
                let refill = (elapsed.as_micros() * self.refill_rate as u128)
                    .checked_div(refill_interval_us)
                    .unwrap_or(self.capacity as u128);
                // Saturate to u64 range
                if refill > u64::MAX as u128 {
                    u64::MAX
                } else {
                    refill as u64
                }
            };

            self.tokens = self.tokens.saturating_add(refill_amount).min(self.capacity);
            self.last_refill = now;
        }
    }

    fn is_idle(&self, now: Instant, max_idle: Duration) -> bool {
        now.duration_since(self.last_seen) >= max_idle
    }
}

/// Rate limiter using token buckets.
pub struct RateLimiter {
    config: RateLimitConfig,
    packet_buckets: parking_lot::Mutex<HashMap<RateLimitKey, TokenBucket>>,
    byte_buckets: parking_lot::Mutex<HashMap<RateLimitKey, TokenBucket>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum RateLimitKey {
    Session(u64),
    Ip(IpAddr),
}

impl RateLimiter {
    /// Create a new rate limiter.
    pub fn new(config: RateLimitConfig) -> Self {
        Self {
            config,
            packet_buckets: parking_lot::Mutex::new(HashMap::new()),
            byte_buckets: parking_lot::Mutex::new(HashMap::new()),
        }
    }

    /// Check if a packet is allowed (by session ID).
    pub fn check_packet(&self, session_id: u64) -> bool {
        self.check_packet_key(RateLimitKey::Session(session_id))
    }

    /// Check if a packet is allowed (by source IP).
    pub fn check_packet_ip(&self, ip: IpAddr) -> bool {
        self.check_packet_ip_cost(ip, 1)
    }

    /// Check if a source packet is allowed with an explicit policy token cost.
    pub fn check_packet_ip_cost(&self, ip: IpAddr, cost: u64) -> bool {
        self.check_packet_key_with_cost(RateLimitKey::Ip(ip), cost)
    }

    fn check_packet_key(&self, key: RateLimitKey) -> bool {
        self.check_packet_key_with_cost(key, 1)
    }

    fn check_packet_key_with_cost(&self, key: RateLimitKey, cost: u64) -> bool {
        if cost == 0 {
            return false;
        }
        let burst = self.config.effective_burst();
        let mut buckets = self.packet_buckets.lock();
        let bucket = buckets.entry(key).or_insert_with(|| {
            TokenBucket::new(burst, self.config.max_pps, self.config.refill_interval)
        });
        let allowed = bucket.consume(cost);

        if !allowed {
            crate::instrumentation::global().server.rate_limit_hit();
        }

        allowed
    }

    /// Check if bytes are allowed (by session ID).
    pub fn check_bytes(&self, session_id: u64, bytes: u64) -> bool {
        self.check_bytes_key(RateLimitKey::Session(session_id), bytes)
    }

    /// Check if bytes are allowed (by source IP).
    pub fn check_bytes_ip(&self, ip: IpAddr, bytes: u64) -> bool {
        self.check_bytes_key(RateLimitKey::Ip(ip), bytes)
    }

    fn check_bytes_key(&self, key: RateLimitKey, bytes: u64) -> bool {
        if self.config.max_bps == 0 {
            return true; // Unlimited
        }

        let Some(capacity) = self.config.byte_burst_capacity() else {
            crate::instrumentation::global().server.rate_limit_hit();
            return false;
        };
        let mut buckets = self.byte_buckets.lock();
        let bucket = buckets.entry(key).or_insert_with(|| {
            TokenBucket::new(capacity, self.config.max_bps, self.config.refill_interval)
        });
        let allowed = bucket.consume(bytes);
        if !allowed {
            crate::instrumentation::global().server.rate_limit_hit();
        }
        allowed
    }

    /// Remove a session's buckets.
    pub fn remove_session(&self, session_id: u64) {
        self.packet_buckets.lock().remove(&RateLimitKey::Session(session_id));
        self.byte_buckets.lock().remove(&RateLimitKey::Session(session_id));
    }

    /// Remove an IP's buckets.
    pub fn remove_ip(&self, ip: IpAddr) {
        self.packet_buckets.lock().remove(&RateLimitKey::Ip(ip));
        self.byte_buckets.lock().remove(&RateLimitKey::Ip(ip));
    }

    /// Prune idle session buckets to bound memory growth under churn/spoofing.
    pub fn prune_idle(&self, max_idle: Duration) {
        let now = Instant::now();
        self.packet_buckets.lock().retain(|_, bucket| !bucket.is_idle(now, max_idle));
        self.byte_buckets.lock().retain(|_, bucket| !bucket.is_idle(now, max_idle));
    }
}

/// Connection limiter per IP address.
pub struct ConnectionLimiter {
    max_per_ip: usize,
    connections: HashMap<IpAddr, usize>,
}

impl ConnectionLimiter {
    /// Create a new connection limiter.
    pub fn new(max_per_ip: usize) -> Self {
        Self { max_per_ip, connections: HashMap::new() }
    }

    /// Check if a new connection from this IP is allowed.
    pub fn check(&self, ip: IpAddr) -> bool {
        self.connections.get(&ip).map(|&count| count < self.max_per_ip).unwrap_or(true)
    }

    /// Add a connection for this IP.
    pub fn add(&mut self, ip: IpAddr) {
        *self.connections.entry(ip).or_insert(0) += 1;
    }

    /// Remove a connection for this IP.
    pub fn remove(&mut self, ip: IpAddr) {
        if let Some(count) = self.connections.get_mut(&ip) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                self.connections.remove(&ip);
            }
        }
    }

    /// Get connection count for an IP.
    pub fn count(&self, ip: IpAddr) -> usize {
        self.connections.get(&ip).copied().unwrap_or(0)
    }
}

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
    last_now: Duration,
    next_prune: Duration,
    next_attempt_id: u64,
    states: HashMap<IpAddr, AuthIpState>,
}

impl AuthRateLimiter {
    pub(crate) fn new(config: AuthPolicyConfig) -> Self {
        Self {
            config,
            anchor: Instant::now(),
            last_now: Duration::ZERO,
            next_prune: Duration::ZERO,
            next_attempt_id: 1,
            states: HashMap::new(),
        }
    }

    pub(crate) fn begin(&mut self, ip: IpAddr) -> AuthAdmission {
        self.begin_at(ip, self.anchor.elapsed())
    }

    pub(crate) fn complete(
        &mut self,
        attempt: AuthAttempt,
        terminal: AuthTerminal,
    ) -> AuthCompletion {
        self.complete_at(attempt, terminal, self.anchor.elapsed())
    }

    pub(crate) fn prune_if_due(&mut self) -> usize {
        self.prune_if_due_at(self.anchor.elapsed())
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
        let cap = if capacity == 0 { refill_per_sec.saturating_mul(2) } else { capacity };
        let anchor = Instant::now();
        Self {
            tokens: AtomicU64::new(cap),
            last_refill_ns: AtomicU64::new(0),
            capacity: cap,
            refill_per_sec,
            anchor,
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

    #[inline]
    fn now_ns(&self) -> u64 {
        self.anchor.elapsed().as_nanos() as u64
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
    timing: parking_lot::Mutex<AnomalyTimingState>,
}

#[allow(dead_code)] // public API for admin tooling / future wiring
impl EwmaAnomalyDetector {
    /// Create a detector with the given smoothing and spike threshold.
    pub fn new(alpha: f64, spike_multiplier: f64) -> Self {
        let config =
            DdosPolicyConfig { ewma_alpha: alpha, spike_multiplier, ..DdosPolicyConfig::default() };
        Self::with_config(config).expect("legacy DDoS detector parameters must be valid")
    }

    pub fn with_config(config: DdosPolicyConfig) -> Result<Self, String> {
        config.validate()?;
        Ok(Self {
            ewma_pps: AtomicU64::new(0f64.to_bits()),
            current_pps: AtomicU64::new(0),
            anomaly_active: AtomicBool::new(false),
            config,
            anchor: Instant::now(),
            timing: parking_lot::Mutex::new(AnomalyTimingState::default()),
        })
    }

    /// Create a detector with sensible defaults (α=0.1, spike=3×).
    pub fn with_defaults() -> Self {
        Self::with_config(DdosPolicyConfig::default()).expect("default DDoS policy must be valid")
    }

    /// Record an observed PPS sample at the detector's monotonic clock.
    pub fn record_pps(&self, pps: u64) -> DdosTransition {
        self.record_pps_at(pps, self.anchor.elapsed())
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
            Self::InvalidData(s) => write!(f, "invalid blacklist data: {s}"),
        }
    }
}

impl std::error::Error for BlacklistError {}

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
}

impl BlacklistSync {
    /// Create a new blacklist synchronizer.
    pub fn new(default_ttl: Duration, sync_url: Option<String>, sync_interval: Duration) -> Self {
        Self::new_bounded(
            default_ttl,
            sync_url,
            sync_interval,
            Duration::from_secs(30),
            MAX_BLACKLIST_BODY_BYTES,
            MAX_BLACKLIST_ENTRIES,
            None,
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
        Self::new_bounded_with_ca(
            default_ttl,
            sync_url,
            sync_interval,
            request_timeout,
            max_body_bytes,
            max_entries,
            cache_path,
            None,
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
        };
        if let Err(error) = synchronizer.load_cache() {
            log::warn!("Blacklist cache ignored: {error}");
        }
        Ok(synchronizer)
    }

    /// Create a synchronizer with no feed configured (manual blocking only).
    pub fn manual_only(default_ttl: Duration) -> Self {
        Self::new(default_ttl, None, Duration::from_secs(3600))
    }

    /// Whether an IP is currently blocked (and not expired).
    pub fn is_blocked(&self, ip: IpAddr) -> bool {
        let now = Instant::now();
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
        let expiry = Instant::now() + ttl;
        self.blocked.write().insert(ip, expiry);
    }

    /// Remove an IP from the blacklist.
    pub fn remove(&self, ip: IpAddr) {
        self.blocked.write().remove(&ip);
    }

    /// Replace the entire blocked set from an external feed (bulk sync).
    /// Each entry is seeded with the default TTL.
    pub fn replace_list(&self, ips: &[IpAddr]) {
        replace_blacklist_entries(&self.blocked, self.default_ttl, ips);
    }

    /// Number of currently-blocked (non-expired) IPs.
    pub fn len(&self) -> usize {
        let now = Instant::now();
        self.blocked.read().values().filter(|e| **e > now).count()
    }

    /// Whether the blacklist is empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Prune expired entries to bound memory.
    pub fn prune_expired(&self) {
        let now = Instant::now();
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
        self.sync_with_cancel(Arc::new(AtomicBool::new(false))).await
    }

    /// Synchronize the feed while honoring the owning worker's cancellation flag.
    pub(crate) async fn sync_with_cancel(
        &self,
        cancellation: Arc<AtomicBool>,
    ) -> Result<usize, BlacklistError> {
        let url = match &self.sync_url {
            Some(u) => u.clone(),
            None => return Err(BlacklistError::NoSyncUrl),
        };
        if cancellation.load(Ordering::Acquire) {
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
            if cancellation.load(Ordering::Acquire) {
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

        if cancellation.load(Ordering::Acquire) {
            return Err(BlacklistError::Cancelled);
        }

        let max_body_bytes = self.max_body_bytes;
        let max_entries = self.max_entries;
        let default_ttl = self.default_ttl;
        let cache_path = self.cache_path.clone();
        let blocked = Arc::clone(&self.blocked);
        let cancellation_for_blocking = Arc::clone(&cancellation);
        let ips = tokio::task::spawn_blocking(move || {
            if cancellation_for_blocking.load(Ordering::Acquire) {
                return Err(BlacklistError::Cancelled);
            }
            let ips = parse_blacklist_feed(&body, max_body_bytes, max_entries)?;
            if cancellation_for_blocking.load(Ordering::Acquire) {
                return Err(BlacklistError::Cancelled);
            }
            persist_blacklist_cache(cache_path.as_deref(), default_ttl, max_body_bytes, &ips)?;
            if cancellation_for_blocking.load(Ordering::Acquire) {
                return Err(BlacklistError::Cancelled);
            }
            replace_blacklist_entries(&blocked, default_ttl, &ips);
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
        let now = current_epoch_secs();
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
        let expiry = Instant::now() + remaining;
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
) {
    let expiry = Instant::now() + default_ttl;
    let mut guard = blocked.write();
    guard.clear();
    guard.reserve(ips.len());
    for ip in ips {
        guard.insert(*ip, expiry);
    }
}

fn persist_blacklist_cache(
    path: Option<&std::path::Path>,
    default_ttl: Duration,
    max_body_bytes: usize,
    ips: &[IpAddr],
) -> Result<(), BlacklistError> {
    let Some(path) = path else {
        return Ok(());
    };
    let cache = BlacklistCache {
        version: 1,
        expires_at_secs: current_epoch_secs().saturating_add(default_ttl.as_secs()),
        ips: ips.to_vec(),
    };
    let bytes = serde_json::to_vec(&cache)
        .map_err(|error| BlacklistError::CacheError(format!("serialize: {error}")))?;
    if bytes.len() > max_body_bytes {
        return Err(BlacklistError::CacheError(format!(
            "serialized cache exceeds {max_body_bytes} bytes"
        )));
    }
    crate::implementations::server::fsutil::atomic_write_file(
        path,
        &bytes,
        Some(0o600),
        "server::blacklist_cache_tmp_nonce",
    )
    .map_err(|error| BlacklistError::CacheError(format!("atomic write: {error}")))
}

#[derive(serde::Deserialize, serde::Serialize)]
struct BlacklistCache {
    version: u8,
    expires_at_secs: u64,
    ips: Vec<IpAddr>,
}

fn current_epoch_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rate_limiter() {
        let config = RateLimitConfig {
            max_pps: 10,
            max_bps: 0,
            refill_interval: Duration::from_secs(1),
            burst_size: 10,
        };
        let limiter = RateLimiter::new(config);

        // Should allow first 10 packets (burst capacity)
        for _ in 0..10 {
            assert!(limiter.check_packet(1));
        }

        // 11th should fail
        assert!(!limiter.check_packet(1));
    }

    #[test]
    fn test_connection_limiter() {
        let mut limiter = ConnectionLimiter::new(2);
        let ip: IpAddr = "1.2.3.4".parse().unwrap();

        assert!(limiter.check(ip));
        limiter.add(ip);
        assert!(limiter.check(ip));
        limiter.add(ip);
        assert!(!limiter.check(ip)); // Limit reached

        limiter.remove(ip);
        assert!(limiter.check(ip)); // Can add again
    }

    #[test]
    fn test_rate_limiter_prune_idle_resets_stale_bucket() {
        let config = RateLimitConfig {
            max_pps: 1,
            max_bps: 0,
            refill_interval: Duration::from_secs(1),
            burst_size: 1,
        };
        let limiter = RateLimiter::new(config);

        assert!(limiter.check_packet(7));
        assert!(!limiter.check_packet(7));

        std::thread::sleep(Duration::from_millis(20));
        limiter.prune_idle(Duration::from_millis(5));

        // Bucket was pruned and recreated, so one packet is allowed again.
        assert!(limiter.check_packet(7));
    }

    #[test]
    fn test_rate_limiter_ip_keys_are_isolated() {
        let config = RateLimitConfig {
            max_pps: 1,
            max_bps: 0,
            refill_interval: Duration::from_secs(1),
            burst_size: 1,
        };
        let limiter = RateLimiter::new(config);
        let ip1: IpAddr = "1.2.3.4".parse().unwrap();
        let ip2: IpAddr = "5.6.7.8".parse().unwrap();

        assert!(limiter.check_packet_ip(ip1));
        assert!(!limiter.check_packet_ip(ip1));

        assert!(limiter.check_packet_ip(ip2));
        assert!(!limiter.check_packet_ip(ip2));
    }

    #[test]
    fn test_rate_limiter_enhanced_cost_reuses_the_same_bucket() {
        let limiter = RateLimiter::new(RateLimitConfig {
            max_pps: 4,
            max_bps: 0,
            refill_interval: Duration::from_secs(1),
            burst_size: 4,
        });
        let ip: IpAddr = "1.2.3.4".parse().unwrap();

        assert!(limiter.check_packet_ip_cost(ip, 2));
        assert!(limiter.check_packet_ip(ip));
        assert!(!limiter.check_packet_ip_cost(ip, 2));
        assert!(limiter.check_packet_ip(ip));
        assert!(!limiter.check_packet_ip(ip));
        assert!(!limiter.check_packet_ip_cost(ip, 0));
    }

    fn test_auth_policy_config() -> AuthPolicyConfig {
        AuthPolicyConfig {
            enabled: true,
            backoff_after_failures: 2,
            backoff_base: Duration::from_millis(10),
            backoff_max: Duration::from_millis(40),
            block_after_failures: 5,
            block_duration: Duration::from_millis(100),
            idle_timeout: Duration::from_millis(50),
            prune_interval: Duration::from_millis(10),
            max_tracked_ips: 3,
            max_pending_attempts_per_ip: 2,
        }
    }

    fn allowed_attempt(admission: AuthAdmission) -> AuthAttempt {
        match admission {
            AuthAdmission::Allowed(attempt) => attempt,
            other => panic!("expected allowed auth attempt, got {other:?}"),
        }
    }

    #[test]
    fn auth_policy_configuration_rejects_every_unsafe_boundary() {
        let valid = test_auth_policy_config();
        assert!(valid.validate().is_ok());

        let mut invalid_cases = Vec::new();
        let mut zero_backoff_threshold = valid.clone();
        zero_backoff_threshold.backoff_after_failures = 0;
        invalid_cases.push(zero_backoff_threshold);
        let mut inverted_thresholds = valid.clone();
        inverted_thresholds.block_after_failures = inverted_thresholds.backoff_after_failures;
        invalid_cases.push(inverted_thresholds);
        let mut zero_base = valid.clone();
        zero_base.backoff_base = Duration::ZERO;
        invalid_cases.push(zero_base);
        let mut inverted_delays = valid.clone();
        inverted_delays.backoff_max = Duration::from_millis(1);
        invalid_cases.push(inverted_delays);
        let mut zero_block = valid.clone();
        zero_block.block_duration = Duration::ZERO;
        invalid_cases.push(zero_block);
        let mut zero_idle = valid.clone();
        zero_idle.idle_timeout = Duration::ZERO;
        invalid_cases.push(zero_idle);
        let mut zero_prune = valid.clone();
        zero_prune.prune_interval = Duration::ZERO;
        invalid_cases.push(zero_prune);
        let mut zero_ips = valid.clone();
        zero_ips.max_tracked_ips = 0;
        invalid_cases.push(zero_ips);
        let mut zero_pending = valid;
        zero_pending.max_pending_attempts_per_ip = 0;
        invalid_cases.push(zero_pending);

        for invalid in invalid_cases {
            assert!(invalid.validate().is_err(), "unsafe auth policy was accepted: {invalid:?}");
        }
    }

    #[test]
    fn auth_policy_enforces_exact_backoff_block_expiry_and_success_reset() {
        let mut limiter = AuthRateLimiter::new(test_auth_policy_config());
        let ip: IpAddr = "1.2.3.4".parse().unwrap();

        let first = allowed_attempt(limiter.begin_at(ip, Duration::ZERO));
        assert_eq!(
            limiter.complete_at(first, AuthTerminal::Failed, Duration::ZERO),
            AuthCompletion::Failed
        );
        let second = allowed_attempt(limiter.begin_at(ip, Duration::ZERO));
        assert_eq!(
            limiter.complete_at(second, AuthTerminal::Failed, Duration::ZERO),
            AuthCompletion::FailedWithBackoff { delay: Duration::from_millis(10) }
        );
        assert_eq!(
            limiter.begin_at(ip, Duration::from_millis(5)),
            AuthAdmission::Backoff { retry_after: Duration::from_millis(5) }
        );

        let third = allowed_attempt(limiter.begin_at(ip, Duration::from_millis(10)));
        assert_eq!(
            limiter.complete_at(third, AuthTerminal::Failed, Duration::from_millis(10)),
            AuthCompletion::FailedWithBackoff { delay: Duration::from_millis(20) }
        );
        let fourth = allowed_attempt(limiter.begin_at(ip, Duration::from_millis(30)));
        assert_eq!(
            limiter.complete_at(fourth, AuthTerminal::Failed, Duration::from_millis(30)),
            AuthCompletion::FailedWithBackoff { delay: Duration::from_millis(40) }
        );
        let fifth = allowed_attempt(limiter.begin_at(ip, Duration::from_millis(70)));
        assert_eq!(
            limiter.complete_at(fifth, AuthTerminal::Failed, Duration::from_millis(70)),
            AuthCompletion::FailedAndBlocked { duration: Duration::from_millis(100) }
        );
        assert_eq!(
            limiter.begin_at(ip, Duration::from_millis(100)),
            AuthAdmission::Blocked { retry_after: Duration::from_millis(70) }
        );

        let after_expiry = allowed_attempt(limiter.begin_at(ip, Duration::from_millis(170)));
        assert_eq!(
            limiter.complete_at(after_expiry, AuthTerminal::Succeeded, Duration::from_millis(170)),
            AuthCompletion::Succeeded
        );
        assert_eq!(limiter.tracked_ips(), 0);
    }

    #[test]
    fn auth_policy_records_exactly_one_terminal_result_per_attempt() {
        let mut limiter = AuthRateLimiter::new(test_auth_policy_config());
        let ip: IpAddr = "1.2.3.4".parse().unwrap();
        let attempt = allowed_attempt(limiter.begin_at(ip, Duration::ZERO));

        assert_eq!(
            limiter.complete_at(attempt, AuthTerminal::Failed, Duration::ZERO),
            AuthCompletion::Failed
        );
        assert_eq!(
            limiter.complete_at(attempt, AuthTerminal::Failed, Duration::ZERO),
            AuthCompletion::Duplicate
        );
    }

    #[test]
    fn auth_policy_handles_one_hundred_attempts_and_isolates_second_ip() {
        let mut config = test_auth_policy_config();
        config.backoff_after_failures = 101;
        config.block_after_failures = 102;
        let mut limiter = AuthRateLimiter::new(config);
        let attacker: IpAddr = "1.2.3.4".parse().unwrap();
        let legitimate: IpAddr = "5.6.7.8".parse().unwrap();

        for attempt_index in 0..100u64 {
            let now = Duration::from_millis(attempt_index);
            let attempt = allowed_attempt(limiter.begin_at(attacker, now));
            assert_eq!(
                limiter.complete_at(attempt, AuthTerminal::Failed, now),
                AuthCompletion::Failed
            );
        }
        let legitimate_attempt =
            allowed_attempt(limiter.begin_at(legitimate, Duration::from_millis(100)));
        assert_eq!(legitimate_attempt.ip(), legitimate);
        assert_eq!(
            limiter.complete_at(
                legitimate_attempt,
                AuthTerminal::Succeeded,
                Duration::from_millis(100)
            ),
            AuthCompletion::Succeeded
        );
    }

    #[test]
    fn auth_policy_bounds_pending_and_tracked_state_then_prunes_idle_entries() {
        let mut config = test_auth_policy_config();
        config.max_tracked_ips = 2;
        let mut limiter = AuthRateLimiter::new(config);
        let ip1: IpAddr = "1.2.3.4".parse().unwrap();
        let ip2: IpAddr = "5.6.7.8".parse().unwrap();
        let ip3: IpAddr = "9.10.11.12".parse().unwrap();

        let pending1 = allowed_attempt(limiter.begin_at(ip1, Duration::ZERO));
        let pending2 = allowed_attempt(limiter.begin_at(ip1, Duration::ZERO));
        assert_eq!(limiter.begin_at(ip1, Duration::ZERO), AuthAdmission::PendingCapacity);
        assert_eq!(
            limiter.complete_at(pending1, AuthTerminal::Failed, Duration::ZERO),
            AuthCompletion::Failed
        );
        assert_eq!(
            limiter.complete_at(pending2, AuthTerminal::Abandoned, Duration::ZERO),
            AuthCompletion::Abandoned
        );

        let second = allowed_attempt(limiter.begin_at(ip2, Duration::ZERO));
        assert_eq!(
            limiter.complete_at(second, AuthTerminal::Failed, Duration::ZERO),
            AuthCompletion::Failed
        );
        assert_eq!(limiter.tracked_ips(), 2);
        assert_eq!(limiter.begin_at(ip3, Duration::ZERO), AuthAdmission::StateCapacity);

        assert_eq!(limiter.prune_if_due_at(Duration::from_millis(51)), 2);
        assert_eq!(limiter.tracked_ips(), 0);
        assert!(matches!(
            limiter.begin_at(ip3, Duration::from_millis(51)),
            AuthAdmission::Allowed(_)
        ));
    }

    #[test]
    fn auth_policy_monotonic_clock_prevents_time_regression_bypass() {
        let mut limiter = AuthRateLimiter::new(test_auth_policy_config());
        let ip: IpAddr = "1.2.3.4".parse().unwrap();
        for now in [0, 10, 30, 70] {
            let attempt = allowed_attempt(limiter.begin_at(ip, Duration::from_millis(now)));
            let _ = limiter.complete_at(attempt, AuthTerminal::Failed, Duration::from_millis(now));
        }
        let fifth = allowed_attempt(limiter.begin_at(ip, Duration::from_millis(110)));
        let _ = limiter.complete_at(fifth, AuthTerminal::Failed, Duration::from_millis(110));

        assert_eq!(
            limiter.begin_at(ip, Duration::from_millis(1)),
            AuthAdmission::Blocked { retry_after: Duration::from_millis(100) }
        );
    }

    #[test]
    fn auth_policy_disable_semantics_allocate_no_state() {
        let mut config = test_auth_policy_config();
        config.enabled = false;
        let mut limiter = AuthRateLimiter::new(config);
        let ip: IpAddr = "1.2.3.4".parse().unwrap();
        let attempt = allowed_attempt(limiter.begin_at(ip, Duration::ZERO));

        assert_eq!(
            limiter.complete_at(attempt, AuthTerminal::Failed, Duration::ZERO),
            AuthCompletion::Disabled
        );
        assert_eq!(limiter.tracked_ips(), 0);
    }

    // ---- RateLimitConfig defaults & burst ----

    #[test]
    fn test_rate_limit_config_default_pps_preserves_tunnel_headroom() {
        let cfg = RateLimitConfig::default();
        assert_eq!(cfg.max_pps, DEFAULT_PER_SOURCE_RATE_LIMIT_PPS);
    }

    #[test]
    fn test_effective_burst_defaults_to_2x_sustained() {
        let cfg = RateLimitConfig {
            max_pps: 1_000,
            max_bps: 0,
            refill_interval: Duration::from_secs(1),
            burst_size: 0,
        };
        assert_eq!(cfg.effective_burst(), 2_000);
    }

    #[test]
    fn test_effective_burst_explicit_override() {
        let cfg = RateLimitConfig {
            max_pps: 1_000,
            max_bps: 0,
            refill_interval: Duration::from_secs(1),
            burst_size: 100,
        };
        assert_eq!(cfg.effective_burst(), 100);
    }

    #[test]
    fn test_byte_burst_capacity_matches_default_and_explicit_packet_bursts() {
        let default_burst = RateLimitConfig {
            max_pps: 1_000,
            max_bps: 1_000_000,
            refill_interval: Duration::from_secs(1),
            burst_size: 0,
        };
        assert_eq!(default_burst.effective_burst(), 2_000);
        assert_eq!(default_burst.byte_burst_capacity(), Some(2_000_000));

        let explicit_burst = RateLimitConfig {
            burst_size: 250,
            refill_interval: Duration::from_millis(250),
            ..default_burst.clone()
        };
        assert_eq!(explicit_burst.byte_burst_capacity(), Some(250_000));
        assert_eq!(
            RateLimitConfig { max_pps: 0, ..explicit_burst.clone() }.byte_burst_capacity(),
            None
        );
        assert_eq!(
            RateLimitConfig {
                max_bps: u64::MAX,
                burst_size: u64::MAX,
                max_pps: 1,
                ..explicit_burst
            }
            .byte_burst_capacity(),
            None
        );
    }

    #[test]
    fn test_rate_limiter_byte_bucket_enforces_packet_equivalent_burst() {
        let limiter = RateLimiter::new(RateLimitConfig {
            max_pps: 200,
            max_bps: 1_000,
            refill_interval: Duration::from_secs(60),
            burst_size: 200,
        });
        let ip: IpAddr = "192.0.2.10".parse().unwrap();

        for _ in 0..100 {
            assert!(limiter.check_bytes_ip(ip, 10));
        }
        assert!(!limiter.check_bytes_ip(ip, 1));
    }

    #[test]
    fn test_token_bucket_burst_then_steady() {
        let anchor = Instant::now();
        let mut bucket = TokenBucket::new_at(4, 2, Duration::from_secs(1), anchor);

        for _ in 0..4 {
            assert!(bucket.consume_at(1, anchor));
        }
        assert!(!bucket.consume_at(1, anchor));
        assert!(!bucket.consume_at(1, anchor + Duration::from_millis(999)));
        assert!(bucket.consume_at(2, anchor + Duration::from_secs(1)));
        assert!(!bucket.consume_at(1, anchor + Duration::from_millis(1999)));
        assert!(bucket.consume_at(2, anchor + Duration::from_secs(2)));
        assert!(!bucket.consume_at(1, anchor + Duration::from_secs(2)));
    }

    // ---- GlobalRateLimiter ----

    #[test]
    fn test_global_rate_limiter_allows_within_burst() {
        // Disable refill for this burst-only invariant. With a high sustained
        // rate, a slow CI runner can legitimately refill one token while this
        // loop is still executing, making the "11th is dropped" assertion
        // time-dependent. Refill behavior is covered separately below.
        let limiter = GlobalRateLimiter::new(0, 10);
        // Burst capacity is 10.
        for _ in 0..10 {
            assert!(limiter.check());
        }
        // 11th is dropped (burst exhausted, no refill yet).
        assert!(!limiter.check());
        assert_eq!(limiter.available_tokens(), 0);
    }

    #[test]
    fn test_global_rate_limiter_refills_over_time() {
        let limiter = GlobalRateLimiter::new(2, 4);

        for _ in 0..4 {
            assert!(limiter.check_at(0));
        }
        assert!(!limiter.check_at(0));
        assert!(!limiter.check_at(499_999_999));
        assert!(limiter.check_at(500_000_000));
        assert!(!limiter.check_at(500_000_000));
        assert!(limiter.check_at(1_000_000_000));
        assert!(!limiter.check_at(1_000_000_000));
        assert_eq!(limiter.accepted.load(Ordering::Relaxed), 6);
    }

    #[test]
    fn test_global_rate_limiter_default_cap() {
        let limiter = GlobalRateLimiter::with_default_cap();
        assert_eq!(limiter.refill_per_sec(), DEFAULT_GLOBAL_RATE_LIMIT_PPS);
        assert_eq!(limiter.capacity(), DEFAULT_GLOBAL_RATE_LIMIT_PPS * 2);
    }

    #[test]
    fn test_global_rate_limiter_aggregate_across_ips() {
        // Simulate 60,000 PPS across many IPs: with a 50,000 PPS global cap
        // and a tiny burst, only the burst + refilled tokens get through.
        let limiter = GlobalRateLimiter::new(50_000, 1_000);
        let mut allowed = 0u64;
        // 60,000 immediate attempts.
        for _ in 0..60_000 {
            if limiter.check() {
                allowed += 1;
            }
        }
        // The burst (1,000) is admitted instantly; some additional tokens may
        // be refilled during the loop's real-world execution time. The key
        // invariant is that the global cap *prevents* all 60,000 from passing.
        assert!(allowed < 60_000, "global cap should prevent flooding: got {allowed}");
        assert!(allowed >= 1_000, "at least the burst should be admitted: got {allowed}");
    }

    #[test]
    fn global_rate_limiter_pps_uses_only_the_latest_interval_delta() {
        let limiter = GlobalRateLimiter::new(1, 1);

        assert_eq!(limiter.sample_pps_at(1_000_000_000, 10_000), 0);
        assert_eq!(limiter.sample_pps_at(2_000_000_000, 11_000), 1_000);
        assert_eq!(limiter.sample_pps_at(2_500_000_000, 11_250), 500);
        assert_eq!(limiter.sample_pps_at(3_500_000_000, 11_250), 0);
    }

    // ---- EwmaAnomalyDetector ----

    fn deterministic_ddos_config() -> DdosPolicyConfig {
        DdosPolicyConfig {
            sample_interval: Duration::from_secs(1),
            activation_window: Duration::from_secs(3),
            clear_window: Duration::from_secs(4),
            ewma_alpha: 0.1,
            spike_multiplier: 3.0,
            clear_factor: 1.5,
            ..DdosPolicyConfig::default()
        }
    }

    #[test]
    fn test_ewma_no_anomaly_at_baseline() {
        let det = EwmaAnomalyDetector::with_defaults();
        // Feed a steady baseline.
        for _ in 0..100 {
            det.record_pps(100);
        }
        assert!(!det.is_anomaly());
        assert_eq!(det.limit_multiplier(), 1.0);
    }

    #[test]
    fn test_ewma_spike_triggers_anomaly() {
        let det = EwmaAnomalyDetector::with_config(deterministic_ddos_config()).unwrap();
        det.record_pps_at(100, Duration::ZERO);
        assert!(!det.is_anomaly());
        assert_eq!(det.record_pps_at(1_000, Duration::from_secs(1)), DdosTransition::Unchanged);
        assert_eq!(det.record_pps_at(1_000, Duration::from_secs(3)), DdosTransition::Unchanged);
        assert_eq!(det.record_pps_at(1_000, Duration::from_secs(4)), DdosTransition::Activated);
        assert!(det.is_anomaly());
        assert_eq!(det.limit_multiplier(), 0.5, "anomaly should halve the per-IP limit");
        assert_eq!(det.enhanced_packet_cost(), 2);
    }

    #[test]
    fn test_ewma_auto_clears_when_rate_settles() {
        let det = EwmaAnomalyDetector::with_config(deterministic_ddos_config()).unwrap();
        det.record_pps_at(100, Duration::ZERO);
        det.record_pps_at(1_000, Duration::from_secs(1));
        det.record_pps_at(1_000, Duration::from_secs(4));
        assert!(det.is_anomaly());
        assert_eq!(det.record_pps_at(100, Duration::from_secs(5)), DdosTransition::Unchanged);
        assert_eq!(det.record_pps_at(100, Duration::from_secs(8)), DdosTransition::Unchanged);
        assert_eq!(det.record_pps_at(100, Duration::from_secs(9)), DdosTransition::Cleared);
        assert!(!det.is_anomaly());
        assert_eq!(det.limit_multiplier(), 1.0);
    }

    #[test]
    fn test_ewma_spike_and_clear_windows_reset_on_one_sample_recovery() {
        let det = EwmaAnomalyDetector::with_config(deterministic_ddos_config()).unwrap();
        det.record_pps_at(100, Duration::ZERO);
        det.record_pps_at(1_000, Duration::from_secs(1));
        det.record_pps_at(100, Duration::from_secs(2));
        det.record_pps_at(1_000, Duration::from_secs(3));
        det.record_pps_at(1_000, Duration::from_secs(5));
        assert!(!det.is_anomaly());
        det.record_pps_at(1_000, Duration::from_secs(6));
        assert!(det.is_anomaly());

        det.record_pps_at(100, Duration::from_secs(7));
        det.record_pps_at(1_000, Duration::from_secs(8));
        det.record_pps_at(100, Duration::from_secs(9));
        det.record_pps_at(100, Duration::from_secs(12));
        assert!(det.is_anomaly());
        det.record_pps_at(100, Duration::from_secs(13));
        assert!(!det.is_anomaly());
    }

    #[test]
    fn test_ddos_policy_validation_and_disable_semantics() {
        let valid = deterministic_ddos_config();
        assert!(valid.validate().is_ok());

        let mut invalid = valid.clone();
        invalid.sample_interval = Duration::ZERO;
        assert!(invalid.validate().is_err());
        invalid = valid.clone();
        invalid.ewma_alpha = f64::NAN;
        assert!(invalid.validate().is_err());
        invalid = valid.clone();
        invalid.spike_multiplier = 1.0;
        assert!(invalid.validate().is_err());
        invalid = valid.clone();
        invalid.clear_factor = invalid.spike_multiplier;
        assert!(invalid.validate().is_err());
        invalid = valid.clone();
        invalid.enhanced_packet_cost = 1;
        assert!(invalid.validate().is_err());

        let disabled = DdosPolicyConfig { enabled: false, ..valid };
        let det = EwmaAnomalyDetector::with_config(disabled).unwrap();
        det.record_pps_at(100, Duration::ZERO);
        for second in 1..10 {
            assert_eq!(
                det.record_pps_at(10_000, Duration::from_secs(second)),
                DdosTransition::Unchanged
            );
        }
        assert!(!det.is_anomaly());
    }

    #[test]
    fn test_ewma_gradual_increase_no_false_positive() {
        let det = EwmaAnomalyDetector::new(0.1, 3.0);
        // Gradual ramp from 100 → 500 over many samples.
        let mut pps = 100u64;
        for _ in 0..200 {
            det.record_pps(pps);
            pps = pps.saturating_add(2);
        }
        assert!(!det.is_anomaly(), "gradual increase must not trigger a false positive");
    }

    #[test]
    fn test_ewma_clear_method() {
        let det = EwmaAnomalyDetector::with_defaults();
        det.anomaly_active.store(true, Ordering::Relaxed);
        assert!(det.is_anomaly());
        det.clear();
        assert!(!det.is_anomaly());
    }

    // ---- GeoIpBlocker ----

    #[test]
    fn test_geoip_disabled_never_blocks() {
        let blocker = GeoIpBlocker::disabled();
        assert!(!blocker.is_enabled());
        assert_eq!(blocker.status(), GeoIpStatus::Disabled);
        let ip: IpAddr = "1.2.3.4".parse().unwrap();
        assert!(!blocker.lookup(ip).unwrap());
        assert!(!blocker.is_blocked(ip));
    }

    #[test]
    fn test_geoip_config_validation_rejects_partial_and_invalid_policies() {
        let cases = [
            (
                GeoIpConfig {
                    db_path: None,
                    blocked_countries: ["CN".to_string()].into_iter().collect(),
                },
                GeoIpError::DatabasePathRequired,
            ),
            (
                GeoIpConfig {
                    db_path: Some(PathBuf::from("country.mmdb")),
                    blocked_countries: HashSet::new(),
                },
                GeoIpError::BlockedCountriesRequired,
            ),
            (
                GeoIpConfig {
                    db_path: Some(PathBuf::from("country.mmdb")),
                    blocked_countries: ["cn".to_string()].into_iter().collect(),
                },
                GeoIpError::InvalidCountryCode("cn".to_string()),
            ),
        ];
        for (config, expected) in cases {
            assert_eq!(config.validate().unwrap_err(), expected);
        }
    }

    #[test]
    fn test_geoip_activation_rejects_missing_empty_and_corrupt_databases() {
        let missing = PathBuf::from(format!(
            "/nonexistent/quicfuscate-geoip-{}-{}.mmdb",
            std::process::id(),
            crate::transport::rand::rand_u64()
        ));
        let config = |path: PathBuf| GeoIpConfig {
            db_path: Some(path),
            blocked_countries: ["CN".to_string()].into_iter().collect(),
        };
        assert!(matches!(
            GeoIpBlocker::try_new(config(missing.clone())),
            Err(GeoIpError::MissingDatabase(path)) if path == missing
        ));

        let empty = std::env::temp_dir().join(format!(
            "quicfuscate-geoip-empty-{}-{}.mmdb",
            std::process::id(),
            crate::transport::rand::rand_u64()
        ));
        std::fs::write(&empty, []).unwrap();
        assert!(matches!(
            GeoIpBlocker::try_new(config(empty.clone())),
            Err(GeoIpError::EmptyDatabase(path)) if path == empty
        ));
        std::fs::remove_file(empty).unwrap();

        let corrupt = std::env::temp_dir().join(format!(
            "quicfuscate-geoip-corrupt-{}-{}.mmdb",
            std::process::id(),
            crate::transport::rand::rand_u64()
        ));
        std::fs::write(&corrupt, b"not a MaxMind database").unwrap();
        assert!(matches!(
            GeoIpBlocker::try_new(config(corrupt.clone())),
            Err(GeoIpError::InvalidDatabase { path, .. }) if path == corrupt
        ));
        std::fs::remove_file(corrupt).unwrap();
    }

    // ---- BlacklistSync ----

    #[test]
    fn test_blacklist_add_and_is_blocked() {
        let bl = BlacklistSync::manual_only(Duration::from_secs(60));
        let ip: IpAddr = "203.0.113.5".parse().unwrap();
        assert!(!bl.is_blocked(ip));
        bl.add(ip);
        assert!(bl.is_blocked(ip));
        assert_eq!(bl.len(), 1);
        assert!(!bl.is_empty());
    }

    #[test]
    fn test_blacklist_remove() {
        let bl = BlacklistSync::manual_only(Duration::from_secs(60));
        let ip: IpAddr = "203.0.113.5".parse().unwrap();
        bl.add(ip);
        assert!(bl.is_blocked(ip));
        bl.remove(ip);
        assert!(!bl.is_blocked(ip));
    }

    #[test]
    fn test_blacklist_ttl_expiry() {
        let bl = BlacklistSync::manual_only(Duration::from_millis(10));
        let ip: IpAddr = "203.0.113.5".parse().unwrap();
        bl.add(ip);
        assert!(bl.is_blocked(ip));
        std::thread::sleep(Duration::from_millis(20));
        assert!(!bl.is_blocked(ip), "entry should expire after TTL");
        bl.prune_expired();
        assert!(bl.is_empty());
    }

    #[test]
    fn test_blacklist_replace_list() {
        let bl = BlacklistSync::manual_only(Duration::from_secs(60));
        let ips: Vec<IpAddr> = vec!["10.0.0.1".parse().unwrap(), "10.0.0.2".parse().unwrap()];
        bl.replace_list(&ips);
        assert!(bl.is_blocked("10.0.0.1".parse().unwrap()));
        assert!(bl.is_blocked("10.0.0.2".parse().unwrap()));
        assert_eq!(bl.len(), 2);
    }

    #[tokio::test]
    async fn test_blacklist_sync_no_url_errors() {
        let bl_no_url = BlacklistSync::manual_only(Duration::from_secs(60));
        assert!(matches!(bl_no_url.sync().await, Err(BlacklistError::NoSyncUrl)));
    }

    #[test]
    fn test_blacklist_sync_interval() {
        let bl = BlacklistSync::new(
            Duration::from_secs(60),
            Some("https://example.com/blacklist".to_string()),
            Duration::from_secs(3600),
        );
        assert_eq!(bl.sync_interval(), Duration::from_secs(3600));
    }

    #[test]
    fn test_blacklist_has_sync_url() {
        let bl_with_url = BlacklistSync::new(
            Duration::from_secs(60),
            Some("https://example.com/blacklist".to_string()),
            Duration::from_secs(3600),
        );
        assert!(bl_with_url.has_sync_url());

        let bl_no_url = BlacklistSync::manual_only(Duration::from_secs(60));
        assert!(!bl_no_url.has_sync_url());
    }

    #[test]
    fn test_blacklist_sync_parses_plain_text_ips() {
        let bl = BlacklistSync::new_bounded(
            Duration::from_secs(60),
            None,
            Duration::from_secs(60),
            Duration::from_secs(1),
            1024,
            3,
            None,
        )
        .unwrap();
        let count = bl
            .apply_feed(b"# exact feed\n10.0.0.2\n10.0.0.1 # inline\n192.168.1.1\n10.0.0.1\n")
            .unwrap();
        assert_eq!(count, 3);
        assert!(bl.is_blocked("10.0.0.1".parse().unwrap()));
        assert!(bl.is_blocked("10.0.0.2".parse().unwrap()));
        assert!(bl.is_blocked("192.168.1.1".parse().unwrap()));
        assert!(!bl.is_blocked("10.0.0.3".parse().unwrap()));
        assert_eq!(bl.len(), 3);
    }

    #[test]
    fn blacklist_feed_rejects_every_bound_without_replacing_last_known_good() {
        let cache_path = std::env::temp_dir();
        let bl = BlacklistSync::new_bounded(
            Duration::from_secs(60),
            None,
            Duration::from_secs(60),
            Duration::from_secs(1),
            32,
            2,
            Some(cache_path),
        )
        .unwrap();
        let retained: IpAddr = "192.0.2.10".parse().unwrap();
        bl.add(retained);

        for invalid in [
            b"not-an-ip\n".as_slice(),
            &[0xff, 0xfe],
            b"192.0.2.1\n192.0.2.2\n192.0.2.3\n".as_slice(),
            &[b'x'; 33],
        ] {
            assert!(bl.apply_feed(invalid).is_err());
            assert!(bl.is_blocked(retained));
            assert_eq!(bl.len(), 1);
        }

        assert!(bl.apply_feed(b"192.0.2.20\n").is_err(), "directory cache path must fail");
        assert!(bl.is_blocked(retained));
        assert_eq!(bl.len(), 1);
    }

    fn blacklist_cache_path(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "quicfuscate-blacklist-{name}-{}-{}.json",
            std::process::id(),
            crate::transport::rand::rand_u64()
        ))
    }

    fn bounded_blacklist(cache_path: PathBuf) -> BlacklistSync {
        BlacklistSync::new_bounded(
            Duration::from_secs(60),
            None,
            Duration::from_secs(60),
            Duration::from_secs(1),
            4096,
            8,
            Some(cache_path),
        )
        .unwrap()
    }

    #[test]
    fn blacklist_cache_roundtrip_restores_only_unexpired_bounded_entries() {
        let path = blacklist_cache_path("roundtrip");
        let first = bounded_blacklist(path.clone());
        let ips = ["192.0.2.1".parse().unwrap(), "2001:db8::1".parse().unwrap()];
        first.persist_cache(&ips).unwrap();
        drop(first);

        let restored = bounded_blacklist(path.clone());
        assert_eq!(restored.len(), 2);
        assert!(restored.is_blocked(ips[0]));
        assert!(restored.is_blocked(ips[1]));

        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn blacklist_cache_rejects_stale_malformed_oversized_and_interrupted_candidates() {
        let stale_path = blacklist_cache_path("stale");
        let stale = BlacklistCache {
            version: 1,
            expires_at_secs: current_epoch_secs().saturating_sub(1),
            ips: vec!["192.0.2.1".parse().unwrap()],
        };
        std::fs::write(&stale_path, serde_json::to_vec(&stale).unwrap()).unwrap();
        assert!(bounded_blacklist(stale_path.clone()).is_empty());
        std::fs::remove_file(stale_path).unwrap();

        let malformed_path = blacklist_cache_path("malformed");
        std::fs::write(&malformed_path, b"{not-json").unwrap();
        assert!(bounded_blacklist(malformed_path.clone()).is_empty());
        std::fs::remove_file(malformed_path).unwrap();

        let oversized_path = blacklist_cache_path("oversized");
        std::fs::write(&oversized_path, vec![0u8; 4097]).unwrap();
        assert!(bounded_blacklist(oversized_path.clone()).is_empty());
        std::fs::remove_file(oversized_path).unwrap();

        let stable_path = blacklist_cache_path("interrupted");
        let stable = bounded_blacklist(stable_path.clone());
        stable.persist_cache(&["192.0.2.2".parse().unwrap()]).unwrap();
        let interrupted_path = stable_path.with_extension("json.tmp-interrupted");
        std::fs::write(&interrupted_path, b"{partial").unwrap();
        let restored = bounded_blacklist(stable_path.clone());
        assert!(restored.is_blocked("192.0.2.2".parse().unwrap()));
        std::fs::remove_file(stable_path).unwrap();
        std::fs::remove_file(interrupted_path).unwrap();
    }

    #[test]
    fn blacklist_bounded_configuration_rejects_unsafe_values_and_plain_http() {
        assert!(BlacklistSync::new_bounded(
            Duration::ZERO,
            None,
            Duration::from_secs(1),
            Duration::from_secs(1),
            1,
            1,
            None,
        )
        .is_err());
        assert!(BlacklistSync::new_bounded(
            Duration::from_secs(1),
            Some("http://example.com/feed".to_string()),
            Duration::from_secs(1),
            Duration::from_secs(1),
            1,
            1,
            None,
        )
        .is_err());
        assert!(BlacklistSync::new_bounded(
            Duration::from_secs(MAX_BLACKLIST_TTL_SECS + 1),
            None,
            Duration::from_secs(1),
            Duration::from_secs(1),
            1,
            1,
            None,
        )
        .is_err());
        assert!(BlacklistSync::new_bounded(
            Duration::from_secs(1),
            None,
            Duration::from_secs(1),
            Duration::from_secs(MAX_BLACKLIST_REQUEST_TIMEOUT_SECS + 1),
            MAX_BLACKLIST_BODY_BYTES,
            MAX_BLACKLIST_ENTRIES,
            None,
        )
        .is_err());
        assert!(BlacklistSync::new_bounded(
            Duration::from_secs(1),
            None,
            Duration::from_secs(1),
            Duration::from_secs(1),
            MAX_BLACKLIST_BODY_BYTES + 1,
            MAX_BLACKLIST_ENTRIES,
            None,
        )
        .is_err());
        assert!(BlacklistSync::new_bounded(
            Duration::from_secs(1),
            None,
            Duration::from_secs(1),
            Duration::from_secs(1),
            MAX_BLACKLIST_BODY_BYTES,
            MAX_BLACKLIST_ENTRIES + 1,
            None,
        )
        .is_err());
    }

    #[test]
    fn blacklist_custom_ca_rejects_missing_and_malformed_bundles() {
        let missing = blacklist_cache_path("missing-ca");
        assert!(BlacklistSync::new_bounded_with_ca(
            Duration::from_secs(1),
            Some("https://example.com/feed".to_string()),
            Duration::from_secs(1),
            Duration::from_secs(1),
            1,
            1,
            None,
            Some(missing),
        )
        .is_err());

        let malformed = blacklist_cache_path("malformed-ca");
        std::fs::write(&malformed, b"not a PEM certificate").unwrap();
        assert!(BlacklistSync::new_bounded_with_ca(
            Duration::from_secs(1),
            Some("https://example.com/feed".to_string()),
            Duration::from_secs(1),
            Duration::from_secs(1),
            1,
            1,
            None,
            Some(malformed.clone()),
        )
        .is_err());
        std::fs::remove_file(malformed).unwrap();
    }
}
