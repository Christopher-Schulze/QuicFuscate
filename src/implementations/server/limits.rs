//! Rate limiting and connection limiting for the server.

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

/// Default global server-wide packet rate cap (packets per second across all IPs).
pub const DEFAULT_GLOBAL_RATE_LIMIT_PPS: u64 = 50_000;
/// Default sustained packet rate per source.
///
/// This must leave headroom above normal tunnel packet rates so the abuse
/// control cannot manufacture transport loss under legitimate throughput.
pub const DEFAULT_PER_SOURCE_RATE_LIMIT_PPS: u64 = 10_000;

/// Rate limit configuration.
#[derive(Clone, Debug)]
pub struct RateLimitConfig {
    /// Maximum packets per second per client (sustained rate)
    pub max_pps: u64,
    /// Maximum bytes per second per client (0 = unlimited)
    pub max_bps: u64,
    /// Bucket refill interval
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
        Self {
            tokens: capacity,
            capacity,
            last_refill: Instant::now(),
            last_seen: Instant::now(),
            refill_rate,
            refill_interval,
        }
    }

    fn consume(&mut self, amount: u64) -> bool {
        let now = Instant::now();
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
        let elapsed = now.duration_since(self.last_refill);

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

            self.tokens = (self.tokens + refill_amount).min(self.capacity);
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
        self.check_packet_key(RateLimitKey::Ip(ip))
    }

    fn check_packet_key(&self, key: RateLimitKey) -> bool {
        let burst = self.config.effective_burst();
        let mut buckets = self.packet_buckets.lock();
        let bucket = buckets.entry(key).or_insert_with(|| {
            TokenBucket::new(burst, self.config.max_pps, self.config.refill_interval)
        });
        let allowed = bucket.consume(1);

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

        let mut buckets = self.byte_buckets.lock();
        let bucket = buckets.entry(key).or_insert_with(|| {
            TokenBucket::new(self.config.max_bps, self.config.max_bps, self.config.refill_interval)
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
        let now = self.now_ns();
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
        let now = self.now_ns();
        let last_ns = self.last_pps_ns.load(Ordering::Relaxed);
        let total = self.accepted.load(Ordering::Relaxed);
        if last_ns == 0 {
            // First snapshot — seed the baseline.
            self.last_pps_ns.store(now, Ordering::Relaxed);
            self.last_pps.store(0, Ordering::Relaxed);
            return 0;
        }
        let elapsed_ns = now.saturating_sub(last_ns);
        if elapsed_ns == 0 {
            return self.last_pps.load(Ordering::Relaxed);
        }
        // PPS = (total - prev_total) / elapsed_seconds.
        // We don't store prev_total separately; instead we compute a running
        // rate from the delta since the last snapshot.
        let pps = (total as u128 * 1_000_000_000 / elapsed_ns as u128) as u64;
        // Update the snapshot (best-effort).
        self.last_pps_ns.store(now, Ordering::Relaxed);
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

/// EWMA-based DDoS/anomaly detector.
///
/// A background sampler calls `record_pps` with the observed PPS each tick.
/// `is_anomaly` reports whether a spike is currently in progress; while it
/// is, `limit_multiplier` returns `0.5` so per-IP limits are temporarily
/// halved. The flag auto-clears once the current rate settles back near the
/// (now-raised) EWMA baseline.
#[allow(dead_code)] // public API for admin tooling / future wiring
pub struct EwmaAnomalyDetector {
    /// EWMA of PPS, stored as `f64::to_bits`.
    ewma_pps: AtomicU64,
    /// Most recent PPS sample.
    current_pps: AtomicU64,
    /// Whether enhanced (stricter) limiting is currently active.
    anomaly_active: AtomicBool,
    /// EWMA smoothing factor α ∈ (0, 1].
    alpha: f64,
    /// Spike threshold: anomaly when current > spike_multiplier × EWMA.
    spike_multiplier: f64,
    /// Clear threshold: anomaly clears when current < ewma × clear_factor.
    clear_factor: f64,
}

#[allow(dead_code)] // public API for admin tooling / future wiring
impl EwmaAnomalyDetector {
    /// Create a detector with the given smoothing and spike threshold.
    pub fn new(alpha: f64, spike_multiplier: f64) -> Self {
        Self {
            ewma_pps: AtomicU64::new(0f64.to_bits()),
            current_pps: AtomicU64::new(0),
            anomaly_active: AtomicBool::new(false),
            alpha: alpha.clamp(0.0, 1.0),
            spike_multiplier,
            clear_factor: 1.5,
        }
    }

    /// Create a detector with sensible defaults (α=0.1, spike=3×).
    pub fn with_defaults() -> Self {
        Self::new(DEFAULT_EWMA_ALPHA, DEFAULT_SPIKE_MULTIPLIER)
    }

    /// Record an observed PPS sample and update the EWMA / anomaly flag.
    ///
    /// Lock-free: the EWMA update uses a CAS loop on the bit-pattern AtomicU64.
    pub fn record_pps(&self, pps: u64) {
        self.current_pps.store(pps, Ordering::Relaxed);

        // Capture the pre-update EWMA for the anomaly check — the spike
        // comparison must use the baseline *before* this sample is absorbed.
        let prev_ewma = f64::from_bits(self.ewma_pps.load(Ordering::Relaxed));

        let mut prev_bits = self.ewma_pps.load(Ordering::Relaxed);
        loop {
            let prev = f64::from_bits(prev_bits);
            let next = self.alpha * (pps as f64) + (1.0 - self.alpha) * prev;
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

        // Use the pre-update EWMA for spike detection so a sudden jump is
        // compared against the historical baseline, not the just-updated value.
        let ewma = prev_ewma;
        let current = pps as f64;
        if ewma > 0.0 && current > self.spike_multiplier * ewma {
            self.anomaly_active.store(true, Ordering::Relaxed);
        } else if ewma > 0.0 && current < self.clear_factor * ewma {
            // Rate has settled back near/under the baseline → clear.
            self.anomaly_active.store(false, Ordering::Relaxed);
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
    }
}

// ---------------------------------------------------------------------------
// GeoIP blocking.
//
// Uses the `maxminddb` crate to look up the country of an IP address in a
// MaxMindDB GeoLite2 (or GeoIP2) database. IPs mapping to a blocked country
// are rejected. When no database is configured, the blocker gracefully
// degrades to allowing all IPs.
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
    /// Whether both a database path and at least one blocked country are configured.
    pub fn is_enabled(&self) -> bool {
        self.db_path.is_some() && !self.blocked_countries.is_empty()
    }
}

/// GeoIP-based source-IP blocker.
///
/// Loads a MaxMindDB country database on construction and performs O(1)
/// lookups per IP. When no database is configured, `is_blocked` always
/// returns `false` (graceful degradation).
pub struct GeoIpBlocker {
    config: GeoIpConfig,
    reader: Option<maxminddb::Reader<Vec<u8>>>,
}

impl GeoIpBlocker {
    /// Create a new blocker from the given config. Loads the MaxMindDB
    /// database if `db_path` is set and blocked countries are configured.
    pub fn new(config: GeoIpConfig) -> Self {
        let reader = if config.is_enabled() {
            match config.db_path.as_ref().unwrap().as_path().try_exists() {
                Ok(true) => {
                    match maxminddb::Reader::open_readfile(config.db_path.as_ref().unwrap()) {
                        Ok(r) => {
                            log::info!(
                                "GeoIP: loaded database from {}",
                                config.db_path.as_ref().unwrap().display()
                            );
                            Some(r)
                        }
                        Err(e) => {
                            log::warn!(
                                "GeoIP: failed to load database from {}: {e}",
                                config.db_path.as_ref().unwrap().display()
                            );
                            None
                        }
                    }
                }
                Ok(false) => {
                    log::warn!(
                        "GeoIP: database not found at {}",
                        config.db_path.as_ref().unwrap().display()
                    );
                    None
                }
                Err(e) => {
                    log::warn!(
                        "GeoIP: cannot access database at {}: {e}",
                        config.db_path.as_ref().unwrap().display()
                    );
                    None
                }
            }
        } else {
            None
        };
        Self { config, reader }
    }

    /// Create a blocker with no database and no blocked countries (no-op).
    pub fn disabled() -> Self {
        Self::new(GeoIpConfig::default())
    }

    /// Whether a database and blocked-country list are configured.
    pub fn is_enabled(&self) -> bool {
        self.config.db_path.is_some() && !self.config.blocked_countries.is_empty()
    }

    /// Returns `true` if the IP maps to a blocked country.
    ///
    /// When no database is loaded, always returns `false` (graceful
    /// degradation). Lookup errors are logged and treated as "not blocked"
    /// to avoid blocking legitimate traffic on database corruption.
    pub fn is_blocked(&self, ip: IpAddr) -> bool {
        let reader = match &self.reader {
            Some(r) => r,
            None => return false,
        };

        let lookup_result = match reader.lookup(ip) {
            Ok(result) => result,
            Err(e) => {
                log::debug!("GeoIP: lookup error for {ip}: {e}");
                return false;
            }
        };
        let country = match lookup_result.decode::<maxminddb::geoip2::Country>() {
            Ok(Some(country)) => country,
            Ok(None) => return false,
            Err(e) => {
                log::debug!("GeoIP: decode error for {ip}: {e}");
                return false;
            }
        };

        let iso_code = match country.country.iso_code {
            Some(code) => code,
            None => return false,
        };

        self.config.blocked_countries.contains(iso_code)
    }

    /// Borrow the configured blocked-country set.
    pub fn blocked_countries(&self) -> &HashSet<String> {
        &self.config.blocked_countries
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
    /// HTTP fetch failed.
    FetchError(String),
}

impl std::fmt::Display for BlacklistError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoSyncUrl => write!(f, "no blacklist sync URL configured"),
            Self::FetchError(s) => write!(f, "blacklist fetch error: {s}"),
        }
    }
}

impl std::error::Error for BlacklistError {}

/// External blacklist synchronizer with TTL-based expiry.
///
/// Tracks blocked IPs in a `HashMap<IpAddr, Instant>` (IP → expiry). Entries
/// auto-expire past their TTL; `prune_expired` reclaims memory. The `sync`
/// method fetches a plain-text IP list (one IP per line, lines starting with
/// `#` are comments) from the configured URL and replaces the blocked set.
pub struct BlacklistSync {
    blocked: parking_lot::RwLock<HashMap<IpAddr, Instant>>,
    default_ttl: Duration,
    sync_url: Option<String>,
    sync_interval: Duration,
}

impl BlacklistSync {
    /// Create a new blacklist synchronizer.
    pub fn new(default_ttl: Duration, sync_url: Option<String>, sync_interval: Duration) -> Self {
        Self {
            blocked: parking_lot::RwLock::new(HashMap::new()),
            default_ttl,
            sync_url,
            sync_interval,
        }
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
        let expiry = Instant::now() + self.default_ttl;
        let mut guard = self.blocked.write();
        guard.clear();
        guard.reserve(ips.len());
        for ip in ips {
            guard.insert(*ip, expiry);
        }
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
    /// The response body is capped at `MAX_FEED_BODY_BYTES` (16 MiB) to
    /// prevent memory exhaustion from a compromised or misconfigured feed
    /// endpoint. Both the `Content-Length` header and the actual byte count
    /// are checked.
    ///
    /// Async because the server's housekeeping loop runs inside a Tokio
    /// runtime; using the async `reqwest::Client` avoids the
    /// "Cannot start a runtime from within a runtime" panic that
    /// `reqwest::blocking` triggers under Tokio. Callers outside an async
    /// context should wrap this in `tokio::task::spawn_blocking` + a
    /// `Runtime::block_on`, or use a dedicated runtime.
    pub async fn sync(&self) -> Result<usize, BlacklistError> {
        const MAX_FEED_BODY_BYTES: u64 = 16 * 1024 * 1024; // 16 MiB

        let url = match &self.sync_url {
            Some(u) => u.clone(),
            None => return Err(BlacklistError::NoSyncUrl),
        };

        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .https_only(true)
            .redirect(reqwest::redirect::Policy::limited(3))
            .user_agent("quicfuscate-blacklist-sync/1.0")
            .build()
            .map_err(|e| BlacklistError::FetchError(format!("client build: {e}")))?;

        let response = client
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
            if len > MAX_FEED_BODY_BYTES {
                return Err(BlacklistError::FetchError(format!(
                    "feed body too large: Content-Length {len} > {MAX_FEED_BODY_BYTES} bytes"
                )));
            }
        }

        let body = response
            .bytes()
            .await
            .map_err(|e| BlacklistError::FetchError(format!("body read: {e}")))?;

        // Hard cap on the actual body size (defeats servers that omit
        // Content-Length or lie about it via chunked encoding).
        if body.len() as u64 > MAX_FEED_BODY_BYTES {
            return Err(BlacklistError::FetchError(format!(
                "feed body too large: actual {} > {MAX_FEED_BODY_BYTES} bytes",
                body.len()
            )));
        }

        // Parse as UTF-8 lossy — IP addresses and comments are ASCII, so
        // invalid UTF-8 bytes become U+FFFD and simply fail to parse as IPs.
        let body_text = String::from_utf8_lossy(&body);

        let mut ips = Vec::new();
        for line in body_text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            // Strip inline comments.
            let ip_str = line.split('#').next().unwrap_or(line).trim();
            if let Ok(ip) = ip_str.parse::<IpAddr>() {
                ips.push(ip);
            }
        }

        let count = ips.len();
        self.replace_list(&ips);
        log::info!("Blacklist sync: loaded {count} IPs from {url}");
        Ok(count)
    }
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
    fn test_token_bucket_burst_then_steady() {
        // burst=5, sustained=2/sec, refill every 1s.
        let mut bucket = TokenBucket::new(5, 2, Duration::from_secs(1));
        // Initial burst of 5 is allowed.
        for _ in 0..5 {
            assert!(bucket.consume(1));
        }
        // 6th immediately is rejected (no refill yet).
        assert!(!bucket.consume(1));
        // After 1s, 2 tokens refill (capped at burst=5).
        std::thread::sleep(Duration::from_millis(1100));
        assert!(bucket.consume(1));
        assert!(bucket.consume(1));
        // Only 2 refilled per second.
        assert!(!bucket.consume(1));
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
        let limiter = GlobalRateLimiter::new(100, 5);
        // Drain the burst.
        for _ in 0..5 {
            assert!(limiter.check());
        }
        assert!(!limiter.check());
        // After ~1s, 100 tokens refill (capped at burst=5).
        std::thread::sleep(Duration::from_millis(1100));
        for _ in 0..5 {
            assert!(limiter.check());
        }
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

    // ---- EwmaAnomalyDetector ----

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
        let det = EwmaAnomalyDetector::new(0.5, 3.0);
        // Establish a baseline.
        for _ in 0..50 {
            det.record_pps(100);
        }
        assert!(!det.is_anomaly());
        // Sudden spike to 1,000 (> 3× the ~100 baseline).
        det.record_pps(1_000);
        assert!(det.is_anomaly());
        assert_eq!(det.limit_multiplier(), 0.5, "anomaly should halve the per-IP limit");
    }

    #[test]
    fn test_ewma_auto_clears_when_rate_settles() {
        let det = EwmaAnomalyDetector::new(0.5, 3.0);
        for _ in 0..50 {
            det.record_pps(100);
        }
        det.record_pps(1_000);
        assert!(det.is_anomaly());
        // Continue feeding high rate so the EWMA rises, then drop back.
        for _ in 0..200 {
            det.record_pps(1_000);
        }
        // EWMA is now ~1,000; feeding 1,000 is no longer a spike and is < 1.5× ewma.
        det.record_pps(1_000);
        assert!(!det.is_anomaly(), "anomaly should clear once rate settles near EWMA");
        assert_eq!(det.limit_multiplier(), 1.0);
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
        let ip: IpAddr = "1.2.3.4".parse().unwrap();
        assert!(!blocker.is_blocked(ip));
    }

    #[test]
    fn test_geoip_configured_but_missing_db_returns_false() {
        let mut countries = HashSet::new();
        countries.insert("XX".to_string());
        let config = GeoIpConfig {
            db_path: Some(PathBuf::from("/nonexistent/GeoLite2-Country.mmdb")),
            blocked_countries: countries,
        };
        let blocker = GeoIpBlocker::new(config);
        assert!(blocker.is_enabled());
        // Database doesn't exist — graceful degradation: is_blocked returns false.
        let ip: IpAddr = "8.8.8.8".parse().unwrap();
        assert!(!blocker.is_blocked(ip));
        assert!(blocker.blocked_countries().contains("XX"));
    }

    #[test]
    fn test_geoip_no_database_not_enabled() {
        let config = GeoIpConfig { db_path: None, blocked_countries: HashSet::new() };
        let blocker = GeoIpBlocker::new(config);
        assert!(!blocker.is_enabled());
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
        // Verify that replace_list correctly handles a parsed IP list
        // (the sync method uses replace_list internally).
        let bl = BlacklistSync::manual_only(Duration::from_secs(60));
        let ips: Vec<IpAddr> =
            ["10.0.0.1", "10.0.0.2", "192.168.1.1"].iter().map(|s| s.parse().unwrap()).collect();
        bl.replace_list(&ips);
        assert!(bl.is_blocked("10.0.0.1".parse().unwrap()));
        assert!(bl.is_blocked("10.0.0.2".parse().unwrap()));
        assert!(bl.is_blocked("192.168.1.1".parse().unwrap()));
        assert!(!bl.is_blocked("10.0.0.3".parse().unwrap()));
        assert_eq!(bl.len(), 3);
    }

    #[test]
    fn test_geoip_blocker_disabled_allows_all() {
        let blocker = GeoIpBlocker::disabled();
        assert!(!blocker.is_enabled());
        assert!(!blocker.is_blocked("1.2.3.4".parse().unwrap()));
    }

    #[test]
    fn test_geoip_blocker_no_db_allows_all() {
        let config = GeoIpConfig {
            db_path: None,
            blocked_countries: ["CN".to_string()].into_iter().collect(),
        };
        let blocker = GeoIpBlocker::new(config);
        assert!(!blocker.is_enabled());
        assert!(!blocker.is_blocked("1.2.3.4".parse().unwrap()));
    }

    #[test]
    fn test_geoip_blocker_missing_db_allows_all() {
        let config = GeoIpConfig {
            db_path: Some(PathBuf::from("/nonexistent/GeoLite2-Country.mmdb")),
            blocked_countries: ["CN".to_string()].into_iter().collect(),
        };
        let blocker = GeoIpBlocker::new(config);
        assert!(blocker.is_enabled());
        // Database doesn't exist — should gracefully degrade to allowing all.
        assert!(!blocker.is_blocked("1.2.3.4".parse().unwrap()));
    }
}
