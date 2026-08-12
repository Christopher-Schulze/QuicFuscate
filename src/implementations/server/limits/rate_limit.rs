use super::*;

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
    pub(super) fn byte_burst_capacity(&self) -> Option<u64> {
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
pub(super) struct TokenBucket {
    tokens: u64,
    capacity: u64,
    last_refill: Instant,
    last_seen: Instant,
    refill_rate: u64,
    refill_interval: Duration,
}

impl TokenBucket {
    #[allow(dead_code)]
    fn new(capacity: u64, refill_rate: u64, refill_interval: Duration) -> Self {
        Self::new_at(capacity, refill_rate, refill_interval, ProtocolClock::default().now())
    }

    pub(super) fn new_at(
        capacity: u64,
        refill_rate: u64,
        refill_interval: Duration,
        now: Instant,
    ) -> Self {
        Self {
            tokens: capacity,
            capacity,
            last_refill: now,
            last_seen: now,
            refill_rate,
            refill_interval,
        }
    }

    #[allow(dead_code)]
    fn consume(&mut self, amount: u64) -> bool {
        self.consume_at(amount, ProtocolClock::default().now())
    }

    pub(super) fn consume_at(&mut self, amount: u64, now: Instant) -> bool {
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
        now.saturating_duration_since(self.last_seen) >= max_idle
    }
}

/// Rate limiter using token buckets.
pub struct RateLimiter {
    config: RateLimitConfig,
    packet_buckets: parking_lot::Mutex<HashMap<RateLimitKey, TokenBucket>>,
    byte_buckets: parking_lot::Mutex<HashMap<RateLimitKey, TokenBucket>>,
    clock: ProtocolClock,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum RateLimitKey {
    Session(u64),
    Ip(IpAddr),
}

impl RateLimiter {
    /// Create a new rate limiter.
    pub fn new(config: RateLimitConfig) -> Self {
        Self::new_with_clock(config, &ProtocolClock::default())
    }

    /// Create a rate limiter bound to an explicit protocol clock.
    pub fn new_with_clock(config: RateLimitConfig, clock: &ProtocolClock) -> Self {
        Self {
            config,
            packet_buckets: parking_lot::Mutex::new(HashMap::new()),
            byte_buckets: parking_lot::Mutex::new(HashMap::new()),
            clock: clock.clone(),
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
            TokenBucket::new_at(
                burst,
                self.config.max_pps,
                self.config.refill_interval,
                self.clock.now(),
            )
        });
        let allowed = bucket.consume_at(cost, self.clock.now());

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
            TokenBucket::new_at(
                capacity,
                self.config.max_bps,
                self.config.refill_interval,
                self.clock.now(),
            )
        });
        let allowed = bucket.consume_at(bytes, self.clock.now());
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
        let now = self.clock.now();
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
