//! Rate limiting and connection limiting for the server.

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

/// Default global server-wide packet rate cap (packets per second across all IPs).
pub const DEFAULT_GLOBAL_RATE_LIMIT_PPS: u64 = 50_000;

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
            max_pps: 1_000, // Down from 10,000 — see TODO-459
            max_bps: 0,     // Unlimited
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
            let refill_amount = if refill_interval_us > 0 {
                let refill = (elapsed.as_micros() * self.refill_rate as u128) / refill_interval_us;
                // Saturate to u64 range
                if refill > u64::MAX as u128 {
                    u64::MAX
                } else {
                    refill as u64
                }
            } else {
                self.capacity
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

/// Per-IP rate limiter for QKey authentication attempts.
///
/// Prevents brute-force attacks on QKey tokens by limiting the number of
/// failed auth attempts per IP within a sliding time window. Successful
/// authentications do not count against the limit.
pub struct AuthRateLimiter {
    max_attempts: u32,
    window: Duration,
    attempts: HashMap<IpAddr, Vec<Instant>>,
}

impl AuthRateLimiter {
    /// Create a new auth rate limiter.
    ///
    /// `max_attempts` is the maximum number of failed auth attempts allowed
    /// per IP within `window`. Once exceeded, further attempts from that IP
    /// are rejected until the oldest attempt expires out of the window.
    pub fn new(max_attempts: u32, window: Duration) -> Self {
        Self { max_attempts, window, attempts: HashMap::new() }
    }

    /// Check if an auth attempt from this IP is allowed without recording it.
    /// Returns `false` if the IP has exceeded the failed-attempt threshold.
    pub fn is_allowed(&self, ip: IpAddr) -> bool {
        match self.attempts.get(&ip) {
            None => true,
            Some(attempts) => {
                let now = Instant::now();
                let recent: usize =
                    attempts.iter().filter(|t| now.duration_since(**t) < self.window).count();
                (recent as u32) < self.max_attempts
            }
        }
    }

    /// Record a failed auth attempt from this IP.
    /// Also prunes expired entries for this IP.
    pub fn record_failure(&mut self, ip: IpAddr) {
        let now = Instant::now();
        let window = self.window;
        let attempts = self.attempts.entry(ip).or_default();
        attempts.retain(|t| now.duration_since(*t) < window);
        attempts.push(now);
    }

    /// Clear all failed attempts for an IP (e.g. on successful auth).
    pub fn clear(&mut self, ip: IpAddr) {
        self.attempts.remove(&ip);
    }

    /// Prune expired entries across all IPs to prevent unbounded memory growth.
    pub fn prune_expired(&mut self) {
        let now = Instant::now();
        let window = self.window;
        self.attempts.retain(|_, attempts| {
            attempts.retain(|t| now.duration_since(*t) < window);
            !attempts.is_empty()
        });
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
// GeoIP blocking stub.
//
// The struct and configuration surface exist now so wiring and config can be
// landed independently of the `maxminddb` integration (planned for a later
// phase). Until a database reader is plugged in, `is_blocked` always returns
// `false` — graceful degradation.
// ---------------------------------------------------------------------------

/// Configuration for GeoIP-based country blocking.
#[allow(dead_code)] // public API for admin tooling / future wiring
#[derive(Clone, Debug, Default)]
pub struct GeoIpConfig {
    /// Path to a MaxMindDB GeoLite2 (or equivalent) country database.
    pub db_path: Option<PathBuf>,
    /// ISO country codes to block (e.g. "CN", "RU", "KP").
    pub blocked_countries: HashSet<String>,
}

/// GeoIP-based source-IP blocker (stub).
///
/// The MaxMindDB reader integration is deferred to a later phase; this struct
/// provides the configuration surface and `is_blocked` interface so callers
/// can be wired in now. Without a loaded database it never blocks.
#[allow(dead_code)] // public API for admin tooling / future wiring
pub struct GeoIpBlocker {
    config: GeoIpConfig,
}

#[allow(dead_code)] // public API for admin tooling / future wiring
impl GeoIpBlocker {
    /// Create a new blocker from the given config.
    pub fn new(config: GeoIpConfig) -> Self {
        Self { config }
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
    /// **Stub**: until `maxminddb` is integrated this always returns `false`,
    /// providing graceful degradation when no GeoIP database is available.
    pub fn is_blocked(&self, _ip: IpAddr) -> bool {
        false
    }

    /// Borrow the configured blocked-country set.
    pub fn blocked_countries(&self) -> &HashSet<String> {
        &self.config.blocked_countries
    }
}

// ---------------------------------------------------------------------------
// Blacklist sync stub.
//
// Maintains a set of blocked IPs with per-entry TTL. The `sync` interface is
// provided for external threat-intelligence feeds (AbuseIPDB-style); the
// actual HTTP fetch is a later phase. Lookups are O(1) under an RwLock read.
// ---------------------------------------------------------------------------

/// Error type for blacklist synchronization operations.
#[allow(dead_code)] // public API for admin tooling / future wiring
#[derive(Debug)]
pub enum BlacklistError {
    /// No sync URL configured.
    NoSyncUrl,
    /// Sync is not yet implemented (stub for a later integration phase).
    NotImplemented,
    /// I/O error reading/writing the local cache.
    Io(std::io::Error),
}

impl std::fmt::Display for BlacklistError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoSyncUrl => write!(f, "no blacklist sync URL configured"),
            Self::NotImplemented => write!(f, "blacklist sync not yet implemented"),
            Self::Io(e) => write!(f, "blacklist I/O error: {}", e),
        }
    }
}

impl std::error::Error for BlacklistError {}

/// External blacklist synchronizer with TTL-based expiry.
///
/// Tracks blocked IPs in a `HashMap<IpAddr, Instant>` (IP → expiry). Entries
/// auto-expire past their TTL; `prune_expired` reclaims memory. The `sync`
/// method is the interface for an external feed (e.g. AbuseIPDB) to be wired
/// in during a later phase.
#[allow(dead_code)] // public API for admin tooling / future wiring
pub struct BlacklistSync {
    blocked: parking_lot::RwLock<HashMap<IpAddr, Instant>>,
    default_ttl: Duration,
    sync_url: Option<String>,
    sync_interval: Duration,
}

#[allow(dead_code)] // public API for admin tooling / future wiring
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

    /// Synchronize the blacklist from the external feed.
    ///
    /// **Stub**: the HTTP fetch integration is deferred to a later phase.
    /// Returns `BlacklistError::NotImplemented` when a URL is configured but
    /// the fetch path is not yet wired, or `NoSyncUrl` when none is set.
    pub fn sync(&self) -> Result<(), BlacklistError> {
        match &self.sync_url {
            None => Err(BlacklistError::NoSyncUrl),
            Some(_) => Err(BlacklistError::NotImplemented),
        }
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

    #[test]
    fn test_auth_rate_limiter_allows_under_threshold() {
        let mut limiter = AuthRateLimiter::new(5, Duration::from_secs(60));
        let ip: IpAddr = "1.2.3.4".parse().unwrap();

        for _ in 0..5 {
            assert!(limiter.is_allowed(ip));
            limiter.record_failure(ip);
        }
        // 6th attempt should be blocked
        assert!(!limiter.is_allowed(ip));
    }

    #[test]
    fn test_auth_rate_limiter_clears_on_success() {
        let mut limiter = AuthRateLimiter::new(3, Duration::from_secs(60));
        let ip: IpAddr = "1.2.3.4".parse().unwrap();

        limiter.record_failure(ip);
        limiter.record_failure(ip);
        assert!(limiter.is_allowed(ip));

        // Successful auth clears the counter
        limiter.clear(ip);
        assert!(limiter.is_allowed(ip));
    }

    #[test]
    fn test_auth_rate_limiter_ips_are_isolated() {
        let mut limiter = AuthRateLimiter::new(2, Duration::from_secs(60));
        let ip1: IpAddr = "1.2.3.4".parse().unwrap();
        let ip2: IpAddr = "5.6.7.8".parse().unwrap();

        limiter.record_failure(ip1);
        limiter.record_failure(ip1);
        assert!(!limiter.is_allowed(ip1));
        assert!(limiter.is_allowed(ip2));
    }

    #[test]
    fn test_auth_rate_limiter_prunes_expired() {
        let mut limiter = AuthRateLimiter::new(1, Duration::from_millis(10));
        let ip: IpAddr = "1.2.3.4".parse().unwrap();

        limiter.record_failure(ip);
        assert!(!limiter.is_allowed(ip));

        std::thread::sleep(Duration::from_millis(20));
        limiter.prune_expired();
        assert!(limiter.is_allowed(ip));
    }

    // ---- RateLimitConfig defaults & burst ----

    #[test]
    fn test_rate_limit_config_default_pps_lowered() {
        let cfg = RateLimitConfig::default();
        assert_eq!(cfg.max_pps, 1_000, "default per-IP PPS must be 1,000 (TODO-459)");
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
        let limiter = GlobalRateLimiter::new(50_000, 10);
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
    fn test_geoip_configured_but_stub_returns_false() {
        let mut countries = HashSet::new();
        countries.insert("XX".to_string());
        let config = GeoIpConfig {
            db_path: Some(PathBuf::from("/nonexistent/GeoLite2-Country.mmdb")),
            blocked_countries: countries,
        };
        let blocker = GeoIpBlocker::new(config);
        assert!(blocker.is_enabled());
        // Stub phase: is_blocked always returns false (graceful degradation).
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

    #[test]
    fn test_blacklist_sync_stub_errors() {
        let bl_no_url = BlacklistSync::manual_only(Duration::from_secs(60));
        assert!(matches!(bl_no_url.sync(), Err(BlacklistError::NoSyncUrl)));

        let bl_with_url = BlacklistSync::new(
            Duration::from_secs(60),
            Some("https://example.com/blacklist".to_string()),
            Duration::from_secs(3600),
        );
        assert!(matches!(bl_with_url.sync(), Err(BlacklistError::NotImplemented)));
        assert_eq!(bl_with_url.sync_interval(), Duration::from_secs(3600));
    }
}
