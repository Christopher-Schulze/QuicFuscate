//! Rate limiting and connection limiting for the server.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Instant;

#[cfg(test)]
use std::collections::{HashMap, HashSet};
#[cfg(test)]
use std::net::IpAddr;
#[cfg(test)]
use std::path::PathBuf;
#[cfg(test)]
use std::time::Duration;

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

mod auth_policy;
mod blacklist;
mod ddos_policy;
mod geoip;
mod rate_limit;
pub use auth_policy::AuthPolicyConfig;
pub(crate) use auth_policy::{
    AuthAdmission, AuthAttempt, AuthCompletion, AuthRateLimiter, AuthTerminal,
};
pub use blacklist::BlacklistSync;
#[cfg(test)]
use blacklist::{current_epoch_secs, publish_blacklist_feed, BlacklistCache};
pub(crate) use blacklist::{BlacklistError, BlacklistSyncControl};
pub use ddos_policy::{DdosPolicyConfig, DdosTransition, EwmaAnomalyDetector};
pub use geoip::{GeoIpBlocker, GeoIpConfig, GeoIpError, GeoIpLookupError, GeoIpStatus};
#[cfg(feature = "rate_limiter")]
pub use rate_limit::load_rate_limit_config_from_env;
#[cfg(test)]
use rate_limit::TokenBucket;
pub use rate_limit::{ConnectionLimiter, RateLimitConfig, RateLimiter};

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

#[cfg(test)]
mod tests;
