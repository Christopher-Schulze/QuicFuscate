//! 0-RTT anti-replay protection via strike register.
//!
//! Implements RFC 8446 Section 8 and RFC 9001 Section 9.2 requirements for
//! single-server deployments. A thread-safe strike register tracks SHA-256
//! fingerprints of seen 0-RTT packets, rejects duplicates, and fails closed
//! when its bounded replay window is full.

mod config;

pub use config::AntiReplaySection;

use parking_lot::RwLock;
use sha2::{Digest, Sha256};
use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};

/// Upper bound for `AntiReplayConfig::max_entries` (16 Mi entries).
///
/// Beyond this the Bloom bitset sizing (`capacity * 16` bits, rounded up to a
/// power of two) could wrap and produce a zero-length table with an unmasked
/// index - an out-of-bounds panic on the first packet. 16 Mi fingerprints is
/// already far beyond any plausible 0-RTT ticket volume inside the maximum
/// ticket age.
pub const MAX_STRIKE_ENTRIES: usize = 1 << 24;

/// Anti-replay configuration for 0-RTT early data.
#[derive(Clone, Debug)]
pub struct AntiReplayConfig {
    /// Replay-fingerprint retention window. Rustls independently validates ticket freshness.
    pub max_ticket_age: Duration,
    /// Maximum retained entries. New entries fail closed at capacity until cleanup.
    pub max_entries: usize,
    /// Minimum interval between cleanup sweeps (default: 1s).
    pub cleanup_interval: Duration,
    /// Maximum early data size in bytes (default: 16384).
    pub max_early_data_size: u32,
}

impl Default for AntiReplayConfig {
    fn default() -> Self {
        Self {
            max_ticket_age: Duration::from_secs(10),
            max_entries: 100_000,
            cleanup_interval: Duration::from_secs(1),
            max_early_data_size: 16384,
        }
    }
}

/// Thread-safe strike register for 0-RTT replay prevention.
///
/// Stores SHA-256(DCID || SCID || decrypted_payload) fingerprints with
/// first-seen timestamps. A 0-RTT packet whose fingerprint is already
/// present is a replay and must be silently discarded.
/// Entries, FIFO order, and Bloom filter are always mutated together inside
/// `check_and_insert` - one lock instead of three separate RwLocks (4
/// acquisitions per packet previously).
struct StrikeInner {
    entries: HashMap<[u8; 32], Instant>,
    order: VecDeque<[u8; 32]>,
    bloom: BloomFilter,
}

pub struct StrikeRegister {
    inner: RwLock<StrikeInner>,
    config: AntiReplayConfig,
    last_cleanup: RwLock<Instant>,
}

impl StrikeRegister {
    /// Create a new strike register with the given configuration.
    pub fn new(config: AntiReplayConfig) -> Self {
        Self::new_with_clock(config, qf_common::time_source::ProtocolClock::default())
    }

    /// Create a strike register with an explicit protocol clock owner.
    pub fn new_with_clock(
        config: AntiReplayConfig,
        clock: qf_common::time_source::ProtocolClock,
    ) -> Self {
        Self {
            inner: RwLock::new(StrikeInner {
                entries: HashMap::new(),
                order: VecDeque::with_capacity(effective_capacity(config.max_entries).min(4096)),
                bloom: BloomFilter::for_capacity(config.max_entries),
            }),
            last_cleanup: RwLock::new(clock.now()),
            config,
        }
    }

    /// Compute a domain-separated, length-delimited 0-RTT packet fingerprint.
    pub fn compute_fingerprint(dcid: &[u8], scid: &[u8], payload: &[u8]) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(b"quicfuscate 0rtt replay v1");
        for part in [dcid, scid, payload] {
            h.update((part.len() as u64).to_be_bytes());
            h.update(part);
        }
        h.finalize().into()
    }

    /// Check-and-insert atomically.
    ///
    /// Returns `true` if this fingerprint is accepted.
    /// Returns `false` for a duplicate or when capacity is saturated.
    ///
    /// When `max_entries` is reached, new fingerprints are rejected until cleanup
    /// removes expired entries. This preserves the replay window under saturation.
    /// A Bloom filter provides fast-negative checks before the full HashMap lookup,
    /// and the FIFO supports bounded expiry cleanup.
    pub fn check_and_insert(&self, fingerprint: &[u8; 32], now: Instant) -> bool {
        let mut inner = self.inner.write();

        // Reject if already seen (replay)
        if inner.bloom.might_contain(fingerprint) && inner.entries.contains_key(fingerprint) {
            return false;
        }

        let capacity = effective_capacity(self.config.max_entries);
        if inner.entries.len() >= capacity {
            return false;
        }
        inner.order.push_back(*fingerprint);
        inner.entries.insert(*fingerprint, now);
        inner.bloom.insert(fingerprint);
        true
    }

    /// Remove all entries older than `max_ticket_age`.
    ///
    /// Rate-limited by `cleanup_interval` to avoid excessive sweeps.
    pub fn cleanup(&self, now: Instant) {
        {
            let last = self.last_cleanup.read();
            if now.saturating_duration_since(*last) < self.config.cleanup_interval {
                return;
            }
        }
        {
            let mut last = self.last_cleanup.write();
            *last = now;
        }
        let max_age = self.config.max_ticket_age;
        let mut guard = self.inner.write();
        let StrikeInner { entries, order, bloom } = &mut *guard;
        entries.retain(|_, first_seen| now.saturating_duration_since(*first_seen) < max_age);
        order.retain(|fingerprint| entries.contains_key(fingerprint));
        let mut rebuilt = BloomFilter::for_capacity(self.config.max_entries);
        for fingerprint in entries.keys() {
            rebuilt.insert(fingerprint);
        }
        *bloom = rebuilt;
    }

    /// Current number of tracked entries.
    pub fn len(&self) -> usize {
        self.inner.read().entries.len()
    }

    /// Returns true if the register is empty.
    pub fn is_empty(&self) -> bool {
        self.inner.read().entries.is_empty()
    }

    /// Maximum accepted early-data payload bytes per connection.
    pub fn max_early_data_size(&self) -> u32 {
        self.config.max_early_data_size
    }
}

fn effective_capacity(configured: usize) -> usize {
    configured.clamp(1, MAX_STRIKE_ENTRIES)
}

#[derive(Clone, Debug)]
struct BloomFilter {
    bits: Vec<u64>,
    mask: u64,
}

impl BloomFilter {
    fn for_capacity(capacity: usize) -> Self {
        let bits = effective_capacity(capacity).saturating_mul(16).max(1024).next_power_of_two();
        let words = bits / u64::BITS as usize;
        Self { bits: vec![0; words], mask: bits as u64 - 1 }
    }

    fn insert(&mut self, fingerprint: &[u8; 32]) {
        for bit in self.bit_indices(fingerprint) {
            self.bits[bit / u64::BITS as usize] |= 1u64 << (bit % u64::BITS as usize);
        }
    }

    fn might_contain(&self, fingerprint: &[u8; 32]) -> bool {
        self.bit_indices(fingerprint).into_iter().all(|bit| {
            (self.bits[bit / u64::BITS as usize] & (1u64 << (bit % u64::BITS as usize))) != 0
        })
    }

    fn bit_indices(&self, fingerprint: &[u8; 32]) -> [usize; 4] {
        let mut first = [0u8; 8];
        first.copy_from_slice(&fingerprint[0..8]);
        let mut second = [0u8; 8];
        second.copy_from_slice(&fingerprint[8..16]);
        let h1 = u64::from_be_bytes(first);
        let h2 = u64::from_be_bytes(second) | 1;
        [
            (h1 & self.mask) as usize,
            (h1.wrapping_add(h2) & self.mask) as usize,
            (h1.wrapping_add(h2.wrapping_mul(2)) & self.mask) as usize,
            (h1.wrapping_add(h2.wrapping_mul(3)) & self.mask) as usize,
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> AntiReplayConfig {
        AntiReplayConfig {
            max_ticket_age: Duration::from_secs(5),
            max_entries: 10,
            cleanup_interval: Duration::from_millis(50),
            max_early_data_size: 16384,
        }
    }

    #[test]
    fn first_insertion_accepted() {
        let reg = StrikeRegister::new(test_config());
        let fp = StrikeRegister::compute_fingerprint(b"dcid1", b"scid1", b"payload1");
        assert!(reg.check_and_insert(&fp, Instant::now()));
        assert_eq!(reg.len(), 1);
    }

    #[test]
    fn duplicate_rejected() {
        let reg = StrikeRegister::new(test_config());
        let fp = StrikeRegister::compute_fingerprint(b"dcid1", b"scid1", b"payload1");
        let now = Instant::now();
        assert!(reg.check_and_insert(&fp, now));
        assert!(!reg.check_and_insert(&fp, now));
        assert_eq!(reg.len(), 1);
    }

    #[test]
    fn different_fingerprints_accepted() {
        let reg = StrikeRegister::new(test_config());
        let fp1 = StrikeRegister::compute_fingerprint(b"dcid1", b"scid1", b"payload1");
        let fp2 = StrikeRegister::compute_fingerprint(b"dcid2", b"scid2", b"payload2");
        let now = Instant::now();
        assert!(reg.check_and_insert(&fp1, now));
        assert!(reg.check_and_insert(&fp2, now));
        assert_eq!(reg.len(), 2);
    }

    #[test]
    fn ttl_expiry_allows_reinsert() {
        let mut cfg = test_config();
        cfg.max_ticket_age = Duration::from_millis(50);
        cfg.cleanup_interval = Duration::from_millis(0);
        let reg = StrikeRegister::new(cfg);

        let fp = StrikeRegister::compute_fingerprint(b"dcid", b"scid", b"data");
        let t0 = Instant::now();
        assert!(reg.check_and_insert(&fp, t0));

        // Cleanup after TTL expiry
        std::thread::sleep(Duration::from_millis(60));
        let t1 = Instant::now();
        reg.cleanup(t1);
        assert_eq!(reg.len(), 0);

        // Same fingerprint accepted again after expiry
        assert!(reg.check_and_insert(&fp, t1));
    }

    #[test]
    fn capacity_saturation_fails_closed_until_entries_expire() {
        let mut cfg = test_config();
        cfg.max_entries = 3;
        cfg.max_ticket_age = Duration::from_millis(50);
        cfg.cleanup_interval = Duration::ZERO;
        let reg = StrikeRegister::new(cfg);

        let now = Instant::now();
        let mut fingerprints = Vec::new();
        // Fill to configured capacity.
        for i in 0..3u8 {
            let fingerprint = StrikeRegister::compute_fingerprint(&[i], &[i], &[i]);
            assert!(reg.check_and_insert(&fingerprint, now + Duration::from_millis(u64::from(i))));
            fingerprints.push(fingerprint);
        }
        assert_eq!(reg.len(), 3);

        // Saturation rejects new fingerprints until the replay window expires.
        let overflow = StrikeRegister::compute_fingerprint(b"new", b"new", b"new");
        assert!(!reg.check_and_insert(&overflow, now + Duration::from_millis(10)));
        assert!(!reg.check_and_insert(&fingerprints[0], now + Duration::from_millis(11)));
        assert_eq!(reg.len(), 3);

        // Expiration cleanup releases capacity without forgetting live fingerprints.
        let expired_at = now + Duration::from_millis(60);
        reg.cleanup(expired_at);
        assert!(reg.is_empty());
        assert!(reg.check_and_insert(&overflow, expired_at));
    }

    #[test]
    fn oversized_capacity_is_clamped_and_stays_functional() {
        // Programmatic AntiReplayConfig construction bypasses section
        // validation; the internal bound must still keep the Bloom sizing
        // arithmetic from wrapping (usize::MAX used to produce a zero-length
        // bit table with mask u64::MAX -> out-of-bounds panic on insert).
        let mut cfg = test_config();
        cfg.max_entries = usize::MAX;
        let reg = StrikeRegister::new(cfg);

        let fp = StrikeRegister::compute_fingerprint(b"huge", b"huge", b"huge");
        assert!(reg.check_and_insert(&fp, Instant::now()));
        assert!(!reg.check_and_insert(&fp, Instant::now()));
        assert_eq!(reg.len(), 1);
    }

    #[test]
    fn zero_capacity_is_clamped_to_one_entry() {
        let mut cfg = test_config();
        cfg.max_entries = 0;
        cfg.max_ticket_age = Duration::from_millis(10);
        cfg.cleanup_interval = Duration::ZERO;
        let reg = StrikeRegister::new(cfg);
        let now = Instant::now();

        let fp1 = StrikeRegister::compute_fingerprint(b"first", b"first", b"first");
        let fp2 = StrikeRegister::compute_fingerprint(b"second", b"second", b"second");
        assert!(reg.check_and_insert(&fp1, now));
        assert!(!reg.check_and_insert(&fp1, now));
        assert!(!reg.check_and_insert(&fp2, now + Duration::from_millis(1)));
        assert_eq!(reg.len(), 1);

        let expired_at = now + Duration::from_millis(20);
        reg.cleanup(expired_at);
        assert!(reg.is_empty());
        assert!(reg.check_and_insert(&fp2, expired_at));
    }

    #[test]
    fn bloom_filter_tracks_inserted_fingerprints() {
        let fp = StrikeRegister::compute_fingerprint(b"dcid", b"scid", b"payload");
        let other = StrikeRegister::compute_fingerprint(b"dcid", b"scid", b"other");
        let mut bloom = BloomFilter::for_capacity(8);

        assert!(!bloom.might_contain(&fp));
        bloom.insert(&fp);
        assert!(bloom.might_contain(&fp));
        assert!(!bloom.might_contain(&other));
    }

    #[test]
    fn cleanup_removes_expired() {
        let mut cfg = test_config();
        cfg.max_ticket_age = Duration::from_millis(50);
        cfg.cleanup_interval = Duration::from_millis(0);
        let reg = StrikeRegister::new(cfg);

        let t0 = Instant::now();
        let fp1 = StrikeRegister::compute_fingerprint(b"a", b"a", b"a");
        assert!(reg.check_and_insert(&fp1, t0));

        std::thread::sleep(Duration::from_millis(60));
        let t1 = Instant::now();

        // Insert fresh entry
        let fp2 = StrikeRegister::compute_fingerprint(b"b", b"b", b"b");
        assert!(reg.check_and_insert(&fp2, t1));

        // Cleanup should remove only the old one
        reg.cleanup(t1);
        assert_eq!(reg.len(), 1);
    }

    #[test]
    fn cleanup_rate_limited() {
        let mut cfg = test_config();
        cfg.max_ticket_age = Duration::from_millis(1);
        cfg.cleanup_interval = Duration::from_secs(60); // Very long interval
        let reg = StrikeRegister::new(cfg);

        let t0 = Instant::now();
        let fp = StrikeRegister::compute_fingerprint(b"x", b"x", b"x");
        assert!(reg.check_and_insert(&fp, t0));

        std::thread::sleep(Duration::from_millis(5));
        // Cleanup should be rate-limited (interval=60s)
        reg.cleanup(t0 + Duration::from_millis(5));
        // Entry should still be present because cleanup didn't run
        assert_eq!(reg.len(), 1);
    }

    #[test]
    fn fingerprint_deterministic() {
        let fp1 = StrikeRegister::compute_fingerprint(b"dcid", b"scid", b"payload");
        let fp2 = StrikeRegister::compute_fingerprint(b"dcid", b"scid", b"payload");
        assert_eq!(fp1, fp2);
    }

    #[test]
    fn fingerprint_differs_with_different_payload() {
        let fp1 = StrikeRegister::compute_fingerprint(b"dcid", b"scid", b"payload_a");
        let fp2 = StrikeRegister::compute_fingerprint(b"dcid", b"scid", b"payload_b");
        assert_ne!(fp1, fp2);
    }

    #[test]
    fn fingerprint_delimits_binary_component_boundaries() {
        let first = StrikeRegister::compute_fingerprint(b"a", b"b|c", b"d");
        let second = StrikeRegister::compute_fingerprint(b"a|b", b"c", b"d");
        assert_ne!(first, second);
    }
}
