//! 0-RTT anti-replay protection via strike register.
//!
//! Implements RFC 8446 Section 8 and RFC 9001 Section 9.2 requirements for
//! single-server deployments. A thread-safe strike register tracks SHA-256
//! fingerprints of seen 0-RTT packets and rejects duplicates.

mod config;

pub use config::AntiReplaySection;

use parking_lot::RwLock;
use sha2::{Digest, Sha256};
use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};

/// Anti-replay configuration for 0-RTT early data.
#[derive(Clone, Debug)]
pub struct AntiReplayConfig {
    /// Maximum ticket age before rejection (default: 10s per RFC 8446).
    pub max_ticket_age: Duration,
    /// Maximum entries in the strike register before oldest are evicted.
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
pub struct StrikeRegister {
    entries: RwLock<HashMap<[u8; 32], Instant>>,
    order: RwLock<VecDeque<[u8; 32]>>,
    bloom: RwLock<BloomFilter>,
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
            entries: RwLock::new(HashMap::new()),
            order: RwLock::new(VecDeque::with_capacity(
                effective_capacity(config.max_entries).min(4096),
            )),
            bloom: RwLock::new(BloomFilter::for_capacity(config.max_entries)),
            last_cleanup: RwLock::new(clock.now()),
            config,
        }
    }

    /// Compute the canonical 0-RTT fingerprint from packet components.
    ///
    /// Uses SHA-256(dcid || 0x7C || scid || 0x7C || payload) to produce
    /// a deterministic 32-byte fingerprint. The pipe byte separators prevent
    /// length-extension ambiguity between fields.
    pub fn compute_fingerprint(dcid: &[u8], scid: &[u8], payload: &[u8]) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(dcid);
        h.update(b"|");
        h.update(scid);
        h.update(b"|");
        h.update(payload);
        h.finalize().into()
    }

    /// Check-and-insert atomically.
    ///
    /// Returns `true` if this fingerprint has NOT been seen before (accept).
    /// Returns `false` if it IS a replay (reject).
    ///
    /// When `max_entries` is reached, the oldest entry is evicted before insertion.
    /// A Bloom filter provides fast-negative checks before the full HashMap lookup,
    /// and a FIFO ring makes capacity eviction O(1).
    pub fn check_and_insert(&self, fingerprint: &[u8; 32], now: Instant) -> bool {
        let mut entries = self.entries.write();
        let bloom_maybe = self.bloom.read().might_contain(fingerprint);

        // Reject if already seen (replay)
        if bloom_maybe && entries.contains_key(fingerprint) {
            return false;
        }

        // Capacity eviction: remove oldest if at limit
        let capacity = effective_capacity(self.config.max_entries);
        {
            let mut order = self.order.write();
            while entries.len() >= capacity {
                if let Some(oldest_key) = order.pop_front() {
                    entries.remove(&oldest_key);
                } else {
                    entries.clear();
                    break;
                }
            }
            order.push_back(*fingerprint);
        }

        entries.insert(*fingerprint, now);
        self.bloom.write().insert(fingerprint);
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
        let mut entries = self.entries.write();
        entries.retain(|_, first_seen| now.saturating_duration_since(*first_seen) < max_age);
        let mut order = self.order.write();
        order.retain(|fingerprint| entries.contains_key(fingerprint));
        let mut bloom = BloomFilter::for_capacity(self.config.max_entries);
        for fingerprint in entries.keys() {
            bloom.insert(fingerprint);
        }
        *self.bloom.write() = bloom;
    }

    /// Current number of tracked entries.
    pub fn len(&self) -> usize {
        self.entries.read().len()
    }

    /// Returns true if the register is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.read().is_empty()
    }
}

fn effective_capacity(configured: usize) -> usize {
    configured.max(1)
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
    fn capacity_eviction() {
        let mut cfg = test_config();
        cfg.max_entries = 3;
        let reg = StrikeRegister::new(cfg);

        let now = Instant::now();
        for i in 0..3u8 {
            let fp = StrikeRegister::compute_fingerprint(&[i], &[i], &[i]);
            assert!(reg.check_and_insert(&fp, now + Duration::from_millis(u64::from(i))));
        }
        assert_eq!(reg.len(), 3);

        // 4th insertion should evict oldest (i=0)
        let fp_new = StrikeRegister::compute_fingerprint(b"new", b"new", b"new");
        assert!(reg.check_and_insert(&fp_new, now + Duration::from_millis(10)));
        assert_eq!(reg.len(), 3);

        // Evicted entry (i=0) should be insertable again
        let fp_evicted = StrikeRegister::compute_fingerprint(&[0], &[0], &[0]);
        assert!(reg.check_and_insert(&fp_evicted, now + Duration::from_millis(11)));
    }

    #[test]
    fn zero_capacity_is_clamped_to_one_entry() {
        let mut cfg = test_config();
        cfg.max_entries = 0;
        let reg = StrikeRegister::new(cfg);
        let now = Instant::now();

        let fp1 = StrikeRegister::compute_fingerprint(b"first", b"first", b"first");
        let fp2 = StrikeRegister::compute_fingerprint(b"second", b"second", b"second");
        assert!(reg.check_and_insert(&fp1, now));
        assert!(!reg.check_and_insert(&fp1, now));
        assert!(reg.check_and_insert(&fp2, now + Duration::from_millis(1)));
        assert_eq!(reg.len(), 1);
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
}
