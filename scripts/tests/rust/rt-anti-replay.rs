#![cfg(feature = "rust-tests")]

use quicfuscate::optimize::telemetry::{
    ZERO_RTT_ACCEPT_TOTAL, ZERO_RTT_POLICY_REJECT_TOTAL, ZERO_RTT_REPLAY_REJECT_TOTAL,
};
use quicfuscate::transport::anti_replay::{AntiReplayConfig, StrikeRegister};
use std::time::{Duration, Instant};

fn test_config() -> AntiReplayConfig {
    AntiReplayConfig {
        max_ticket_age: Duration::from_secs(5),
        max_entries: 10,
        cleanup_interval: Duration::from_millis(50),
        max_early_data_size: 16384,
    }
}

#[test]
fn first_insertion_returns_true() {
    let reg = StrikeRegister::new(test_config());
    let fp = StrikeRegister::compute_fingerprint(b"dcid1", b"scid1", b"payload1");
    assert!(reg.check_and_insert(&fp, Instant::now()));
    assert_eq!(reg.len(), 1);
}

#[test]
fn duplicate_returns_false() {
    let reg = StrikeRegister::new(test_config());
    let fp = StrikeRegister::compute_fingerprint(b"dcid1", b"scid1", b"payload1");
    let now = Instant::now();
    assert!(reg.check_and_insert(&fp, now));
    assert!(!reg.check_and_insert(&fp, now));
    assert_eq!(reg.len(), 1);
}

#[test]
fn ttl_expiry_allows_reinsert() {
    let cfg = AntiReplayConfig {
        max_ticket_age: Duration::from_millis(50),
        max_entries: 100,
        cleanup_interval: Duration::from_millis(0),
        max_early_data_size: 16384,
    };
    let reg = StrikeRegister::new(cfg);

    let fp = StrikeRegister::compute_fingerprint(b"dcid", b"scid", b"data");
    let t0 = Instant::now();
    assert!(reg.check_and_insert(&fp, t0));

    // Wait for TTL to expire, then cleanup
    std::thread::sleep(Duration::from_millis(60));
    let t1 = Instant::now();
    reg.cleanup(t1);
    assert_eq!(reg.len(), 0);

    // Same fingerprint accepted again after expiry + cleanup
    assert!(reg.check_and_insert(&fp, t1));
    assert_eq!(reg.len(), 1);
}

#[test]
fn capacity_saturation_fails_closed_until_expiry() {
    let cfg = AntiReplayConfig {
        max_ticket_age: Duration::from_millis(50),
        max_entries: 3,
        cleanup_interval: Duration::ZERO,
        max_early_data_size: 16384,
    };
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
fn cleanup_removes_expired_entries() {
    let cfg = AntiReplayConfig {
        max_ticket_age: Duration::from_millis(50),
        max_entries: 100,
        cleanup_interval: Duration::from_millis(0),
        max_early_data_size: 16384,
    };
    let reg = StrikeRegister::new(cfg);

    let t0 = Instant::now();
    let fp1 = StrikeRegister::compute_fingerprint(b"a", b"a", b"a");
    assert!(reg.check_and_insert(&fp1, t0));

    std::thread::sleep(Duration::from_millis(60));
    let t1 = Instant::now();

    // Insert fresh entry at t1
    let fp2 = StrikeRegister::compute_fingerprint(b"b", b"b", b"b");
    assert!(reg.check_and_insert(&fp2, t1));
    assert_eq!(reg.len(), 2);

    // Cleanup at t1 removes only the expired entry (fp1)
    reg.cleanup(t1);
    assert_eq!(reg.len(), 1);
}

#[test]
fn fingerprint_is_deterministic() {
    let fp1 = StrikeRegister::compute_fingerprint(b"dcid", b"scid", b"payload");
    let fp2 = StrikeRegister::compute_fingerprint(b"dcid", b"scid", b"payload");
    assert_eq!(fp1, fp2);
}

#[test]
fn different_payloads_produce_different_fingerprints() {
    let fp_a = StrikeRegister::compute_fingerprint(b"dcid", b"scid", b"payload_a");
    let fp_b = StrikeRegister::compute_fingerprint(b"dcid", b"scid", b"payload_b");
    assert_ne!(fp_a, fp_b);
}

#[test]
fn different_dcids_produce_different_fingerprints() {
    let fp1 = StrikeRegister::compute_fingerprint(b"dcid_1", b"scid", b"payload");
    let fp2 = StrikeRegister::compute_fingerprint(b"dcid_2", b"scid", b"payload");
    assert_ne!(fp1, fp2);
}

#[test]
fn different_scids_produce_different_fingerprints() {
    let fp1 = StrikeRegister::compute_fingerprint(b"dcid", b"scid_1", b"payload");
    let fp2 = StrikeRegister::compute_fingerprint(b"dcid", b"scid_2", b"payload");
    assert_ne!(fp1, fp2);
}

#[test]
fn empty_register_reports_empty() {
    let reg = StrikeRegister::new(test_config());
    assert!(reg.is_empty());
    assert_eq!(reg.len(), 0);

    let fp = StrikeRegister::compute_fingerprint(b"a", b"b", b"c");
    reg.check_and_insert(&fp, Instant::now());
    assert!(!reg.is_empty());
}

#[test]
fn telemetry_counters_are_accessible() {
    // These counters are incremented by connection.rs recv() path, not by StrikeRegister
    // directly. Here we just verify the counters are importable and monotonically readable.
    let accept_before = ZERO_RTT_ACCEPT_TOTAL.get();
    let replay_before = ZERO_RTT_REPLAY_REJECT_TOTAL.get();
    let policy_before = ZERO_RTT_POLICY_REJECT_TOTAL.get();

    assert!(accept_before < u64::MAX);
    assert!(replay_before < u64::MAX);
    assert!(policy_before < u64::MAX);

    assert!(ZERO_RTT_ACCEPT_TOTAL.get() >= accept_before);
    assert!(ZERO_RTT_REPLAY_REJECT_TOTAL.get() >= replay_before);
    assert!(ZERO_RTT_POLICY_REJECT_TOTAL.get() >= policy_before);
}

#[test]
fn cleanup_rate_limiting_prevents_premature_sweep() {
    let cfg = AntiReplayConfig {
        max_ticket_age: Duration::from_millis(1),
        max_entries: 100,
        cleanup_interval: Duration::from_secs(60), // Very long interval
        max_early_data_size: 16384,
    };
    let reg = StrikeRegister::new(cfg);

    let t0 = Instant::now();
    let fp = StrikeRegister::compute_fingerprint(b"x", b"x", b"x");
    assert!(reg.check_and_insert(&fp, t0));

    std::thread::sleep(Duration::from_millis(5));
    // Cleanup should be rate-limited (interval=60s), so expired entry stays
    reg.cleanup(t0 + Duration::from_millis(5));
    assert_eq!(reg.len(), 1);
}

#[test]
fn default_config_has_sane_values() {
    let cfg = AntiReplayConfig::default();
    assert_eq!(cfg.max_ticket_age, Duration::from_secs(10));
    assert_eq!(cfg.max_entries, 100_000);
    assert_eq!(cfg.cleanup_interval, Duration::from_secs(1));
    assert_eq!(cfg.max_early_data_size, 16384);
}
