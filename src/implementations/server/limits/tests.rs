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
        assert_eq!(limiter.complete_at(attempt, AuthTerminal::Failed, now), AuthCompletion::Failed);
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
    assert!(matches!(limiter.begin_at(ip3, Duration::from_millis(51)), AuthAdmission::Allowed(_)));
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
        RateLimitConfig { max_bps: u64::MAX, burst_size: u64::MAX, max_pps: 1, ..explicit_burst }
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
fn rate_limiter_refill_uses_explicit_clock_without_sleeping() {
    let source = crate::time_source::test_support::ManualTimeSource::new(
        Instant::now(),
        std::time::SystemTime::UNIX_EPOCH,
    );
    let clock = ProtocolClock::from_source(source.clone());
    let limiter = RateLimiter::new_with_clock(
        RateLimitConfig {
            max_pps: 1,
            max_bps: 0,
            refill_interval: Duration::from_secs(1),
            burst_size: 1,
        },
        &clock,
    );
    let ip: IpAddr = "192.0.2.11".parse().unwrap();
    assert!(limiter.check_packet_ip(ip));
    assert!(!limiter.check_packet_ip(ip));
    source.advance(Duration::from_secs(1));
    assert!(limiter.check_packet_ip(ip));
}

#[test]
fn auth_rate_limiter_runtime_clock_advances_backoff_without_sleeping() {
    let source = crate::time_source::test_support::ManualTimeSource::new(
        Instant::now(),
        std::time::SystemTime::UNIX_EPOCH,
    );
    let clock = ProtocolClock::from_source(source.clone());
    let mut limiter = AuthRateLimiter::new_with_clock(test_auth_policy_config(), &clock);
    let ip: IpAddr = "192.0.2.12".parse().unwrap();
    let first = allowed_attempt(limiter.begin(ip));
    assert_eq!(limiter.complete(first, AuthTerminal::Failed), AuthCompletion::Failed);
    let second = allowed_attempt(limiter.begin(ip));
    assert!(matches!(
        limiter.complete(second, AuthTerminal::Failed),
        AuthCompletion::FailedWithBackoff { .. }
    ));
    assert!(matches!(limiter.begin(ip), AuthAdmission::Backoff { .. }));
    source.advance(Duration::from_millis(11));
    assert!(matches!(limiter.begin(ip), AuthAdmission::Allowed(_)));
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
fn blacklist_cache_rejects_pre_epoch_wall_clock_without_epoch_zero() {
    let source = crate::time_source::test_support::ManualTimeSource::new(
        Instant::now(),
        std::time::UNIX_EPOCH.checked_sub(Duration::from_secs(1)).unwrap(),
    );
    let clock = ProtocolClock::from_source(source);
    let path = blacklist_cache_path("pre-epoch");
    let synchronizer = BlacklistSync::new_bounded_with_clock(
        Duration::from_secs(60),
        None,
        Duration::from_secs(60),
        Duration::from_secs(1),
        4096,
        8,
        Some(path.clone()),
        &clock,
    )
    .unwrap();

    let error = synchronizer.persist_cache(&["192.0.2.1".parse().unwrap()]).unwrap_err();
    assert!(matches!(
        error,
        BlacklistError::Clock(crate::time_source::WallClockError::BeforeUnixEpoch)
    ));
    assert!(!path.exists());
}

#[test]
fn blacklist_cache_cancellation_rejects_atomic_commit() {
    let path = blacklist_cache_path("cancelled-commit");
    std::fs::write(&path, b"last-known-good").unwrap();
    let control = BlacklistSyncControl::new();
    assert!(control.begin_publication());
    control.request_cancel();

    let blocked = parking_lot::RwLock::new(HashMap::new());
    blocked
        .write()
        .insert("198.51.100.1".parse().unwrap(), Instant::now() + Duration::from_secs(60));
    let error = publish_blacklist_feed(
        Some(&path),
        Duration::from_secs(60),
        4096,
        &["192.0.2.1".parse().unwrap()],
        &ProtocolClock::default(),
        &blocked,
        &control,
    )
    .unwrap_err();

    assert!(matches!(error, BlacklistError::Cancelled));
    assert_eq!(std::fs::read(&path).unwrap(), b"last-known-good");
    assert!(blocked.read().contains_key(&"198.51.100.1".parse().unwrap()));
    assert!(!blocked.read().contains_key(&"192.0.2.1".parse().unwrap()));
    std::fs::remove_file(path).unwrap();
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
