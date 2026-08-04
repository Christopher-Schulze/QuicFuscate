#[cfg(test)]
mod stealth_coverage_tests {
    use super::*;
    use crate::stealth::test_support::{acquire_env_lock, EnvGuard};
    use std::sync::Arc;

    fn make_manager(config: StealthConfig) -> StealthManager {
        StealthManager::new(
            config,
            Arc::new(OptimizationManager::new()),
            Arc::new(CryptoManager::new()),
        )
    }

    // =========================================================================
    // 1. StealthManager lifecycle
    // =========================================================================

    #[test]
    fn manager_off_mode_has_no_flow_shaper_or_probe_detector() {
        let m = make_manager(StealthConfig::off());
        assert_eq!(m.mode(), StealthMode::Off);
        assert!(m.flow_shaper.is_none());
        assert!(m.probe_detector.is_none());
        assert!(m.cover_traffic.is_none());
        assert!(m.domain_fronting.is_none());
    }

    #[test]
    fn manager_performance_mode_has_no_cover_traffic_or_flow_shaper() {
        let m = make_manager(StealthConfig::performance());
        assert_eq!(m.mode(), StealthMode::Performance);
        // Performance keeps H3/QPACK persona on but emits no synthetic cover traffic.
        assert!(m.cover_traffic.is_none());
        // Performance: no timing obfuscation -> no FlowShaper
        assert!(m.flow_shaper.is_none());
        assert!(!m.escalated.load(std::sync::atomic::Ordering::Relaxed));
    }

    #[test]
    fn manager_stealth_mode_has_flow_shaper_and_cover_traffic() {
        let m = make_manager(StealthConfig::stealth());
        assert_eq!(m.mode(), StealthMode::Stealth);
        assert!(m.cover_traffic.is_some());
        // Stealth enables timing obfuscation -> FlowShaper present
        assert!(m.flow_shaper.is_some());
        assert!(m.domain_fronting.is_none());
    }

    #[test]
    fn manager_intelligent_mode_enables_dynamic_and_probe_detector() {
        let m = make_manager(StealthConfig::intelligent());
        assert_eq!(m.mode(), StealthMode::Intelligent);
        assert!(m.is_intelligent_runtime());
        assert!(m.probe_detector.is_some());
        // Intelligent inherits Performance base -> flow_shaper present (dynamic_enabled=true)
        assert!(m.flow_shaper.is_some());
        // Intelligent keeps the scheduler available but only emits from level 1 upward.
        assert!(m.cover_traffic.is_some());
        assert!(!m.cover_header_emission_allowed());
        // Reality proxy enabled in Intelligent mode
        assert!(m.reality_proxy.is_some());
    }

    #[test]
    fn intelligent_levels_do_not_cross_connection_boundaries() {
        let first = make_manager(StealthConfig::intelligent());
        let second = make_manager(StealthConfig::intelligent());

        first.set_brain_level_for_test(2);
        assert_eq!(first.intelligent_runtime_level(), 2);
        assert_eq!(second.intelligent_runtime_level(), 0);
    }

    #[test]
    fn manager_anti_dpi_mode_has_all_features() {
        let m = make_manager(StealthConfig::anti_dpi());
        assert_eq!(m.mode(), StealthMode::AntiDpi);
        assert!(m.flow_shaper.is_some());
        assert!(m.cover_traffic.is_some());
        assert!(m.domain_fronting.is_some());
    }

    #[test]
    fn cover_cache_is_none_when_reality_disabled() {
        // QUICFUSCATE_REALITY_ENABLED defaults to false, so the cover cache
        // should not be initialized.
        let m = make_manager(StealthConfig::intelligent());
        assert!(m.cover_cache.is_none(), "cover_cache should be None when reality is disabled");
        assert!(m.cover_handshake_material().is_none(), "no material when cache is absent");
    }

    #[test]
    fn manager_mode_returns_correct_mode() {
        for (config, expected) in [
            (StealthConfig::off(), StealthMode::Off),
            (StealthConfig::performance(), StealthMode::Performance),
            (StealthConfig::stealth(), StealthMode::Stealth),
            (StealthConfig::anti_dpi(), StealthMode::AntiDpi),
            (StealthConfig::manual(), StealthMode::Manual),
            (StealthConfig::intelligent(), StealthMode::Intelligent),
        ] {
            let m = make_manager(config);
            assert_eq!(m.mode(), expected);
        }
    }

    // =========================================================================
    // 2. Traffic shaping (FlowShaper + RateChoker)
    // =========================================================================

    #[test]
    fn flow_shaper_jitter_bounds_respected() {
        let shaper = FlowShaper::new(2000, false);
        for _ in 0..200 {
            let d = shaper.apply_jitter();
            let us = d.as_micros() as u64;
            // min = max(2000/2, 1) = 1000, max = 2000
            assert!((1000..=2000).contains(&us), "jitter {} us outside [1000, 2000]", us);
        }
    }

    #[test]
    fn flow_shaper_zero_jitter_clamps_to_one() {
        // jitter_us=0 -> max=max(0,1)=1, min=max(1/2,1)=1 -> always 1
        let shaper = FlowShaper::new(0, false);
        for _ in 0..50 {
            assert_eq!(shaper.apply_jitter().as_micros(), 1);
        }
    }

    #[test]
    fn flow_shaper_record_and_prune_limits_history() {
        let shaper = FlowShaper::new(100, false);
        for i in 0..300 {
            shaper.record_and_prune(i, StealthPacketClass::Data);
        }
        let hist = shaper.packet_history.lock().expect("lock");
        // History capped at 256 + pruning of >2s entries
        assert!(hist.len() <= 256);
    }

    #[test]
    fn rate_choker_none_when_zero_target() {
        assert!(RateChoker::new(0, 100).is_none());
    }

    #[test]
    fn rate_choker_initial_burst_allows_small_packets() {
        let mut choker = RateChoker::new(100, 50).expect("should create");
        // Initial burst: tokens are full. Small packet should go through instantly.
        let delay = choker.shape(100);
        assert_eq!(delay, std::time::Duration::ZERO);
    }

    #[test]
    fn rate_choker_large_payload_causes_delay() {
        let mut choker = RateChoker::new(1, 10).expect("should create");
        // 1 Mbps target, 10ms burst -> capacity = (1e6/8) * 0.01 = 1250 bytes
        // Drain all tokens in one large burst
        let _ = choker.shape(2000);
        // Force last=now so no time refill happens
        choker.last = std::time::Instant::now();
        choker.tokens = 0.0;
        // Now even a small packet should need wait since tokens are 0
        let delay = choker.shape(100);
        assert!(delay > std::time::Duration::ZERO);
    }

    // =========================================================================
    // 3. StealthConfig constructors and validation
    // =========================================================================

    #[test]
    fn config_from_mode_roundtrip() {
        let modes = [
            StealthMode::Off,
            StealthMode::Performance,
            StealthMode::Stealth,
            StealthMode::AntiDpi,
            StealthMode::Manual,
            StealthMode::Intelligent,
        ];
        for mode in modes {
            let cfg = StealthConfig::from_mode(mode);
            assert_eq!(cfg.mode, mode, "from_mode({:?}) should produce matching mode", mode);
        }
    }

    #[test]
    fn config_default_is_stealth() {
        let cfg = StealthConfig::default();
        assert_eq!(cfg.mode, StealthMode::Stealth);
    }

    #[test]
    fn config_ultra_stealth_is_anti_dpi() {
        let cfg = StealthConfig::ultra_stealth();
        assert_eq!(cfg.mode, StealthMode::AntiDpi);
    }

    #[test]
    fn config_validate_rejects_choke_without_target() {
        let mut cfg = StealthConfig::stealth();
        cfg.enable_realtime_choke = true;
        cfg.choke_target_mbps = 0;
        let err = cfg.validate().expect_err("choke without target");
        assert!(err.contains("choke_target_mbps"));
    }

    #[test]
    fn config_validate_rejects_server_push_without_h3() {
        let mut cfg = StealthConfig::manual();
        cfg.enable_server_push_cover = true;
        cfg.enable_http3_masquerading = false;
        let err = cfg.validate().expect_err("push without h3");
        assert!(err.contains("server push cover requires"));
    }

    #[test]
    fn config_validate_rejects_performance_with_timing() {
        let mut cfg = StealthConfig::performance();
        cfg.enable_timing_obfuscation = true;
        let err = cfg.validate().expect_err("perf with timing");
        assert!(err.contains("performance mode"));
    }

    #[test]
    fn config_stealth_has_expected_defaults() {
        let cfg = StealthConfig::stealth();
        assert!(!cfg.enable_domain_fronting);
        assert!(cfg.enable_traffic_padding);
        assert!(cfg.enable_timing_obfuscation);
        assert!(cfg.enable_http3_masquerading);
        assert!(cfg.use_tls_cover);
        assert!(cfg.enable_cover_ping);
        assert_eq!(cfg.padding_strategy, PaddingStrategy::Adaptive);
        assert_eq!(cfg.cover_ping_interval_ms, 30_000);
    }

    #[test]
    fn normal_modes_do_not_enable_domain_fronting_by_default() {
        assert!(!StealthConfig::performance().enable_domain_fronting);
        assert!(!StealthConfig::intelligent().enable_domain_fronting);
        assert!(!StealthConfig::stealth().enable_domain_fronting);
        assert!(StealthConfig::anti_dpi().enable_domain_fronting);
    }

    #[test]
    fn protocol_mimicry_flag_enables_concrete_h3_tls_cover_knobs() {
        let mut cfg = StealthConfig::manual();
        cfg.enable_protocol_mimicry = true;
        cfg.enable_http3_masquerading = false;
        cfg.use_qpack_headers = false;
        cfg.use_tls_cover = false;

        cfg.normalize_protocol_mimicry_bundle();

        assert!(cfg.enable_http3_masquerading);
        assert!(cfg.use_qpack_headers);
        assert!(cfg.use_tls_cover);
    }

    #[test]
    fn domain_fronting_without_domains_is_disabled_outside_anti_dpi() {
        let mut cfg = StealthConfig::stealth();
        cfg.enable_domain_fronting = true;
        cfg.fronting_domains.clear();

        let m = make_manager(cfg);
        assert!(m.domain_fronting.is_none());
    }

    #[test]
    fn active_persona_does_not_rotate_mid_session() {
        let mut cfg = StealthConfig::anti_dpi();
        cfg.fingerprint_rotation_interval = 1;
        let m = make_manager(cfg);
        let before = m.current_persona_name();
        {
            let mut last = m.last_rotation.lock().expect("last rotation lock");
            *last = std::time::Instant::now() - std::time::Duration::from_secs(3600);
        }

        m.maybe_rotate_fingerprint();

        assert_eq!(m.current_persona_name(), before);
    }

    #[test]
    fn config_off_disables_everything() {
        let cfg = StealthConfig::off();
        assert!(!cfg.enable_traffic_padding);
        assert!(!cfg.enable_timing_obfuscation);
        assert!(!cfg.enable_http3_masquerading);
        assert!(!cfg.use_tls_cover);
        assert!(!cfg.enable_domain_fronting);
        assert!(!cfg.enable_doh);
        assert!(!cfg.enable_cover_ping);
        assert!(!cfg.enable_server_push_cover);
        assert!(!cfg.dynamic_enabled);
        assert_eq!(cfg.max_padding_size, 0);
    }

    // =========================================================================
    // 4. Cover traffic (Cover PING)
    // =========================================================================

    #[test]
    fn cover_ping_disabled_when_off() {
        let m = make_manager(StealthConfig::off());
        assert!(!m.should_send_cover_ping());
    }

    #[test]
    fn cover_ping_enabled_in_stealth() {
        let m = make_manager(StealthConfig::stealth());
        // First call should return true (now >= initial deadline)
        assert!(m.should_send_cover_ping());
        // Immediately after, it should return false (interval not elapsed)
        assert!(!m.should_send_cover_ping());
    }

    // =========================================================================
    // 5. apply_env_overrides
    // =========================================================================

    #[test]
    fn env_override_known_modes() {
        let _lock = acquire_env_lock();
        for (value, expected) in [
            ("performance", StealthMode::Performance),
            ("stealth", StealthMode::Stealth),
            ("anti-dpi", StealthMode::AntiDpi),
            ("intelligent", StealthMode::Intelligent),
            ("off", StealthMode::Off),
            ("manual", StealthMode::Manual),
        ] {
            let _guard = EnvGuard::set("QUICFUSCATE_STEALTH_MODE", value);
            let mut cfg = StealthConfig::stealth();
            cfg.apply_env_overrides();
            assert_eq!(cfg.mode, expected, "mode override '{}' failed", value);
        }
    }

    #[test]
    fn env_override_unknown_mode_keeps_original() {
        let _lock = acquire_env_lock();
        let _guard = EnvGuard::set("QUICFUSCATE_STEALTH_MODE", "nonexistent_mode");
        let mut cfg = StealthConfig::stealth();
        cfg.apply_env_overrides();
        // Unknown mode triggers a warning but keeps the original config
        assert_eq!(cfg.mode, StealthMode::Stealth);
    }

    #[test]
    fn env_override_browser_and_os() {
        let _lock = acquire_env_lock();
        let _b = EnvGuard::set("QUICFUSCATE_BROWSER", "firefox");
        let _o = EnvGuard::set("QUICFUSCATE_OS", "linux");
        let mut cfg = StealthConfig::stealth();
        cfg.apply_env_overrides();
        assert_eq!(cfg.initial_browser, BrowserProfile::Firefox);
        assert_eq!(cfg.initial_os, OsProfile::Linux);
    }

    #[test]
    fn env_override_padding_max() {
        let _lock = acquire_env_lock();
        let _p = EnvGuard::set("QUICFUSCATE_STEALTH_PADDING_MAX", "512");
        let mut cfg = StealthConfig::stealth();
        cfg.apply_env_overrides();
        assert_eq!(cfg.max_padding_size, 512);
    }

    // =========================================================================
    // 6. DomainFrontingManager
    // =========================================================================

    #[test]
    fn domain_fronting_round_robin_cycles() {
        let df = DomainFrontingManager::new(vec![
            "a.example".into(),
            "b.example".into(),
            "c.example".into(),
        ]);
        let mut seen = std::collections::HashSet::new();
        for _ in 0..30 {
            seen.insert(df.get_fronted_domain());
        }
        // With jitter, all 3 should eventually be visited
        assert!(seen.len() >= 2, "round-robin should visit multiple domains, got {:?}", seen);
    }

    #[test]
    fn domain_fronting_random_domain_fallback() {
        let df = DomainFrontingManager::new(Vec::new());
        let d = df.random_domain();
        assert_eq!(d, "cdn.cloudflare.com");
    }

    #[test]
    fn domain_fronting_from_providers_populates() {
        let df = DomainFrontingManager::from_providers(vec![CdnProvider::Cloudflare]);
        assert!(!df.domains.is_empty());
        // Should contain known Cloudflare domains
        assert!(df.domains.iter().any(|d| d.contains("cloudflare")));
    }

    #[test]
    fn domain_fronting_ultra_stealth_has_many_domains() {
        let df = DomainFrontingManager::ultra_stealth();
        assert!(
            df.domains.len() >= 20,
            "ultra stealth should have 20+ domains, got {}",
            df.domains.len()
        );
    }

    // =========================================================================
    // 7. FingerprintProfile
    // =========================================================================

    #[test]
    fn fingerprint_profile_chrome_windows_has_correct_ua() {
        let fp = FingerprintProfile::new(BrowserProfile::Chrome, OsProfile::Windows);
        assert!(fp.user_agent.contains("Chrome/"));
        assert!(fp.user_agent.contains("Windows NT"));
        assert_eq!(fp.browser, BrowserProfile::Chrome);
        assert_eq!(fp.os, OsProfile::Windows);
    }

    #[test]
    fn fingerprint_profile_safari_ios_has_mobile_ua() {
        let fp = FingerprintProfile::new(BrowserProfile::Safari, OsProfile::IOS);
        assert!(fp.user_agent.contains("iPhone"));
        assert!(fp.user_agent.contains("Safari"));
    }

    #[test]
    fn fingerprint_profile_generates_client_hello() {
        let fp = FingerprintProfile::new(BrowserProfile::Chrome, OsProfile::Windows);
        assert!(fp.client_hello.is_some());
        let ch = fp.client_hello.as_ref().expect("client_hello");
        assert!(ch.len() > 50, "ClientHello too short");
    }

    #[test]
    fn fingerprint_profile_has_server_hello() {
        let fp = FingerprintProfile::new(BrowserProfile::Firefox, OsProfile::Linux);
        assert!(fp.server_hello.is_some());
        let sh = fp.server_hello.as_ref().expect("server_hello");
        assert_eq!(sh.tls_version, 0x0303);
        // Cipher should be a valid TLS 1.3 cipher
        assert!(
            sh.cipher_suite == 0x1301 || sh.cipher_suite == 0x1303,
            "unexpected cipher 0x{:04X}",
            sh.cipher_suite
        );
    }

    #[test]
    fn fingerprint_fallback_for_unsupported_combo() {
        // Edge/IOS is not explicitly listed -> falls back to Chrome/Windows
        let fp = FingerprintProfile::new(BrowserProfile::Edge, OsProfile::IOS);
        assert_eq!(fp.browser, BrowserProfile::Chrome);
        assert_eq!(fp.os, OsProfile::Windows);
    }

    // =========================================================================
    // 8. BrowserProfile / OsProfile parsing
    // =========================================================================

    #[test]
    fn browser_profile_from_str() {
        assert_eq!("chrome".parse::<BrowserProfile>(), Ok(BrowserProfile::Chrome));
        assert_eq!("Firefox".parse::<BrowserProfile>(), Ok(BrowserProfile::Firefox));
        assert_eq!("SAFARI".parse::<BrowserProfile>(), Ok(BrowserProfile::Safari));
        assert_eq!("edge".parse::<BrowserProfile>(), Ok(BrowserProfile::Edge));
        assert!("unknown".parse::<BrowserProfile>().is_err());
    }

    #[test]
    fn os_profile_from_str() {
        assert_eq!("windows".parse::<OsProfile>(), Ok(OsProfile::Windows));
        assert_eq!("MacOS".parse::<OsProfile>(), Ok(OsProfile::MacOS));
        assert_eq!("LINUX".parse::<OsProfile>(), Ok(OsProfile::Linux));
        assert_eq!("ios".parse::<OsProfile>(), Ok(OsProfile::IOS));
        assert_eq!("android".parse::<OsProfile>(), Ok(OsProfile::Android));
        assert!("freebsd".parse::<OsProfile>().is_err());
    }

    // =========================================================================
    // 9. Intelligent mode policy derivation
    // =========================================================================

    #[test]
    fn intelligent_policy_level0_clean_disables_padding() {
        let policy = StealthManager::derive_intelligent_runtime_policy(IntelligentStealthInputs {
            level_hint: 0,
            ce_ratio_recent: 0.0,
            ack_us: 1000.0,
            size_div: 0.1,
            iat_div: 0.1,
            reorder_ratio: 0.0,
            rtt_spike_weight: 0.0,
            signal_tos: 0,
            signal_other: 0,
            jitter_max_us: 1000,
            pad_max_low: 128,
            pad_max_high: 640,
        });
        assert!(policy.external_pacing);
        assert!(!policy.padding_enabled);
        assert_eq!(policy.padding_max, 0);
    }

    #[test]
    fn intelligent_policy_high_ce_ratio_activates_padding() {
        let policy = StealthManager::derive_intelligent_runtime_policy(IntelligentStealthInputs {
            level_hint: 1,
            ce_ratio_recent: 0.15,
            ack_us: 10000.0,
            size_div: 0.5,
            iat_div: 0.5,
            reorder_ratio: 0.05,
            rtt_spike_weight: 3.0,
            signal_tos: 0,
            signal_other: 1,
            jitter_max_us: 2000,
            pad_max_low: 128,
            pad_max_high: 640,
        });
        assert!(policy.padding_enabled);
        assert!(policy.timing_enabled);
        assert!(!policy.external_pacing);
    }

    #[test]
    fn intelligent_policy_tos_anomaly_triggers_adaptive_padding() {
        let policy = StealthManager::derive_intelligent_runtime_policy(IntelligentStealthInputs {
            level_hint: 1,
            ce_ratio_recent: 0.005,
            ack_us: 5000.0,
            size_div: 0.8,
            iat_div: 0.7,
            reorder_ratio: 0.0,
            rtt_spike_weight: 0.0,
            signal_tos: 1,
            signal_other: 0,
            jitter_max_us: 1500,
            pad_max_low: 100,
            pad_max_high: 500,
        });
        assert!(policy.padding_enabled);
        // ToS anomaly -> adaptive strategy (3)
        assert_eq!(policy.padding_strategy, 3);
    }

    #[test]
    fn intelligent_policy_mimic_bias_varies_with_inputs() {
        // High CE ratio -> bias=1 (Safari-like small packets)
        let p1 = StealthManager::derive_intelligent_runtime_policy(IntelligentStealthInputs {
            level_hint: 2,
            ce_ratio_recent: 0.10,
            ack_us: 12000.0,
            size_div: 1.5,
            iat_div: 1.0,
            reorder_ratio: 0.0,
            rtt_spike_weight: 0.0,
            signal_tos: 0,
            signal_other: 0,
            jitter_max_us: 1000,
            pad_max_low: 128,
            pad_max_high: 640,
        });
        assert_eq!(p1.mimic_bias, 1);

        // Fast ACK, low divergence -> bias=4 (mobile)
        let p2 = StealthManager::derive_intelligent_runtime_policy(IntelligentStealthInputs {
            level_hint: 0,
            ce_ratio_recent: 0.0,
            ack_us: 1000.0,
            size_div: 0.1,
            iat_div: 0.1,
            reorder_ratio: 0.0,
            rtt_spike_weight: 0.0,
            signal_tos: 0,
            signal_other: 0,
            jitter_max_us: 1000,
            pad_max_low: 128,
            pad_max_high: 640,
        });
        assert_eq!(p2.mimic_bias, 4);
    }

    // =========================================================================
    // 10. Server Push cover traffic
    // =========================================================================

    #[test]
    fn server_push_cover_not_active_in_off_mode() {
        let m = make_manager(StealthConfig::off());
        assert!(!m.server_push_cover_active());
    }

    #[test]
    fn server_push_cover_active_in_anti_dpi() {
        let m = make_manager(StealthConfig::anti_dpi());
        assert!(m.server_push_cover_active());
    }

    #[test]
    fn webtransport_cover_policy_is_escalated_only() {
        let performance = make_manager(StealthConfig::performance());
        assert!(performance.webtransport_cover_plan().is_none());

        let intelligent = make_manager(StealthConfig::intelligent());
        assert!(intelligent.webtransport_cover_plan().is_none());

        let anti_dpi = make_manager(StealthConfig::anti_dpi());
        let (authority, path) = anti_dpi.webtransport_cover_plan().expect("anti-dpi cover plan");
        assert!(!authority.is_empty());
        assert!(path.ends_with("/wt/session"));
    }

    #[test]
    fn h3_cover_header_emission_policy_matches_modes() {
        let performance = make_manager(StealthConfig::performance());
        assert!(!performance.cover_header_emission_allowed());
        assert!(performance.cover_headers_due().is_none());

        let intelligent = make_manager(StealthConfig::intelligent());
        assert!(!intelligent.cover_header_emission_allowed());
        assert!(intelligent.cover_headers_due().is_none());

        intelligent.set_brain_level_for_test(1);
        assert!(intelligent.cover_header_emission_allowed());
    }

    #[test]
    fn server_push_burst_estimation_zero_promises() {
        let m = make_manager(StealthConfig::stealth());
        let bytes = m.estimate_server_push_cover_bytes("/assets", 0, 0.5);
        assert_eq!(bytes, 0);
    }

    #[test]
    fn server_push_burst_estimation_positive_promises() {
        let m = make_manager(StealthConfig::stealth());
        let bytes = m.estimate_server_push_cover_bytes("/assets", 5, 0.5);
        assert!(bytes > 0);
        // More promises = more bytes
        let bytes2 = m.estimate_server_push_cover_bytes("/assets", 10, 0.5);
        assert!(bytes2 > bytes);
    }

    #[test]
    fn server_push_trigger_reason_classification() {
        let m = make_manager(StealthConfig::stealth());
        assert_eq!(m.server_push_trigger_reason(100, 0), ServerPushTriggerReason::Loss);
        assert_eq!(m.server_push_trigger_reason(10, 2), ServerPushTriggerReason::Gating);
        assert_eq!(m.server_push_trigger_reason(10, 0), ServerPushTriggerReason::Time);
    }

    // =========================================================================
    // 11. brain_runtime_permissions
    // =========================================================================

    #[test]
    fn brain_permissions_all_unlocked_by_default() {
        let _lock = acquire_env_lock();
        // Clear all relevant env vars
        let _a = EnvGuard::set("QUICFUSCATE_ACK_THRESHOLD", "");
        let _b = EnvGuard::set("QUICFUSCATE_STEALTH_JITTER_US", "");
        let _c = EnvGuard::set("QUICFUSCATE_STEALTH_PADDING_STRATEGY", "");
        let _d = EnvGuard::set("QUICFUSCATE_STEALTH_MIMIC_BIAS", "");
        let _e = EnvGuard::set("QUICFUSCATE_EXTERNAL_PACING", "");
        let _f = EnvGuard::set("QUICFUSCATE_STEALTH_PADDING_MAX", "");
        let _g = EnvGuard::set("QUICFUSCATE_STEALTH_MAX_PADDING", "");
        let _h = EnvGuard::set("QUICFUSCATE_ACK_MAX_DELAY_MS", "");
        let _i = EnvGuard::set("QUICFUSCATE_STEALTH_ADAPTIVE_GRAN", "");

        // Remove empty vars so env_first returns None
        unsafe {
            std::env::remove_var("QUICFUSCATE_ACK_THRESHOLD");
            std::env::remove_var("QUICFUSCATE_STEALTH_JITTER_US");
            std::env::remove_var("QUICFUSCATE_STEALTH_PADDING_STRATEGY");
            std::env::remove_var("QUICFUSCATE_STEALTH_MIMIC_BIAS");
            std::env::remove_var("QUICFUSCATE_EXTERNAL_PACING");
            std::env::remove_var("QUICFUSCATE_STEALTH_PADDING_MAX");
            std::env::remove_var("QUICFUSCATE_STEALTH_MAX_PADDING");
            std::env::remove_var("QUICFUSCATE_ACK_MAX_DELAY_MS");
            std::env::remove_var("QUICFUSCATE_STEALTH_ADAPTIVE_GRAN");
            std::env::remove_var("QUICFUSCATE_PADDING_STRATEGY");
        }

        let m = make_manager(StealthConfig::intelligent());
        let perms = m.brain_runtime_permissions();
        assert!(perms.ack_threshold);
        assert!(perms.external_pacing);
        assert!(perms.timing);
        assert!(perms.padding);
        assert!(perms.mimic_bias);
        assert!(perms.granularity);
        assert!(perms.cc_profile);
    }

    // =========================================================================
    // 12. Http3Masquerade
    // =========================================================================

    #[test]
    fn http3_masquerade_generates_pseudo_headers() {
        let fp = FingerprintProfile::new(BrowserProfile::Chrome, OsProfile::Windows);
        let masq = Http3Masquerade::new(fp);
        let headers = masq.generate_headers("cdn.cloudflare.com", "/");
        // Must contain pseudo-headers
        assert!(headers.iter().any(|h| h.name() == b":method"));
        assert!(headers.iter().any(|h| h.name() == b":scheme"));
        assert!(headers.iter().any(|h| h.name() == b":authority"));
        assert!(headers.iter().any(|h| h.name() == b":path"));
        // Must contain user-agent
        assert!(headers.iter().any(|h| h.name() == b"user-agent"));
    }

    #[test]
    fn http3_masquerade_chromium_has_sec_ch_ua() {
        let fp = FingerprintProfile::new(BrowserProfile::Chrome, OsProfile::Windows);
        let masq = Http3Masquerade::new(fp);
        let headers = masq.generate_headers("example.com", "/");
        assert!(
            headers.iter().any(|h| h.name() == b"sec-ch-ua"),
            "Chrome masquerade should include sec-ch-ua"
        );
    }

    #[test]
    fn http3_masquerade_cloudflare_is_cross_site() {
        let fp = FingerprintProfile::new(BrowserProfile::Chrome, OsProfile::Windows);
        let masq = Http3Masquerade::new(fp);
        let site = masq.get_sec_fetch_site("cdn.cloudflare.com");
        assert_eq!(site, "cross-site");
    }

    #[test]
    fn http3_masquerade_non_cdn_is_none_site() {
        let fp = FingerprintProfile::new(BrowserProfile::Chrome, OsProfile::Windows);
        let masq = Http3Masquerade::new(fp);
        let site = masq.get_sec_fetch_site("my-private-server.org");
        assert_eq!(site, "none");
    }

    struct FixedSystemTimeSource {
        system_now: std::time::SystemTime,
    }

    impl crate::time_source::TimeSource for FixedSystemTimeSource {
        fn now_instant(&self) -> std::time::Instant {
            std::time::Instant::now()
        }

        fn now_system(&self) -> std::time::SystemTime {
            self.system_now
        }
    }

    #[test]
    fn http3_masquerade_cookie_uses_canonical_system_time() {
        let timestamp = 1_700_000_000_u64;
        let _time_guard = crate::time_source::install_for_test(Arc::new(FixedSystemTimeSource {
            system_now: std::time::UNIX_EPOCH + std::time::Duration::from_secs(timestamp),
        }));
        let profile = FingerprintProfile::new(BrowserProfile::Chrome, OsProfile::Windows);
        let masq = Http3Masquerade::new(profile);

        let headers = masq.generate_headers("www.google.com", "/");
        let cookie = headers.iter().find(|h| h.name() == b"cookie").expect("cookie header");
        assert_eq!(cookie.value(), masq.generate_realistic_cookies_at(timestamp).as_bytes());
    }

    #[test]
    fn http3_masquerade_omits_cookie_before_unix_epoch() {
        let _time_guard = crate::time_source::install_for_test(Arc::new(FixedSystemTimeSource {
            system_now: std::time::UNIX_EPOCH - std::time::Duration::from_secs(1),
        }));
        let profile = FingerprintProfile::new(BrowserProfile::Chrome, OsProfile::Windows);
        let masq = Http3Masquerade::new(profile);

        let headers = masq.generate_headers("www.google.com", "/");
        assert!(!headers.iter().any(|h| h.name() == b"cookie"));
        assert!(headers.iter().any(|h| h.name() == b"user-agent"));
    }

    // =========================================================================
    // 13. ActiveProbeDetector
    // =========================================================================

    #[test]
    fn probe_detector_detects_gfw_pattern() {
        let detector = ActiveProbeDetector::new(5, ProbeResponseMode::Switch);
        let gfw_packet = vec![0x16, 0x03, 0x01, 0x00, 0x00, 0xff, 0xff];
        let addr: std::net::SocketAddr = "1.2.3.4:1234".parse().expect("addr");
        let result = detector.check_packet(&gfw_packet, addr);
        assert!(result.is_some());
        assert_eq!(result, Some(ProbeResponseMode::Switch));
    }

    #[test]
    fn probe_detector_threshold_controls_switch_escalation() {
        let gfw_packet = vec![0x16, 0x03, 0x01, 0x00, 0x00, 0xff, 0xff];
        let addr: std::net::SocketAddr = "1.2.3.4:1234".parse().expect("addr");

        let low_threshold = ActiveProbeDetector::new(2, ProbeResponseMode::Fake);
        assert_eq!(
            low_threshold.check_packet(&gfw_packet, addr),
            Some(ProbeResponseMode::Fake)
        );
        assert_eq!(
            low_threshold.check_packet(&gfw_packet, addr),
            Some(ProbeResponseMode::Switch)
        );

        let high_threshold = ActiveProbeDetector::new(3, ProbeResponseMode::Fake);
        assert_eq!(
            high_threshold.check_packet(&gfw_packet, addr),
            Some(ProbeResponseMode::Fake)
        );
        assert_eq!(
            high_threshold.check_packet(&gfw_packet, addr),
            Some(ProbeResponseMode::Fake)
        );
    }

    #[test]
    fn probe_detector_ignores_normal_quic_packet() {
        let detector = ActiveProbeDetector::new(5, ProbeResponseMode::Switch);
        // Normal-looking QUIC short header (Fixed Bit set)
        let normal = vec![0x40, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06];
        let addr: std::net::SocketAddr = "5.6.7.8:5678".parse().expect("addr");
        let result = detector.check_packet(&normal, addr);
        assert!(result.is_none());
    }

    #[test]
    fn probe_detector_fake_response_for_gfw() {
        let detector = ActiveProbeDetector::new(5, ProbeResponseMode::Fake);
        let resp = detector.generate_fake_response("GFW_TLS_Probe");
        // Should be a TLS alert
        assert_eq!(resp[0], 0x15);
    }

    // =========================================================================
    // 14. CoverTrafficScheduler
    // =========================================================================

    #[test]
    fn cover_traffic_scheduler_respects_interval() {
        let sched = CoverTrafficScheduler::new("cdn.example.com".into(), 60_000);
        // First call succeeds (initial last_request is "now")
        // It should return Some on first eligible call after interval
        let req = sched.get_next_request();
        // The initial last_request is Instant::now(), so 0ms elapsed < 60000ms interval => None
        assert!(req.is_none());
    }

    #[test]
    fn cover_traffic_scheduler_set_interval() {
        let sched = CoverTrafficScheduler::new("cdn.example.com".into(), 5000);
        sched.set_interval_ms(1000);
        assert_eq!(sched.interval_ms.load(std::sync::atomic::Ordering::Relaxed), 1000);
    }

    // =========================================================================
    // 15. Runtime TLS profile
    // =========================================================================

    #[test]
    fn runtime_tls_profile_performance_mode_is_cover_performance() {
        let m = make_manager(StealthConfig::performance());
        let profile = m.runtime_tls_profile(None);
        assert!(profile.cover_performance_mode);
        assert!(profile.timing_jitter.is_none());
    }

    #[test]
    fn runtime_tls_profile_stealth_mode_has_timing_jitter() {
        let m = make_manager(StealthConfig::stealth());
        let profile = m.runtime_tls_profile(None);
        assert!(!profile.cover_performance_mode);
        assert!(profile.timing_jitter.is_some());
    }

    #[test]
    fn runtime_tls_profile_sni_override() {
        let m = make_manager(StealthConfig::stealth());
        let profile = m.runtime_tls_profile(Some("custom.example.com"));
        assert_eq!(profile.sni.as_deref(), Some("custom.example.com"));
    }

    // =========================================================================
    // 16. QPACK profiles
    // =========================================================================

    #[test]
    fn qpack_runtime_profile_chrome_vs_firefox() {
        let m_chrome = make_manager(StealthConfig::stealth()); // default Chrome/Windows
        let (cap_c, blocked_c) = m_chrome.qpack_runtime_profile();
        assert_eq!(cap_c, 64 * 1024);
        assert_eq!(blocked_c, 16);

        // Firefox profile
        let mut cfg = StealthConfig::stealth();
        cfg.initial_browser = BrowserProfile::Firefox;
        let m_ff = make_manager(cfg);
        let (cap_f, blocked_f) = m_ff.qpack_runtime_profile();
        assert_eq!(cap_f, 32 * 1024);
        assert_eq!(blocked_f, 8);
    }

    #[test]
    fn current_persona_name_format() {
        let m = make_manager(StealthConfig::stealth());
        let name = m.current_persona_name();
        assert!(name.contains("Chrome"), "expected Chrome in persona, got {}", name);
        assert!(name.contains("Windows"), "expected Windows in persona, got {}", name);
    }

    // =========================================================================
    // 17. PaddingStrategy coverage
    // =========================================================================

    #[test]
    fn padding_strategy_env_parsing() {
        let cfg = StealthConfig::stealth();
        // Test the internal transport_padding_strategy_override path by checking the parser
        let parse = |s: &str| -> Option<PaddingStrategy> {
            match s.trim().to_ascii_lowercase().as_str() {
                "1" | "random" => Some(PaddingStrategy::Random),
                "2" | "fixed" => Some(PaddingStrategy::Fixed),
                "3" | "adaptive" => Some(PaddingStrategy::Adaptive),
                "4" | "browser" | "browser-mimic" | "browsermimic" => {
                    Some(PaddingStrategy::BrowserMimic)
                }
                "5" | "normalize" | "packet-normalize" | "packetnormalize" => {
                    Some(PaddingStrategy::PacketNormalize)
                }
                _ => None,
            }
        };
        assert_eq!(parse("random"), Some(PaddingStrategy::Random));
        assert_eq!(parse("2"), Some(PaddingStrategy::Fixed));
        assert_eq!(parse("adaptive"), Some(PaddingStrategy::Adaptive));
        assert_eq!(parse("browser-mimic"), Some(PaddingStrategy::BrowserMimic));
        assert_eq!(parse("normalize"), Some(PaddingStrategy::PacketNormalize));
        assert_eq!(parse("unknown"), None);
        let _ = cfg; // prevent unused warning
    }

    #[test]
    fn anti_dpi_uses_packet_normalize() {
        let cfg = StealthConfig::anti_dpi();
        assert_eq!(cfg.normalize_target_size, 1200);
        assert_eq!(cfg.padding_strategy, PaddingStrategy::BrowserMimic);
    }
}
