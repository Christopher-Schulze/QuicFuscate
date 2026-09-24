use super::*;

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
        assert!(m.cover_targets.is_none());
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
        assert!(m.cover_targets.is_none());
    }

    #[test]
    fn manager_intelligent_mode_enables_dynamic_and_probe_detector() {
        let m = make_manager(StealthConfig::dynamic());
        assert_eq!(m.mode(), StealthMode::Dynamic);
        assert!(m.is_intelligent_runtime());
        assert!(m.probe_detector.is_some());
        // Stealth image: flow shaper and cover scheduler are wired from
        // connect — the frozen image already emits at level 0 (TODO-1059).
        assert!(m.flow_shaper.is_some());
        assert!(m.cover_traffic.is_some());
        assert!(m.cover_header_emission_allowed());
        // Reality proxy enabled in Intelligent mode
        assert!(m.reality_proxy.is_some());
    }

    #[test]
    fn intelligent_levels_do_not_cross_connection_boundaries() {
        let first = make_manager(StealthConfig::dynamic());
        let second = make_manager(StealthConfig::dynamic());

        first.set_brain_level_for_test(2);
        assert_eq!(first.intelligent_runtime_level(), 2);
        assert_eq!(second.intelligent_runtime_level(), 0);
    }

    #[test]
    fn manager_anti_dpi_mode_has_all_features() {
        let m = make_manager(StealthConfig::stealth_max());
        assert_eq!(m.mode(), StealthMode::StealthMax);
        assert!(m.flow_shaper.is_some());
        assert!(m.cover_traffic.is_some());
        assert!(m.cover_targets.is_some());
        // StealthMax presets populate Reality cover targets (TODO-1048), so the
        // probe-fallback relay is armed for this mode.
        assert!(m.reality_proxy.is_some());
    }

    #[test]
    fn cover_cache_is_none_when_reality_disabled() {
        // QUICFUSCATE_REALITY_ENABLED defaults to false, so the cover cache
        // should not be initialized.
        let m = make_manager(StealthConfig::dynamic());
        assert!(m.cover_cache.is_none(), "cover_cache should be None when reality is disabled");
        assert!(m.cover_handshake_material().is_none(), "no material when cache is absent");
    }

    #[test]
    fn manager_mode_returns_correct_mode() {
        for (config, expected) in [
            (StealthConfig::off(), StealthMode::Off),
            (StealthConfig::performance(), StealthMode::Performance),
            (StealthConfig::stealth(), StealthMode::Stealth),
            (StealthConfig::stealth_max(), StealthMode::StealthMax),
            (StealthConfig::manual(), StealthMode::Manual),
            (StealthConfig::dynamic(), StealthMode::Dynamic),
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
        // Steady band (8..=31 records) -> classic uniform [1000, 2000].
        for _ in 0..16 {
            shaper.record_and_prune(64, StealthPacketClass::Data);
        }
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
        // History capped at 256 + pruning of >2s entries
        assert!(shaper.history_len() <= 256);
    }

    #[test]
    fn ack_only_packets_bypass_jitter_but_feed_history() {
        let m = make_manager(StealthConfig::stealth_max());
        let shaper = m.flow_shaper.as_ref().expect("anti_dpi has FlowShaper");
        let mut packet = vec![0u8; 64];

        // ACK-only datagrams carry no ack-eliciting frames; jitter would only
        // inflate the peer's RTT measurement, never shape the data flow.
        assert!(m.process_outgoing_packet(&mut packet, true).is_none());
        assert!(m.process_outgoing_packet(&mut packet, true).is_none());

        // They still occupy the wire, so they feed the rate estimator history.
        assert!(shaper.history_len() >= 2);

        // Ack-eliciting packets remain jitter targets (jitter_us=3000, min>0).
        assert!(m.process_outgoing_packet(&mut packet, false).is_some());
    }

    #[test]
    fn ack_only_stays_undelayed_when_manual_choke_is_enabled() {
        let mut cfg = StealthConfig::stealth_max();
        cfg.enable_realtime_choke = true;
        cfg.choke_target_mbps = 1;
        cfg.choke_burst_ms = 10;
        let m = make_manager(cfg);
        let mut packet = vec![0u8; 2000];
        assert!(m.process_outgoing_packet(&mut packet, true).is_none());
        assert!(m.process_outgoing_packet(&mut packet, false).is_none());
        let mut config =
            crate::transport::Config::new_with_version(crate::transport::PROTOCOL_VERSION)
                .expect("transport config");
        m.apply_utls_profile(&mut config);
        assert_eq!(config.max_pacing_rate, Some(125_000));
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
            StealthMode::StealthMax,
            StealthMode::Manual,
            StealthMode::Dynamic,
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
    fn config_stealth_max_matches_preset() {
        let cfg = StealthConfig::stealth_max();
        assert_eq!(cfg.mode, StealthMode::StealthMax);
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
    fn config_toml_rejects_enable_server_push_cover() {
        let toml = "[stealth]\nenable_server_push_cover = true\n";
        let err = StealthConfig::from_toml(toml).err().expect("server push cover must be rejected");
        assert!(err.to_string().contains("removed in TODO-1055"));
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
        assert!(cfg.reality_cover_targets.is_empty());
        assert!(cfg.enable_traffic_padding);
        assert!(cfg.enable_timing_obfuscation);
        assert!(cfg.enable_http3_masquerading);
        assert!(cfg.use_tls_cover);
        assert!(cfg.enable_cover_ping);
        assert_eq!(cfg.wire_shape, WireShape::PersonaTrace);
        // TODO-1054: the fixed interval grid is gone — the persona trace
        // inside the wire ledger decides when a cover PING is due.
        assert_eq!(cfg.cover_ping_interval_ms, 0);
    }

    #[test]
    fn normal_modes_do_not_configure_cover_targets_by_default() {
        assert!(StealthConfig::performance().reality_cover_targets.is_empty());
        assert!(StealthConfig::dynamic().reality_cover_targets.is_empty());
        assert!(StealthConfig::stealth().reality_cover_targets.is_empty());
        assert!(!StealthConfig::stealth_max().reality_cover_targets.is_empty());
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
    fn cover_targets_absent_when_no_targets_configured() {
        let cfg = StealthConfig::stealth();
        let m = make_manager(cfg);
        assert!(m.cover_targets.is_none());
    }

    #[test]
    fn cover_targets_rotator_from_explicit_list() {
        let mut cfg = StealthConfig::stealth();
        cfg.reality_cover_targets = vec!["cover-a.example".into(), "cover-b.example".into()];

        let m = make_manager(cfg);
        let rotator = m.cover_targets.as_ref().expect("cover target rotator");
        assert_eq!(rotator.targets(), ["cover-a.example", "cover-b.example"]);
    }

    // =========================================================================
    // TODO-1056: disguise migration timer (2-10 min draw, stealth modes only)
    // =========================================================================

    #[test]
    fn disguise_migration_never_due_for_speed_profiles() {
        use qf_common::time_source::test_support::ManualTimeSource;
        for cfg in [StealthConfig::off(), StealthConfig::performance()] {
            let clock =
                ManualTimeSource::new(std::time::Instant::now(), std::time::SystemTime::now());
            let _guard = crate::time_source::install_for_test(clock.clone());
            let m = make_manager(cfg);
            clock.advance(std::time::Duration::from_secs(3600));
            assert!(!m.disguise_migration_due(), "speed profiles never migrate for disguise");
        }
    }

    #[test]
    fn disguise_migration_fires_once_per_draw_for_stealth() {
        use qf_common::time_source::test_support::ManualTimeSource;
        let clock = ManualTimeSource::new(std::time::Instant::now(), std::time::SystemTime::now());
        let _guard = crate::time_source::install_for_test(clock.clone());
        let m = make_manager(StealthConfig::stealth());

        // Draw is uniform in [120, 600]: not due before the minimum, always due
        // past the maximum.
        clock.advance(std::time::Duration::from_secs(119));
        assert!(!m.disguise_migration_due(), "draw never fires before 120 s");
        clock.advance(std::time::Duration::from_secs(482));
        assert!(m.disguise_migration_due(), "draw must fire by 601 s");

        // Recording the migration redraws the window — the next attempt is at
        // least 120 s away again (no retry storm, no fixed cadence).
        m.note_disguise_migration();
        assert!(!m.disguise_migration_due(), "redraw starts a fresh window");
        clock.advance(std::time::Duration::from_secs(119));
        assert!(!m.disguise_migration_due(), "redraw respects the 120 s floor");
        clock.advance(std::time::Duration::from_secs(482));
        assert!(m.disguise_migration_due(), "redraw fires again by 601 s");
    }

    #[test]
    fn elapsed_rotation_interval_starts_no_handshake_and_keeps_persona() {
        use qf_common::time_source::test_support::ManualTimeSource;
        let clock = ManualTimeSource::new(std::time::Instant::now(), std::time::SystemTime::now());
        let _guard = crate::time_source::install_for_test(clock.clone());
        // stealth_max historically rotated on a 120 s timer — advancing far past
        // it must change neither the persona nor the TLS profile name; the only
        // due signal is the disguise migration draw (TODO-1056).
        let m = make_manager(StealthConfig::stealth_max());
        let persona_before = m.current_persona_name();
        let tls_before = m.runtime_tls_profile(None).name.clone();

        clock.advance(std::time::Duration::from_secs(3600));

        assert_eq!(m.current_persona_name(), persona_before, "no mid-session persona swap");
        assert_eq!(m.runtime_tls_profile(None).name, tls_before, "no new handshake material");
        assert!(m.disguise_migration_due(), "the only due signal is the migration draw");
    }

    #[test]
    fn config_off_disables_everything() {
        let cfg = StealthConfig::off();
        assert!(!cfg.enable_traffic_padding);
        assert!(!cfg.enable_timing_obfuscation);
        assert!(!cfg.enable_http3_masquerading);
        assert!(!cfg.use_tls_cover);
        assert!(cfg.reality_cover_targets.is_empty());
        assert!(!cfg.enable_doh);
        assert!(!cfg.enable_cover_ping);
        assert!(!cfg.dynamic_enabled);
        assert_eq!(cfg.max_padding_size, 0);
    }

    // =========================================================================
    // 4. Cover traffic (Cover PING)
    // =========================================================================

    #[test]
    fn cover_ping_disabled_when_off() {
        let m = make_manager(StealthConfig::off());
        assert!(!m.cover_ping_enabled());
    }

    #[test]
    fn cover_ping_enabled_in_stealth() {
        let m = make_manager(StealthConfig::stealth());
        // Policy gate only: the wire ledger's persona trace owns the
        // schedule — this flag just says cover PINGs may be considered.
        assert!(m.cover_ping_enabled());
        let m = make_manager(StealthConfig::performance());
        assert!(!m.cover_ping_enabled());
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
            ("Stealth MAX", StealthMode::StealthMax),
            ("dynamic", StealthMode::Dynamic),
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

    #[test]
    fn snapshot_env_overrides_skip_invalid_aliases_and_retain_defaults() {
        let environment = crate::env_utils::EnvSnapshot::from_pairs([
            ("QUICFUSCATE_STEALTH_PADDING_STRATEGY", "unsupported"),
            ("QUICFUSCATE_PADDING_STRATEGY", "browser"),
            ("QUICFUSCATE_STEALTH_PADDING", "malformed"),
        ]);
        let mut config = StealthConfig::stealth();

        config.apply_env_overrides_with_snapshot(&environment);

        assert_eq!(config.wire_shape, WireShape::PersonaTrace);
        assert!(config.enable_traffic_padding);
    }

    // =========================================================================
    // 6. CoverTargetRotator
    // =========================================================================

    #[test]
    fn cover_target_round_robin_is_exact_in_serial_calls() {
        let rotator = CoverTargetRotator::new(vec![
            "a.example".into(),
            "b.example".into(),
            "c.example".into(),
        ]);
        let expected =
            ["a.example", "b.example", "c.example", "a.example", "b.example", "c.example"];
        for target in expected {
            assert_eq!(rotator.next_cover_target(), target);
        }
    }

    #[test]
    fn cover_target_round_robin_preserves_concurrent_coverage() {
        let rotator = Arc::new(CoverTargetRotator::new(vec![
            "a.example".into(),
            "b.example".into(),
            "c.example".into(),
        ]));
        let handles = (0..12)
            .map(|_| {
                let rotator = Arc::clone(&rotator);
                std::thread::spawn(move || rotator.next_cover_target())
            })
            .collect::<Vec<_>>();
        let results = handles
            .into_iter()
            .map(|handle| handle.join().expect("cover target selection thread must join"))
            .collect::<Vec<_>>();

        for target in ["a.example", "b.example", "c.example"] {
            assert_eq!(results.iter().filter(|selected| selected.as_str() == target).count(), 4);
        }
    }

    #[test]
    fn cover_target_empty_list_falls_back_to_default() {
        let rotator = CoverTargetRotator::new(Vec::new());
        assert_eq!(rotator.next_cover_target(), "cdn.cloudflare.com");
        assert_eq!(rotator.random_cover_target(), "cdn.cloudflare.com");
    }

    #[test]
    fn cover_target_from_providers_populates() {
        let rotator = CoverTargetRotator::from_providers(vec![CdnProvider::Cloudflare]);
        assert!(!rotator.targets().is_empty());
        // Should contain known Cloudflare cover names
        assert!(rotator.targets().iter().any(|d| d.contains("cloudflare")));
    }

    #[test]
    fn cover_target_broad_providers_has_many_targets() {
        let rotator = CoverTargetRotator::broad_providers();
        assert!(
            rotator.targets().len() >= 20,
            "broad providers should have 20+ cover targets, got {}",
            rotator.targets().len()
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
    fn fingerprint_profile_does_not_store_a_synthetic_client_hello() {
        let fp = FingerprintProfile::new(BrowserProfile::Chrome, OsProfile::Windows);
        assert!(fp.server_hello.is_some());
        assert!(fp.user_agent.contains("Chrome/"));
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

    #[test]
    fn fingerprint_try_new_rejects_unsupported_combo_without_fallback() {
        assert!(FingerprintProfile::try_new(BrowserProfile::Edge, OsProfile::IOS).is_err());
        let profile = FingerprintProfile::try_new(BrowserProfile::Firefox, OsProfile::Linux)
            .expect("supported browser/OS pair");
        assert_eq!(profile.browser, BrowserProfile::Firefox);
        assert_eq!(profile.os, OsProfile::Linux);
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
    // 9. Intelligent mode actuator derivation (TODO-1060)
    // =========================================================================

    fn clean_inputs() -> qf_stealth::IntelligentStealthInputs {
        qf_stealth::IntelligentStealthInputs {
            ce_effective: 0.0,
            ce_ratio_recent: 0.0,
            ack_us: 1000.0,
            jitter_ratio: 0.0,
            reorder_ratio: 0.0,
            rtt_spike_weight: 0.0,
            size_div: 0.1,
            iat_div: 0.1,
            signal_rst: 0,
            signal_tos: 0,
            signal_other: 0,
            probe_level: 0,
        }
    }

    #[test]
    fn intelligent_actuators_clean_path_stays_at_baseline() {
        let mut state = qf_stealth::IntelligentRepairState::default();
        let hints = qf_stealth::derive_intelligent_actuators(clean_inputs(), &mut state);
        assert!(!hints.reality_armed);
        assert!((80_000..=320_000).contains(&hints.repair_ratio_ppm));
        assert!((2..=20).contains(&hints.repair_interval_pkts));
    }

    #[test]
    fn intelligent_actuators_raise_repair_ratio_under_ce() {
        let mut state = qf_stealth::IntelligentRepairState::default();
        let clean = qf_stealth::derive_intelligent_actuators(clean_inputs(), &mut state);
        let pressured = qf_stealth::derive_intelligent_actuators(
            qf_stealth::IntelligentStealthInputs {
                ce_effective: 0.15,
                ce_ratio_recent: 0.15,
                ack_us: 10_000.0,
                jitter_ratio: 0.3,
                reorder_ratio: 0.05,
                rtt_spike_weight: 3.0,
                size_div: 0.5,
                iat_div: 0.5,
                signal_rst: 0,
                signal_tos: 0,
                signal_other: 1,
                probe_level: 0,
            },
            &mut state,
        );
        assert!(pressured.reality_armed);
        assert!(pressured.repair_ratio_ppm > clean.repair_ratio_ppm);
        assert!((80_000..=320_000).contains(&pressured.repair_ratio_ppm));
    }

    #[test]
    fn intelligent_actuators_arm_reality_on_tos_anomaly() {
        let mut state = qf_stealth::IntelligentRepairState::default();
        let hints = qf_stealth::derive_intelligent_actuators(
            qf_stealth::IntelligentStealthInputs { signal_tos: 1, ..clean_inputs() },
            &mut state,
        );
        assert!(hints.reality_armed, "ToS anomaly must arm the Reality hint");
    }

    #[test]
    fn intelligent_actuators_smooth_repair_ratio() {
        // EMA momentum prevents one-tick jumps: repeated clean ticks after a
        // pressured tick relax the ratio gradually instead of snapping back.
        let mut state = qf_stealth::IntelligentRepairState::default();
        let _ = qf_stealth::derive_intelligent_actuators(
            qf_stealth::IntelligentStealthInputs {
                ce_effective: 0.20,
                ce_ratio_recent: 0.20,
                ..clean_inputs()
            },
            &mut state,
        );
        let relaxing = qf_stealth::derive_intelligent_actuators(clean_inputs(), &mut state);
        assert!(
            relaxing.repair_ratio_ppm >= 80_000,
            "ratio must stay inside the byte cap bounds while relaxing"
        );
    }

    // =========================================================================
    // 10. Cover session policy
    // =========================================================================

    #[test]
    fn webtransport_cover_policy_is_image_bound() {
        // TODO-1059: the frozen image decides — never the escalation level.
        let performance = make_manager(StealthConfig::performance());
        assert!(performance.webtransport_cover_plan().is_none());

        let thin_dynamic = make_manager(StealthConfig::dynamic_with_image(
            qf_stealth::DynamicWireImage::Performance,
        ));
        assert!(thin_dynamic.webtransport_cover_plan().is_none());

        // The stealth image offers the one-shot session plan from level 0.
        let stealth_dynamic = make_manager(StealthConfig::dynamic());
        let (authority, path) =
            stealth_dynamic.webtransport_cover_plan().expect("stealth image cover plan");
        assert!(!authority.is_empty());
        assert!(path.ends_with("/wt/session"));

        let anti_dpi = make_manager(StealthConfig::stealth_max());
        assert!(anti_dpi.webtransport_cover_plan().is_some());
    }

    #[test]
    fn h3_cover_header_emission_policy_matches_frozen_image() {
        let performance = make_manager(StealthConfig::performance());
        assert!(!performance.cover_header_emission_allowed());
        assert!(performance.cover_request_due().is_none());

        // Stealth image: cover emission is allowed from level 0 — the
        // persona trace in the ledger owns the timing, not the level.
        let stealth_dynamic = make_manager(StealthConfig::dynamic());
        assert!(stealth_dynamic.cover_header_emission_allowed());

        // Thin image: the gate stays shut even after probe escalation.
        let thin_dynamic = make_manager(StealthConfig::dynamic_with_image(
            qf_stealth::DynamicWireImage::Performance,
        ));
        assert!(!thin_dynamic.cover_header_emission_allowed());
        thin_dynamic.set_brain_level_for_test(2);
        assert!(!thin_dynamic.cover_header_emission_allowed());
    }

    // =========================================================================
    // 11. brain_runtime_permissions
    // =========================================================================

    #[test]
    fn brain_permissions_all_unlocked_by_default() {
        let _lock = acquire_env_lock();
        // TODO-1060: the permission table only gates the congestion-driven
        // ACK threshold — unlocked unless an operator override claims it.
        let _a = EnvGuard::set("QUICFUSCATE_ACK_THRESHOLD", "");
        let _b = EnvGuard::set("QUICFUSCATE_ACK_MAX_DELAY_MS", "");

        // Remove empty vars so env_first returns None
        unsafe {
            std::env::remove_var("QUICFUSCATE_ACK_THRESHOLD");
            std::env::remove_var("QUICFUSCATE_ACK_MAX_DELAY_MS");
        }

        for cfg in [StealthConfig::dynamic(), StealthConfig::stealth()] {
            let manager = make_manager(cfg);
            assert!(
                manager.brain_runtime_permissions().ack_threshold,
                "no operator override → ACK threshold unlocked"
            );
        }
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
        assert_eq!(low_threshold.check_packet(&gfw_packet, addr), Some(ProbeResponseMode::Fake));
        assert_eq!(low_threshold.check_packet(&gfw_packet, addr), Some(ProbeResponseMode::Switch));

        let high_threshold = ActiveProbeDetector::new(3, ProbeResponseMode::Fake);
        assert_eq!(high_threshold.check_packet(&gfw_packet, addr), Some(ProbeResponseMode::Fake));
        assert_eq!(high_threshold.check_packet(&gfw_packet, addr), Some(ProbeResponseMode::Fake));
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
        let req = sched.next_cover_target();
        // The initial last_request is Instant::now(), so 0ms elapsed < 60000ms interval => None
        assert!(req.is_none());
    }

    #[test]
    fn cover_traffic_scheduler_set_interval() {
        let sched = CoverTrafficScheduler::new("cdn.example.com".into(), 5000);
        sched.set_interval_ms(1000);
        assert_eq!(sched.interval_ms(), 1000);
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
    // 17. WireShape coverage (TODO-1052)
    // =========================================================================

    #[test]
    fn wire_shape_env_parsing_collapses_legacy_spellings() {
        let environment = crate::env_utils::EnvSnapshot::from_pairs([(
            "QUICFUSCATE_STEALTH_PADDING_STRATEGY",
            "browser-mimic",
        )]);
        let cfg = StealthConfig::stealth();
        assert_eq!(cfg.transport_wire_shape_override(&environment), Some(WireShape::PersonaTrace));
        let environment = crate::env_utils::EnvSnapshot::from_pairs([(
            "QUICFUSCATE_STEALTH_PADDING_STRATEGY",
            "normalize",
        )]);
        assert_eq!(cfg.transport_wire_shape_override(&environment), Some(WireShape::FixedCell));
        let environment = crate::env_utils::EnvSnapshot::from_pairs([(
            "QUICFUSCATE_STEALTH_PADDING_STRATEGY",
            "bogus",
        )]);
        assert_eq!(cfg.transport_wire_shape_override(&environment), None);
    }

    #[test]
    fn anti_dpi_keeps_normalize_target_as_fixed_cell_size() {
        let cfg = StealthConfig::stealth_max();
        assert_eq!(cfg.normalize_target_size, 1200);
        assert_eq!(cfg.wire_shape, WireShape::PersonaTrace);
        assert!(cfg.wire_cap_bytes_per_sec > 0);
    }
}
