use super::test_support::*;
use super::{PaddingStrategy, StealthConfig, StealthManager, StealthMode};
use crate::{crypto::CryptoManager, optimize::OptimizationManager};
use std::sync::Arc;

#[test]
fn canonical_stealth_modes_keep_padding_ssot() {
    let stealth = StealthConfig::stealth();
    assert_eq!(stealth.padding_strategy, PaddingStrategy::Adaptive);
    assert!(stealth.enable_http3_masquerading);
    assert!(stealth.use_tls_cover);

    let anti_dpi = StealthConfig::anti_dpi();
    assert_eq!(anti_dpi.padding_strategy, PaddingStrategy::BrowserMimic);
    assert!(anti_dpi.enable_http3_masquerading);
    assert!(anti_dpi.use_tls_cover);
    assert!(!anti_dpi.enable_realtime_choke);
}

#[test]
fn validate_rejects_qpack_without_http3() {
    let mut cfg = StealthConfig::manual();
    cfg.use_qpack_headers = true;
    cfg.enable_http3_masquerading = false;
    let err = cfg.validate().expect_err("qpack without h3 must be rejected");
    assert!(err.contains("qpack headers require HTTP/3 masquerading"));
}

#[test]
fn validate_rejects_intelligent_without_dynamic() {
    let mut cfg = StealthConfig::intelligent();
    cfg.dynamic_enabled = false;
    let err = cfg.validate().expect_err("intelligent mode without dynamic must be rejected");
    assert!(err.contains("intelligent mode requires dynamic_enabled"));
    assert_eq!(cfg.mode, StealthMode::Intelligent);
}

#[test]
fn validate_rejects_off_mode_runtime_features() {
    let mut cfg = StealthConfig::off();
    cfg.enable_http3_masquerading = true;
    let err = cfg.validate().expect_err("off mode with runtime stealth features must be rejected");
    assert!(err.contains("off mode cannot enable stealth transport/runtime features"));
}

#[test]
fn runtime_tls_profile_tracks_cover_performance_mode_from_stealth_mode() {
    let optimization = Arc::new(OptimizationManager::new());
    let crypto = Arc::new(CryptoManager::new());

    let performance = StealthManager::new(
        StealthConfig::performance(),
        Arc::clone(&optimization),
        Arc::clone(&crypto),
    );
    let intelligent = StealthManager::new(
        StealthConfig::intelligent(),
        Arc::clone(&optimization),
        Arc::clone(&crypto),
    );
    let stealth = StealthManager::new(
        StealthConfig::stealth(),
        Arc::clone(&optimization),
        Arc::clone(&crypto),
    );

    let perf_profile = performance.runtime_tls_profile(None);
    let intelligent_profile = intelligent.runtime_tls_profile(None);
    let stealth_profile = stealth.runtime_tls_profile(None);

    assert!(perf_profile.cover_performance_mode);
    assert!(intelligent_profile.cover_performance_mode);
    assert!(!stealth_profile.cover_performance_mode);
    assert!(perf_profile.timing_jitter.is_none());
    assert!(intelligent_profile.timing_jitter.is_none());
    assert!(stealth_profile.timing_jitter.is_some());
}

#[test]
fn stealth_manager_constructs_without_a_tokio_runtime() {
    let manager = StealthManager::new(
        StealthConfig::intelligent(),
        Arc::new(OptimizationManager::new()),
        Arc::new(CryptoManager::new()),
    );

    assert_eq!(manager.mode(), StealthMode::Intelligent);
    assert!(manager.reality_proxy.is_some());
}

#[test]
fn brain_runtime_permissions_lock_operator_overrides() {
    let _env_lock = acquire_env_lock();
    let _ack = EnvGuard::set("QUICFUSCATE_ACK_THRESHOLD", "5");
    let _jitter = EnvGuard::set("QUICFUSCATE_STEALTH_JITTER_US", "900");
    let _padding = EnvGuard::set("QUICFUSCATE_STEALTH_PADDING_STRATEGY", "browser");
    let _bias = EnvGuard::set("QUICFUSCATE_STEALTH_MIMIC_BIAS", "safari");

    let manager = StealthManager::new(
        StealthConfig::intelligent(),
        Arc::new(OptimizationManager::new()),
        Arc::new(CryptoManager::new()),
    );
    let permissions = manager.brain_runtime_permissions();

    assert!(!permissions.ack_threshold);
    assert!(!permissions.external_pacing);
    assert!(!permissions.timing);
    assert!(!permissions.padding);
    assert!(!permissions.mimic_bias);
    assert!(!permissions.granularity);
    assert!(!permissions.cc_profile);
}

#[test]
fn intelligent_runtime_policy_prefers_clean_pacing_and_browser_padding() {
    // Level 0 = clean path: padding must be disabled (near-zero Intelligent overhead guarantee).
    let policy = StealthManager::derive_intelligent_runtime_policy(
        crate::stealth::IntelligentStealthInputs {
            level_hint: 0,
            ce_ratio_recent: 0.0005,
            ack_us: 2_400.0,
            size_div: 0.2,
            iat_div: 0.3,
            reorder_ratio: 0.0,
            rtt_spike_weight: 0.0,
            signal_tos: 0,
            signal_other: 0,
            jitter_max_us: 1_000,
            pad_max_low: 128,
            pad_max_high: 640,
        },
    );

    assert!(policy.external_pacing);
    assert!(!policy.timing_enabled);
    // Level 0 clean path: padding is off.
    assert!(!policy.padding_enabled);
    assert_eq!(policy.padding_strategy, 0);
    assert_eq!(policy.padding_max, 0);
    assert_eq!(policy.mimic_bias, 4);
    assert_eq!(policy.cc_profile, crate::transport::recovery::BrowserProfile::Edge);
}

#[test]
fn intelligent_runtime_policy_escalates_under_loss_and_divergence() {
    let policy = StealthManager::derive_intelligent_runtime_policy(
        crate::stealth::IntelligentStealthInputs {
            level_hint: 2,
            ce_ratio_recent: 0.12,
            ack_us: 14_500.0,
            size_div: 1.6,
            iat_div: 1.1,
            reorder_ratio: 0.03,
            rtt_spike_weight: 5.0,
            signal_tos: 1,
            signal_other: 1,
            jitter_max_us: 1_200,
            pad_max_low: 96,
            pad_max_high: 700,
        },
    );

    assert!(!policy.external_pacing);
    assert!(policy.timing_enabled);
    assert_eq!(policy.padding_strategy, 1);
    assert_eq!(policy.padding_max, 96);
    assert_eq!(policy.mimic_bias, 1);
    assert_eq!(policy.adaptive_granularity, 32);
    assert_eq!(policy.cc_profile, crate::transport::recovery::BrowserProfile::Safari);
}

// --- TLS Cover Tests (TODO-297) ---

#[test]
fn tls_cover_cipher_suite_tls_id_roundtrip() {
    use super::TlsCoverCipherSuite;
    assert_eq!(TlsCoverCipherSuite::Aes128Gcm.tls_id(), 0x1301);
    assert_eq!(TlsCoverCipherSuite::ChaCha20Poly1305.tls_id(), 0x1303);
    // Verify as_str matches expected names
    assert_eq!(TlsCoverCipherSuite::Aes128Gcm.as_str(), "aes-128-gcm");
    assert_eq!(TlsCoverCipherSuite::ChaCha20Poly1305.as_str(), "chacha20-poly1305");
}

#[test]
fn tls_cover_cipher_preference_parse_variants() {
    use super::TlsCoverCipherPreference;
    assert_eq!(TlsCoverCipherPreference::parse("auto"), Some(TlsCoverCipherPreference::Auto));
    assert_eq!(
        TlsCoverCipherPreference::parse("chacha"),
        Some(TlsCoverCipherPreference::ChaCha20Poly1305)
    );
    assert_eq!(
        TlsCoverCipherPreference::parse("chacha20poly1305"),
        Some(TlsCoverCipherPreference::ChaCha20Poly1305)
    );
    assert_eq!(TlsCoverCipherPreference::parse("aes"), Some(TlsCoverCipherPreference::Aes128Gcm));
    assert_eq!(
        TlsCoverCipherPreference::parse("aes-128-gcm"),
        Some(TlsCoverCipherPreference::Aes128Gcm)
    );
    assert_eq!(TlsCoverCipherPreference::parse(""), Some(TlsCoverCipherPreference::Auto));
    assert_eq!(TlsCoverCipherPreference::parse("unknown"), None);
}

#[test]
fn tls_cover_resolve_cipher_auto_selects_based_on_hardware() {
    use super::{TlsCoverCipherSuite, TlsCoverProvider};
    let resolved = TlsCoverProvider::resolve_cipher_suite(super::TlsCoverCipherPreference::Auto);
    // On any platform, must return a valid variant
    assert!(
        resolved == TlsCoverCipherSuite::Aes128Gcm
            || resolved == TlsCoverCipherSuite::ChaCha20Poly1305
    );
}

#[test]
fn tls_cover_resolve_cipher_explicit_chacha() {
    use super::{TlsCoverCipherSuite, TlsCoverProvider};
    let resolved =
        TlsCoverProvider::resolve_cipher_suite(super::TlsCoverCipherPreference::ChaCha20Poly1305);
    assert_eq!(resolved, TlsCoverCipherSuite::ChaCha20Poly1305);
}

#[test]
fn tls_cover_resolve_cipher_explicit_aes() {
    use super::{TlsCoverCipherSuite, TlsCoverProvider};
    let resolved =
        TlsCoverProvider::resolve_cipher_suite(super::TlsCoverCipherPreference::Aes128Gcm);
    assert_eq!(resolved, TlsCoverCipherSuite::Aes128Gcm);
}

#[test]
fn tls_cover_material_derivation_is_domain_separated() {
    use super::TlsCoverProvider;

    let entropy = [0xA5u8; 32];
    let chrome_client =
        TlsCoverProvider::derive_tls_cover_material_from_entropy("chrome", false, &entropy);
    let chrome_server =
        TlsCoverProvider::derive_tls_cover_material_from_entropy("chrome", true, &entropy);
    let firefox_client =
        TlsCoverProvider::derive_tls_cover_material_from_entropy("firefox", false, &entropy);

    assert_ne!(chrome_client, chrome_server, "client and server material must differ");
    assert_ne!(chrome_client, firefox_client, "profile rotation must derive fresh material");
    assert_eq!(
        chrome_client,
        TlsCoverProvider::derive_tls_cover_material_from_entropy("chrome", false, &entropy),
        "fixed entropy and context must remain deterministic"
    );
}

#[test]
fn tls_cover_material_is_fresh_for_each_provider_connection() {
    use super::TlsCoverProvider;

    let first = TlsCoverProvider::derive_tls_cover_material("chrome", false).expect("first derive");
    let second =
        TlsCoverProvider::derive_tls_cover_material("chrome", false).expect("second derive");
    assert_ne!(first, second, "independent connections must not reuse key and IV material");
}

#[test]
fn tls_cover_client_hello_is_valid_tls_record() {
    use super::{tls_cover::TlsCover, BrowserProfile, OsProfile};
    for browser in [
        BrowserProfile::Chrome,
        BrowserProfile::Firefox,
        BrowserProfile::Safari,
        BrowserProfile::Edge,
    ] {
        for os in [
            OsProfile::Windows,
            OsProfile::MacOS,
            OsProfile::Linux,
            OsProfile::IOS,
            OsProfile::Android,
        ] {
            let ch = TlsCover::generate_client_hello(browser, os, Some("example.com"));
            // TLS record header: 0x16 (Handshake), 0x03 0x03 (TLS 1.2)
            assert!(ch.len() >= 9, "ClientHello too short for {:?}/{:?}", browser, os);
            assert_eq!(ch[0], 0x16, "not a TLS Handshake record for {:?}/{:?}", browser, os);
            assert_eq!(ch[1], 0x03, "wrong TLS major for {:?}/{:?}", browser, os);
            assert_eq!(ch[2], 0x03, "wrong TLS minor for {:?}/{:?}", browser, os);
            // Record length
            let rec_len = u16::from_be_bytes([ch[3], ch[4]]) as usize;
            assert_eq!(ch.len(), 5 + rec_len, "length mismatch for {:?}/{:?}", browser, os);
            // Handshake type: 0x01 = ClientHello
            assert_eq!(ch[5], 0x01, "not a ClientHello handshake for {:?}/{:?}", browser, os);
        }
    }
}

fn deterministic_client_hello_cipher_suites(record: &[u8]) -> Vec<u16> {
    assert!(record.len() >= 9, "ClientHello record is truncated");
    assert_eq!(record[0], 0x16, "expected a TLS handshake record");
    assert_eq!(record[5], 0x01, "expected a ClientHello handshake");
    let body_len = usize::try_from(u32::from_be_bytes([0, record[6], record[7], record[8]]))
        .expect("ClientHello body length");
    assert!(record.len() >= 9 + body_len, "ClientHello body is truncated");
    let body = &record[9..9 + body_len];
    assert!(body.len() >= 35, "ClientHello body lacks version/random/session ID");
    let session_id_len = usize::from(body[34]);
    let suites_len_offset = 35 + session_id_len;
    assert!(body.len() >= suites_len_offset + 2, "cipher-suite length is truncated");
    let suites_len =
        usize::from(u16::from_be_bytes([body[suites_len_offset], body[suites_len_offset + 1]]));
    let suites_start = suites_len_offset + 2;
    assert_eq!(suites_len % 2, 0, "cipher-suite vector has an odd length");
    assert!(body.len() >= suites_start + suites_len, "cipher-suite vector is truncated");
    body[suites_start..suites_start + suites_len]
        .chunks_exact(2)
        .map(|bytes| u16::from_be_bytes([bytes[0], bytes[1]]))
        .collect()
}

#[test]
fn deterministic_client_hello_metadata_excludes_chacha_for_chrome_and_firefox() {
    use super::{BrowserProfile, FingerprintProfile, OsProfile};

    for (browser, os) in
        [(BrowserProfile::Chrome, OsProfile::Windows), (BrowserProfile::Firefox, OsProfile::Linux)]
    {
        let profile = FingerprintProfile::new(browser, os);
        let hello = profile.client_hello.as_ref().expect("ClientHello metadata");
        let suites = deterministic_client_hello_cipher_suites(hello);
        assert!(
            !suites.iter().any(|suite| matches!(*suite, 0x1303 | 0xCCA8 | 0xCCA9)),
            "deterministic ClientHello for {:?}/{:?} contains ChaCha: {:?}",
            browser,
            os,
            suites
        );
    }
}

#[test]
fn tls_cover_client_hello_firefox_has_no_session_id() {
    use super::{tls_cover::TlsCover, BrowserProfile, OsProfile};
    let ch = TlsCover::generate_client_hello(BrowserProfile::Firefox, OsProfile::Linux, None);
    // Skip record header (5) + handshake header (4) + version (2) + random (32) = offset 43
    let sid_len = ch[43];
    assert_eq!(sid_len, 0, "Firefox should have empty session ID");
}

#[test]
fn tls_cover_client_hello_chrome_has_session_id() {
    use super::{tls_cover::TlsCover, BrowserProfile, OsProfile};
    let ch = TlsCover::generate_client_hello(BrowserProfile::Chrome, OsProfile::Windows, None);
    let sid_len = ch[43];
    assert_eq!(sid_len, 32, "Chrome should have 32-byte session ID");
}

#[test]
fn tls_cover_grease_not_in_safari() {
    use super::{tls_cover::TlsCover, BrowserProfile, OsProfile};
    let ch = TlsCover::generate_client_hello(BrowserProfile::Safari, OsProfile::MacOS, None);
    // Skip to cipher_suites offset: 5 (rec) + 4 (hs) + 2 (ver) + 32 (rand) = 43 + sid_len + 1
    let sid_len = ch[43] as usize;
    let cs_offset = 44 + sid_len;
    let cs_len = u16::from_be_bytes([ch[cs_offset], ch[cs_offset + 1]]) as usize;
    let cipher_bytes = &ch[cs_offset + 2..cs_offset + 2 + cs_len];
    // Check no GREASE values (0x?a?a pattern) in cipher suites
    for pair in cipher_bytes.chunks_exact(2) {
        let val = u16::from_be_bytes([pair[0], pair[1]]);
        let is_grease = (val & 0x0F0F) == 0x0A0A;
        assert!(!is_grease, "Safari should not include GREASE cipher 0x{:04X}", val);
    }
}

#[test]
fn tls_cover_server_hello_cipher_matches_resolved() {
    use super::{BrowserProfile, FingerprintProfile, OsProfile, TlsCoverProvider};
    let _env_lock = acquire_env_lock();
    // Clear env to ensure default Auto behavior
    let _cipher = EnvGuard::set("QUICFUSCATE_TLS_COVER_CIPHER", "auto");

    let pref = TlsCoverProvider::cipher_preference_from_env();
    let expected_id = TlsCoverProvider::resolve_cipher_suite(pref).tls_id();

    // Check across all browser/OS combinations
    for browser in [
        BrowserProfile::Chrome,
        BrowserProfile::Firefox,
        BrowserProfile::Safari,
        BrowserProfile::Edge,
    ] {
        for os in [
            OsProfile::Windows,
            OsProfile::MacOS,
            OsProfile::Linux,
            OsProfile::IOS,
            OsProfile::Android,
        ] {
            let profile = FingerprintProfile::new(browser, os);
            let sh = profile
                .server_hello
                .as_ref()
                .unwrap_or_else(|| panic!("no ServerHello for {:?}/{:?}", browser, os));
            assert_eq!(
                sh.cipher_suite, expected_id,
                "ServerHello cipher mismatch for {:?}/{:?}: got 0x{:04X}, expected 0x{:04X}",
                browser, os, sh.cipher_suite, expected_id
            );
        }
    }
}

#[test]
fn tls_cover_server_hello_cipher_respects_explicit_chacha() {
    use super::{BrowserProfile, FingerprintProfile, OsProfile};
    let _env_lock = acquire_env_lock();
    let _cipher = EnvGuard::set("QUICFUSCATE_TLS_COVER_CIPHER", "chacha");

    let profile = FingerprintProfile::new(BrowserProfile::Chrome, OsProfile::Windows);
    let sh = profile.server_hello.as_ref().expect("no ServerHello");
    assert_eq!(sh.cipher_suite, 0x1303, "explicit chacha preference must yield 0x1303");
}

#[test]
fn tls_cover_server_hello_cipher_respects_explicit_aes() {
    use super::{BrowserProfile, FingerprintProfile, OsProfile};
    let _env_lock = acquire_env_lock();
    let _cipher = EnvGuard::set("QUICFUSCATE_TLS_COVER_CIPHER", "aes");

    let profile = FingerprintProfile::new(BrowserProfile::Chrome, OsProfile::Windows);
    let sh = profile.server_hello.as_ref().expect("no ServerHello");
    assert_eq!(sh.cipher_suite, 0x1301, "explicit aes preference must yield 0x1301");
}

#[test]
fn tls_cover_extension_helpers_produce_valid_tlv() {
    use super::tls_cover;
    // Each extension helper must produce: type(2) + length(2) + payload(length)
    let alpn = tls_cover::alpn_ext(&["h2", "http/1.1"]);
    assert!(alpn.len() >= 4);
    let ext_type = u16::from_be_bytes([alpn[0], alpn[1]]);
    let ext_len = u16::from_be_bytes([alpn[2], alpn[3]]) as usize;
    assert_eq!(ext_type, 0x0010, "ALPN extension type");
    assert_eq!(alpn.len(), 4 + ext_len, "ALPN length mismatch");

    let sni = tls_cover::sni_ext("example.com");
    assert!(sni.len() >= 4);
    let sni_type = u16::from_be_bytes([sni[0], sni[1]]);
    let sni_len = u16::from_be_bytes([sni[2], sni[3]]) as usize;
    assert_eq!(sni_type, 0x0000, "SNI extension type");
    assert_eq!(sni.len(), 4 + sni_len, "SNI length mismatch");

    let sv = tls_cover::supported_versions_ext(&[0x0304, 0x0303]);
    let sv_type = u16::from_be_bytes([sv[0], sv[1]]);
    let sv_len = u16::from_be_bytes([sv[2], sv[3]]) as usize;
    assert_eq!(sv_type, 0x002B, "supported_versions extension type");
    assert_eq!(sv.len(), 4 + sv_len, "supported_versions length mismatch");

    let pad = tls_cover::padding_ext(32);
    let pad_type = u16::from_be_bytes([pad[0], pad[1]]);
    let pad_len = u16::from_be_bytes([pad[2], pad[3]]) as usize;
    assert_eq!(pad_type, 0x0015, "padding extension type");
    assert_eq!(pad_len, 32, "padding payload size");
    assert_eq!(pad.len(), 4 + 32, "padding total size");
    // All padding bytes must be zero
    assert!(pad[4..].iter().all(|&b| b == 0), "padding must be zeros");
}

#[test]
fn tls_cover_padding_ext_clamps_at_256() {
    use super::tls_cover;
    let pad = tls_cover::padding_ext(512);
    let pad_len = u16::from_be_bytes([pad[2], pad[3]]) as usize;
    assert_eq!(pad_len, 256, "padding must clamp at 256");
}

#[test]
fn tls_cover_grease_value_deterministic_and_aligned() {
    use super::tls_cover::grease_value;
    for idx in 0..16 {
        let g = grease_value(idx);
        // GREASE values follow the pattern 0x?a?a
        assert_eq!(g & 0x0F0F, 0x0A0A, "grease_value({}) = 0x{:04X} not GREASE-aligned", idx, g);
    }
    // Same idx must produce same value
    assert_eq!(grease_value(3), grease_value(3));
}

#[test]
fn tls_cover_ech_grease_ext_has_correct_type() {
    use super::tls_cover::ech_grease_ext;
    let ext = ech_grease_ext(42);
    assert!(ext.len() >= 4);
    let ext_type = u16::from_be_bytes([ext[0], ext[1]]);
    assert_eq!(ext_type, 0xFE0D, "ECH GREASE extension type");
    let ext_len = u16::from_be_bytes([ext[2], ext[3]]) as usize;
    assert_eq!(ext.len(), 4 + ext_len, "ECH GREASE length mismatch");
    assert!((8..=40).contains(&ext_len), "ECH GREASE payload out of range: {}", ext_len);
}

// --- FlowShaper Jitter Tests ---

#[test]
fn flow_shaper_jitter_stays_in_range() {
    use super::FlowShaper;
    let shaper = FlowShaper::new(1000, false);
    for _ in 0..200 {
        let d = shaper.apply_jitter();
        let us = d.as_micros() as u64;
        // min = max/2 = 500, max = 1000
        assert!((500..=1000).contains(&us), "jitter {} us out of [500, 1000]", us);
    }
}

#[test]
fn flow_shaper_jitter_min_clamped_to_one() {
    use super::FlowShaper;
    // jitter_us = 1 -> max=1, min=max(1/2,1)=1 -> range [1,1]
    let shaper = FlowShaper::new(1, false);
    for _ in 0..50 {
        let d = shaper.apply_jitter();
        assert_eq!(d.as_micros(), 1, "jitter with max=1 must always be 1us");
    }
}

#[test]
fn flow_shaper_jitter_produces_variation() {
    use super::FlowShaper;
    let shaper = FlowShaper::new(5000, false);
    let mut values: Vec<u64> = (0..100).map(|_| shaper.apply_jitter().as_micros() as u64).collect();
    values.sort();
    values.dedup();
    // With range [2500, 5000] and 100 samples, we expect significant variation
    assert!(
        values.len() > 10,
        "expected variation in jitter, got only {} distinct values",
        values.len()
    );
}

#[test]
fn flow_shaper_flight_pacing_handshake_is_15ms() {
    use super::FlowShaper;
    let shaper = FlowShaper::new(1000, false);
    let d = shaper.apply_flight_pacing(true);
    assert_eq!(d.as_millis(), 15);
    let d2 = shaper.apply_flight_pacing(false);
    assert_eq!(d2.as_micros(), 0);
}

// --- Padding Strategy Config Tests ---

#[test]
fn padding_strategy_defaults_per_mode() {
    use super::{PaddingStrategy, StealthConfig};
    assert_eq!(StealthConfig::stealth().padding_strategy, PaddingStrategy::Adaptive);
    assert_eq!(StealthConfig::anti_dpi().padding_strategy, PaddingStrategy::BrowserMimic);
    assert_eq!(StealthConfig::performance().padding_strategy, PaddingStrategy::Random);
    assert_eq!(StealthConfig::manual().padding_strategy, PaddingStrategy::Random);
    assert_eq!(StealthConfig::intelligent().padding_strategy, PaddingStrategy::Random);
}

#[test]
fn padding_strategy_serde_roundtrip() {
    use super::PaddingStrategy;
    for strategy in [
        PaddingStrategy::Random,
        PaddingStrategy::Fixed,
        PaddingStrategy::Adaptive,
        PaddingStrategy::BrowserMimic,
    ] {
        let json = serde_json::to_string(&strategy).expect("serialize");
        let back: PaddingStrategy = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(strategy, back, "serde roundtrip failed for {:?}", strategy);
    }
}

#[test]
fn padding_strategy_parse_from_env_values() {
    use super::PaddingStrategy;
    // parse_padding_strategy is a private helper, test via StealthConfig
    fn parse(raw: &str) -> Option<PaddingStrategy> {
        match raw.to_ascii_lowercase().as_str() {
            "random" | "1" => Some(PaddingStrategy::Random),
            "fixed" | "constant" | "2" => Some(PaddingStrategy::Fixed),
            "adaptive" | "3" => Some(PaddingStrategy::Adaptive),
            "browser" | "browser_mimic" | "browsermimic" | "4" => {
                Some(PaddingStrategy::BrowserMimic)
            }
            _ => None,
        }
    }
    assert_eq!(parse("random"), Some(PaddingStrategy::Random));
    assert_eq!(parse("1"), Some(PaddingStrategy::Random));
    assert_eq!(parse("fixed"), Some(PaddingStrategy::Fixed));
    assert_eq!(parse("2"), Some(PaddingStrategy::Fixed));
    assert_eq!(parse("adaptive"), Some(PaddingStrategy::Adaptive));
    assert_eq!(parse("3"), Some(PaddingStrategy::Adaptive));
    assert_eq!(parse("browser"), Some(PaddingStrategy::BrowserMimic));
    assert_eq!(parse("4"), Some(PaddingStrategy::BrowserMimic));
    assert_eq!(parse("unknown"), None);
}

#[test]
fn cover_ping_should_send_respects_interval() {
    let optimization = Arc::new(OptimizationManager::new());
    let crypto = Arc::new(CryptoManager::new());
    let mut cfg = StealthConfig::stealth();
    // Very short interval so the test doesn't have to sleep long
    cfg.cover_ping_interval_ms = 20;
    let manager = StealthManager::new(cfg, optimization, crypto);

    // First call: interval elapsed (next_cover_ping initialized to Instant::now())
    assert!(
        manager.should_send_cover_ping(),
        "first call must return true - interval elapsed at init"
    );
    // Immediate second call: interval not elapsed yet
    assert!(
        !manager.should_send_cover_ping(),
        "immediate second call must return false - interval not elapsed"
    );
    // After sleeping past the interval it should fire again
    std::thread::sleep(std::time::Duration::from_millis(25));
    assert!(manager.should_send_cover_ping(), "call after interval elapsed must return true again");
}

#[test]
fn cover_ping_disabled_when_config_off() {
    let optimization = Arc::new(OptimizationManager::new());
    let crypto = Arc::new(CryptoManager::new());
    let manager = StealthManager::new(StealthConfig::off(), optimization, crypto);
    // off() preset has enable_cover_ping = false
    assert!(!manager.should_send_cover_ping(), "off preset must never fire cover ping");
}

#[test]
fn packet_normalize_is_distinct_variant() {
    // Verify PacketNormalize is a distinct PaddingStrategy variant and that
    // it can be set and read back on StealthConfig without aliasing other variants.
    let mut cfg = StealthConfig::performance();
    cfg.padding_strategy = PaddingStrategy::PacketNormalize;
    cfg.normalize_target_size = 1400;
    assert_eq!(cfg.padding_strategy, PaddingStrategy::PacketNormalize);
    assert_eq!(cfg.normalize_target_size, 1400);
    // Must not equal any other variant
    assert_ne!(cfg.padding_strategy, PaddingStrategy::Fixed);
    assert_ne!(cfg.padding_strategy, PaddingStrategy::BrowserMimic);
    assert_ne!(cfg.padding_strategy, PaddingStrategy::Adaptive);
    assert_ne!(cfg.padding_strategy, PaddingStrategy::Random);
}

// --- RateChoker Tests ---

#[test]
fn rate_choker_full_bucket_no_wait() {
    // Bucket starts full (capacity_bytes = target_bps/8 * burst_ms/1000).
    // A request smaller than the capacity must return ZERO immediately.
    let mut choker = super::RateChoker::new(1, 100).expect("choker init");
    let wait = choker.shape(100);
    assert_eq!(wait, std::time::Duration::ZERO, "fresh bucket must not impose a wait");
}

#[test]
fn rate_choker_deficit_causes_positive_wait() {
    // 1 Mbps, 10ms burst -> capacity = 1_000_000/8 * 0.01 = 1250 bytes.
    // Drain the bucket completely, then request more - expect a positive wait.
    let mut choker = super::RateChoker::new(1, 10).expect("choker init");
    let _ = choker.shape(1250); // drain
    let wait = choker.shape(1250); // deficit
    assert!(wait > std::time::Duration::ZERO, "wait after drain must be > 0");
}

// --- DomainFrontingManager Tests ---

#[test]
fn domain_fronting_result_always_in_list() {
    let domains =
        vec!["alpha.example".to_string(), "beta.example".to_string(), "gamma.example".to_string()];
    let mgr = super::DomainFrontingManager::new(domains.clone());
    for _ in 0..30 {
        let d = mgr.get_fronted_domain();
        assert!(domains.contains(&d), "returned domain '{}' not in configured list", d);
    }
}

#[test]
fn domain_fronting_ultra_stealth_returns_non_empty() {
    let mgr = super::DomainFrontingManager::ultra_stealth();
    let d = mgr.get_fronted_domain();
    assert!(!d.is_empty(), "ultra_stealth must return a non-empty domain");
}

// --- Http3Masquerade Tests ---

#[test]
fn http3_masquerade_pseudo_headers_present() {
    use super::{BrowserProfile, FingerprintProfile, Http3Masquerade, OsProfile};
    let masq =
        Http3Masquerade::new(FingerprintProfile::new(BrowserProfile::Chrome, OsProfile::Windows));
    let headers = masq.generate_headers("example.com", "/index.html");

    let find = |name: &[u8]| headers.iter().find(|h| h.name() == name).map(|h| h.value().to_vec());
    assert_eq!(find(b":method"), Some(b"GET".to_vec()), ":method must be GET");
    assert_eq!(find(b":scheme"), Some(b"https".to_vec()), ":scheme must be https");
    assert_eq!(find(b":authority"), Some(b"example.com".to_vec()), ":authority mismatch");
    assert_eq!(find(b":path"), Some(b"/index.html".to_vec()), ":path mismatch");
    assert!(
        headers.iter().any(|h| h.name().eq_ignore_ascii_case(b"user-agent")),
        "user-agent header missing"
    );
}

#[test]
fn http3_masquerade_user_agent_differs_by_browser() {
    use super::{BrowserProfile, FingerprintProfile, Http3Masquerade, OsProfile};
    let chrome =
        Http3Masquerade::new(FingerprintProfile::new(BrowserProfile::Chrome, OsProfile::Windows));
    let firefox =
        Http3Masquerade::new(FingerprintProfile::new(BrowserProfile::Firefox, OsProfile::Linux));

    let ua = |headers: &[crate::transport::h3::Header]| {
        headers
            .iter()
            .find(|h| h.name().eq_ignore_ascii_case(b"user-agent"))
            .map(|h| h.value().to_vec())
    };
    let ch = chrome.generate_headers("t.example", "/");
    let fh = firefox.generate_headers("t.example", "/");
    assert_ne!(ua(&ch), ua(&fh), "Chrome and Firefox must produce different user-agent values");
}

#[test]
fn http3_masquerade_safari_omits_sec_fetch_headers() {
    use super::{BrowserProfile, FingerprintProfile, Http3Masquerade, OsProfile};
    let safari =
        Http3Masquerade::new(FingerprintProfile::new(BrowserProfile::Safari, OsProfile::MacOS));
    let headers = safari.generate_headers("example.com", "/");
    let forbidden = [
        b"sec-fetch-dest".as_slice(),
        b"sec-fetch-mode".as_slice(),
        b"sec-fetch-site".as_slice(),
        b"sec-fetch-user".as_slice(),
    ];

    assert!(headers
        .iter()
        .all(|header| { forbidden.iter().all(|name| !header.name().eq_ignore_ascii_case(name)) }));
}

// --- FingerprintRotation Tests (via StealthManager) ---

#[test]
fn fingerprint_rotation_fixed_mode_stable() {
    use super::{RotationMode, StealthConfig};
    let optimization = Arc::new(OptimizationManager::new());
    let crypto = Arc::new(CryptoManager::new());
    let mut cfg = StealthConfig::stealth();
    cfg.fingerprint_rotation_mode = RotationMode::Fixed;
    cfg.enable_fingerprint_rotation = false;
    cfg.fingerprint_rotation_interval = 0;
    let mgr = StealthManager::new(cfg, optimization, crypto);

    let name_before = mgr.runtime_tls_profile(None).name.clone();
    for _ in 0..20 {
        mgr.maybe_rotate_fingerprint();
    }
    let name_after = mgr.runtime_tls_profile(None).name;
    assert_eq!(name_before, name_after, "Fixed mode must not change fingerprint");
}

#[test]
fn fingerprint_rotation_all_mode_no_panic_under_load() {
    use super::{RotationMode, StealthConfig};
    let optimization = Arc::new(OptimizationManager::new());
    let crypto = Arc::new(CryptoManager::new());
    let mut cfg = StealthConfig::stealth();
    cfg.fingerprint_rotation_mode = RotationMode::All;
    cfg.enable_fingerprint_rotation = true;
    // interval=0 causes early-return (guarded), so this tests the guard path
    cfg.fingerprint_rotation_interval = 0;
    let mgr = StealthManager::new(cfg, optimization, crypto);
    // Must never panic across many calls
    for _ in 0..50 {
        mgr.maybe_rotate_fingerprint();
    }
}

// --- ActiveProbeDetector Tests ---

#[test]
fn active_probe_detector_gfw_tls_pattern_detected() {
    use super::{ActiveProbeDetector, ProbeResponseMode};
    let detector = ActiveProbeDetector::new(10, ProbeResponseMode::Fake);
    let addr = "127.0.0.1:1234".parse().unwrap();
    // GFW_TLS_Probe pattern: [0x16, 0x03, 0x01, 0x00, 0x00] + trailing bytes
    let probe = vec![0x16u8, 0x03, 0x01, 0x00, 0x00, 0xAA, 0xBB];
    let result = detector.check_packet(&probe, addr);
    assert!(result.is_some(), "GFW TLS probe pattern must be detected");
}

#[test]
fn active_probe_detector_dpi_quic_scan_mask_detected() {
    use super::{ActiveProbeDetector, ProbeResponseMode};
    let detector = ActiveProbeDetector::new(10, ProbeResponseMode::Block);
    let addr = "10.0.0.1:5000".parse().unwrap();
    // DPI_QUIC_Scan pattern was removed because it matched legitimate QUICv1
    // Initial packets (0xc0 + version 0x00000001 + DCID len 0x01). The pattern
    // is indistinguishable from a real client's Initial at the byte level.
    // Verify that the removed pattern no longer triggers false positives.
    let probe = vec![0xc0u8, 0xDE, 0xAD, 0xBE, 0x01, 0x00];
    let result = detector.check_packet(&probe, addr);
    assert!(
        result.is_none(),
        "DPI QUIC scan pattern must not match (removed: false positive on QUICv1 Initial)"
    );
}

#[test]
fn active_probe_detector_benign_packet_ignored() {
    use super::{ActiveProbeDetector, ProbeResponseMode};
    let detector = ActiveProbeDetector::new(10, ProbeResponseMode::Ignore);
    let addr = "192.168.1.1:443".parse().unwrap();
    // A typical valid QUIC Initial (long header, version 1): starts with 0xC0 | flags, version...
    // byte[0]=0xC0 doesn't match GFW_TLS_Probe (needs byte[0]=0x16)
    let benign = vec![0xC0u8, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00];
    let result = detector.check_packet(&benign, addr);
    assert!(result.is_none(), "benign QUIC packet must not trigger probe detection");
}

// --- ServerPushState Tests ---

#[test]
fn server_push_cover_plan_none_after_burst() {
    let optimization = Arc::new(OptimizationManager::new());
    let crypto = Arc::new(CryptoManager::new());
    let mut cfg = StealthConfig::anti_dpi();
    cfg.enable_server_push_cover = true;
    cfg.server_push_burst_interval = 30; // 30-second interval
    let mgr = StealthManager::new(cfg, optimization, crypto);

    // Simulate a burst: observe it, which resets last_burst to now
    mgr.observe_server_push_burst("/assets/app.js", 3, 0.5, 0, 0);
    // Immediately after, the interval has not elapsed - plan should be None
    let plan = mgr.server_push_cover_plan_for_test();
    assert!(plan.is_none(), "cover plan must be None immediately after a burst resets the timer");
}

#[test]
fn server_push_cover_plan_disabled_returns_none() {
    let optimization = Arc::new(OptimizationManager::new());
    let crypto = Arc::new(CryptoManager::new());
    let mut cfg = StealthConfig::stealth();
    cfg.enable_server_push_cover = false;
    let mgr = StealthManager::new(cfg, optimization, crypto);
    let plan = mgr.server_push_cover_plan_for_test();
    assert!(plan.is_none(), "server_push_cover_plan must be None when cover is disabled");
}

// =============================================================================
// TODO-416: Gradual Stealth Escalation Tests
// =============================================================================

#[test]
fn test_escalate_to_level_0_no_overhead() {
    let mgr = StealthManager::new(
        StealthConfig::intelligent(),
        Arc::new(OptimizationManager::new()),
        Arc::new(CryptoManager::new()),
    );
    mgr.escalate_to_level(0);
    assert_eq!(mgr.runtime_padding_rate(), 0);
    assert_eq!(mgr.runtime_timing_rate(), 0);
    assert_eq!(mgr.runtime_rotation_rate(), 0);
}

#[test]
fn test_escalate_to_level_1_partial_padding() {
    let mgr = StealthManager::new(
        StealthConfig::intelligent(),
        Arc::new(OptimizationManager::new()),
        Arc::new(CryptoManager::new()),
    );
    mgr.escalate_to_level(1);
    // Level 1: padding at 50% (default), no timing, no rotation
    assert!(mgr.runtime_padding_rate() > 0, "padding should be active at level 1");
    assert!(mgr.runtime_padding_rate() <= 100, "padding rate should be <= 100");
    assert_eq!(mgr.runtime_timing_rate(), 0, "timing should be off at level 1");
    assert_eq!(mgr.runtime_rotation_rate(), 0, "rotation should be off at level 1");
}

#[test]
fn test_escalate_to_level_2_full_overhead() {
    let mgr = StealthManager::new(
        StealthConfig::intelligent(),
        Arc::new(OptimizationManager::new()),
        Arc::new(CryptoManager::new()),
    );
    mgr.escalate_to_level(2);
    assert_eq!(mgr.runtime_padding_rate(), 100);
    assert_eq!(mgr.runtime_timing_rate(), 100);
    assert_eq!(mgr.runtime_rotation_rate(), 0, "active persona rotation stays disabled");
}

#[test]
fn test_de_escalate_from_level_2_to_0() {
    let mgr = StealthManager::new(
        StealthConfig::intelligent(),
        Arc::new(OptimizationManager::new()),
        Arc::new(CryptoManager::new()),
    );
    mgr.escalate_to_level(2);
    assert_eq!(mgr.runtime_padding_rate(), 100);
    mgr.de_escalate_to_level(0);
    assert_eq!(mgr.runtime_padding_rate(), 0);
    assert_eq!(mgr.runtime_timing_rate(), 0);
    assert_eq!(mgr.runtime_rotation_rate(), 0);
}

#[test]
fn test_gradual_escalation_ladder() {
    let mgr = StealthManager::new(
        StealthConfig::intelligent(),
        Arc::new(OptimizationManager::new()),
        Arc::new(CryptoManager::new()),
    );
    // Level 0 → Level 1 → Level 2: each step increases overhead
    mgr.escalate_to_level(0);
    let l0_padding = mgr.runtime_padding_rate();
    mgr.escalate_to_level(1);
    let l1_padding = mgr.runtime_padding_rate();
    mgr.escalate_to_level(2);
    let l2_padding = mgr.runtime_padding_rate();
    assert!(l0_padding < l1_padding, "level 1 should have more padding than level 0");
    assert!(l1_padding < l2_padding, "level 2 should have more padding than level 1");
}

/// Single probe detection must NOT trigger escalation (stays at Level 0).
#[test]
fn test_single_probe_no_escalation() {
    let mgr = StealthManager::new(
        StealthConfig::intelligent(),
        Arc::new(OptimizationManager::new()),
        Arc::new(CryptoManager::new()),
    );
    mgr.reset_escalation_state();
    // Record a single probe — should not escalate.
    let result = mgr.record_probe_for_test();
    assert!(result.is_none(), "single probe must not trigger escalation");
    assert_eq!(mgr.escalation_level(), 0, "level should remain 0 after 1 probe");
    assert_eq!(mgr.probe_count_60s(), 1, "probe should be recorded in window");
}

/// Three probes within 60 seconds must escalate to Level 1.
#[test]
fn test_three_probes_in_60s_escalate_to_level_1() {
    let mgr = StealthManager::new(
        StealthConfig::intelligent(),
        Arc::new(OptimizationManager::new()),
        Arc::new(CryptoManager::new()),
    );
    mgr.reset_escalation_state();

    // Probe 1: no escalation
    let r1 = mgr.record_probe_for_test();
    assert!(r1.is_none(), "probe 1 should not escalate");

    // Probe 2: no escalation
    let r2 = mgr.record_probe_for_test();
    assert!(r2.is_none(), "probe 2 should not escalate");

    // Probe 3: escalate to level 1
    let r3 = mgr.record_probe_for_test();
    assert_eq!(r3, Some(1), "probe 3 should escalate to level 1");
    assert_eq!(mgr.escalation_level(), 1, "level should be 1 after 3 probes");
}

/// Eight probes within 120 seconds must escalate to Level 2.
#[test]
fn test_eight_probes_in_120s_escalate_to_level_2() {
    let mgr = StealthManager::new(
        StealthConfig::intelligent(),
        Arc::new(OptimizationManager::new()),
        Arc::new(CryptoManager::new()),
    );
    mgr.reset_escalation_state();

    // First 3 probes → level 1
    for _ in 0..3 {
        mgr.record_probe_for_test();
    }
    assert_eq!(mgr.escalation_level(), 1, "should be at level 1 after 3 probes");

    // 5 more probes (total 8) → level 2
    let mut last_result = None;
    for _ in 3..8 {
        last_result = mgr.record_probe_for_test();
    }
    assert_eq!(last_result, Some(2), "8th probe should escalate to level 2");
    assert_eq!(mgr.escalation_level(), 2, "level should be 2 after 8 probes");
}

/// De-escalation: after quiet period, level should drop by one.
/// This test uses a very short quiet period via env override.
#[test]
fn test_de_escalation_after_quiet_period() {
    use std::sync::Mutex;

    // Use a 1-second quiet period for testing.
    static ENV_GUARD: Mutex<()> = Mutex::new(());
    let _guard = ENV_GUARD.lock().unwrap();
    std::env::set_var("QUICFUSCATE_STEALTH_DEESCALATION_QUIET_PERIOD_SEC", "1");

    let mgr = StealthManager::new(
        StealthConfig::intelligent(),
        Arc::new(OptimizationManager::new()),
        Arc::new(CryptoManager::new()),
    );
    mgr.reset_escalation_state();

    // Escalate to level 2 with 8 probes
    for _ in 0..8 {
        mgr.record_probe_for_test();
    }
    assert_eq!(mgr.escalation_level(), 2, "should be at level 2");

    // Wait for quiet period to elapse (1 second + small buffer)
    std::thread::sleep(std::time::Duration::from_millis(1200));

    // Check de-escalation — should drop from 2 to 1
    let result = mgr.check_de_escalation_for_test();
    assert_eq!(result, Some(1), "should de-escalate from 2 to 1 after quiet period");
    assert_eq!(mgr.escalation_level(), 1, "level should be 1 after de-escalation");
    assert_eq!(
        mgr.check_de_escalation_for_test(),
        None,
        "a second level drop must wait for a fresh quiet period"
    );

    // Wait again for another quiet period
    std::thread::sleep(std::time::Duration::from_millis(1200));

    // Should de-escalate from 1 to 0
    let result2 = mgr.check_de_escalation_for_test();
    assert_eq!(result2, Some(0), "should de-escalate from 1 to 0 after quiet period");
    assert_eq!(mgr.escalation_level(), 0, "level should be 0 after second de-escalation");

    std::env::remove_var("QUICFUSCATE_STEALTH_DEESCALATION_QUIET_PERIOD_SEC");
}

/// Padding rate in StealthRuntimePolicy scales correctly per level.
#[test]
fn test_policy_padding_rate_scales_per_level() {
    use crate::stealth::IntelligentStealthInputs;

    // Level 0: padding_rate = 0
    let policy_l0 = StealthManager::derive_intelligent_runtime_policy(IntelligentStealthInputs {
        level_hint: 0,
        ce_ratio_recent: 0.0,
        ack_us: 5000.0,
        size_div: 0.0,
        iat_div: 0.0,
        reorder_ratio: 0.0,
        rtt_spike_weight: 0.0,
        signal_tos: 0,
        signal_other: 0,
        jitter_max_us: 3000,
        pad_max_low: 128,
        pad_max_high: 512,
    });
    assert_eq!(policy_l0.padding_rate, 0, "level 0 padding rate should be 0");
    assert_eq!(policy_l0.timing_rate, 0, "level 0 timing rate should be 0");

    // Level 2 with pressure: padding_rate = 100, timing_rate = 100
    let policy_l2 = StealthManager::derive_intelligent_runtime_policy(IntelligentStealthInputs {
        level_hint: 2,
        ce_ratio_recent: 0.15,
        ack_us: 15000.0,
        size_div: 1.5,
        iat_div: 1.2,
        reorder_ratio: 0.05,
        rtt_spike_weight: 4.0,
        signal_tos: 1,
        signal_other: 1,
        jitter_max_us: 3000,
        pad_max_low: 128,
        pad_max_high: 512,
    });
    assert_eq!(policy_l2.padding_rate, 100, "level 2 padding rate should be 100");
    assert_eq!(policy_l2.timing_rate, 100, "level 2 timing rate should be 100");
}

/// Timing rate in StealthRuntimePolicy is 0 at level 1, 100 at level 2.
#[test]
fn test_policy_timing_rate_per_level() {
    use crate::stealth::IntelligentStealthInputs;

    // Level 1 with pressure: timing_rate = 0 (timing only at level 2)
    let policy_l1 = StealthManager::derive_intelligent_runtime_policy(IntelligentStealthInputs {
        level_hint: 1,
        ce_ratio_recent: 0.05,
        ack_us: 8000.0,
        size_div: 0.8,
        iat_div: 0.5,
        reorder_ratio: 0.01,
        rtt_spike_weight: 1.0,
        signal_tos: 0,
        signal_other: 1,
        jitter_max_us: 3000,
        pad_max_low: 128,
        pad_max_high: 512,
    });
    assert_eq!(policy_l1.timing_rate, 0, "level 1 timing rate should be 0");
    assert!(policy_l1.padding_rate > 0, "level 1 padding rate should be > 0");
}

// --- ChaffGenerator tests (TODO-455) ---

use super::ChaffGenerator;
use std::time::{Duration, Instant};

#[test]
fn test_chaff_generator_disabled_rate_zero() {
    let mut gen = ChaffGenerator::new(0, 1280, true);
    assert!(gen.is_disabled());
    assert_eq!(gen.rate_pps(), 0);
    // should_chaff never returns true when disabled.
    let now = Instant::now();
    for _ in 0..10 {
        assert!(!gen.should_chaff(now, false));
    }
}

#[test]
fn test_chaff_generator_produces_packets_at_correct_rate() {
    // 10 pps => base interval 100ms. With ±10% jitter the interval is in
    // [90ms, 110ms]. Over 1 second we expect ~10 emissions.
    let mut gen = ChaffGenerator::new(10, 1280, true);
    let start = Instant::now();
    let mut emitted = 0usize;
    // Simulate 1000ms of time in 1ms steps.
    for ms in 1..=1000 {
        let now = start + Duration::from_millis(ms);
        if gen.should_chaff(now, false) {
            emitted += 1;
        }
    }
    // Expect roughly 10 packets; allow [7, 13] for jitter variance.
    assert!(
        (7..=13).contains(&emitted),
        "expected ~10 chaff emissions in 1s at 10pps, got {emitted}"
    );
}

#[test]
fn test_chaff_generator_timing_boundaries() {
    // At 10 pps the base interval is 100ms. Immediately after construction the
    // first chaff should not fire (less than one interval elapsed). After ~100ms
    // it should fire.
    let mut gen = ChaffGenerator::new(10, 1280, true);
    let t0 = Instant::now();
    // 50ms in — should not fire (interval is >= 90ms with jitter).
    assert!(!gen.should_chaff(t0 + Duration::from_millis(50), false));
    // 120ms in — should fire (interval is <= 110ms with jitter).
    assert!(
        gen.should_chaff(t0 + Duration::from_millis(120), false),
        "chaff should fire after one interval"
    );
}

#[test]
fn test_chaff_generator_real_traffic_suppresses_chaff() {
    let mut gen = ChaffGenerator::new(10, 1280, true);
    let t0 = Instant::now();
    // Real traffic at t0+50ms resets the clock.
    assert!(!gen.should_chaff(t0 + Duration::from_millis(50), true));
    // 80ms after the real packet (t0+130ms) — within the minimum jittered
    // interval (90ms at 10pps with -10% jitter), no chaff.
    assert!(!gen.should_chaff(t0 + Duration::from_millis(130), false));
    // 130ms after the real packet (t0+180ms) — should fire (beyond max
    // jittered interval of 110ms).
    assert!(
        gen.should_chaff(t0 + Duration::from_millis(180), false),
        "chaff should fire one interval after real traffic"
    );
}

#[test]
fn test_chaff_generator_record_real_traffic_resets_clock() {
    let mut gen = ChaffGenerator::new(10, 1280, true);
    let t0 = Instant::now();
    gen.record_real_traffic(t0 + Duration::from_millis(50));
    // 80ms after recorded real traffic — within minimum jittered interval, no chaff.
    assert!(!gen.should_chaff(t0 + Duration::from_millis(130), false));
    // 130ms after recorded real traffic — should fire (beyond max jittered interval).
    assert!(
        gen.should_chaff(t0 + Duration::from_millis(180), false),
        "chaff should fire one interval after recorded real traffic"
    );
}

#[test]
fn test_chaff_generator_base_interval() {
    assert_eq!(ChaffGenerator::base_interval(0), Duration::ZERO);
    assert_eq!(ChaffGenerator::base_interval(1), Duration::from_secs(1));
    assert_eq!(ChaffGenerator::base_interval(10), Duration::from_millis(100));
    assert_eq!(ChaffGenerator::base_interval(100), Duration::from_millis(10));
    assert_eq!(ChaffGenerator::base_interval(1000), Duration::from_millis(1));
}

#[test]
fn test_chaff_generator_jitter_within_ten_percent() {
    // The next_interval must be within [90%, 110%] of the base interval.
    for _ in 0..256 {
        let gen = ChaffGenerator::new(100, 1280, true);
        let base = ChaffGenerator::base_interval(100);
        let lo = base * 90 / 100;
        let hi = base * 110 / 100;
        let ni = gen.next_interval();
        assert!(ni >= lo && ni <= hi, "jittered interval {ni:?} outside [{lo:?}, {hi:?}]");
    }
}

#[test]
fn test_chaff_generator_acking_packet_has_valid_quic_structure() {
    // A chaff packet plaintext must be: PING (0x01) + PADDING (0x00...).
    let gen = ChaffGenerator::new(10, 1280, true);
    assert!(gen.ack_eliciting());
    let pt = gen.generate_chaff(100);
    assert_eq!(pt.len(), 100, "plaintext must be exactly target_plaintext_len bytes");
    // First byte is the PING frame type (0x01).
    assert_eq!(pt[0], 0x01, "first frame must be PING (0x01) when ack_eliciting");
    // Remaining bytes are PADDING frames (0x00).
    for &b in &pt[1..] {
        assert_eq!(b, 0x00, "padding bytes must be 0x00 (PADDING frame)");
    }
}

#[test]
fn test_chaff_generator_non_acking_packet_is_all_padding() {
    let gen = ChaffGenerator::new(10, 1280, false);
    assert!(!gen.ack_eliciting());
    let pt = gen.generate_chaff(64);
    assert_eq!(pt.len(), 64);
    for &b in &pt {
        assert_eq!(
            b,
            super::CHAFF_PADDING_FRAME_BYTE,
            "non-acking chaff must be entirely PADDING frames"
        );
    }
}

#[test]
fn test_chaff_generator_sized_respects_header_and_tag() {
    // chaff_size_bytes=1280, header=20, tag=16 => plaintext = 1244.
    let gen = ChaffGenerator::new(10, 1280, true);
    let pt = gen.generate_chaff_sized(20, 16);
    assert_eq!(pt.len(), 1280 - 20 - 16);
    assert_eq!(pt[0], 0x01, "PING frame present");
}

#[test]
fn test_chaff_generator_sized_saturates_on_small_target() {
    // If header+tag exceeds chaff_size_bytes, plaintext is empty (no panic).
    let gen = ChaffGenerator::new(10, 100, true);
    let pt = gen.generate_chaff_sized(200, 16);
    assert!(pt.is_empty(), "plaintext should be empty when overhead exceeds target");
}

#[test]
fn test_chaff_generator_empty_plaintext() {
    let gen = ChaffGenerator::new(10, 1280, true);
    let pt = gen.generate_chaff(0);
    assert!(pt.is_empty());
}

#[test]
fn test_chaff_generator_single_byte_plaintext_omits_ping() {
    // With ack_eliciting but only 1 byte, PING fits (1 byte). Verify it's PING.
    let gen = ChaffGenerator::new(10, 1280, true);
    let pt = gen.generate_chaff(1);
    assert_eq!(pt, vec![0x01]);
}

#[test]
fn test_chaff_generator_debug_format() {
    let gen = ChaffGenerator::new(10, 1280, true);
    let s = format!("{:?}", gen);
    assert!(s.contains("ChaffGenerator"));
    assert!(s.contains("rate_pps: 10"));
    assert!(s.contains("chaff_size_bytes: 1280"));
}
