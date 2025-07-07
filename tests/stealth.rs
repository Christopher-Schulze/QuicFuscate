use quicfuscate::crypto::CryptoManager;
use quicfuscate::optimize::OptimizationManager;
use quicfuscate::stealth::{StealthConfig, StealthManager};
use quicfuscate::stealth::{BrowserProfile, FingerprintProfile, OsProfile};
use std::time::Duration;
use std::sync::Arc;

#[test]
fn outgoing_packet_obfuscation_cycle() {
    let crypto = Arc::new(CryptoManager::new());
    let optimize = Arc::new(OptimizationManager::new());
    let config = StealthConfig::default();
    let mgr = StealthManager::new(config, crypto, optimize);

    let mut payload = vec![1u8, 2, 3, 4];
    let original = payload.clone();
    mgr.process_outgoing_packet(&mut payload);
    assert_ne!(payload, original, "payload should be obfuscated");
    mgr.process_incoming_packet(&mut payload);
    assert_eq!(payload, original, "payload should roundtrip correctly");
}

#[test]
fn domain_fronting_changes_sni() {
    let crypto = Arc::new(CryptoManager::new());
    let optimize = Arc::new(OptimizationManager::new());
    let mut config = StealthConfig::default();
    config.enable_domain_fronting = true;
    let mgr = StealthManager::new(config, crypto, optimize);

    let (sni, host) = mgr.get_connection_headers("example.com");
    assert_eq!(host, "example.com");
    assert_ne!(sni, host, "SNI should differ when fronting is enabled");
}

#[test]
fn generate_http3_headers() {
    let crypto = Arc::new(CryptoManager::new());
    let optimize = Arc::new(OptimizationManager::new());
    let config = StealthConfig::default();
    let mgr = StealthManager::new(config, crypto, optimize);

    let headers = mgr
        .get_http3_masquerade_headers("example.com", "/")
        .expect("headers");
    assert!(!headers.is_empty());
}

#[test]
fn doh_disabled_fallback() {
    let crypto = Arc::new(CryptoManager::new());
    let optimize = Arc::new(OptimizationManager::new());
    let mut config = StealthConfig::default();
    config.enable_doh = false;
    let mgr = StealthManager::new(config, crypto, optimize);

    let ip = mgr.resolve_domain("example.com");
    assert_eq!(ip.to_string(), "1.1.1.1");
}

#[test]
fn doh_failure_fallback() {
    let crypto = Arc::new(CryptoManager::new());
    let optimize = Arc::new(OptimizationManager::new());
    let mut config = StealthConfig::default();
    config.doh_provider = "https://invalid.invalid/dns-query".to_string();
    let mgr = StealthManager::new(config, crypto, optimize);

    let ip = mgr.resolve_domain("example.com");
    assert_eq!(ip.to_string(), "1.1.1.1");
}

#[test]
fn profile_rotation_changes_active_profile() {
    let crypto = Arc::new(CryptoManager::new());
    let optimize = Arc::new(OptimizationManager::new());
    let config = StealthConfig::default();
    let mgr = Arc::new(StealthManager::new(config, crypto, optimize));

    let profiles = vec![
        FingerprintProfile::new(BrowserProfile::Chrome, OsProfile::Windows),
        FingerprintProfile::new(BrowserProfile::Firefox, OsProfile::Linux),
    ];
    let first = mgr.current_profile();
    mgr.start_profile_rotation(profiles, Duration::from_millis(10));
    std::thread::sleep(Duration::from_millis(30));
    let second = mgr.current_profile();
    assert_ne!(first.browser, second.browser);
}

#[test]
fn apply_utls_profile_runs() {
    let crypto = Arc::new(CryptoManager::new());
    let optimize = Arc::new(OptimizationManager::new());
    let config = StealthConfig::default();
    let mgr = StealthManager::new(config, crypto, optimize);

    let mut cfg = quiche::Config::new(quiche::PROTOCOL_VERSION).unwrap();
    mgr.apply_utls_profile(&mut cfg, None);
}
