#![cfg(feature = "rust-tests")]

use quicfuscate::compress;
use quicfuscate::stealth::{BrowserProfile, OsProfile, PaddingStrategy, StealthConfig};
use std::sync::Mutex;

// These tests mutate one process-global compression policy. Keep the capture,
// mutation, and restoration transaction together when the test binary runs in
// parallel with another policy-guarded test.
static POLICY_TEST_LOCK: Mutex<()> = Mutex::new(());

struct PolicyGuard(compress::CompressionPolicy);

impl PolicyGuard {
    fn capture() -> Self {
        Self(compress::global_policy())
    }
}

impl Drop for PolicyGuard {
    fn drop(&mut self) {
        compress::set_global_policy(self.0.clone());
    }
}

#[test]
fn stealth_config_from_toml_overrides_fields_and_updates_policy() {
    let _policy_lock = POLICY_TEST_LOCK.lock().expect("policy test lock");
    let _guard = PolicyGuard::capture();
    let toml = r#"
[stealth]
initial_browser = "Firefox"
initial_os = "Linux"
enable_network_fingerprint_normalization = false
suppress_icmp_unreachable = true
use_tls_cover = true
enable_doh = false
doh_provider = "https://example.com/doh"
enable_http3_masquerading = false
use_qpack_headers = false
enable_domain_fronting = false
fronting_domains = ["front1.example", "front2.example"]
enable_traffic_padding = true
enable_timing_obfuscation = true
enable_protocol_mimicry = false
padding_strategy = "fixed"
max_padding_size = 512

[compression]
enabled = false
min_len = 512
level = 7
allow = ["text/plain"]
deny = ["image/*"]
"#;

    let cfg = StealthConfig::from_toml(toml).expect("parse stealth toml");
    assert_eq!(cfg.initial_browser, BrowserProfile::Firefox);
    assert_eq!(cfg.initial_os, OsProfile::Linux);
    assert!(!cfg.enable_network_fingerprint_normalization);
    assert!(cfg.suppress_icmp_unreachable);
    assert!(cfg.use_tls_cover);
    assert!(!cfg.enable_doh);
    assert_eq!(cfg.doh_provider, "https://example.com/doh");
    assert!(!cfg.enable_http3_masquerading);
    assert!(!cfg.use_qpack_headers);
    assert!(!cfg.enable_domain_fronting);
    assert_eq!(
        cfg.fronting_domains,
        vec!["front1.example".to_string(), "front2.example".to_string()]
    );
    assert!(cfg.enable_traffic_padding);
    assert!(cfg.enable_timing_obfuscation);
    assert!(!cfg.enable_protocol_mimicry);
    assert_eq!(cfg.padding_strategy, PaddingStrategy::Fixed);
    assert_eq!(cfg.max_padding_size, 512);

    let policy = compress::global_policy();
    assert!(!policy.enabled);
    assert_eq!(policy.min_len, 512);
    assert_eq!(policy.level, 7);
    assert_eq!(policy.allow, vec!["text/plain".to_string()]);
    assert_eq!(policy.deny, vec!["image/*".to_string()]);
}

#[test]
fn stealth_config_from_toml_ignores_unknown_keys() {
    let _policy_lock = POLICY_TEST_LOCK.lock().expect("policy test lock");
    let _guard = PolicyGuard::capture();
    let toml = r#"
[stealth]
initial_browser = "Chrome"
unknown_key = 123
"#;

    let cfg = StealthConfig::from_toml(toml).expect("parse with unknown keys");
    assert_eq!(cfg.initial_browser, BrowserProfile::Chrome);
}

// ---------------------------------------------------------------------------
// Phase 2: PacketNormalize padding strategy
// ---------------------------------------------------------------------------

#[test]
fn packet_normalize_variant_serializes_and_deserializes() {
    let toml = r#"
[stealth]
padding_strategy = "PacketNormalize"
normalize_target_size = 1200
"#;
    let cfg = StealthConfig::from_toml(toml).expect("parse PacketNormalize");
    assert_eq!(cfg.padding_strategy, PaddingStrategy::PacketNormalize);
    assert_eq!(cfg.normalize_target_size, 1200);
}

#[test]
fn anti_dpi_preset_uses_packet_normalize_with_target() {
    let cfg = StealthConfig::anti_dpi();
    assert_eq!(cfg.padding_strategy, PaddingStrategy::BrowserMimic);
    // Anti-DPI carries a normalize_target for operators who switch to PacketNormalize
    assert_eq!(cfg.normalize_target_size, 1200);
}

#[test]
fn off_preset_has_normalize_target_zero() {
    let cfg = StealthConfig::off();
    assert_eq!(cfg.normalize_target_size, 0);
    assert!(!cfg.enable_network_fingerprint_normalization);
    assert!(!cfg.suppress_icmp_unreachable);
    assert!(!cfg.enable_cover_ping);
}

// ---------------------------------------------------------------------------
// Phase 3: Cover PING scheduling
// ---------------------------------------------------------------------------

#[test]
fn stealth_preset_enables_cover_ping() {
    let cfg = StealthConfig::stealth();
    assert!(cfg.enable_cover_ping);
    assert_eq!(cfg.cover_ping_interval_ms, 30_000);
}

#[test]
fn anti_dpi_preset_has_aggressive_cover_ping() {
    let cfg = StealthConfig::anti_dpi();
    assert!(cfg.enable_cover_ping);
    assert_eq!(cfg.cover_ping_interval_ms, 15_000);
}

#[test]
fn cover_ping_config_roundtrips_toml() {
    let toml = r#"
[stealth]
enable_cover_ping = true
cover_ping_interval_ms = 5000
"#;
    let cfg = StealthConfig::from_toml(toml).expect("parse cover ping config");
    assert!(cfg.enable_cover_ping);
    assert_eq!(cfg.cover_ping_interval_ms, 5000);
}

#[test]
fn performance_and_off_presets_disable_cover_ping() {
    for cfg in [StealthConfig::performance(), StealthConfig::off()] {
        assert!(!cfg.enable_cover_ping, "mode {:?} should have cover ping off", cfg.mode);
    }
}
