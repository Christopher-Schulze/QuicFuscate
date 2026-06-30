#![cfg(feature = "rust-tests")]

use quicfuscate::error::ConnectionError;
use quicfuscate::transport::{Config, CongestionControlAlgorithm, PROTOCOL_VERSION};

#[test]
fn config_accepts_known_version() {
    let cfg = Config::new_with_version(PROTOCOL_VERSION);
    assert!(cfg.is_ok());
}

#[test]
fn config_rejects_unknown_version() {
    let cfg = Config::new_with_version(PROTOCOL_VERSION + 1);
    assert!(matches!(cfg, Err(ConnectionError::VersionMismatch)));
}

#[test]
fn config_cc_algorithm_name_parsing() {
    let mut cfg = Config::new_with_version(PROTOCOL_VERSION).expect("config");
    cfg.set_cc_algorithm_name("reno").expect("reno");
    assert_eq!(cfg.cc_algorithm(), CongestionControlAlgorithm::Reno);
    cfg.set_cc_algorithm_name("bbr2").expect("bbr2");
    assert_eq!(cfg.cc_algorithm(), CongestionControlAlgorithm::BBR2);
    cfg.set_cc_algorithm_name("bbr3").expect("bbr3");
    assert_eq!(cfg.cc_algorithm(), CongestionControlAlgorithm::BBR3);
    cfg.set_cc_algorithm_name("cubic").expect("cubic");
    assert_eq!(cfg.cc_algorithm(), CongestionControlAlgorithm::Cubic);
    // Unknown names are rejected
    assert!(cfg.set_cc_algorithm_name("bbr").is_err());
    assert!(cfg.set_cc_algorithm_name("ledbat").is_err());
    assert!(cfg.set_cc_algorithm_name("bbr2_gcongestion").is_err());
    assert!(cfg.set_cc_algorithm_name("not-a-cc").is_err());
}

#[test]
fn config_wire_format_and_stealth_setters_are_safe() {
    let mut cfg = Config::new_with_version(PROTOCOL_VERSION).expect("config");
    cfg.set_application_protos_wire_format(b"").expect("wire format");
    cfg.set_application_protos_wire_format(b"\x02h3\x08http/1.1").expect("wire format");
    cfg.set_stealth_padding(true, 2, 128);
    cfg.set_stealth_timing(true, 250);
    cfg.set_ack_eliciting_threshold(3);
    cfg.set_external_pacing(true);
}

#[test]
fn config_rejects_invalid_wire_format() {
    let mut cfg = Config::new_with_version(PROTOCOL_VERSION).expect("config");
    let err = cfg
        .set_application_protos_wire_format(b"\x03h3")
        .expect_err("invalid wire format must fail");
    assert!(matches!(err, ConnectionError::InvalidState));
}

#[test]
fn config_rejects_missing_cert_key_and_ca_paths() {
    let mut cfg = Config::new_with_version(PROTOCOL_VERSION).expect("config");
    let missing = std::env::temp_dir().join(format!(
        "qf-missing-{}-{}.pem",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("time")
            .as_nanos()
    ));
    let missing_str = missing.to_str().expect("utf8 path");

    let cert_err = cfg.load_cert_chain_from_pem_file(missing_str).expect_err("missing cert path");
    assert!(matches!(cert_err, ConnectionError::TlsError(_)));

    let key_err = cfg.load_priv_key_from_pem_file(missing_str).expect_err("missing key path");
    assert!(matches!(key_err, ConnectionError::TlsError(_)));

    let ca_err =
        cfg.load_verify_locations_from_file(missing_str).expect_err("missing ca file path");
    assert!(matches!(ca_err, ConnectionError::TlsError(_)));

    let ca_dir_err =
        cfg.load_verify_locations_from_directory(missing_str).expect_err("missing ca dir path");
    assert!(matches!(ca_dir_err, ConnectionError::TlsError(_)));
}

// --- 0-RTT Early Data Config Tests ---

#[test]
fn early_data_disabled_by_default() {
    let cfg = Config::new_with_version(PROTOCOL_VERSION).expect("config");
    assert!(!cfg.is_early_data_enabled(), "0-RTT must be off by default");
}

#[test]
fn early_data_can_be_enabled() {
    let mut cfg = Config::new_with_version(PROTOCOL_VERSION).expect("config");
    cfg.enable_early_data();
    assert!(cfg.is_early_data_enabled());
}

#[test]
fn early_data_with_strike_register() {
    use quicfuscate::transport::anti_replay::StrikeRegister;
    use std::sync::Arc;

    let mut cfg = Config::new_with_version(PROTOCOL_VERSION).expect("config");
    let register = Arc::new(StrikeRegister::new(Default::default()));
    cfg.set_strike_register(register);
    cfg.enable_early_data();
    assert!(cfg.is_early_data_enabled());
}

// --- Stealth Padding Config Tests ---

#[test]
fn stealth_padding_strategies_all_configurable() {
    let mut cfg = Config::new_with_version(PROTOCOL_VERSION).expect("config");
    // Strategy codes: 1=Random, 2=Fixed, 3=Adaptive, 4=BrowserMimic, 5=PacketNormalize
    for strategy in [1u8, 2, 3, 4, 5] {
        cfg.set_stealth_padding(true, strategy, 256);
        if strategy == 5 {
            cfg.set_stealth_normalize_target(1200);
        }
    }
    // Disabling works
    cfg.set_stealth_padding(false, 1, 0);
}

#[test]
fn stealth_timing_configurable() {
    let mut cfg = Config::new_with_version(PROTOCOL_VERSION).expect("config");
    cfg.set_stealth_timing(true, 500);
    cfg.set_stealth_timing(false, 0);
}
