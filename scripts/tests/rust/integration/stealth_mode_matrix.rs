use quicfuscate::crypto::CryptoManager;
use quicfuscate::optimize::OptimizationManager;
use quicfuscate::stealth::{StealthConfig, StealthManager, StealthMode};
use std::sync::Arc;
use std::time::Duration;

fn manager_for_mode(mode: StealthMode) -> StealthManager {
    StealthManager::new(
        StealthConfig::from_mode(mode),
        Arc::new(OptimizationManager::new()),
        Arc::new(CryptoManager::new()),
    )
}

fn manager_for_config(cfg: StealthConfig) -> StealthManager {
    StealthManager::new(cfg, Arc::new(OptimizationManager::new()), Arc::new(CryptoManager::new()))
}

fn manager_for_config_with_core_masque(cfg: StealthConfig) -> StealthManager {
    manager_for_config(cfg)
}

#[test]
fn test_mode_feature_matrix_core_expectations() {
    let off = StealthConfig::from_mode(StealthMode::Off);
    let perf = StealthConfig::from_mode(StealthMode::Performance);
    let stealth = StealthConfig::from_mode(StealthMode::Stealth);
    let anti = StealthConfig::from_mode(StealthMode::AntiDpi);
    let intelligent = StealthConfig::from_mode(StealthMode::Intelligent);

    assert!(!off.enable_http3_masquerading);
    assert!(!off.enable_domain_fronting);
    assert!(!off.enable_traffic_padding);

    assert!(perf.enable_http3_masquerading);
    assert!(!perf.enable_domain_fronting);
    assert!(perf.use_tls_cover);
    assert!(!perf.enable_traffic_padding);
    assert!(!perf.enable_timing_obfuscation);

    assert!(stealth.enable_http3_masquerading);
    assert!(!stealth.enable_domain_fronting);
    assert!(stealth.enable_traffic_padding);
    assert!(stealth.enable_timing_obfuscation);
    assert!(stealth.use_tls_cover);

    assert!(anti.enable_http3_masquerading);
    assert!(anti.enable_domain_fronting);
    assert!(anti.enable_traffic_padding);
    assert!(anti.enable_timing_obfuscation);
    assert!(anti.enable_server_push_cover);
    assert!(anti.use_tls_cover);

    assert_eq!(intelligent.mode, StealthMode::Intelligent);
    assert!(intelligent.dynamic_enabled);
    assert!(intelligent.enable_http3_masquerading);
    assert!(!intelligent.enable_domain_fronting);
}

#[test]
fn test_anti_dpi_escalation_stack_is_cumulative_and_reversible() {
    let perf = StealthConfig::performance();
    let stealth = StealthConfig::stealth();
    let anti = StealthConfig::anti_dpi();

    assert!(stealth.enable_http3_masquerading >= perf.enable_http3_masquerading);
    assert!(stealth.use_tls_cover >= perf.use_tls_cover);

    assert!(anti.enable_http3_masquerading >= stealth.enable_http3_masquerading);
    assert!(anti.enable_domain_fronting >= stealth.enable_domain_fronting);
    assert!(anti.enable_traffic_padding >= stealth.enable_traffic_padding);
    assert!(anti.enable_timing_obfuscation >= stealth.enable_timing_obfuscation);
    assert!(anti.enable_server_push_cover);

    let back_to_perf = StealthConfig::from_mode(StealthMode::Performance);
    assert!(!back_to_perf.enable_traffic_padding);
    assert!(!back_to_perf.enable_timing_obfuscation);
    assert!(!back_to_perf.enable_server_push_cover);
}

#[test]
fn test_no_mode_silently_disables_required_primitives() {
    let modes = [
        StealthMode::Performance,
        StealthMode::Stealth,
        StealthMode::AntiDpi,
        StealthMode::Intelligent,
    ];
    for mode in modes {
        let cfg = StealthConfig::from_mode(mode);
        assert!(cfg.use_tls_cover, "mode {:?} must keep TLS Cover primitive enabled", mode);
        assert!(
            cfg.enable_http3_masquerading,
            "mode {:?} must keep HTTP/3 masquerading enabled",
            mode
        );
    }

    assert!(
        !StealthConfig::from_mode(StealthMode::Performance).enable_domain_fronting,
        "Performance mode must stay on the clean H3/QUIC path by default"
    );
    assert!(
        !StealthConfig::from_mode(StealthMode::Stealth).enable_domain_fronting,
        "Stealth mode must not front domains without explicit fronting domains"
    );
    assert!(
        !StealthConfig::from_mode(StealthMode::Intelligent).enable_domain_fronting,
        "Intelligent mode starts from the clean Performance baseline"
    );
    assert!(
        StealthConfig::from_mode(StealthMode::AntiDpi).enable_domain_fronting,
        "Anti-DPI mode is the only preset that enables domain fronting by default"
    );
}

#[test]
fn test_conflicting_stealth_feature_combinations_are_rejected() {
    let mut invalid_push = StealthConfig::stealth();
    invalid_push.enable_http3_masquerading = false;
    invalid_push.enable_server_push_cover = true;
    assert!(invalid_push.validate().is_err());

    let mut invalid_choke = StealthConfig::stealth();
    invalid_choke.enable_realtime_choke = true;
    invalid_choke.choke_target_mbps = 0;
    assert!(invalid_choke.validate().is_err());

    let mut invalid_perf = StealthConfig::performance();
    invalid_perf.enable_timing_obfuscation = true;
    assert!(invalid_perf.validate().is_err());
}

#[test]
fn test_intelligent_runtime_push_requires_nonzero_level_hint() {
    let manager = manager_for_mode(StealthMode::Intelligent);
    manager.enable_server_push_runtime_for_test(true, Some(0.8));
    assert!(manager.server_push_cover_plan_for_test().is_none());
}

#[test]
fn test_intelligent_masque_preference_uses_hint_fallback() {
    let manager =
        manager_for_config_with_core_masque(StealthConfig::from_mode(StealthMode::Intelligent));
    manager.set_masque_preferred(true);
    manager.sync_masque_preference_with_hint_for_test(0);
    assert!(!manager.masque_preferred());

    manager.sync_masque_preference_with_hint_for_test(1);
    assert!(manager.masque_preferred());
}

#[test]
fn test_should_trigger_server_push_mode_matrix() {
    let off = manager_for_mode(StealthMode::Off);
    assert!(off.server_push_cover_plan_for_test().is_none());

    let mut perf_cfg = StealthConfig::performance();
    perf_cfg.server_push_burst_interval = 1;
    let perf = manager_for_config(perf_cfg);
    perf.enable_server_push_runtime_for_test(true, Some(0.5));
    std::thread::sleep(Duration::from_millis(1100));
    assert!(perf.server_push_cover_plan_for_test().is_some());

    let mut stealth_cfg = StealthConfig::stealth();
    stealth_cfg.server_push_burst_interval = 1;
    let stealth = manager_for_config(stealth_cfg);
    stealth.enable_server_push_runtime_for_test(true, Some(0.7));
    std::thread::sleep(Duration::from_millis(1100));
    assert!(stealth.server_push_cover_plan_for_test().is_some());

    let mut anti_cfg = StealthConfig::anti_dpi();
    anti_cfg.server_push_burst_interval = 1;
    let anti = manager_for_config(anti_cfg);
    std::thread::sleep(Duration::from_millis(1100));
    assert!(anti.server_push_cover_plan_for_test().is_some());

    let mut intelligent_cfg = StealthConfig::from_mode(StealthMode::Intelligent);
    intelligent_cfg.server_push_burst_interval = 1;
    let intelligent = manager_for_config(intelligent_cfg);
    intelligent.enable_server_push_runtime_for_test(true, Some(0.8));
    std::thread::sleep(Duration::from_millis(1100));
    assert!(
        intelligent.server_push_cover_plan_for_test().is_none(),
        "intelligent mode should not trigger without brain level hint >= 1"
    );
}
