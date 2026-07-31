//! Subsystem initialization and management.

use std::sync::Arc;

use crate::engine::{EngineConfig, EngineError};

use super::{ClientSubsystems, FecCodec};

pub fn init_subsystems(config: &EngineConfig) -> Result<ClientSubsystems, EngineError> {
    let stealth = init_stealth(config)?;
    let fec = Arc::new(std::sync::Mutex::new(FecCodec::new(config.fec.clone())));
    Ok(ClientSubsystems { stealth, fec })
}

fn engine_mode_to_stealth(mode: crate::engine::StealthMode) -> crate::stealth::StealthMode {
    use crate::engine::StealthMode as E;
    use crate::stealth::StealthMode as S;
    match mode {
        E::Off => S::Off,
        E::Performance => S::Performance,
        E::Stealth => S::Stealth,
        E::AntiDpi => S::AntiDpi,
        E::Manual => S::Manual,
        E::Auto => S::Intelligent,
    }
}

fn init_stealth(config: &EngineConfig) -> Result<Arc<crate::stealth::StealthManager>, EngineError> {
    use crate::crypto::CryptoManager;
    use crate::optimize::OptimizationManager;
    use crate::stealth::{StealthConfig, StealthManager};

    let runtime_mode = engine_mode_to_stealth(config.stealth.mode);

    // Start from the correct mode preset so all defaults (padding, timing, rotation,
    // server-push, compress, dynamic_enabled) match the chosen mode.
    let mut stealth_config = StealthConfig::from_mode(runtime_mode);

    // For Manual mode, overlay every individual field from the engine config.
    // For other modes, only apply explicit user overrides (non-empty fronting domains).
    if matches!(config.stealth.mode, crate::engine::StealthMode::Manual) {
        stealth_config.enable_domain_fronting = config.stealth.enable_domain_fronting;
        stealth_config.enable_http3_masquerading = config.stealth.enable_http3_masquerading;
        stealth_config.use_tls_cover = config.stealth.use_tls_cover;
        stealth_config.use_qpack_headers = config.stealth.use_qpack_headers;
        stealth_config.enable_traffic_padding = config.stealth.enable_traffic_padding;
        stealth_config.enable_timing_obfuscation = config.stealth.enable_timing_obfuscation;
        stealth_config.enable_protocol_mimicry = config.stealth.enable_protocol_mimicry;
        stealth_config.enable_doh = config.stealth.enable_doh;
        stealth_config.doh_provider = config.stealth.doh_provider.clone();
        stealth_config.max_padding_size = config.stealth.max_padding_size;
        stealth_config.fronting_domains = config.stealth.fronting_domains.clone();
    }

    if !config.stealth.fronting_domains.is_empty() {
        // Explicit fronting domain override applies to all modes.
        stealth_config.enable_domain_fronting = config.stealth.enable_domain_fronting;
        stealth_config.fronting_domains = config.stealth.fronting_domains.clone();
    }
    if let Ok(browser) = config.stealth.initial_browser.parse() {
        stealth_config.initial_browser = browser;
    }
    if let Ok(os) = config.stealth.initial_os.parse() {
        stealth_config.initial_os = os;
    }
    stealth_config.enable_network_fingerprint_normalization =
        config.stealth.enable_network_fingerprint_normalization;
    stealth_config.suppress_icmp_unreachable = config.stealth.suppress_icmp_unreachable;
    if let Some(strategy) = parse_padding_strategy(&config.stealth.padding_strategy) {
        stealth_config.padding_strategy = strategy;
    }
    stealth_config.normalize_protocol_mimicry_bundle();

    let opt_mgr = Arc::new(OptimizationManager::new());
    let crypto_mgr = Arc::new(CryptoManager::new());
    Ok(Arc::new(StealthManager::new(stealth_config, opt_mgr, crypto_mgr)))
}

fn parse_padding_strategy(value: &str) -> Option<crate::stealth::PaddingStrategy> {
    match value.trim().to_ascii_lowercase().as_str() {
        "random" | "1" => Some(crate::stealth::PaddingStrategy::Random),
        "fixed" | "2" => Some(crate::stealth::PaddingStrategy::Fixed),
        "adaptive" | "3" => Some(crate::stealth::PaddingStrategy::Adaptive),
        "browser" | "browser-mimic" | "browsermimic" | "4" => {
            Some(crate::stealth::PaddingStrategy::BrowserMimic)
        }
        "normalize" | "packet-normalize" | "packetnormalize" | "5" => {
            Some(crate::stealth::PaddingStrategy::PacketNormalize)
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::StealthMode as E;
    use crate::stealth::StealthMode as S;

    #[test]
    fn test_engine_mode_to_stealth_all_variants() {
        assert_eq!(engine_mode_to_stealth(E::Off), S::Off);
        assert_eq!(engine_mode_to_stealth(E::Performance), S::Performance);
        assert_eq!(engine_mode_to_stealth(E::Stealth), S::Stealth);
        assert_eq!(engine_mode_to_stealth(E::AntiDpi), S::AntiDpi);
        assert_eq!(engine_mode_to_stealth(E::Manual), S::Manual);
        assert_eq!(engine_mode_to_stealth(E::Auto), S::Intelligent);
    }

    #[test]
    fn test_init_subsystems_default_config() {
        let config = EngineConfig::default();
        let result = init_subsystems(&config);
        assert!(result.is_ok(), "init_subsystems with default config must succeed");
        let subs = result.unwrap();
        // Verify both subsystems are initialized
        let _stealth_ref = &subs.stealth;
        let _fec_lock = subs.fec.lock().expect("fec mutex not poisoned");
    }

    #[test]
    fn test_init_subsystems_manual_mode() {
        let mut config = EngineConfig::default();
        config.stealth.mode = E::Manual;
        config.stealth.enable_domain_fronting = true;
        config.stealth.enable_traffic_padding = true;
        config.stealth.max_padding_size = 512;
        let result = init_subsystems(&config);
        assert!(result.is_ok(), "init_subsystems with Manual mode must succeed");
    }
}
