//! Subsystem initialization and management.

use std::sync::Arc;

use crate::engine::{EngineConfig, EngineError};
use crate::stealth::StealthRuntimeOwner;

use super::{ClientSubsystems, FecCodec};

pub fn init_subsystems_with_runtime(
    config: &EngineConfig,
    runtime_owner: Option<Arc<StealthRuntimeOwner>>,
) -> Result<ClientSubsystems, EngineError> {
    config
        .validate()
        .map_err(|error| EngineError::Config(format!("Invalid engine configuration: {error}")))?;
    let stealth = init_stealth(config, runtime_owner)?;
    let fec_config = config
        .fec
        .to_runtime_config()
        .map_err(|error| EngineError::Config(format!("FEC config error: {error}")))?;
    let fec = Arc::new(std::sync::Mutex::new(FecCodec::new(fec_config)));
    Ok(ClientSubsystems { stealth, fec })
}

fn init_stealth(
    config: &EngineConfig,
    runtime_owner: Option<Arc<StealthRuntimeOwner>>,
) -> Result<Arc<crate::stealth::StealthManager>, EngineError> {
    use crate::crypto::CryptoManager;
    use crate::optimize::OptimizationManager;
    use crate::stealth::StealthManager;

    let stealth_config = config
        .stealth
        .to_runtime_config(&config.fingerprint_rotation)
        .map_err(|error| EngineError::Config(format!("Stealth config error: {error}")))?;
    let optimize_config = config
        .optimization
        .to_runtime_config()
        .map_err(|error| EngineError::Config(format!("Optimization config error: {error}")))?;
    let opt_mgr = Arc::new(OptimizationManager::from_cfg(optimize_config));
    let crypto_mgr = Arc::new(CryptoManager::new());
    Ok(Arc::new(StealthManager::new_with_runtime_owner(
        stealth_config,
        opt_mgr,
        crypto_mgr,
        runtime_owner,
    )))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_engine_stealth_projection_is_canonical() {
        let config = EngineConfig::default();
        let runtime = config
            .stealth
            .to_runtime_config(&config.fingerprint_rotation)
            .expect("default stealth projection");
        assert_eq!(runtime.mode, crate::stealth::StealthMode::Intelligent);
        assert_eq!(runtime.initial_browser, crate::stealth::BrowserProfile::Chrome);
        assert_eq!(runtime.initial_os, crate::stealth::OsProfile::Windows);
    }

    #[test]
    fn test_init_subsystems_default_config() {
        let config = EngineConfig::default();
        let result = init_subsystems_with_runtime(&config, None);
        assert!(result.is_ok(), "init_subsystems with default config must succeed");
        let subs = result.unwrap();
        // Verify both subsystems are initialized
        let _stealth_ref = &subs.stealth;
        let _fec_lock = subs.fec.lock().expect("fec mutex not poisoned");
    }

    #[test]
    fn test_init_subsystems_manual_mode() {
        let mut config = EngineConfig::default();
        config.stealth.mode = crate::engine::StealthMode::Manual;
        config.stealth.enable_domain_fronting = true;
        config.stealth.enable_traffic_padding = true;
        config.stealth.max_padding_size = 512;
        let result = init_subsystems_with_runtime(&config, None);
        assert!(result.is_ok(), "init_subsystems with Manual mode must succeed");
    }
}
