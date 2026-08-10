use super::{AntiReplaySection, EngineConfig};
use crate::fec::FecConfig;
use crate::optimize::OptimizeConfig;
use crate::stealth::StealthConfig;

/// Runtime projection for FEC, stealth, optimization, and anti-replay.
///
/// `EngineConfig::validate` must succeed before this reduced projection is
/// constructed. Transport policies and startup-owned engine sections remain
/// in the source `EngineConfig` and are consumed by their dedicated adapters.
#[derive(Clone)]
pub struct AppConfig {
    /// Forward error correction settings.
    pub fec: FecConfig,
    /// Stealth and obfuscation settings.
    pub stealth: StealthConfig,
    /// Memory pool and optimization settings.
    pub optimize: OptimizeConfig,
    /// 0-RTT anti-replay protection settings.
    pub anti_replay: AntiReplaySection,
}

impl AppConfig {
    fn from_engine_toml(source: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let parsed = EngineConfig::from_toml(source)?;
        parsed.validate()?;
        let fec = parsed.fec.to_runtime_config()?;
        let stealth = parsed.stealth.to_runtime_config(&parsed.fingerprint_rotation)?;
        let optimize = parsed.optimization.to_runtime_config()?;

        Ok(Self { fec, stealth, optimize, anti_replay: parsed.anti_replay })
    }

    /// Load configuration from a TOML string.
    pub fn from_toml(source: &str) -> Result<Self, Box<dyn std::error::Error>> {
        Self::from_engine_toml(source)
    }

    /// Load configuration from a file path.
    pub fn from_file(path: &std::path::Path) -> Result<Self, Box<dyn std::error::Error>> {
        let contents = std::fs::read_to_string(path)?;
        Self::from_toml(&contents)
    }

    /// Validate all sub-configurations.
    pub fn validate(&self) -> Result<(), String> {
        self.fec.validate()?;
        self.stealth.validate()?;
        self.optimize.validate()?;
        self.anti_replay.validate().map_err(|error| error.to_string())?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn app_config_rejects_unknown_engine_keys_before_projection() {
        let error = match AppConfig::from_toml(
            r#"
[connection]
remote = "127.0.0.1:4433"

[stealth]
unknown_setting = true
"#,
        ) {
            Ok(_) => panic!("unknown engine settings must not be silently dropped"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("unknown_setting"));
    }

    #[test]
    fn app_config_preserves_typed_engine_projection() {
        let config = AppConfig::from_toml(
            r#"
[connection]
remote = "127.0.0.1:4433"

[stealth]
initial_browser = "firefox"
initial_os = "linux"
padding_strategy = "browser-mimic"

[optimization]
memory_pool_size = 1048576
memory_pool_alignment = 4096
"#,
        )
        .expect("valid engine projection");
        assert_eq!(config.stealth.initial_browser, crate::stealth::BrowserProfile::Firefox);
        assert_eq!(config.stealth.initial_os, crate::stealth::OsProfile::Linux);
        assert_eq!(config.stealth.padding_strategy, crate::stealth::PaddingStrategy::BrowserMimic);
        assert_eq!(config.optimize.block_size, 65_536);
        assert_eq!(config.optimize.pool_capacity, 16);
    }
}
