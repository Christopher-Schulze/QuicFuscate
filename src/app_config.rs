use crate::fec::FecConfig;
use crate::optimize::OptimizeConfig;
use crate::stealth::StealthConfig;
use serde::Deserialize;
use std::path::Path;

/// Unified configuration structure parsed from a TOML file.
#[derive(Clone)]
pub struct AppConfig {
    pub fec: FecConfig,
    pub stealth: StealthConfig,
    pub optimize: OptimizeConfig,
}

impl AppConfig {
    /// Load configuration from a TOML string.
    pub fn from_toml(s: &str) -> Result<Self, Box<dyn std::error::Error>> {
        Ok(Self {
            fec: FecConfig::from_toml(s).unwrap_or_default(),
            stealth: StealthConfig::from_toml(s).unwrap_or_default(),
            optimize: OptimizeConfig::from_toml(s).unwrap_or_default(),
        })
    }

    /// Load configuration from a file path.
    pub fn from_file(path: &Path) -> Result<Self, Box<dyn std::error::Error>> {
        let contents = std::fs::read_to_string(path)?;
        Self::from_toml(&contents)
    }

    /// Validate all sub-configurations.
    pub fn validate(&self) -> Result<(), String> {
        self.fec.validate()?;
        self.stealth.validate()?;
        self.optimize.validate()?;
        Ok(())
    }
}
