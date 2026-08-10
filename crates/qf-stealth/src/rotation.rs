//! Root-independent fingerprint rotation configuration.

use crate::{parse_profile_slot, OsProfile, RotationMode};

/// Fingerprint rotation policy embedded in the engine configuration.
#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct FingerprintRotationConfig {
    /// Enable rotation.
    pub enabled: bool,
    /// Rotation interval in seconds.
    pub interval_secs: u64,
    /// Rotation mode.
    pub mode: RotationMode,
    /// Browser/OS profile slots.
    pub profile_slots: Vec<String>,
}

impl Default for FingerprintRotationConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            interval_secs: 300,
            mode: RotationMode::Fixed,
            profile_slots: vec![
                "chrome@windows".to_string(),
                "firefox@windows".to_string(),
                "safari@macos".to_string(),
            ],
        }
    }
}

impl FingerprintRotationConfig {
    /// Validate the serialized rotation policy without importing the engine runtime.
    pub fn validate(&self) -> Result<(), String> {
        if self.enabled && self.interval_secs == 0 {
            return Err("fingerprint_rotation.interval_secs must be > 0 when rotation is enabled"
                .to_string());
        }
        if self.profile_slots.len() > 64 {
            return Err(
                "fingerprint_rotation.profile_slots must contain at most 64 entries".to_string()
            );
        }
        if self.enabled && self.mode == RotationMode::Slots && self.profile_slots.is_empty() {
            return Err(
                "fingerprint_rotation.profile_slots must not be empty in slots mode".to_string()
            );
        }
        for slot in &self.profile_slots {
            parse_profile_slot(slot, OsProfile::Windows).map_err(|error| {
                format!("fingerprint_rotation.profile_slots entry '{slot}': {error}")
            })?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::FingerprintRotationConfig;
    use crate::RotationMode;

    #[test]
    fn defaults_preserve_engine_rotation_contract() {
        let config = FingerprintRotationConfig::default();
        assert!(!config.enabled);
        assert_eq!(config.interval_secs, 300);
        assert_eq!(config.mode, RotationMode::Fixed);
        assert_eq!(config.profile_slots, ["chrome@windows", "firefox@windows", "safari@macos"]);
        assert!(config.validate().is_ok());
    }

    #[test]
    fn validation_rejects_invalid_enabled_policy() {
        let mut config =
            FingerprintRotationConfig { enabled: true, interval_secs: 0, ..Default::default() };
        assert_eq!(
            config.validate().expect_err("zero enabled interval must fail"),
            "fingerprint_rotation.interval_secs must be > 0 when rotation is enabled"
        );

        config.interval_secs = 1;
        config.mode = RotationMode::Slots;
        config.profile_slots.clear();
        assert_eq!(
            config.validate().expect_err("enabled slots mode needs a slot"),
            "fingerprint_rotation.profile_slots must not be empty in slots mode"
        );
    }

    #[test]
    fn validation_rejects_bad_profile_slot() {
        let config = FingerprintRotationConfig {
            profile_slots: vec!["chrome:windows".to_string()],
            ..Default::default()
        };
        assert_eq!(
            config.validate().expect_err("legacy separator must fail"),
            "fingerprint_rotation.profile_slots entry 'chrome:windows': profile slot 'chrome:windows' uses ':', expected browser[@os]"
        );
    }
}
