//! Root-independent stealth configuration value contracts.

/// Padding strategies for traffic obfuscation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub enum PaddingStrategy {
    /// Random padding between 0 and max_padding_size.
    Random,
    /// Fixed padding to nearest power of 2.
    Fixed,
    /// Adaptive padding based on traffic patterns.
    Adaptive,
    /// Mimic browser-specific padding patterns.
    BrowserMimic,
    /// Normalize all outgoing 1-RTT packets to a fixed size.
    PacketNormalize,
}

/// High-level stealth operating modes controlling which obfuscation features are active.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub enum StealthMode {
    /// No stealth features.
    #[serde(rename = "off")]
    Off,
    /// Cheap browser baseline. Costly stealth features stay off.
    #[serde(rename = "performance")]
    Performance,
    /// Balanced stealth.
    #[serde(rename = "stealth")]
    Stealth,
    /// Aggressive stealth.
    #[serde(rename = "Stealth MAX")]
    StealthMax,
    /// Operator-selected stealth flags.
    #[serde(rename = "manual")]
    Manual,
    /// Starts like performance and escalates.
    #[serde(rename = "dynamic")]
    Dynamic,
}

impl StealthMode {
    /// The one config name for this mode.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Off => "off",
            Self::Performance => "performance",
            Self::Stealth => "stealth",
            Self::StealthMax => "Stealth MAX",
            Self::Manual => "manual",
            Self::Dynamic => "dynamic",
        }
    }
}

/// Controls how fingerprint profiles are cycled during rotation.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum RotationMode {
    /// Single profile - no rotation.
    #[default]
    Fixed,
    /// Rotate through configured slots.
    Slots,
    /// Rotate through all available profiles.
    All,
}

#[cfg(test)]
mod tests {
    use super::{PaddingStrategy, RotationMode, StealthMode};

    #[test]
    fn padding_strategy_serialization_is_stable() {
        let encoded = serde_json::to_string(&PaddingStrategy::PacketNormalize).expect("serialize");
        assert_eq!(encoded, "\"PacketNormalize\"");
        let decoded: PaddingStrategy = serde_json::from_str(&encoded).expect("deserialize");
        assert_eq!(decoded, PaddingStrategy::PacketNormalize);
    }

    #[test]
    fn stealth_mode_has_one_name() {
        assert_eq!(
            serde_json::from_str::<StealthMode>("\"Stealth MAX\"").unwrap(),
            StealthMode::StealthMax
        );
        assert_eq!(
            serde_json::from_str::<StealthMode>("\"dynamic\"").unwrap(),
            StealthMode::Dynamic
        );
        assert_eq!(serde_json::to_string(&StealthMode::Performance).unwrap(), "\"performance\"");
        assert!(serde_json::from_str::<StealthMode>("\"anti-dpi\"").is_err());
        assert!(serde_json::from_str::<StealthMode>("\"auto\"").is_err());
        assert!(serde_json::from_str::<StealthMode>("\"base\"").is_err());
        assert!(serde_json::from_str::<StealthMode>("\"max\"").is_err());
    }

    #[test]
    fn rotation_modes_are_distinct() {
        assert_ne!(RotationMode::Fixed, RotationMode::Slots);
        assert_ne!(RotationMode::Slots, RotationMode::All);
    }
}
