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
    /// Disabled - no stealth features.
    #[serde(alias = "off", alias = "Off")]
    Off,
    /// Performance - stealth baseline with all costly features off.
    #[serde(alias = "Performance", alias = "performance", alias = "Base", alias = "base")]
    Performance,
    /// Stealth - balanced features with minimal overhead.
    #[serde(alias = "stealth", alias = "Stealth")]
    Stealth,
    /// Anti-DPI - aggressive stealth with higher overhead.
    #[serde(
        alias = "StealthMax",
        alias = "stealthmax",
        alias = "stealth-max",
        alias = "Anti-DPI",
        alias = "AntiDPI",
        alias = "anti-dpi",
        alias = "antidpi",
        alias = "max",
        alias = "Max"
    )]
    AntiDpi,
    /// Manual - user controlled.
    #[serde(alias = "manual", alias = "Manual")]
    Manual,
    /// Intelligent - starts at a baseline and escalates based on signals.
    #[serde(
        alias = "Dynamic",
        alias = "dynamic",
        alias = "auto",
        alias = "Auto",
        alias = "intelligent"
    )]
    Intelligent,
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
    fn stealth_mode_aliases_preserve_legacy_wire_values() {
        assert_eq!(
            serde_json::from_str::<StealthMode>("\"Anti-DPI\"").unwrap(),
            StealthMode::AntiDpi
        );
        assert_eq!(
            serde_json::from_str::<StealthMode>("\"Dynamic\"").unwrap(),
            StealthMode::Intelligent
        );
    }

    #[test]
    fn rotation_modes_are_distinct() {
        assert_ne!(RotationMode::Fixed, RotationMode::Slots);
        assert_ne!(RotationMode::Slots, RotationMode::All);
    }
}
