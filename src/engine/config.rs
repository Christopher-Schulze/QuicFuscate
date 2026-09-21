//! Compatibility projection for the child-owned aggregate engine configuration.

pub use crate::optimize::OptimizeConfig;
pub use qf_engine_types::*;
pub use qf_fec::FecConfig;
pub use qf_stealth::StealthConfig;

impl crate::crypto::DataAeadConfig for CryptoConfig {
    fn data_aead_preference(&self) -> qf_crypto::DataAeadPreference {
        self.aead_preference
    }

    fn force_aead(&self) -> &str {
        &self.force_aead
    }
}

/// Return whether configuration requests the retained private packet-AEAD policy.
///
/// This policy is retained for the authenticated post-handshake private 1-RTT path.
/// Connection construction still begins with standard rustls protection; the Core owner
/// activates the selected family only after the authenticated control gates pass.
pub fn requests_private_packet_protection(config: &CryptoConfig) -> bool {
    config.aead_preference != AeadPreference::Auto
        || !matches!(config.force_aead.trim().to_ascii_lowercase().as_str(), "" | "auto")
}

/// Return whether the selected policy requires a private packet owner at connection startup.
pub fn requires_private_packet_protection(config: &CryptoConfig) -> bool {
    config.packet_protection_mode == qf_crypto::PacketProtectionMode::AdvancedRequired
}

/// `off` and `performance` pin libaegis. `manual` uses it only when selected.
/// `stealth`, `Stealth MAX`, and `dynamic` stay on AES-GCM.
pub fn engine_mode_uses_libaegis(mode: StealthMode, manual_selected_aegis: bool) -> bool {
    match mode {
        StealthMode::Off | StealthMode::Performance => true,
        StealthMode::Manual => manual_selected_aegis,
        StealthMode::Stealth | StealthMode::StealthMax | StealthMode::Dynamic => false,
    }
}

/// Runtime twin of `engine_mode_uses_libaegis` for the qf-stealth mode enum.
pub fn runtime_mode_uses_libaegis(
    mode: qf_stealth::StealthMode,
    manual_selected_aegis: bool,
) -> bool {
    match mode {
        qf_stealth::StealthMode::Off | qf_stealth::StealthMode::Performance => true,
        qf_stealth::StealthMode::Manual => manual_selected_aegis,
        qf_stealth::StealthMode::Stealth
        | qf_stealth::StealthMode::StealthMax
        | qf_stealth::StealthMode::Dynamic => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn private_packet_protection_request_detection_is_explicit() {
        let mut config = CryptoConfig::default();
        assert!(!requests_private_packet_protection(&config));

        config.force_aead = " AUTO ".to_string();
        assert!(!requests_private_packet_protection(&config));

        config.force_aead = "aegis".to_string();
        assert!(requests_private_packet_protection(&config));

        config.force_aead.clear();
        config.aead_preference = AeadPreference::Aegis128L;
        assert!(requests_private_packet_protection(&config));
    }

    #[test]
    fn advanced_required_is_distinguished_from_auto_family_preference() {
        let mut config =
            CryptoConfig { aead_preference: AeadPreference::Aegis128L, ..CryptoConfig::default() };
        assert!(requests_private_packet_protection(&config));
        assert!(!requires_private_packet_protection(&config));
        config.packet_protection_mode = qf_crypto::PacketProtectionMode::AdvancedRequired;
        assert!(requires_private_packet_protection(&config));
    }

    #[test]
    fn payload_cipher_follows_stealth_mode() {
        assert!(engine_mode_uses_libaegis(StealthMode::Off, false));
        assert!(engine_mode_uses_libaegis(StealthMode::Performance, false));
        assert!(!engine_mode_uses_libaegis(StealthMode::Manual, false));
        assert!(engine_mode_uses_libaegis(StealthMode::Manual, true));
        assert!(!engine_mode_uses_libaegis(StealthMode::Stealth, true));
        assert!(!engine_mode_uses_libaegis(StealthMode::StealthMax, true));
        assert!(!engine_mode_uses_libaegis(StealthMode::Dynamic, true));
        assert!(runtime_mode_uses_libaegis(qf_stealth::StealthMode::Off, false));
        assert!(runtime_mode_uses_libaegis(qf_stealth::StealthMode::Performance, false));
        assert!(!runtime_mode_uses_libaegis(qf_stealth::StealthMode::Manual, false));
        assert!(runtime_mode_uses_libaegis(qf_stealth::StealthMode::Manual, true));
        assert!(!runtime_mode_uses_libaegis(qf_stealth::StealthMode::Dynamic, true));
    }
}
