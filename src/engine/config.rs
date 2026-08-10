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
