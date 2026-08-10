//! Compatibility projection for the standalone `qf-crypto` machine room.
//!
//! The implementation lives in the workspace leaf so transport, TLS, and runtime consumers can
//! depend on one-way crypto contracts. This module preserves the historic `crate::crypto::*`
//! paths while keeping configuration conversion at the caller-owned boundary.

pub use qf_crypto::*;

/// Provides the engine-owned values required by the data-plane AEAD selector.
pub trait DataAeadConfig {
    /// Returns the selected AEAD family.
    fn data_aead_preference(&self) -> qf_crypto::DataAeadPreference;
    /// Returns an optional forced AEAD name.
    fn force_aead(&self) -> &str;
}

/// Install the data-plane AEAD selection from any compatible configuration shape.
pub fn install_data_aead_config<C: DataAeadConfig>(cfg: &C) {
    qf_crypto::install_data_aead_selection(cfg.data_aead_preference(), cfg.force_aead());
}
