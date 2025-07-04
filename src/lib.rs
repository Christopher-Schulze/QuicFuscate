// QuicFuscate Core Library
//
// This library contains the core modules for QUIC connection
// management, optimization, cryptography, forward error correction,
// and stealth techniques, consolidated into a single crate.

pub mod core;
pub mod crypto;
pub mod fec;
pub mod optimize;
pub mod stealth;
pub mod xdp_socket;

pub use optimize::{CpuFeature, FeatureDetector};

/// Provides global access to detected CPU features.
pub fn cpu_features() -> &'static FeatureDetector {
    FeatureDetector::instance()
}
