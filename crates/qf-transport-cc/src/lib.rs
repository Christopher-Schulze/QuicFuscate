//! Congestion-control algorithms and stealth pacing for QuicFuscate transport.
//!
//! The crate owns the Reno, CUBIC, BBR2, BBR3, and browser-profile shaping
//! implementations. The root package keeps a compatibility projection for
//! the existing `quicfuscate::transport::cc` path.

pub mod cc;

mod stats;

#[doc(hidden)]
pub use stats::ConnectionStats;
