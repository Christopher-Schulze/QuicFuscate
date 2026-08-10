//! Compatibility projection for the standalone SIMD workspace crate.
//!
//! The dispatch implementation and architecture-specific tests live in `qf-simd`; this module
//! preserves the historical `quicfuscate::simd` namespace for the root product and downstream
//! callers.

pub use qf_simd::*;

#[cfg(target_arch = "aarch64")]
#[doc(hidden)]
pub use qf_simd::arm_stream;
#[cfg(target_arch = "x86_64")]
#[doc(hidden)]
pub use qf_simd::x86_ack;
