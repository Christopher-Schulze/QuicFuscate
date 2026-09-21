//! Compatibility projection for the standalone `qf-crypto` machine room.
//!
//! The implementation lives in the workspace leaf so transport, TLS, and runtime consumers can
//! depend on one-way crypto contracts. This module preserves the historic `crate::crypto::*`
//! paths while keeping configuration conversion at the caller-owned boundary.

pub use qf_crypto::*;
