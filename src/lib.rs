// QuicFuscate Core Library
//
// This library contains the core modules for QUIC connection
// management, optimization, cryptography, forward error correction,
// and stealth techniques, consolidated into a single crate.

// Core and stealth modules require full quiche bindings which are stubbed out
// for the test environment. They are omitted from builds without the
// `full` feature to simplify testing.
#[cfg(feature = "full")]
pub mod core;
pub mod crypto;
pub mod fec;
pub mod optimize;
#[cfg(feature = "full")]
pub mod stealth;