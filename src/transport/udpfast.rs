//! Compatibility projection for the UDP fastpath workspace owner.
//!
//! The implementation and tests live in `qf-transport-udp`; this module preserves the historical
//! `transport::udpfast` namespace for runtime, harness, and integration callers.

#[cfg(any(test, feature = "rust-tests"))]
pub use qf_transport_udp::aligned_buffer_len_for_rust_tests;
pub use qf_transport_udp::{likely, unlikely, UdpFastPath, MAX_BATCH_SIZE};
