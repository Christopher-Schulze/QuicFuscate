//! Shared leaf contracts for QuicFuscate workspace crates.
//!
//! This crate intentionally contains no product/runtime subsystem. It owns
//! only environment snapshots, protocol time, secure randomness, and
//! zeroizing secret wrappers.

pub mod env_utils;
pub mod rng;
pub mod secret;
pub mod time_source;
