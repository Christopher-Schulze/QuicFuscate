//! # Core Forked Connection Runtime
//!
//! This module provides the central `QuicFuscateConnection` struct for the
//! forked QuicFuscate runtime. It orchestrates crypto, FEC, transport, and
//! stealth ownership for the canonical connection lifecycle used by this fork.

mod connection;

pub use connection::*;
