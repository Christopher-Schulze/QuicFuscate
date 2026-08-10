//! QuicFuscate Engine Module
//!
//! This module provides the unified `QuicFuscateEngine` API for embedding
//! QuicFuscate in applications. It is designed to be the single entry point
//! for controlling all VPN functionality.
//!
//! # Features
//!
//! - Complete configuration via TOML file or programmatic builder
//! - Lifecycle management (start/stop/connect/disconnect)
//! - Runtime control (stealth mode, FEC mode, config updates)
//! - Event callbacks for status, errors, and stats
//!
//! # Example
//!
//! ```ignore
//! use quicfuscate::engine::{QuicFuscateEngine, EngineConfig};
//!
//! // Load from config file
//! let config = EngineConfig::from_file("config/quicfuscate.toml")?;
//! let mut engine = QuicFuscateEngine::new(config)?;
//!
//! // Or use builder
//! let config = EngineConfig::builder()
//!     .mode(EngineMode::Client)
//!     .remote("vpn.example.com:4433")
//!     .stealth_mode(StealthMode::Auto)
//!     .build()?;
//!
//! engine.start()?;
//! engine.connect()?;
//! ```

pub mod app_config;
mod config;
#[allow(clippy::module_inception)]
mod engine;
pub mod qkey;

pub use config::*;
pub use engine::*;
