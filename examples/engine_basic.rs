//! QuicFuscate Engine Basic Usage Example
//!
//! This example demonstrates the basic usage of the QuicFuscateEngine API
//! for embedding QuicFuscate in applications.

use quicfuscate::engine::{
    DisconnectReason, EngineCallback, EngineConfig, EngineError, EngineState, QuicFuscateEngine,
    StatsSnapshot, StealthMode,
};
use std::net::SocketAddr;

/// Example callback implementation that logs engine events.
struct LoggingCallback;

impl EngineCallback for LoggingCallback {
    fn on_state_change(&self, old: EngineState, new: EngineState) {
        println!("[Callback] State changed: {} -> {}", old, new);
    }

    fn on_connected(&self, remote: SocketAddr) {
        println!("[Callback] Connected to: {}", remote);
    }

    fn on_disconnected(&self, reason: DisconnectReason) {
        println!("[Callback] Disconnected: {:?}", reason);
    }

    fn on_error(&self, error: &EngineError) {
        eprintln!("[Callback] Error: {}", error);
    }

    fn on_stats_update(&self, stats: &StatsSnapshot) {
        println!(
            "[Callback] Stats: {} bytes sent, {} bytes received, RTT: {}ms",
            stats.bytes_sent, stats.bytes_received, stats.rtt_ms
        );
    }

    fn on_stealth_escalation(&self, from: u8, to: u8) {
        println!("[Callback] Stealth escalated: {} -> {}", from, to);
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== QuicFuscate Engine Example ===\n");

    // ========================================================================
    // Method 1: Load configuration from file
    // ========================================================================
    println!("1. Loading configuration from file...");

    // Try to load from config file (will use defaults if file doesn't exist)
    let _config = match EngineConfig::from_file("config/quicfuscate.toml") {
        Ok(cfg) => {
            println!("   Loaded config from file");
            cfg
        }
        Err(e) => {
            println!("   Config file not found ({}), using defaults", e);
            EngineConfig::default()
        }
    };

    // ========================================================================
    // Method 2: Build configuration programmatically
    // ========================================================================
    println!("\n2. Building configuration programmatically...");

    let config = EngineConfig::builder()
        .mode(quicfuscate::engine::EngineMode::Client)
        .remote("127.0.0.1:4433")
        .verify_peer(false) // Disable for local testing
        .stealth_mode(StealthMode::Auto)
        .aead_preference(quicfuscate::engine::AeadPreference::Auto)
        .cc_algorithm(quicfuscate::engine::CcAlgorithm::Bbr3)
        .build()?;

    println!("   Mode: {:?}", config.engine.mode);
    println!("   Remote: {}", config.connection.remote);
    println!("   Stealth: {:?}", config.stealth.mode);

    // ========================================================================
    // Create and configure the engine
    // ========================================================================
    println!("\n3. Creating engine...");

    let mut engine = QuicFuscateEngine::new(config)?;
    println!("   Engine created, state: {}", engine.state());

    // Add callback for event notifications
    engine.add_callback(LoggingCallback);

    // ========================================================================
    // Start the engine
    // ========================================================================
    println!("\n4. Starting engine...");
    engine.start()?;
    println!("   Engine started, state: {}", engine.state());

    // ========================================================================
    // Runtime control examples
    // ========================================================================
    println!("\n5. Runtime control examples...");

    // Change stealth mode
    println!("   Setting stealth mode to AntiDpi...");
    engine.set_stealth_mode(StealthMode::AntiDpi)?;
    println!("   Stealth mode: {:?}", engine.stealth_mode());

    // Enable traffic padding
    println!("   Enabling traffic padding...");
    engine.set_traffic_padding(true)?;

    // Update multiple settings at once
    println!("   Batch updating config...");
    engine.update_config(|cfg| {
        cfg.stealth.enable_timing_obfuscation = true;
        cfg.transport.mtu = 1350;
    })?;

    // Get current stats
    let stats = engine.stats();
    println!("   Current stats: {} packets sent", stats.packets_sent);

    // ========================================================================
    // Connect (would fail without actual server, but demonstrates API)
    // ========================================================================
    println!("\n6. Connection lifecycle...");

    // Note: This would actually connect to the server
    // For demo purposes, we'll show the API without actual connection
    if engine.is_running() {
        println!("   Engine is running, ready for connections");

        // Demonstrate connect/disconnect cycle
        match engine.connect() {
            Ok(()) => {
                println!("   Connected! State: {}", engine.state());

                // Simulate some work
                std::thread::sleep(std::time::Duration::from_millis(100));

                // Disconnect
                engine.disconnect()?;
                println!("   Disconnected, state: {}", engine.state());
            }
            Err(e) => {
                println!("   Connection would fail in demo: {}", e);
            }
        }
    }

    // ========================================================================
    // Stop the engine
    // ========================================================================
    println!("\n7. Stopping engine...");
    engine.stop()?;
    println!("   Engine stopped, state: {}", engine.state());

    println!("\n=== Example Complete ===");
    Ok(())
}
