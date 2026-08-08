//! QuicFuscate Engine Basic Usage Example
//!
//! This example demonstrates the basic usage of the QuicFuscateEngine API
//! for embedding QuicFuscate in applications.
//!
//! It is offline by default: it configures, starts, and stops the engine without
//! opening a network connection, so it runs deterministically with no server. Peer
//! verification stays on, because an example is copied, and a copied
//! `.verify_peer(false)` silently removes TLS peer authentication from whatever it
//! lands in.
//!
//! Two opt-ins exist, both explicit and both announced at runtime:
//!
//! ```text
//! cargo run --example engine_basic -- --connect            # attempt a real connection
//! cargo run --example engine_basic -- --insecure-no-verify # disable peer verification
//! ```

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

/// What the caller explicitly asked this example to do.
///
/// Both default to off. Nothing here is inferred, because the whole point of the
/// defaults is that copying this file cannot weaken a deployment or make an
/// unannounced network attempt.
struct ExampleOptions {
    connect: bool,
    insecure_no_verify: bool,
}

fn parse_options() -> Result<ExampleOptions, String> {
    let mut options = ExampleOptions { connect: false, insecure_no_verify: false };
    for argument in std::env::args().skip(1) {
        match argument.as_str() {
            "--connect" => options.connect = true,
            "--insecure-no-verify" => options.insecure_no_verify = true,
            "--help" | "-h" => {
                println!(
                    "Usage: engine_basic [--connect] [--insecure-no-verify]\n\n\
                     --connect              attempt a real connection to the configured remote\n\
                     --insecure-no-verify   disable TLS peer verification (never for production)"
                );
                std::process::exit(0);
            }
            other => return Err(format!("unknown option {other:?}; try --help")),
        }
    }
    Ok(options)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let options = parse_options()?;
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

    if options.insecure_no_verify {
        eprintln!(
            "   WARNING: --insecure-no-verify disables TLS peer verification. This accepts any \
             certificate and must never be used outside a throwaway local test."
        );
    }
    let config = EngineConfig::builder()
        .mode(quicfuscate::engine::EngineMode::Client)
        .remote("127.0.0.1:4433")
        // Verification stays on by default. To connect to a server with a private CA,
        // point the client at that CA rather than turning this off.
        .verify_peer(!options.insecure_no_verify)
        .stealth_mode(StealthMode::Auto)
        .aead_preference(quicfuscate::engine::AeadPreference::Auto)
        .cc_algorithm(quicfuscate::engine::CcAlgorithm::Bbr3)
        .build()?;

    println!("   Mode: {:?}", config.engine.mode);
    println!("   Remote: {}", config.connection.remote);
    println!("   Stealth: {:?}", config.stealth.mode);
    println!("   Verify peer: {}", config.connection.verify_peer);

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
    // Connection lifecycle (opt-in; nothing here touches the network by default)
    // ========================================================================
    println!("\n6. Connection lifecycle...");

    if !options.connect {
        // The comment here used to say no connection was made while the code called
        // connect() anyway, so running the example made an unannounced network attempt
        // that could be mistaken for a connectivity smoke test.
        println!("   Skipping connection: pass --connect to attempt one.");
        println!("   Engine is running and ready: {}", engine.is_running());
    } else if !engine.is_running() {
        println!("   Engine is not running; nothing to connect.");
    } else {
        println!("   Connecting to {} ...", engine.config().connection.remote);
        match engine.connect() {
            Ok(()) => {
                println!("   Connected! State: {}", engine.state());
                std::thread::sleep(std::time::Duration::from_millis(100));
                engine.disconnect()?;
                println!("   Disconnected, state: {}", engine.state());
            }
            Err(error) => {
                // An explicitly requested connection that fails is a real failure, not a
                // demo outcome to print and move past.
                engine.stop()?;
                return Err(format!("--connect was requested but failed: {error}").into());
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
