use clap::Parser;
use log::{error, info};
use logger::init as init_logger;

use quicfuscate_cli::options::{CommandLineOptions, Fingerprint, FecCliMode};
use quicfuscate_cli::run_cli;

fn print_fingerprints() {
    info!("Verfügbare Browser-Fingerprints:");
    info!("  chrome         - Google Chrome (neueste Version)");
    info!("  firefox        - Mozilla Firefox (neueste Version)");
    info!("  safari         - Apple Safari (neueste Version)");
    info!("  edge           - Microsoft Edge (Chromium-basiert)");
    info!("  brave          - Brave Browser");
    info!("  opera          - Opera Browser");
    info!("  chrome_android - Chrome auf Android");
    info!("  safari_ios     - Safari auf iOS");
    info!("  random         - Zufälliger Fingerprint");
}

fn main() {
    init_logger();
    let opts = CommandLineOptions::parse().merge_config().unwrap_or_else(|e| {
        error!("Failed to load config: {}", e);
        std::process::exit(1);
    });

    if opts.list_fingerprints {
        print_fingerprints();
        return;
    }

    let demo_mode = std::env::args().next().map(|a| a.contains("demo")).unwrap_or(false);

    info!("QuicFuscate VPN - QUIC mit uTLS Integration");
    info!("=========================================");
    let mut msg = format!("Verbinde zu {}:{}", opts.server, opts.port);
    if !opts.no_utls {
        msg.push_str(&format!(" mit Browser-Fingerprint: {:?}", opts.fingerprint));
    } else {
        msg.push_str(" mit Standard-TLS (uTLS deaktiviert)");
    }
    info!("{msg}");

    if opts.verify_peer {
        let mut msg = String::from("Server-Zertifikatsverifikation aktiviert");
        if let Some(ca) = opts.ca_file.as_ref() {
            msg.push_str(&format!(" mit CA-Datei: {}", ca));
        }
        info!("{msg}");
    }

    if opts.verbose {
        info!("[verbose] Verbose logging enabled");
    }
    if opts.debug_tls {
        info!("[debug] TLS debug enabled");
    }

    match run_cli(opts, demo_mode) {
        Ok(data) => {
            if demo_mode {
                info!("Demo roundtrip: {}", String::from_utf8_lossy(&data));
            }
        }
        Err(e) => error!("Error: {}", e),
    }
}
