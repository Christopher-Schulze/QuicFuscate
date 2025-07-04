use clap::Parser;
use env_logger::Env;
use log::info;

use quicfuscate_cli::options::{CommandLineOptions, Fingerprint, FecCliMode};
use quicfuscate_cli::run_cli;

fn print_fingerprints() {
    println!("Verfügbare Browser-Fingerprints:");
    println!("  chrome         - Google Chrome (neueste Version)");
    println!("  firefox        - Mozilla Firefox (neueste Version)");
    println!("  safari         - Apple Safari (neueste Version)");
    println!("  edge           - Microsoft Edge (Chromium-basiert)");
    println!("  brave          - Brave Browser");
    println!("  opera          - Opera Browser");
    println!("  chrome_android - Chrome auf Android");
    println!("  safari_ios     - Safari auf iOS");
    println!("  random         - Zufälliger Fingerprint");
}

fn main() {
    env_logger::Builder::from_env(Env::default().default_filter_or("info")).init();
    let opts = CommandLineOptions::parse();

    if opts.list_fingerprints {
        print_fingerprints();
        return;
    }

    let demo_mode = std::env::args().next().map(|a| a.contains("demo")).unwrap_or(false);

    println!("QuicFuscate VPN - QUIC mit uTLS Integration");
    println!("=========================================");
    print!("Verbinde zu {}:{}", opts.server, opts.port);
    if !opts.no_utls {
        println!(" mit Browser-Fingerprint: {:?}", opts.fingerprint);
    } else {
        println!(" mit Standard-TLS (uTLS deaktiviert)");
    }

    if opts.verify_peer {
        print!("Server-Zertifikatsverifikation aktiviert");
        if let Some(ca) = opts.ca_file.as_ref() {
            print!(" mit CA-Datei: {}", ca);
        }
        println!();
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
                println!("Demo roundtrip: {}", String::from_utf8_lossy(&data));
            }
        }
        Err(e) => eprintln!("Error: {}", e),
    }
}
