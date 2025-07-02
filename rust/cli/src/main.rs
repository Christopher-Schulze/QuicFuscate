mod options;
use clap::Parser;
use options::{CommandLineOptions, Fingerprint};
use core as quic_core; // dummy use, kann entfernt werden, falls nicht gebraucht
use stealth::QuicFuscateStealth;

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
    let opts = CommandLineOptions::parse();

    println!("QuicFuscate CLI gestartet. Optionen: --server/--host, --port, etc.");

    if opts.list_fingerprints {
        print_fingerprints();
        return;
    }

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
        println!("[verbose] Verbose logging enabled");
    }

    if opts.debug_tls {
        println!("[debug] TLS debug enabled");
    }

    let stealth = QuicFuscateStealth::new();
    if stealth.initialize() {
        println!("Stealth subsystem initialized.");
    } else {
        println!("Failed to initialize stealth subsystem.");
    }
    stealth.shutdown();
}
