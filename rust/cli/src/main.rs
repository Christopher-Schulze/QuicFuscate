mod options;
use clap::Parser;
use options::{CommandLineOptions, Fingerprint, FecCliMode};
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

    match opts.fec {
        FecCliMode::Off => println!("FEC disabled"),
        FecCliMode::Performance => println!("FEC performance mode"),
        FecCliMode::Always => println!("FEC always-on ratio {}%", opts.fec_ratio),
        FecCliMode::Adaptive => println!("FEC adaptive with target latency {} ms", opts.fec_ratio),
    }

    let mut stealth = QuicFuscateStealth::new();
    stealth.enable_domain_fronting(opts.domain_fronting);
    stealth.enable_http3_masq(opts.http3_masq);
    stealth.enable_doh(opts.doh);
    stealth.enable_spinbit(opts.spin_random);
    stealth.enable_zero_rtt(opts.zero_rtt);
    if stealth.initialize() {
        println!("Stealth subsystem initialized.");
    } else {
        println!("Failed to initialize stealth subsystem.");
    }
    stealth.shutdown();
}
