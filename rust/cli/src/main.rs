mod options;
use clap::Parser;
use options::{CommandLineOptions, Fingerprint, FecCliMode};
use fec::FECConfig;
use core as quic_core; // dummy use, kann entfernt werden, falls nicht gebraucht
use stealth::{QuicFuscateStealth, BrowserProfile};
use env_logger::Env;
use log::info;

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
        info!("[verbose] Verbose logging enabled");
    }

    if opts.debug_tls {
        info!("[debug] TLS debug enabled");
    }

    let mut fec_cfg = FECConfig::default();
    fec_cfg.mode = opts.fec.into();
    fec_cfg.redundancy_ratio = (opts.fec_ratio as f64) / 100.0;
    match opts.fec {
        FecCliMode::Off => info!("FEC disabled"),
        FecCliMode::Performance => info!("FEC performance mode"),
        FecCliMode::Always => info!("FEC always-on ratio {}%", opts.fec_ratio),
        FecCliMode::Adaptive => info!("FEC adaptive with target latency {} ms", opts.fec_ratio),
    }

    let mut stealth = QuicFuscateStealth::new();
    stealth.set_browser_profile(BrowserProfile::from(opts.fingerprint));
    stealth.enable_utls(!opts.no_utls);
    stealth.set_spinbit_probability(opts.spin_probability);
    stealth.set_zero_rtt_max_early_data(opts.zero_rtt_max);
    stealth.enable_domain_fronting(opts.domain_fronting);
    stealth.enable_http3_masq(opts.http3_masq);
    stealth.enable_doh(opts.doh);
    stealth.enable_spinbit(opts.spin_random);
    stealth.enable_zero_rtt(opts.zero_rtt);
    if stealth.initialize() {
        info!("Stealth subsystem initialized.");
    } else {
        info!("Failed to initialize stealth subsystem.");
    }
    stealth.shutdown();
}