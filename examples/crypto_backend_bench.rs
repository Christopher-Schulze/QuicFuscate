use std::env;
use std::time::Instant;

use quicfuscate::crypto::{build_data_aead_for_benches, BenchDataAeadBackend};
use quicfuscate::telemetry;

fn parse_usize(s: &str) -> usize {
    if let Some(stripped) = s.strip_suffix("KiB") {
        return stripped.parse::<usize>().unwrap() * 1024;
    }
    if let Some(stripped) = s.strip_suffix("MiB") {
        return stripped.parse::<usize>().unwrap() * 1024 * 1024;
    }
    if let Some(stripped) = s.strip_suffix("B") {
        return stripped.parse::<usize>().unwrap();
    }
    s.parse::<usize>().unwrap()
}

fn format_mbps(bytes: usize, ns: u128) -> f64 {
    if ns == 0 {
        return 0.0;
    }
    let seconds = (ns as f64) / 1_000_000_000.0;
    (bytes as f64) / seconds / 1_000_000.0
}

fn backend_from_str(value: &str) -> BenchDataAeadBackend {
    match value {
        "aegis128l" | "aegis-l" | "l" => BenchDataAeadBackend::Aegis128L,
        "aegis128x4" | "aegis-x4" | "x4" => BenchDataAeadBackend::Aegis128X4,
        "aegis128x8" | "aegis-x8" | "x8" => BenchDataAeadBackend::Aegis128X8,
        "morus" | "morus1280_128" | "morus1280-128" => BenchDataAeadBackend::Morus,
        other => panic!("unknown backend: {}", other),
    }
}

fn backend_counter_value(backend: BenchDataAeadBackend) -> u64 {
    match backend {
        BenchDataAeadBackend::Aegis128L => telemetry::DATA_AEAD_BACKEND_AEGIS_L_TOTAL.get(),
        BenchDataAeadBackend::Aegis128X4 => telemetry::DATA_AEAD_BACKEND_AEGIS_X4_TOTAL.get(),
        BenchDataAeadBackend::Aegis128X8 => telemetry::DATA_AEAD_BACKEND_AEGIS_X8_TOTAL.get(),
        BenchDataAeadBackend::Morus => telemetry::DATA_AEAD_BACKEND_MORUS_TOTAL.get(),
    }
}

fn bench_backend(backend: BenchDataAeadBackend, total_bytes: usize, iters: usize) {
    let key = [0x5Au8; 16];
    let iv = [0xA5u8; 12];
    let ad = b"crypto-backend-bench";
    let mut sink = 0u8;

    let counter_before = backend_counter_value(backend);
    let (seal, open) = build_data_aead_for_benches(backend, &key, &iv)
        .expect("validated benchmark key and IV lengths");
    let counter_after = backend_counter_value(backend);

    let mut plaintext = vec![0u8; total_bytes.max(1)];
    for (i, byte) in plaintext.iter_mut().enumerate() {
        *byte = (i as u8).wrapping_mul(17).wrapping_add(3);
    }
    let mut buffer = vec![0u8; plaintext.len() + 16];

    let start = Instant::now();
    for i in 0..iters {
        buffer[..plaintext.len()].copy_from_slice(&plaintext);
        let sealed = seal
            .seal_with_u64_counter(i as u64, ad, buffer.as_mut_slice(), plaintext.len(), None)
            .expect("seal_with_u64_counter");
        let opened = open
            .open_with_u64_counter(i as u64, ad, &mut buffer[..sealed])
            .expect("open_with_u64_counter");
        sink ^= buffer.first().copied().unwrap_or(0);
        sink ^= buffer[opened.saturating_sub(1)];
        plaintext[0] = plaintext[0].wrapping_add(1);
    }
    let elapsed = start.elapsed().as_nanos();
    let processed = plaintext.len() * iters;

    println!(
        "bench,crypto-backend,backend,{},bytes,{},iters,{},ns_total,{},mbps,{:.3},instantiations,{},sink,{}",
        backend.as_str(),
        processed,
        iters,
        elapsed,
        format_mbps(processed, elapsed),
        counter_after.saturating_sub(counter_before),
        sink
    );
}

fn print_help() {
    eprintln!(
        "Crypto backend bench\n\nCommands:\n  profile\n  run <backend:aegis128l|aegis128x4|aegis128x8|morus> <bytes_per_iter> <iters>"
    );
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 || args[1] == "help" || args[1] == "--help" {
        print_help();
        return;
    }
    match args[1].as_str() {
        "profile" => {
            println!(
                "profile_info,profile={:?},features={:?}",
                quicfuscate::optimize::FeatureDetector::instance().profile(),
                quicfuscate::optimize::FeatureDetector::instance().features_full()
            );
        }
        "run" => {
            if args.len() < 5 {
                print_help();
                std::process::exit(2);
            }
            let backend = backend_from_str(&args[2]);
            let bytes = parse_usize(&args[3]);
            let iters = parse_usize(&args[4]);
            bench_backend(backend, bytes, iters);
        }
        _ => {
            print_help();
            std::process::exit(2);
        }
    }
}
