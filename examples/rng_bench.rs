use quicfuscate::rng;
use rand::RngCore;
use std::env;
use std::time::Instant;

#[path = "bench_cli/mod.rs"]
mod bench_cli;

use bench_cli::{checked_workload, fail, parse_iters, parse_size};

fn main() {
    let mut args = env::args().skip(1);
    let mut total_mb: u64 = 128;
    let mut block_size: usize = 64 * 1024;
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--total-mb" => {
                let Some(value) = args.next() else {
                    fail("--total-mb requires a value");
                };
                total_mb = parse_iters("--total-mb", &value).unwrap_or_else(|error| fail(error));
            }
            "--block" => {
                let Some(value) = args.next() else {
                    fail("--block requires a value");
                };
                block_size = parse_size("--block", &value).unwrap_or_else(|error| fail(error));
            }
            "--help" | "-h" => {
                println!("usage: rng_bench [--total-mb <u64>] [--block <bytes>]");
                return;
            }
            // Ignoring an unknown option ran a different workload than the caller asked
            // for and still exited zero, so automation accepted it as a valid result.
            other => fail(format!("unknown option {other:?}; try --help")),
        }
    }

    let total_bytes = checked_workload("--total-mb", 1024 * 1024, total_mb)
        .unwrap_or_else(|error| fail(error)) as u64;
    let iterations = std::cmp::max(1, total_bytes / block_size as u64);
    let effective_bytes = iterations
        .checked_mul(block_size as u64)
        .unwrap_or_else(|| fail("the requested workload overflows the measured byte count"));

    println!(
        "# RNG benchmark\n# total ≈ {} MB ({} bytes), block {} bytes, iterations {}",
        effective_bytes as f64 / (1024.0 * 1024.0),
        effective_bytes,
        block_size,
        iterations
    );

    let mut buffer = vec![0u8; block_size];

    // Warm-up
    rng::fill_secure_or_abort(&mut buffer, "examples::rng_bench::warmup");
    let mut rand_rng = rand::rng();
    rand_rng.fill_bytes(&mut buffer);

    // Measure canonical secure entropy API
    let start_simd = Instant::now();
    for _ in 0..iterations {
        rng::fill_secure_or_abort(&mut buffer, "examples::rng_bench::loop");
    }
    let dur_simd = start_simd.elapsed();
    let throughput_simd = bytes_per_second(effective_bytes, dur_simd);

    // Measure rand::rng fallback
    let start_scalar = Instant::now();
    for _ in 0..iterations {
        rand_rng.fill_bytes(&mut buffer);
    }
    let dur_scalar = start_scalar.elapsed();
    let throughput_scalar = bytes_per_second(effective_bytes, dur_scalar);

    println!(
        "rng::fill_secure_or_abort: {:.2} MB/s (elapsed {:.3}s)",
        throughput_simd / (1024.0 * 1024.0),
        dur_simd.as_secs_f64()
    );
    println!(
        "rand::rng::fill_bytes: {:.2} MB/s (elapsed {:.3}s)",
        throughput_scalar / (1024.0 * 1024.0),
        dur_scalar.as_secs_f64()
    );
}

fn bytes_per_second(total: u64, duration: std::time::Duration) -> f64 {
    if duration.as_secs_f64() == 0.0 {
        return total as f64;
    }
    total as f64 / duration.as_secs_f64()
}
