use quicfuscate::accelerate::random;
use rand::seq::SliceRandom;
use std::env;
use std::time::{Duration, Instant};

fn main() {
    let mut args = env::args().skip(1);
    let mut total_ops: u64 = 80_000_000; // total shuffled elements
    let mut lengths: Vec<usize> = (2..=8).collect();

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--total-ops" => {
                let value = args
                    .next()
                    .expect("missing value for --total-ops")
                    .parse::<u64>()
                    .expect("invalid --total-ops value");
                if value == 0 {
                    eprintln!("--total-ops must be > 0");
                    return;
                }
                total_ops = value;
            }
            "--length" => {
                let value = args
                    .next()
                    .expect("missing value for --length")
                    .parse::<usize>()
                    .expect("invalid --length value");
                lengths = vec![value];
            }
            "--lengths" => {
                let value = args.next().expect("missing value for --lengths");
                // `filter_map(.. .ok())` silently dropped every unparseable entry, so
                // `--lengths 4,oops` measured a different set than was requested.
                lengths = Vec::new();
                for part in value.split(',') {
                    match part.trim().parse::<usize>() {
                        Ok(length) => lengths.push(length),
                        Err(error) => fail(format!("--lengths entry {part:?} is invalid: {error}")),
                    }
                }
                if lengths.is_empty() {
                    fail("--lengths must contain at least one integer");
                }
            }
            "--help" | "-h" => {
                print_usage();
                return;
            }
            other => {
                print_usage();
                fail(format!("unknown argument {other:?}"));
            }
        }
    }

    lengths.sort_unstable();
    lengths.dedup();

    println!("# Shuffle benchmark\n# total_ops={} elements", total_ops);
    println!("len\titers\tsimd_MB/s\tscalar_MB/s\tspeedup\tsimd_ms\tscalar_ms");

    // A run where every requested length was skipped printed a header and exited zero,
    // which is an empty artifact that looks like a measurement.
    let mut measured = 0usize;
    for len in lengths {
        if !(2..=8).contains(&len) {
            eprintln!("skipping len={} (only 2..=8 supported by NEON path)", len);
            continue;
        }
        measured += 1;

        let iterations = (total_ops / len as u64).max(1);
        let baseline: Vec<u32> = (0..len as u32).collect();
        let mut buffer = baseline.clone();
        let mut sink: u32 = 0;

        // Warm-up both paths
        for _ in 0..1024 {
            random::shuffle(&mut buffer);
            buffer.copy_from_slice(&baseline);
            scalar_shuffle(&mut buffer);
            buffer.copy_from_slice(&baseline);
        }

        // SIMD/NEON path (current implementation)
        let simd_start = Instant::now();
        for _ in 0..iterations {
            random::shuffle(&mut buffer);
            sink ^= buffer[0];
            buffer.copy_from_slice(&baseline);
        }
        let simd_duration = simd_start.elapsed();
        let simd_bytes = len as u64 * 4 * iterations;
        let simd_throughput = bytes_per_second(simd_bytes, simd_duration);

        // Scalar fallback baseline (pre-optimization)
        let scalar_start = Instant::now();
        for _ in 0..iterations {
            scalar_shuffle(&mut buffer);
            sink ^= buffer[0].rotate_left(1);
            buffer.copy_from_slice(&baseline);
        }
        let scalar_duration = scalar_start.elapsed();
        let scalar_bytes = len as u64 * 4 * iterations;
        let scalar_throughput = bytes_per_second(scalar_bytes, scalar_duration);

        std::hint::black_box(sink);

        let speedup = if scalar_throughput > 0.0 {
            simd_throughput / scalar_throughput
        } else {
            f64::INFINITY
        };

        println!(
            "{}\t{}\t{:.2}\t{:.2}\t{:.2}x\t{:.3}\t{:.3}",
            len,
            iterations,
            to_mebibytes(simd_throughput),
            to_mebibytes(scalar_throughput),
            speedup,
            simd_duration.as_secs_f64() * 1000.0,
            scalar_duration.as_secs_f64() * 1000.0
        );
    }

    if measured == 0 {
        fail("no requested length is supported (only 2..=8); nothing was measured");
    }
}

fn scalar_shuffle(data: &mut [u32]) {
    data.shuffle(&mut rand::rng());
}

fn bytes_per_second(total_bytes: u64, duration: Duration) -> f64 {
    if duration.as_secs_f64() == 0.0 {
        return total_bytes as f64;
    }
    total_bytes as f64 / duration.as_secs_f64()
}

fn to_mebibytes(bytes_per_second: f64) -> f64 {
    bytes_per_second / (1024.0 * 1024.0)
}

#[path = "bench_cli/mod.rs"]
mod bench_cli;

use bench_cli::fail;

fn print_usage() {
    println!("Shuffle benchmark for quicfuscate::accelerate::random::shuffle");
    println!("Usage: shuffle_bench [--total-ops <u64>] [--length <usize>] [--lengths <list>]");
    println!("  --total-ops  Total shuffled elements per length (default: 80_000_000)");
    println!("  --length     Benchmark a single length (2..=8)");
    println!("  --lengths    Comma-separated list of lengths (2..=8)");
}
