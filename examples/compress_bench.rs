use clap::{Parser, ValueEnum};
use quicfuscate::compress::{CompressionConfig, CompressionManager};
use quicfuscate::optimize::MemoryPool;
use rand::RngCore;
use std::sync::Arc;
use std::time::Instant;

#[derive(Debug, Clone, Copy, ValueEnum)]
enum DatasetKind {
    Text,
    Binary,
}

#[derive(Parser)]
#[command(author, version, about = "Compression micro-benchmark", long_about = None)]
struct Opts {
    /// Payload size in bytes
    #[arg(long, default_value_t = 256 * 1024)]
    size: usize,
    /// Iterations to run
    #[arg(long, default_value_t = 50)]
    iterations: u32,
    /// Dataset type (textual or binary)
    #[arg(long, value_enum, default_value_t = DatasetKind::Text)]
    dataset: DatasetKind,
    /// Emit JSON output instead of human-readable lines
    #[arg(long)]
    json: bool,
}

fn make_dataset(kind: DatasetKind, size: usize) -> Vec<u8> {
    match kind {
        DatasetKind::Text => {
            const SAMPLE: &str = "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. ";
            let mut out = Vec::with_capacity(size);
            while out.len() < size {
                let remaining = size - out.len();
                let chunk = SAMPLE.as_bytes();
                if chunk.len() <= remaining {
                    out.extend_from_slice(chunk);
                } else {
                    out.extend_from_slice(&chunk[..remaining]);
                }
            }
            out
        }
        DatasetKind::Binary => {
            let mut out = vec![0u8; size];
            rand::rng().fill_bytes(&mut out);
            out
        }
    }
}

fn main() {
    let opts = Opts::parse();
    let dataset = make_dataset(opts.dataset, opts.size);
    let mgr = CompressionManager::new(CompressionConfig::default());
    let pool = Arc::new(MemoryPool::new(256, (opts.size + 1024).next_power_of_two()));

    // Warmup
    let _ = mgr.compress_to_pool(&pool, &dataset);

    let start = Instant::now();
    let mut total_out = 0usize;
    let mut compressed_input = 0usize;
    let mut successes = 0usize;
    for _ in 0..opts.iterations {
        if let Some((block, used)) = mgr.compress_to_pool(&pool, &dataset) {
            successes += 1;
            compressed_input += dataset.len();
            total_out += used.saturating_sub(5); // exclude header length
            drop(block);
        }
    }
    let elapsed = start.elapsed();
    let seconds = elapsed.as_secs_f64();

    let throughput_mib =
        if seconds > 0.0 { (compressed_input as f64 / (1024.0 * 1024.0)) / seconds } else { 0.0 };
    let ratio = if compressed_input > 0 { total_out as f64 / compressed_input as f64 } else { 1.0 };
    let skipped = opts.iterations as usize - successes;

    if opts.json {
        let report = serde_json::json!({
            "payload_bytes": opts.size,
            "iterations": opts.iterations,
            "dataset": format!("{:?}", opts.dataset).to_lowercase(),
            "elapsed_sec": seconds,
            "throughput_mib_s": throughput_mib,
            "compression_ratio": ratio,
            "successes": successes,
            "skipped": skipped,
        });
        println!("{}", report);
    } else {
        println!("Dataset: {:?}", opts.dataset);
        println!("Payload: {} bytes, Iterations: {}", opts.size, opts.iterations);
        println!("Elapsed: {:.3}s", seconds);
        println!("Throughput: {:.2} MiB/s", throughput_mib);
        println!("Compression ratio: {:.3}", ratio);
        println!("Successes: {} / {} (skipped: {})", successes, opts.iterations, skipped);
    }
}
