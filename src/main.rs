use clap::{Parser, Subcommand};
use log::{error, info, warn};
use std::path::Path;
use quicfuscate::app_config::AppConfig;
use quicfuscate::core::QuicFuscateConnection;
use quicfuscate::error::ConnectionError;
use quicfuscate::fec::{AdaptiveFec, FecConfig, FecMode};
use quicfuscate::optimize::OptimizationManager;
use quicfuscate::optimize::OptimizeConfig;
#[cfg(unix)]
use quicfuscate::optimize::ZeroCopyBuffer;
use quicfuscate::stealth::StealthConfig;
use quicfuscate::stealth::TlsClientHelloSpoofer;
use quicfuscate::stealth::{BrowserProfile, FingerprintProfile, OsProfile};
use quicfuscate::telemetry;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::net::ToSocketAddrs;
#[cfg(unix)]
use std::os::unix::io::AsRawFd;
use std::path::PathBuf;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use tokio::signal;
use tokio::time;
#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
#[clap(propagate_version = true)]
struct Cli {
    /// Enable verbose logging
    #[clap(short, long, global = true)]
    verbose: bool,
    /// Enable telemetry metrics
    #[clap(long, global = true)]
    telemetry: bool,
    #[clap(subcommand)]
    command: Commands,
}

// Common helper to insert unified benchmark metadata fields
#[cfg(feature = "benches")]
fn insert_bench_metadata(
    map: &mut serde_json::Map<String, serde_json::Value>,
    bench_name: &str,
    items: usize,
    payload_bytes: usize,
    warmup: usize,
    duration_secs: f64,
) {
    use serde_json::json;
    map.insert("bench_name".into(), json!(bench_name));
    map.insert("items".into(), json!(items));
    map.insert("payload_bytes".into(), json!(payload_bytes));
    map.insert("warmup".into(), json!(warmup));
    map.insert(
        "duration_ms".into(),
        json!((duration_secs * 1000.0).max(0.0)),
    );
    let rate = if duration_secs > 0.0 {
        (items as f64) / duration_secs
    } else {
        0.0
    };
    map.insert("rate_ops".into(), json!(rate));
    map.insert("os".into(), json!(std::env::consts::OS));
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    map.insert("timestamp".into(), json!(ts));
    map.insert(
        "git_rev".into(),
        json!(option_env!("QUICFUSCATE_GIT_REV").unwrap_or("n/a")),
    );
    map.insert(
        "cpu_model".into(),
        json!(option_env!("QUICFUSCATE_CPU_MODEL").unwrap_or("n/a")),
    );
    map.insert(
        "rustc".into(),
        json!(option_env!("QUICFUSCATE_RUSTC_VERSION").unwrap_or("n/a")),
    );
}

#[cfg(feature = "benches")]
fn run_fec_bench(
    packets: usize,
    payload: usize,
    mode: FecMode,
    pool_capacity: usize,
    block_size: usize,
    warmup: usize,
    json: bool,
) -> std::io::Result<()> {
    if payload == 0 || payload > block_size {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "payload must be > 0 and <= block_size",
        ));
    }
    let bench_once = |parallel: bool| -> (f64, usize) {
        // configure env toggle used by fec emit path
        std::env::set_var("QUICFUSCATE_FEC_PARALLEL", if parallel { "1" } else { "0" });
        let opt = OptimizationManager::new_with_config(pool_capacity, block_size, false);
        let mem_pool = opt.memory_pool();
        let mut cfg = FecConfig::default();
        cfg.initial_mode = mode;
        // fresh FEC per run for fairness
        let mut fec = AdaptiveFec::new(cfg, mem_pool);
        let mut out = VecDeque::with_capacity(256);

        // small helper to make packet with payload bytes; id increments
        let mut id: u64 = 1;
        let make_pkt = |id: u64| -> Packet {
            let mut block = opt.alloc_block();
            // mark as systematic in our simple framing
            if !block.is_empty() {
                block[0] = 1;
            }
            let len = payload.min(block.len());
            // touch a few bytes to avoid compiler eliding
            if len > 8 {
                block[1] = (id & 0xff) as u8;
                block[2] = ((id >> 8) & 0xff) as u8;
                block[3] = ((id >> 16) & 0xff) as u8;
                block[4] = ((id >> 24) & 0xff) as u8;
            }
            // construct packet owned by pool/opt
            Packet::from_block(id, block, len, &opt).expect("packet build")
        };

        // optional warmup
        for _ in 0..warmup {
            let p = make_pkt(id);
            id += 1;
            fec.on_send(p, &mut out);
            // drain emitted to keep memory bounded
            while let Some(mut q) = out.pop_front() {
                drop(&mut q);
            }
        }

        let start = Instant::now();
        for _ in 0..packets {
            let p = make_pkt(id);
            id += 1;
            fec.on_send(p, &mut out);
            while let Some(mut q) = out.pop_front() {
                drop(&mut q);
            }
        }
        let elapsed = start.elapsed().as_secs_f64();
        // clear env to avoid side-effects on caller
        if parallel {
            std::env::set_var("QUICFUSCATE_FEC_PARALLEL", "0");
        }
        (elapsed, packets)
    };

    let (t_seq, n_seq) = bench_once(false);
    let (t_par, n_par) = bench_once(true);

    if json {
        let mut map = serde_json::Map::new();
        insert_bench_metadata(&mut map, "fec-bench", packets, payload, warmup, t_seq);
        map.insert(
            "mode".into(),
            serde_json::json!(format!("{:?}", mode).to_lowercase()),
        );
        map.insert("seq_seconds".into(), serde_json::json!(t_seq));
        map.insert("par_seconds".into(), serde_json::json!(t_par));
        map.insert(
            "seq_pps".into(),
            serde_json::json!((n_seq as f64 / t_seq).max(0.0)),
        );
        map.insert(
            "par_pps".into(),
            serde_json::json!((n_par as f64 / t_par).max(0.0)),
        );
        println!("{}", serde_json::Value::Object(map).to_string());
    } else {
        println!(
            "[FEC-BENCH] packets={}, payload={}B, mode={:?}",
            packets, payload, mode
        );
        println!(
            " sequential: {:.3}s  ({:.0} pkt/s)",
            t_seq,
            (n_seq as f64 / t_seq).round()
        );
        println!(
            "   parallel: {:.3}s  ({:.0} pkt/s)",
            t_par,
            (n_par as f64 / t_par).round()
        );
        if t_par > 0.0 {
            println!(" speedup: {:.2}x", (t_seq / t_par));
        }
    }
    Ok(())
}

#[cfg(feature = "benches")]
#[derive(Copy, Clone, Debug, Eq, PartialEq, clap::ValueEnum)]
enum CryptoMode {
    #[clap(name = "fnv1a")]
    Fnv1a,
    #[clap(name = "xor")]
    Xor,
    #[clap(name = "rolling")]
    Rolling,
}

#[cfg(feature = "benches")]
fn run_pool_bench(
    iterations: usize,
    payload: usize,
    pool_capacity: usize,
    block_size: usize,
    warmup: usize,
    json: bool,
) -> std::io::Result<()> {
    if payload == 0 || payload > block_size {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "payload must be > 0 and <= block_size",
        ));
    }
    let opt = OptimizationManager::new_with_config(pool_capacity, block_size, false);
    let start_once = |iters: usize| -> f64 {
        let mut touched: u64 = 0;
        let t0 = Instant::now();
        for i in 0..iters {
            let mut b = opt.alloc_block();
            let sz = payload.min(b.len());
            if sz > 0 {
                b[0] = 0xAA;
            }
            // deterministic touches
            for j in (0..sz).step_by(64) {
                b[j] ^= ((i as u8).wrapping_add(j as u8)) ^ 0x5A;
                touched = touched.wrapping_add(b[j] as u64);
            }
            drop(b);
        }
        let _ = touched; // avoid optimization
        t0.elapsed().as_secs_f64()
    };

    // warmup
    if warmup > 0 {
        let _ = start_once(warmup);
    }
    let elapsed = start_once(iterations);

    if json {
        let mut map = serde_json::Map::new();
        insert_bench_metadata(&mut map, "pool-bench", iterations, payload, warmup, elapsed);
        map.insert("pool_capacity".into(), serde_json::json!(pool_capacity));
        map.insert("block_size".into(), serde_json::json!(block_size));
        println!("{}", serde_json::Value::Object(map).to_string());
    } else {
        let rate = if elapsed > 0.0 {
            iterations as f64 / elapsed
        } else {
            0.0
        };
        println!(
            "[POOL-BENCH] iters={}, payload={}B, pool_cap={}, block={}B",
            iterations, payload, pool_capacity, block_size
        );
        println!(" elapsed: {:.3}s  ({:.0} ops/s)", elapsed, rate.round());
    }
    Ok(())
}

#[cfg(feature = "benches")]
fn run_crypto_bench(
    iterations: usize,
    payload: usize,
    mode: CryptoMode,
    warmup: usize,
    json: bool,
) -> std::io::Result<()> {
    if payload == 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "payload must be > 0",
        ));
    }

    // deterministic input generator (LCG)
    let mut seed: u64 = 0x9E3779B97F4A7C15;
    let mut make_buf = || {
        let mut v = vec![0u8; payload];
        for i in 0..payload {
            seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
            v[i] = (seed >> 32) as u8 ^ (i as u8);
        }
        v
    };

    let mutate = |buf: &mut [u8], idx: usize, mode: CryptoMode| -> u64 {
        let mut acc: u64 = 0xcbf29ce484222325; // FNV offset
        match mode {
            CryptoMode::Fnv1a => {
                for &b in buf.iter() {
                    acc ^= b as u64;
                    acc = acc.wrapping_mul(0x100000001b3);
                }
            }
            CryptoMode::Xor => {
                let k = ((idx as u8).wrapping_mul(0x5D)) ^ 0xA5;
                for x in buf.iter_mut() {
                    *x ^= k;
                    acc = acc.wrapping_add(*x as u64);
                }
            }
            CryptoMode::Rolling => {
                let mut s: u8 = (idx as u8).wrapping_add(0x33);
                for x in buf.iter_mut() {
                    s = s.rotate_left(1).wrapping_add(*x);
                    *x = x.rotate_left(1) ^ s;
                    acc = acc.wrapping_mul(131).wrapping_add(*x as u64);
                }
            }
        }
        acc
    };

    let mut run = |iters: usize| -> (f64, u64) {
        let mut checksum: u64 = 0;
        let t0 = Instant::now();
        for i in 0..iters {
            let mut buf = make_buf();
            checksum ^= mutate(&mut buf, i, mode);
        }
        let sec = t0.elapsed().as_secs_f64();
        (sec, checksum)
    };

    if warmup > 0 {
        let _ = run(warmup);
    }
    let (elapsed, checksum) = run(iterations);

    if json {
        let mut map = serde_json::Map::new();
        insert_bench_metadata(
            &mut map,
            "crypto-bench",
            iterations,
            payload,
            warmup,
            elapsed,
        );
        map.insert(
            "mode".into(),
            serde_json::json!(format!("{:?}", mode).to_lowercase()),
        );
        map.insert(
            "checksum".into(),
            serde_json::json!(format!("0x{:016x}", checksum)),
        );
        println!("{}", serde_json::Value::Object(map).to_string());
    } else {
        let rate = if elapsed > 0.0 {
            iterations as f64 / elapsed
        } else {
            0.0
        };
        println!(
            "[CRYPTO-BENCH] iters={}, payload={}B, mode={:?}",
            iterations, payload, mode
        );
        println!(
            " elapsed: {:.3}s  ({:.0} ops/s) checksum=0x{:016x}",
            elapsed,
            rate.round(),
            checksum
        );
    }
    Ok(())
}

#[cfg(feature = "benches")]
fn run_net_bench(
    iterations: usize,
    payload: usize,
    warmup: usize,
    json: bool,
) -> std::io::Result<()> {
    if payload == 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "payload must be > 0",
        ));
    }

    let mut seed: u64 = 0xD6E8FEB86659FD93;
    let mut gen_packet = || {
        let mut v = vec![0u8; payload];
        for i in 0..payload {
            seed ^= seed << 7;
            seed ^= seed >> 9;
            v[i] = (seed as u8).wrapping_add(i as u8);
        }
        v
    };

    let mut pipe: VecDeque<Vec<u8>> = VecDeque::with_capacity(1024);
    let mut run = |iters: usize, pipe: &mut VecDeque<Vec<u8>>| -> (f64, usize) {
        let mut moved = 0usize;
        let t0 = Instant::now();
        for _ in 0..iters {
            // enqueue
            pipe.push_back(gen_packet());
            // process stage: copy into scratch then drop
            if let Some(pkt) = pipe.pop_front() {
                let mut scratch = vec![0u8; pkt.len()];
                scratch.copy_from_slice(&pkt);
                moved += scratch.len();
            }
        }
        (t0.elapsed().as_secs_f64(), moved)
    };

    if warmup > 0 {
        let _ = run(warmup, &mut pipe);
        pipe.clear();
    }
    let (elapsed, moved) = run(iterations, &mut pipe);

    if json {
        let mut map = serde_json::Map::new();
        insert_bench_metadata(&mut map, "net-bench", iterations, payload, warmup, elapsed);
        map.insert("bytes_moved".into(), serde_json::json!(moved));
        println!("{}", serde_json::Value::Object(map).to_string());
    } else {
        let rate = if elapsed > 0.0 {
            iterations as f64 / elapsed
        } else {
            0.0
        };
        println!("[NET-BENCH] iters={}, payload={}B", iterations, payload);
        println!(
            " elapsed: {:.3}s  ({:.0} ops/s) bytes_moved={} ",
            elapsed,
            rate.round(),
            moved
        );
    }
    Ok(())
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Runs the client
    Client {
        /// The remote server address to connect to
        #[clap(long, required = true)]
        remote: String,

        /// Local UDP address to bind
        #[clap(long, default_value = "0.0.0.0:0")]
        local: String,

        /// The URL to request
        #[clap(short, long, default_value = "https://example.com")]
        url: String,

        /// Browser fingerprint profile (chrome, firefox, opera, brave)
        #[clap(long, value_enum, default_value_t = BrowserProfile::Chrome)]
        profile: BrowserProfile,

        /// Operating system for the profile (windows, macos, linux, ios, android)
        #[clap(long, value_enum, default_value_t = OsProfile::Windows)]
        os: OsProfile,

        /// Comma separated list of profiles to cycle through
        #[clap(long, value_delimiter = ',')]
        profile_seq: Option<Vec<String>>,

        /// Interval in seconds for profile switching
        #[clap(long, default_value_t = 0)]
        profile_interval: u64,

        /// Initial FEC mode
        #[clap(long, value_enum, default_value = "zero")]
        fec_mode: FecMode,

        /// Memory pool capacity (number of blocks)
        #[clap(long, default_value_t = 1024)]
        pool_capacity: usize,

        /// Memory pool block size in bytes
        #[clap(long, default_value_t = 4096)]
        pool_block: usize,

        /// Enable XDP acceleration if supported
        #[clap(long)]
        xdp: bool,

        /// Print live XDP statistics
        #[clap(long)]
        xdp_stats: bool,

        /// Path to a unified TOML configuration file
        #[clap(long, value_name = "PATH")]
        config: Option<PathBuf>,

        /// Path to a TOML file with Adaptive FEC settings
        #[clap(long, value_name = "PATH")]
        fec_config: Option<PathBuf>,

        /// Custom DNS-over-HTTPS provider URL
        #[clap(long, default_value = "https://cloudflare-dns.com/dns-query")]
        doh_provider: String,

        /// Domain used for fronting (can be specified multiple times)
        #[clap(long, value_delimiter = ',')]
        front_domain: Vec<String>,
        /// CA file for peer verification
        #[clap(long, value_name = "PATH")]
        ca_file: Option<PathBuf>,
        /// Disable uTLS and use regular TLS
        #[clap(long)]
        no_utls: bool,
        /// Show TLS debug information
        #[clap(long)]
        debug_tls: bool,
        /// List available browser fingerprints
        #[clap(long)]
        list_fingerprints: bool,
        /// Enable certificate validation when connecting to the server
        #[clap(long)]
        verify_peer: bool,

        /// Disable DNS over HTTPS
        #[clap(long)]
        disable_doh: bool,

        /// Disable domain fronting
        #[clap(long)]
        disable_fronting: bool,

        /// Disable XOR obfuscation
        #[clap(long)]
        disable_xor: bool,

        /// Disable HTTP/3 masquerading
        #[clap(long)]
        disable_http3: bool,
    },
    /// Runs the server
    Server {
        /// The address to listen on
        #[clap(short, long, default_value = "127.0.0.1:4433")]
        listen: String,

        /// Path to the certificate file
        #[clap(short, long, required = true)]
        cert: PathBuf,

        /// Path to the private key file
        #[clap(short, long, required = true)]
        key: PathBuf,

        /// Browser fingerprint profile used for connections
        #[clap(long, value_enum, default_value_t = BrowserProfile::Chrome)]
        profile: BrowserProfile,

        /// Operating system for the profile (windows, macos, linux, ios, android)
        #[clap(long, value_enum, default_value_t = OsProfile::Windows)]
        os: OsProfile,

        /// Comma separated list of profiles to cycle through
        #[clap(long, value_delimiter = ',')]
        profile_seq: Option<Vec<String>>,

        /// Interval in seconds for profile switching
        #[clap(long, default_value_t = 0)]
        profile_interval: u64,

        /// Initial FEC mode
        #[clap(long, value_enum, default_value = "zero")]
        fec_mode: FecMode,

        /// Memory pool capacity (number of blocks)
        #[clap(long, default_value_t = 1024)]
        pool_capacity: usize,

        /// Memory pool block size in bytes
        #[clap(long, default_value_t = 4096)]
        pool_block: usize,

        /// Enable XDP acceleration if supported
        #[clap(long)]
        xdp: bool,

        /// Print live XDP statistics
        #[clap(long)]
        xdp_stats: bool,

        /// Path to a unified TOML configuration file
        #[clap(long, value_name = "PATH")]
        config: Option<PathBuf>,

        /// Path to a TOML file with Adaptive FEC settings
        #[clap(long, value_name = "PATH")]
        fec_config: Option<PathBuf>,

        /// Custom DNS-over-HTTPS provider URL
        #[clap(long, default_value = "https://cloudflare-dns.com/dns-query")]
        doh_provider: String,

        /// Domain used for fronting (can be specified multiple times)
        #[clap(long, value_delimiter = ',')]
        front_domain: Vec<String>,

        /// Disable DNS over HTTPS
        #[clap(long)]
        disable_doh: bool,

        /// Disable domain fronting
        #[clap(long)]
        disable_fronting: bool,

        /// Disable XOR obfuscation
        #[clap(long)]
        disable_xor: bool,

        /// Disable HTTP/3 masquerading
        #[clap(long)]
        disable_http3: bool,
    },
    #[clap(hide = true)]
    CrossFadeSim {},
    #[clap(hide = true)]
    HighLossSim {},
    #[clap(hide = true)]
    OptimizeProbe {},
    #[clap(hide = true)]
    XdpSmoke {},
    #[cfg(feature = "benches")]
    #[clap(hide = true)]
    /// Internal FEC benchmark harness (sequential vs parallel)
    FecBench {
        /// Number of source packets to send during the measured run
        #[clap(long, alias = "iterations", default_value_t = 8192)]
        packets: usize,
        /// Payload size per packet (bytes)
        #[clap(long, default_value_t = 1200)]
        payload: usize,
        /// Initial FEC mode/window profile to benchmark
        #[clap(long, value_enum, default_value = "normal")]
        mode: FecMode,
        /// Memory pool capacity (blocks)
        #[clap(long, default_value_t = 1024)]
        pool_capacity: usize,
        /// Memory pool block size (bytes)
        #[clap(long, default_value_t = 4096)]
        block_size: usize,
        /// Warm-up packet count (not timed)
        #[clap(long, default_value_t = 0)]
        warmup: usize,
        /// Print machine-readable JSON summary
        #[clap(long)]
        json: bool,
    },
    #[cfg(feature = "benches")]
    #[clap(hide = true)]
    /// Internal Memory Pool micro-benchmark
    PoolBench {
        /// Total iterations to perform (alias: --packets)
        #[clap(long, alias = "packets", default_value_t = 200_000)]
        iterations: usize,
        /// Bytes to touch per allocation
        #[clap(long, default_value_t = 1200)]
        payload: usize,
        /// Memory pool capacity (blocks)
        #[clap(long, default_value_t = 1024)]
        pool_capacity: usize,
        /// Memory pool block size (bytes)
        #[clap(long, default_value_t = 4096)]
        block_size: usize,
        /// Warm-up iterations (not timed)
        #[clap(long, default_value_t = 0)]
        warmup: usize,
        /// Print machine-readable JSON summary
        #[clap(long)]
        json: bool,
    },
    #[cfg(feature = "benches")]
    #[clap(hide = true)]
    /// Internal Crypto/Encode micro-benchmark
    CryptoBench {
        /// Total iterations to perform (alias: --packets)
        #[clap(long, alias = "packets", default_value_t = 200_000)]
        iterations: usize,
        /// Payload size per iteration (bytes)
        #[clap(long, default_value_t = 1200)]
        payload: usize,
        /// Hash/encode mode
        #[clap(long, value_enum, default_value = "fnv1a")]
        mode: CryptoMode,
        /// Warm-up iterations (not timed)
        #[clap(long, default_value_t = 0)]
        warmup: usize,
        /// Print machine-readable JSON summary
        #[clap(long)]
        json: bool,
    },
    #[cfg(feature = "benches")]
    #[clap(hide = true)]
    /// Internal synthetic networking micro-benchmark
    NetBench {
        /// Total iterations to perform (alias: --packets)
        #[clap(long, alias = "packets", default_value_t = 100_000)]
        iterations: usize,
        /// Payload size per synthetic packet (bytes)
        #[clap(long, default_value_t = 1200)]
        payload: usize,
        /// Warm-up iterations (not timed)
        #[clap(long, default_value_t = 0)]
        warmup: usize,
        /// Print machine-readable JSON summary
        #[clap(long)]
        json: bool,
    },
    #[clap(hide = true)]
    /// Internal capability probe for system diagnostics
    Capabilities {
        /// Print machine-readable JSON (recommended)
        #[clap(long)]
        json: bool,
    },
}

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let cli = Cli::parse();
    if cli.verbose {
        std::env::set_var("RUST_LOG", "info");
    }
    env_logger::init();
    if cli.telemetry {
        telemetry::TELEMETRY_ENABLED.store(true, Ordering::Relaxed);
        crate::telemetry::serve("0.0.0.0:9898");
    }

    match &cli.command {
        Commands::Client {
            remote,
            local,
            url,
            profile,
            os,
            profile_seq,
            profile_interval,
            fec_mode,
            pool_capacity,
            pool_block,
            xdp,
            xdp_stats,
            config,
            fec_config,
            doh_provider,
            front_domain,
            ca_file,
            no_utls,
            debug_tls,
            list_fingerprints,
            verify_peer,
            disable_doh,
            disable_fronting,
            disable_xor,
            disable_http3,
        } => {
            let browser = *profile;
            let os_profile = *os;
            run_client(
                remote,
                local,
                url,
                browser,
                os_profile,
                profile_seq,
                *profile_interval,
                *fec_mode,
                *pool_capacity,
                *pool_block,
                *xdp,
                *xdp_stats,
                config,
                fec_config,
                doh_provider,
                front_domain,
                ca_file,
                *no_utls,
                *debug_tls,
                *list_fingerprints,
                *verify_peer,
                *disable_doh,
                *disable_fronting,
                *disable_xor,
                *disable_http3,
            )
            .await?;
        }
        Commands::Server {
            listen,
            cert,
            key,
            profile,
            os,
            profile_seq,
            profile_interval,
            fec_mode,
            pool_capacity,
            pool_block,
            config,
            fec_config,
            doh_provider,
            front_domain,
            xdp,
            xdp_stats,
            disable_doh,
            disable_fronting,
            disable_xor,
            disable_http3,
        } => {
            let browser = *profile;
            let os_profile = *os;
            run_server(
                listen,
                cert,
                key,
                browser,
                os_profile,
                profile_seq,
                *profile_interval,
                *fec_mode,
                *pool_capacity,
                *pool_block,
                *xdp,
                *xdp_stats,
                config,
                fec_config,
                doh_provider,
                front_domain,
                *disable_doh,
                *disable_fronting,
                *disable_xor,
                *disable_http3,
            )
            .await?;
        }
        Commands::CrossFadeSim {} => {
            run_crossfade_sim()?;
        }
        Commands::HighLossSim {} => {
            run_high_loss_sim()?;
        }
        Commands::OptimizeProbe {} => {
            run_optimize_probe()?;
        }
        Commands::XdpSmoke {} => {
            run_xdp_smoke()?;
        }
        #[cfg(feature = "benches")]
        Commands::FecBench {
            packets,
            payload,
            mode,
            pool_capacity,
            block_size,
            warmup,
            json,
        } => {
            run_fec_bench(
                *packets,
                *payload,
                *mode,
                *pool_capacity,
                *block_size,
                *warmup,
                *json,
            )?;
        }
        #[cfg(feature = "benches")]
        Commands::PoolBench {
            iterations,
            payload,
            pool_capacity,
            block_size,
            warmup,
            json,
        } => {
            run_pool_bench(
                *iterations,
                *payload,
                *pool_capacity,
                *block_size,
                *warmup,
                *json,
            )?;
        }
        #[cfg(feature = "benches")]
        Commands::CryptoBench {
            iterations,
            payload,
            mode,
            warmup,
            json,
        } => {
            run_crypto_bench(*iterations, *payload, *mode, *warmup, *json)?;
        }
        #[cfg(feature = "benches")]
        Commands::NetBench {
            iterations,
            payload,
            warmup,
            json,
        } => {
            run_net_bench(*iterations, *payload, *warmup, *json)?;
        }
        Commands::Capabilities { json: _ } => {
            let _json = serde_json::json!({
                "fec_bench": cfg!(feature = "benches"),
                "pool_bench": cfg!(feature = "benches"),
                "crypto_bench": cfg!(feature = "benches"),
                "net_bench": cfg!(feature = "benches"),
            });
            println!("{}", _json);
        }
    }

    if telemetry::TELEMETRY_ENABLED.load(Ordering::Relaxed) {
        telemetry::flush();
    }
    Ok(())
}

fn parse_profile_entry(entry: &str, default_os: OsProfile) -> Option<FingerprintProfile> {
    let parts: Vec<&str> = entry.split('@').collect();
    let browser_part = parts.first()?;
    let browser = match browser_part.parse() {
        Ok(b) => b,
        Err(_) => {
            warn!("Invalid browser profile: {}", browser_part);
            return None;
        }
    };
    let os = if let Some(os_part) = parts.get(1) {
        match os_part.parse() {
            Ok(o) => o,
            Err(_) => {
                warn!("Invalid OS profile: {}", os_part);
                return None;
            }
        }
    } else {
        default_os
    };
    let fp = FingerprintProfile::new(browser, os);
    if fp.client_hello.is_none() {
        warn!(
            "No ClientHello found for {}@{}",
            browser_part,
            format!("{:?}", os).to_lowercase()
        );
        return None;
    }
    Some(fp)
}

fn run_crossfade_sim() -> std::io::Result<()> {
    println!("[legacy] Cross-fade simulation starting...");
    let opt = OptimizationManager::new();
    let mem_pool = opt.memory_pool();
    let mut fec = AdaptiveFec::new(FecConfig::default(), mem_pool);
    let mut last_mode = fec.current_mode();
    println!(" initial mode: {:?}", last_mode);

    let phases: &[(usize, usize, usize)] = &[
        (0, 100, 16),  // clean
        (10, 100, 16), // light loss
        (30, 100, 24), // moderate
        (50, 100, 24), // heavy
        (10, 100, 16), // recover
    ];
    for (lost, total, iters) in phases {
        for _ in 0..*iters {
            fec.report_loss(*lost, *total);
            let m = fec.current_mode();
            if m != last_mode || fec.is_transitioning() {
                println!(
                    " mode: {:?}  transitioning: {}  (loss={}/{})",
                    m,
                    fec.is_transitioning(),
                    lost,
                    total
                );
                last_mode = m;
            }
        }
    }
    println!(
        "[legacy] Cross-fade simulation complete. final mode: {:?}",
        last_mode
    );
    Ok(())
}

fn run_high_loss_sim() -> std::io::Result<()> {
    println!("[legacy] High-loss simulation starting...");
    let opt = OptimizationManager::new();
    let mem_pool = opt.memory_pool();
    let mut fec = AdaptiveFec::new(FecConfig::default(), mem_pool);
    let mut last_mode = fec.current_mode();
    println!(" initial mode: {:?}", last_mode);
    for _ in 0..64 {
        fec.report_loss(70, 100);
        let m = fec.current_mode();
        if m != last_mode || fec.is_transitioning() {
            println!(" mode: {:?}  transitioning: {}", m, fec.is_transitioning());
            last_mode = m;
        }
    }
    println!(
        "[legacy] High-loss simulation complete. final mode: {:?}",
        last_mode
    );
    Ok(())
}

fn run_optimize_probe() -> std::io::Result<()> {
    println!("[legacy] Optimization probe starting...");
    let opt = OptimizationManager::new_with_config(64, 4096, false);
    println!(
        " xdp_available={} xdp_enabled={}",
        opt.is_xdp_available(),
        opt.is_xdp_enabled()
    );
    // Exercise the memory pool
    let b1 = opt.alloc_block();
    let b2 = opt.alloc_block();
    println!(" allocated two blocks: {} + {} bytes", b1.len(), b2.len());
    // Touch memory to exercise NUMA moves where applicable
    let mut b1 = b1;
    let mut b2 = b2;
    if !b1.is_empty() {
        b1[0] = 1;
    }
    if !b2.is_empty() {
        b2[0] = 2;
    }
    opt.free_block(b1);
    opt.free_block(b2);
    // Adjust capacity dynamically
    let pool = opt.memory_pool();
    pool.set_capacity(128);
    println!(" pool capacity adjusted to 128 (probe)");
    println!("[legacy] Optimization probe complete.");
    Ok(())
}

fn run_xdp_smoke() -> std::io::Result<()> {
    println!("[legacy] XDP smoke starting...");
    let opt = OptimizationManager::new_with_config(64, 4096, true);
    println!(
        " xdp_available={} xdp_enabled={}",
        opt.is_xdp_available(),
        opt.is_xdp_enabled()
    );
    if !opt.is_xdp_available() {
        println!(" XDP not supported on this platform — skipping.");
        return Ok(());
    }
    let bind: SocketAddr = "127.0.0.1:60000".parse().unwrap();
    let remote: SocketAddr = "127.0.0.1:60001".parse().unwrap();
    match opt.create_xdp_socket(bind, remote) {
        Some(_) => {
            println!(" XDP socket created (or UDP fallback established). OK.");
        }
        None => {
            println!(" XDP disabled or unavailable — no socket created.");
        }
    }
    println!("[legacy] XDP smoke complete.");
    Ok(())
}
#[allow(clippy::too_many_arguments)]
async fn run_client(
    remote_addr_str: &str,
    local_addr_str: &str,
    url: &str,
    profile: BrowserProfile,
    os: OsProfile,
    profile_seq: &Option<Vec<String>>,
    profile_interval: u64,
    fec_mode: FecMode,
    pool_capacity: usize,
    pool_block: usize,
    xdp: bool,
    xdp_stats: bool,
    config: &Option<PathBuf>,
    fec_config: &Option<PathBuf>,
    doh_provider: &str,
    front_domain: &[String],
    ca_file: &Option<PathBuf>,
    no_utls: bool,
    debug_tls: bool,
    list_fingerprints: bool,
    verify_peer: bool,
    disable_doh: bool,
    disable_fronting: bool,
    disable_xor: bool,
    disable_http3: bool,
) -> std::io::Result<()> {
    let config_path = config.clone();
    if list_fingerprints {
        info!("Available browser fingerprints:");
        for (b, o) in TlsClientHelloSpoofer::available_profiles() {
            info!(
                "- {}@{}",
                format!("{:?}", b).to_lowercase(),
                format!("{:?}", o).to_lowercase()
            );
        }
        return Ok(());
    }

    let server_addr = remote_addr_str.to_socket_addrs()?.next().ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::NotFound, "Server address not found")
    })?;

    let local_addr = local_addr_str.to_socket_addrs()?.next().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::AddrNotAvailable,
            "Local address invalid",
        )
    })?;

    let socket = std::net::UdpSocket::bind(local_addr)?;
    socket.connect(server_addr)?;
    socket.set_nonblocking(true)?;

    info!("Client connecting to {}", server_addr);

    if xdp_stats {
        tokio::spawn(async move {
            loop {
                info!(
                    "XDP tx: {} bytes, rx: {} bytes",
                    telemetry::XDP_BYTES_SENT.get(),
                    telemetry::XDP_BYTES_RECEIVED.get()
                );
                time::sleep(std::time::Duration::from_secs(1)).await;
            }
        });
    }

    let (mut fec_cfg, mut stealth_config, opt_cfg) = if let Some(cfg) = config_path.as_ref() {
        match AppConfig::from_file(cfg) {
            Ok(c) => {
                if let Err(e) = c.validate() {
                    warn!("Config validation failed: {}", e);
                }
                (c.fec, c.stealth, c.optimize)
            }
            Err(e) => {
                error!("Failed to load config {}: {}", cfg.display(), e);
                (
                    FecConfig::default(),
                    StealthConfig::default(),
                    OptimizeConfig::default(),
                )
            }
        }
    } else {
        let fec = if let Some(path) = fec_config {
            match FecConfig::from_file(path) {
                Ok(cfg) => {
                    if let Err(e) = cfg.validate() {
                        warn!("FEC config validation failed: {}", e);
                    }
                    cfg
                }
                Err(e) => {
                    error!("Failed to load FEC config {}: {}", path.display(), e);
                    FecConfig::default()
                }
            }
        } else {
            FecConfig::default()
        };
        (fec, StealthConfig::default(), OptimizeConfig::default())
    };
    fec_cfg.initial_mode = fec_mode;

    let mut config = match quiche::Config::new(quiche::PROTOCOL_VERSION) {
        Ok(c) => c,
        Err(e) => {
            error!("Failed to create quiche config: {}", e);
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "quiche config init failed",
            ));
        }
    };
    if let Err(e) = config.set_application_protos(&[
        b"\x0ahq-interop",
        b"\x05h3-29",
        b"\x05h3-28",
        b"\x05h3-27",
        b"\x08http/0.9",
    ]) {
        warn!("Failed to set application protos: {}", e);
    }
    config.set_max_idle_timeout(30000);
    config.set_max_recv_udp_payload_size(1460);
    config.set_max_send_udp_payload_size(1200);
    config.set_initial_max_data(10_000_000);
    config.set_initial_max_stream_data_bidi_local(1_000_000);
    config.set_initial_max_stream_data_bidi_remote(1_000_000);
    config.set_initial_max_streams_bidi(100);
    config.set_initial_max_streams_uni(100);
    config.verify_peer(verify_peer);
    if debug_tls {
        config.log_keys();
    }
    if let Some(path) = ca_file {
        match path.to_str() {
            Some(s) => {
                if let Err(e) = config.load_verify_locations_from_file(s) {
                    error!("Failed to load CA file {}: {}", path.display(), e);
                }
            }
            None => {
                error!("CA file path is not valid UTF-8: {}", path.display());
            }
        }
    }

    let url_parsed = match url::Url::parse(url) {
        Ok(u) => u,
        Err(e1) => {
            warn!(
                "Invalid URL '{}': {}. Falling back to https://example.com/",
                url, e1
            );
            match url::Url::parse("https://example.com/") {
                Ok(u2) => u2,
                Err(e2) => {
                    error!("Fallback URL parse failed: {}", e2);
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "invalid URL",
                    ));
                }
            }
        }
    };
    stealth_config.browser_profile = profile;
    stealth_config.os_profile = os;
    stealth_config.enable_doh = !disable_doh;
    stealth_config.doh_provider = doh_provider.to_string();
    stealth_config.enable_domain_fronting = !disable_fronting;
    stealth_config.fronting_domains = front_domain.to_vec();
    stealth_config.enable_xor_obfuscation = !disable_xor;
    stealth_config.enable_http3_masquerading = !disable_http3;
    telemetry!(telemetry::STEALTH_BROWSER_PROFILE.set(stealth_config.browser_profile as i64));
    telemetry!(telemetry::STEALTH_OS_PROFILE.set(stealth_config.os_profile as i64));

    let host = url_parsed.host_str().unwrap_or("example.com");
    let opt_params = if config_path.is_some() {
        OptimizeConfig {
            pool_capacity: opt_cfg.pool_capacity,
            block_size: opt_cfg.block_size,
            enable_xdp: opt_cfg.enable_xdp || xdp,
        }
    } else {
        OptimizeConfig {
            pool_capacity,
            block_size: pool_block,
            enable_xdp: xdp,
        }
    };
    let mut conn = match QuicFuscateConnection::new_client(
        host,
        local_addr,
        server_addr,
        config,
        stealth_config.clone(),
        fec_cfg,
        opt_params,
        !no_utls,
    ) {
        Ok(c) => c,
        Err(e) => {
            error!("failed to create client connection: {}", e);
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "client connection init failed",
            ));
        }
    };

    let profiles: Vec<FingerprintProfile> = match profile_seq {
        Some(seq) => seq
            .iter()
            .filter_map(|s| parse_profile_entry(s, os))
            .collect(),
        None => vec![FingerprintProfile::new(profile, os)],
    };

    if profile_interval > 0 && profiles.is_empty() {
        error!("No valid profiles supplied with --profile-seq");
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "invalid profile sequence",
        ));
    }

    if profile_interval > 0 && profiles.len() > 1 {
        let sm = conn.stealth_manager();
        sm.start_profile_rotation(profiles, std::time::Duration::from_secs(profile_interval));
    }

    let mut buf = [0; 65535];
    let mut out = [0; 65535];

    // Send initial packet
    if let Ok(len) = conn.send(&mut out) {
        if len > 0 {
            telemetry!(telemetry::BYTES_SENT.inc_by(len as u64));
            #[cfg(unix)]
            {
                let zc = ZeroCopyBuffer::new(&[&out[..len]]);
                zc.send(socket.as_raw_fd());
            }
            #[cfg(not(unix))]
            {
                socket.send(&out[..len])?;
            }
            info!("Sent initial packet of size {}", len);
        }
    }

    let mut request_sent = false;
    let shutdown = signal::ctrl_c();
    tokio::pin!(shutdown);

    loop {
        tokio::select! {
            _ = &mut shutdown => {
                info!("Shutdown signal received");
                let _ = conn.conn.close(true, 0x0, b"ctrl_c");
                break;
            }
            _ = async {
                // Process incoming packets
                let res: Result<usize, std::io::Error> = {
                    #[cfg(unix)]
                    {
                        let mut slice = [&mut buf[..]];
                        let mut zc = ZeroCopyBuffer::new_mut(&mut slice);
                        let r = zc.recv(socket.as_raw_fd());
                        if r >= 0 { Ok(r as usize) } else { Err(std::io::Error::last_os_error()) }
                    }
                    #[cfg(not(unix))]
                    {
                        socket.recv(&mut buf)
                    }
                };
                match res {
                    Ok(len) => {
                        telemetry!(telemetry::BYTES_RECEIVED.inc_by(len as u64));
                        let _ = conn.recv(&buf[..len]);
                    }
                    Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                    Err(e) => {
                        error!("Failed to read from socket: {}", e);
                        return;
                    }
                }

        if conn.conn.is_established() && !request_sent {
            if let Err(e) = conn.send_http3_request(url_parsed.path()) {
                warn!("HTTP/3 request failed: {:?}", e);
            } else {
                request_sent = true;
            }
        }

        if let Err(e) = conn.poll_http3() {
            warn!("HTTP/3 error: {:?}", e);
        }

        loop {
            match conn.send(&mut out) {
                Ok(len) if len > 0 => {
                    telemetry!(telemetry::BYTES_SENT.inc_by(len as u64));
                    #[cfg(unix)]
                    {
                        let zc = ZeroCopyBuffer::new(&[&out[..len]]);
                        zc.send(socket.as_raw_fd());
                    }
                    #[cfg(not(unix))]
                    {
                        socket.send(&out[..len])?;
                    }
                }
                Ok(_) => break,
                Err(ConnectionError::Quiche(quiche::Error::Done)) => break,
                Err(e) => {
                    error!("Send failed: {:?}", e);
                    break;
                }
            }
        }

                conn.update_state();
                info!(
                    "client stats: RTT {:.0} ms, Loss {:.2}%",
                    conn.rtt_ms(),
                    conn.loss_rate() * 100.0
                );
                conn.conn.on_timeout();

                // Sleep to avoid busy-looping
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            } => {}
        }
    }

    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn run_server(
    listen_addr: &str,
    cert_path: &Path,
    key_path: &Path,
    profile: BrowserProfile,
    os: OsProfile,
    profile_seq: &Option<Vec<String>>,
    profile_interval: u64,
    fec_mode: FecMode,
    pool_capacity: usize,
    pool_block: usize,
    xdp: bool,
    xdp_stats: bool,
    config: &Option<PathBuf>,
    fec_config: &Option<PathBuf>,
    doh_provider: &str,
    front_domain: &[String],
    disable_doh: bool,
    disable_fronting: bool,
    disable_xor: bool,
    disable_http3: bool,
) -> std::io::Result<()> {
    let config_path = config.clone();
    let socket = std::net::UdpSocket::bind(listen_addr)?;
    socket.set_nonblocking(true)?;
    info!("Server listening on {}", listen_addr);

    if xdp_stats {
        tokio::spawn(async move {
            loop {
                info!(
                    "XDP tx: {} bytes, rx: {} bytes",
                    telemetry::XDP_BYTES_SENT.get(),
                    telemetry::XDP_BYTES_RECEIVED.get()
                );
                time::sleep(std::time::Duration::from_secs(1)).await;
            }
        });
    }

    let (mut fec_cfg, stealth_cfg, opt_cfg) = if let Some(cfg) = config_path.as_ref() {
        match AppConfig::from_file(cfg) {
            Ok(c) => {
                if let Err(e) = c.validate() {
                    warn!("Config validation failed: {}", e);
                }
                (c.fec, c.stealth, c.optimize)
            }
            Err(e) => {
                error!("Failed to load config {}: {}", cfg.display(), e);
                (
                    FecConfig::default(),
                    StealthConfig::default(),
                    OptimizeConfig::default(),
                )
            }
        }
    } else {
        let fec = if let Some(path) = fec_config {
            match FecConfig::from_file(path) {
                Ok(cfg) => {
                    if let Err(e) = cfg.validate() {
                        warn!("FEC config validation failed: {}", e);
                    }
                    cfg
                }
                Err(e) => {
                    error!("Failed to load FEC config {}: {}", path.display(), e);
                    FecConfig::default()
                }
            }
        } else {
            FecConfig::default()
        };
        (fec, StealthConfig::default(), OptimizeConfig::default())
    };
    fec_cfg.initial_mode = fec_mode;

    let mut config = match quiche::Config::new(quiche::PROTOCOL_VERSION) {
        Ok(c) => c,
        Err(e) => {
            error!("Failed to create quiche server config: {}", e);
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "quiche server config init failed",
            ));
        }
    };
    match cert_path.to_str() {
        Some(s) => {
            if let Err(e) = config.load_cert_chain_from_pem_file(s) {
                error!("Failed to load server cert {}: {}", cert_path.display(), e);
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "invalid certificate path",
                ));
            }
        }
        None => {
            error!(
                "Certificate path is not valid UTF-8: {}",
                cert_path.display()
            );
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "invalid certificate path",
            ));
        }
    }
    match key_path.to_str() {
        Some(s) => {
            if let Err(e) = config.load_priv_key_from_pem_file(s) {
                error!("Failed to load server key {}: {}", key_path.display(), e);
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "invalid private key path",
                ));
            }
        }
        None => {
            error!(
                "Private key path is not valid UTF-8: {}",
                key_path.display()
            );
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "invalid private key path",
            ));
        }
    }
    if let Err(e) = config.set_application_protos(&[
        b"\x0ahq-interop",
        b"\x05h3-29",
        b"\x05h3-28",
        b"\x05h3-27",
        b"\x08http/0.9",
    ]) {
        warn!("Failed to set application protos: {}", e);
    }
    config.set_max_idle_timeout(30000);
    config.set_max_recv_udp_payload_size(1460);
    config.set_max_send_udp_payload_size(1200);
    config.set_initial_max_data(10_000_000);
    config.set_initial_max_stream_data_bidi_local(1_000_000);
    config.set_initial_max_stream_data_bidi_remote(1_000_000);
    config.set_initial_max_streams_bidi(100);
    config.set_initial_max_streams_uni(100);

    let mut clients: HashMap<std::net::SocketAddr, QuicFuscateConnection> = HashMap::new();
    let mut buf = [0; 65535];
    let mut out = [0; 1460];
    let initial_sc = stealth_cfg.clone();
    let stealth_config = Arc::new(Mutex::new(initial_sc));
    {
        let mut sc = match stealth_config.lock() {
            Ok(g) => g,
            Err(p) => {
                warn!("stealth_config mutex poisoned; recovering inner state");
                p.into_inner()
            }
        };
        sc.browser_profile = profile;
        sc.os_profile = os;
        sc.enable_doh = !disable_doh;
        sc.doh_provider = doh_provider.to_string();
        sc.enable_domain_fronting = !disable_fronting;
        sc.fronting_domains = front_domain.to_vec();
        sc.enable_xor_obfuscation = !disable_xor;
        sc.enable_http3_masquerading = !disable_http3;
        telemetry!(telemetry::STEALTH_BROWSER_PROFILE.set(sc.browser_profile as i64));
        telemetry!(telemetry::STEALTH_OS_PROFILE.set(sc.os_profile as i64));
    }
    let opt_params = if config_path.is_some() {
        OptimizeConfig {
            pool_capacity: opt_cfg.pool_capacity,
            block_size: opt_cfg.block_size,
            enable_xdp: opt_cfg.enable_xdp || xdp,
        }
    } else {
        OptimizeConfig {
            pool_capacity,
            block_size: pool_block,
            enable_xdp: xdp,
        }
    };

    let profiles: Vec<FingerprintProfile> = match profile_seq {
        Some(seq) => seq
            .iter()
            .filter_map(|s| parse_profile_entry(s, os))
            .collect(),
        None => vec![FingerprintProfile::new(profile, os)],
    };

    if profile_interval > 0 && profiles.is_empty() {
        error!("No valid profiles supplied with --profile-seq");
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "invalid profile sequence",
        ));
    }

    if profile_interval > 0 && profiles.len() > 1 {
        let cfg = stealth_config.clone();
        tokio::spawn(async move {
            let mut idx = 0usize;
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(profile_interval)).await;
                idx = (idx + 1) % profiles.len();
                let mut guard = match cfg.lock() {
                    Ok(g) => g,
                    Err(p) => {
                        warn!("stealth_config mutex poisoned; recovering inner state");
                        p.into_inner()
                    }
                };
                guard.browser_profile = profiles[idx].browser;
                guard.os_profile = profiles[idx].os;
            }
        });
    }

    let shutdown = signal::ctrl_c();
    tokio::pin!(shutdown);

    loop {
        tokio::select! {
            _ = &mut shutdown => {
                info!("Shutdown signal received");
                for conn in clients.values_mut() {
                    let _ = conn.conn.close(true, 0x0, b"ctrl_c");
                }
                break;
            }
            _ = async {
                match socket.recv_from(&mut buf) {
            Ok((len, from)) => {
                telemetry!(telemetry::BYTES_RECEIVED.inc_by(len as u64));
                info!("Received {} bytes from {}", len, from);
                let client_conn_opt: Option<&mut QuicFuscateConnection> = if let std::collections::hash_map::Entry::Occupied(entry) = clients.entry(from) {
                    Some(entry.into_mut())
                } else {
                    info!("New client connected: {}", from);
                    let scid = quiche::ConnectionId::from_ref(&[0; quiche::MAX_CONN_ID_LEN]);
                    let cfg = match stealth_config.lock() {
                        Ok(g) => g,
                        Err(p) => {
                            warn!("stealth_config mutex poisoned; recovering inner state");
                            p.into_inner()
                        }
                    }
                    .clone();
                    match QuicFuscateConnection::new_server(
                        &scid,
                        None,
                        match socket.local_addr() {
                            Ok(a) => a,
                            Err(e) => {
                                error!("socket.local_addr() failed: {} — using unspecified address", e);
                                std::net::SocketAddr::from(([0, 0, 0, 0], 0))
                            }
                        },
                        from,
                        &mut config,
                        cfg,
                        fec_cfg.clone(),
                        opt_params,
                    ) {
                        Ok(conn) => Some(clients.entry(from).or_insert(conn)),
                        Err(e) => {
                            error!("failed to create server connection: {}", e);
                            None
                        }
                    }
                };

                if let Some(client_conn) = client_conn_opt {
                    if let Err(e) = client_conn.recv(&buf[..len]) {
                        error!("QUIC recv failed: {:?}", e);
                    }

                    if let Err(e) = client_conn.poll_http3() {
                        warn!("HTTP/3 error: {:?}", e);
                    }
                }
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                // No packets to read
            }
            Err(e) => {
                error!("Failed to read from socket: {}", e);

            }
        }

        // Send packets for all clients
        for (addr, conn) in clients.iter_mut() {
            loop {
                match conn.send(&mut out) {
                    Ok(len) if len > 0 => {
                        telemetry!(telemetry::BYTES_SENT.inc_by(len as u64));
                        if let Err(e) = socket.send_to(&out[..len], addr) {
                            error!("Failed to send packet to {}: {}", addr, e);
                        }
                    }
                    Ok(_) => break,
                    Err(ConnectionError::Quiche(quiche::Error::Done)) => break,
                    Err(e) => {
                        error!("Send failed to {}: {:?}", addr, e);
                        break;
                    }
                }
            }
            conn.update_state();
            info!(
                "client {} stats: RTT {:.0} ms, Loss {:.2}%",
                addr,
                conn.rtt_ms(),
                conn.loss_rate() * 100.0
            );
            conn.conn.on_timeout();
        }

                // Clean up closed connections
                clients.retain(|_, conn| !conn.conn.is_closed());

                // Sleep to avoid busy-looping
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            } => {}
        }
    }

    Ok(())
}
