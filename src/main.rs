use clap::{Args, Parser, Subcommand};
use log::{error, info, warn};
use quicfuscate::app_config::AppConfig;
use quicfuscate::core::QuicFuscateConnection;
use quicfuscate::error::ConnectionError;
#[cfg(feature = "benches")]
use quicfuscate::fec::FecMode as RuntimeFecMode;
#[cfg(feature = "benches")]
use quicfuscate::fec::FecPacket;
use quicfuscate::fec::{AdaptiveFec, FecConfig};
use quicfuscate::implementations::server::ServerRuntime;
use quicfuscate::optimize::OptimizationManager;
use quicfuscate::optimize::OptimizeConfig;
#[cfg(unix)]
use quicfuscate::optimize::ZeroCopyBuffer;
use quicfuscate::stealth::StealthConfig;
use quicfuscate::stealth::TlsClientHelloSpoofer;
use quicfuscate::stealth::{BrowserProfile, FingerprintProfile, OsProfile};
use quicfuscate::telemetry;
#[cfg(feature = "benches")]
use std::collections::VecDeque;
use std::net::ToSocketAddrs;
use std::path::Path;
use std::path::PathBuf;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::sync::OnceLock;
#[cfg(feature = "benches")]
use std::time::Instant;
use tokio::io::Interest;
use tokio::time::{interval, Duration, MissedTickBehavior};

static ADMIN_LOG_BUFFER: OnceLock<
    Arc<quicfuscate::implementations::server::admin_logs::AdminLogBuffer>,
> = OnceLock::new();

const DEFAULT_RUNTIME_SNI_HOST: &str = "cdn.cloudflare.com";
const DEFAULT_RUNTIME_URL: &str = "https://cloudflare-dns.com/";

#[cfg(test)]
mod qkey_auth_tests {
    use super::*;
    use quicfuscate::engine::qkey;
    use quicfuscate::implementations::server::qkey_registry::qkey_id as registry_qkey_id;

    #[test]
    fn require_qkey_for_new_clients_is_strict_by_default() {
        assert!(quicfuscate::implementations::server::require_qkey_for_new_clients());
    }

    #[test]
    fn engine_qkey_id_matches_registry_qkey_id() {
        let cfg = qkey::QKeyConfig::new("127.0.0.1:4433", DEFAULT_RUNTIME_SNI_HOST)
            .with_stealth("auto")
            .with_fec("auto")
            .with_token("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        let qkey_value = qkey::generate(&cfg);
        assert_eq!(qkey::id(&qkey_value), registry_qkey_id(&qkey_value));
    }
}

#[cfg(all(test, feature = "rate_limiter"))]
mod rate_limiter_env_tests {
    use super::*;
    use std::sync::{Mutex, OnceLock};

    fn with_rate_limit_env<T>(
        pps: Option<&str>,
        bps: Option<&str>,
        refill_ms: Option<&str>,
        f: impl FnOnce() -> T,
    ) -> T {
        static ENV_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        let _guard =
            ENV_LOCK.get_or_init(|| Mutex::new(())).lock().unwrap_or_else(|e| e.into_inner());

        let prev_pps = std::env::var("QUICFUSCATE_RATE_LIMIT_PPS").ok();
        let prev_bps = std::env::var("QUICFUSCATE_RATE_LIMIT_BPS").ok();
        let prev_refill = std::env::var("QUICFUSCATE_RATE_LIMIT_REFILL_MS").ok();

        match pps {
            Some(v) => std::env::set_var("QUICFUSCATE_RATE_LIMIT_PPS", v),
            None => std::env::remove_var("QUICFUSCATE_RATE_LIMIT_PPS"),
        }
        match bps {
            Some(v) => std::env::set_var("QUICFUSCATE_RATE_LIMIT_BPS", v),
            None => std::env::remove_var("QUICFUSCATE_RATE_LIMIT_BPS"),
        }
        match refill_ms {
            Some(v) => std::env::set_var("QUICFUSCATE_RATE_LIMIT_REFILL_MS", v),
            None => std::env::remove_var("QUICFUSCATE_RATE_LIMIT_REFILL_MS"),
        }

        let out = f();

        match prev_pps {
            Some(v) => std::env::set_var("QUICFUSCATE_RATE_LIMIT_PPS", v),
            None => std::env::remove_var("QUICFUSCATE_RATE_LIMIT_PPS"),
        }
        match prev_bps {
            Some(v) => std::env::set_var("QUICFUSCATE_RATE_LIMIT_BPS", v),
            None => std::env::remove_var("QUICFUSCATE_RATE_LIMIT_BPS"),
        }
        match prev_refill {
            Some(v) => std::env::set_var("QUICFUSCATE_RATE_LIMIT_REFILL_MS", v),
            None => std::env::remove_var("QUICFUSCATE_RATE_LIMIT_REFILL_MS"),
        }

        out
    }

    #[test]
    fn rate_limit_env_overrides_are_applied() {
        with_rate_limit_env(Some("777"), Some("888"), Some("250"), || {
            let cfg = quicfuscate::implementations::server::load_rate_limit_config_from_env();
            assert_eq!(cfg.max_pps, 777);
            assert_eq!(cfg.max_bps, 888);
            assert_eq!(cfg.refill_interval, Duration::from_millis(250));
        });
    }

    #[test]
    fn rate_limit_env_invalid_values_fallback_to_defaults() {
        with_rate_limit_env(Some("0"), Some("NaN"), Some("0"), || {
            let cfg = quicfuscate::implementations::server::load_rate_limit_config_from_env();
            let defaults = quicfuscate::implementations::server::RateLimitConfig::default();
            assert_eq!(cfg.max_pps, defaults.max_pps);
            assert_eq!(cfg.max_bps, defaults.max_bps);
            assert_eq!(cfg.refill_interval, defaults.refill_interval);
        });
    }
}

#[cfg(unix)]
async fn recv_connected_datagram(
    socket: &tokio::net::UdpSocket,
    buf: &mut [u8],
) -> std::io::Result<usize> {
    use std::io::Error;
    use std::os::unix::io::AsRawFd;

    // Use `async_io` to avoid edge-triggered busy-loop (same fix as server).
    let fd = socket.as_raw_fd();
    socket
        .async_io(Interest::READABLE, || {
            let mut slice = [&mut buf[..]];
            let mut zc = ZeroCopyBuffer::new_mut(&mut slice);
            let rc = zc.recv(fd);
            if rc >= 0 {
                Ok(rc as usize)
            } else {
                Err(Error::last_os_error())
            }
        })
        .await
}

#[cfg(not(unix))]
async fn recv_connected_datagram(
    socket: &tokio::net::UdpSocket,
    buf: &mut [u8],
) -> std::io::Result<usize> {
    loop {
        socket.ready(Interest::READABLE).await?;
        match socket.try_recv(buf) {
            Ok(len) => return Ok(len),
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => continue,
            Err(e) => return Err(e),
        }
    }
}

#[cfg(unix)]
async fn send_connected_datagram(
    socket: &tokio::net::UdpSocket,
    data: &[u8],
) -> std::io::Result<()> {
    use std::io::Error;
    use std::os::unix::io::AsRawFd;

    // Use `async_io` to avoid edge-triggered busy-loop (same fix as recv).
    let fd = socket.as_raw_fd();
    socket
        .async_io(Interest::WRITABLE, || {
            let zc = ZeroCopyBuffer::new(&[data]);
            let rc = zc.send(fd);
            if rc >= 0 {
                if rc as usize == data.len() {
                    Ok(())
                } else {
                    Err(std::io::Error::new(std::io::ErrorKind::WriteZero, "partial datagram send"))
                }
            } else {
                Err(Error::last_os_error())
            }
        })
        .await
}

#[cfg(not(unix))]
async fn send_connected_datagram(
    socket: &tokio::net::UdpSocket,
    data: &[u8],
) -> std::io::Result<()> {
    loop {
        socket.ready(Interest::WRITABLE).await?;
        match socket.try_send(data) {
            Ok(len) if len == data.len() => return Ok(()),
            Ok(_) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::WriteZero,
                    "partial datagram send",
                ))
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => continue,
            Err(e) => return Err(e),
        }
    }
}

async fn flush_connected_outgoing(
    socket: &tokio::net::UdpSocket,
    conn: &mut QuicFuscateConnection,
    out: &mut [u8],
) -> std::io::Result<()> {
    loop {
        match conn.send(out) {
            Ok(len) if len > 0 => {
                telemetry!(quicfuscate::telemetry::BYTES_SENT.inc_by(len as u64));
                send_connected_datagram(socket, &out[..len]).await?;
            }
            Ok(_) => break,
            Err(ConnectionError::Done) => break,
            Err(e) => {
                log::error!("Send failed: {:?}", e);
                break;
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tokio_udp_tests {
    use super::*;
    use std::time::Duration;
    use tokio::time::timeout;

    async fn bind_pair() -> std::io::Result<(tokio::net::UdpSocket, tokio::net::UdpSocket)> {
        let server = tokio::net::UdpSocket::bind("127.0.0.1:0").await?;
        let client = tokio::net::UdpSocket::bind("127.0.0.1:0").await?;
        let server_addr = server.local_addr()?;
        let client_addr = client.local_addr()?;
        client.connect(server_addr).await?;
        server.connect(client_addr).await?;
        Ok((server, client))
    }

    #[tokio::test]
    async fn zero_copy_connected_roundtrip() -> Result<(), Box<dyn std::error::Error>> {
        let (server, client) = bind_pair().await?;
        let payload = b"tokio-connected";
        send_connected_datagram(&client, payload).await?;
        let mut buf = [0u8; 64];
        let len =
            timeout(Duration::from_secs(1), recv_connected_datagram(&server, &mut buf)).await??;
        assert_eq!(&buf[..len], payload);
        Ok(())
    }

    #[tokio::test]
    async fn zero_copy_unconnected_roundtrip() -> Result<(), Box<dyn std::error::Error>> {
        let server = tokio::net::UdpSocket::bind("127.0.0.1:0").await?;
        let client = tokio::net::UdpSocket::bind("127.0.0.1:0").await?;
        let server_addr = server.local_addr()?;
        let client_addr = client.local_addr()?;

        let payload = b"tokio-unconnected";
        quicfuscate::implementations::server::send_live_datagram_to(&client, &server_addr, payload)
            .await?;
        let mut buf = [0u8; 64];
        let (len, from) = timeout(Duration::from_secs(1), server.recv_from(&mut buf)).await??;
        assert_eq!(from, client_addr);
        assert_eq!(&buf[..len], payload);
        Ok(())
    }
}
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
#[command(propagate_version = true)]
struct Cli {
    /// Enable verbose logging
    #[arg(short, long, global = true)]
    verbose: bool,
    /// Enable telemetry metrics
    #[arg(long, global = true)]
    telemetry: bool,
    #[command(subcommand)]
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
    map.insert("duration_ms".into(), json!((duration_secs * 1000.0).max(0.0)));
    let rate = if duration_secs > 0.0 { (items as f64) / duration_secs } else { 0.0 };
    map.insert("rate_ops".into(), json!(rate));
    map.insert("os".into(), json!(std::env::consts::OS));
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    map.insert("timestamp".into(), json!(ts));
    map.insert("git_rev".into(), json!(option_env!("QUICFUSCATE_GIT_REV").unwrap_or("n/a")));
    map.insert("cpu_model".into(), json!(option_env!("QUICFUSCATE_CPU_MODEL").unwrap_or("n/a")));
    map.insert("rustc".into(), json!(option_env!("QUICFUSCATE_RUSTC_VERSION").unwrap_or("n/a")));
}

#[cfg(feature = "benches")]
fn run_fec_bench(
    packets: usize,
    payload: usize,
    mode: RuntimeFecMode,
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
        let opt = OptimizationManager::new_with_config(pool_capacity, block_size);
        let mem_pool = opt.memory_pool();
        let cfg = FecConfig { initial_mode: mode, ..Default::default() };
        // fresh FEC per run for fairness
        let mut fec = AdaptiveFec::new(cfg);
        let mut out = VecDeque::with_capacity(256);

        // small helper to make packet with payload bytes; id increments
        let mut id: u64 = 1;
        let make_pkt = |id: u64| -> FecPacket {
            let mut block = opt.alloc_block();
            if !block.is_empty() {
                block[0] = 1;
            }
            let len = payload.min(block.len());
            if len > 8 {
                block[1] = (id & 0xff) as u8;
                block[2] = ((id >> 8) & 0xff) as u8;
                block[3] = ((id >> 16) & 0xff) as u8;
                block[4] = ((id >> 24) & 0xff) as u8;
            }
            FecPacket::new(id, Some(block), len, true, None, 0, mem_pool.clone())
        };

        // optional warmup
        for _ in 0..warmup {
            let p = make_pkt(id);
            id += 1;
            for pkt in fec.on_send(p) {
                out.push_back(pkt);
            }
            // drain emitted to keep memory bounded
            while let Some(_q) = out.pop_front() {}
        }

        let start = Instant::now();
        for _ in 0..packets {
            let p = make_pkt(id);
            id += 1;
            for pkt in fec.on_send(p) {
                out.push_back(pkt);
            }
            while let Some(_q) = out.pop_front() {}
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
        map.insert("mode".into(), serde_json::json!(format!("{:?}", mode).to_lowercase()));
        map.insert("seq_seconds".into(), serde_json::json!(t_seq));
        map.insert("par_seconds".into(), serde_json::json!(t_par));
        map.insert("seq_pps".into(), serde_json::json!((n_seq as f64 / t_seq).max(0.0)));
        map.insert("par_pps".into(), serde_json::json!((n_par as f64 / t_par).max(0.0)));
        println!("{}", serde_json::Value::Object(map));
    } else {
        println!("[FEC-BENCH] packets={}, payload={}B, mode={:?}", packets, payload, mode);
        println!(" sequential: {:.3}s  ({:.0} pkt/s)", t_seq, (n_seq as f64 / t_seq).round());
        println!("   parallel: {:.3}s  ({:.0} pkt/s)", t_par, (n_par as f64 / t_par).round());
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
    let opt = OptimizationManager::new_with_config(pool_capacity, block_size);
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
        println!("{}", serde_json::Value::Object(map));
    } else {
        let rate = if elapsed > 0.0 { iterations as f64 / elapsed } else { 0.0 };
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
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, "payload must be > 0"));
    }

    // deterministic input generator (LCG)
    let mut seed: u64 = 0x9E3779B97F4A7C15;
    let mut make_buf = || {
        let mut v = vec![0u8; payload];
        for (i, x) in v.iter_mut().enumerate() {
            seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
            *x = (seed >> 32) as u8 ^ (i as u8);
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
        insert_bench_metadata(&mut map, "crypto-bench", iterations, payload, warmup, elapsed);
        map.insert("mode".into(), serde_json::json!(format!("{:?}", mode).to_lowercase()));
        map.insert("checksum".into(), serde_json::json!(format!("0x{:016x}", checksum)));
        println!("{}", serde_json::Value::Object(map));
    } else {
        let rate = if elapsed > 0.0 { iterations as f64 / elapsed } else { 0.0 };
        println!("[CRYPTO-BENCH] iters={}, payload={}B, mode={:?}", iterations, payload, mode);
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
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, "payload must be > 0"));
    }

    let mut seed: u64 = 0xD6E8FEB86659FD93;
    let mut gen_packet = || {
        let mut v = vec![0u8; payload];
        for (i, x) in v.iter_mut().enumerate() {
            seed ^= seed << 7;
            seed ^= seed >> 9;
            *x = (seed as u8).wrapping_add(i as u8);
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
        println!("{}", serde_json::Value::Object(map));
    } else {
        let rate = if elapsed > 0.0 { iterations as f64 / elapsed } else { 0.0 };
        println!("[NET-BENCH] iters={}, payload={}B", iterations, payload);
        println!(" elapsed: {:.3}s  ({:.0} ops/s) bytes_moved={} ", elapsed, rate.round(), moved);
    }
    Ok(())
}

/// Congestion control algorithms selectable via CLI.
#[derive(Copy, Clone, Debug, Eq, PartialEq, clap::ValueEnum)]
enum CcAlgorithm {
    #[clap(name = "reno")]
    Reno,
    #[clap(name = "bbr2")]
    Bbr2,
    #[clap(name = "bbr3")]
    Bbr3,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, clap::ValueEnum)]
enum CliFecMode {
    #[clap(name = "off")]
    Off,
    #[clap(name = "auto")]
    Auto,
}

fn resolve_cli_fec_mode_override(mode: Option<CliFecMode>) -> Option<quicfuscate::engine::FecMode> {
    mode.map(|mode| match mode {
        CliFecMode::Off => quicfuscate::engine::FecMode::Off,
        CliFecMode::Auto => quicfuscate::engine::FecMode::Auto,
    })
}

impl From<CcAlgorithm> for quicfuscate::transport::CongestionControlAlgorithm {
    fn from(cc: CcAlgorithm) -> Self {
        match cc {
            CcAlgorithm::Reno => quicfuscate::transport::CongestionControlAlgorithm::Reno,
            CcAlgorithm::Bbr2 => quicfuscate::transport::CongestionControlAlgorithm::BBR2,
            CcAlgorithm::Bbr3 => quicfuscate::transport::CongestionControlAlgorithm::BBR3,
        }
    }
}

/// Shared CLI arguments used by both client and server subcommands.
#[derive(Args, Clone, Debug)]
struct SharedArgs {
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

    /// FEC mode (auto or off)
    #[clap(long, value_enum)]
    fec_mode: Option<CliFecMode>,

    /// Memory pool capacity (number of blocks)
    #[clap(long, default_value_t = 1024)]
    pool_capacity: usize,

    /// Memory pool block size in bytes
    #[clap(long, default_value_t = 4096)]
    pool_block: usize,

    // XDP is compatibility-only in this branch and maps to UDP/io_uring fast paths
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

    /// Disable HTTP/3 masquerading
    #[clap(long)]
    disable_http3: bool,

    /// Congestion control algorithm
    #[clap(long, value_enum, default_value = "bbr3")]
    cc_algorithm: CcAlgorithm,

    /// Enable TUN bridging (experimental)
    #[clap(long)]
    tun: bool,

    /// TUN interface name (optional)
    #[clap(long)]
    tun_name: Option<String>,

    /// TUN MTU
    #[clap(long)]
    tun_mtu: Option<u16>,

    /// TUN IP address
    #[clap(long)]
    tun_ip: Option<String>,

    /// TUN netmask
    #[clap(long)]
    tun_netmask: Option<String>,
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
        #[clap(short, long, default_value = "https://cloudflare-dns.com/")]
        url: String,

        #[command(flatten)]
        shared: SharedArgs,

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
        /// QKey string used to authenticate with the server (provides the
        /// x-qf-auth bearer token). When omitted, the client connects without
        /// a QKey token and will be rejected by servers that require one.
        #[clap(long, value_name = "QKEY")]
        qkey: Option<String>,
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

        #[command(flatten)]
        shared: SharedArgs,

        /// Admin control socket (unix only)
        #[clap(long, value_name = "PATH")]
        admin_socket: Option<PathBuf>,

        /// Metrics HTTP port (optional)
        #[clap(long)]
        metrics_port: Option<u16>,

        /// Admin web server bind address (e.g. 127.0.0.1:9000)
        #[clap(long)]
        admin_web: Option<std::net::SocketAddr>,

        /// Admin web static root (default: assets/web-admin)
        #[clap(long, value_name = "PATH", default_value = "assets/web-admin")]
        admin_web_root: PathBuf,

        /// Admin web username (required when --admin-web is set)
        #[clap(long)]
        admin_web_user: Option<String>,

        /// Admin web password (required when --admin-web is set)
        #[clap(long)]
        admin_web_password: Option<String>,

        /// Default QKey TTL in seconds (0 disables expiration)
        #[clap(long)]
        qkey_ttl_secs: Option<u64>,

        /// QKey registry store path (defaults near config or ./config/local/qkeys.json)
        #[clap(long, value_name = "PATH")]
        qkey_store: Option<PathBuf>,
    },
    #[clap(hide = true)]
    CrossFadeSim {},
    #[clap(hide = true)]
    HighLossSim {},
    #[clap(hide = true)]
    OptimizeProbe {},
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
        /// Internal runtime FEC mode/window profile to benchmark
        #[clap(long, value_enum, default_value = "normal")]
        mode: RuntimeFecMode,
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

fn main() -> std::io::Result<()> {
    // Quick CLI parse before full async startup (must happen before Tokio runtime
    // because std::env::set_var is unsafe in multi-threaded contexts since Rust 1.66).
    let args: Vec<String> = std::env::args().collect();
    let worker_threads = {
        let mut threads = 8usize; // default
        if let Some(pos) = args.iter().position(|a| a == "--config") {
            if let Some(cfg_path) = args.get(pos + 1) {
                if let Ok(content) = std::fs::read_to_string(cfg_path) {
                    if let Ok(engine_cfg) = quicfuscate::engine::EngineConfig::from_toml(&content) {
                        if engine_cfg.optimization.num_worker_threads > 0 {
                            threads = engine_cfg.optimization.num_worker_threads;
                        }
                    }
                }
            }
        }
        threads
    };
    if args.iter().any(|a| a == "--verbose" || a == "-v") {
        std::env::set_var("RUST_LOG", "info");
    }
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(worker_threads)
        .enable_all()
        .build()?;
    runtime.block_on(async_main())
}

async fn async_main() -> std::io::Result<()> {
    let cli = Cli::parse();
    let admin_log_buffer =
        Arc::new(quicfuscate::implementations::server::admin_logs::AdminLogBuffer::new(4096));
    if ADMIN_LOG_BUFFER.set(admin_log_buffer.clone()).is_err() {
        log::debug!("ADMIN_LOG_BUFFER already initialized, reusing existing buffer");
    }
    {
        use std::io::Write;
        // We keep the env_logger filter permissive (Trace) and let runtime mode changes
        // control effective verbosity via log::set_max_level.
        let mut builder = env_logger::Builder::new();
        builder.filter_level(log::LevelFilter::Trace);
        let buf = admin_log_buffer.clone();
        builder.format(move |fmt, record| {
            let msg = format!("{}", record.args());
            buf.push(record.level(), &msg);
            writeln!(fmt, "[{}] {}", record.level(), msg)
        });
        builder.init();
    }
    // Default runtime verbosity. Server and Admin UI may override via persisted log mode.
    log::set_max_level(log::LevelFilter::Info);

    // One-time validation of consolidated in-memory profiles.
    // Logs warnings for any profile that doesn't pass the sanity checks.
    {
        // Validate profiles using stealth module's TlsClientHelloSpoofer
        let results = quicfuscate::stealth::TlsClientHelloSpoofer::available_profiles()
            .into_iter()
            .map(|(b, o)| {
                // Simple validation - check if we can generate a ClientHello
                let ch =
                    quicfuscate::stealth::tls_cover::TlsCover::generate_client_hello(b, o, None);
                let res: Result<(), String> =
                    if ch.len() > 100 { Ok(()) } else { Err("ClientHello too short".into()) };
                (b, o, res)
            })
            .collect::<Vec<_>>();
        let mut failures = 0usize;
        for (b, o, res) in results {
            if let Err(e) = res {
                failures += 1;
                warn!("profile validation failed for {:?}/{:?}: {}", b, o, e);
            }
        }
        if failures > 0 {
            warn!("{} profile(s) had validation issues; proceeding with best-effort.", failures);
        } else {
            info!("All consolidated browser profiles passed validation.");
        }
    }
    if cli.telemetry {
        use quicfuscate::telemetry::TELEMETRY_ENABLED;
        TELEMETRY_ENABLED.store(true, Ordering::Relaxed);
        // Spawn minimal telemetry HTTP server at /telemetry
        quicfuscate::metrics::spawn_telemetry_server();
    }

    match cli.command {
        Commands::Client {
            remote,
            local,
            url,
            shared,
            ca_file,
            no_utls,
            debug_tls,
            list_fingerprints,
            verify_peer,
            qkey,
        } => {
            let fec_mode = resolve_cli_fec_mode_override(shared.fec_mode);
            run_client(
                remote.as_str(),
                local.as_str(),
                url.as_str(),
                shared.profile,
                shared.os,
                &shared.profile_seq,
                shared.profile_interval,
                fec_mode,
                shared.pool_capacity,
                shared.pool_block,
                &shared.config,
                &shared.fec_config,
                shared.doh_provider.as_str(),
                &shared.front_domain,
                &ca_file,
                no_utls,
                debug_tls,
                list_fingerprints,
                verify_peer,
                shared.disable_doh,
                shared.disable_fronting,
                shared.disable_http3,
                shared.cc_algorithm,
                shared.tun,
                shared.tun_name,
                shared.tun_mtu,
                shared.tun_ip,
                shared.tun_netmask,
                qkey.as_deref(),
            )
            .await?;
        }
        Commands::Server {
            listen,
            cert,
            key,
            shared,
            admin_socket,
            metrics_port,
            admin_web,
            admin_web_root,
            admin_web_user,
            admin_web_password,
            qkey_ttl_secs,
            qkey_store,
        } => {
            let fec_mode = resolve_cli_fec_mode_override(shared.fec_mode);
            run_server(
                listen.as_str(),
                cert.as_path(),
                key.as_path(),
                shared.profile,
                shared.os,
                &shared.profile_seq,
                shared.profile_interval,
                fec_mode,
                shared.pool_capacity,
                shared.pool_block,
                &shared.config,
                &shared.fec_config,
                shared.doh_provider.as_str(),
                &shared.front_domain,
                shared.disable_doh,
                shared.disable_fronting,
                shared.disable_http3,
                shared.cc_algorithm,
                shared.tun,
                shared.tun_name,
                shared.tun_mtu,
                shared.tun_ip,
                shared.tun_netmask,
                admin_socket,
                metrics_port,
                admin_web,
                admin_web_root,
                admin_web_user,
                admin_web_password,
                qkey_ttl_secs,
                qkey_store,
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
        #[cfg(feature = "benches")]
        Commands::FecBench { packets, payload, mode, pool_capacity, block_size, warmup, json } => {
            run_fec_bench(packets, payload, mode, pool_capacity, block_size, warmup, json)?;
        }
        #[cfg(feature = "benches")]
        Commands::PoolBench { iterations, payload, pool_capacity, block_size, warmup, json } => {
            run_pool_bench(iterations, payload, pool_capacity, block_size, warmup, json)?;
        }
        #[cfg(feature = "benches")]
        Commands::CryptoBench { iterations, payload, mode, warmup, json } => {
            run_crypto_bench(iterations, payload, mode, warmup, json)?;
        }
        #[cfg(feature = "benches")]
        Commands::NetBench { iterations, payload, warmup, json } => {
            run_net_bench(iterations, payload, warmup, json)?;
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

    use quicfuscate::telemetry::TELEMETRY_ENABLED;
    if TELEMETRY_ENABLED.load(Ordering::Relaxed) {
        quicfuscate::telemetry::flush();
    }
    Ok(())
}

fn run_crossfade_sim() -> std::io::Result<()> {
    println!("[compat] Cross-fade simulation starting...");
    let opt = OptimizationManager::new();
    let _mem_pool = opt.memory_pool();
    let mut fec = AdaptiveFec::new(FecConfig::default());
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
    println!("[compat] Cross-fade simulation complete. final mode: {:?}", last_mode);
    Ok(())
}

fn run_high_loss_sim() -> std::io::Result<()> {
    println!("[compat] High-loss simulation starting...");
    let opt = OptimizationManager::new();
    let _mem_pool = opt.memory_pool();
    let mut fec = AdaptiveFec::new(FecConfig::default());
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
    println!("[compat] High-loss simulation complete. final mode: {:?}", last_mode);
    Ok(())
}

fn run_optimize_probe() -> std::io::Result<()> {
    println!("[compat] Optimization probe starting...");
    let opt = OptimizationManager::new_with_config(64, 4096);
    println!(" xdp_compat_request_normalized=false active=false");
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
    println!("[compat] Optimization probe complete.");
    Ok(())
}

fn load_runtime_profiles(
    config_path: Option<&PathBuf>,
    fec_config: &Option<PathBuf>,
    fec_mode_override: Option<quicfuscate::engine::FecMode>,
) -> (FecConfig, StealthConfig, OptimizeConfig, quicfuscate::engine::AntiReplaySection) {
    let (mut fec, stealth, optimize, anti_replay) = if let Some(cfg) = config_path {
        match AppConfig::from_file(cfg) {
            Ok(c) => {
                if let Err(e) = c.validate() {
                    warn!("Config validation failed: {}", e);
                }
                quicfuscate::implementations::server::runtime_components_from_app_config(
                    c,
                    fec_mode_override,
                )
            }
            Err(e) => {
                error!("Failed to load config {}: {}", cfg.display(), e);
                (
                    FecConfig::product_default(),
                    StealthConfig::default(),
                    OptimizeConfig::default(),
                    quicfuscate::engine::AntiReplaySection::default(),
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
                    FecConfig::product_default()
                }
            }
        } else {
            FecConfig::product_default()
        };
        (
            fec,
            StealthConfig::default(),
            OptimizeConfig::default(),
            quicfuscate::engine::AntiReplaySection::default(),
        )
    };

    if let Some(mode) = fec_mode_override {
        fec.apply_engine_mode(mode);
    }

    (fec, stealth, optimize, anti_replay)
}

fn apply_runtime_transport_defaults(
    config: &mut quicfuscate::transport::Config,
    cc_algorithm: CcAlgorithm,
) {
    config.set_cc_algorithm(cc_algorithm.into());
    if let Err(e) =
        config.set_application_protos(&[b"hq-interop", b"h3-29", b"h3-28", b"h3-27", b"http/0.9"])
    {
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
}

fn runtime_optimize_config(
    config_path: Option<&PathBuf>,
    opt_cfg: OptimizeConfig,
    pool_capacity: usize,
    pool_block: usize,
    origin: &str,
) -> OptimizeConfig {
    if config_path.is_some() {
        quicfuscate::implementations::server::normalize_runtime_optimize_config(
            OptimizeConfig { pool_capacity: opt_cfg.pool_capacity, block_size: opt_cfg.block_size },
            origin,
        )
    } else {
        OptimizeConfig { pool_capacity, block_size: pool_block }
    }
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
    fec_mode: Option<quicfuscate::engine::FecMode>,
    pool_capacity: usize,
    pool_block: usize,
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
    disable_http3: bool,
    cc_algorithm: CcAlgorithm,
    tun_enable: bool,
    tun_name: Option<String>,
    tun_mtu: Option<u16>,
    tun_ip: Option<String>,
    tun_netmask: Option<String>,
    qkey: Option<&str>,
) -> std::io::Result<()> {
    let config_path = config.as_ref();
    if list_fingerprints {
        info!("Available browser fingerprints:");
        for (b, o) in TlsClientHelloSpoofer::available_profiles() {
            info!("- {}@{}", format!("{:?}", b).to_lowercase(), format!("{:?}", o).to_lowercase());
        }
        return Ok(());
    }

    let server_addr = remote_addr_str.to_socket_addrs()?.next().ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::NotFound, "Server address not found")
    })?;

    let local_addr = local_addr_str.to_socket_addrs()?.next().ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::AddrNotAvailable, "Local address invalid")
    })?;

    let std_socket = std::net::UdpSocket::bind(local_addr)?;
    std_socket.connect(server_addr)?;
    std_socket.set_nonblocking(true)?;
    let socket = tokio::net::UdpSocket::from_std(std_socket)?;

    info!("Client connecting to {}", server_addr);

    let (fec_cfg, mut stealth_config, opt_cfg, _) =
        load_runtime_profiles(config_path, fec_config, fec_mode);

    let mut config = match quicfuscate::transport::Config::new_with_version(
        quicfuscate::transport::PROTOCOL_VERSION,
    ) {
        Ok(c) => c,
        Err(e) => {
            error!("Failed to create transport config: {}", e);
            return Err(std::io::Error::other("transport config init failed"));
        }
    };
    apply_runtime_transport_defaults(&mut config, cc_algorithm);
    config.verify_peer(verify_peer);
    if debug_tls {
        warn!(
            "--debug-tls currently relies on QUICFUSCATE_TRACE_TLS tracing paths; transport keylog emission is not wired in this fork"
        );
    }
    if let Some(path) = ca_file {
        match path.to_str() {
            Some(s) => {
                if let Err(e) = config.load_verify_locations_from_file(s) {
                    error!("Failed to load CA file {}: {}", path.display(), e);
                }
                // Also set the global override so the rustls provider picks it up
                quicfuscate::qftls::set_tls_ca_path(s);
            }
            None => {
                error!("CA file path is not valid UTF-8: {}", path.display());
            }
        }
    }

    let url_parsed = match url::Url::parse(url) {
        Ok(u) => u,
        Err(e1) => {
            warn!("Invalid URL '{}': {}. Falling back to {}", url, e1, DEFAULT_RUNTIME_URL);
            match url::Url::parse(DEFAULT_RUNTIME_URL) {
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
    quicfuscate::implementations::server::apply_runtime_stealth_overrides(
        &mut stealth_config,
        profile,
        os,
        disable_doh,
        doh_provider,
        disable_fronting,
        front_domain,
        disable_http3,
    );

    let host = url_parsed.host_str().unwrap_or(DEFAULT_RUNTIME_SNI_HOST);
    let opt_params = runtime_optimize_config(
        config_path,
        opt_cfg,
        pool_capacity,
        pool_block,
        "client runtime config",
    );
    // Derive the QKey bearer token (x-qf-auth) from a supplied QKey string.
    // Servers that require a QKey reject clients without a valid token.
    let qkey_auth_token_hex = match qkey {
        Some(raw) if !raw.trim().is_empty() => match quicfuscate::engine::qkey::parse(raw.trim()) {
            Ok(parsed) => match parsed.token.as_deref().map(str::trim) {
                Some(tok) if !tok.is_empty() => Some(tok.to_string()),
                _ => {
                    error!("supplied --qkey does not contain a token");
                    return Err(std::io::Error::other("qkey missing token"));
                }
            },
            Err(e) => {
                error!("failed to parse --qkey: {}", e);
                return Err(std::io::Error::other("invalid qkey"));
            }
        },
        _ => None,
    };
    // Compute the 12-char QKey ID for the QUIC Initial packet token.
    let qkey_initial_token: Option<Vec<u8>> =
        qkey.map(|raw| quicfuscate::engine::qkey::id(raw.trim()).into_bytes());

    let mut conn = match QuicFuscateConnection::new_client(
        host,
        local_addr,
        server_addr,
        config,
        stealth_config.clone(),
        fec_cfg,
        opt_params,
        qkey_auth_token_hex,
        qkey_initial_token,
        !no_utls,
    ) {
        Ok(c) => c,
        Err(e) => {
            error!("failed to create client connection: {}", e);
            return Err(std::io::Error::other("client connection init failed"));
        }
    };

    let profiles: Vec<FingerprintProfile> = match profile_seq {
        Some(seq) => {
            quicfuscate::implementations::server::resolve_runtime_profiles(profile, os, seq, false)
        }
        None => {
            quicfuscate::implementations::server::resolve_runtime_profiles(profile, os, &[], true)
        }
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
            telemetry!(quicfuscate::telemetry::BYTES_SENT.inc_by(len as u64));
            if let Err(e) = send_connected_datagram(&socket, &out[..len]).await {
                error!("Failed to send initial packet: {}", e);
            } else {
                info!("Sent initial packet of size {}", len);
            }
        }
    }

    let mut request_sent = false;

    // Optional TUN bridging setup
    #[allow(clippy::type_complexity)]
    let (tun_rx, tun_writer, mut h3_stream_id): (
        Option<std::sync::mpsc::Receiver<Vec<u8>>>,
        Option<Arc<quicfuscate::interface::TunInterface>>,
        Option<u64>,
    ) = if tun_enable {
        let tcfg = quicfuscate::interface::TunConfig {
            name: tun_name,
            ip: tun_ip.and_then(|s| s.parse().ok()),
            netmask: tun_netmask.and_then(|s| s.parse().ok()),
            mtu: tun_mtu.unwrap_or(1500),
            ..Default::default()
        };
        let optm = OptimizationManager::from_cfg(opt_params);
        let pool = optm.memory_pool();
        match quicfuscate::interface::TunInterface::open(tcfg, pool.clone()) {
            Ok(tun) => {
                // Share the TUN via a plain Arc (no Mutex): read_block() and write()
                // both take &self and the kernel serializes the fd, so the blocking
                // reader thread must NOT hold a lock that would starve the downlink
                // writer (that deadlock left the tunnel one-directional).
                let tun = Arc::new(tun);
                // Install the MASQUE→TUN sink so downlink CONNECT-UDP datagrams
                // (decoded raw IP packets) are written to the client TUN by
                // drain_masque_datagrams inside poll_http3_event_loop.
                let tun_for_cb = tun.clone();
                conn.set_masque_datagram_cb(std::sync::Arc::new(std::sync::Mutex::new(Box::new(
                    move |payload: &[u8]| {
                        // Only write to TUN if the data looks like a valid IP packet
                        // (version 4 or 6 in the high nibble of the first byte).
                        // This filters out CONNECT-UDP capsule protocol data, which
                        // is not a raw IP packet and would cause EIO on TUN write.
                        if !payload.is_empty() && (payload[0] >> 4 == 4 || payload[0] >> 4 == 6) {
                            if let Err(e) = tun_for_cb.write(payload) {
                                warn!("Client TUN write (MASQUE downlink) failed: {:?}", e);
                            }
                        }
                    },
                ))));
                // Spawn a blocking reader thread that forwards TUN frames into a channel
                let (tx, rx) = std::sync::mpsc::channel::<Vec<u8>>();
                let tun_for_reader = tun.clone();
                std::thread::spawn(move || {
                    loop {
                        let read_result = tun_for_reader.read_block();
                        match read_result {
                            Ok((block, len)) if len > 0 => {
                                let mut v = vec![0u8; len];
                                v.copy_from_slice(&block[..len]);
                                if tx.send(v).is_err() {
                                    break;
                                }
                                // block freed when dropped
                            }
                            Ok(_) => {}
                            Err(_) => break,
                        }
                    }
                });
                (Some(rx), Some(tun), None)
            }
            Err(e) => {
                warn!("TUN open failed: {:?}", e);
                (None, None, None)
            }
        }
    } else {
        (None, None, None)
    };
    let mut housekeeping = interval(Duration::from_millis(5));
    housekeeping.set_missed_tick_behavior(MissedTickBehavior::Delay);

    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                info!("Shutdown signal received");
                if let Err(e) = conn.conn.close(true, 0x0, b"ctrl_c") {
                    warn!("Client close on ctrl_c failed: {:?}", e);
                }
                break;
            }
            recv_res = recv_connected_datagram(&socket, &mut buf) => {
                match recv_res {
                    Ok(len) => {
                        telemetry!(quicfuscate::telemetry::BYTES_RECEIVED.inc_by(len as u64));
                        if let Err(e) = conn.recv(&buf[..len]) {
                            error!("QUIC recv failed: {:?}", e);
                        } else if let Err(e) =
                            flush_connected_outgoing(&socket, &mut conn, &mut out).await
                        {
                            warn!("Failed to send response packet: {}", e);
                        }
                        // TUN uplink: forward frames from the TUN reader channel
                        // to the MASQUE data plane. This is done here (in the recv
                        // branch) rather than in the housekeeping branch because
                        // tokio::select! is not fair: when the peer constantly sends
                        // packets, the recv branch is always ready first and the
                        // housekeeping tick may never fire, starving the TUN uplink.
                        if tun_enable {
                            if let (Some(ref rx), Some(sid)) = (&tun_rx, h3_stream_id) {
                                for _ in 0..16 {
                                    match rx.try_recv() {
                                        Ok(frame) => {
                                            if let Err(e) = conn.http3_send_body_chunk(sid, &frame, false) {
                                                warn!("http3_send_body_chunk failed: {:?}", e);
                                                break;
                                            }
                                        }
                                        Err(std::sync::mpsc::TryRecvError::Empty) => break,
                                        Err(std::sync::mpsc::TryRecvError::Disconnected) => break,
                                    }
                                }
                            }
                            // Flush any outgoing packets generated by the body chunk sends.
                            if let Err(e) = flush_connected_outgoing(&socket, &mut conn, &mut out).await {
                                warn!("Failed to flush TUN uplink packets: {}", e);
                            }
                        }
                    }
                    Err(e) => {
                        error!("Failed to read from socket: {}", e);
                    }
                }
            }
            _ = housekeeping.tick() => {
                if conn.conn.is_established() && !request_sent {
                    match conn.send_http3_request(url_parsed.path()) {
                        Ok(_) => {
                            request_sent = true;
                        }
                        Err(e) => {
                            warn!("HTTP/3 request failed: {:?}", e);
                        }
                    }
                }

                if tun_enable {
                    if h3_stream_id.is_none() {
                        match conn.open_http3_stream_post("/tun") {
                            Ok(sid) => { h3_stream_id = Some(sid); }
                            Err(e) => { warn!("open_http3_stream_post failed: {:?}", e); }
                        }
                    }
                    // Downlink: H3 stream data from server → TUN interface
                    let tun_writer_ref = tun_writer.clone();
                    if let Err(e) = conn.poll_http3_with(move |data| {
                        if let Some(ref tw) = tun_writer_ref {
                            // Only write to TUN if the data looks like a valid IP packet.
                            if !data.is_empty() && (data[0] >> 4 == 4 || data[0] >> 4 == 6) {
                                if let Err(e) = tw.write(data) {
                                    warn!("Client TUN write (H3 downlink) failed: {:?}", e);
                                }
                            }
                        }
                    }) {
                        warn!("HTTP/3 poll in TUN mode failed: {:?}", e);
                    }
                    // MASQUE CONNECT-UDP downlink datagrams are drained and written
                    // to the TUN by drain_masque_datagrams (inside poll_http3_with
                    // above) via the masque_datagram_cb sink installed at TUN open.
                    // The previous bare dgram_recv loop expected unframed QUIC
                    // datagrams and has been removed in favor of the single
                    // consistent MASQUE transport.

                    // TUN uplink: forward frames from the TUN reader channel to
                    // the MASQUE data plane. Also done in the recv branch above,
                    // but tokio::select! is not fair and the recv branch may not
                    // fire when the server is silent. This ensures TUN frames are
                    // forwarded on every housekeeping tick (every 5ms).
                    if let (Some(ref rx), Some(sid)) = (&tun_rx, h3_stream_id) {
                        for _ in 0..16 {
                            match rx.try_recv() {
                                Ok(frame) => {
                                    if let Err(e) = conn.http3_send_body_chunk(sid, &frame, false) {
                                        warn!("http3_send_body_chunk failed: {:?}", e);
                                        break;
                                    }
                                }
                                Err(std::sync::mpsc::TryRecvError::Empty) => break,
                                Err(std::sync::mpsc::TryRecvError::Disconnected) => break,
                            }
                        }
                    }
                } else if let Err(e) = conn.poll_http3() {
                    warn!("HTTP/3 error: {:?}", e);
                }

                if let Err(e) = flush_connected_outgoing(&socket, &mut conn, &mut out).await {
                    warn!("Failed to flush outgoing packets: {}", e);
                }

                conn.update_state();
                info!(
                    "client stats: RTT {:.0} ms, Loss {:.2}%",
                    conn.rtt_ms(),
                    conn.loss_rate() * 100.0
                );
                // Only drive the idle timeout when the connection has actually been
                // idle; calling it every tick collapses cwnd and inflates loss.
                if conn.conn.idle_timeout_elapsed() {
                    conn.conn.on_timeout();
                }
                tokio::task::yield_now().await;
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod runtime_reload_tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::Mutex;

    #[test]
    fn normalize_runtime_optimize_config_preserves_runtime_values() {
        let normalized = quicfuscate::implementations::server::normalize_runtime_optimize_config(
            OptimizeConfig { pool_capacity: 64, block_size: 65_536 },
            "test",
        );
        assert_eq!(normalized.pool_capacity, 64);
        assert_eq!(normalized.block_size, 65_536);
    }

    #[test]
    fn load_runtime_profiles_applies_non_zero_fec_mode_without_config_file() {
        let (fec, stealth, optimize, _) = load_runtime_profiles(None, &None, None);
        let default_stealth = StealthConfig::default();
        let default_optimize = OptimizeConfig::default();
        assert_eq!(fec.initial_mode, quicfuscate::fec::FecMode::Normal);
        assert_eq!(stealth.initial_browser, default_stealth.initial_browser);
        assert_eq!(stealth.initial_os, default_stealth.initial_os);
        assert_eq!(stealth.enable_http3_masquerading, default_stealth.enable_http3_masquerading);
        assert_eq!(optimize.pool_capacity, default_optimize.pool_capacity);
        assert_eq!(optimize.block_size, default_optimize.block_size);
    }

    #[test]
    fn runtime_optimize_config_uses_cli_values_without_config_file() {
        let resolved = runtime_optimize_config(
            None,
            OptimizeConfig { pool_capacity: 1, block_size: 2 },
            96,
            32_768,
            "test",
        );
        assert_eq!(resolved.pool_capacity, 96);
        assert_eq!(resolved.block_size, 32_768);
    }

    fn write_temp_config(contents: &str) -> std::path::PathBuf {
        static NEXT_ID: AtomicU64 = AtomicU64::new(1);
        let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
        let mut dir = std::env::temp_dir();
        dir.push(format!(
            "qf-reload-test-{}-{}-{}",
            std::process::id(),
            id,
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_else(|_| Duration::from_secs(0))
                .as_millis()
        ));
        std::fs::create_dir_all(&dir).expect("create temp dir");
        let path = dir.join("server.toml");
        std::fs::write(&path, contents).expect("write config");
        path
    }

    #[test]
    fn runtime_config_reload_updates_shared_state_and_transport_overrides() {
        let cfg_path = write_temp_config(
            r#"
[fec]
mode = "auto"
initial_mode = "auto"
window_good = 10
window_fair = 30
window_poor = 50

[stealth]
mode = "max"
enable_doh = true
doh_provider = "https://example.invalid/dns-query"
enable_domain_fronting = true
enable_http3_masquerading = true

[optimization]
memory_pool_size = 7274496

[transport]
mtu = 1400
cc_algorithm = "bbr3"
enable_pacing = false
"#,
        );

        let fec_shared = Arc::new(Mutex::new(FecConfig::default()));
        let opt_shared = Arc::new(Mutex::new(OptimizeConfig::default()));
        let stealth_shared = Arc::new(Mutex::new(StealthConfig::default()));
        let mut transport = quicfuscate::transport::Config::new_with_version(
            quicfuscate::transport::PROTOCOL_VERSION,
        )
        .expect("transport config");

        // Keep runtime overrides strict to prove merge behavior.
        let front_domains = vec!["front.example".to_string()];
        quicfuscate::implementations::server::apply_runtime_config_reload(
            &cfg_path,
            Some(quicfuscate::engine::FecMode::Auto), // CLI override should win over config's initial mode
            &mut transport,
            &fec_shared,
            &opt_shared,
            &stealth_shared,
            quicfuscate::implementations::server::RuntimeStealthPolicy {
                profile: BrowserProfile::Chrome,
                os: OsProfile::MacOS,
                disable_doh: true, // disable DoH
                doh_provider: "runtime-doh",
                disable_fronting: true, // disable fronting
                front_domain: &front_domains,
                disable_http3: true, // disable http3 masquerade
            },
        )
        .expect("reload ok");

        let fec = fec_shared.lock().unwrap_or_else(|e| e.into_inner()).clone();
        assert_eq!(fec.initial_mode, quicfuscate::fec::FecMode::Normal);

        let opt = *opt_shared.lock().unwrap_or_else(|e| e.into_inner());
        assert_eq!(opt.pool_capacity, 111);
        assert_eq!(opt.block_size, 65_536);

        let sc = stealth_shared.lock().unwrap_or_else(|e| e.into_inner()).clone();
        assert_eq!(sc.initial_browser, BrowserProfile::Chrome);
        assert_eq!(sc.initial_os, OsProfile::MacOS);
        assert!(!sc.enable_doh);
        assert_eq!(sc.doh_provider, "runtime-doh");
        assert!(!sc.enable_domain_fronting);
        assert_eq!(sc.fronting_domains, front_domains);
        assert!(!sc.enable_http3_masquerading);

        assert_eq!(transport.max_udp_payload_size(), 1400);
        assert_eq!(
            transport.cc_algorithm(),
            quicfuscate::transport::CongestionControlAlgorithm::BBR3
        );
        assert!(!transport.pacing_enabled());
    }

    #[test]
    fn runtime_config_reload_rejects_invalid_transport_section() {
        let cfg_path = write_temp_config(
            r#"
[fec]
mode = "auto"
initial_mode = "auto"

[stealth]
mode = "auto"

[optimization]
memory_pool_size = 655360

[transport]
mtu = 100
"#,
        );

        let fec_shared = Arc::new(Mutex::new(FecConfig::default()));
        let opt_shared = Arc::new(Mutex::new(OptimizeConfig::default()));
        let stealth_shared = Arc::new(Mutex::new(StealthConfig::default()));
        let mut transport = quicfuscate::transport::Config::new_with_version(
            quicfuscate::transport::PROTOCOL_VERSION,
        )
        .expect("transport config");
        let before = transport.max_udp_payload_size();

        let err = quicfuscate::implementations::server::apply_runtime_config_reload(
            &cfg_path,
            Some(quicfuscate::engine::FecMode::Off),
            &mut transport,
            &fec_shared,
            &opt_shared,
            &stealth_shared,
            quicfuscate::implementations::server::RuntimeStealthPolicy {
                profile: BrowserProfile::Chrome,
                os: OsProfile::MacOS,
                disable_doh: false,
                doh_provider: "runtime-doh",
                disable_fronting: false,
                front_domain: &[],
                disable_http3: false,
            },
        )
        .unwrap_err();
        assert!(err.to_ascii_lowercase().contains("transport.mtu"));
        assert_eq!(transport.max_udp_payload_size(), before);
    }
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
    fec_mode: Option<quicfuscate::engine::FecMode>,
    pool_capacity: usize,
    pool_block: usize,
    config: &Option<PathBuf>,
    fec_config: &Option<PathBuf>,
    doh_provider: &str,
    front_domain: &[String],
    disable_doh: bool,
    disable_fronting: bool,
    disable_http3: bool,
    cc_algorithm: CcAlgorithm,
    tun_enable: bool,
    tun_name: Option<String>,
    tun_mtu: Option<u16>,
    tun_ip: Option<String>,
    tun_netmask: Option<String>,
    admin_socket: Option<PathBuf>,
    metrics_port: Option<u16>,
    admin_web: Option<std::net::SocketAddr>,
    admin_web_root: PathBuf,
    admin_web_user: Option<String>,
    admin_web_password: Option<String>,
    qkey_ttl_secs: Option<u64>,
    qkey_store: Option<PathBuf>,
) -> std::io::Result<()> {
    let config_path = config.as_ref();
    let config_path_ref = config_path.map(PathBuf::as_path);

    let (fec_cfg, stealth_cfg, opt_cfg, anti_replay_section) =
        load_runtime_profiles(config_path, fec_config, fec_mode);

    // Apply telemetry.enabled and logging.level from TOML config file when present.
    // CLI --telemetry flag (already applied above) takes precedence; config only adds enablement.
    if let Some(cfg_path) = config_path.as_ref() {
        if let Ok(content) = std::fs::read_to_string(cfg_path) {
            if let Ok(engine_cfg) = quicfuscate::engine::EngineConfig::from_toml(&content) {
                if engine_cfg.telemetry.enabled {
                    use quicfuscate::telemetry::TELEMETRY_ENABLED;
                    TELEMETRY_ENABLED.store(true, Ordering::Relaxed);
                }
                // Apply per-category telemetry export gates
                {
                    use quicfuscate::telemetry::{
                        COLLECT_CONGESTION_STATS, COLLECT_FEC_STATS, COLLECT_PACKET_STATS,
                        COLLECT_STEALTH_STATS, COLLECT_STREAM_STATS,
                    };
                    COLLECT_PACKET_STATS
                        .store(engine_cfg.telemetry.collect_packet_stats, Ordering::Relaxed);
                    COLLECT_STREAM_STATS
                        .store(engine_cfg.telemetry.collect_stream_stats, Ordering::Relaxed);
                    COLLECT_CONGESTION_STATS
                        .store(engine_cfg.telemetry.collect_congestion_stats, Ordering::Relaxed);
                    COLLECT_FEC_STATS
                        .store(engine_cfg.telemetry.collect_fec_stats, Ordering::Relaxed);
                    COLLECT_STEALTH_STATS
                        .store(engine_cfg.telemetry.collect_stealth_stats, Ordering::Relaxed);
                }
                // Apply logging config: effective() applies mode overrides (Verbose/Minimal/NoLog),
                // then engine.log_level overrides the result when explicitly different.
                let effective_logging = engine_cfg.logging.effective();
                let effective_level = if engine_cfg.engine.log_level != "info"
                    && engine_cfg.engine.log_level != effective_logging.level
                {
                    engine_cfg.engine.log_level.clone()
                } else {
                    effective_logging.level.clone()
                };
                let level_filter = match effective_level.to_ascii_lowercase().as_str() {
                    "error" => Some(log::LevelFilter::Error),
                    "warn" => Some(log::LevelFilter::Warn),
                    "info" => Some(log::LevelFilter::Info),
                    "debug" => Some(log::LevelFilter::Debug),
                    "trace" => Some(log::LevelFilter::Trace),
                    _ => None,
                };
                if let Some(filter) = level_filter {
                    log::set_max_level(filter);
                }
                // Apply log_to_stdout: when mode=no-log disables stdout, suppress output
                if !effective_logging.log_to_stdout {
                    log::set_max_level(log::LevelFilter::Off);
                }
            }
        }
    }

    let mut config = match quicfuscate::transport::Config::new_with_version(
        quicfuscate::transport::PROTOCOL_VERSION,
    ) {
        Ok(c) => c,
        Err(e) => {
            error!("Failed to create server transport config: {}", e);
            return Err(std::io::Error::other("server transport config init failed"));
        }
    };
    apply_runtime_transport_defaults(&mut config, cc_algorithm);
    quicfuscate::implementations::server::load_server_identity(&mut config, cert_path, key_path)?;

    if let Some(cfg_path) = config_path.as_ref() {
        quicfuscate::implementations::server::apply_transport_overrides_from_file(
            cfg_path,
            &mut config,
        );
    }

    let server_config =
        quicfuscate::implementations::server::server_config_from_listen_addr(listen_addr)
            .map_err(std::io::Error::other)?;
    let opt_params = runtime_optimize_config(
        config_path,
        opt_cfg,
        pool_capacity,
        pool_block,
        "server runtime config",
    );
    let profiles: Vec<FingerprintProfile> = match profile_seq {
        Some(seq) => {
            quicfuscate::implementations::server::resolve_runtime_profiles(profile, os, seq, false)
        }
        None => {
            quicfuscate::implementations::server::resolve_runtime_profiles(profile, os, &[], true)
        }
    };

    if profile_interval > 0 && profiles.is_empty() {
        error!("No valid profiles supplied with --profile-seq");
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "invalid profile sequence",
        ));
    }

    let standalone_tun_config = if tun_enable {
        Some(quicfuscate::interface::TunConfig {
            name: tun_name,
            ip: tun_ip.and_then(|s| s.parse().ok()),
            netmask: tun_netmask.and_then(|s| s.parse().ok()),
            mtu: tun_mtu.unwrap_or(1500),
            ..Default::default()
        })
    } else {
        None
    };
    let mut runtime = ServerRuntime::new_initialized_standalone_default(
        quicfuscate::engine::EngineConfig::default(),
        server_config,
        standalone_tun_config,
        opt_params,
        config_path_ref,
        ADMIN_LOG_BUFFER.get().cloned(),
        qkey_ttl_secs,
        qkey_store,
    )?;
    let fec_mode_override = fec_mode;
    let mut launch =
        quicfuscate::implementations::server::PreparedStandaloneLaunch::new_with_runtime_stealth(
            metrics_port,
            admin_socket,
            admin_web,
            admin_web_root,
            admin_web_user,
            admin_web_password,
            config_path.cloned(),
            config,
            fec_cfg,
            opt_params,
            stealth_cfg,
            fec_mode_override,
            profiles,
            profile_interval,
            quicfuscate::implementations::server::RuntimeStealthPolicy {
                profile,
                os,
                disable_doh,
                doh_provider,
                disable_fronting,
                front_domain,
                disable_http3,
            },
            tun_enable,
        );
    launch.set_anti_replay_section(anti_replay_section);
    let local_addr = runtime.local_addr();
    info!("Server listening on {}", local_addr);

    runtime.run_standalone(launch).await?;

    Ok(())
}
