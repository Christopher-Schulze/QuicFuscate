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
#[cfg(unix)]
use quicfuscate::optimize::ZeroCopyRecvBuffer;
use quicfuscate::stealth::StealthConfig;
use quicfuscate::stealth::TlsClientHelloProfileCatalog;
use quicfuscate::stealth::{BrowserProfile, FingerprintProfile, OsProfile};
use quicfuscate::stealth::StealthRuntimeOwner;
use quicfuscate::telemetry;
#[cfg(feature = "benches")]
use std::collections::VecDeque;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, ToSocketAddrs};
use std::path::Path;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::sync::OnceLock;
use std::time::Instant;
use tokio::io::Interest;
use tokio::time::{interval, Duration, MissedTickBehavior};

static ADMIN_LOG_BUFFER: OnceLock<
    Arc<quicfuscate::implementations::server::admin_logs::AdminLogBuffer>,
> = OnceLock::new();

#[cfg(test)]
const DEFAULT_RUNTIME_SNI_HOST: &str = "cdn.cloudflare.com";
const DEFAULT_RUNTIME_URL: &str = "https://cloudflare-dns.com/";
const CLIENT_RECV_DIAGNOSTICS_ENV: &str = "QUICFUSCATE_CLIENT_RECV_DIAGNOSTICS";

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct ClientIoDiagnostics {
    socket_datagrams: u64,
    socket_bytes: u64,
    core_recv_successes: u64,
    core_recv_errors: u64,
    activity_updates: u64,
    send_polls: u64,
    send_datagrams: u64,
    send_bytes: u64,
    send_zero_results: u64,
    send_done_results: u64,
    send_errors: u64,
    last_send_at: Option<Instant>,
}

impl ClientIoDiagnostics {
    fn record_socket_datagram(&mut self, bytes: usize) {
        self.socket_datagrams = self.socket_datagrams.saturating_add(1);
        self.socket_bytes = self.socket_bytes.saturating_add(bytes as u64);
    }

    fn record_core_recv_success(&mut self, activity_updated: bool) {
        self.core_recv_successes = self.core_recv_successes.saturating_add(1);
        if activity_updated {
            self.activity_updates = self.activity_updates.saturating_add(1);
        }
    }

    fn record_core_recv_error(&mut self) {
        self.core_recv_errors = self.core_recv_errors.saturating_add(1);
    }

    fn record_send_poll(&mut self) {
        self.send_polls = self.send_polls.saturating_add(1);
    }

    fn record_send_datagram(&mut self, bytes: usize) {
        self.send_datagrams = self.send_datagrams.saturating_add(1);
        self.send_bytes = self.send_bytes.saturating_add(bytes as u64);
        self.last_send_at = Some(Instant::now());
    }

    fn record_send_zero(&mut self) {
        self.send_zero_results = self.send_zero_results.saturating_add(1);
    }

    fn record_send_done(&mut self) {
        self.send_done_results = self.send_done_results.saturating_add(1);
    }

    fn record_send_error(&mut self) {
        self.send_errors = self.send_errors.saturating_add(1);
    }
}

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

/// Wait for a shutdown signal (SIGINT/SIGTERM on Unix, Ctrl+C on Windows).
async fn wait_shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let mut sigterm = match signal(SignalKind::terminate()) {
            Ok(s) => s,
            Err(e) => {
                warn!("Failed to install SIGTERM handler: {}, falling back to ctrl_c only", e);
                let _ = tokio::signal::ctrl_c().await;
                return;
            }
        };
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                info!("SIGINT received");
            }
            _ = sigterm.recv() => {
                info!("SIGTERM received");
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
        info!("Shutdown signal received");
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
            let mut zc = ZeroCopyRecvBuffer::new_mut(&mut slice).map_err(Error::from)?;
            let transfer = zc.recv(fd).map_err(Error::from)?;
            Ok(transfer.transferred())
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
            let zc = ZeroCopyBuffer::new(&[data]).map_err(Error::from)?;
            let transfer = zc.send(fd).map_err(Error::from)?;
            if transfer.is_complete() {
                Ok(())
            } else {
                Err(std::io::Error::new(std::io::ErrorKind::WriteZero, "partial datagram send"))
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
    mut diagnostics: Option<&mut ClientIoDiagnostics>,
) -> Result<(), quicfuscate::engine::DataPlaneFault> {
    for _ in 0..quicfuscate::transport::UDP_DATAGRAM_BURST_LIMIT {
        if let Some(diagnostics) = diagnostics.as_deref_mut() {
            diagnostics.record_send_poll();
        }
        match conn.send(out) {
            Ok(len) if len > 0 => {
                if let Some(diagnostics) = diagnostics.as_deref_mut() {
                    diagnostics.record_send_datagram(len);
                }
                send_connected_datagram(socket, &out[..len]).await.map_err(|error| {
                    quicfuscate::engine::DataPlaneFault::TransportSend {
                        component: "standalone client UDP socket".to_string(),
                        error: error.to_string(),
                    }
                })?;
                telemetry!(quicfuscate::telemetry::BYTES_SENT.inc_by(len as u64));
            }
            Ok(_) => {
                if let Some(diagnostics) = diagnostics.as_deref_mut() {
                    diagnostics.record_send_zero();
                }
                break;
            }
            Err(ConnectionError::Done) => {
                if let Some(diagnostics) = diagnostics.as_deref_mut() {
                    diagnostics.record_send_done();
                }
                break;
            }
            Err(e) => {
                if let Some(diagnostics) = diagnostics.as_deref_mut() {
                    diagnostics.record_send_error();
                }
                log::error!("Send failed: {:?}", e);
                return Err(quicfuscate::engine::DataPlaneFault::TransportSend {
                    component: "standalone client connection send".to_string(),
                    error: e.to_string(),
                });
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

#[cfg(test)]
mod client_io_diagnostics_tests {
    use super::*;

    #[test]
    fn receive_diagnostics_distinguish_socket_core_and_activity_boundaries() {
        let mut diagnostics = ClientIoDiagnostics::default();

        diagnostics.record_socket_datagram(1200);
        diagnostics.record_socket_datagram(64);
        diagnostics.record_core_recv_success(true);
        diagnostics.record_core_recv_success(false);
        diagnostics.record_core_recv_error();
        diagnostics.record_send_poll();
        diagnostics.record_send_datagram(1280);
        diagnostics.record_send_poll();
        diagnostics.record_send_zero();
        diagnostics.record_send_poll();
        diagnostics.record_send_done();
        diagnostics.record_send_poll();
        diagnostics.record_send_error();

        assert_eq!(diagnostics.socket_datagrams, 2);
        assert_eq!(diagnostics.socket_bytes, 1264);
        assert_eq!(diagnostics.core_recv_successes, 2);
        assert_eq!(diagnostics.core_recv_errors, 1);
        assert_eq!(diagnostics.activity_updates, 1);
        assert_eq!(diagnostics.send_polls, 4);
        assert_eq!(diagnostics.send_datagrams, 1);
        assert_eq!(diagnostics.send_bytes, 1280);
        assert_eq!(diagnostics.send_zero_results, 1);
        assert_eq!(diagnostics.send_done_results, 1);
        assert_eq!(diagnostics.send_errors, 1);
        assert!(diagnostics.last_send_at.is_some());
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
            FecPacket::try_new(id, Some(block), len, true, None, 0, mem_pool.clone())
                .expect("early test packet fits the pool block")
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
            opt.free_block(b);
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
    #[clap(name = "cubic")]
    Cubic,
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
            CcAlgorithm::Cubic => quicfuscate::transport::CongestionControlAlgorithm::Cubic,
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

    /// TUN IPv6 address (for dual-stack VPN)
    #[clap(long)]
    tun_ip6: Option<String>,

    /// TUN IPv6 prefix length (1-128, default 64)
    #[clap(long)]
    tun_prefix6: Option<u8>,

    /// Enable kill switch (blocks all non-VPN traffic when disconnected)
    #[clap(long)]
    kill_switch: bool,

    /// Cleanup stale firewall rules from a crashed previous session, then exit
    #[clap(long)]
    cleanup_firewall: bool,

    /// VPN DNS server allowed on port 53 while the tunnel is connected
    #[clap(long, value_delimiter = ',')]
    vpn_dns: Vec<IpAddr>,

    /// Maximum inbound silence before fail-closed tunnel-loss handling
    #[clap(long, default_value_t = 30_000)]
    heartbeat_timeout_ms: u64,
}

#[derive(Subcommand, Debug)]
#[allow(clippy::large_enum_variant)]
enum Commands {
    /// Runs the client
    Client {
        /// The remote server address to connect to
        #[clap(long, required = true)]
        remote: String,

        /// Local UDP address to bind
        #[clap(long, default_value = "0.0.0.0:0")]
        local: String,

        /// The HTTPS URL to request; omitted uses https://cloudflare-dns.com/
        #[clap(short, long, value_name = "URL")]
        url: Option<String>,

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
        /// Compatibility flag; certificate validation is always enabled
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

        /// Maximum simultaneous admin web connections (default: 16, maximum: 1024)
        #[clap(long, value_name = "COUNT", default_value_t = quicfuscate::implementations::server::DEFAULT_ADMIN_WEB_MAX_CONNECTIONS)]
        admin_web_max_connections: usize,

        /// Maximum time for one admin web request operation in milliseconds (default: 30000, range: 50..=120000)
        #[clap(long, value_name = "MILLISECONDS", default_value_t = quicfuscate::implementations::server::DEFAULT_ADMIN_WEB_OPERATION_TIMEOUT_MS)]
        admin_web_operation_timeout_ms: u64,

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

        /// Allow direct unicast between authenticated VPN clients
        #[clap(long)]
        allow_client_to_client: bool,

        /// Skip privilege dropping after setup (debugging only - never use in production)
        #[clap(long = "no-drop-privileges")]
        no_drop_privileges: bool,

        /// User name or numeric UID to assume after privileged setup
        #[clap(long, default_value = "quicfuscate", value_name = "USER_OR_UID")]
        drop_user: String,

        /// Group name or numeric GID to assume after privileged setup
        #[clap(long, default_value = "quicfuscate", value_name = "GROUP_OR_GID")]
        drop_group: String,

        /// Audit log file path (NDJSON, hash-chained, tamper-evident).
        /// When set, security-relevant events are written to this file.
        #[clap(long = "audit-log", value_name = "PATH")]
        audit_log: Option<PathBuf>,
    },
    /// Verify the hash chain of an audit NDJSON file
    VerifyAuditLog {
        /// Audit log path to verify
        #[clap(value_name = "PATH")]
        path: PathBuf,
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
    /// Report process identity, Linux capability sets, and startup readiness
    Capabilities {
        /// Print machine-readable JSON (recommended)
        #[clap(long)]
        json: bool,

        /// Validate a target user name or numeric UID
        #[clap(long, default_value = "quicfuscate", value_name = "USER_OR_UID")]
        user: String,

        /// Validate a target group name or numeric GID
        #[clap(long, default_value = "quicfuscate", value_name = "GROUP_OR_GID")]
        group: String,

        /// Require TUN/routing startup capabilities
        #[clap(long)]
        tun: bool,

        /// UDP listen port whose bind capability should be checked
        #[clap(long, default_value_t = 4433)]
        listen_port: u16,
    },
}
