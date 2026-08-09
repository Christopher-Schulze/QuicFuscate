use clap::{Parser, Subcommand};
use std::net::SocketAddr;
use std::sync::{
    atomic::{AtomicBool, AtomicU64, Ordering},
    Arc,
};
use std::thread;
use std::time::{Duration, Instant};

/// Runtime-dispatched QPACK encoder supplied by the root compatibility layer.
pub type QpackEncoder = fn(input: &[u8], output: &mut [u8]) -> usize;

/// Minimal UDP sender contract required by the throughput benchmark.
pub trait UdpSender {
    /// Send one batch and return the number of packets accepted by the sender.
    fn send_batch(&mut self, packets: &[(&[u8], SocketAddr)]) -> std::io::Result<usize>;
}

/// Factory for the production UDP sender supplied by the root compatibility layer.
pub type UdpSenderFactory = fn(bind: SocketAddr) -> std::io::Result<Box<dyn UdpSender>>;

/// Developer harness: central CLI used by scripts/ (no tests here)
#[derive(Parser, Debug)]
#[command(name = "harness", version, about = "QuicFuscate developer harness")]
pub struct Cli {
    #[command(subcommand)]
    pub cmd: Command,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Benchmark QPACK Huffman encoder via runtime-dispatch (scalar/AVX2/NEON)
    QpackEncode {
        /// Input size in bytes (supports k/m suffix, e.g. 64k, 1m)
        #[arg(long, default_value = "65536")]
        input: String,
        /// Iterations
        #[arg(long, default_value_t = 200)]
        iters: usize,
    },
    /// UDP fast-path throughput benchmark (loopback by default)
    UdpThroughput {
        /// Payload size in bytes (supports k/m suffix, e.g. 1200, 64k)
        #[arg(long, default_value = "1200")]
        size: String,
        /// Iterations (batches)
        #[arg(long, default_value_t = 10000)]
        iters: usize,
        /// Batch size
        #[arg(long, default_value_t = 32)]
        batch: usize,
        /// Local bind address for sender (default: 0.0.0.0:0)
        #[arg(long, default_value = "0.0.0.0:0")]
        bind: String,
        /// Remote address (if omitted, loopback receiver is spawned)
        #[arg(long)]
        remote: Option<String>,
    },
}

fn parse_size(s: &str) -> usize {
    let s = s.trim();
    if let Some(num) = s.strip_suffix(['k', 'K']) {
        return num.parse::<usize>().unwrap_or(0) * 1024;
    }
    if let Some(num) = s.strip_suffix(['m', 'M']) {
        return num.parse::<usize>().unwrap_or(0) * 1024 * 1024;
    }
    s.parse::<usize>().unwrap_or(0)
}

fn make_input(size: usize) -> Vec<u8> {
    let sample = b":method: GET\n:scheme: https\n:authority: example.com\n:path: /index.html\nuser-agent: quicfuscate/0.1\naccept: */*\naccept-encoding: gzip, br\n";
    let mut buf = Vec::with_capacity(size);
    while buf.len() < size {
        let take = (size - buf.len()).min(sample.len());
        buf.extend_from_slice(&sample[..take]);
    }
    buf
}

pub fn run_cli(cli: Cli, qpack_encode: QpackEncoder, udp_sender_factory: UdpSenderFactory) {
    match cli.cmd {
        Command::QpackEncode { input, iters } => bench_qpack(&input, iters, qpack_encode),
        Command::UdpThroughput { size, iters, batch, bind, remote } => {
            bench_udp_throughput(&size, iters, batch, &bind, remote.as_deref(), udp_sender_factory)
        }
    }
}

fn bench_qpack(size_str: &str, iters: usize, qpack_encode: QpackEncoder) {
    let size = parse_size(size_str);
    let input = make_input(size);
    let mut out = vec![0u8; input.len() * 2 + 16];

    // Warmup
    let start = Instant::now();
    let _ = qpack_encode(&input, &mut out);
    let warmup = start.elapsed();

    // Timed
    let start = Instant::now();
    let mut total_bytes: usize = 0;
    for _ in 0..iters {
        let written = qpack_encode(&input, &mut out);
        total_bytes += written;
    }
    let dur = start.elapsed();
    let secs = dur.as_secs_f64();
    let mib = total_bytes as f64 / (1024.0 * 1024.0);

    println!(
        "variant=dispatch size={}B iters={} total_out={}B time_ms={:.2} throughput_MiBps={:.2} warmup_ms={:.2}",
        size,
        iters,
        total_bytes,
        secs * 1000.0,
        mib / secs,
        warmup.as_secs_f64() * 1000.0
    );
}

fn parse_addr(s: &str) -> Option<SocketAddr> {
    s.parse::<SocketAddr>().ok()
}

fn bench_udp_throughput(
    size_str: &str,
    iters: usize,
    batch: usize,
    bind_str: &str,
    remote: Option<&str>,
    udp_sender_factory: UdpSenderFactory,
) {
    let size = parse_size(size_str);
    if size == 0 {
        eprintln!("size must be > 0");
        return;
    }
    let batch = batch.max(1);

    let bind_addr = match parse_addr(bind_str) {
        Some(addr) => addr,
        None => {
            eprintln!("invalid bind address: {}", bind_str);
            return;
        }
    };

    let stop = Arc::new(AtomicBool::new(false));
    let recv_bytes = Arc::new(AtomicU64::new(0));

    let (remote_addr, recv_handle) = if let Some(remote_str) = remote {
        let addr = match parse_addr(remote_str) {
            Some(addr) => addr,
            None => {
                eprintln!("invalid remote address: {}", remote_str);
                return;
            }
        };
        (addr, None)
    } else {
        let recv_sock = match std::net::UdpSocket::bind("127.0.0.1:0") {
            Ok(sock) => sock,
            Err(err) => {
                eprintln!("recv bind failed: {}", err);
                return;
            }
        };
        if let Err(err) = recv_sock.set_read_timeout(Some(Duration::from_millis(10))) {
            eprintln!("recv timeout setup failed: {}", err);
            return;
        }
        let recv_addr = match recv_sock.local_addr() {
            Ok(addr) => addr,
            Err(err) => {
                eprintln!("recv local_addr failed: {}", err);
                return;
            }
        };
        let stop_flag = Arc::clone(&stop);
        let recv_bytes = Arc::clone(&recv_bytes);
        let handle = thread::spawn(move || {
            let mut buf = vec![0u8; size + 64];
            loop {
                if stop_flag.load(Ordering::Relaxed) {
                    break;
                }
                match recv_sock.recv_from(&mut buf) {
                    Ok((n, _)) => {
                        recv_bytes.fetch_add(n as u64, Ordering::Relaxed);
                    }
                    Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => continue,
                    Err(err) if err.kind() == std::io::ErrorKind::TimedOut => continue,
                    Err(_) => break,
                }
            }
        });
        (recv_addr, Some(handle))
    };

    let mut fast = match udp_sender_factory(bind_addr) {
        Ok(v) => v,
        Err(err) => {
            eprintln!("udpfast init failed: {}", err);
            return;
        }
    };
    let mut payload = vec![0u8; size];
    for (i, b) in payload.iter_mut().enumerate() {
        *b = (i as u8).wrapping_mul(31).wrapping_add(7);
    }

    let mut packets: Vec<(&[u8], SocketAddr)> = Vec::with_capacity(batch);
    for _ in 0..batch {
        packets.push((payload.as_slice(), remote_addr));
    }

    let _ = fast.send_batch(&packets);
    let start = Instant::now();
    let mut total_packets = 0usize;
    let mut total_bytes = 0usize;
    for _ in 0..iters {
        match fast.send_batch(&packets) {
            Ok(sent) => {
                total_packets += sent;
                total_bytes += sent * size;
            }
            Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => continue,
            Err(err) => {
                eprintln!("send error: {}", err);
                break;
            }
        }
    }
    let dur = start.elapsed();

    stop.store(true, Ordering::Relaxed);
    if let Some(handle) = recv_handle {
        let _ = handle.join();
    }
    let recv_total = recv_bytes.load(Ordering::Relaxed);
    let secs = dur.as_secs_f64().max(1e-9);
    let mib = total_bytes as f64 / (1024.0 * 1024.0);

    println!(
        "variant=udpfast size={}B iters={} batch={} sent_packets={} sent_bytes={} recv_bytes={} time_ms={:.2} throughput_MiBps={:.2}",
        size,
        iters,
        batch,
        total_packets,
        total_bytes,
        recv_total,
        secs * 1000.0,
        mib / secs
    );
}
