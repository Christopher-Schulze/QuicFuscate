//! Async I/O driver for client packet processing.
//!
//! This module implements the bidirectional packet flow:
//! - TUN -> Stealth -> FEC -> QUIC (outbound)
//! - QUIC -> FEC -> Stealth -> TUN (inbound)

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;

use crate::implementations::client::circuit_runtime::ClientDataPlane;
use crate::interface::TunInterface;
#[cfg(target_os = "linux")]
use crate::interface::TunReadContract;
use crate::time_source::ProtocolClock;
use qf_engine_types::{DataPlaneFault, EngineError};

#[inline]
fn profile_prefers_wide_batches(profile: crate::optimize::CpuProfile) -> bool {
    use crate::optimize::CpuProfile;
    matches!(
        profile,
        CpuProfile::X86_P2a
            | CpuProfile::X86_P2b
            | CpuProfile::X86_P3a
            | CpuProfile::X86_P3b
            | CpuProfile::X86_P3c
            | CpuProfile::X86_P3d
            | CpuProfile::X86_P3e
            | CpuProfile::X86_P4a
            | CpuProfile::X86_P4b
            | CpuProfile::ARM_A2
            | CpuProfile::Apple_M
            | CpuProfile::RVV
    )
}

/// I/O driver configuration.
#[derive(Clone, Debug)]
pub struct IoDriverConfig {
    /// UDP socket buffer size
    pub socket_buffer_size: usize,
    /// Channel buffer size for packet queues
    pub channel_buffer_size: usize,
    /// Maximum packets per batch
    pub batch_size: usize,
    /// Poll interval in microseconds for non-blocking reads
    pub poll_interval_us: u64,
}

impl Default for IoDriverConfig {
    fn default() -> Self {
        Self {
            socket_buffer_size: 2 * 1024 * 1024, // 2 MB
            channel_buffer_size: 1024,
            batch_size: 64,
            poll_interval_us: 100,
        }
    }
}

/// I/O driver statistics.
#[derive(Debug, Default)]
pub struct IoDriverStats {
    pub tun_packets_read: AtomicU64,
    pub tun_packets_written: AtomicU64,
    pub udp_packets_sent: AtomicU64,
    pub udp_packets_received: AtomicU64,
    pub errors: AtomicU64,
    /// Number of terminal data-plane faults published by this driver.
    pub data_plane_faults: AtomicU64,
}

impl IoDriverStats {
    pub fn snapshot(&self) -> IoDriverStatsSnapshot {
        IoDriverStatsSnapshot {
            tun_packets_read: self.tun_packets_read.load(Ordering::Relaxed),
            tun_packets_written: self.tun_packets_written.load(Ordering::Relaxed),
            udp_packets_sent: self.udp_packets_sent.load(Ordering::Relaxed),
            udp_packets_received: self.udp_packets_received.load(Ordering::Relaxed),
            errors: self.errors.load(Ordering::Relaxed),
            data_plane_faults: self.data_plane_faults.load(Ordering::Relaxed),
        }
    }
}

#[derive(Debug, Clone)]
pub struct IoDriverStatsSnapshot {
    pub tun_packets_read: u64,
    pub tun_packets_written: u64,
    pub udp_packets_sent: u64,
    pub udp_packets_received: u64,
    pub errors: u64,
    pub data_plane_faults: u64,
}

const MAX_CLIENT_INGRESS_PACKETS: usize = 256;
const MAX_CLIENT_INGRESS_BYTES: usize = 384 * 1024;

#[derive(Default)]
struct ClientTunnelIngressState {
    packets: std::collections::VecDeque<Vec<u8>>,
    bytes: usize,
}

/// Bounded handoff shared by H3/MASQUE callbacks and the client TUN writer.
#[derive(Clone, Default)]
pub struct ClientTunnelIngress {
    state: Arc<parking_lot::Mutex<ClientTunnelIngressState>>,
}

impl ClientTunnelIngress {
    /// Create an empty bounded ingress queue.
    pub fn new() -> Self {
        Self::default()
    }

    /// Queue one validated-looking IP payload without allowing unbounded growth.
    pub fn push(&self, payload: &[u8]) -> bool {
        if payload.is_empty()
            || !matches!(payload.first().map(|byte| byte >> 4), Some(4 | 6))
            || payload.len() > u16::MAX as usize
        {
            return false;
        }
        let mut state = self.state.lock();
        if state.packets.len() >= MAX_CLIENT_INGRESS_PACKETS
            || state.bytes.saturating_add(payload.len()) > MAX_CLIENT_INGRESS_BYTES
        {
            return false;
        }
        state.bytes = state.bytes.saturating_add(payload.len());
        state.packets.push_back(payload.to_vec());
        true
    }

    fn drain(&self) -> Vec<Vec<u8>> {
        let mut state = self.state.lock();
        state.bytes = 0;
        state.packets.drain(..).collect()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg(target_os = "linux")]
enum OutboundDispatch {
    #[cfg(feature = "io_uring")]
    IoUringBatch,
    SendmmsgBatch,
    #[cfg(any(test, feature = "io_uring"))]
    SocketPerPacket,
}

#[inline]
#[cfg(all(target_os = "linux", any(test, feature = "io_uring")))]
fn resolve_outbound_dispatch(_queued: usize, _has_uring: bool) -> OutboundDispatch {
    #[cfg(feature = "io_uring")]
    if _queued > 1 && _has_uring {
        return OutboundDispatch::IoUringBatch;
    }
    if _queued > 1 {
        OutboundDispatch::SendmmsgBatch
    } else {
        OutboundDispatch::SocketPerPacket
    }
}

#[cfg(target_os = "linux")]
trait IoHotpathAdapter: Send + Sync {
    fn sendmmsg_batch(&self, socket_fd: i32, payloads: &[&[u8]]) -> Result<usize, std::io::Error>;
}

#[cfg(target_os = "linux")]
struct SystemIoHotpathAdapter {
    acceleration_initialized: AtomicBool,
}

#[cfg(target_os = "linux")]
impl Default for SystemIoHotpathAdapter {
    fn default() -> Self {
        Self { acceleration_initialized: AtomicBool::new(false) }
    }
}

#[cfg(target_os = "linux")]
impl IoHotpathAdapter for SystemIoHotpathAdapter {
    fn sendmmsg_batch(&self, socket_fd: i32, payloads: &[&[u8]]) -> Result<usize, std::io::Error> {
        if self
            .acceleration_initialized
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            if let Err(e) = crate::transport::init_socket_acceleration_fd(socket_fd) {
                log::debug!("batch acceleration init failed: {}", e);
            }
        }

        crate::optimize::zc_batch::sendmmsg(socket_fd, payloads)
    }
}

#[cfg(target_os = "linux")]
fn try_sendmmsg_batch(
    adapter: &dyn IoHotpathAdapter,
    socket_fd: i32,
    dispatch: OutboundDispatch,
    payloads: &[&[u8]],
) -> Result<usize, std::io::Error> {
    match dispatch {
        #[cfg(feature = "io_uring")]
        OutboundDispatch::IoUringBatch => Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "io_uring dispatch must be handled by the io_uring sender",
        )),
        OutboundDispatch::SendmmsgBatch => {
            Ok(adapter.sendmmsg_batch(socket_fd, payloads)?.min(payloads.len()))
        }
        #[cfg(any(test, feature = "io_uring"))]
        OutboundDispatch::SocketPerPacket => Ok(0),
    }
}

#[derive(Debug, Clone, Copy)]
pub struct HotpathPerfThresholds {
    pub max_copy_bytes_per_packet: u64,
    pub min_sendmmsg_packets_per_call: u64,
    pub max_batch_drain_ratio_ppm: u64,
}

impl Default for HotpathPerfThresholds {
    fn default() -> Self {
        Self {
            max_copy_bytes_per_packet: 65_535,
            min_sendmmsg_packets_per_call: 2,
            max_batch_drain_ratio_ppm: 1_000_000, // <= 1 extra drained packet per first packet
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct HotpathPerfCounters {
    pub udp_packets_received: u64,
    pub io_copy_ops: u64,
    pub io_copy_bytes: u64,
    pub batch_drain_packets: u64,
    pub sendmmsg_calls: u64,
    pub sendmmsg_packets: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HotpathBenchmarkScenario {
    pub payload_bytes: usize,
    pub batch_size: usize,
    pub iterations: usize,
}

pub const HOTPATH_BENCHMARK_SET: [HotpathBenchmarkScenario; 3] = [
    HotpathBenchmarkScenario { payload_bytes: 512, batch_size: 32, iterations: 20_000 },
    HotpathBenchmarkScenario { payload_bytes: 1200, batch_size: 64, iterations: 20_000 },
    HotpathBenchmarkScenario { payload_bytes: 1400, batch_size: 128, iterations: 10_000 },
];

pub fn evaluate_hotpath_perf_smoke(
    counters: HotpathPerfCounters,
    thresholds: HotpathPerfThresholds,
) -> Result<(), &'static str> {
    if counters.io_copy_ops > 0
        && (counters.io_copy_bytes / counters.io_copy_ops) > thresholds.max_copy_bytes_per_packet
    {
        return Err("copy bytes per packet exceeds threshold");
    }

    if counters.sendmmsg_calls > 0
        && (counters.sendmmsg_packets / counters.sendmmsg_calls)
            < thresholds.min_sendmmsg_packets_per_call
    {
        return Err("sendmmsg batch utilization below threshold");
    }

    let ratio_ppm = counters
        .batch_drain_packets
        .saturating_mul(1_000_000)
        .checked_div(counters.udp_packets_received)
        .unwrap_or(0);
    if ratio_ppm > thresholds.max_batch_drain_ratio_ppm {
        return Err("batch drain ratio exceeds threshold");
    }

    Ok(())
}

/// Async I/O driver handle.
pub struct IoDriver {
    config: IoDriverConfig,
    clock: ProtocolClock,
    shutdown: Arc<AtomicBool>,
    stats: Arc<IoDriverStats>,
    #[cfg(target_os = "linux")]
    hotpath_adapter: Arc<dyn IoHotpathAdapter>,
    #[cfg(all(target_os = "linux", feature = "io_uring"))]
    uring_worker: Option<crate::optimize::uring_batch::UringBatchWorker>,
    /// Cached at construction: true when io_uring init succeeded.
    /// Avoids a Mutex lock just to check availability on every hot-path iteration.
    #[cfg(all(target_os = "linux", feature = "io_uring"))]
    uring_available: bool,
    wide_batch_cpu: bool,
}

#[cfg(all(target_os = "linux", feature = "io_uring"))]
struct UringInboundRuntime {
    receiver: crate::optimize::uring_batch::UringRecvBatch,
    event: tokio::io::unix::AsyncFd<std::os::fd::OwnedFd>,
}

#[cfg(all(target_os = "linux", feature = "io_uring"))]
fn validate_eventfd_read_len(read_len: isize) -> std::io::Result<()> {
    if read_len == 8 {
        return Ok(());
    }
    Err(std::io::Error::new(
        std::io::ErrorKind::InvalidData,
        format!("io_uring eventfd returned {read_len} bytes instead of 8"),
    ))
}

mod runtime;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::interface::FastpathMode;

    #[test]
    fn test_io_driver_config_default() {
        let config = IoDriverConfig::default();
        assert_eq!(config.batch_size, 64);
        assert_eq!(config.channel_buffer_size, 1024);
    }

    #[test]
    fn client_tunnel_ingress_rejects_malformed_and_bounds_payloads() {
        let ingress = ClientTunnelIngress::new();
        assert!(!ingress.push(&[]));
        assert!(!ingress.push(&[0x30, 0x00]));

        let payload = vec![0x45; 65_000];
        for _ in 0..6 {
            assert!(ingress.push(&payload));
        }
        assert!(!ingress.push(&payload));
        assert_eq!(ingress.drain().len(), 6);
    }

    #[test]
    fn client_tunnel_ingress_is_bounded_fifo_and_reusable() {
        let ingress = ClientTunnelIngress::new();
        for index in 0..MAX_CLIENT_INGRESS_PACKETS {
            assert!(ingress.push(&[if index % 2 == 0 { 0x45 } else { 0x60 }, index as u8]));
        }
        assert!(!ingress.push(&[0x45, 0xff]));

        let packets = ingress.drain();
        assert_eq!(packets.len(), MAX_CLIENT_INGRESS_PACKETS);
        assert_eq!(packets.first(), Some(&vec![0x45, 0]));
        assert_eq!(packets.last(), Some(&vec![0x60, 255]));
        assert!(ingress.push(&[0x45, 1]));
        assert_eq!(ingress.drain(), vec![vec![0x45, 1]]);
    }

    #[test]
    fn test_io_driver_stats() {
        let stats = IoDriverStats::default();
        stats.tun_packets_read.fetch_add(10, Ordering::Relaxed);
        stats.udp_packets_sent.fetch_add(5, Ordering::Relaxed);
        stats.data_plane_faults.fetch_add(2, Ordering::Relaxed);

        let snapshot = stats.snapshot();
        assert_eq!(snapshot.tun_packets_read, 10);
        assert_eq!(snapshot.udp_packets_sent, 5);
        assert_eq!(snapshot.data_plane_faults, 2);
    }

    #[test]
    fn test_io_driver_records_terminal_data_plane_fault() {
        let driver = IoDriver::new(IoDriverConfig::default());

        driver.record_data_plane_fault();

        let snapshot = driver.stats().snapshot();
        assert_eq!(snapshot.data_plane_faults, 1);
        assert_eq!(snapshot.errors, 1);
    }

    #[test]
    fn test_io_driver_shutdown() {
        let driver = IoDriver::new(IoDriverConfig::default());
        assert!(!driver.shutdown.load(Ordering::Relaxed));
        driver.shutdown();
        assert!(driver.shutdown.load(Ordering::Relaxed));
    }

    #[tokio::test]
    async fn standby_loop_honors_owned_shutdown_without_tun() {
        let local_addr = "127.0.0.1:45000".parse().expect("local address");
        let remote_addr = "127.0.0.1:45001".parse().expect("remote address");
        let transport =
            crate::transport::Config::new_with_version(crate::transport::PROTOCOL_VERSION)
                .expect("transport config");
        let connection = crate::core::QuicFuscateConnection::new_client(
            "localhost",
            local_addr,
            remote_addr,
            transport,
            crate::stealth::StealthConfig::default(),
            crate::fec::FecConfig::default(),
            crate::optimize::OptimizeConfig::default(),
            None,
            None,
            false,
        )
        .expect("client connection");
        let data_plane = Arc::new(parking_lot::Mutex::new(ClientDataPlane::single(connection)));
        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.expect("standby socket"));
        let driver = IoDriver::new(IoDriverConfig::default());
        driver.shutdown();

        tokio::time::timeout(
            Duration::from_millis(100),
            driver.run_standby(data_plane, socket, ClientTunnelIngress::new()),
        )
        .await
        .expect("standby loop must observe shutdown")
        .expect("shutdown is clean");
    }

    #[test]
    fn test_fastpath_mode_parse() {
        assert_eq!(FastpathMode::parse("auto"), FastpathMode::Auto);
        assert_eq!(FastpathMode::parse("off"), FastpathMode::Off);
        assert_eq!(FastpathMode::parse("unknown"), FastpathMode::Auto);
    }

    #[test]
    fn test_normalized_batch_size_bounds() {
        let d0 = IoDriver::new(IoDriverConfig { batch_size: 0, ..IoDriverConfig::default() });
        assert_eq!(d0.normalized_batch_size(), 1);

        let d1 = IoDriver::new(IoDriverConfig { batch_size: 64, ..IoDriverConfig::default() });
        assert_eq!(d1.normalized_batch_size(), 64);

        let d2 = IoDriver::new(IoDriverConfig { batch_size: 1024, ..IoDriverConfig::default() });
        assert!(matches!(d2.normalized_batch_size(), 128 | 256));
    }

    #[cfg(all(target_os = "linux", feature = "io_uring"))]
    #[test]
    fn test_eventfd_read_requires_exact_eight_bytes() {
        assert!(validate_eventfd_read_len(8).is_ok());
        for length in [0, 1, 4, 7, 9, -1] {
            assert!(
                validate_eventfd_read_len(length).is_err(),
                "eventfd read length {length} must be rejected"
            );
        }
    }

    #[test]
    fn test_resolve_outbound_dispatch_paths() {
        #[cfg(target_os = "linux")]
        {
            // Without io_uring available.
            assert_eq!(resolve_outbound_dispatch(1, false), OutboundDispatch::SocketPerPacket);
            assert_eq!(resolve_outbound_dispatch(8, false), OutboundDispatch::SendmmsgBatch);

            // With io_uring available (feature-gated variant).
            #[cfg(feature = "io_uring")]
            {
                assert_eq!(resolve_outbound_dispatch(1, true), OutboundDispatch::SocketPerPacket);
                assert_eq!(resolve_outbound_dispatch(8, true), OutboundDispatch::IoUringBatch);
            }

            // has_uring=true without feature compiles to sendmmsg.
            #[cfg(not(feature = "io_uring"))]
            assert_eq!(resolve_outbound_dispatch(8, true), OutboundDispatch::SendmmsgBatch);
        }
    }

    #[cfg(target_os = "linux")]
    struct MockHotpathAdapter {
        sendmmsg_result: std::sync::Mutex<Result<usize, String>>,
        sendmmsg_calls: AtomicU64,
    }

    #[cfg(target_os = "linux")]
    impl MockHotpathAdapter {
        fn new(sendmmsg_result: Result<usize, String>) -> Self {
            Self {
                sendmmsg_result: std::sync::Mutex::new(sendmmsg_result),
                sendmmsg_calls: AtomicU64::new(0),
            }
        }
    }

    #[cfg(target_os = "linux")]
    impl IoHotpathAdapter for MockHotpathAdapter {
        fn sendmmsg_batch(
            &self,
            _socket_fd: i32,
            _payloads: &[&[u8]],
        ) -> Result<usize, std::io::Error> {
            self.sendmmsg_calls.fetch_add(1, Ordering::Relaxed);
            match self
                .sendmmsg_result
                .lock()
                .map_err(|e| std::io::Error::other(e.to_string()))?
                .clone()
            {
                Ok(sent) => Ok(sent),
                Err(error) => Err(std::io::Error::other(error)),
            }
        }
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn test_try_sendmmsg_batch_uses_adapter_and_caps_result() {
        let adapter = MockHotpathAdapter::new(Ok(99));
        let payloads = vec![&b"one"[..], &b"two"[..], &b"three"[..]];

        let sent = try_sendmmsg_batch(&adapter, 0, OutboundDispatch::SendmmsgBatch, &payloads)
            .expect("sendmmsg");

        assert_eq!(sent, payloads.len());
        assert_eq!(adapter.sendmmsg_calls.load(Ordering::Relaxed), 1);
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn test_try_sendmmsg_batch_skips_non_sendmmsg_dispatch() {
        let adapter = MockHotpathAdapter::new(Ok(1));
        let payloads = vec![&b"one"[..], &b"two"[..]];

        let sent = try_sendmmsg_batch(&adapter, 0, OutboundDispatch::SocketPerPacket, &payloads)
            .expect("sendmmsg");

        assert_eq!(sent, 0);
        assert_eq!(adapter.sendmmsg_calls.load(Ordering::Relaxed), 0);
    }

    #[test]
    #[cfg(all(target_os = "linux", feature = "io_uring"))]
    fn test_try_sendmmsg_batch_rejects_io_uring_dispatch() {
        let adapter = MockHotpathAdapter::new(Ok(1));
        let payloads = vec![&b"one"[..], &b"two"[..]];

        let error = try_sendmmsg_batch(&adapter, 0, OutboundDispatch::IoUringBatch, &payloads)
            .expect_err("io_uring dispatch must not silently report zero sends");

        assert!(error.to_string().contains("io_uring"));
        assert_eq!(adapter.sendmmsg_calls.load(Ordering::Relaxed), 0);
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn test_with_hotpath_adapter_uses_custom_adapter() {
        let custom_impl = Arc::new(MockHotpathAdapter::new(Ok(2)));
        let custom: Arc<dyn IoHotpathAdapter> = custom_impl.clone();
        let driver = IoDriver::with_hotpath_adapter(IoDriverConfig::default(), custom);
        let payloads = vec![&b"one"[..], &b"two"[..]];
        let sent = try_sendmmsg_batch(
            driver.hotpath_adapter.as_ref(),
            0,
            OutboundDispatch::SendmmsgBatch,
            &payloads,
        )
        .expect("sendmmsg");
        assert_eq!(sent, 2);
        assert_eq!(custom_impl.sendmmsg_calls.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn test_hotpath_perf_smoke_thresholds_pass() {
        let counters = HotpathPerfCounters {
            udp_packets_received: 100,
            io_copy_ops: 100,
            io_copy_bytes: 120_000,
            batch_drain_packets: 80,
            sendmmsg_calls: 10,
            sendmmsg_packets: 40,
        };
        assert!(evaluate_hotpath_perf_smoke(counters, HotpathPerfThresholds::default()).is_ok());
    }

    #[test]
    fn test_hotpath_perf_smoke_thresholds_reject_bad_sendmmsg_ratio() {
        let counters = HotpathPerfCounters {
            udp_packets_received: 100,
            io_copy_ops: 100,
            io_copy_bytes: 120_000,
            batch_drain_packets: 80,
            sendmmsg_calls: 10,
            sendmmsg_packets: 10,
        };
        let err = evaluate_hotpath_perf_smoke(counters, HotpathPerfThresholds::default())
            .expect_err("expected sendmmsg utilization rejection");
        assert_eq!(err, "sendmmsg batch utilization below threshold");
    }

    #[test]
    fn test_hotpath_benchmark_set_is_ordered_and_nonzero() {
        assert_eq!(HOTPATH_BENCHMARK_SET.len(), 3);
        for scenario in HOTPATH_BENCHMARK_SET {
            assert!(scenario.payload_bytes > 0);
            assert!(scenario.batch_size > 0);
            assert!(scenario.iterations > 0);
        }
        assert!(HOTPATH_BENCHMARK_SET[0].payload_bytes <= HOTPATH_BENCHMARK_SET[1].payload_bytes);
        assert!(HOTPATH_BENCHMARK_SET[1].payload_bytes <= HOTPATH_BENCHMARK_SET[2].payload_bytes);
    }

    #[test]
    fn test_profile_prefers_wide_batches_mapping() {
        assert!(profile_prefers_wide_batches(crate::optimize::CpuProfile::X86_P2a));
        assert!(profile_prefers_wide_batches(crate::optimize::CpuProfile::ARM_A2));
        assert!(!profile_prefers_wide_batches(crate::optimize::CpuProfile::X86_P0a));
        assert!(!profile_prefers_wide_batches(crate::optimize::CpuProfile::Scalar));
    }

    #[test]
    fn test_new_driver_publishes_cpu_profile_mask() {
        crate::optimize::telemetry::CPU_FEATURE_MASK.store(0, Ordering::Relaxed);
        let profile = crate::optimize::FeatureDetector::instance().profile();
        let expected = crate::optimize::telemetry::cpu_profile_mask(profile);
        let _driver = IoDriver::new(IoDriverConfig::default());
        assert_eq!(crate::optimize::telemetry::CPU_FEATURE_MASK.load(Ordering::Relaxed), expected);
    }
}
