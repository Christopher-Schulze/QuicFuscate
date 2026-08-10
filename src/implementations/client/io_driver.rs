//! Async I/O driver for client packet processing.
//!
//! This module implements the bidirectional packet flow:
//! - TUN -> Stealth -> FEC -> QUIC (outbound)
//! - QUIC -> FEC -> Stealth -> TUN (inbound)

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;

use crate::core::QuicFuscateConnection;
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

impl IoDriver {
    #[inline]
    fn normalized_batch_size(&self) -> usize {
        let cap = if self.wide_batch_cpu { 256 } else { 128 };
        self.config.batch_size.clamp(1, cap)
    }

    /// Create a new I/O driver.
    pub fn new(config: IoDriverConfig) -> Self {
        Self::new_with_clock(config, &ProtocolClock::default())
    }

    /// Create an I/O driver bound to an explicit protocol clock.
    pub fn new_with_clock(config: IoDriverConfig, clock: &ProtocolClock) -> Self {
        #[cfg(target_os = "linux")]
        let hotpath_adapter: Arc<dyn IoHotpathAdapter> =
            Arc::new(SystemIoHotpathAdapter::default());
        #[cfg(all(target_os = "linux", feature = "io_uring"))]
        let (uring_sender, uring_available) = {
            let worker = crate::optimize::uring_batch::UringBatchWorker::with_defaults();
            let available = worker.is_some();
            if available {
                log::info!("io_uring batch worker initialised");
            }
            (worker, available)
        };
        let profile = crate::optimize::FeatureDetector::instance().profile();
        crate::optimize::telemetry::publish_cpu_profile_mask(profile);
        let wide_batch_cpu = profile_prefers_wide_batches(profile);
        Self {
            config,
            clock: clock.clone(),
            shutdown: Arc::new(AtomicBool::new(false)),
            stats: Arc::new(IoDriverStats::default()),
            #[cfg(target_os = "linux")]
            hotpath_adapter,
            #[cfg(all(target_os = "linux", feature = "io_uring"))]
            uring_worker: uring_sender,
            #[cfg(all(target_os = "linux", feature = "io_uring"))]
            uring_available,
            wide_batch_cpu,
        }
    }

    #[cfg(all(target_os = "linux", test))]
    fn with_hotpath_adapter(
        config: IoDriverConfig,
        hotpath_adapter: Arc<dyn IoHotpathAdapter>,
    ) -> Self {
        let mut driver = Self::new(config);
        driver.hotpath_adapter = hotpath_adapter;
        driver
    }

    /// True when io_uring was successfully initialised at construction.
    /// Cached to avoid a Mutex lock on every hot-path iteration.
    #[cfg(all(target_os = "linux", feature = "io_uring"))]
    #[inline(always)]
    fn has_uring(&self) -> bool {
        self.uring_available
            && self.uring_worker.as_ref().is_some_and(|worker| worker.is_available())
    }

    /// Get shutdown signal.
    pub fn shutdown_signal(&self) -> Arc<AtomicBool> {
        self.shutdown.clone()
    }

    /// Request shutdown.
    pub fn shutdown(&self) {
        self.shutdown.store(true, Ordering::SeqCst);
        #[cfg(all(target_os = "linux", feature = "io_uring"))]
        if let Some(worker) = self.uring_worker.as_ref() {
            worker.request_shutdown();
        }
    }

    /// Join the owned io_uring blocking worker after its async loops stopped.
    #[cfg(all(target_os = "linux", feature = "io_uring"))]
    pub fn join_io_uring_worker(&self) -> Result<(), String> {
        self.uring_worker.as_ref().map_or(Ok(()), |worker| worker.join())
    }

    /// Get stats reference.
    pub fn stats(&self) -> &Arc<IoDriverStats> {
        &self.stats
    }

    /// Record a terminal data-plane fault that was detected by a task wrapper
    /// rather than inside one of the driver loops.
    pub fn record_data_plane_fault(&self) {
        self.stats.data_plane_faults.fetch_add(1, Ordering::Relaxed);
        self.stats.errors.fetch_add(1, Ordering::Relaxed);
    }

    fn data_plane_error(&self, fault: DataPlaneFault) -> EngineError {
        EngineError::DataPlane(fault)
    }

    fn transport_send_error(&self, component: &str, error: impl std::fmt::Display) -> EngineError {
        self.data_plane_error(DataPlaneFault::TransportSend {
            component: component.to_string(),
            error: error.to_string(),
        })
    }

    fn transport_receive_error(
        &self,
        component: &str,
        error: impl std::fmt::Display,
    ) -> EngineError {
        self.data_plane_error(DataPlaneFault::TransportReceive {
            component: component.to_string(),
            error: error.to_string(),
        })
    }

    fn tun_write_error(&self, component: &str, error: impl std::fmt::Display) -> EngineError {
        self.data_plane_error(DataPlaneFault::TunWrite {
            component: component.to_string(),
            error: error.to_string(),
        })
    }

    #[cfg(target_os = "linux")]
    fn reader_stopped_error(&self, component: &str, error: impl std::fmt::Display) -> EngineError {
        self.data_plane_error(DataPlaneFault::ReaderStopped {
            component: component.to_string(),
            error: error.to_string(),
        })
    }

    /// Compute the next inbound poll timeout, capping it by the connection's
    /// earliest send deadline (pacing/stealth release or recovery/PTO timer).
    fn recv_timeout(&self, conn: &Arc<parking_lot::Mutex<QuicFuscateConnection>>) -> Duration {
        let base = Duration::from_millis(200);
        let deadline = { conn.lock().next_send_deadline() };
        if let Some(deadline) = deadline {
            let remaining = deadline.saturating_duration_since(self.clock.now());
            if remaining.is_zero() {
                return Duration::from_millis(1);
            }
            return remaining.min(base).max(Duration::from_millis(1));
        }
        base
    }

    /// Flush any pending outgoing packets (ACKs, PTO probes, etc.) produced by
    /// the QUIC connection.  Used by the inbound loop so probes are not held
    /// back until the outbound TUN loop wakes.
    async fn flush_outbound(
        &self,
        conn: &Arc<parking_lot::Mutex<QuicFuscateConnection>>,
        socket: &Arc<UdpSocket>,
        out: &mut [u8],
    ) -> Result<(), EngineError> {
        loop {
            let written = {
                let mut conn_guard = conn.lock();
                match conn_guard.send(&mut *out) {
                    Ok(0) | Err(crate::error::ConnectionError::Done) => break,
                    Ok(written) => written,
                    Err(e) => {
                        log::debug!("Connection send error during flush: {:?}", e);
                        return Err(self.transport_send_error("client inbound flush", e));
                    }
                }
            };

            if let Err(e) = socket.send(&out[..written]).await {
                log::warn!("UDP send error during outbound flush: {}", e);
                return Err(self.transport_send_error("client inbound UDP flush", e));
            }

            self.stats.udp_packets_sent.fetch_add(1, Ordering::Relaxed);
            let global = crate::instrumentation::global();
            global.transport.record_bytes_out(written as u64);
            global.transport.record_packet_out();
        }
        Ok(())
    }

    /// Drive QUIC and H3 until the authenticated server assignment arrives.
    /// No TUN handle is needed or opened during this phase.
    pub async fn negotiate_assignment(
        &self,
        conn: &Arc<parking_lot::Mutex<QuicFuscateConnection>>,
        socket: &Arc<UdpSocket>,
        generation: u64,
        deadline: Instant,
    ) -> Result<crate::control_plane::ClientAssignment, EngineError> {
        let reception = Arc::new(parking_lot::Mutex::new(
            crate::control_plane::AssignmentReception::new(generation)
                .map_err(|error| EngineError::Connection(error.to_string()))?,
        ));
        {
            let callback_state = Arc::clone(&reception);
            let mut guard = conn.lock();
            guard.set_client_connection_generation(generation);
            guard.set_masque_control_cb(Arc::new(std::sync::Mutex::new(Box::new(
                move |capsule_type: u64, payload: &[u8]| {
                    let mut state = callback_state.lock();
                    state.receive(capsule_type, payload);
                },
            ))));
        }

        let mut recv_buf = vec![0u8; 65_535];
        let mut send_buf = vec![0u8; 65_535];
        let mut control_started = false;
        while self.clock.now() < deadline {
            self.flush_outbound(conn, socket, &mut send_buf).await?;
            let (failure, assignment) = {
                let state = reception.lock();
                (state.failure().cloned(), state.assignment().cloned())
            };
            if let Some(error) = failure {
                return Err(EngineError::Connection(format!(
                    "client assignment control plane rejected: {error}"
                )));
            }
            if let Some(assignment) = assignment {
                if conn.lock().masque_tunnel_established() {
                    return Ok(assignment);
                }
            }

            let established = { conn.lock().conn.is_established() };
            if established && !control_started {
                conn.lock()
                    .begin_masque_control_tunnel()
                    .map_err(|error| EngineError::Connection(error.to_string()))?;
                control_started = true;
                continue;
            }

            let remaining = deadline.saturating_duration_since(self.clock.now());
            let wait = remaining.min(Duration::from_millis(100));
            if wait.is_zero() {
                break;
            }
            match tokio::time::timeout(wait, socket.recv(&mut recv_buf)).await {
                Ok(Ok(length)) if length > 0 => {
                    let mut guard = conn.lock();
                    guard.recv(&recv_buf[..length]).map_err(|error| {
                        self.transport_receive_error("client assignment QUIC receive", error)
                    })?;
                    if control_started {
                        guard.poll_http3().map_err(|error| {
                            self.transport_receive_error("client assignment H3 poll", error)
                        })?;
                    }
                }
                Ok(Ok(_)) => {}
                Ok(Err(error)) => {
                    return Err(
                        self.transport_receive_error("client assignment UDP receive", error)
                    );
                }
                Err(_) => {}
            }
            if conn.lock().conn.is_closed() {
                return Err(EngineError::Connection(
                    "client closed before receiving server assignment".to_string(),
                ));
            }
        }
        Err(EngineError::Connection(
            "timed out waiting for authenticated server assignment".to_string(),
        ))
    }

    #[cfg(target_os = "linux")]
    fn poll_connection_send(
        &self,
        conn: &Arc<parking_lot::Mutex<QuicFuscateConnection>>,
        out: &mut [u8],
    ) -> Result<Option<usize>, EngineError> {
        let mut conn_guard = conn.lock();
        match conn_guard.send(out) {
            Ok(0) | Err(crate::error::ConnectionError::Done) => Ok(None),
            Ok(written) => Ok(Some(written)),
            Err(error) => Err(self.transport_send_error("client outbound connection send", error)),
        }
    }

    #[cfg(target_os = "linux")]
    async fn enqueue_tun_datagram(
        &self,
        conn: &Arc<parking_lot::Mutex<QuicFuscateConnection>>,
        socket: &Arc<UdpSocket>,
        out: &mut [u8],
        tunnel_stream_id: u64,
        packet: &[u8],
    ) -> Result<(), EngineError> {
        loop {
            let result = {
                let mut conn_guard = conn.lock();
                conn_guard.send_tunnel_packet(tunnel_stream_id, packet)
            };
            match result {
                Ok(()) => return Ok(()),
                Err(crate::error::ConnectionError::DgramQueueFull) => {
                    if self.shutdown.load(Ordering::Relaxed) {
                        return Ok(());
                    }
                    // A full QUIC DATAGRAM queue can only drain when the
                    // connection emits packets. Flush that output before
                    // retrying so backpressure cannot become an infinite
                    // sleep loop.
                    self.flush_outbound(conn, socket, out).await?;
                    tokio::time::sleep(Duration::from_millis(1)).await;
                }
                Err(error) => {
                    return Err(self.transport_send_error("client TUN datagram enqueue", error));
                }
            }
        }
    }

    /// Run the outbound loop (TUN -> QUIC).
    ///
    /// Reads packets from TUN, processes through Stealth/FEC, sends via UDP.
    pub async fn run_outbound(
        &self,
        tun: Arc<parking_lot::Mutex<TunInterface>>,
        conn: Arc<parking_lot::Mutex<QuicFuscateConnection>>,
        socket: Arc<UdpSocket>,
        tunnel_stream_id: u64,
    ) -> Result<(), EngineError> {
        #[cfg(target_os = "linux")]
        {
            let read_contract = tun.lock().read_contract();
            if read_contract != TunReadContract::NonBlocking {
                return Err(self.reader_stopped_error(
                    "client outbound TUN reader",
                    std::io::Error::new(
                        std::io::ErrorKind::Unsupported,
                        "generic client I/O requires a nonblocking TUN backend; use an owned reader for blocking backends",
                    ),
                ));
            }
        }
        #[cfg(target_os = "linux")]
        let mut send_buf = vec![0u8; 65535];
        #[cfg(target_os = "linux")]
        let batch_cap = self.normalized_batch_size();
        #[cfg(target_os = "linux")]
        let mut batch_payloads: Vec<Vec<u8>> =
            (0..batch_cap).map(|_| Vec::with_capacity(2048)).collect();
        #[cfg(target_os = "linux")]
        while !self.shutdown.load(Ordering::Relaxed) {
            // Read from the validated nonblocking TUN backend - returns (block, len).
            let read_result = {
                let tun_guard = tun.lock();
                tun_guard.read_block()
            };
            match read_result {
                Ok((block, len)) if len > 0 => {
                    self.stats.tun_packets_read.fetch_add(1, Ordering::Relaxed);

                    self.enqueue_tun_datagram(
                        &conn,
                        &socket,
                        &mut send_buf,
                        tunnel_stream_id,
                        &block[..len],
                    )
                    .await?;

                    let mut queued = 0usize;
                    while queued < batch_cap {
                        let written = {
                            let mut conn_guard = conn.lock();
                            match conn_guard.send(&mut send_buf) {
                                Ok(0) | Err(crate::error::ConnectionError::Done) => break,
                                Ok(written) => written,
                                Err(e) => {
                                    log::debug!("Connection send done: {:?}", e);
                                    return Err(
                                        self.transport_send_error("client TUN connection send", e)
                                    );
                                }
                            }
                        };
                        let slot = &mut batch_payloads[queued];
                        slot.clear();
                        slot.extend_from_slice(&send_buf[..written]);
                        crate::optimize::telemetry::IO_DRIVER_COPY_OPS
                            .fetch_add(1, Ordering::Relaxed);
                        crate::optimize::telemetry::IO_DRIVER_COPY_BYTES
                            .fetch_add(written as u64, Ordering::Relaxed);
                        queued += 1;
                    }

                    if queued == 0 {
                        continue;
                    }

                    #[cfg(all(target_os = "linux", feature = "io_uring"))]
                    let dispatch = { resolve_outbound_dispatch(queued, self.has_uring()) };
                    #[cfg(target_os = "linux")]
                    let mut sent = vec![false; queued];
                    #[cfg(target_os = "linux")]
                    {
                        use std::os::fd::AsRawFd;
                        let socket_fd = socket.as_raw_fd();
                        // The reference vector is scoped to the synchronous
                        // dispatch phase. It cannot keep borrowing
                        // `batch_payloads` into the next loop iteration, and
                        // SmallVec keeps the configured maximum batch inline.
                        #[cfg(feature = "io_uring")]
                        let batch_refs: smallvec::SmallVec<[&[u8]; 256]> = batch_payloads
                            .iter()
                            .take(queued)
                            .map(|payload| payload.as_slice())
                            .collect();

                        // io_uring batch path (preferred when available).
                        #[cfg(feature = "io_uring")]
                        if matches!(dispatch, OutboundDispatch::IoUringBatch) {
                            if let Some(worker) = self.uring_worker.as_ref() {
                                match worker
                                    .send_batch_with_disposition(socket_fd, &batch_refs)
                                    .await
                                {
                                    Ok(result) => {
                                        for (index, sent_slot) in sent.iter_mut().enumerate() {
                                            *sent_slot = result.is_sent(index);
                                        }
                                        crate::telemetry::IO_URING_SUBMIT_PACKETS
                                            .inc_by(result.sent_count() as u64);
                                    }
                                    Err(error)
                                        if error.kind() == std::io::ErrorKind::WouldBlock =>
                                    {
                                        log::debug!(
                                            "io_uring worker busy, falling back: {}",
                                            error
                                        );
                                        crate::telemetry::IO_URING_FALLBACKS.inc();
                                    }
                                    Err(error) => {
                                        return Err(self.transport_send_error(
                                            "client io_uring blocking worker",
                                            error,
                                        ));
                                    }
                                }
                            }
                        }

                        // sendmmsg receives only the slots not already accepted by
                        // io_uring. Its contiguous prefix is therefore relative to
                        // a retry subset, never to the original batch.
                        let mut fallback_indices: smallvec::SmallVec<[usize; 256]> =
                            smallvec::SmallVec::new();
                        let mut fallback_refs: smallvec::SmallVec<[&[u8]; 256]> =
                            smallvec::SmallVec::new();
                        for (index, payload) in batch_payloads.iter().take(queued).enumerate() {
                            if !sent[index] {
                                fallback_indices.push(index);
                                fallback_refs.push(payload.as_slice());
                            }
                        }

                        // sendmmsg batch path (fallback from io_uring, or primary).
                        if fallback_refs.len() > 1 {
                            match try_sendmmsg_batch(
                                self.hotpath_adapter.as_ref(),
                                socket_fd,
                                OutboundDispatch::SendmmsgBatch,
                                &fallback_refs,
                            ) {
                                Ok(n) => {
                                    let sent_by_batch = n.min(fallback_indices.len());
                                    for index in fallback_indices.iter().take(sent_by_batch) {
                                        sent[*index] = true;
                                    }
                                    crate::optimize::telemetry::IO_DRIVER_SENDMMSG_CALLS
                                        .fetch_add(1, Ordering::Relaxed);
                                    crate::optimize::telemetry::IO_DRIVER_SENDMMSG_PACKETS
                                        .fetch_add(sent_by_batch as u64, Ordering::Relaxed);
                                }
                                Err(error)
                                    if matches!(
                                        error.kind(),
                                        std::io::ErrorKind::InvalidData
                                            | std::io::ErrorKind::WriteZero
                                    ) =>
                                {
                                    return Err(self.transport_send_error(
                                        "client UDP sendmmsg result",
                                        error,
                                    ));
                                }
                                Err(error) => {
                                    log::debug!("sendmmsg batch fallback: {}", error);
                                }
                            }
                        }
                    }

                    for (index, payload) in batch_payloads.iter().take(queued).enumerate() {
                        if sent[index] {
                            continue;
                        }
                        if let Err(e) = socket.send(payload).await {
                            log::warn!("UDP send error: {}", e);
                            return Err(self.transport_send_error("client TUN UDP send", e));
                        }

                        {
                            self.stats.udp_packets_sent.fetch_add(1, Ordering::Relaxed);
                            let global = crate::instrumentation::global();
                            global.transport.record_bytes_out(payload.len() as u64);
                            global.transport.record_packet_out();
                        }
                    }
                    for (index, payload) in batch_payloads.iter().take(queued).enumerate() {
                        if !sent[index] {
                            continue;
                        }
                        self.stats.udp_packets_sent.fetch_add(1, Ordering::Relaxed);
                        let global = crate::instrumentation::global();
                        global.transport.record_bytes_out(payload.len() as u64);
                        global.transport.record_packet_out();
                    }
                }
                Ok(_) => {
                    // No TUN data. Still flush pending transport packets (handshake/acks/pto)
                    // so short-lived and no-tun clients can complete connection setup.
                    if let Some(written) = self.poll_connection_send(&conn, &mut send_buf)? {
                        if written > 0 {
                            if let Err(e) = socket.send(&send_buf[..written]).await {
                                log::warn!("UDP send error (idle flush): {}", e);
                                return Err(self.transport_send_error("client idle UDP flush", e));
                            }
                            self.stats.udp_packets_sent.fetch_add(1, Ordering::Relaxed);
                            let global = crate::instrumentation::global();
                            global.transport.record_bytes_out(written as u64);
                            global.transport.record_packet_out();
                            continue;
                        }
                    }
                    tokio::time::sleep(tokio::time::Duration::from_micros(
                        self.config.poll_interval_us,
                    ))
                    .await;
                }
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
                    ) =>
                {
                    // A nonblocking or interrupted read is a retryable idle state.
                    if let Some(written) = self.poll_connection_send(&conn, &mut send_buf)? {
                        if written > 0 {
                            if let Err(e) = socket.send(&send_buf[..written]).await {
                                log::warn!("UDP send error (error-path flush): {}", e);
                                return Err(
                                    self.transport_send_error("client read-error UDP flush", e)
                                );
                            } else {
                                self.stats.udp_packets_sent.fetch_add(1, Ordering::Relaxed);
                                let global = crate::instrumentation::global();
                                global.transport.record_bytes_out(written as u64);
                                global.transport.record_packet_out();
                                continue;
                            }
                        }
                    }
                    tokio::time::sleep(tokio::time::Duration::from_millis(1)).await;
                }
                Err(error) => {
                    return Err(self.reader_stopped_error("client outbound TUN reader", error));
                }
            }
        }

        #[cfg(not(target_os = "linux"))]
        {
            let _ = (tun, conn, socket, tunnel_stream_id);
            Err(EngineError::Transport(
                "outbound Linux TUN loop is only available on Linux".to_string(),
            ))
        }

        #[cfg(target_os = "linux")]
        Ok(())
    }

    /// Run the inbound loop (QUIC -> TUN).
    ///
    /// Receives packets from UDP, processes through FEC/Stealth, writes to TUN.
    /// On Linux with `io_uring` feature: uses a dedicated io_uring ring with
    /// pre-posted RecvMsg SQEs and an eventfd bridge to Tokio.
    pub async fn run_inbound(
        &self,
        tun: Arc<parking_lot::Mutex<TunInterface>>,
        conn: Arc<parking_lot::Mutex<QuicFuscateConnection>>,
        socket: Arc<UdpSocket>,
        ingress: ClientTunnelIngress,
        handshake_event: Arc<(parking_lot::Mutex<bool>, parking_lot::Condvar)>,
    ) -> Result<(), EngineError> {
        // Try io_uring recv path on Linux.
        #[cfg(all(target_os = "linux", feature = "io_uring"))]
        {
            if let Some(uring) = Self::try_init_uring_recv(&socket, &conn) {
                return self
                    .run_inbound_uring(tun, conn, socket, ingress, handshake_event, uring)
                    .await;
            }
        }

        // Fallback: standard Tokio recv path.
        self.run_inbound_standard(tun, conn, socket, ingress, handshake_event).await
    }

    /// Standard inbound path using Tokio async recv + try_recv drain loop.
    async fn run_inbound_standard(
        &self,
        tun: Arc<parking_lot::Mutex<TunInterface>>,
        conn: Arc<parking_lot::Mutex<QuicFuscateConnection>>,
        socket: Arc<UdpSocket>,
        ingress: ClientTunnelIngress,
        handshake_event: Arc<(parking_lot::Mutex<bool>, parking_lot::Condvar)>,
    ) -> Result<(), EngineError> {
        let mut recv_buf = vec![0u8; 65535];
        let mut send_buf = vec![0u8; 65535];
        let batch_cap = self.normalized_batch_size();
        let mut inbound_batch: Vec<Vec<u8>> =
            (0..batch_cap).map(|_| Vec::with_capacity(2048)).collect();
        let mut handshake_signaled = false;

        while !self.shutdown.load(Ordering::Relaxed) {
            let timeout = self.recv_timeout(&conn);
            let recv = tokio::time::timeout(timeout, socket.recv(&mut recv_buf)).await;
            match recv {
                Err(_) => {}
                Ok(Err(e)) => {
                    if e.kind() != std::io::ErrorKind::WouldBlock {
                        log::warn!("UDP recv error: {}", e);
                        return Err(self.transport_receive_error("client UDP receive", e));
                    }
                }
                Ok(Ok(len)) if len > 0 => {
                    let mut queued = 0usize;
                    inbound_batch[queued].clear();
                    inbound_batch[queued].extend_from_slice(&recv_buf[..len]);
                    crate::optimize::telemetry::IO_DRIVER_COPY_OPS.fetch_add(1, Ordering::Relaxed);
                    crate::optimize::telemetry::IO_DRIVER_COPY_BYTES
                        .fetch_add(len as u64, Ordering::Relaxed);
                    queued += 1;

                    while queued < batch_cap {
                        match socket.try_recv(&mut recv_buf) {
                            Ok(more) if more > 0 => {
                                inbound_batch[queued].clear();
                                inbound_batch[queued].extend_from_slice(&recv_buf[..more]);
                                crate::optimize::telemetry::IO_DRIVER_COPY_OPS
                                    .fetch_add(1, Ordering::Relaxed);
                                crate::optimize::telemetry::IO_DRIVER_COPY_BYTES
                                    .fetch_add(more as u64, Ordering::Relaxed);
                                queued += 1;
                            }
                            Ok(_) => break,
                            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                            Err(e) => {
                                log::debug!("UDP try_recv batch stop: {}", e);
                                return Err(
                                    self.transport_receive_error("client UDP batch receive", e)
                                );
                            }
                        }
                    }
                    if queued > 1 {
                        crate::optimize::telemetry::IO_DRIVER_BATCH_DRAIN_PACKETS
                            .fetch_add((queued - 1) as u64, Ordering::Relaxed);
                    }

                    self.process_inbound_batch(&conn, &tun, &ingress, &inbound_batch, queued)?;
                }
                Ok(Ok(_)) => {}
            }

            if !handshake_signaled {
                let established = { conn.lock().conn.is_established() };
                if established {
                    let (lock, cvar) = &*handshake_event;
                    *lock.lock() = true;
                    cvar.notify_all();
                    handshake_signaled = true;
                }
            }

            // Flush any ACKs or PTO probes produced by recv or by a recovery
            // deadline that fired while we were waiting.
            self.flush_outbound(&conn, &socket, &mut send_buf).await?;
        }
        Ok(())
    }

    /// io_uring inbound path using pre-posted RecvMsg SQEs and eventfd bridge.
    #[cfg(all(target_os = "linux", feature = "io_uring"))]
    async fn run_inbound_uring(
        &self,
        tun: Arc<parking_lot::Mutex<TunInterface>>,
        conn: Arc<parking_lot::Mutex<QuicFuscateConnection>>,
        socket: Arc<UdpSocket>,
        ingress: ClientTunnelIngress,
        handshake_event: Arc<(parking_lot::Mutex<bool>, parking_lot::Condvar)>,
        uring: UringInboundRuntime,
    ) -> Result<(), EngineError> {
        let UringInboundRuntime { mut receiver, event } = uring;
        let mut send_buf = vec![0u8; 65535];
        let mut handshake_signaled = false;

        while !self.shutdown.load(Ordering::Relaxed) {
            // Wait for CQ notification via eventfd, capped by the connection's
            // earliest send deadline so recovery/PTO timers are not overslept.
            let timeout = self.recv_timeout(&conn);
            let readable = tokio::time::timeout(timeout, event.readable()).await;

            match readable {
                Ok(Ok(mut guard)) => {
                    // Clear the eventfd counter (read 8 bytes).
                    let mut efd_buf = [0u8; 8];
                    // SAFETY: `receiver.eventfd_fd()` returns the eventfd file descriptor
                    // created inside `UringRecvBatch::with_defaults`. It is valid and open
                    // for the lifetime of `receiver`. `efd_buf` is an 8-byte stack buffer
                    // (the exact width mandated by the eventfd ABI). We request exactly 8
                    // bytes, which is the only valid read size for an eventfd. The raw
                    // pointer cast to `*mut c_void` is safe for a `[u8; 8]` stack array.
                    let efd_ret = unsafe {
                        libc::read(
                            receiver.eventfd_fd(),
                            efd_buf.as_mut_ptr() as *mut libc::c_void,
                            8,
                        )
                    };
                    if efd_ret < 0 {
                        let error = std::io::Error::last_os_error();
                        if !matches!(
                            error.kind(),
                            std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
                        ) {
                            return Err(
                                self.transport_receive_error("client io_uring eventfd read", error)
                            );
                        }
                    } else if let Err(error) = validate_eventfd_read_len(efd_ret) {
                        return Err(self
                            .transport_receive_error("client io_uring eventfd short read", error));
                    }
                    guard.clear_ready();

                    // Drain all completed receives.
                    let completions = receiver.drain_completions().map_err(|e| {
                        self.transport_receive_error("client io_uring completion drain", e)
                    })?;

                    if !completions.is_empty() {
                        crate::telemetry::IO_URING_RECV_BATCHES.inc();
                        crate::telemetry::IO_URING_RECV_PACKETS.inc_by(completions.len() as u64);

                        for c in completions {
                            self.stats.udp_packets_received.fetch_add(1, Ordering::Relaxed);
                            let global = crate::instrumentation::global();
                            global.transport.record_bytes_in(c.len() as u64);
                            global.transport.record_packet_in();

                            {
                                let mut conn_guard = conn.lock();
                                let recv_result = if let Some(block) = c.block {
                                    conn_guard.recv_pooled_block(block, c.len)
                                } else {
                                    conn_guard.recv(&c.data)
                                };
                                if let Err(e) = recv_result {
                                    log::debug!("Connection recv error: {:?}", e);
                                    return Err(self.transport_receive_error(
                                        "client io_uring QUIC receive",
                                        e,
                                    ));
                                }
                            }

                            self.poll_http3_to_ingress(&conn, &ingress)?;
                            self.drain_ingress_to_tun(&tun, &ingress)?;
                        }
                    }
                }
                Ok(Err(e)) => {
                    log::warn!("AsyncFd error on uring recv eventfd: {}", e);
                    return Err(self.transport_receive_error("client io_uring eventfd", e));
                }
                Err(_) => {
                    // Timeout - check shutdown, continue.
                }
            }

            if !handshake_signaled {
                let established = { conn.lock().conn.is_established() };
                if established {
                    let (lock, cvar) = &*handshake_event;
                    *lock.lock() = true;
                    cvar.notify_all();
                    handshake_signaled = true;
                }
            }

            // Flush ACKs or PTO probes produced by the completions/timeout.
            self.flush_outbound(&conn, &socket, &mut send_buf).await?;
        }
        Ok(())
    }

    /// Try to initialise io_uring recv batch on the socket fd.
    #[cfg(all(target_os = "linux", feature = "io_uring"))]
    fn try_init_uring_recv(
        socket: &Arc<UdpSocket>,
        conn: &Arc<parking_lot::Mutex<QuicFuscateConnection>>,
    ) -> Option<UringInboundRuntime> {
        use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

        let socket_fd = socket.as_raw_fd();
        let memory_pool = { conn.lock().recv_memory_pool() };
        let mut receiver = crate::optimize::uring_batch::UringRecvBatch::with_defaults_pool(
            socket_fd,
            false,
            memory_pool,
        )?;

        if receiver.post_initial().is_err() {
            log::debug!("io_uring recv post_initial failed");
            return None;
        }

        // dup() the eventfd so AsyncFd can take ownership of the copy
        // while UringRecvBatch retains the original (both sides close safely).
        // SAFETY: `receiver.eventfd_fd()` returns a valid open eventfd descriptor for
        // the lifetime of `receiver`. `dup()` creates a new independent fd referring to
        // the same underlying kernel object; the original is unaffected. We check for < 0
        // (error) before using `efd_dup`.
        let efd_dup = unsafe { libc::dup(receiver.eventfd_fd()) };
        if efd_dup < 0 {
            log::debug!("eventfd dup failed");
            return None;
        }
        // SAFETY: `efd_dup` is the freshly duplicated file descriptor obtained from the
        // successful `libc::dup()` call above. It is a valid, open fd that we have just
        // created, so we are taking its sole ownership here. `OwnedFd` will close it on
        // drop; the original eventfd in `receiver` is separately managed.
        let owned_efd = unsafe { OwnedFd::from_raw_fd(efd_dup) };
        let event = tokio::io::unix::AsyncFd::new(owned_efd).ok()?;

        log::info!("io_uring recv batch initialised (eventfd bridge active)");
        crate::telemetry::IO_URING_RECV_ACTIVE.store(1, std::sync::atomic::Ordering::Relaxed);

        Some(UringInboundRuntime { receiver, event })
    }

    fn poll_http3_to_ingress(
        &self,
        conn: &Arc<parking_lot::Mutex<QuicFuscateConnection>>,
        ingress: &ClientTunnelIngress,
    ) -> Result<(), EngineError> {
        let sink = ingress.clone();
        let result = conn.lock().poll_http3_with(|data| {
            if !sink.push(data) {
                log::debug!("client H3/MASQUE ingress queue rejected {} bytes", data.len());
            }
        });
        result.map_err(|error| self.transport_receive_error("client H3 poll", error))
    }

    fn drain_ingress_to_tun(
        &self,
        tun: &Arc<parking_lot::Mutex<TunInterface>>,
        ingress: &ClientTunnelIngress,
    ) -> Result<(), EngineError> {
        for packet in ingress.drain() {
            let mut tun_guard = tun.lock();
            if let Err(error) = tun_guard.write_packet(&packet) {
                log::warn!("TUN write error: {:?}", error);
                return Err(self.tun_write_error("client H3/MASQUE downlink", error));
            }
            self.stats.tun_packets_written.fetch_add(1, Ordering::Relaxed);
        }
        Ok(())
    }

    /// Process a batch of received inbound packets through QUIC, H3/MASQUE, and TUN.
    fn process_inbound_batch(
        &self,
        conn: &Arc<parking_lot::Mutex<QuicFuscateConnection>>,
        tun: &Arc<parking_lot::Mutex<TunInterface>>,
        ingress: &ClientTunnelIngress,
        batch: &[Vec<u8>],
        count: usize,
    ) -> Result<(), EngineError> {
        for payload in batch.iter().take(count) {
            self.stats.udp_packets_received.fetch_add(1, Ordering::Relaxed);
            let global = crate::instrumentation::global();
            global.transport.record_bytes_in(payload.len() as u64);
            global.transport.record_packet_in();

            {
                let mut conn_guard = conn.lock();
                if let Err(e) = conn_guard.recv(payload) {
                    log::debug!("Connection recv error: {:?}", e);
                    self.stats.errors.fetch_add(1, Ordering::Relaxed);
                    return Err(EngineError::DataPlane(DataPlaneFault::TransportReceive {
                        component: "client QUIC receive".to_string(),
                        error: e.to_string(),
                    }));
                }
            }
            self.poll_http3_to_ingress(conn, ingress)?;
            self.drain_ingress_to_tun(tun, ingress)?;
        }
        Ok(())
    }
}

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
