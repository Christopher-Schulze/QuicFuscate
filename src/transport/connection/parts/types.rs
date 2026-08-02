// ============================================================================
// QUIC Connection - Core Transport State Machine
// ============================================================================

/// QUIC connection
pub struct Connection {
    // Internal state
    scid: ConnectionId,
    dcid: ConnectionId,
    /// Destination Connection ID retained for the Initial packet space.
    /// Client: the original DCID used to verify Retry integrity.
    /// Server: the DCID from the accepted Initial, including the Retry SCID
    /// selected by the server when Retry occurred.
    initial_dcid: ConnectionId,
    is_server: bool,
    is_established: bool,
    is_closed: bool,
    is_draining: bool,
    received_non_vn_packet: bool,
    /// Stream storage. HashMap provides O(1) amortized lookup but poor cache locality
    /// at high stream counts (>10k). Hash table entries scatter across memory, causing
    /// L1/L2 cache misses during iteration and lookup. Consider replacing with a slot map
    /// (slotmap crate) or arena-based structure for better cache locality at scale.
    /// See: todo-181
    streams: HashMap<u64, Stream>,
    local_addr: SocketAddr,
    peer_addr: SocketAddr,
    config: Config,
    version_negotiation: super::version::VersionNegotiationState,
    stats: Stats,
    #[cfg(not(feature = "zero_copy_dgram"))]
    dgram_recv_queue: VecDeque<Vec<u8>>,
    #[cfg(not(feature = "zero_copy_dgram"))]
    dgram_send_queue: VecDeque<Vec<u8>>,
    #[cfg(feature = "zero_copy_dgram")]
    dgram_recv_queue: VecDeque<DatagramBuffer>,
    #[cfg(feature = "zero_copy_dgram")]
    dgram_send_queue: VecDeque<DatagramBuffer>,
    #[cfg(feature = "zero_copy_dgram")]
    dgram_pool: Arc<crate::optimize::MemoryPool>,
    dgram_send_max_size: usize,
    timeout_count: u32,
    rtt: Duration,
    cwnd: usize,
    bytes_in_flight: usize,
    path_id: u64,
    path_events: VecDeque<PathEvent>,
    validated_paths: HashSet<(SocketAddr, SocketAddr)>,
    pending_path_validation: Option<PendingPathValidation>,
    pending_path_frames: VecDeque<PendingPathFrame>,
    last_migration_at: Option<Instant>,
    dest_cids: cid::ConnectionIdSet,
    pkt_spaces: [pnspace::PktNumSpace; 3],
    next_send_pn_by_space: [u64; 3],
    // Current key phase (short header KEY_PHASE bit). Header bit only; no rotation here.
    key_phase: bool,
    readable_streams: VecDeque<u64>,
    writable_streams: VecDeque<u64>,
    local_error: Option<crate::error::ConnectionError>,
    #[cfg(any(test, feature = "rust-tests"))]
    retired_scids: VecDeque<ConnectionId>,
    bytes_in_flight_started: Option<Instant>,
    /// Last time an inbound packet was successfully received. Drives the idle
    /// timeout: run loops call on_timeout() every tick, but it must only act once
    /// the connection has actually been idle for `timeout()`, not on every tick.
    last_activity: Instant,
    // Basic flow-control (local receive limits)
    // Receive-side connection window (what we allow peer to send)
    conn_max_data: u64,
    conn_bytes_recvd: u64,
    // Send-side connection window (what peer allows us to send)
    peer_max_data: u64,

    // Unified TLS provider (rustls + optional TLS Cover)
    tls_provider: Option<Box<dyn crate::qftls::QuicTlsProvider>>,
    tls_profile: Option<crate::qftls::TlsProfile>,
    conn_bytes_sent: u64,
    /// Control frames admitted through `queue_control_frame`; bounded and window-update coalesced.
    pending_control: VecDeque<Frame<'static>>,
    // Crypto context (AEAD/HP) hooks for header and payload processing
    crypto: Arc<parking_lot::RwLock<packet::CryptoContext>>,
    /// Lock-free 1-RTT crypto keys for the data-plane hot path.
    /// Loaded via `arc_swap::ArcSwapOption::load()` - no lock acquisition in steady state.
    crypto_1rtt: arc_swap::ArcSwapOption<packet::OneRttCrypto>,
    /// Cached AEAD tag reserve (0 or 16) after 1-RTT seal key installation.
    short_header_tag_reserve: u8,
    // ECN counters (for ACK ECN section)
    ecn_ect0: u64,
    ecn_ect1: u64,
    ecn_ce: u64,
    // Recovery / CC
    recovery: crate::transport::recovery::Recovery,
    // Deep FEC integration hooks (transport-level hints only; core applies)
    fec_escalation_threshold: f32,
    fec_ctrl_delta: FecControlDelta,
    // Recovery callback feedback counters for live FEC adaptation wiring.
    fec_cb_sent_packets: Arc<std::sync::atomic::AtomicU64>,
    fec_cb_lost_packets: Arc<std::sync::atomic::AtomicU64>,
    fec_cb_sent_bytes: Arc<std::sync::atomic::AtomicU64>,
    fec_cb_lost_bytes: Arc<std::sync::atomic::AtomicU64>,
    // ACK classification is owned by this connection, so no callback/atomic is needed.
    fec_acked_packets: u64,
    // Packet spaces pending an RFC 9002 §6.2.4 PTO probe. Filled by
    // `on_recovery_timeout`, consumed by the handshake flight loop and the
    // 1-RTT assembly. Probes bypass the congestion gate (§7.5) but count in flight.
    pending_probe_spaces: VecDeque<recovery::PacketSpace>,
    // Reliable STREAM ownership. Packet maps hold compact transmission IDs while
    // payload bytes remain owned exactly once until any packet copy is ACKed.
    stream_transmissions: HashMap<u64, StreamTransmission>,
    stream_retransmit_queue: VecDeque<u64>,
    stream_transmission_by_pn: BTreeMap<u64, u64>,
    lost_stream_transmission_by_pn: BTreeMap<u64, Vec<u64>>,
    next_stream_transmission_id: u64,
    stream_retransmit_bytes: usize,
    // Stealth timing: next eligible send time (if timing obfuscation enabled)
    // Whether Brain may actively steer stealth runtime actuators for this connection.
    intelligent_stealth_runtime: bool,
    // Fine-grained lock surface for explicit operator transport overrides.
    brain_runtime_permissions: crate::transport::BrainRuntimePermissions,
    // Optional observer for external modules (Stealth/Brain) to tap into telemetry
    observer: Option<Arc<dyn TransportObserver>>,
    // Optional HTTP/3 connection bound to this QUIC transport
    h3: Option<crate::transport::h3::Connection>,
    // Shared 0-RTT anti-replay strike register (server-side only).
    strike_register: Option<Arc<super::anti_replay::StrikeRegister>>,
    // DPLPMTUD (RFC 8899) state for path MTU discovery.
    pmtu: PmtuState,
    // Packet number of the in-flight DPLPMTUD probe (if any). Used to detect
    // probe ACK/loss in the ACK processing path.
    pmtu_probe_pn: Option<u64>,
    // Packet numbers whose complete outer datagram exercised capacity above
    // the configured safe MTU floor.
    pmtu_above_floor_pns: HashSet<u64>,
    // Single transport-owned deadline and bounded pending slot for idle chaff
    // and constant-rate traffic-analysis defense.
    traffic_analysis: Option<crate::stealth::TrafficAnalysisScheduler>,
    // Authenticated baseline restored when Intelligent escalation deactivates.
    traffic_analysis_base_policy: crate::transport::config::TrafficAnalysisPolicy,
    // Post-authentication Intelligent escalation ceiling. None is fail-closed.
    traffic_analysis_escalation_ceiling:
        Option<crate::transport::config::TrafficAnalysisPolicy>,
}

#[cfg(feature = "zero_copy_dgram")]
struct DatagramBuffer {
    data: crate::optimize::AlignedBox<[u8]>,
    len: usize,
    _pool: Arc<crate::optimize::MemoryPool>,
}

/// Fixed-size 64 KB ring buffer for zero-copy stream I/O (feature-gated).
#[cfg(feature = "stream_ring_buffer")]
#[derive(Debug)]
pub struct StreamRingBuffer {
    buffer: Box<[u8; 65536]>, // Fixed 64KB ring
    head: usize,
    tail: usize,
    size: usize,
}

#[cfg(feature = "stream_ring_buffer")]
impl StreamRingBuffer {
    #[inline(always)]
    fn new() -> Self {
        Self { buffer: Box::new([0u8; 65536]), head: 0, tail: 0, size: 0 }
    }

    #[inline(always)]
    fn write(&mut self, data: &[u8]) -> usize {
        let capacity = self.buffer.len();
        let available = capacity - self.size;
        let to_write = data.len().min(available);

        let first = to_write.min(capacity - self.tail);
        self.buffer[self.tail..self.tail + first].copy_from_slice(&data[..first]);
        if first < to_write {
            let second = to_write - first;
            self.buffer[..second].copy_from_slice(&data[first..to_write]);
        }
        self.tail = (self.tail + to_write) & (capacity - 1);
        self.size += to_write;
        to_write
    }

    #[inline(always)]
    fn read(&mut self, buf: &mut [u8]) -> usize {
        let to_read = buf.len().min(self.size);
        let capacity = self.buffer.len();

        let first = to_read.min(capacity - self.head);
        buf[..first].copy_from_slice(&self.buffer[self.head..self.head + first]);
        if first < to_read {
            let second = to_read - first;
            buf[first..to_read].copy_from_slice(&self.buffer[..second]);
        }
        self.head = (self.head + to_read) & (capacity - 1);
        self.size -= to_read;
        to_read
    }

    #[inline(always)]
    fn len(&self) -> usize {
        self.size
    }

    #[inline(always)]
    fn is_empty(&self) -> bool {
        self.size == 0
    }
}

#[cfg(all(test, feature = "stream_ring_buffer"))]
#[test]
fn stream_ring_buffer_roundtrip() {
    let mut ring = StreamRingBuffer::new();
    let payload: Vec<u8> = (0..4096).map(|i| (i % 251) as u8).collect();
    let written = ring.write(&payload);
    assert_eq!(written, payload.len());
    let mut out = vec![0u8; payload.len()];
    let read = ring.read(&mut out);
    assert_eq!(read, payload.len());
    assert_eq!(out, payload);
}
