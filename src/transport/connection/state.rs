// ============================================================================
// QUIC Connection - Core Transport State Machine
// ============================================================================

use super::*;
use crate::time_source::ProtocolClock;

/// QUIC connection
pub struct Connection {
    /// Monotonic clock shared by every protocol-facing transport owner.
    pub(crate) clock: ProtocolClock,
    // Internal state
    pub(super) scid: ConnectionId,
    pub(super) dcid: ConnectionId,
    /// Destination Connection ID retained for the Initial packet space.
    /// Client: the original DCID used to verify Retry integrity.
    /// Server: the DCID from the accepted Initial, including the Retry SCID
    /// selected by the server when Retry occurred.
    pub(super) initial_dcid: ConnectionId,
    /// Original client-selected Destination Connection ID retained independently from the
    /// Initial key-derivation CID. On a server this remains the pre-Retry ODCID.
    pub(super) original_dcid: ConnectionId,
    pub(super) is_server: bool,
    pub(super) is_established: bool,
    pub(super) is_closed: bool,
    pub(super) is_draining: bool,
    pub(super) received_non_vn_packet: bool,
    /// Stream storage. HashMap provides O(1) amortized lookup but poor cache locality
    /// at high stream counts (>10k). Hash table entries scatter across memory, causing
    /// L1/L2 cache misses during iteration and lookup. Consider replacing with a slot map
    /// (slotmap crate) or arena-based structure for better cache locality at scale.
    /// See: todo-181
    pub(super) streams: HashMap<u64, Stream>,
    pub(super) local_addr: SocketAddr,
    pub(super) peer_addr: SocketAddr,
    pub(super) config: Config,
    pub(super) version_negotiation: super::version::VersionNegotiationState,
    pub(super) stats: Stats,
    pub(super) dgram_recv_queue: DatagramQueue,
    pub(super) dgram_send_queue: DatagramQueue,
    #[cfg(feature = "zero_copy_dgram")]
    /// Pool whose fixed block-size contract bounds every zero-copy datagram payload.
    pub(super) dgram_pool: Arc<crate::optimize::MemoryPool>,
    pub(super) dgram_send_max_size: usize,
    pub(super) timeout_count: u32,
    pub(super) rtt: Duration,
    pub(super) cwnd: usize,
    pub(super) bytes_in_flight: usize,
    pub(super) path_id: u64,
    pub(super) path_events: VecDeque<PathEvent>,
    pub(super) validated_paths: HashSet<(SocketAddr, SocketAddr)>,
    pub(super) pending_path_validation: Option<PendingPathValidation>,
    pub(super) pending_path_frames: VecDeque<PendingPathFrame>,
    pub(super) last_migration_at: Option<Instant>,
    pub(super) dest_cids: cid::ConnectionIdSet,
    pub(super) pkt_spaces: [pnspace::PktNumSpace; 3],
    /// Next outbound packet number for each QUIC packet-number space.
    ///
    /// The connection owner never resets these counters during a 1-RTT key update. A
    /// reset is valid only when a new packet-number/key epoch is installed, such as
    /// connection/version restart or Retry Initial-key derivation.
    pub(super) next_send_pn_by_space: [u64; 3],
    // Current key phase (short-header KEY_PHASE bit); key updates keep packet numbers.
    pub(super) key_phase: bool,
    pub(super) readable_streams: VecDeque<u64>,
    pub(super) readable_stream_ids: HashSet<u64>,
    pub(super) reset_streams: VecDeque<(u64, u64)>,
    pub(super) reset_stream_ids: HashSet<u64>,
    pub(super) writable_streams: VecDeque<u64>,
    pub(super) writable_stream_ids: HashSet<u64>,
    /// First locally decided terminal/protocol error.
    pub(super) local_error: Option<crate::error::ConnectionError>,
    /// First peer-provided close reason, kept separate from local failures.
    pub(super) remote_error: Option<crate::error::ConnectionError>,
    #[cfg(any(test, feature = "rust-tests"))]
    pub(super) retired_scids: VecDeque<ConnectionId>,
    pub(super) bytes_in_flight_started: Option<Instant>,
    /// Last time an inbound packet was successfully received. Drives the idle
    /// timeout: run loops call on_timeout() every tick, but it must only act once
    /// the connection has actually been idle for `timeout()`, not on every tick.
    pub(super) last_activity: Instant,
    // Basic flow-control (local receive limits)
    // Receive-side connection window (what we allow peer to send)
    pub(super) conn_max_data: u64,
    pub(super) conn_bytes_recvd: u64,
    // Send-side connection window (what peer allows us to send)
    pub(super) peer_max_data: u64,

    // Unified TLS provider (rustls + optional TLS Cover)
    pub(super) tls_provider: Option<Box<dyn crate::qftls::QuicTlsProvider>>,
    pub(super) tls_profile: Option<qf_stealth::TlsProfile>,
    /// Immutable environment generation used by all TLS provider rebuilds for this connection.
    pub(super) environment: Arc<crate::env_utils::EnvSnapshot>,
    pub(super) conn_bytes_sent: u64,
    /// Control frames admitted through `queue_control_frame`; bounded and window-update coalesced.
    pub(super) pending_control: VecDeque<Frame<'static>>,
    // Crypto context (AEAD/HP) hooks for header and payload processing
    pub(super) crypto: Arc<parking_lot::RwLock<packet::CryptoContext>>,
    /// Lock-free 1-RTT crypto keys for the data-plane hot path.
    /// Loaded via `arc_swap::ArcSwapOption::load()` - no lock acquisition in steady state.
    pub(super) crypto_1rtt: arc_swap::ArcSwapOption<packet::OneRttCrypto>,
    /// Cached AEAD tag reserve (0 or 16) after 1-RTT seal key installation.
    pub(super) short_header_tag_reserve: u8,
    // ECN counters (for ACK ECN section)
    pub(super) ecn_ect0: u64,
    pub(super) ecn_ect1: u64,
    pub(super) ecn_ce: u64,
    // Recovery / CC
    pub(super) recovery: crate::transport::recovery::Recovery,
    // Deep FEC integration hooks (transport-level hints only; core applies)
    pub(super) fec_escalation_threshold: f32,
    pub(super) fec_ctrl_delta: FecControlDelta,
    // Recovery callback feedback counters for live FEC adaptation wiring.
    pub(super) fec_cb_sent_packets: Arc<std::sync::atomic::AtomicU64>,
    pub(super) fec_cb_lost_packets: Arc<std::sync::atomic::AtomicU64>,
    pub(super) fec_cb_sent_bytes: Arc<std::sync::atomic::AtomicU64>,
    pub(super) fec_cb_lost_bytes: Arc<std::sync::atomic::AtomicU64>,
    // ACK classification is owned by this connection, so no callback/atomic is needed.
    pub(super) fec_acked_packets: u64,
    // Packet spaces pending an RFC 9002 §6.2.4 PTO probe. Filled by
    // `on_recovery_timeout`, consumed by the handshake flight loop and the
    // 1-RTT assembly. Probes bypass the congestion gate (§7.5) but count in flight.
    pub(super) pending_probe_spaces: VecDeque<recovery::PacketSpace>,
    // Reliable STREAM ownership. Packet maps hold compact transmission IDs while
    // payload bytes remain owned exactly once until any packet copy is ACKed.
    pub(super) stream_transmissions: HashMap<u64, StreamTransmission>,
    pub(super) stream_retransmit_queue: VecDeque<u64>,
    pub(super) stream_transmission_by_pn: BTreeMap<u64, u64>,
    pub(super) lost_stream_transmission_by_pn: BTreeMap<u64, Vec<u64>>,
    pub(super) next_stream_transmission_id: u64,
    pub(super) stream_retransmit_bytes: usize,
    // Stealth timing: next eligible send time (if timing obfuscation enabled)
    // Whether Brain may actively steer stealth runtime actuators for this connection.
    pub(super) intelligent_stealth_runtime: bool,
    // Fine-grained lock surface for explicit operator transport overrides.
    pub(super) brain_runtime_permissions: crate::transport::BrainRuntimePermissions,
    // Optional observer for external modules (Stealth/Brain) to tap into telemetry
    pub(super) observer: Option<Arc<dyn TransportObserver>>,
    // Optional HTTP/3 connection bound to this QUIC transport
    pub(super) h3: Option<crate::transport::h3::Connection>,
    // Shared 0-RTT anti-replay strike register (server-side only).
    pub(super) strike_register: Option<Arc<super::anti_replay::StrikeRegister>>,
    // DPLPMTUD (RFC 8899) state for path MTU discovery.
    pub(super) pmtu: PmtuState,
    // Packet number of the in-flight DPLPMTUD probe (if any). Used to detect
    // probe ACK/loss in the ACK processing path.
    pub(super) pmtu_probe_pn: Option<u64>,
    // Packet numbers whose complete outer datagram exercised capacity above
    // the configured safe MTU floor.
    pub(super) pmtu_above_floor_pns: HashSet<u64>,
    // Single transport-owned deadline and bounded pending slot for idle chaff
    // and constant-rate traffic-analysis defense.
    pub(super) traffic_analysis: Option<qf_stealth::TrafficAnalysisScheduler>,
    // Authenticated baseline restored when Intelligent escalation deactivates.
    pub(super) traffic_analysis_base_policy: crate::transport::config::TrafficAnalysisPolicy,
    // Post-authentication Intelligent escalation ceiling. None is fail-closed.
    pub(super) traffic_analysis_escalation_ceiling:
        Option<crate::transport::config::TrafficAnalysisPolicy>,
}

impl Connection {
    /// Returns the connection-owned protocol clock for child transport owners.
    pub(crate) fn protocol_clock(&self) -> ProtocolClock {
        self.clock.clone()
    }

    /// Returns the next packet number only while it remains valid for QUIC's 62-bit
    /// packet-number field. The stateless AEAD primitives rely on this connection-owned
    /// guard to prevent counter reuse after overflow under one traffic-secret/IV epoch.
    #[inline(always)]
    pub(super) fn next_send_packet_number(
        &self,
        space_idx: usize,
    ) -> Result<u64, crate::error::ConnectionError> {
        let packet_number = self.next_send_pn_by_space[space_idx];
        if packet_number > pnspace::PktNumSpace::MAX_PACKET_NUMBER {
            return Err(crate::error::ConnectionError::AeadLimitReached);
        }
        Ok(packet_number)
    }

    /// Advances an outbound packet number without allowing a wrapping reuse.
    #[inline(always)]
    pub(super) fn advance_send_packet_number(
        &mut self,
        space_idx: usize,
    ) -> Result<(), crate::error::ConnectionError> {
        let packet_number = self.next_send_pn_by_space[space_idx];
        if packet_number > pnspace::PktNumSpace::MAX_PACKET_NUMBER {
            return Err(crate::error::ConnectionError::AeadLimitReached);
        }
        self.next_send_pn_by_space[space_idx] =
            packet_number.checked_add(1).ok_or(crate::error::ConnectionError::AeadLimitReached)?;
        Ok(())
    }
}

#[cfg(not(feature = "zero_copy_dgram"))]
type DatagramQueue = VecDeque<Vec<u8>>;

#[cfg(feature = "zero_copy_dgram")]
type DatagramQueue = VecDeque<DatagramBuffer>;

#[cfg(feature = "zero_copy_dgram")]
pub(super) struct DatagramBuffer {
    /// Pool-aware ownership guard. Dropping this buffer returns its block to `dgram_pool`.
    pub(super) data: crate::optimize::PooledBlock,
    pub(super) len: usize,
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
    pub(super) fn new() -> Self {
        Self { buffer: Box::new([0u8; 65536]), head: 0, tail: 0, size: 0 }
    }

    #[inline(always)]
    pub(super) fn write(&mut self, data: &[u8]) -> usize {
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
    pub(super) fn read(&mut self, buf: &mut [u8]) -> usize {
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
    pub(super) fn len(&self) -> usize {
        self.size
    }

    #[inline(always)]
    pub(super) fn is_empty(&self) -> bool {
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
