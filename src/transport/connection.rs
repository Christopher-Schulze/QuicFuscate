use super::{
    cid, config::Config, config::PmtuPolicy, config::TrafficAnalysisDefense, frames, packet,
    pnspace, recovery, udpfast, ConnectionId, EcnCounts, EcnMark, FecControlDelta, Frame,
    PacketType, PathStats, RecvInfo, SendInfo, Stats, Stream, TransportObserver, INITIAL_WINDOW,
    MAX_STREAM_SIZE, MIN_CLIENT_INITIAL_LEN,
};
use std::borrow::Cow;
use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::crypto::aead::AeadSeal;
use crate::optimize::{prefetch, PrefetchHint};

const MAX_RX_KEY_UPDATE_ADVANCE: usize = 4;
const PATH_VALIDATION_TIMEOUT: Duration = Duration::from_secs(3);
const MIGRATION_COOLDOWN: Duration = Duration::from_millis(750);
const MAX_STREAM_RETRANSMIT_BYTES: usize = 16 * 1024 * 1024;
const MAX_STREAM_ORIGINAL_TRANSMISSIONS: usize = 16 * 1024;
const MAX_STREAM_TRANSMISSIONS: usize = 2 * MAX_STREAM_ORIGINAL_TRANSMISSIONS;
const MAX_STREAM_LOST_PACKET_HISTORY: usize = 32;

/// DPLPMTUD (RFC 8899) state for packetization-layer MTU discovery.
///
/// Probes the path MTU by sending padded PING packets at increasing sizes.
/// Uses bounded binary search between the configured minimum and maximum.
/// Black hole detection falls back to the configured safe minimum.
/// DPLPMTUD probe state machine.
#[derive(Clone, Debug)]
pub struct PmtuState {
    /// Current confirmed MTU (starts at PMTU_MIN).
    confirmed_mtu: usize,
    /// Current probe target (binary search between confirmed and max).
    probe_target: usize,
    /// Whether a probe is in flight (and its size).
    probe_in_flight: Option<usize>,
    /// Timestamp of the last probe send.
    last_probe_sent: Option<Instant>,
    /// First unacknowledged packet above the safe floor. Later sends must not
    /// move this timestamp or a continuously black-holed path would never age.
    above_floor_unacked_since: Option<Instant>,
    /// Whether DPLPMTUD is enabled.
    enabled: bool,
    min_mtu: usize,
    max_mtu: usize,
    probe_interval: Duration,
    black_hole_timeout: Duration,
}

impl PmtuState {
    pub fn new(enabled: bool, policy: PmtuPolicy) -> Self {
        Self {
            confirmed_mtu: policy.min_mtu,
            probe_target: if enabled { policy.max_mtu } else { policy.min_mtu },
            probe_in_flight: None,
            last_probe_sent: None,
            above_floor_unacked_since: None,
            enabled,
            min_mtu: policy.min_mtu,
            max_mtu: policy.max_mtu,
            probe_interval: policy.probe_interval,
            black_hole_timeout: policy.black_hole_timeout,
        }
    }

    /// Returns the current effective MTU (confirmed, not probe target).
    pub fn effective_mtu(&self) -> usize {
        self.confirmed_mtu
    }

    /// Returns true if a DPLPMTUD probe should be sent now.
    pub fn should_send_probe(&self, now: Instant) -> bool {
        if !self.enabled {
            return false;
        }
        if self.probe_in_flight.is_some() {
            return false; // Already probing
        }
        if self.probe_target <= self.confirmed_mtu {
            return false; // No larger size to probe
        }
        // Send probe if interval has elapsed since last probe
        match self.last_probe_sent {
            Some(last) => now.duration_since(last) >= self.probe_interval,
            None => true, // First probe
        }
    }

    /// Returns whether a PMTU probe can bypass a closed congestion gate.
    ///
    /// RFC 8899 requires probes that are not congestion-controlled to be
    /// separated by at least one RTT. The caller still tracks an emitted probe
    /// as ack-eliciting, but only this interval makes the bypass safe.
    fn can_bypass_congestion(&self, rtt: Duration) -> bool {
        self.probe_interval >= rtt
    }

    /// Record that a probe of `size` bytes was sent.
    pub fn on_probe_sent(&mut self, size: usize, now: Instant) {
        self.probe_in_flight = Some(size);
        self.last_probe_sent = Some(now);
    }

    /// Record that a probe was ACKed - confirm the MTU.
    pub fn on_probe_acked(&mut self, _now: Instant) {
        if let Some(size) = self.probe_in_flight.take() {
            self.confirmed_mtu = size;
            // Next probe: try larger (binary search up)
            self.probe_target = (size + self.max_mtu) / 2;
            if self.probe_target == size {
                self.probe_target = self.max_mtu; // Already at max
            }
        }
        self.above_floor_unacked_since = None;
    }

    /// Record that a probe was lost - reduce probe target.
    pub fn on_probe_lost(&mut self) {
        if let Some(size) = self.probe_in_flight.take() {
            // Binary search down: try midpoint between confirmed and failed size
            let next_target = (self.confirmed_mtu + size) / 2;
            // Once the search converges at the confirmed floor, retain an
            // upward target. The probe interval then becomes the quiet period
            // before a periodic re-probe instead of leaving discovery parked
            // at the reduced MTU forever.
            self.probe_target =
                if next_target <= self.confirmed_mtu { self.max_mtu } else { next_target };
        }
    }

    /// Check for black hole (no ACKs for extended period).
    /// Returns true if MTU should be reset to minimum.
    pub fn check_black_hole(&self, now: Instant) -> bool {
        self.enabled
            && self.confirmed_mtu > self.min_mtu
            && self
                .above_floor_unacked_since
                .is_some_and(|sent| now.saturating_duration_since(sent) > self.black_hole_timeout)
    }

    /// Reset to minimum MTU (black hole detected).
    pub fn reset_to_minimum(&mut self, now: Instant) {
        self.confirmed_mtu = self.min_mtu;
        self.probe_target = self.min_mtu + (self.max_mtu - self.min_mtu) / 4;
        self.probe_in_flight = None;
        self.last_probe_sent = Some(now);
        self.above_floor_unacked_since = None;
    }

    /// Records the first packet that exercises capacity above the safe floor.
    pub fn on_packet_sent(&mut self, packet_size: usize, now: Instant) {
        if self.confirmed_mtu > self.min_mtu && packet_size > self.min_mtu {
            self.above_floor_unacked_since.get_or_insert(now);
        }
    }

    /// Records only ACKs that prove capacity above the safe floor remains usable.
    pub fn on_packet_acked(&mut self, packet_size: usize, _now: Instant) {
        if packet_size > self.min_mtu {
            self.above_floor_unacked_since = None;
        }
    }

    /// Returns the probe size to send (or None if no probe needed).
    pub fn probe_size(&self) -> Option<usize> {
        if self.enabled && self.probe_in_flight.is_none() && self.probe_target > self.confirmed_mtu
        {
            Some(self.probe_target)
        } else {
            None
        }
    }

    /// Returns the current probe target (the size the state machine wants to
    /// probe next), regardless of whether a probe is in flight.
    pub fn probe_target(&self) -> Option<usize> {
        if self.enabled && self.probe_target > self.confirmed_mtu {
            Some(self.probe_target)
        } else {
            None
        }
    }

    /// Returns true if DPLPMTUD is enabled.
    pub fn enabled(&self) -> bool {
        self.enabled
    }
}

/// Upper bound for peer-advertised MAX_DATA to prevent resource exhaustion (1 GiB).
/// A malicious peer sending MAX_DATA(u64::MAX) would effectively disable flow control.
const MAX_PEER_MAX_DATA: u64 = 1_073_741_824;

#[inline(always)]
fn prefetch_recv_packet_buffer(buf: &[u8]) {
    // SAFETY: `buf.as_ptr()` is a valid pointer to at least `buf.len()` bytes for the
    // lifetime of `buf`. Prefetch instructions are pure hints to the CPU and cannot
    // cause faults or UB even if the address turns out to be unmapped - on all supported
    // architectures a prefetch to an invalid address is silently ignored by the hardware.
    // The second prefetch (`ptr + 64`) is only issued when `buf.len() > 64`, ensuring
    // the offset is within the allocated object, making the pointer arithmetic valid.
    unsafe {
        prefetch(buf.as_ptr(), PrefetchHint::T0);
        if buf.len() > 64 {
            prefetch(buf.as_ptr().add(64), PrefetchHint::T0);
        }
    }
}

#[inline(always)]
fn prefetch_frame_parse_window(buf: *const u8, end: usize, off: usize) {
    let ahead = core::cmp::min(off + 64, end);
    crate::fec::prefetch_decode_window(buf.wrapping_add(ahead));
}

fn trace_send_packet(
    is_server: bool,
    pkt_ty: PacketType,
    space_idx: usize,
    pn: u64,
    pn_len: usize,
    header_len: usize,
    total_len: usize,
) {
    log::trace!(
        "[send] role={} ty={:?} space={} pn={} pn_len={} hdr_len={} total={}",
        if is_server { "server" } else { "client" },
        pkt_ty,
        space_idx,
        pn,
        pn_len,
        header_len,
        total_len
    );
}

/// Path-related events.
///
/// Path validation follows a single-candidate RFC 9000-style control path:
///
/// - New candidate paths emit `PathEvent::New` immediately.
/// - The transport generates PATH_CHALLENGE probes proactively.
/// - Matching PATH_RESPONSE frames are required before `Validated` is emitted.
/// - Peer-discovered unvalidated paths are subject to a 3x-style amplification cap.
/// - Local re-migration attempts are gated by a cooldown to avoid rapid path churn.
///
/// Current intentional limitation:
/// - The transport tracks one pending candidate path at a time rather than a full
///   multi-path validation set.
#[derive(Debug, Clone)]
pub enum PathEvent {
    /// New path has been created
    New(SocketAddr, SocketAddr),

    /// Path has been validated
    Validated(SocketAddr, SocketAddr),

    /// Path validation failed
    FailedValidation(SocketAddr, SocketAddr),

    /// Path has been closed
    Closed(SocketAddr, SocketAddr),

    /// Connection ID reused
    ReusedSourceConnectionId(u64, Option<(SocketAddr, SocketAddr)>, (SocketAddr, SocketAddr)),

    /// Peer migrated from the previous peer address to the new peer address.
    PeerMigrated(SocketAddr, SocketAddr),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PathValidationOrigin {
    LocalMigration,
    PeerPath,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct FecCallbackFeedback {
    pub(crate) sent_packets: u64,
    pub(crate) acked_packets: u64,
    pub(crate) lost_packets: u64,
}

#[derive(Debug, Clone)]
struct PendingPathFrame {
    local_addr: SocketAddr,
    peer_addr: SocketAddr,
    frame: Frame<'static>,
}

#[derive(Debug, Clone)]
struct PendingPathValidation {
    path_id: u64,
    old_local_addr: SocketAddr,
    old_peer_addr: SocketAddr,
    local_addr: SocketAddr,
    peer_addr: SocketAddr,
    challenge: [u8; 8],
    issued_at: Instant,
    received_bytes: usize,
    sent_bytes: usize,
    origin: PathValidationOrigin,
}

#[derive(Debug)]
struct StreamTransmission {
    stream_id: u64,
    offset: u64,
    data: Arc<[u8]>,
    fin: bool,
    queued: bool,
    active_packet: Option<u64>,
    lost_packets: VecDeque<u64>,
}

impl PendingPathValidation {
    fn matches_path(&self, local_addr: SocketAddr, peer_addr: SocketAddr) -> bool {
        self.local_addr == local_addr && self.peer_addr == peer_addr
    }
}

// ============================================================================
// QUIC Connection - Core Transport State Machine
// ============================================================================

/// QUIC connection
pub struct Connection {
    // Internal state
    scid: ConnectionId,
    dcid: ConnectionId,
    /// Original Destination Connection ID (ODCID) used for Initial key derivation (RFC 9001).
    /// Client: this is the initial DCID it chose for the first Initial packet.
    /// Server: this is the DCID observed in the first client Initial packet.
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
    // Chaff (dummy packet) generator for traffic analysis defense (TODO-455).
    // Active only when `traffic_analysis_defense` is `ConstantRate` and
    // `chaff_rate_pps > 0`. The generator is polled on every `send()` call; if
    // it signals that a chaff packet is due and no real ack-eliciting payload
    // was written, a PING+PADDING chaff packet is emitted instead.
    chaff: Option<crate::stealth::ChaffGenerator>,
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

        for &b in data.iter().take(to_write) {
            self.buffer[self.tail] = b;
            self.tail = (self.tail + 1) & (capacity - 1); // Fast modulo for power of 2
        }
        self.size += to_write;
        to_write
    }

    #[inline(always)]
    fn read(&mut self, buf: &mut [u8]) -> usize {
        let to_read = buf.len().min(self.size);
        for out in buf.iter_mut().take(to_read) {
            *out = self.buffer[self.head];
            self.head = (self.head + 1) & (self.buffer.len() - 1);
        }
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

impl Connection {
    /// Set the ODCID used for Initial key derivation (RFC 9001).
    ///
    /// For clients this also initializes the current destination CID used in the first Initial
    /// packet. For servers the current destination CID is learned from the peer's SCID when the
    /// first packet is received.
    pub(crate) fn set_initial_dcid(&mut self, dcid: ConnectionId) {
        self.initial_dcid = dcid;
        if !self.is_server {
            self.dcid = dcid;
        }
    }

    /// Set the current destination CID (what we put into outgoing DCID fields).
    pub(crate) fn set_destination_cid(&mut self, dcid: ConnectionId) {
        self.dcid = dcid;
        self.dest_cids.insert(&self.dcid);
    }

    pub(crate) fn new_with_role(
        scid: &[u8],
        local: SocketAddr,
        peer: SocketAddr,
        config: Config,
        is_server: bool,
    ) -> Self {
        let dgram_send_max_size = config.max_udp_payload_size as usize;
        let initial_max_data = config.initial_max_data;
        let pmtu_enabled = config.pmtu_discovery_enabled();
        let pmtu_policy = config.pmtu_policy();
        let version_negotiation = super::version::VersionNegotiationState::new(config.version);
        let mut conn = Self {
            scid: ConnectionId::from_vec(scid.to_vec()),
            dcid: ConnectionId::default(),
            initial_dcid: ConnectionId::default(),
            is_server,
            is_established: false,
            is_closed: false,
            is_draining: false,
            received_non_vn_packet: false,
            streams: HashMap::new(),
            local_addr: local,
            peer_addr: peer,
            config,
            version_negotiation,
            stats: Stats::default(),
            #[cfg(not(feature = "zero_copy_dgram"))]
            dgram_recv_queue: VecDeque::new(),
            #[cfg(not(feature = "zero_copy_dgram"))]
            dgram_send_queue: VecDeque::new(),
            #[cfg(feature = "zero_copy_dgram")]
            dgram_recv_queue: VecDeque::new(),
            #[cfg(feature = "zero_copy_dgram")]
            dgram_send_queue: VecDeque::new(),
            #[cfg(feature = "zero_copy_dgram")]
            dgram_pool: crate::optimize::global_pool(),
            dgram_send_max_size,
            timeout_count: 0,
            rtt: Duration::from_millis(0),
            cwnd: INITIAL_WINDOW,
            bytes_in_flight: 0,
            path_id: 0,
            path_events: VecDeque::new(),
            validated_paths: HashSet::from([(local, peer)]),
            pending_path_validation: None,
            pending_path_frames: VecDeque::new(),
            last_migration_at: None,
            dest_cids: cid::ConnectionIdSet::new(),
            pkt_spaces: [
                pnspace::PktNumSpace::default(),
                pnspace::PktNumSpace::default(),
                pnspace::PktNumSpace::default(),
            ],
            next_send_pn_by_space: [0, 0, 0],
            key_phase: false,
            readable_streams: VecDeque::new(),
            writable_streams: VecDeque::new(),
            local_error: None,
            #[cfg(any(test, feature = "rust-tests"))]
            retired_scids: VecDeque::new(),
            bytes_in_flight_started: None,
            last_activity: Instant::now(),
            conn_max_data: initial_max_data,
            conn_bytes_recvd: 0,
            peer_max_data: initial_max_data,
            tls_provider: None,
            tls_profile: None,
            conn_bytes_sent: 0,
            pending_control: VecDeque::new(),
            crypto: Arc::new(parking_lot::RwLock::new(packet::CryptoContext::default())),
            crypto_1rtt: arc_swap::ArcSwapOption::new(None),
            short_header_tag_reserve: 0,
            ecn_ect0: 0,
            ecn_ect1: 0,
            ecn_ce: 0,
            recovery: recovery::Recovery::new(INITIAL_WINDOW, dgram_send_max_size),
            fec_escalation_threshold: 0.05,
            fec_ctrl_delta: FecControlDelta::default(),
            fec_cb_sent_packets: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            fec_cb_lost_packets: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            fec_cb_sent_bytes: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            fec_cb_lost_bytes: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            fec_acked_packets: 0,
            pending_probe_spaces: VecDeque::new(),
            stream_transmissions: HashMap::new(),
            stream_retransmit_queue: VecDeque::new(),
            stream_transmission_by_pn: BTreeMap::new(),
            lost_stream_transmission_by_pn: BTreeMap::new(),
            next_stream_transmission_id: 0,
            stream_retransmit_bytes: 0,
            intelligent_stealth_runtime: false,
            brain_runtime_permissions: crate::transport::BrainRuntimePermissions::default(),
            observer: None,
            h3: None,
            strike_register: None,
            pmtu: PmtuState::new(pmtu_enabled, pmtu_policy),
            pmtu_probe_pn: None,
            pmtu_above_floor_pns: HashSet::new(),
            chaff: None,
        };
        // Initialize chaff generator when ConstantRate defense is configured
        // with a non-zero chaff rate.
        if matches!(
            conn.config.traffic_analysis_defense,
            crate::transport::config::TrafficAnalysisDefense::ConstantRate
        ) && conn.config.chaff_rate_pps > 0
        {
            conn.chaff = Some(crate::stealth::ChaffGenerator::new(
                conn.config.chaff_rate_pps,
                conn.config.chaff_size_bytes,
                true, // ack-eliciting so the peer generates cover ACKs
            ));
        }
        // Inherit strike register from config (server-side 0-RTT anti-replay).
        conn.strike_register = conn.config.strike_register.clone();
        // Apply configured initial RTT estimate before the first real measurement.
        if conn.config.initial_rtt_ms != 100 {
            conn.recovery.set_initial_rtt(Duration::from_millis(conn.config.initial_rtt_ms));
        }
        conn.install_recovery_fec_callbacks();
        conn.refresh_path_count();
        conn
    }

    pub(crate) fn new_client(
        scid: &[u8],
        local: SocketAddr,
        peer: SocketAddr,
        config: Config,
    ) -> Self {
        Self::new_with_role(scid, local, peer, config, false)
    }

    pub(crate) fn new_server(
        scid: &[u8],
        local: SocketAddr,
        peer: SocketAddr,
        config: Config,
    ) -> Self {
        Self::new_with_role(scid, local, peer, config, true)
    }

    /// Public wrapper to enable QUIC DATAGRAM queues via config
    pub fn enable_datagrams(&mut self, recv_q: usize, send_q: usize) {
        self.config.enable_dgram(recv_q, send_q);
    }
    pub(crate) fn dgram_pool_or_global(&self) -> Arc<crate::optimize::MemoryPool> {
        #[cfg(feature = "zero_copy_dgram")]
        {
            self.dgram_pool.clone()
        }
        #[cfg(not(feature = "zero_copy_dgram"))]
        {
            crate::optimize::global_pool()
        }
    }
    fn total_send_buffered_bytes(&self) -> usize {
        #[cfg(not(feature = "stream_ring_buffer"))]
        return self.streams.values().map(|s| s.send_buf.len()).sum();
        #[cfg(feature = "stream_ring_buffer")]
        return self.streams.values().map(|s| s.send_ring.len()).sum();
    }

    #[inline]
    fn stream_ledger_has_capacity(&self, payload_len: usize) -> bool {
        self.stream_transmissions.len() < MAX_STREAM_ORIGINAL_TRANSMISSIONS
            && self.stream_retransmit_bytes.saturating_add(payload_len)
                <= MAX_STREAM_RETRANSMIT_BYTES
    }

    fn has_sendable_stream_frame(&self) -> bool {
        if self.stream_retransmit_queue.iter().any(|transmission_id| {
            self.stream_transmissions
                .get(transmission_id)
                .is_some_and(|transmission| transmission.queued)
        }) {
            return true;
        }
        let Some(stream_id) = self.writable_streams.front() else {
            return false;
        };
        let Some(stream) = self.streams.get(stream_id) else {
            return false;
        };
        #[cfg(not(feature = "stream_ring_buffer"))]
        let has_data = !stream.send_buf.is_empty();
        #[cfg(feature = "stream_ring_buffer")]
        let has_data = !stream.send_ring.is_empty();
        if has_data {
            self.stream_ledger_has_capacity(1)
        } else {
            stream.send_fin && self.stream_ledger_has_capacity(0)
        }
    }

    fn stage_stream_transmission(
        &mut self,
        stream_id: u64,
        offset: u64,
        data: Arc<[u8]>,
        fin: bool,
    ) -> Result<u64, crate::error::ConnectionError> {
        if !self.stream_ledger_has_capacity(data.len()) {
            return Err(crate::error::ConnectionError::Done);
        }

        let transmission_id = self.allocate_stream_transmission_id()?;

        self.stream_retransmit_bytes = self.stream_retransmit_bytes.saturating_add(data.len());
        self.stream_transmissions.insert(
            transmission_id,
            StreamTransmission {
                stream_id,
                offset,
                data,
                fin,
                queued: true,
                active_packet: None,
                lost_packets: VecDeque::new(),
            },
        );
        self.stream_retransmit_queue.push_back(transmission_id);
        Ok(transmission_id)
    }

    fn allocate_stream_transmission_id(&mut self) -> Result<u64, crate::error::ConnectionError> {
        let transmission_id = self.next_stream_transmission_id;
        self.next_stream_transmission_id = self.next_stream_transmission_id.wrapping_add(1);
        if self.stream_transmissions.contains_key(&transmission_id) {
            return Err(crate::error::ConnectionError::InvalidState);
        }
        Ok(transmission_id)
    }

    fn split_queued_stream_transmission(
        &mut self,
        transmission_id: u64,
        prefix_len: usize,
    ) -> Result<(), crate::error::ConnectionError> {
        let Some(transmission) = self.stream_transmissions.get(&transmission_id) else {
            return Err(crate::error::ConnectionError::InvalidState);
        };
        if !transmission.queued
            || transmission.active_packet.is_some()
            || prefix_len == 0
            || prefix_len >= transmission.data.len()
        {
            return Err(crate::error::ConnectionError::InvalidState);
        }
        if self.stream_transmissions.len() >= MAX_STREAM_TRANSMISSIONS {
            return Err(crate::error::ConnectionError::Done);
        }

        let stream_id = transmission.stream_id;
        let tail_offset = transmission.offset.saturating_add(prefix_len as u64);
        let prefix = Arc::<[u8]>::from(&transmission.data[..prefix_len]);
        let tail = Arc::<[u8]>::from(&transmission.data[prefix_len..]);
        let tail_fin = transmission.fin;
        let lost_packets = transmission.lost_packets.clone();
        let tail_id = self.allocate_stream_transmission_id()?;

        let Some(transmission) = self.stream_transmissions.get_mut(&transmission_id) else {
            return Err(crate::error::ConnectionError::InvalidState);
        };
        transmission.data = prefix;
        transmission.fin = false;
        self.stream_transmissions.insert(
            tail_id,
            StreamTransmission {
                stream_id,
                offset: tail_offset,
                data: tail,
                fin: tail_fin,
                queued: true,
                active_packet: None,
                lost_packets: lost_packets.clone(),
            },
        );
        let tail_position = self
            .stream_retransmit_queue
            .iter()
            .position(|id| *id == transmission_id)
            .map_or(self.stream_retransmit_queue.len(), |position| position + 1);
        self.stream_retransmit_queue.insert(tail_position, tail_id);
        for packet_number in lost_packets {
            let transmission_ids =
                self.lost_stream_transmission_by_pn.entry(packet_number).or_default();
            if !transmission_ids.contains(&tail_id) {
                transmission_ids.push(tail_id);
            }
        }
        Ok(())
    }

    fn remove_stream_retransmit_queue_entry(&mut self, transmission_id: u64) {
        if self.stream_retransmit_queue.front() == Some(&transmission_id) {
            self.stream_retransmit_queue.pop_front();
        } else {
            self.stream_retransmit_queue.retain(|id| *id != transmission_id);
        }
    }

    fn commit_stream_transmission(&mut self, transmission_id: u64, packet_number: u64) {
        let Some(transmission) = self.stream_transmissions.get_mut(&transmission_id) else {
            return;
        };
        transmission.queued = false;
        transmission.active_packet = Some(packet_number);
        self.remove_stream_retransmit_queue_entry(transmission_id);
        self.stream_transmission_by_pn.insert(packet_number, transmission_id);
    }

    fn retire_stream_transmission(&mut self, transmission_id: u64) {
        let Some(transmission) = self.stream_transmissions.remove(&transmission_id) else {
            return;
        };
        self.stream_retransmit_bytes =
            self.stream_retransmit_bytes.saturating_sub(transmission.data.len());
        if let Some(packet_number) = transmission.active_packet {
            self.stream_transmission_by_pn.remove(&packet_number);
        }
        for packet_number in transmission.lost_packets {
            let remove_packet = if let Some(transmission_ids) =
                self.lost_stream_transmission_by_pn.get_mut(&packet_number)
            {
                transmission_ids.retain(|id| *id != transmission_id);
                transmission_ids.is_empty()
            } else {
                false
            };
            if remove_packet {
                self.lost_stream_transmission_by_pn.remove(&packet_number);
            }
        }
        if transmission.queued {
            self.remove_stream_retransmit_queue_entry(transmission_id);
        }
    }

    fn acknowledge_stream_transmission_packet(&mut self, packet_number: u64) {
        if let Some(transmission_id) = self.stream_transmission_by_pn.get(&packet_number).copied() {
            self.retire_stream_transmission(transmission_id);
            return;
        }
        let transmission_ids =
            self.lost_stream_transmission_by_pn.get(&packet_number).cloned().unwrap_or_default();
        for transmission_id in transmission_ids {
            self.retire_stream_transmission(transmission_id);
        }
    }

    fn lose_stream_transmission_packet(&mut self, packet_number: u64) {
        let Some(transmission_id) = self.stream_transmission_by_pn.remove(&packet_number) else {
            return;
        };

        let mut evicted_packet = None;
        if let Some(transmission) = self.stream_transmissions.get_mut(&transmission_id) {
            if transmission.active_packet == Some(packet_number) {
                transmission.active_packet = None;
            }
            if transmission.lost_packets.len() == MAX_STREAM_LOST_PACKET_HISTORY {
                evicted_packet = transmission.lost_packets.pop_front();
            }
            transmission.lost_packets.push_back(packet_number);
            if !transmission.queued {
                transmission.queued = true;
                self.stream_retransmit_queue.push_back(transmission_id);
            }
        }
        if let Some(evicted_packet) = evicted_packet {
            let remove_packet = if let Some(transmission_ids) =
                self.lost_stream_transmission_by_pn.get_mut(&evicted_packet)
            {
                transmission_ids.retain(|id| *id != transmission_id);
                transmission_ids.is_empty()
            } else {
                false
            };
            if remove_packet {
                self.lost_stream_transmission_by_pn.remove(&evicted_packet);
            }
        }
        let transmission_ids =
            self.lost_stream_transmission_by_pn.entry(packet_number).or_default();
        if !transmission_ids.contains(&transmission_id) {
            transmission_ids.push(transmission_id);
        }
    }

    fn acknowledge_late_stream_packets(&mut self, ranges: &[(u64, u64)]) {
        let mut transmission_ids = Vec::new();
        for (start, end) in ranges {
            transmission_ids.extend(
                self.lost_stream_transmission_by_pn
                    .range(*start..*end)
                    .flat_map(|(_, transmission_ids)| transmission_ids.iter().copied()),
            );
        }
        transmission_ids.sort_unstable();
        transmission_ids.dedup();
        for transmission_id in transmission_ids {
            self.retire_stream_transmission(transmission_id);
        }
    }

    /// Whether the peer's address counts as validated for recovery purposes
    /// (RFC 9002 §6.2.2.1). Clients are never amplification-limited; for a
    /// server, handshake completion implies validation happened by then.
    fn client_address_validated(&self) -> bool {
        !self.is_server || self.tls_handshake_complete()
    }

    /// Earliest loss/PTO deadline across all packet number spaces
    /// (RFC 9002 §6.1.2/§6.2.1). `None` disarms the recovery timer.
    pub fn recovery_deadline(&self) -> Option<Instant> {
        self.recovery.loss_detection_timeout(
            self.tls_handshake_complete(),
            self.is_server,
            self.client_address_validated(),
        )
    }

    /// Runs the recovery loss-detection timer: declares time-threshold losses
    /// or queues PTO probes (RFC 9002 A.8). Event loops call this when
    /// [`recovery_deadline`](Self::recovery_deadline) expires.
    pub fn on_recovery_timeout(&mut self, now: Instant) {
        let outcome = self.recovery.on_loss_detection_timeout(
            self.tls_handshake_complete(),
            self.is_server,
            now,
        );
        // Time-threshold losses: retire stream transmissions, PMTU, crypto.
        for (space, pn, sz) in &outcome.lost {
            self.stats.lost = self.stats.lost.saturating_add(1);
            self.stats.lost_bytes = self.stats.lost_bytes.saturating_add(*sz as u64);
            if *space == recovery::PacketSpace::Application {
                self.lose_stream_transmission_packet(*pn);
                self.pmtu_above_floor_pns.remove(pn);
                if self.pmtu_probe_pn == Some(*pn) {
                    self.pmtu.on_probe_lost();
                    self.pmtu_probe_pn = None;
                }
            }
        }
        if !outcome.crypto_lost.is_empty() {
            let mut crypto = self.crypto.write();
            for (space, off, len) in &outcome.crypto_lost {
                let stream = match space {
                    recovery::PacketSpace::Initial => &mut crypto.crypto_initial,
                    recovery::PacketSpace::Handshake => &mut crypto.crypto_handshake,
                    recovery::PacketSpace::Application => &mut crypto.crypto_application,
                };
                stream.requeue_crypto(*off, *len);
            }
        }
        if !outcome.lost.is_empty() {
            self.cwnd = self.recovery.cwnd;
        }
        // PTO probes: handshake spaces requeue their retained CRYPTO (the
        // flight loop re-emits it or sends a PING-only probe), the app space
        // gets a PING in the 1-RTT assembly.
        for space in outcome.probe_spaces {
            match space {
                recovery::PacketSpace::Application => {}
                recovery::PacketSpace::Initial | recovery::PacketSpace::Handshake => {
                    let mut crypto = self.crypto.write();
                    let stream = match space {
                        recovery::PacketSpace::Initial => &mut crypto.crypto_initial,
                        recovery::PacketSpace::Handshake => &mut crypto.crypto_handshake,
                        recovery::PacketSpace::Application => continue,
                    };
                    stream.requeue_all_unacked();
                }
            }
            self.pending_probe_spaces.push_back(space);
        }
    }

    /// Applies the connection-level reactions of an ACK processed by the
    /// canonical recovery owner: stream retirement, PMTU bookkeeping, CRYPTO
    /// range ack/requeue, stats, RTT mirror, and the FEC clean-ACK counter.
    fn apply_ack_outcome(
        &mut self,
        space: recovery::PacketSpace,
        outcome: recovery::AckOutcome,
        now: Instant,
    ) {
        if !outcome.crypto_acked.is_empty() || !outcome.crypto_lost.is_empty() {
            let mut crypto = self.crypto.write();
            let stream = match space {
                recovery::PacketSpace::Initial => &mut crypto.crypto_initial,
                recovery::PacketSpace::Handshake => &mut crypto.crypto_handshake,
                recovery::PacketSpace::Application => &mut crypto.crypto_application,
            };
            for (off, len) in &outcome.crypto_acked {
                stream.ack_crypto(*off, *len);
            }
            for (off, len) in &outcome.crypto_lost {
                stream.requeue_crypto(*off, *len);
            }
        }
        let mut above_floor_acked = false;
        let acked_packet_count = outcome.newly_acked.len() as u64;
        let mut acked_bytes = 0usize;
        for &(pn, sz) in &outcome.newly_acked {
            acked_bytes = acked_bytes.saturating_add(sz);
            if space == recovery::PacketSpace::Application {
                self.acknowledge_stream_transmission_packet(pn);
                above_floor_acked |= self.pmtu_above_floor_pns.remove(&pn);
                if self.pmtu_probe_pn == Some(pn) {
                    let previous_mtu = self.pmtu.effective_mtu();
                    self.pmtu.on_probe_acked(now);
                    if self.pmtu.effective_mtu() != previous_mtu {
                        log::info!(
                            "DPLPMTUD confirmed path MTU: {}B -> {}B",
                            previous_mtu,
                            self.pmtu.effective_mtu()
                        );
                    }
                    self.pmtu_probe_pn = None;
                }
            }
        }
        for &(pn, sz) in &outcome.lost {
            self.stats.lost = self.stats.lost.saturating_add(1);
            self.stats.lost_bytes = self.stats.lost_bytes.saturating_add(sz as u64);
            if space == recovery::PacketSpace::Application {
                self.lose_stream_transmission_packet(pn);
                self.pmtu_above_floor_pns.remove(&pn);
                if self.pmtu_probe_pn == Some(pn) {
                    self.pmtu.on_probe_lost();
                    self.pmtu_probe_pn = None;
                }
            }
        }
        if let Some(sample) = outcome.rtt_sample {
            self.rtt = sample;
        }
        self.stats.acked_bytes = self.stats.acked_bytes.saturating_add(acked_bytes as u64);
        if !outcome.newly_acked.is_empty() || !outcome.lost.is_empty() {
            self.cwnd = self.recovery.cwnd;
        }
        // Only a packet above the safe floor proves that the discovered
        // capacity remains usable. Floor-sized ACKs cannot mask a black hole.
        if above_floor_acked {
            self.pmtu.on_packet_acked(self.pmtu.effective_mtu(), now);
        }
        if space == recovery::PacketSpace::Application {
            self.fec_acked_packets = self.fec_acked_packets.saturating_add(acked_packet_count);
        }
        if let Some(evidence) = outcome.persistent_congestion_evidence {
            log::info!(
                "persistent congestion established; cwnd={} space={:?} largest_acked={} ack_delay_us={} largest_acked_age_known={} largest_acked_age_us={} acked_packets={} ack_lost_packets={} ack_packet_threshold_losses={} ack_time_threshold_losses={} run_start_pn={} terminal_lost_pn={} terminal_packet_threshold={} terminal_time_threshold={} lost_packets={} smoothed_rtt_us={} rtt_variance_us={} loss_delay_us={} period_us={} run_us={}",
                self.recovery.cwnd,
                space,
                evidence.largest_acked,
                evidence.triggering_ack_delay.as_micros(),
                evidence.largest_acked_packet_age.is_some(),
                evidence
                    .largest_acked_packet_age
                    .map(|age| age.as_micros())
                    .unwrap_or(0),
                evidence.triggering_ack_newly_acked_packets,
                evidence.triggering_ack_lost_packets,
                evidence.triggering_ack_packet_threshold_losses,
                evidence.triggering_ack_time_threshold_losses,
                evidence.run_start_pn,
                evidence.terminal_lost_pn,
                evidence.terminal_loss_by_packet_threshold,
                evidence.terminal_loss_by_time_threshold,
                evidence.lost_packet_count,
                evidence.smoothed_rtt.as_micros(),
                evidence.rtt_variance.as_micros(),
                evidence.loss_delay.as_micros(),
                evidence.period.as_micros(),
                evidence.run_end.saturating_duration_since(evidence.run_start).as_micros(),
            );
        }
    }

    fn refresh_path_count(&mut self) {
        self.stats.paths_count = self
            .validated_paths
            .len()
            .saturating_add(usize::from(self.pending_path_validation.is_some()));
    }

    fn path_validation_budget_allows(
        &self,
        path: &PendingPathValidation,
        frame: &Frame<'_>,
    ) -> bool {
        if path.origin != PathValidationOrigin::PeerPath {
            return true;
        }
        let estimated_packet_len =
            1 + self.dcid.as_ref().len() + 4 + frames::wire_len(frame) + self.tag_reserve_1rtt();
        let max_factor = self.config.max_amplification_factor.max(1);
        path.sent_bytes.saturating_add(estimated_packet_len)
            <= path.received_bytes.saturating_mul(max_factor)
    }

    fn queue_targeted_path_frame(
        &mut self,
        local_addr: SocketAddr,
        peer_addr: SocketAddr,
        frame: Frame<'static>,
    ) {
        self.pending_path_frames.push_back(PendingPathFrame { local_addr, peer_addr, frame });
    }

    fn count_pending_path_responses(&self, local_addr: SocketAddr, peer_addr: SocketAddr) -> usize {
        self.pending_path_frames
            .iter()
            .filter(|item| {
                item.local_addr == local_addr
                    && item.peer_addr == peer_addr
                    && matches!(item.frame, Frame::PathResponse { .. })
            })
            .count()
    }

    fn pop_targeted_path_frame_for_send(&mut self) -> Option<PendingPathFrame> {
        self.poll_path_validation_timeout(Instant::now());

        if let Some(front) = self.pending_path_frames.front() {
            if let Some(path) = self.pending_path_validation.as_ref() {
                if path.matches_path(front.local_addr, front.peer_addr)
                    && !self.path_validation_budget_allows(path, &front.frame)
                {
                    return None;
                }
            }
        }

        self.pending_path_frames.pop_front()
    }

    fn mark_unvalidated_path_send(
        &mut self,
        local_addr: SocketAddr,
        peer_addr: SocketAddr,
        bytes: usize,
    ) {
        if let Some(path) = self.pending_path_validation.as_mut() {
            if path.matches_path(local_addr, peer_addr) {
                path.sent_bytes = path.sent_bytes.saturating_add(bytes);
            }
        }
    }

    fn enqueue_path_response(
        &mut self,
        local_addr: SocketAddr,
        peer_addr: SocketAddr,
        data: [u8; 8],
    ) {
        if self.count_pending_path_responses(local_addr, peer_addr)
            >= self.config.path_challenge_recv_max_queue_len.max(1)
        {
            return;
        }
        self.queue_targeted_path_frame(local_addr, peer_addr, Frame::PathResponse { data });
    }

    fn emit_failed_validation(&mut self, local_addr: SocketAddr, peer_addr: SocketAddr) {
        self.path_events.push_back(PathEvent::FailedValidation(local_addr, peer_addr));
    }

    fn poll_path_validation_timeout(&mut self, now: Instant) {
        let should_fail = self.pending_path_validation.as_ref().is_some_and(|path| {
            now.saturating_duration_since(path.issued_at) >= PATH_VALIDATION_TIMEOUT
        });
        if !should_fail {
            return;
        }

        let Some(path) = self.pending_path_validation.take() else {
            return;
        };
        self.pending_path_frames
            .retain(|frame| !path.matches_path(frame.local_addr, frame.peer_addr));
        self.emit_failed_validation(path.local_addr, path.peer_addr);
        self.refresh_path_count();
    }

    fn begin_path_validation(
        &mut self,
        local_addr: SocketAddr,
        peer_addr: SocketAddr,
        origin: PathValidationOrigin,
        initial_received_bytes: usize,
    ) -> Result<u64, crate::error::ConnectionError> {
        self.poll_path_validation_timeout(Instant::now());

        if self.validated_paths.contains(&(local_addr, peer_addr)) {
            return Ok(self.path_id);
        }

        if let Some(path) = self.pending_path_validation.as_ref() {
            if path.matches_path(local_addr, peer_addr) {
                return Ok(path.path_id);
            }
            return Err(crate::error::ConnectionError::InvalidState);
        }

        if origin != PathValidationOrigin::PeerPath
            && self.last_migration_at.is_some_and(|last| last.elapsed() < MIGRATION_COOLDOWN)
        {
            return Err(crate::error::ConnectionError::InvalidState);
        }

        let mut challenge = [0u8; 8];
        crate::transport::rand::rand_bytes(&mut challenge);
        let next_path_id = self.path_id.wrapping_add(1);
        let path = PendingPathValidation {
            path_id: next_path_id,
            old_local_addr: self.local_addr,
            old_peer_addr: self.peer_addr,
            local_addr,
            peer_addr,
            challenge,
            issued_at: Instant::now(),
            received_bytes: initial_received_bytes,
            sent_bytes: 0,
            origin,
        };
        self.pending_path_validation = Some(path);
        self.queue_targeted_path_frame(
            local_addr,
            peer_addr,
            Frame::PathChallenge { data: challenge },
        );
        self.path_events.push_back(PathEvent::New(local_addr, peer_addr));
        self.refresh_path_count();
        Ok(next_path_id)
    }

    fn observe_incoming_path(
        &mut self,
        local_addr: SocketAddr,
        peer_addr: SocketAddr,
        received_bytes: usize,
    ) {
        if self.local_addr == local_addr && self.peer_addr == peer_addr {
            return;
        }

        if let Some(path) = self.pending_path_validation.as_mut() {
            if path.matches_path(local_addr, peer_addr) {
                path.received_bytes = path.received_bytes.saturating_add(received_bytes);
            }
            return;
        }

        if self.config.disable_active_migration {
            return;
        }

        if self.last_migration_at.is_some_and(|last| last.elapsed() < MIGRATION_COOLDOWN) {
            return;
        }

        let _ = self.begin_path_validation(
            local_addr,
            peer_addr,
            PathValidationOrigin::PeerPath,
            received_bytes,
        );
    }

    fn handle_path_response_frame(
        &mut self,
        local_addr: SocketAddr,
        peer_addr: SocketAddr,
        data: [u8; 8],
    ) {
        self.poll_path_validation_timeout(Instant::now());

        let Some(path) = self.pending_path_validation.as_ref() else {
            return;
        };
        if !path.matches_path(local_addr, peer_addr) || path.challenge != data {
            return;
        }

        let Some(path) = self.pending_path_validation.take() else {
            return;
        };
        self.pending_path_frames
            .retain(|frame| !path.matches_path(frame.local_addr, frame.peer_addr));
        self.local_addr = path.local_addr;
        self.peer_addr = path.peer_addr;
        self.path_id = path.path_id;
        // Gentle migration: reduce cwnd by 50% instead of resetting to INITIAL_WINDOW.
        // Preserve bytes_in_flight (packets are still in flight, peer will ACK/lose them).
        // This prevents throughput collapse on WiFi→LTE transitions.
        self.recovery.on_path_change();
        self.cwnd = self.recovery.cwnd;
        self.validated_paths.insert((path.local_addr, path.peer_addr));
        self.last_migration_at = Some(Instant::now());
        self.path_events.push_back(PathEvent::Validated(path.local_addr, path.peer_addr));
        if path.old_local_addr != path.local_addr || path.old_peer_addr != path.peer_addr {
            self.path_events.push_back(PathEvent::PeerMigrated(path.old_peer_addr, path.peer_addr));
        }
        self.refresh_path_count();
    }

    /// Returns pending path validation state for test assertions.
    #[cfg(any(test, feature = "rust-tests"))]
    pub fn pending_path_validation_for_test(
        &self,
    ) -> Option<(u64, SocketAddr, SocketAddr, [u8; 8])> {
        self.pending_path_validation
            .as_ref()
            .map(|path| (path.path_id, path.local_addr, path.peer_addr, path.challenge))
    }

    /// Injects a PATH_RESPONSE for test-driven path validation.
    #[cfg(any(test, feature = "rust-tests"))]
    pub fn receive_path_response_for_test(
        &mut self,
        local_addr: SocketAddr,
        peer_addr: SocketAddr,
        data: [u8; 8],
    ) {
        self.handle_path_response_frame(local_addr, peer_addr, data);
    }

    /// Forces the pending path validation to expire for timeout testing.
    #[cfg(any(test, feature = "rust-tests"))]
    pub fn expire_pending_path_validation_for_test(&mut self) {
        if let Some(path) = self.pending_path_validation.as_mut() {
            path.issued_at = Instant::now() - PATH_VALIDATION_TIMEOUT - Duration::from_millis(1);
        }
        self.poll_path_validation_timeout(Instant::now());
    }

    // ============================================================================
    // Real-TLS Integration Methods
    // ============================================================================

    /// Enable rustls-backed TLS provider with optional TLS Cover layer.
    pub(crate) fn enable_tls(
        &mut self,
        profile_name: &str,
    ) -> Result<(), crate::error::ConnectionError> {
        log::info!("Enabling rustls TLS provider with profile: {}", profile_name);

        // TLS provider must operate on the same CryptoContext as the transport,
        // otherwise secrets would never be installed into the packet protection keys.
        let crypto_arc = self.crypto.clone();
        let mut available_versions = self.config.supported_versions.clone();
        available_versions.push(self.version_negotiation.grease);
        let version_information = super::version::VersionInformation {
            chosen: self.config.version,
            available: available_versions,
        }
        .encode_parameter()?;

        // Create the TLS composition stack (rustls + optional TLS Cover).
        let provider = crate::qftls::create_provider_for_version(
            self.is_server,
            crypto_arc.clone(),
            self.config.verify_peer,
            self.config.version,
            &version_information,
        )?;

        // Store provider
        self.tls_provider = Some(provider);

        if let Some(provider_ref) = self.tls_provider.as_ref() {
            log::info!("TLS provider enabled: {}", provider_ref.provider_name());
        } else {
            return Err(crate::error::ConnectionError::InvalidState);
        }

        // Install Initial secrets/HP from DCID for early Long Header encryption.
        // QUIC initial keys are direction-specific:
        // - Client: write=client_secret, read=server_secret
        // - Server: write=server_secret, read=client_secret
        // RFC 9001: Initial secrets derive from the Destination Connection ID in the first Initial.
        // Use the recorded ODCID if available (server accepts it from the first client packet).
        let initial_dcid = if !self.initial_dcid.is_empty() {
            self.initial_dcid.as_ref()
        } else {
            self.dcid.as_ref()
        };
        let (client_secret, server_secret) =
            packet::derive_initial_secrets(initial_dcid, self.config.version);
        {
            let (read_secret, write_secret) = if self.is_server {
                (client_secret.as_slice(), server_secret.as_slice())
            } else {
                (server_secret.as_slice(), client_secret.as_slice())
            };
            let mut crypto = self.crypto.write();
            crypto.install_aes_gcm_initial(read_secret, write_secret, self.config.version);
            crypto.install_hp_initial(read_secret, write_secret, self.config.version);
        }

        Ok(())
    }

    /// Configure TLS provider with a specific profile and SNI.
    pub(crate) fn configure_tls(
        &mut self,
        profile: &crate::qftls::TlsProfile,
        sni: &str,
    ) -> Result<(), crate::error::ConnectionError> {
        let Some(provider) = &mut self.tls_provider else {
            return Err(crate::error::ConnectionError::InvalidState);
        };

        let mut effective = profile.clone();
        if !sni.is_empty() {
            effective.sni = Some(sni.to_string());
        }
        provider.configure(&effective)?;
        self.tls_profile = Some(effective);
        // Optionally enable 0-RTT when desired.
        if let Err(e) = provider.enable_0rtt() {
            log::debug!("TLS provider 0-RTT enablement failed: {:?}", e);
        }
        Ok(())
    }

    /// Process TLS handshake with optional cover CH override.
    pub(crate) fn do_tls_handshake(
        &mut self,
        override_template: Option<&str>,
    ) -> Result<bool, crate::error::ConnectionError> {
        if let Some(provider) = &mut self.tls_provider {
            // Apply cover layer CH override if supported and requested.
            if let Some(template_name) = override_template {
                if provider.supports_ch_override() {
                    // Create simple template bytes; cover layer expands details.
                    let template_bytes = template_name.as_bytes();
                    provider.apply_ch_override(template_bytes)?;
                }
            }

            // Check handshake completion
            let done = provider.handshake_complete();
            if done {
                // If ALPN negotiated HTTP/3, enable H3 binding
                if let Some(alpn) = provider.alpn() {
                    if alpn.starts_with("h3") {
                        if let Err(e) = self.enable_h3() {
                            log::warn!("Failed to enable HTTP/3 after ALPN negotiation: {:?}", e);
                        }
                    }
                }
            }
            Ok(done)
        } else {
            // No TLS provider configured, consider handshake complete
            Ok(true)
        }
    }

    /// Returns true when the TLS provider reports handshake completion.
    /// This is intentionally distinct from transport liveness/establishment.
    pub fn tls_handshake_complete(&self) -> bool {
        self.tls_provider.as_ref().map(|p| p.handshake_complete()).unwrap_or(true)
    }

    /// Enable HTTP/3 connection bound to this transport (idempotent)
    pub(crate) fn enable_h3(&mut self) -> Result<(), crate::transport::h3::Error> {
        if self.h3.is_some() {
            return Ok(());
        }
        let cfg = crate::transport::h3::Config::new()
            .map_err(|_| crate::transport::h3::Error::InternalError)?;
        let h3c = crate::transport::h3::Connection::with_transport(self, &cfg)?;
        self.h3 = Some(h3c);
        Ok(())
    }

    /// Establish a MASQUE CONNECT-UDP stream via HTTP/3, returns stream id
    #[cfg(any(test, feature = "rust-tests"))]
    pub fn masque_connect_udp(
        &mut self,
        proxy_authority: &str,
        target_host_port: &str,
    ) -> Result<u64, crate::transport::h3::Error> {
        if self.h3.is_none() {
            self.enable_h3()?;
        }
        // Temporarily take ownership to avoid aliasing &mut borrows
        let Some(mut h3c) = self.h3.take() else {
            return Err(crate::transport::h3::Error::InternalError);
        };
        let res = h3c.connect_udp(self, proxy_authority, target_host_port);
        self.h3 = Some(h3c);
        res
    }

    /// Enable MASQUE DATAGRAM context on an existing CONNECT-UDP stream
    #[cfg(any(test, feature = "rust-tests"))]
    pub fn masque_enable_datagram(
        &mut self,
        stream_id: u64,
    ) -> Result<u64, crate::transport::h3::Error> {
        if self.h3.is_none() {
            self.enable_h3()?;
        }
        let Some(mut h3c) = self.h3.take() else {
            return Err(crate::transport::h3::Error::InternalError);
        };
        let res = h3c.enable_masque_datagram(self, stream_id);
        self.h3 = Some(h3c);
        res
    }

    /// Send one MASQUE UDP payload as QUIC DATAGRAM (Flow-ID implicit)
    #[cfg(any(test, feature = "rust-tests"))]
    pub fn masque_send_datagram(
        &mut self,
        stream_id: u64,
        udp_payload: &[u8],
    ) -> Result<(), crate::transport::h3::Error> {
        if self.h3.is_none() {
            self.enable_h3()?;
        }
        let Some(mut h3c) = self.h3.take() else {
            return Err(crate::transport::h3::Error::InternalError);
        };
        let res = h3c.send_masque_datagram(self, stream_id, udp_payload);
        self.h3 = Some(h3c);
        res
    }

    /// Try to receive one MASQUE DATAGRAM; returns (flow_id, payload)
    #[cfg(any(test, feature = "rust-tests"))]
    pub fn masque_try_recv_datagram(&mut self) -> Option<(u64, Vec<u8>)> {
        if let Some(mut h3c) = self.h3.take() {
            let out = h3c.try_recv_masque_datagram(self);
            self.h3 = Some(h3c);
            out
        } else {
            None
        }
    }

    /// Process incoming CRYPTO frame
    pub(crate) fn process_crypto_frame(
        &mut self,
        level: crate::qftls::Level,
        offset: u64,
        data: Cow<'_, [u8]>,
    ) -> Result<(), crate::error::ConnectionError> {
        if self.tls_provider.is_some() {
            // CRYPTO frames can arrive out-of-order. Buffer and drain contiguous handshake bytes
            // before feeding into the TLS provider.
            let mut chunks: Vec<Vec<u8>> = Vec::new();
            {
                let mut crypto = self.crypto.write();
                let stream = match level {
                    crate::qftls::Level::Initial => &mut crypto.crypto_initial,
                    crate::qftls::Level::Handshake => &mut crypto.crypto_handshake,
                    _ => &mut crypto.crypto_application,
                };
                stream.recv(offset, data.into_owned())?;
                let mut tmp = [0u8; 2048];
                while stream.has_data() {
                    let n = stream.read(&mut tmp);
                    if n == 0 {
                        break;
                    }
                    chunks.push(tmp[..n].to_vec());
                }
            }

            if let Some(provider) = &mut self.tls_provider {
                for chunk in chunks {
                    if let Err(error) = provider.provide_quic_data(level, &chunk) {
                        self.local_error = Some(error.clone());
                        self.is_closed = true;
                        return Err(error);
                    }
                }
            }
            // Install any newly derived secrets into the shared CryptoContext.
            // Without this, the transport would never transition to 1-RTT and application streams
            // (including HTTP/3 HEADERS carrying x-qf-auth) would stall behind the handshake gate.
            if let Err(error) = self.poll_tls_and_validate_versions() {
                self.local_error = Some(error.clone());
                self.is_closed = true;
                return Err(error);
            }
        } else {
            // Store in crypto stream for later processing
            let mut crypto = self.crypto.write();
            let stream = match level {
                crate::qftls::Level::Initial => &mut crypto.crypto_initial,
                crate::qftls::Level::Handshake => &mut crypto.crypto_handshake,
                _ => &mut crypto.crypto_application,
            };
            stream.recv(offset, data.into_owned())?;
        }

        Ok(())
    }

    fn poll_tls_and_validate_versions(&mut self) -> Result<(), crate::error::ConnectionError> {
        let peer_parameters = {
            let Some(provider) = &mut self.tls_provider else {
                return Ok(());
            };
            provider.poll_secrets_and_install(&self.crypto)?;
            provider.peer_quic_transport_params()
        };
        self.refresh_short_header_tag_reserve();
        self.validate_peer_version_information(peer_parameters)
    }

    fn validate_peer_version_information(
        &mut self,
        peer_parameters: Option<Vec<u8>>,
    ) -> Result<(), crate::error::ConnectionError> {
        if self.version_negotiation.peer_information_validated {
            return Ok(());
        }
        let Some(peer_parameters) = peer_parameters else {
            return Ok(());
        };
        let information = match super::version::find_version_information(&peer_parameters) {
            Ok(information) => information,
            Err(_) => {
                return Err(self.fail_version_negotiation(
                    super::version::TRANSPORT_PARAMETER_ERROR_CODE,
                    "malformed version_information transport parameter",
                ));
            }
        };
        let required = !self.is_server
            && (self.config.version == super::PROTOCOL_VERSION_V2
                || self.version_negotiation.reacted_to_vn);
        let information = match information {
            Some(information) => information,
            None if !self.is_server
                && self.version_negotiation.reacted_to_vn
                && self.config.version == super::PROTOCOL_VERSION =>
            {
                super::version::VersionInformation {
                    chosen: super::PROTOCOL_VERSION,
                    available: vec![super::PROTOCOL_VERSION],
                }
            }
            None => {
                if required {
                    return Err(self.fail_version_negotiation(
                        super::version::VERSION_NEGOTIATION_ERROR_CODE,
                        "required version_information transport parameter missing",
                    ));
                }
                self.version_negotiation.peer_information_validated = true;
                return Ok(());
            }
        };

        if self.is_server && !information.available.contains(&information.chosen) {
            return Err(self.fail_version_negotiation(
                super::version::TRANSPORT_PARAMETER_ERROR_CODE,
                "client chosen version missing from available versions",
            ));
        }
        let valid_choice = information.chosen == self.config.version
            && self.config.supported_versions.contains(&information.chosen);
        let negotiated_preference_matches = if self.version_negotiation.reacted_to_vn
            && !self.is_server
        {
            if information.available.is_empty() {
                false
            } else {
                self.config
                    .supported_versions
                    .iter()
                    .find(|version| {
                        **version == self.config.version || information.available.contains(version)
                    })
                    .is_some_and(|version| *version == self.config.version)
            }
        } else {
            true
        };
        if !valid_choice || !negotiated_preference_matches {
            return Err(self.fail_version_negotiation(
                super::version::VERSION_NEGOTIATION_ERROR_CODE,
                "authenticated version_information rejected negotiated version",
            ));
        }
        self.version_negotiation.peer_information_validated = true;
        Ok(())
    }

    fn fail_version_negotiation(
        &mut self,
        error_code: u64,
        reason: &'static str,
    ) -> crate::error::ConnectionError {
        let error = crate::error::ConnectionError::Transport(reason.to_string());
        let _ = self.close(false, error_code, reason.as_bytes());
        self.local_error = Some(error.clone());
        error
    }

    /// Get next CRYPTO frame to send
    pub(crate) fn next_crypto_frame(
        &mut self,
        level: crate::qftls::Level,
        max_len: usize,
    ) -> Option<(u64, Vec<u8>)> {
        if let Some(provider) = &mut self.tls_provider {
            provider.next_crypto_frame(level, max_len)
        } else {
            let mut crypto = self.crypto.write();
            let stream = match level {
                crate::qftls::Level::Initial => &mut crypto.crypto_initial,
                crate::qftls::Level::Handshake => &mut crypto.crypto_handshake,
                _ => &mut crypto.crypto_application,
            };
            stream.next_crypto_frame(max_len)
        }
    }

    // ============================================================================
    // Packet Processing Methods
    // ============================================================================

    fn handle_version_negotiation_packet(
        &mut self,
        header: &packet::Header,
        packet_len: usize,
    ) -> Result<usize, crate::error::ConnectionError> {
        use crate::error::ConnectionError;

        let valid_context = !self.is_server
            && !self.received_non_vn_packet
            && header.dcid.as_slice() == self.scid.as_ref()
            && header.scid.as_slice() == self.initial_dcid.as_ref();
        if !valid_context {
            return Ok(packet_len);
        }
        let peer_versions = header.versions.as_deref().unwrap_or_default();
        let selected = match self
            .version_negotiation
            .select_from_vn(&self.config.supported_versions, peer_versions)
        {
            Ok(version) => version,
            Err(ConnectionError::Done) => return Ok(packet_len),
            Err(ConnectionError::VersionMismatch) => {
                self.is_closed = true;
                self.local_error = Some(ConnectionError::VersionMismatch);
                return Err(ConnectionError::VersionMismatch);
            }
            Err(error) => return Err(error),
        };

        self.config.select_version(selected)?;
        self.version_negotiation.peer_information_validated = false;
        let mut scid = [0u8; super::MAX_CONN_ID_LEN];
        let mut dcid = [0u8; super::MAX_CONN_ID_LEN];
        super::rand::rand_bytes(&mut scid);
        super::rand::rand_bytes(&mut dcid);
        self.scid = ConnectionId::from_vec(scid.to_vec());
        self.initial_dcid = ConnectionId::from_vec(dcid.to_vec());
        self.dcid = self.initial_dcid;
        self.dest_cids = cid::ConnectionIdSet::new();
        self.dest_cids.insert(&self.dcid);
        self.is_established = false;
        self.is_closed = false;
        self.is_draining = false;
        self.local_error = None;
        self.pkt_spaces = [
            pnspace::PktNumSpace::default(),
            pnspace::PktNumSpace::default(),
            pnspace::PktNumSpace::default(),
        ];
        self.next_send_pn_by_space = [0, 0, 0];
        self.pending_control.clear();
        self.recovery.discard_space(recovery::PacketSpace::Initial);
        self.recovery.discard_space(recovery::PacketSpace::Handshake);
        self.recovery.discard_space(recovery::PacketSpace::Application);
        self.pending_probe_spaces.clear();
        self.stream_transmission_by_pn.clear();
        self.lost_stream_transmission_by_pn.clear();
        self.stream_retransmit_queue.clear();
        for (transmission_id, transmission) in &mut self.stream_transmissions {
            transmission.queued = true;
            transmission.active_packet = None;
            transmission.lost_packets.clear();
            self.stream_retransmit_queue.push_back(*transmission_id);
        }
        self.bytes_in_flight = 0;
        self.bytes_in_flight_started = None;
        self.cwnd = INITIAL_WINDOW;
        self.rtt = Duration::ZERO;
        self.timeout_count = 0;
        self.last_activity = Instant::now();
        self.conn_bytes_sent = 0;
        self.conn_bytes_recvd = 0;
        self.peer_max_data = self.config.initial_max_data;
        self.h3 = None;
        self.pmtu_probe_pn = None;
        self.pmtu_above_floor_pns.clear();
        self.recovery = recovery::Recovery::new(INITIAL_WINDOW, self.dgram_send_max_size);
        if self.config.initial_rtt_ms != 100 {
            self.recovery.set_initial_rtt(Duration::from_millis(self.config.initial_rtt_ms));
        }
        self.install_recovery_fec_callbacks();
        self.crypto = Arc::new(parking_lot::RwLock::new(packet::CryptoContext::default()));
        self.crypto_1rtt.store(None);
        self.short_header_tag_reserve = 0;
        let tls_was_enabled = self.tls_provider.is_some();
        self.tls_provider = None;

        if tls_was_enabled {
            let profile = self.tls_profile.clone();
            self.enable_tls("version-negotiation-restart")?;
            if let Some(profile) = profile {
                let sni = profile.sni.clone().unwrap_or_default();
                self.configure_tls(&profile, &sni)?;
            }
        }

        self.stats.recv = self.stats.recv.saturating_add(1);
        self.stats.recv_bytes = self.stats.recv_bytes.saturating_add(packet_len as u64);
        Ok(packet_len)
    }

    /// Processes incoming packet
    #[inline(always)]
    pub fn recv(
        &mut self,
        buf: &mut [u8],
        info: &RecvInfo,
    ) -> Result<usize, crate::error::ConnectionError> {
        use crate::error::ConnectionError;
        use udpfast::unlikely;
        if unlikely(buf.is_empty()) {
            return Err(ConnectionError::BufferTooShort);
        }

        // Prefetch packet input for the recv hotpath.
        prefetch_recv_packet_buffer(buf);

        // Pre-parse header to determine space and largest PN hint.
        // For short headers, DCID length is the local SCID length (the peer routes to our CID).
        let short_dcid_len = self.scid.as_ref().len();
        let (pre_ty, largest_hint, mut pre_parsed_hdr) =
            match packet::parse_header(buf, short_dcid_len) {
                Ok((hdr_native, pn_off)) => {
                    let t = hdr_native.ty;
                    let idx = match t {
                        PacketType::Initial => 0,
                        PacketType::Handshake => 1,
                        _ => 2,
                    };
                    (t, self.pkt_spaces[idx].largest_recv.unwrap_or(0), Some((hdr_native, pn_off)))
                }
                Err(_) => (PacketType::Short, 0, None),
            };

        if pre_ty == PacketType::VersionNegotiation {
            let Some((header, _)) = pre_parsed_hdr.as_ref() else {
                return Ok(buf.len());
            };
            return self.handle_version_negotiation_packet(header, buf.len());
        }

        // Retry verification (no payload decrypt)
        if let PacketType::Retry = pre_ty {
            let retry_version_matches = pre_parsed_hdr
                .as_ref()
                .is_some_and(|(header, _)| header.version == self.version_negotiation.chosen);
            if self.is_server || !retry_version_matches {
                return Ok(buf.len());
            }
            let odcid = if !self.initial_dcid.is_empty() {
                self.initial_dcid.as_ref()
            } else {
                self.dcid.as_ref()
            };
            if let Err(e) = packet::verify_retry_tag(buf, odcid, self.config.version) {
                self.local_error = Some(e);
                if let Some(err) = self.local_error.clone() {
                    return Err(err);
                }
                return Err(ConnectionError::InvalidState);
            }

            // Client-side Retry handling: adopt token/DCID and re-derive Initial keys.
            // Reuse the pre-parsed header instead of re-parsing (TODO-391).
            if !self.is_server {
                if let Some((retry_hdr, _)) = pre_parsed_hdr.as_ref() {
                    if !retry_hdr.scid.is_empty() {
                        self.set_destination_cid(ConnectionId::from_vec(retry_hdr.scid.clone()));
                    }
                    self.config.initial_token = retry_hdr.token.clone();
                    let (client_secret, server_secret) =
                        packet::derive_initial_secrets(self.dcid.as_ref(), self.config.version);
                    let (read_secret, write_secret) =
                        (server_secret.as_slice(), client_secret.as_slice());
                    let mut crypto = self.crypto.write();
                    crypto.install_aes_gcm_initial(read_secret, write_secret, self.config.version);
                    crypto.install_hp_initial(read_secret, write_secret, self.config.version);
                    drop(crypto);
                    self.refresh_short_header_tag_reserve();
                    self.next_send_pn_by_space[0] = 0;
                    self.pkt_spaces[0] = pnspace::PktNumSpace::default();
                }
            }
            // For Retry we do not parse further.
            self.received_non_vn_packet = true;
            self.stats.recv += 1;
            self.stats.recv_bytes += buf.len() as u64;
            return Ok(buf.len());
        }

        // Try to unprotect+decrypt using installed secrets.
        // For short-header packets, a bounded read-key catch-up loop tolerates peer key updates
        // across multiple generations before we receive packets in each phase.
        let mut rx_key_advances = 0usize;
        let (hdr_native, aad_len, pt_len) = loop {
            // Hot path: try lock-free 1-RTT ArcSwap first.
            // Consume pre_parsed_hdr by move (no clone) - on the common 1-RTT
            // success path this eliminates a Header clone (Vec dcid/scid alloc)
            // per packet. On the rare failure path we re-parse below.
            if let Some(keys) = self.crypto_1rtt.load().as_ref() {
                match packet::unprotect_and_decrypt_1rtt(
                    keys,
                    buf,
                    short_dcid_len,
                    largest_hint,
                    pre_parsed_hdr.take(),
                ) {
                    Ok(v) => break v,
                    Err(ConnectionError::Done) | Err(ConnectionError::CryptoError(_)) => {
                        // Fall through to RwLock path (key update in progress or non-Short packet).
                        // Re-parse if the 1-RTT attempt consumed pre_parsed_hdr.
                        // Safe: for Short headers the form/fixed bits (0x80/0x40) are not
                        // HP-protected (mask covers 0x1f only), so parse_header still
                        // identifies the packet type correctly after HP removal.
                        if pre_parsed_hdr.is_none() {
                            pre_parsed_hdr = packet::parse_header(buf, short_dcid_len).ok();
                        }
                    }
                    Err(e) => return Err(e),
                }
            }
            // Fallback: full RwLock path (handles Initial, Handshake, 0-RTT, previous keys).
            let decrypt = {
                let crypto_ref_for_rx = self.crypto.read();
                packet::unprotect_and_decrypt_parsed(
                    &crypto_ref_for_rx,
                    buf,
                    short_dcid_len,
                    largest_hint,
                    pre_parsed_hdr.take(),
                )
            };
            match decrypt {
                Ok(v) => break v,
                Err(ConnectionError::Done) | Err(ConnectionError::CryptoError(_))
                    if pre_ty == PacketType::Short
                        && rx_key_advances < MAX_RX_KEY_UPDATE_ADVANCE
                        && self.try_advance_read_keys() =>
                {
                    rx_key_advances += 1;
                    // Re-parse for the next retry iteration.
                    if pre_parsed_hdr.is_none() {
                        pre_parsed_hdr = packet::parse_header(buf, short_dcid_len).ok();
                    }
                    continue;
                }
                Err(ConnectionError::Done) => return Err(ConnectionError::Done),
                Err(e) => {
                    self.local_error = Some(e);
                    if let Some(err) = self.local_error.clone() {
                        return Err(err);
                    }
                    return Err(ConnectionError::InvalidState);
                }
            }
        };
        let pkt_ty = hdr_native.ty;
        self.received_non_vn_packet = true;

        // Receiving a valid 1-RTT (Short) packet confirms the peer has the
        // 1-RTT keys and therefore the handshake is done. Discard the
        // Initial/Handshake packet number spaces and keys per RFC 9002 §6.2.2
        // so unacknowledged handshake packets stop triggering PTO probes and
        // inflating bytes_in_flight.
        if pkt_ty == PacketType::Short {
            self.recovery.discard_space(recovery::PacketSpace::Initial);
            self.recovery.discard_space(recovery::PacketSpace::Handshake);
            let mut crypto = self.crypto.write();
            crypto.seal_initial = None;
            crypto.open_initial = None;
            crypto.seal_handshake = None;
            crypto.open_handshake = None;
        }

        // Learn peer CID from the first long-header packets.
        // - Server: outgoing DCID must be the client's SCID.
        // - Client: after receiving a server packet, outgoing DCID becomes the server's SCID.
        if hdr_native.ty != PacketType::Short && !hdr_native.scid.is_empty() {
            if self.is_server {
                if self.dcid.is_empty() {
                    self.set_destination_cid(ConnectionId::from_vec(hdr_native.scid.clone()));
                }
                if self.initial_dcid.is_empty() && !hdr_native.dcid.is_empty() {
                    self.initial_dcid = ConnectionId::from_vec(hdr_native.dcid.clone());
                }
            } else {
                // Client: only rotate away from the initial placeholder DCID once we have a peer SCID.
                if self.dcid.is_empty() || self.dcid == self.initial_dcid {
                    self.set_destination_cid(ConnectionId::from_vec(hdr_native.scid.clone()));
                }
            }
        }
        // Observer hook: notify after header processed and payload length known
        if let Some(obs) = &self.observer {
            obs.on_packet_recv(hdr_native.pkt_num, pt_len);
        }
        let space_idx = match pkt_ty {
            PacketType::Initial => 0,
            PacketType::Handshake => 1,
            _ => 2,
        };
        // Duplicate PN detection: if already observed, count and return.
        if hdr_native.pkt_num_len > 0 {
            if self.pkt_spaces[space_idx].contains(hdr_native.pkt_num) {
                let len = aad_len.saturating_add(pt_len).min(buf.len());
                self.stats.recv += 1;
                self.stats.recv_bytes += len as u64;
                return Ok(len);
            }
            if !self.pkt_spaces[space_idx].on_packet_recv(hdr_native.pkt_num) {
                // Duplicate or overflow PN - silently discard per RFC 9000 Section 12.3
                let len = aad_len.saturating_add(pt_len).min(buf.len());
                self.stats.recv += 1;
                self.stats.recv_bytes += len as u64;
                return Ok(len);
            }
        }

        // 0-RTT anti-replay gate (RFC 8446 Section 8, RFC 9001 Section 9.2).
        // After AEAD decryption and PN dedup, but before frame parsing.
        // Silently discard replayed 0-RTT packets - matches duplicate-PN pattern.
        if pkt_ty == PacketType::ZeroRTT {
            if let Some(ref strike_register) = self.strike_register {
                let end_replay = aad_len.saturating_add(pt_len).min(buf.len());
                let payload = &buf[aad_len..end_replay];
                let fingerprint = super::anti_replay::StrikeRegister::compute_fingerprint(
                    &hdr_native.dcid,
                    &hdr_native.scid,
                    payload,
                );
                if !strike_register.check_and_insert(&fingerprint, Instant::now()) {
                    crate::telemetry!(
                        crate::optimize::telemetry::ZERO_RTT_REPLAY_REJECT_TOTAL.inc()
                    );
                    log::warn!("0-RTT replay detected and rejected");
                    let len = end_replay;
                    self.stats.recv += 1;
                    self.stats.recv_bytes += len as u64;
                    return Ok(len);
                }
                crate::telemetry!(crate::optimize::telemetry::ZERO_RTT_ACCEPT_TOTAL.inc());
            }
        }

        // Parse frames from decrypted payload region
        let mut off = aad_len;
        let end = aad_len.saturating_add(pt_len).min(buf.len());
        self.observe_incoming_path(info.to, info.from, end);
        let mut ack_eliciting = false;
        while off < end {
            // Prefetch the next frame parse window for the recv hotpath.
            prefetch_frame_parse_window(buf.as_ptr(), end, off);
            match frames::from_bytes(&buf[off..end], pkt_ty) {
                Ok((frame, used)) => {
                    if used == 0 {
                        break;
                    }
                    off += used;
                    // Minimal: handle accounting for Stream/Crypto sizes
                    // 0-RTT must not carry CRYPTO frames.
                    if pkt_ty == PacketType::ZeroRTT && matches!(frame, Frame::Crypto { .. }) {
                        continue;
                    }
                    match frame {
                        Frame::Stream { stream_id, offset, data, fin } => {
                            ack_eliciting = true;
                            self.stats.stream_recv_bytes += data.len() as u64;
                            if !self.readable_streams.contains(&stream_id) {
                                self.readable_streams.push_back(stream_id);
                            }
                            // Flow-control tracking
                            let s = self.streams.entry(stream_id).or_insert_with(|| Stream {
                                id: stream_id,
                                #[cfg(not(feature = "stream_ring_buffer"))]
                                send_buf: Vec::new(),
                                #[cfg(not(feature = "stream_ring_buffer"))]
                                recv_buf: Vec::new(),
                                #[cfg(feature = "stream_ring_buffer")]
                                send_ring: StreamRingBuffer::new(),
                                #[cfg(feature = "stream_ring_buffer")]
                                recv_ring: StreamRingBuffer::new(),
                                send_fin: false,
                                recv_fin: false,
                                send_off: 0,
                                recv_off: 0,
                                recv_next: 0,
                                recv_final_size: None,
                                recv_frags: std::collections::BTreeMap::new(),
                                priority_urgency: 3,
                                #[cfg(any(test, feature = "rust-tests"))]
                                priority_incremental: false,
                                max_stream_data_rx: self.config.initial_max_stream_data_bidi_local,
                                max_stream_data_tx: self.config.initial_max_stream_data_bidi_remote,
                            });
                            let end = offset.saturating_add(data.len() as u64);
                            // Track highest received offset for flow control accounting.
                            s.recv_off = s.recv_off.max(end);
                            self.conn_bytes_recvd =
                                self.conn_bytes_recvd.saturating_add(data.len() as u64);

                            // Store fragment for ordered delivery.
                            if !data.is_empty() {
                                let mut start = offset;
                                if start < s.recv_next {
                                    let drop_n = (s.recv_next - start) as usize;
                                    if drop_n < data.len() {
                                        start = s.recv_next;
                                        s.recv_frags.insert(start, data[drop_n..].to_vec());
                                    }
                                } else if start == s.recv_next && s.recv_frags.is_empty() {
                                    // In-order fast path: copy directly to recv buffer, skip recv_frags.
                                    #[cfg(not(feature = "stream_ring_buffer"))]
                                    {
                                        s.recv_buf.extend_from_slice(&data);
                                    }
                                    #[cfg(feature = "stream_ring_buffer")]
                                    {
                                        s.recv_ring.write(&data);
                                    }
                                    s.recv_next += data.len() as u64;
                                } else {
                                    s.recv_frags.insert(start, data.into_owned());
                                }
                            }

                            // FIN denotes the final size of the stream (offset + data_len).
                            if fin {
                                match s.recv_final_size {
                                    None => s.recv_final_size = Some(end),
                                    Some(prev) if prev == end => {}
                                    Some(_) => {
                                        self.local_error =
                                            Some(crate::error::ConnectionError::FinalSize);
                                    }
                                }
                            }

                            // Drain contiguous fragments into the receive buffer/ring.
                            loop {
                                let next = s.recv_next;
                                // Normalize any fragment that overlaps `next` by re-keying.
                                if let Some((&start, _)) = s.recv_frags.range(..=next).next_back() {
                                    if start < next {
                                        if let Some(mut frag) = s.recv_frags.remove(&start) {
                                            let start_end = start.saturating_add(frag.len() as u64);
                                            if start_end <= next {
                                                continue;
                                            }
                                            let skip = (next - start) as usize;
                                            frag.drain(..skip);
                                            s.recv_frags.insert(next, frag);
                                            continue;
                                        }
                                    }
                                }

                                let Some(frag) = s.recv_frags.remove(&next) else {
                                    break;
                                };

                                #[cfg(not(feature = "stream_ring_buffer"))]
                                {
                                    s.recv_buf.extend_from_slice(&frag);
                                    s.recv_next = s.recv_next.saturating_add(frag.len() as u64);
                                }
                                #[cfg(feature = "stream_ring_buffer")]
                                {
                                    let written = s.recv_ring.write(&frag);
                                    s.recv_next = s.recv_next.saturating_add(written as u64);
                                    if written < frag.len() {
                                        // Keep remainder for later to avoid truncation.
                                        s.recv_frags.insert(s.recv_next, frag[written..].to_vec());
                                        break;
                                    }
                                }
                            }

                            if let Some(final_size) = s.recv_final_size {
                                if s.recv_next >= final_size {
                                    s.recv_fin = true;
                                }
                            }
                            // If exceeding current stream window, flag flow control (minimal handling)
                            if s.recv_off > s.max_stream_data_rx {
                                self.local_error = Some(crate::error::ConnectionError::FlowControl);
                            } else if s.recv_off * 4 >= s.max_stream_data_rx * 3 {
                                // Grow stream window and queue MAX_STREAM_DATA
                                let new_max =
                                    (s.max_stream_data_rx.saturating_mul(2)).min(MAX_STREAM_SIZE);
                                s.max_stream_data_rx = new_max;
                                self.pending_control
                                    .push_back(Frame::MaxStreamData { stream_id, max: new_max });
                            }
                            if self.conn_bytes_recvd * 4 >= self.conn_max_data * 3 {
                                // Grow connection window and queue MAX_DATA
                                let new_max =
                                    self.conn_max_data.saturating_mul(2).min(MAX_STREAM_SIZE);
                                self.conn_max_data = new_max;
                                self.pending_control.push_back(Frame::MaxData { max: new_max });
                            }
                        }
                        Frame::MaxData { max } => {
                            // Peer increased our send window - validate and clamp
                            let clamped = if max > MAX_PEER_MAX_DATA {
                                log::warn!(
                                    "[transport] peer MAX_DATA {} exceeds cap {}, clamping",
                                    max,
                                    MAX_PEER_MAX_DATA
                                );
                                MAX_PEER_MAX_DATA
                            } else {
                                max
                            };
                            // RFC 9000: MAX_DATA must be monotonically increasing
                            if clamped > self.peer_max_data {
                                self.peer_max_data = clamped;
                            }
                        }
                        Frame::MaxStreamData { stream_id, max } => {
                            // Peer increased per-stream send window
                            let s = self.streams.entry(stream_id).or_insert_with(|| Stream {
                                id: stream_id,
                                #[cfg(not(feature = "stream_ring_buffer"))]
                                send_buf: Vec::new(),
                                #[cfg(not(feature = "stream_ring_buffer"))]
                                recv_buf: Vec::new(),
                                #[cfg(feature = "stream_ring_buffer")]
                                send_ring: StreamRingBuffer::new(),
                                #[cfg(feature = "stream_ring_buffer")]
                                recv_ring: StreamRingBuffer::new(),
                                send_fin: false,
                                recv_fin: false,
                                send_off: 0,
                                recv_off: 0,
                                recv_next: 0,
                                recv_final_size: None,
                                recv_frags: std::collections::BTreeMap::new(),
                                priority_urgency: 3,
                                #[cfg(any(test, feature = "rust-tests"))]
                                priority_incremental: false,
                                max_stream_data_rx: self.config.initial_max_stream_data_bidi_local,
                                max_stream_data_tx: self.config.initial_max_stream_data_bidi_remote,
                            });
                            s.max_stream_data_tx = max;
                        }
                        Frame::ConnectionClose { .. } | Frame::ApplicationClose { .. } => {
                            self.is_closed = true;
                            self.is_draining = true;
                        }
                        Frame::PathChallenge { data } => {
                            ack_eliciting = true;
                            self.stats.path_challenge_rx_count =
                                self.stats.path_challenge_rx_count.saturating_add(1);
                            self.enqueue_path_response(info.to, info.from, data);
                        }
                        Frame::Datagram { data } => {
                            ack_eliciting = true;
                            self.stats.dgram_recv += 1;
                            if !self.is_dgram_recv_queue_full() {
                                #[cfg(not(feature = "zero_copy_dgram"))]
                                self.dgram_recv_queue.push_back(data.into_owned());
                                #[cfg(feature = "zero_copy_dgram")]
                                {
                                    let mut buf = self.dgram_pool.alloc();
                                    let len = data.len().min(buf.len());
                                    buf[..len].copy_from_slice(&data[..len]);
                                    self.dgram_recv_queue.push_back(DatagramBuffer {
                                        data: buf,
                                        len,
                                        _pool: self.dgram_pool.clone(),
                                    });
                                }
                            }
                        }
                        Frame::Ack { ranges, ack_delay, .. } => {
                            // Decode ack_delay using the configured ack_delay_exponent
                            // (RFC 9000 §19.3: ack_delay is in microseconds = value << exponent)
                            let exp = self.config.ack_delay_exponent.min(20);
                            let ack_delay_us = ack_delay << exp;
                            let ack_delay = Duration::from_micros(ack_delay_us);
                            // Late ACKs retire stream transmissions whose packet was
                            // previously declared lost (spurious-loss accounting).
                            self.acknowledge_late_stream_packets(&ranges);
                            let space = recovery::PacketSpace::from_index(space_idx);
                            let now = Instant::now();
                            let outcome = self.recovery.on_ack_received(
                                space,
                                &ranges,
                                ack_delay,
                                self.tls_handshake_complete(),
                                self.is_server,
                                now,
                            );
                            self.apply_ack_outcome(space, outcome, now);
                        }
                        Frame::Crypto { offset, data } => {
                            let lvl = match pkt_ty {
                                PacketType::Initial => crate::qftls::Level::Initial,
                                PacketType::Handshake => crate::qftls::Level::Handshake,
                                _ => crate::qftls::Level::Application,
                            };
                            self.process_crypto_frame(lvl, offset, data)?;
                            ack_eliciting = true;
                        }
                        Frame::Ping { .. } => {
                            ack_eliciting = true;
                        }
                        Frame::ResetStream { .. } => {
                            // Transport-level RST indicator
                            crate::optimize::telemetry::STEALTH_SIGNAL_RST
                                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                            ack_eliciting = true;
                        }
                        Frame::StopSending { .. } => {
                            // Transport-level stop-sending treated as soft RST indicator
                            crate::optimize::telemetry::STEALTH_SIGNAL_RST
                                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                            ack_eliciting = true;
                        }
                        Frame::PathResponse { data } => {
                            ack_eliciting = true;
                            self.handle_path_response_frame(info.to, info.from, data);
                        }
                        Frame::NewToken { .. }
                        | Frame::MaxStreamsBidi { .. }
                        | Frame::MaxStreamsUni { .. }
                        | Frame::DataBlocked { .. }
                        | Frame::StreamDataBlocked { .. }
                        | Frame::StreamsBlockedBidi { .. }
                        | Frame::StreamsBlockedUni { .. }
                        | Frame::NewConnectionId { .. }
                        | Frame::RetireConnectionId { .. } => {
                            ack_eliciting = true;
                        }
                        _ => {}
                    }
                }
                Err(_) => {
                    break;
                }
            }
        }
        if ack_eliciting {
            self.pkt_spaces[space_idx]
                .note_ack_eliciting(self.config.max_ack_delay, self.config.ack_eliciting_threshold);
        }

        // Update ECN counters for ACK ECN section (per-datagram)
        if let Some(mark) = info.ecn {
            match mark {
                EcnMark::Ect0 => self.ecn_ect0 = self.ecn_ect0.saturating_add(1),
                EcnMark::Ect1 => self.ecn_ect1 = self.ecn_ect1.saturating_add(1),
                EcnMark::Ce => self.ecn_ce = self.ecn_ce.saturating_add(1),
            }
            if let Some(obs) = &self.observer {
                obs.on_ecn_update(self.ecn_ect0, self.ecn_ect1, self.ecn_ce);
            }
        }
        // Update connection state
        let len = end;
        self.stats.recv += 1;
        self.stats.recv_bytes += len as u64;
        self.last_activity = Instant::now();
        if !self.is_established && self.stats.recv > 0 && self.stats.sent > 0 {
            self.is_established = true;
        }
        Ok(len)
    }

    #[inline(always)]
    fn refresh_short_header_tag_reserve(&mut self) {
        let has_seal = self.crypto.read().seal_1rtt.is_some();
        self.short_header_tag_reserve = if has_seal { 16 } else { 0 };
        // Sync the lock-free 1-RTT ArcSwap whenever we refresh the tag reserve.
        // This is called after all TLS key installations and key updates, ensuring
        // the ArcSwap mirrors the RwLock-protected CryptoContext.
        self.sync_1rtt();
    }

    /// Sync the lock-free `crypto_1rtt` ArcSwap from the RwLock-protected CryptoContext.
    ///
    /// Must be called after any `crypto.write()` that installs, rotates, or clears 1-RTT keys.
    /// In steady state (no key updates), the ArcSwap is never touched - the hot path loads
    /// it lock-free via `arc_swap::ArcSwapOption::load()`.
    fn sync_1rtt(&self) {
        let crypto = self.crypto.read();
        if let (Some(seal), Some(open), Some(hp_seal), Some(hp_open)) = (
            crypto.seal_1rtt.clone(),
            crypto.open_1rtt.clone(),
            crypto.hp_1rtt.clone(),
            crypto.hp_1rtt_open.clone(),
        ) {
            self.crypto_1rtt.store(Some(std::sync::Arc::new(packet::OneRttCrypto {
                seal,
                open,
                hp_seal,
                hp_open,
            })));
        } else {
            self.crypto_1rtt.store(None);
        }
    }

    #[inline(always)]
    fn tag_reserve_1rtt(&self) -> usize {
        self.short_header_tag_reserve as usize
    }

    /// Returns true if `frame` is ack-eliciting per RFC 9000 §19 / RFC 9002 §7.2.
    /// Ack-eliciting frames require the peer to send an ACK and are congestion-
    /// controlled. Non-ack-eliciting frames: PADDING, ACK, CONNECTION_CLOSE,
    /// APPLICATION_CLOSE. All other frame types are ack-eliciting.
    #[inline(always)]
    fn frame_is_ack_eliciting(frame: &Frame<'_>) -> bool {
        !matches!(
            frame,
            Frame::Padding { .. }
                | Frame::Ack { .. }
                | Frame::ConnectionClose { .. }
                | Frame::ApplicationClose { .. }
        )
    }

    /// Flushes pending control frames. Returns `(new_off, wrote_ack_eliciting)`
    /// where `wrote_ack_eliciting` is true if any ack-eliciting frame was
    /// emitted (e.g. PING, MAX_DATA, NEW_CONNECTION_ID). This is used by the
    /// caller to decide whether the packet is congestion-controlled.
    ///
    /// When `congestion_bypass` is true, the caller is emitting an ACK-only
    /// packet to bypass the congestion gate (RFC 9002 §7.2). In that mode only
    /// non-ack-eliciting control frames (CONNECTION_CLOSE / APPLICATION_CLOSE)
    /// may be emitted - emitting ack-eliciting frames would inflate
    /// bytes_in_flight beyond cwnd, violating RFC 9002 §7.2 ("A sender MUST
    /// NOT send a packet if it would cause bytes_in_flight to exceed the
    /// congestion window"). Ack-eliciting control frames are left in the queue
    /// and flushed on a later non-bypassed send.
    #[inline(always)]
    fn flush_pending_control_frames(
        &mut self,
        out: &mut [u8],
        mut off: usize,
        congestion_bypass: bool,
    ) -> Result<(usize, bool), crate::error::ConnectionError> {
        let mut wrote_ack_eliciting = false;
        while let Some(ctrl) = self.pending_control.front() {
            // When bypassing the congestion gate, skip ack-eliciting control
            // frames (PING, MAX_DATA, NEW_CONNECTION_ID, HANDSHAKE_DONE,
            // RESET_STREAM, STOP_SENDING, PATH_CHALLENGE, PATH_RESPONSE,
            // DATA_BLOCKED, STREAM_DATA_BLOCKED, …). They are left in the
            // queue and emitted on a later send that respects the cwnd.
            if congestion_bypass && Self::frame_is_ack_eliciting(ctrl) {
                break;
            }
            let need = frames::wire_len(ctrl);
            let tag_reserve = self.tag_reserve_1rtt();
            if out.len() >= off + need + tag_reserve {
                off += frames::to_bytes(ctrl, &mut out[off..])?;
                if Self::frame_is_ack_eliciting(ctrl) {
                    wrote_ack_eliciting = true;
                }
                self.pending_control.pop_front();
            } else {
                break;
            }
        }
        Ok((off, wrote_ack_eliciting))
    }

    #[inline(always)]
    fn maybe_emit_application_ack_frame(
        &mut self,
        out: &mut [u8],
        mut off: usize,
    ) -> Result<usize, crate::error::ConnectionError> {
        if let Some((ack_delay, ack_ranges)) =
            self.pkt_spaces[2].take_ack(self.config.ack_delay_exponent)
        {
            let ecn = if self.ecn_ect0 | self.ecn_ect1 | self.ecn_ce > 0 {
                Some(EcnCounts { ect0: self.ecn_ect0, ect1: self.ecn_ect1, ce: self.ecn_ce })
            } else {
                None
            };
            let ack = Frame::Ack { ack_delay, ranges: ack_ranges, ecn_counts: ecn };
            let need = frames::wire_len(&ack);
            let tag_reserve = self.tag_reserve_1rtt();
            let mut ack_written = false;
            if out.len() >= off + need + tag_reserve {
                off += frames::to_bytes(&ack, &mut out[off..])?;
                ack_written = true;
            }
            if ack_written {
                if let Some(obs) = &self.observer {
                    if let Frame::Ack { ranges, .. } = &ack {
                        obs.on_ack(ack_delay, ranges);
                    }
                }
                if matches!(&ack, Frame::Ack { ecn_counts: Some(_), .. }) {
                    self.ecn_ect0 = 0;
                    self.ecn_ect1 = 0;
                    self.ecn_ce = 0;
                }
                let exp = self.config.ack_delay_exponent.min(20);
                let ack_delay_us = ack_delay << exp;
                crate::telemetry::ACK_DELAY_LAST_US
                    .store(ack_delay_us, std::sync::atomic::Ordering::Relaxed);
                if let Some(obs) = self.observer.as_ref().cloned() {
                    obs.apply_policy(self);
                }
            }
        }
        Ok(off)
    }

    /// Flushes one retransmitted or new STREAM range. Returns `(new_off,
    /// wrote_ack_eliciting, transmission_id)` - STREAM frames are always
    /// ack-eliciting when emitted (RFC 9000 §19.8).
    fn maximum_stream_payload(
        packet_len: usize,
        packet_offset: usize,
        tag_reserve: usize,
        stream_id: u64,
        stream_offset: u64,
        available: usize,
    ) -> usize {
        let mut lower = 0usize;
        let mut upper = available;
        while lower < upper {
            let candidate = lower + (upper - lower).div_ceil(2);
            let wire_len = frames::stream_frame_wire_len(stream_id, stream_offset, candidate);
            if packet_offset.saturating_add(wire_len).saturating_add(tag_reserve) <= packet_len {
                lower = candidate;
            } else {
                upper = candidate - 1;
            }
        }
        lower
    }

    #[inline(always)]
    fn maybe_flush_one_writable_stream(
        &mut self,
        out: &mut [u8],
        mut off: usize,
    ) -> Result<(usize, bool, Option<u64>), crate::error::ConnectionError> {
        use crate::error::ConnectionError;

        while let Some(transmission_id) = self.stream_retransmit_queue.front().copied() {
            let Some(transmission) = self.stream_transmissions.get(&transmission_id) else {
                self.stream_retransmit_queue.pop_front();
                continue;
            };
            if !transmission.queued {
                self.stream_retransmit_queue.pop_front();
                continue;
            }

            let stream_id = transmission.stream_id;
            let stream_offset = transmission.offset;
            let data = Arc::clone(&transmission.data);
            let fin = transmission.fin;
            let need = frames::stream_frame_wire_len(stream_id, stream_offset, data.len());
            let tag_reserve = self.tag_reserve_1rtt();
            if out.len() < off + need + tag_reserve {
                let prefix_len = Self::maximum_stream_payload(
                    out.len(),
                    off,
                    tag_reserve,
                    stream_id,
                    stream_offset,
                    data.len(),
                );
                if prefix_len == 0 || data.is_empty() {
                    return Ok((off, false, None));
                }
                self.split_queued_stream_transmission(transmission_id, prefix_len)?;
                continue;
            }
            off += frames::write_stream_frame(
                stream_id,
                stream_offset,
                data.as_ref(),
                fin,
                &mut out[off..],
            )?;
            return Ok((off, true, Some(transmission_id)));
        }

        let ledger_bytes = self.stream_retransmit_bytes;
        let ledger_entries = self.stream_transmissions.len();
        let mut staged_transmission: Option<(u64, u64, Arc<[u8]>, bool)> = None;
        if let Some(stream_id) = self.writable_streams.front().copied() {
            let tag_reserve = self.tag_reserve_1rtt();
            if let Some(s) = self.streams.get_mut(&stream_id) {
                let available = {
                    #[cfg(not(feature = "stream_ring_buffer"))]
                    {
                        s.send_buf.len()
                    }
                    #[cfg(feature = "stream_ring_buffer")]
                    {
                        s.send_ring.len()
                    }
                };
                if available > 0 {
                    let header_overhead = frames::stream_frame_wire_len(stream_id, s.send_off, 0);
                    if off + header_overhead + tag_reserve <= out.len() {
                        let conn_avail =
                            self.peer_max_data.saturating_sub(self.conn_bytes_sent) as usize;
                        let stream_avail = s.max_stream_data_tx.saturating_sub(s.send_off) as usize;
                        let send_avail = conn_avail.min(stream_avail);
                        if send_avail == 0 {
                            self.pending_control
                                .push_back(Frame::DataBlocked { limit: self.peer_max_data });
                            self.pending_control.push_back(Frame::StreamDataBlocked {
                                stream_id,
                                limit: s.max_stream_data_tx,
                            });
                            return Err(ConnectionError::Done);
                        }
                        let body_len = Self::maximum_stream_payload(
                            out.len(),
                            off,
                            tag_reserve,
                            stream_id,
                            s.send_off,
                            available.min(send_avail),
                        );
                        if body_len == 0 {
                            return Ok((off, false, None));
                        }
                        if ledger_entries >= MAX_STREAM_TRANSMISSIONS
                            || ledger_bytes.saturating_add(body_len) > MAX_STREAM_RETRANSMIT_BYTES
                        {
                            return Ok((off, false, None));
                        }
                        let stream_offset = s.send_off;
                        let fin_now = {
                            #[cfg(not(feature = "stream_ring_buffer"))]
                            {
                                s.send_fin && body_len == available
                            }
                            #[cfg(feature = "stream_ring_buffer")]
                            {
                                s.send_fin && body_len == available
                            }
                        };
                        #[cfg(not(feature = "stream_ring_buffer"))]
                        let data = {
                            let data = Arc::<[u8]>::from(&s.send_buf[..body_len]);
                            let written = frames::write_stream_frame(
                                s.id,
                                stream_offset,
                                data.as_ref(),
                                fin_now,
                                &mut out[off..],
                            )?;
                            off += written;
                            data
                        };
                        #[cfg(feature = "stream_ring_buffer")]
                        let data = {
                            let mut v = vec![0u8; body_len];
                            let read = s.send_ring.read(&mut v[..]);
                            if read < body_len {
                                v.truncate(read);
                            }
                            let data = Arc::<[u8]>::from(v);
                            let written = frames::write_stream_frame(
                                s.id,
                                stream_offset,
                                data.as_ref(),
                                fin_now,
                                &mut out[off..],
                            )?;
                            off += written;
                            data
                        };
                        let data_len = data.len();
                        s.send_off += data_len as u64;
                        #[cfg(not(feature = "stream_ring_buffer"))]
                        {
                            if data_len == s.send_buf.len() {
                                s.send_buf.clear();
                            } else {
                                s.send_buf.drain(0..data_len);
                            }
                        }
                        self.conn_bytes_sent = self.conn_bytes_sent.saturating_add(data_len as u64);
                        self.stats.stream_sent_bytes += data_len as u64;
                        let emptied = {
                            #[cfg(not(feature = "stream_ring_buffer"))]
                            {
                                s.send_buf.is_empty()
                            }
                            #[cfg(feature = "stream_ring_buffer")]
                            {
                                s.send_ring.is_empty()
                            }
                        };
                        if emptied && fin_now {
                            self.writable_streams.retain(|&id| id != stream_id);
                        }
                        staged_transmission = Some((stream_id, stream_offset, data, fin_now));
                    }
                } else if s.send_fin {
                    // Stream has no pending data but fin was requested: emit a
                    // fin-only STREAM frame so the peer learns the stream is
                    // half-closed. Without this, the fin flag would never reach
                    // the peer and the stream would stay open forever.
                    let header_overhead = 1
                        + crate::transport::varint::varint_len(stream_id)
                        + crate::transport::varint::varint_len(s.send_off)
                        + 2;
                    if off + header_overhead + tag_reserve < out.len() {
                        if ledger_entries >= MAX_STREAM_TRANSMISSIONS {
                            return Ok((off, false, None));
                        }
                        let stream_offset = s.send_off;
                        let written = frames::write_stream_frame(
                            s.id,
                            stream_offset,
                            &[],
                            true,
                            &mut out[off..],
                        )?;
                        off += written;
                        self.writable_streams.retain(|&id| id != stream_id);
                        staged_transmission = Some((stream_id, stream_offset, Arc::from([]), true));
                    }
                } else {
                    // Stream has no pending data and no fin: remove it from the
                    // writable queue so the next stream gets a turn. The stream
                    // is re-added to the queue when stream_send() is called again.
                    // Without this, an idle stream blocks all other streams
                    // forever because maybe_flush_one_writable_stream only looks
                    // at the front of the queue.
                    self.writable_streams.retain(|&id| id != stream_id);
                }
            }
        }
        if let Some((stream_id, stream_offset, data, fin)) = staged_transmission {
            let transmission_id =
                self.stage_stream_transmission(stream_id, stream_offset, data, fin)?;
            return Ok((off, true, Some(transmission_id)));
        }
        Ok((off, false, None))
    }

    #[inline(always)]
    fn pending_datagram_frame_reserve(&self) -> Option<usize> {
        #[cfg(not(feature = "zero_copy_dgram"))]
        let payload_len = self.dgram_send_queue.front()?.len();
        #[cfg(feature = "zero_copy_dgram")]
        let payload_len = self.dgram_send_queue.front()?.len;
        Some(1 + 2 + payload_len)
    }

    /// Flushes one DATAGRAM frame. Returns `(new_off, wrote_ack_eliciting)`.
    /// DATAGRAM frames are ack-eliciting per RFC 9221 §2.
    #[inline(always)]
    fn maybe_flush_one_datagram_frame(
        &mut self,
        out: &mut [u8],
        mut off: usize,
    ) -> Result<(usize, bool), crate::error::ConnectionError> {
        if let Some(need) = self.pending_datagram_frame_reserve() {
            let tag_reserve = self.tag_reserve_1rtt();
            log::debug!("maybe_flush_one_datagram_frame: off={} need={} tag_reserve={} out_len={} queue_len={}",
                off, need, tag_reserve, out.len(), self.dgram_send_queue.len());
            if off + need + tag_reserve <= out.len() {
                #[cfg(not(feature = "zero_copy_dgram"))]
                {
                    let Some(front_owned) = self.dgram_send_queue.pop_front() else {
                        return Err(crate::error::ConnectionError::Done);
                    };
                    let frame = Frame::Datagram { data: Cow::Owned(front_owned) };
                    log::debug!("maybe_flush_one_datagram_frame: attempting to write frame, frame_wire_len={}", frames::wire_len(&frame));
                    match frames::to_bytes(&frame, &mut out[off..]) {
                        Ok(written) => {
                            log::debug!("maybe_flush_one_datagram_frame: wrote {} bytes", written);
                            off += written;
                            // DATAGRAM frames are ack-eliciting (RFC 9221 §2).
                            return Ok((off, true));
                        }
                        Err(e) => {
                            log::debug!("maybe_flush_one_datagram_frame: to_bytes failed: {:?}", e);
                            if let Frame::Datagram { data } = frame {
                                self.dgram_send_queue.push_front(data.into_owned());
                            }
                            return Err(e);
                        }
                    }
                }
                #[cfg(feature = "zero_copy_dgram")]
                {
                    let Some(front) = self.dgram_send_queue.pop_front() else {
                        return Err(crate::error::ConnectionError::Done);
                    };
                    let frame =
                        Frame::Datagram { data: Cow::Owned(front.data[..front.len].to_vec()) };
                    match frames::to_bytes(&frame, &mut out[off..]) {
                        Ok(written) => {
                            off += written;
                            return Ok((off, true));
                        }
                        Err(error) => {
                            self.dgram_send_queue.push_front(front);
                            return Err(error);
                        }
                    }
                }
            }
        }
        Ok((off, false))
    }

    #[inline(always)]
    fn maybe_apply_stealth_padding(
        &mut self,
        out: &mut [u8],
        pn_off: usize,
        pn_len: usize,
        mut off: usize,
    ) -> Result<usize, crate::error::ConnectionError> {
        // --- Traffic analysis defense modes (TODO-455) ---
        //
        // FullPadding / ConstantRate take precedence over the legacy
        // probabilistic padding path. They pad EVERY 1-RTT packet to a fixed
        // target size regardless of `stealth_padding_rate`, eliminating
        // size-based traffic analysis.
        let defense = self.config.traffic_analysis_defense;
        if matches!(defense, TrafficAnalysisDefense::FullPadding)
            || matches!(defense, TrafficAnalysisDefense::ConstantRate)
        {
            let tag_reserve = self.tag_reserve_1rtt();
            let avail = out.len().saturating_sub(off + tag_reserve);
            // Target total packet size. FullPadding uses max_udp_payload_size;
            // ConstantRate uses the chaff size (consistent across real + chaff).
            let target_total = match defense {
                TrafficAnalysisDefense::FullPadding => self.config.max_udp_payload_size as usize,
                TrafficAnalysisDefense::ConstantRate => self.config.chaff_size_bytes as usize,
                _ => 0,
            };
            if target_total > 0 && target_total > off + tag_reserve {
                let needed = target_total - off - tag_reserve;
                let pad_len = needed.min(avail);
                if pad_len > 0 {
                    off += frames::write_padding(pad_len, &mut out[off..])?;
                }
            }
            return Ok(off);
        }

        if self.config.stealth_padding_enabled {
            let tag_reserve = self.tag_reserve_1rtt();
            let avail = out.len().saturating_sub(off + tag_reserve);

            // Strategy 5 = PacketNormalize: pad all 1-RTT packets to a fixed total size.
            // target covers header + payload + tag; compute payload padding needed.
            if self.config.stealth_padding_strategy == 5 {
                let target = self.config.stealth_normalize_target_size;
                if target > 0 && target > off + tag_reserve {
                    let needed = target - off - tag_reserve;
                    let pad_len = needed.min(avail);
                    if pad_len > 0 {
                        off += frames::write_padding(pad_len, &mut out[off..])?;
                    }
                }
                return Ok(off);
            }

            let ad_len = pn_off + pn_len;
            let pt_len_now = off.saturating_sub(ad_len);
            if avail > 0 {
                let pad_len = self.compute_stealth_padding(pt_len_now, avail);
                if pad_len > 0 {
                    let written = frames::write_padding(pad_len, &mut out[off..])?;
                    off += written;
                }
            }
        }
        Ok(off)
    }

    /// Queues a cover PING frame to be emitted in the next outgoing 1-RTT packet.
    ///
    /// The PING is ack-eliciting: the peer sends an ACK, generating symmetric traffic
    /// that matches idle HTTP/3 keepalive patterns observed in real browser sessions.
    pub(crate) fn queue_cover_ping(&mut self) {
        if self.is_established() {
            self.pending_control.push_back(Frame::Ping { mtu_probe: None });
        }
    }

    #[inline(always)]
    fn seal_short_header_packet(
        &mut self,
        out: &mut [u8],
        pn: u64,
        pn_off: usize,
        pn_len: usize,
        mut off: usize,
    ) -> Result<usize, crate::error::ConnectionError> {
        // Set PN length bits in the first byte BEFORE sealing so the AAD
        // matches what the peer sees after HP removal. Without this, the
        // first byte used for AEAD sealing is 0x40 (from format_short_header,
        // which doesn't set PN length bits), but the peer reconstructs it as
        // 0x40 | (pn_len-1) after HP removal. For 1-byte PN this happens to
        // match (0x40), but for 2+ byte PN the AAD differs and decryption fails.
        out[0] = 0x40 | (((pn_len as u8) - 1) & 0x03);
        if self.key_phase {
            out[0] |= packet::KEY_PHASE_BIT;
        }

        // Hot path: try lock-free 1-RTT ArcSwap first.
        let one_rtt = self.crypto_1rtt.load();
        if let Some(keys) = one_rtt.as_ref() {
            // 1-RTT steady state - no lock acquisition.
            let ad_len = pn_off + pn_len;
            let (ad_slice, rest) = out.split_at_mut(ad_len);
            let pt_len = off.saturating_sub(ad_len);
            let mut item = crate::crypto::aead::AeadSealItem {
                counter: pn,
                ad: ad_slice,
                buf: rest,
                plaintext_len: pt_len,
            };
            keys.seal.seal_batch(core::slice::from_mut(&mut item))?;
            let sealed_len = pt_len + 16;
            off = ad_len + sealed_len;
            let mask = if off >= pn_off + 4 + packet::SAMPLE_LEN {
                let sample = &out[pn_off + 4..pn_off + 4 + packet::SAMPLE_LEN];
                Some(keys.hp_seal.new_mask(sample))
            } else {
                None
            };
            if let Some(mask) = mask {
                out[0] ^= mask[0] & 0x1f;
                for i in 0..pn_len {
                    out[pn_off + i] ^= mask[i + 1];
                }
            }
            self.next_send_pn_by_space[2] = self.next_send_pn_by_space[2].wrapping_add(1);
            return Ok(off);
        }

        // Fallback: 0-RTT or handshake - use RwLock.
        let use_1rtt_seal = {
            let crypto_guard = self.crypto.read();
            crypto_guard.seal_1rtt.is_some()
        };
        let sealed_len = {
            let crypto_guard = self.crypto.read();
            let ad_len = pn_off + pn_len;
            let (ad_slice, rest) = out.split_at_mut(ad_len);
            let pt_len = off.saturating_sub(ad_len);
            let mut item = crate::crypto::aead::AeadSealItem {
                counter: pn,
                ad: ad_slice,
                buf: rest,
                plaintext_len: pt_len,
            };
            packet::seal_data_aead_batch(&crypto_guard, core::slice::from_mut(&mut item))?;
            pt_len + 16
        };
        let ad_len = pn_off + pn_len;
        off = ad_len + sealed_len;
        let mask = {
            let crypto_guard = self.crypto.read();
            let hp = if use_1rtt_seal {
                crypto_guard.hp_1rtt.as_deref()
            } else {
                crypto_guard.hp_0rtt.as_deref().or(crypto_guard.hp_1rtt.as_deref())
            };
            if off >= pn_off + 4 + packet::SAMPLE_LEN {
                hp.map(|hp| {
                    let sample = &out[pn_off + 4..pn_off + 4 + packet::SAMPLE_LEN];
                    hp.new_mask(sample)
                })
            } else {
                None
            }
        };
        if let Some(mask) = mask {
            out[0] ^= mask[0] & 0x1f;
            for i in 0..pn_len {
                out[pn_off + i] ^= mask[i + 1];
            }
        }
        self.next_send_pn_by_space[2] = self.next_send_pn_by_space[2].wrapping_add(1);
        Ok(off)
    }

    #[inline(always)]
    fn send_targeted_short_header_frame(
        &mut self,
        out: &mut [u8],
        send_local: SocketAddr,
        send_peer: SocketAddr,
        frame: &Frame<'_>,
    ) -> Result<(usize, SendInfo), crate::error::ConnectionError> {
        // Build short header prefix with DCID directly - avoids two Vec
        // allocations (dcid.to_vec() + scid.to_vec()) per outbound packet.
        let hdr_len = packet::format_short_header(self.dcid.as_ref(), false, out)?;
        let pn = self.next_send_pn_by_space[2];
        let pn_len = if pn < (1 << 8) {
            1
        } else if pn < (1 << 16) {
            2
        } else if pn < (1 << 24) {
            3
        } else {
            4
        };
        if out.len() < hdr_len + pn_len {
            return Err(crate::error::ConnectionError::BufferTooShort);
        }

        let pn_off = 1 + self.dcid.as_ref().len();
        let mut tmp = [0u8; 4];
        packet::encode_pkt_num(pn, pn_len, &mut tmp[..pn_len])?;
        out[pn_off..pn_off + pn_len].copy_from_slice(&tmp[..pn_len]);

        let mut off = pn_off + pn_len;
        let need = frames::wire_len(frame);
        let tag_reserve = self.tag_reserve_1rtt();
        if out.len() < off + need + tag_reserve {
            return Err(crate::error::ConnectionError::BufferTooShort);
        }
        off += frames::to_bytes(frame, &mut out[off..])?;
        off = self.seal_short_header_packet(out, pn, pn_off, pn_len, off)?;

        let info = SendInfo {
            from: send_local,
            to: send_peer,
            at: Instant::now(),
            congestion_controlled: true,
        };
        self.mark_unvalidated_path_send(send_local, send_peer, off);
        self.stats.sent += 1;
        self.stats.sent_bytes += off as u64;
        let now = Instant::now();
        self.recovery.on_packet_sent_in_space(
            recovery::PacketSpace::Application,
            pn,
            off,
            true,
            true,
            None,
            now,
        );
        self.cwnd = self.recovery.cwnd;
        self.refresh_path_count();
        Ok((off, info))
    }

    /// Generates outgoing packet
    #[inline(always)]
    pub fn send(
        &mut self,
        out: &mut [u8],
    ) -> Result<(usize, SendInfo), crate::error::ConnectionError> {
        self.send_with_datagram_overhead(out, 0)
    }

    /// Generates an outgoing packet while reserving bytes for an outer datagram
    /// envelope. Non-zero overhead is valid only after the QUIC handshake.
    #[inline(always)]
    pub fn send_with_datagram_overhead(
        &mut self,
        out: &mut [u8],
        datagram_overhead: usize,
    ) -> Result<(usize, SendInfo), crate::error::ConnectionError> {
        use crate::error::ConnectionError;
        use udpfast::unlikely;
        if unlikely(out.len() < MIN_CLIENT_INITIAL_LEN) {
            return Err(ConnectionError::BufferTooShort);
        }
        if unlikely(datagram_overhead != 0 && !self.post_handshake_datagram_ready()?) {
            return Err(ConnectionError::InvalidState);
        }
        // Never emit a QUIC packet larger than the negotiated max UDP payload size.
        // The caller's buffer may be larger than the path MTU (e.g. a pooled 2 KiB block),
        // but downstream send paths use fixed-size datagram buffers; an oversized packet
        // would be silently truncated, destroying the AEAD tag and making the peer unable
        // to decrypt. Clamping the working buffer to the MTU forces CRYPTO/stream framing
        // to fragment across multiple packets instead of overflowing a single one.
        //
        // DPLPMTUD (TODO-451): when enabled, clamp to the *confirmed* path MTU rather
        // than the configured max. Probe packets are sized separately below.
        let now = Instant::now();
        // Apply black-hole recovery before deriving this send's packetization
        // budget so the first recovery packet uses the safe floor immediately.
        if self.pmtu.check_black_hole(now) {
            let previous_mtu = self.pmtu.effective_mtu();
            self.pmtu.reset_to_minimum(now);
            self.pmtu_above_floor_pns.clear();
            log::warn!(
                "DPLPMTUD black hole detected: path MTU {}B -> {}B",
                previous_mtu,
                self.pmtu.effective_mtu()
            );
        }
        let pmtu = self.pmtu.effective_mtu();
        let available_probe_target = self.pmtu.probe_target().filter(|target| {
            self.is_established
                && self.pmtu.should_send_probe(now)
                && *target <= self.dgram_send_max_size
                && *target <= out.len()
        });
        let dedicated_pmtu_probe = available_probe_target.is_some();
        let packetization_mtu = available_probe_target.unwrap_or(pmtu).max(pmtu);
        let outer_mtu_cap = out
            .len()
            .min(self.dgram_send_max_size.max(MIN_CLIENT_INITIAL_LEN))
            .min(packetization_mtu.max(MIN_CLIENT_INITIAL_LEN));
        let mtu_cap = outer_mtu_cap.saturating_sub(datagram_overhead);
        log::debug!("send_with_datagram_overhead: out_len={} dgram_send_max_size={} pmtu={} packetization_mtu={} outer_mtu_cap={} datagram_overhead={} mtu_cap={} dgram_queue_len={} bytes_in_flight={} cwnd={}",
            out.len(), self.dgram_send_max_size, pmtu, packetization_mtu, outer_mtu_cap, datagram_overhead, mtu_cap, self.dgram_send_queue.len(), self.bytes_in_flight, self.cwnd);
        if unlikely(mtu_cap == 0) {
            return Err(ConnectionError::BufferTooShort);
        }
        let out = &mut out[..mtu_cap];
        // Congestion gate: only send if within cwnd budget.
        // ACK-only packets bypass the gate (RFC 9002 §7.2) to prevent
        // congestion-control deadlocks where both sides exhaust their windows
        // and neither can send ACKs to release budget.
        let congestion_blocked = !self.recovery.can_send(self.dgram_send_max_size);
        log::debug!("send_with_datagram_overhead congestion gate: recovery.bytes_in_flight={} recovery.cwnd={} dgram_send_max_size={} congestion_blocked={}",
            self.recovery.bytes_in_flight, self.recovery.cwnd, self.dgram_send_max_size, congestion_blocked);
        let mut congestion_bypass = congestion_blocked && self.has_pending_application_ack();
        let mut pmtu_probe_bypassed_congestion = false;
        if congestion_blocked && !congestion_bypass {
            // RFC 9002 §7.5/§6.2.4: PTO probes MUST NOT be blocked by the
            // congestion controller (they still count as in flight). The probe
            // PING is written below in the assembly; stream/datagram payloads
            // stay gated.
            if self.pending_probe_spaces.iter().any(|s| *s == recovery::PacketSpace::Application) {
                congestion_bypass = true;
            }
        }
        if congestion_blocked
            && !congestion_bypass
            && dedicated_pmtu_probe
            && self.pmtu.can_bypass_congestion(self.recovery.rtt)
        {
            // RFC 8899 permits an isolated probe outside congestion control
            // only when the configured probe interval is at least one RTT.
            // This path emits only the PING+PADDING probe below.
            congestion_bypass = true;
            pmtu_probe_bypassed_congestion = true;
        }
        if congestion_blocked && !congestion_bypass {
            log::debug!("send_with_datagram_overhead: early Done congestion_blocked congestion_bypass={} dgram_queue_len={}", congestion_bypass, self.dgram_send_queue.len());
            return Err(ConnectionError::Done);
        }
        self.poll_path_validation_timeout(now);

        // TLS provider may derive new secrets during write-side progression. Poll here so
        // handshake completion and key installation are not dependent on receiving more CRYPTO.
        self.poll_tls_and_validate_versions()?;

        let handshake_incomplete =
            self.tls_provider.as_ref().map(|p| !p.handshake_complete()).unwrap_or(false);

        // Always flush any pending Initial/Handshake CRYPTO before falling through to the
        // 1-RTT path, even if rustls has just reported the handshake complete. The client's
        // Finished is produced at the very instant completion flips to true; if we skipped the
        // handshake send path as soon as handshake_complete became true, that Finished would
        // never reach the wire and the peer would stay stuck handshaking forever (it would
        // only ever see Initial + 1-RTT, never the Handshake-level Finished).
        {
            let (has_initial, has_handshake) = {
                let crypto = self.crypto.read();
                (crypto.seal_initial.is_some(), crypto.seal_handshake.is_some())
            };
            // Try Initial first (when applicable), then Handshake. This avoids stalling if
            // Initial keys are installed but there is no pending Initial CRYPTO, while Handshake
            // CRYPTO is ready.
            for pkt_ty in [PacketType::Initial, PacketType::Handshake] {
                if matches!(pkt_ty, PacketType::Initial) && !has_initial {
                    continue;
                }
                if matches!(pkt_ty, PacketType::Handshake) && !has_handshake {
                    continue;
                }

                let token = if matches!(pkt_ty, PacketType::Initial) {
                    self.config.initial_token.clone()
                } else {
                    None
                };
                let base_hdr = packet::Header {
                    ty: pkt_ty,
                    version: self.config.version,
                    dcid: self.dcid.to_vec(),
                    scid: self.scid.to_vec(),
                    pkt_num: 0,
                    pkt_num_len: 0,
                    token,
                    versions: None,
                    key_phase: false,
                };
                let hdr_len_wo_pn = packet::format_header(&base_hdr, out)?;
                let space_idx = match pkt_ty {
                    PacketType::Initial => 0,
                    PacketType::Handshake => 1,
                    _ => 2,
                };
                let pn = self.next_send_pn_by_space[space_idx];
                let pn_len = if pn < (1 << 8) {
                    1
                } else if pn < (1 << 16) {
                    2
                } else if pn < (1 << 24) {
                    3
                } else {
                    4
                };
                if out.len() < hdr_len_wo_pn + pn_len {
                    return Err(ConnectionError::BufferTooShort);
                }
                let mut tmp = [0u8; 4];
                packet::encode_pkt_num(pn, pn_len, &mut tmp[..pn_len])?;
                out[hdr_len_wo_pn..hdr_len_wo_pn + pn_len].copy_from_slice(&tmp[..pn_len]);
                let header_len = hdr_len_wo_pn + pn_len;
                let mut off = header_len;

                // The CRYPTO data budget must reserve room for everything written into
                // the same packet *after* the data: the AEAD tag (16), the CRYPTO frame
                // header (type 1 + offset varint ≤8 + length varint ≤8), and the ACK/PING
                // frames added below. Without this reserve, next_crypto_frame() returns up
                // to `out.len() - off - 16` bytes, the framed packet overflows the buffer
                // and the seal fails with BufferTooShort. (Since the CRYPTO retention
                // buffer keeps drained bytes unacked, a failed seal no longer loses the
                // data - but the oversized write would still error out every send.)
                const SEND_FRAME_OVERHEAD_RESERVE: usize = 64;
                let crypto_budget =
                    out.len().saturating_sub(off + 16 + SEND_FRAME_OVERHEAD_RESERVE);
                let (lvl, max_len) = match pkt_ty {
                    PacketType::Initial => (crate::qftls::Level::Initial, crypto_budget),
                    PacketType::Handshake => (crate::qftls::Level::Handshake, crypto_budget),
                    _ => (crate::qftls::Level::Application, crypto_budget),
                };
                if max_len < 32 {
                    continue;
                }
                let crypto_frame = self.next_crypto_frame(lvl, max_len);
                let probe_pos = self
                    .pending_probe_spaces
                    .iter()
                    .position(|s| *s == recovery::PacketSpace::from_index(space_idx));
                if crypto_frame.is_none() && probe_pos.is_none() {
                    continue;
                }
                // RFC 9002 §6.2.4: a PTO probe for this space. The packet below
                // always carries PING (ack-eliciting), plus retransmitted or
                // fresh CRYPTO when available. Client Initial probes stay
                // padded to >= 1200 bytes (§6.2.2.1) via target_total below.
                if let Some(pos) = probe_pos {
                    self.pending_probe_spaces.remove(pos);
                }
                let crypto_range = crypto_frame.as_ref().map(|(o, d)| (*o, d.len() as u64));

                if let Some((ack_delay, ack_ranges)) =
                    self.pkt_spaces[space_idx].take_ack(self.config.ack_delay_exponent)
                {
                    let ack = Frame::Ack { ack_delay, ranges: ack_ranges, ecn_counts: None };
                    let need = frames::wire_len(&ack);
                    if out.len() >= off + need + 16 {
                        off += frames::to_bytes(&ack, &mut out[off..])?;
                    }
                }
                let ping = Frame::Ping { mtu_probe: None };
                off += frames::to_bytes(&ping, &mut out[off..])?;
                if let Some((crypto_off, data)) = crypto_frame {
                    let frame = Frame::Crypto { offset: crypto_off, data: Cow::Owned(data) };
                    let written = frames::to_bytes(&frame, &mut out[off..])?;
                    off += written;
                }

                let pn_off = hdr_len_wo_pn;
                let sample_min = pn_off + 4 + packet::SAMPLE_LEN;
                let mut target_total = header_len + 16;
                if sample_min > target_total {
                    target_total = sample_min;
                }
                // Ensure we can actually carry the frames we already wrote, plus the AEAD tag.
                // sample_min only guarantees enough ciphertext for header protection sampling,
                // but we may have already written more plaintext than that budget.
                let frames_min_total = off.saturating_add(16);
                if frames_min_total > target_total {
                    target_total = frames_min_total;
                }
                if matches!(pkt_ty, PacketType::Initial) && MIN_CLIENT_INITIAL_LEN > target_total {
                    target_total = MIN_CLIENT_INITIAL_LEN;
                }
                if out.len() < target_total {
                    return Err(ConnectionError::BufferTooShort);
                }
                let target_off = target_total - 16;
                if off < target_off {
                    let pad_len = target_off - off;
                    frames::write_padding(pad_len, &mut out[off..])?;
                }

                trace_send_packet(
                    self.is_server,
                    pkt_ty,
                    space_idx,
                    pn,
                    pn_len,
                    header_len,
                    target_total,
                );

                let used = {
                    let crypto = self.crypto.read();
                    packet::encrypt_and_protect(
                        &crypto,
                        &mut out[..target_total],
                        header_len,
                        pn,
                        pn_len,
                        pkt_ty,
                    )?
                };
                self.next_send_pn_by_space[space_idx] =
                    self.next_send_pn_by_space[space_idx].wrapping_add(1);
                self.stats.sent += 1;
                self.stats.sent_bytes += used as u64;
                // RFC 9002 §4.9: handshake packets are not special - they are
                // tracked for loss recovery exactly like 1-RTT packets.
                self.recovery.on_packet_sent_in_space(
                    recovery::PacketSpace::from_index(space_idx),
                    pn,
                    used,
                    true,
                    true,
                    crypto_range,
                    Instant::now(),
                );
                if !self.is_established && self.stats.recv > 0 && self.stats.sent > 0 {
                    self.is_established = true;
                }
                return Ok((
                    used,
                    SendInfo {
                        at: Instant::now(),
                        from: self.local_addr,
                        to: self.peer_addr,
                        congestion_controlled: true,
                    },
                ));
            }

            // No pending Initial/Handshake CRYPTO to send. If the handshake is still in
            // progress there is nothing else to do this turn; once it is complete we fall
            // through to the 1-RTT path below.
            if handshake_incomplete {
                log::debug!("send_with_datagram_overhead: early Done handshake_incomplete dgram_queue_len={}", self.dgram_send_queue.len());
                return Err(ConnectionError::Done);
            }
        }
        if let Some(targeted_frame) = self.pop_targeted_path_frame_for_send() {
            return self.send_targeted_short_header_frame(
                out,
                targeted_frame.local_addr,
                targeted_frame.peer_addr,
                &targeted_frame.frame,
            );
        }
        // Nothing to send: return Done to avoid emitting empty 1-RTT packets
        // (header + AEAD tag only). Without this guard, the sender enters an
        // infinite loop of 38B empty packets that flood the socket buffer and
        // starve the recv path on the peer.
        //
        // The handshake-incomplete case is already handled by the early return
        // above (after the Initial/Handshake CRYPTO flush loop) - by this point
        // the handshake is always complete.
        let has_pending_data = !self.pending_control.is_empty()
            || self.has_pending_application_ack()
            || self.has_sendable_stream_frame()
            || !self.dgram_send_queue.is_empty()
            || self.pending_probe_spaces.iter().any(|s| *s == recovery::PacketSpace::Application);
        if !has_pending_data && !congestion_bypass && !dedicated_pmtu_probe {
            log::debug!("send_with_datagram_overhead: early Done has_pending_data=false dgram_queue_len={} pending_control={} app_ack={} sendable_stream={} probe_spaces={} congestion_bypass={} pmtu_probe={}",
                self.dgram_send_queue.len(), self.pending_control.is_empty(), self.has_pending_application_ack(), self.has_sendable_stream_frame(), self.pending_probe_spaces.iter().any(|s| *s == recovery::PacketSpace::Application), congestion_bypass, dedicated_pmtu_probe);
            return Err(ConnectionError::Done);
        }
        // Outbound stealth timing is owned by core::QuicFuscateConnection (next_packet_release).
        // Build short header prefix with DCID directly - avoids two Vec
        // allocations (dcid.to_vec() + scid.to_vec()) per outbound packet.
        let hdr_len = packet::format_short_header(self.dcid.as_ref(), false, out)?; // first byte + DCID
        let dcid_end = 1 + self.dcid.as_ref().len();
        // Decide packet number and length
        let pn = self.next_send_pn_by_space[2];
        let pn_len = if pn < (1 << 8) {
            1
        } else if pn < (1 << 16) {
            2
        } else if pn < (1 << 24) {
            3
        } else {
            4
        };
        if out.len() < hdr_len + pn_len {
            return Err(ConnectionError::BufferTooShort);
        }
        // Write truncated PN (big-endian) before encryption
        {
            let mut tmp = [0u8; 4];
            packet::encode_pkt_num(pn, pn_len, &mut tmp[..pn_len])?;
            out[dcid_end..dcid_end + pn_len].copy_from_slice(&tmp[..pn_len]);
        }
        let pn_off = dcid_end;
        let mut off = pn_off + pn_len;

        // Track whether any ack-eliciting frame was written in this packet.
        // Per RFC 9002 §7.2, only packets containing ack-eliciting frames are
        // congestion-controlled. Non-ack-eliciting frames: PADDING, ACK,
        // CONNECTION_CLOSE, APPLICATION_CLOSE. All others (STREAM, DATAGRAM,
        // CRYPTO, PING, MAX_DATA, NEW_CONNECTION_ID, etc.) are ack-eliciting.
        let mut wrote_ack_eliciting = false;
        let mut stream_transmission_id = None;

        // Post-handshake Application-level CRYPTO (e.g. NewSessionTicket) is not
        // emitted here. The early return above guarantees `handshake_incomplete`
        // is false at this point, so any Application CRYPTO would be
        // post-handshake and should be flushed via a dedicated path that
        // respects flow control and the congestion window. The previous
        // `if handshake_incomplete` block was unreachable dead code.

        if !dedicated_pmtu_probe {
            let (off_after_ctrl, ctrl_ack_eliciting) =
                self.flush_pending_control_frames(out, off, congestion_bypass)?;
            off = off_after_ctrl;
            wrote_ack_eliciting |= ctrl_ack_eliciting;
            off = self.maybe_emit_application_ack_frame(out, off)?;
            // RFC 9002 §6.2.4: emit one ack-eliciting PING per pending
            // Application-space PTO probe. Written directly (not via
            // pending_control) so it also fires when the congestion gate was
            // bypassed for the probe; stream/datagram payloads stay gated.
            if let Some(pos) = self
                .pending_probe_spaces
                .iter()
                .position(|s| *s == recovery::PacketSpace::Application)
            {
                let ping = Frame::Ping { mtu_probe: None };
                let tag_reserve = self.tag_reserve_1rtt();
                if out.len() >= off + frames::wire_len(&ping) + tag_reserve {
                    self.pending_probe_spaces.remove(pos);
                    off += frames::to_bytes(&ping, &mut out[off..])?;
                    wrote_ack_eliciting = true;
                }
            }
            // When bypassing the congestion gate for ACK-only packets, skip
            // stream and datagram data - those are congestion-controlled and
            // must not be sent when the window is exhausted.
            if !congestion_bypass {
                let datagram_reserve = self
                    .pending_datagram_frame_reserve()
                    .filter(|reserve| off + reserve + self.tag_reserve_1rtt() <= out.len())
                    .unwrap_or(0);
                let stream_limit = out.len().saturating_sub(datagram_reserve);
                let (off_after_stream, stream_ack_eliciting, emitted_transmission_id) =
                    self.maybe_flush_one_writable_stream(&mut out[..stream_limit], off)?;
                off = off_after_stream;
                wrote_ack_eliciting |= stream_ack_eliciting;
                stream_transmission_id = emitted_transmission_id;
                // FEC feed removed (handled by core)
                let (off_after_dgram, dgram_ack_eliciting) =
                    self.maybe_flush_one_datagram_frame(out, off)?;
                off = off_after_dgram;
                wrote_ack_eliciting |= dgram_ack_eliciting;
            }
        }
        // DPLPMTUD probe (TODO-451): when the PMTU state machine requests a
        // probe and the current packet has no ack-eliciting payload (otherwise
        // the real data already serves as a probe), inject a PING frame and pad
        // the packet up to the probe target size. The probe is ack-eliciting so
        // the peer's ACK confirms the larger MTU. We only probe when the buffer
        // can hold the probe size (the caller's buffer is typically ≥ PMTU_MAX).
        let mut _pmtu_probe_sent = false;
        if dedicated_pmtu_probe
            && !wrote_ack_eliciting
            && outer_mtu_cap >= self.pmtu.probe_target().unwrap_or(0)
        {
            if let Some(probe_size) = self.pmtu.probe_size() {
                // PING frame (ack-eliciting) so the peer ACKs the probe.
                use crate::transport::Frame;
                let ping = Frame::Ping { mtu_probe: None };
                off += crate::transport::frames::to_bytes(&ping, &mut out[off..])?;
                wrote_ack_eliciting = true;
                // Pad the remainder of the probe region with PADDING frames.
                let tag_reserve = self.tag_reserve_1rtt();
                let transport_probe_size = probe_size.saturating_sub(datagram_overhead);
                let avail = out.len().saturating_sub(off + tag_reserve);
                let needed = transport_probe_size.saturating_sub(off + tag_reserve);
                let pad_len = needed.min(avail);
                if pad_len > 0 {
                    off += crate::transport::frames::write_padding(pad_len, &mut out[off..])?;
                }
                self.pmtu.on_probe_sent(probe_size, now);
                _pmtu_probe_sent = true;
                self.pmtu_probe_pn = Some(pn);
            }
        }
        // Chaff injection (TODO-455): when the chaff generator signals that a
        // dummy packet is due and no ack-eliciting payload was written (real
        // traffic already covers the slot), inject a PING + PADDING chaff
        // packet sized to `chaff_size_bytes`. The chaff is a real 1-RTT packet
        // - encrypted with the same keys, same header format - indistinguishable
        // from a real data packet to an outside observer.
        if !wrote_ack_eliciting {
            // Extract values before mutable borrow of self.chaff.
            let tag_reserve = self.tag_reserve_1rtt();
            let chaff_size = self.chaff.as_ref().map(|c| c.chaff_size_bytes()).unwrap_or(0);
            if let Some(ref mut chaff) = self.chaff {
                if chaff.should_chaff(now, false) {
                    use crate::transport::Frame;
                    let ping = Frame::Ping { mtu_probe: None };
                    off += crate::transport::frames::to_bytes(&ping, &mut out[off..])?;
                    wrote_ack_eliciting = true;
                    let avail = out.len().saturating_sub(off + tag_reserve);
                    let needed = (chaff_size as usize).saturating_sub(off + tag_reserve);
                    let pad_len = needed.min(avail);
                    if pad_len > 0 {
                        off += crate::transport::frames::write_padding(pad_len, &mut out[off..])?;
                    }
                }
            }
        } else if let Some(ref mut chaff) = self.chaff {
            // Real ack-eliciting traffic was sent - reset the chaff clock so the
            // next chaff is deferred for one interval.
            chaff.record_real_traffic(now);
        }
        if off == pn_off + pn_len {
            log::debug!("send_with_datagram_overhead: off==pn_off+pn_len, returning Done; dgram_queue_len={} pending_control={} application_ack={} writable_streams={} probe_spaces={}",
                self.dgram_send_queue.len(), self.pending_control.len(), self.has_pending_application_ack(), self.writable_streams.len(), self.pending_probe_spaces.len());
            return Err(ConnectionError::Done);
        }
        off = self.maybe_apply_stealth_padding(out, pn_off, pn_len, off)?;
        off = self.seal_short_header_packet(out, pn, pn_off, pn_len, off)?;

        // Mark bytes-in-flight timing start if we actually wrote payload beyond header
        if off > (pn_off + pn_len) && self.bytes_in_flight_started.is_none() {
            self.bytes_in_flight_started = Some(Instant::now());
        }
        // Maintain minimal paths_count
        self.refresh_path_count();

        // Legacy transport-level FEC removed

        // Stealth-friendly: do not force 1200-byte minimum for short-header packets
        let total = off;
        let info = SendInfo {
            from: self.local_addr,
            to: self.peer_addr,
            at: Instant::now(),
            congestion_controlled: wrote_ack_eliciting,
        };
        self.stats.sent += 1;
        self.stats.sent_bytes += total as u64;
        if !self.is_established && self.stats.recv > 0 && self.stats.sent > 0 {
            self.is_established = true;
        }
        // Per RFC 9002 §7.2, only packets containing ack-eliciting frames are
        // congestion-controlled. Packets carrying only ACK/PADDING/CONNECTION_CLOSE
        // are not congestion-controlled and must not inflate bytes_in_flight.
        // They are also not tracked in sent_packets_by_pn because the peer will
        // never ACK them - tracking them would leak bytes_in_flight permanently.
        //
        // `wrote_ack_eliciting` is set whenever any ack-eliciting frame (STREAM,
        // DATAGRAM, CRYPTO, PING, MAX_DATA, NEW_CONNECTION_ID, RESET_STREAM,
        // STOP_SENDING, PATH_CHALLENGE, PATH_RESPONSE, HANDSHAKE_DONE, etc.) was
        // emitted. This is the correct RFC 9002 §7.2 condition - the previous
        // heuristic ("no stream/dgram payload") misclassified PING-only keepalive
        // probes and flow-control updates as non-congestion-controlled, breaking
        // PTO-based loss detection for those packets.
        let is_ack_only = !wrote_ack_eliciting;
        if !is_ack_only {
            let now = Instant::now();
            if _pmtu_probe_sent && pmtu_probe_bypassed_congestion {
                self.recovery.on_pmtu_probe_sent_in_space(
                    recovery::PacketSpace::Application,
                    pn,
                    total,
                    now,
                );
            } else {
                self.recovery.on_packet_sent_in_space(
                    recovery::PacketSpace::Application,
                    pn,
                    total,
                    true,
                    true,
                    None,
                    now,
                );
            }
            if let Some(transmission_id) = stream_transmission_id {
                self.commit_stream_transmission(transmission_id, pn);
            }
            let outer_datagram_size = total.saturating_add(datagram_overhead);
            self.pmtu.on_packet_sent(outer_datagram_size, now);
            if outer_datagram_size > self.pmtu.min_mtu {
                self.pmtu_above_floor_pns.insert(pn);
            }
            self.cwnd = self.recovery.cwnd;
        }
        Ok((total, info))
    }

    /// Compute stealth padding length given current plaintext payload length and budget.
    ///
    /// Dispatches on the configured [`TrafficAnalysisDefense`] mode (TODO-455):
    /// - `Off`: existing probabilistic padding (gated by `stealth_padding_rate`).
    /// - `FullPadding`: always pad to the full available budget (no rate gating,
    ///   no random roll). The precise total-packet-size targeting to
    ///   `max_udp_payload_size` is performed in `maybe_apply_stealth_padding`,
    ///   which calls this after computing the budget; here we return `budget`
    ///   so every packet is maximally padded regardless of `stealth_padding_rate`.
    /// - `ConstantRate`: same maximal-padding behavior as `FullPadding` at this
    ///   layer; the consistent target size and chaff injection are orchestrated
    ///   by `maybe_apply_stealth_padding` and the `ChaffGenerator`.
    #[inline(always)]
    pub(crate) fn compute_stealth_padding(&self, cur_pt_len: usize, budget: usize) -> usize {
        // Traffic analysis defense modes take precedence over the legacy
        // probabilistic path. They never skip padding based on rate.
        match self.config.traffic_analysis_defense {
            TrafficAnalysisDefense::FullPadding | TrafficAnalysisDefense::ConstantRate => {
                return budget;
            }
            TrafficAnalysisDefense::Off => {}
        }

        if !self.config.stealth_padding_enabled {
            return 0;
        }
        // Gradual padding rate: only pad a fraction of packets based on the
        // configured rate (0-100%). At 100%, every packet is padded; at 50%,
        // only half of packets receive padding. This implements the gradual
        // stealth escalation from TODO-416.
        let padding_rate = self.config.stealth_padding_rate;
        if padding_rate == 0 {
            return 0;
        }
        if padding_rate < 100 {
            let roll = crate::transport::rand::fast_rand_u64_uniform(100) as u8;
            if roll >= padding_rate {
                return 0;
            }
        }
        let strategy = self.config.stealth_padding_strategy;
        if strategy == 3 && self.config.stealth_adaptive_granularity == 64 {
            let rem = cur_pt_len & 63;
            if rem == 0 {
                return 0;
            }
            let max = self.config.stealth_padding_max_size.min(budget);
            return (64 - rem).min(max);
        }
        let max = self.config.stealth_padding_max_size.min(budget);
        if max == 0 {
            return 0;
        }
        match strategy {
            // 1 = Random [0..=max]
            1 => crate::transport::rand::fast_rand_u64_uniform((max as u64).saturating_add(1))
                as usize,
            // 2 = Fixed (always pad up to max budget)
            2 => max,
            // 3 = Adaptive (pad up to next 64B boundary, capped by max)
            3 => {
                let g = self.config.stealth_adaptive_granularity.max(1) as usize;
                let rem = if g.is_power_of_two() { cur_pt_len & (g - 1) } else { cur_pt_len % g };
                if rem == 0 {
                    0
                } else {
                    let pad = g - rem;
                    if pad < max {
                        pad
                    } else {
                        max
                    }
                }
            }
            // 4 = BrowserMimic: bias profile to small values; bucket depends on bias
            4 => {
                let (bucket_div, samples) = match self.config.stealth_mimic_bias {
                    1 => (8usize, 3), // very small (Safari/iOS)
                    2 => (6usize, 2), // small (Firefox/Linux)
                    4 => (5usize, 2), // mobile (Android)
                    _ => (4usize, 2), // default (Chromium/Windows)
                };
                let bucket = (max / bucket_div).max(1) as u64;
                let mut val = crate::transport::rand::fast_rand_u64_uniform(bucket + 1);
                for _ in 1..samples {
                    let r = crate::transport::rand::fast_rand_u64_uniform(bucket + 1);
                    if r < val {
                        val = r;
                    }
                }
                std::cmp::min(val as usize, max)
            }
            _ => 0,
        }
    }

    fn try_advance_read_keys(&mut self) -> bool {
        let provider_updated = self
            .tls_provider
            .as_mut()
            .map(|provider| provider.key_update_read().is_ok())
            .unwrap_or(false);
        if provider_updated {
            // The rustls provider rotated the read key inside CryptoContext.
            // Sync the lock-free ArcSwap so the hot path picks up the new key.
            self.sync_1rtt();
            return true;
        }
        let updated = self.crypto.write().key_update_1rtt_read();
        if updated {
            self.sync_1rtt();
        }
        updated
    }

    /// Performs a local 1-RTT write key update and toggles the short-header key phase bit.
    pub fn key_update(&mut self) {
        let mut updated = self
            .tls_provider
            .as_mut()
            .map(|provider| provider.key_update_write().is_ok())
            .unwrap_or(false);
        if !updated {
            updated = self.crypto.write().key_update_1rtt_write();
        }
        if updated {
            self.key_phase = !self.key_phase;
            self.refresh_short_header_tag_reserve();
        }
    }

    /// Receives data from a stream
    #[inline(always)]
    pub fn stream_recv(
        &mut self,
        stream_id: u64,
        buf: &mut [u8],
    ) -> Result<(usize, bool), crate::error::ConnectionError> {
        // Receive stream data
        let stream = self
            .streams
            .get_mut(&stream_id)
            .ok_or(crate::error::ConnectionError::InvalidStreamState(stream_id))?;

        let len: usize;
        #[cfg(not(feature = "stream_ring_buffer"))]
        {
            let l = std::cmp::min(buf.len(), stream.recv_buf.len());
            buf[..l].copy_from_slice(&stream.recv_buf[..l]);
            stream.recv_buf.drain(..l);
            len = l;
        }
        #[cfg(feature = "stream_ring_buffer")]
        {
            len = stream.recv_ring.read(buf);
        }

        #[cfg(not(feature = "stream_ring_buffer"))]
        let fin = stream.recv_fin && stream.recv_buf.is_empty();
        #[cfg(feature = "stream_ring_buffer")]
        let fin = stream.recv_fin && stream.recv_ring.is_empty();
        Ok((len, fin))
    }

    /// Sends data on a stream
    #[inline(always)]
    pub fn stream_send(
        &mut self,
        stream_id: u64,
        buf: &[u8],
        fin: bool,
    ) -> Result<usize, crate::error::ConnectionError> {
        // Send stream data
        // Compute connection-level pending bytes before borrowing a specific stream mutably
        let pending_conn_after = (self.conn_bytes_sent)
            .saturating_add(self.total_send_buffered_bytes() as u64)
            .saturating_add(buf.len() as u64);
        if pending_conn_after > self.peer_max_data {
            // Inform peer we are blocked by connection window
            self.pending_control.push_back(Frame::DataBlocked { limit: self.peer_max_data });
            return Err(crate::error::ConnectionError::FlowControl);
        }

        let stream = self.streams.entry(stream_id).or_insert_with(|| Stream {
            id: stream_id,
            #[cfg(not(feature = "stream_ring_buffer"))]
            send_buf: Vec::new(),
            #[cfg(not(feature = "stream_ring_buffer"))]
            recv_buf: Vec::new(),
            #[cfg(feature = "stream_ring_buffer")]
            send_ring: StreamRingBuffer::new(),
            #[cfg(feature = "stream_ring_buffer")]
            recv_ring: StreamRingBuffer::new(),
            send_fin: false,
            recv_fin: false,
            send_off: 0,
            recv_off: 0,
            recv_next: 0,
            recv_final_size: None,
            recv_frags: std::collections::BTreeMap::new(),
            priority_urgency: 3,
            #[cfg(any(test, feature = "rust-tests"))]
            priority_incremental: false,
            max_stream_data_rx: self.config.initial_max_stream_data_bidi_local,
            max_stream_data_tx: self.config.initial_max_stream_data_bidi_remote,
        });

        // Sender-side flow control checks (per-stream)
        let pending_stream_after = {
            #[cfg(not(feature = "stream_ring_buffer"))]
            {
                stream
                    .send_off
                    .saturating_add(stream.send_buf.len() as u64)
                    .saturating_add(buf.len() as u64)
            }
            #[cfg(feature = "stream_ring_buffer")]
            {
                stream
                    .send_off
                    .saturating_add(stream.send_ring.len() as u64)
                    .saturating_add(buf.len() as u64)
            }
        };
        if pending_stream_after > stream.max_stream_data_tx {
            self.pending_control.push_back(Frame::StreamDataBlocked {
                stream_id,
                limit: stream.max_stream_data_tx,
            });
            return Err(crate::error::ConnectionError::FlowControl);
        }

        if stream.send_fin {
            return Err(crate::error::ConnectionError::FinalSize);
        }
        // Append payload and mark FIN if requested
        #[cfg(not(feature = "stream_ring_buffer"))]
        stream.send_buf.extend_from_slice(buf);
        #[cfg(feature = "stream_ring_buffer")]
        {
            let written = stream.send_ring.write(buf);
            if written < buf.len() {
                return Err(crate::error::ConnectionError::InvalidState);
            }
        }
        stream.send_fin = fin;
        if !self.writable_streams.contains(&stream_id) {
            let urgency = self.streams.get(&stream_id).map(|s| s.priority_urgency).unwrap_or(3);
            let mut insert_at = None;
            for (idx, id) in self.writable_streams.iter().enumerate() {
                if let Some(s) = self.streams.get(id) {
                    if urgency < s.priority_urgency {
                        insert_at = Some(idx);
                        break;
                    }
                }
            }
            if let Some(idx) = insert_at {
                self.writable_streams.insert(idx, stream_id);
            } else {
                self.writable_streams.push_back(stream_id);
            }
        }

        Ok(buf.len())
    }

    /// Dequeues one received DATAGRAM frame into the caller's buffer.
    #[inline(always)]
    pub fn dgram_recv(&mut self, buf: &mut [u8]) -> Result<usize, crate::error::ConnectionError> {
        if self.dgram_recv_queue.is_empty() {
            return Err(crate::error::ConnectionError::Done);
        }
        #[cfg(not(feature = "zero_copy_dgram"))]
        {
            let dgram =
                self.dgram_recv_queue.pop_front().ok_or(crate::error::ConnectionError::Done)?;
            let len = std::cmp::min(buf.len(), dgram.len());
            buf[..len].copy_from_slice(&dgram[..len]);
            self.stats.dgram_recv += 1;
            Ok(len)
        }
        #[cfg(feature = "zero_copy_dgram")]
        {
            let dgram =
                self.dgram_recv_queue.pop_front().ok_or(crate::error::ConnectionError::Done)?;
            let len = std::cmp::min(buf.len(), dgram.len);
            buf[..len].copy_from_slice(&dgram.data[..len]);
            self.stats.dgram_recv += 1;
            Ok(len)
        }
    }

    /// Enqueues a DATAGRAM frame for transmission on the next send call.
    #[inline(always)]
    pub fn dgram_send(&mut self, buf: &[u8]) -> Result<(), crate::error::ConnectionError> {
        if buf.len() > self.dgram_send_max_size {
            return Err(crate::error::ConnectionError::InvalidState);
        }
        if self.is_dgram_send_queue_full() {
            return Err(crate::error::ConnectionError::DgramQueueFull);
        }
        #[cfg(not(feature = "zero_copy_dgram"))]
        {
            self.dgram_send_queue.push_back(buf.to_vec());
        }
        #[cfg(feature = "zero_copy_dgram")]
        {
            let mut data = self.dgram_pool.alloc();
            let len = buf.len().min(data.len());
            data[..len].copy_from_slice(&buf[..len]);
            self.dgram_send_queue.push_back(DatagramBuffer {
                data,
                len,
                _pool: self.dgram_pool.clone(),
            });
        }
        self.stats.dgram_sent += 1;
        Ok(())
    }

    /// Dequeues one received DATAGRAM as an owned `Vec<u8>` (test helper).
    #[cfg(any(test, feature = "rust-tests"))]
    pub fn dgram_recv_vec(&mut self) -> Result<Vec<u8>, crate::error::ConnectionError> {
        if self.dgram_recv_queue.is_empty() {
            return Err(crate::error::ConnectionError::Done);
        }
        #[cfg(not(feature = "zero_copy_dgram"))]
        {
            self.stats.dgram_recv += 1;
            if let Some(v) = self.dgram_recv_queue.pop_front() {
                Ok(v)
            } else {
                Err(crate::error::ConnectionError::Done)
            }
        }
        #[cfg(feature = "zero_copy_dgram")]
        {
            let Some(dgram) = self.dgram_recv_queue.pop_front() else {
                return Err(crate::error::ConnectionError::Done);
            };
            let mut vec = vec![0u8; dgram.len];
            vec.copy_from_slice(&dgram.data[..dgram.len]);
            self.stats.dgram_recv += 1;
            Ok(vec)
        }
    }

    /// Peeks at the front received DATAGRAM without consuming it.
    #[cfg(any(test, feature = "rust-tests"))]
    pub fn dgram_recv_peek(
        &self,
        buf: &mut [u8],
        len: usize,
    ) -> Result<usize, crate::error::ConnectionError> {
        if self.dgram_recv_queue.is_empty() {
            return Err(crate::error::ConnectionError::Done);
        }
        #[cfg(not(feature = "zero_copy_dgram"))]
        {
            let front = &self.dgram_recv_queue[0];
            let n = std::cmp::min(len, std::cmp::min(buf.len(), front.len()));
            buf[..n].copy_from_slice(&front[..n]);
            Ok(n)
        }
        #[cfg(feature = "zero_copy_dgram")]
        {
            let front = &self.dgram_recv_queue[0];
            let n = std::cmp::min(len, std::cmp::min(buf.len(), front.len));
            buf[..n].copy_from_slice(&front.data[..n]);
            Ok(n)
        }
    }

    /// Returns the byte length of the front received DATAGRAM, if any.
    #[cfg(any(test, feature = "rust-tests"))]
    pub fn dgram_recv_front_len(&self) -> Option<usize> {
        #[cfg(not(feature = "zero_copy_dgram"))]
        return self.dgram_recv_queue.front().map(|v| v.len());
        #[cfg(feature = "zero_copy_dgram")]
        return self.dgram_recv_queue.front().map(|v| v.len);
    }

    /// Number of DATAGRAMs currently in the receive queue.
    #[cfg(any(test, feature = "rust-tests"))]
    pub fn dgram_recv_queue_len(&self) -> usize {
        self.dgram_recv_queue.len()
    }
    /// Total bytes across all DATAGRAMs in the receive queue.
    #[cfg(any(test, feature = "rust-tests"))]
    pub fn dgram_recv_queue_byte_size(&self) -> usize {
        #[cfg(not(feature = "zero_copy_dgram"))]
        return self.dgram_recv_queue.iter().map(|v| v.len()).sum();
        #[cfg(feature = "zero_copy_dgram")]
        return self.dgram_recv_queue.iter().map(|v| v.len).sum();
    }
    /// Number of DATAGRAMs currently in the send queue.
    pub fn dgram_send_queue_len(&self) -> usize {
        self.dgram_send_queue.len()
    }
    /// Total bytes across all DATAGRAMs in the send queue.
    #[cfg(any(test, feature = "rust-tests"))]
    pub fn dgram_send_queue_byte_size(&self) -> usize {
        #[cfg(not(feature = "zero_copy_dgram"))]
        return self.dgram_send_queue.iter().map(|v| v.len()).sum();
        #[cfg(feature = "zero_copy_dgram")]
        return self.dgram_send_queue.iter().map(|v| v.len).sum();
    }
    fn is_dgram_send_queue_full(&self) -> bool {
        let lim = self.config.dgram_send_max_queue_len;
        lim > 0 && self.dgram_send_queue.len() >= lim
    }
    fn is_dgram_recv_queue_full(&self) -> bool {
        let lim = self.config.dgram_recv_max_queue_len;
        lim > 0 && self.dgram_recv_queue.len() >= lim
    }
    /// Enqueues an owned `Vec<u8>` as a DATAGRAM for transmission (test helper).
    #[cfg(any(test, feature = "rust-tests"))]
    pub fn dgram_send_vec(&mut self, buf: Vec<u8>) -> Result<(), crate::error::ConnectionError> {
        if buf.len() > self.dgram_send_max_size {
            return Err(crate::error::ConnectionError::InvalidState);
        }
        // Delegate to dgram_send so zero_copy path is handled uniformly
        self.dgram_send(&buf[..])
    }
    /// Removes outgoing DATAGRAMs matching the predicate.
    #[cfg(any(test, feature = "rust-tests"))]
    pub fn dgram_purge_outgoing<FN: Fn(&[u8]) -> bool>(&mut self, f: FN) {
        #[cfg(not(feature = "zero_copy_dgram"))]
        {
            self.dgram_send_queue.retain(|d| !f(d));
        }
        #[cfg(feature = "zero_copy_dgram")]
        {
            self.dgram_send_queue.retain(|d| !f(&d.data[..d.len]));
        }
    }
    /// Returns the maximum DATAGRAM payload size, or `None` if the send queue is full.
    #[cfg(any(test, feature = "rust-tests"))]
    pub fn dgram_max_writable_len(&self) -> Option<usize> {
        if self.is_dgram_send_queue_full() {
            None
        } else {
            Some(self.dgram_send_max_size)
        }
    }

    /// Returns true if the connection is established
    pub fn is_established(&self) -> bool {
        self.is_established
            && !self.is_closed
            && self
                .tls_provider
                .as_ref()
                .map(|provider| provider.handshake_complete())
                .unwrap_or(true)
    }

    /// Returns true only when an outer data-plane envelope cannot capture a
    /// pending Initial or Handshake packet.
    pub fn post_handshake_datagram_ready(&mut self) -> Result<bool, crate::error::ConnectionError> {
        self.poll_tls_and_validate_versions()?;
        if !self.is_established() {
            return Ok(false);
        }
        // PTO probes for Initial/Handshake are flushed before 1-RTT data; a
        // non-zero outer datagram overhead (FEC) would leave the handshake
        // probe with too little buffer to reach MIN_CLIENT_INITIAL_LEN.
        if self
            .pending_probe_spaces
            .iter()
            .any(|s| *s == recovery::PacketSpace::Initial || *s == recovery::PacketSpace::Handshake)
        {
            return Ok(false);
        }
        Ok(!self.crypto.read().has_pending_handshake_send())
    }

    /// Returns true if the connection is closed
    pub fn is_closed(&self) -> bool {
        self.is_closed
    }
    /// Returns true if the connection has any readable streams
    #[cfg(any(test, feature = "rust-tests"))]
    pub fn is_readable(&self) -> bool {
        !self.readable_streams.is_empty()
    }
    /// Returns whether this is a server-side connection
    pub fn is_server(&self) -> bool {
        self.is_server
    }

    /// Returns a mutable reference to the BBR3 recovery/congestion controller.
    pub fn recovery_mut(&mut self) -> &mut recovery::Recovery {
        &mut self.recovery
    }

    /// Loss-rate threshold above which FEC escalation is triggered.
    pub fn fec_escalation_threshold(&self) -> f32 {
        self.fec_escalation_threshold
    }
    /// Returns true if the connection is draining
    #[cfg(any(test, feature = "rust-tests"))]
    pub fn is_draining(&self) -> bool {
        self.is_draining
    }
    /// Returns true if the connection has timed out
    #[cfg(any(test, feature = "rust-tests"))]
    pub fn is_timed_out(&self) -> bool {
        self.timeout_count > 0
    }
    /// Returns true when a session ticket is present in config or provider state.
    #[cfg(any(test, feature = "rust-tests"))]
    pub fn is_resumed(&self) -> bool {
        let cfg_ticket = self.config.tls_session.as_ref().map(|t| !t.is_empty()).unwrap_or(false);
        let provider_ticket = self
            .tls_provider
            .as_ref()
            .and_then(|p| p.session_ticket())
            .map(|t| !t.is_empty())
            .unwrap_or(false);
        cfg_ticket || provider_ticket
    }
    /// Returns true while 0-RTT is allowed and handshake has not fully established.
    #[cfg(any(test, feature = "rust-tests"))]
    pub fn is_in_early_data(&self) -> bool {
        self.config.enable_early_data && !self.is_established && !self.is_closed
    }

    /// Returns connection statistics
    pub fn stats(&self) -> &Stats {
        &self.stats
    }

    /// Smoothed packet-loss signal owned by the active congestion controller.
    pub(crate) fn recovery_loss_rate(&self) -> f32 {
        self.recovery.get_loss_rate()
    }

    /// Lightweight telemetry: ECN counters since last ACK emission
    #[cfg(any(test, feature = "rust-tests"))]
    pub fn ecn_counts(&self) -> (u64, u64, u64) {
        (self.ecn_ect0, self.ecn_ect1, self.ecn_ce)
    }

    /// Current send quantum (bytes) derived from recovery
    pub fn send_quantum(&self) -> usize {
        self.recovery.send_quantum()
    }

    /// Active production pacing rate in bytes per second.
    ///
    /// A configured maximum caps the congestion controller estimate. Before
    /// the controller has a delivery sample, the configured value is used as
    /// the startup rate when present.
    pub(crate) fn pacing_rate(&self) -> Option<u64> {
        if !self.config.pacing {
            return None;
        }
        match (self.recovery.get_pacing_rate(), self.config.max_pacing_rate) {
            (Some(rate), Some(cap)) => Some(rate.min(cap)).filter(|rate| *rate > 0),
            (Some(rate), None) | (None, Some(rate)) => Some(rate).filter(|rate| *rate > 0),
            (None, None) => None,
        }
    }
    /// True if we can send at least one datagram of size `sz` within cwnd
    #[cfg(any(test, feature = "rust-tests"))]
    pub fn can_send(&self, sz: usize) -> bool {
        self.bytes_in_flight.saturating_add(sz) <= self.cwnd
    }

    /// Current RTT estimate
    pub fn rtt(&self) -> Duration {
        self.rtt
    }

    /// Confirmed packetization-layer MTU for the active path.
    pub fn effective_path_mtu(&self) -> usize {
        self.pmtu.effective_mtu().min(self.dgram_send_max_size)
    }

    /// Configured upper bound for one outgoing UDP payload.
    pub fn max_send_udp_payload_size(&self) -> usize {
        self.dgram_send_max_size
    }

    /// Bytes currently considered in flight
    pub fn bytes_in_flight(&self) -> usize {
        self.bytes_in_flight
    }

    /// Current congestion window in bytes.
    pub fn cwnd(&self) -> usize {
        self.cwnd
    }

    /// Estimated delivery rate (bytes/s)
    pub fn delivery_rate(&self) -> u64 {
        self.stats.delivery_rate
    }

    /// ACK-eliciting threshold (packets) before emitting ACK
    #[cfg(any(test, feature = "rust-tests"))]
    pub fn ack_eliciting_threshold(&self) -> u64 {
        self.config.ack_eliciting_threshold
    }

    /// Whether the transport-level stealth jitter gate is active (core-owned scheduling).
    pub(crate) fn transport_stealth_timing_active(&self) -> bool {
        self.config.stealth_timing_enabled && !self.config.external_pacing
    }

    /// Configured transport stealth jitter ceiling in microseconds.
    pub(crate) fn transport_stealth_timing_max_jitter_us(&self) -> u32 {
        self.config.stealth_timing_max_jitter_us
    }

    /// Samples a transport stealth jitter delay when the gate is active.
    pub(crate) fn transport_stealth_jitter_delay(&self) -> Option<Duration> {
        if !self.transport_stealth_timing_active() {
            return None;
        }
        let max_jitter_us = self.transport_stealth_timing_max_jitter_us();
        if max_jitter_us == 0 {
            return None;
        }
        // Gradual timing rate: scale jitter magnitude by the configured rate
        // (0-100%). At 100%, full jitter is applied; at 50%, jitter is halved.
        // This implements the gradual stealth escalation from TODO-416.
        let timing_rate = self.config.stealth_timing_rate;
        let scaled_max = if timing_rate >= 100 {
            max_jitter_us
        } else {
            ((max_jitter_us * timing_rate as u32) / 100).max(1)
        };
        let jitter_us = crate::transport::rand::fast_rand_u64_uniform(scaled_max as u64 + 1);
        Some(Duration::from_micros(jitter_us))
    }

    /// Whether external pacing is enabled (internal sleeps disabled)
    #[cfg(any(test, feature = "rust-tests"))]
    pub fn external_pacing_enabled(&self) -> bool {
        self.config.external_pacing
    }

    /// Whether stealth timing obfuscation is enabled (test accessor).
    #[cfg(any(test, feature = "rust-tests"))]
    pub fn stealth_timing_enabled_for_test(&self) -> bool {
        self.config.stealth_timing_enabled
    }

    /// Configured maximum jitter in microseconds (test accessor).
    #[cfg(any(test, feature = "rust-tests"))]
    pub fn stealth_timing_max_jitter_us_for_test(&self) -> u32 {
        self.config.stealth_timing_max_jitter_us
    }

    /// Whether stealth padding is enabled (test accessor).
    #[cfg(any(test, feature = "rust-tests"))]
    pub fn stealth_padding_enabled_for_test(&self) -> bool {
        self.config.stealth_padding_enabled
    }

    /// Active stealth padding strategy ID (test accessor).
    #[cfg(any(test, feature = "rust-tests"))]
    pub fn stealth_padding_strategy_for_test(&self) -> u8 {
        self.config.stealth_padding_strategy
    }

    /// Whether the Brain sensor-fusion engine may steer this connection (test accessor).
    #[cfg(any(test, feature = "rust-tests"))]
    pub fn intelligent_stealth_runtime_enabled_for_test(&self) -> bool {
        self.intelligent_stealth_runtime
    }

    /// Current Brain runtime permission set (test accessor).
    #[cfg(any(test, feature = "rust-tests"))]
    pub fn brain_runtime_permissions_for_test(&self) -> crate::transport::BrainRuntimePermissions {
        self.brain_runtime_permissions
    }

    /// Set or clear the transport observer (integration hook)
    pub fn set_observer(&mut self, obs: Option<Arc<dyn TransportObserver>>) {
        self.observer = obs;
    }

    pub(crate) fn intelligent_stealth_runtime_enabled(&self) -> bool {
        self.intelligent_stealth_runtime
    }

    pub(crate) fn set_intelligent_stealth_runtime(&mut self, enabled: bool) {
        self.intelligent_stealth_runtime = enabled;
    }

    /// Enables or disables Brain-driven stealth runtime for this connection (test helper).
    #[cfg(any(test, feature = "rust-tests"))]
    pub fn set_intelligent_stealth_runtime_for_test(&mut self, enabled: bool) {
        self.set_intelligent_stealth_runtime(enabled);
    }

    pub(crate) fn brain_runtime_permissions(&self) -> crate::transport::BrainRuntimePermissions {
        self.brain_runtime_permissions
    }

    pub(crate) fn set_brain_runtime_permissions(
        &mut self,
        permissions: crate::transport::BrainRuntimePermissions,
    ) {
        self.brain_runtime_permissions = permissions;
    }

    /// Overrides Brain runtime permissions for this connection (test helper).
    #[cfg(any(test, feature = "rust-tests"))]
    pub fn set_brain_runtime_permissions_for_test(
        &mut self,
        permissions: crate::transport::BrainRuntimePermissions,
    ) {
        self.set_brain_runtime_permissions(permissions);
    }

    fn install_recovery_fec_callbacks(&mut self) {
        let sent_pkts = Arc::clone(&self.fec_cb_sent_packets);
        let lost_pkts = Arc::clone(&self.fec_cb_lost_packets);
        let sent_bytes = Arc::clone(&self.fec_cb_sent_bytes);
        let lost_bytes = Arc::clone(&self.fec_cb_lost_bytes);
        self.recovery.set_fec_callbacks(
            move |_pn, bytes| {
                sent_pkts.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                sent_bytes.fetch_add(bytes as u64, std::sync::atomic::Ordering::Relaxed);
            },
            move |_pn, bytes| {
                lost_pkts.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                lost_bytes.fetch_add(bytes as u64, std::sync::atomic::Ordering::Relaxed);
            },
        );
    }
    /// Adjust ACK-eliciting threshold at runtime
    pub fn set_ack_eliciting_threshold(&mut self, thr: u64) {
        self.config.ack_eliciting_threshold = thr.max(1);
    }
    /// Toggle external pacing controller at runtime
    pub(crate) fn set_external_pacing(&mut self, v: bool) {
        self.config.external_pacing = v;
    }
    /// Toggles external pacing for this connection (test helper).
    #[cfg(any(test, feature = "rust-tests"))]
    pub fn set_external_pacing_for_test(&mut self, v: bool) {
        self.set_external_pacing(v);
    }
    /// Adjust streaming FEC emission interval (AdaptiveFec only)
    pub fn set_fec_stream_every(&mut self, every: usize) {
        self.fec_ctrl_delta.stream_every = Some(every.clamp(1, 32));
    }
    /// Enable/disable stealth timing and set max jitter
    pub(crate) fn set_stealth_timing(&mut self, enabled: bool, max_jitter_us: u32) {
        self.config.stealth_timing_enabled = enabled;
        self.config.stealth_timing_max_jitter_us = max_jitter_us;
    }
    /// Set adaptive padding granularity (>=1)
    pub(crate) fn set_stealth_adaptive_granularity(&mut self, gran: u16) {
        self.config.stealth_adaptive_granularity = if gran == 0 { 1 } else { gran };
    }
    /// Set browser mimic bias (1..=4)
    pub(crate) fn set_stealth_mimic_bias(&mut self, bias: u8) {
        self.config.stealth_mimic_bias = match bias {
            1..=4 => bias,
            _ => 3,
        };
    }
    /// Adjust stealth padding parameters at runtime
    pub(crate) fn set_stealth_padding(&mut self, enabled: bool, strategy: u8, max_size: usize) {
        self.config.stealth_padding_enabled = enabled;
        self.config.stealth_padding_strategy = strategy;
        self.config.stealth_padding_max_size = max_size;
    }
    /// Set padding application rate (0-100%): fraction of packets that receive padding.
    pub(crate) fn set_stealth_padding_rate(&mut self, rate: u8) {
        self.config.stealth_padding_rate = rate.min(100);
    }
    /// Set timing obfuscation rate (0-100%): scales jitter magnitude.
    pub(crate) fn set_stealth_timing_rate(&mut self, rate: u8) {
        self.config.stealth_timing_rate = rate.min(100);
    }
    pub(crate) fn apply_brain_stealth_runtime_delta(
        &mut self,
        delta: crate::transport::StealthRuntimeDelta,
    ) {
        if let Some(pacing) = delta.external_pacing {
            self.set_external_pacing(pacing);
        }
        if let Some((enabled, max_jitter_us)) = delta.timing {
            self.set_stealth_timing(enabled, max_jitter_us);
        }
        if let Some(bias) = delta.mimic_bias {
            self.set_stealth_mimic_bias(bias);
        }
        if let Some(granularity) = delta.adaptive_granularity {
            self.set_stealth_adaptive_granularity(granularity);
        }
        if let Some(profile) = delta.cc_profile {
            self.set_cc_stealth_profile(true, profile);
        }
        if let Some((enabled, strategy, max_size)) = delta.padding {
            self.set_stealth_padding(enabled, strategy, max_size);
        }
        if let Some(rate) = delta.padding_rate {
            self.set_stealth_padding_rate(rate);
        }
        if let Some(rate) = delta.timing_rate {
            self.set_stealth_timing_rate(rate);
        }
    }
    /// Configure CC stealth profile to shape pacing like common browsers
    pub fn set_cc_stealth_profile(
        &mut self,
        enabled: bool,
        profile: crate::transport::recovery::BrowserProfile,
    ) {
        self.recovery.set_stealth_mode(enabled, profile);
    }
    /// Force AdaptiveFec into streaming mode for minimal latency
    pub fn force_fec_streaming(&mut self) {
        self.fec_ctrl_delta.force_streaming = true;
    }
    /// Set redundancy hint in parts-per-million on AdaptiveFec (if present)
    pub fn set_fec_redundancy_ppm(&mut self, ppm: u32) {
        self.fec_ctrl_delta.redundancy_ppm = Some(ppm);
    }

    /// Take and clear pending FEC control delta (to be consumed by core FEC)
    pub fn take_fec_control_delta(&mut self) -> FecControlDelta {
        let d = self.fec_ctrl_delta;
        self.fec_ctrl_delta = FecControlDelta::default();
        d
    }

    /// Take and reset exact transport feedback for live FEC adaptation.
    pub(crate) fn take_fec_callback_feedback(&mut self) -> FecCallbackFeedback {
        let feedback = FecCallbackFeedback {
            sent_packets: self.fec_cb_sent_packets.swap(0, std::sync::atomic::Ordering::Relaxed),
            acked_packets: std::mem::take(&mut self.fec_acked_packets),
            lost_packets: self.fec_cb_lost_packets.swap(0, std::sync::atomic::Ordering::Relaxed),
        };
        self.fec_cb_sent_bytes.swap(0, std::sync::atomic::Ordering::Relaxed);
        self.fec_cb_lost_bytes.swap(0, std::sync::atomic::Ordering::Relaxed);
        feedback
    }

    /// Returns the source connection ID
    pub fn source_id(&self) -> &ConnectionId {
        &self.scid
    }

    /// Returns all source IDs (minimal: only current scid)
    #[cfg(any(test, feature = "rust-tests"))]
    pub fn source_ids(&self) -> impl Iterator<Item = &ConnectionId> {
        std::iter::once(&self.scid)
    }
    /// Peer streams left (bidi)
    #[cfg(any(test, feature = "rust-tests"))]
    pub fn peer_streams_left_bidi(&self) -> u64 {
        self.config.initial_max_streams_bidi
    }
    /// Peer streams left (uni)
    #[cfg(any(test, feature = "rust-tests"))]
    pub fn peer_streams_left_uni(&self) -> u64 {
        self.config.initial_max_streams_uni
    }

    /// Closes the connection
    pub fn close(
        &mut self,
        app: bool,
        err: u64,
        reason: &[u8],
    ) -> Result<(), crate::error::ConnectionError> {
        self.is_closed = true;
        self.is_draining = true;
        self.local_error = Some(crate::error::ConnectionError::ApplicationClosed);
        // Emit Close frame into control queue.
        if app {
            self.pending_control.push_back(Frame::ApplicationClose {
                error_code: err,
                reason: Cow::Owned(reason.to_vec()),
            });
        } else {
            // frame_type=0 (unknown) in minimal implementation
            self.pending_control.push_back(Frame::ConnectionClose {
                error_code: err,
                frame_type: 0,
                reason: Cow::Owned(reason.to_vec()),
            });
        }
        Ok(())
    }

    /// Returns the connection timeout
    pub fn timeout(&self) -> Option<Duration> {
        Some(Duration::from_millis(30000))
    }
    /// Whether the connection has been idle (no inbound packet) for at least the
    /// idle-timeout window. Run loops invoke this each housekeeping tick to decide
    /// whether to drive `on_timeout()`; calling on_timeout() unconditionally every
    /// tick would inflate the loss counter and repeatedly collapse the congestion
    /// window for a perfectly healthy connection.
    pub fn idle_timeout_elapsed(&self) -> bool {
        let window = self.timeout().unwrap_or(Duration::from_secs(30));
        self.last_activity.elapsed() >= window
    }

    /// Returns the duration elapsed since the last inbound packet was received.
    /// Used by the heartbeat watchdog to detect connection loss before the
    /// transport-level idle timeout fires.
    pub fn last_activity_elapsed(&self) -> Duration {
        self.last_activity.elapsed()
    }

    /// Returns the exact inbound-activity marker used by the heartbeat watchdog.
    ///
    /// This permits opt-in runtime diagnostics to distinguish a transport
    /// receive call that returned from one that completed frame processing and
    /// refreshed inbound activity, without changing transport scheduling.
    pub fn last_activity_marker(&self) -> Instant {
        self.last_activity
    }

    /// Returns true if there are pending ACK frames in the application (1-RTT)
    /// packet space that need to be sent. Used to bypass the congestion gate
    /// for ACK-only packets (RFC 9002 §7.2).
    #[inline(always)]
    pub fn has_pending_application_ack(&self) -> bool {
        self.pkt_spaces[2].has_pending_ack()
    }

    /// Handles timeout
    pub fn on_timeout(&mut self) {
        // Handle connection timeout
        self.timeout_count += 1;

        // Retransmit lost packets
        for stream in self.streams.values_mut() {
            let has_pending = {
                #[cfg(not(feature = "stream_ring_buffer"))]
                {
                    !stream.send_buf.is_empty()
                }
                #[cfg(feature = "stream_ring_buffer")]
                {
                    !stream.send_ring.is_empty()
                }
            };
            if has_pending {
                // Mark for retransmission
                self.stats.lost += 1;
            }
        }

        // RTT estimate is NOT inflated on timeout. Per RFC 9000 §5.1, the RTT
        // estimate is only updated from ACK samples (see account_sent_bytes_for_ack_ranges_with_delay).
        // The previous code added 100ms on every timeout, causing monotonic RTT inflation
        // (0→385ms observed on loopback). The PTO backoff is handled by the loss detection
        // timer, not by inflating self.rtt.
        // Treat timeout as loss of in-flight bytes (coarse approximation)
        if self.bytes_in_flight > 0 {
            let lost = self.bytes_in_flight;
            self.recovery.on_loss(lost, Instant::now());
            self.stats.lost = self.stats.lost.saturating_add(1);
            self.stats.lost_bytes = self.stats.lost_bytes.saturating_add(lost as u64);
            self.cwnd = self.recovery.cwnd;
            self.bytes_in_flight = 0;
        }
        // Update bytes in flight duration (mock)
        if let Some(start) = self.bytes_in_flight_started.take() {
            self.stats.bytes_in_flight_duration = self
                .stats
                .bytes_in_flight_duration
                .saturating_add(Instant::now().saturating_duration_since(start));
        }
        // Switch into draining on timeout.
        self.is_draining = true;
    }
    /// Server name (SNI) from TLS provider
    pub fn server_name(&self) -> Option<&str> {
        self.tls_provider.as_ref().and_then(|p| p.server_name_get())
    }

    /// Stream priority
    /// Sets urgency and incremental scheduling hints for a stream.
    #[cfg(any(test, feature = "rust-tests"))]
    pub fn stream_priority(
        &mut self,
        stream_id: u64,
        _urgency: u8,
        _incremental: bool,
    ) -> Result<(), crate::error::ConnectionError> {
        let _stream = self
            .streams
            .get_mut(&stream_id)
            .ok_or(crate::error::ConnectionError::InvalidStreamState(stream_id))?;
        _stream.priority_urgency = _urgency;
        #[cfg(any(test, feature = "rust-tests"))]
        {
            _stream.priority_incremental = _incremental;
        }

        if self.writable_streams.contains(&stream_id) {
            self.writable_streams.retain(|&id| id != stream_id);
            let mut insert_at = None;
            for (idx, id) in self.writable_streams.iter().enumerate() {
                if let Some(s) = self.streams.get(id) {
                    if _urgency < s.priority_urgency {
                        insert_at = Some(idx);
                        break;
                    }
                }
            }
            if let Some(idx) = insert_at {
                self.writable_streams.insert(idx, stream_id);
            } else {
                self.writable_streams.push_back(stream_id);
            }
        }
        Ok(())
    }

    /// Shuts down a stream in the given direction (no-op in minimal impl).
    #[cfg(any(test, feature = "rust-tests"))]
    pub fn stream_shutdown(
        &mut self,
        _stream_id: u64,
        _direction: std::net::Shutdown,
        _err: u64,
    ) -> Result<(), crate::error::ConnectionError> {
        Ok(())
    }

    /// Returns the remaining send capacity for a stream (fixed 64 KB in minimal impl).
    #[cfg(any(test, feature = "rust-tests"))]
    pub fn stream_capacity(&self, _stream_id: u64) -> Result<usize, crate::error::ConnectionError> {
        Ok(65536)
    }

    /// Returns true if the stream has buffered receive data.
    #[cfg(any(test, feature = "rust-tests"))]
    pub fn stream_readable(&self, _stream_id: u64) -> bool {
        self.readable_streams.contains(&_stream_id)
    }

    /// Returns true if the stream has queued send data.
    #[cfg(any(test, feature = "rust-tests"))]
    pub fn stream_writable(&self, _stream_id: u64, _len: usize) -> bool {
        self.writable_streams.contains(&_stream_id)
    }

    /// Returns true if the stream's send buffer is empty and FIN has been set.
    #[cfg(any(test, feature = "rust-tests"))]
    pub fn stream_finished(&self, _stream_id: u64) -> bool {
        if let Some(s) = self.streams.get(&_stream_id) {
            #[cfg(not(feature = "stream_ring_buffer"))]
            {
                s.send_fin && s.send_buf.is_empty()
            }
            #[cfg(feature = "stream_ring_buffer")]
            {
                s.send_fin && s.send_ring.is_empty()
            }
        } else {
            false
        }
    }

    /// Iterates over stream IDs that have readable data.
    #[cfg(any(test, feature = "rust-tests"))]
    pub fn readable(&self) -> impl Iterator<Item = u64> + '_ {
        self.readable_streams.iter().copied()
    }

    /// Iterates over stream IDs that have pending send data.
    #[cfg(any(test, feature = "rust-tests"))]
    pub fn writable(&self) -> impl Iterator<Item = u64> + '_ {
        self.writable_streams.iter().copied()
    }

    /// Pops and returns the next stream ID that has data ready to read.
    pub fn stream_readable_next(&mut self) -> Option<u64> {
        if self.readable_streams.is_empty() {
            None
        } else {
            self.readable_streams.pop_front()
        }
    }

    /// Returns the number of streams with pending writable data.
    pub fn writable_streams_count(&self) -> usize {
        self.writable_streams.len()
    }

    /// Pops the next stream ID with queued send data (test helper).
    #[cfg(any(test, feature = "rust-tests"))]
    pub fn stream_writable_next(&mut self) -> Option<u64> {
        if self.writable_streams.is_empty() {
            None
        } else {
            self.writable_streams.pop_front()
        }
    }

    /// Path migration
    pub fn migrate(
        &mut self,
        local: SocketAddr,
        peer: SocketAddr,
    ) -> Result<u64, crate::error::ConnectionError> {
        self.begin_path_validation(local, peer, PathValidationOrigin::LocalMigration, 0)
    }
    /// Change only the local address (migrate source path)
    #[cfg(any(test, feature = "rust-tests"))]
    pub fn migrate_source(
        &mut self,
        local: SocketAddr,
    ) -> Result<u64, crate::error::ConnectionError> {
        self.begin_path_validation(local, self.peer_addr, PathValidationOrigin::LocalMigration, 0)
    }
    /// Probe a path and emit path lifecycle events for observers/control-plane.
    #[cfg(any(test, feature = "rust-tests"))]
    pub fn probe_path(
        &mut self,
        from: SocketAddr,
        to: SocketAddr,
    ) -> Result<(), crate::error::ConnectionError> {
        if from == to {
            return Err(crate::error::ConnectionError::InvalidState);
        }

        let _ = self.begin_path_validation(from, to, PathValidationOrigin::LocalMigration, 0)?;
        Ok(())
    }

    /// Returns per-path statistics for each validated path.
    pub fn path_stats(&self) -> impl Iterator<Item = PathStats> {
        std::iter::once(PathStats {
            recv: self.stats.recv_bytes,
            sent: self.stats.sent_bytes,
            lost: self.stats.lost as u64,
            rtt: self.rtt,
            cwnd: self.cwnd,
            delivery_rate: self.stats.delivery_rate,
            local_addr: self.local_addr,
            peer_addr: self.peer_addr,
        })
    }
    // Pacing / Congestion / Release hooks
    /// Returns the next pacing-based release time for outbound packets.
    #[cfg(any(test, feature = "rust-tests"))]
    pub fn get_next_release_time(&self) -> Option<Instant> {
        if !self.config.pacing {
            return None;
        }

        let now = Instant::now();
        let rate_bps = self.recovery.get_pacing_rate().or(self.config.max_pacing_rate)?;
        if rate_bps == 0 || self.bytes_in_flight == 0 {
            return Some(now);
        }

        let release_delay_us =
            ((self.bytes_in_flight as u128) * 1_000_000u128 / rate_bps as u128).max(1) as u64;
        Some(now + Duration::from_micros(release_delay_us))
    }
    /// Whether send pacing is enabled.
    #[cfg(any(test, feature = "rust-tests"))]
    pub fn pacing_enabled(&self) -> bool {
        self.config.pacing
    }

    /// Sends a packet targeting a specific peer address (delegates to `send`).
    #[cfg(any(test, feature = "rust-tests"))]
    pub fn send_on_path(
        &mut self,
        out: &mut [u8],
        _to: SocketAddr,
    ) -> Result<(usize, SendInfo), crate::error::ConnectionError> {
        self.send(out)
    }

    /// Returns the next path event, if any
    pub fn path_event_next(&mut self) -> Option<PathEvent> {
        self.poll_path_validation_timeout(Instant::now());
        if self.path_events.is_empty() {
            None
        } else {
            self.path_events.pop_front()
        }
    }
    /// Active SCIDs count (minimal: 1)
    #[cfg(any(test, feature = "rust-tests"))]
    pub fn active_scids(&self) -> usize {
        1
    }
    /// SCIDs left to issue (minimal: 0)
    #[cfg(any(test, feature = "rust-tests"))]
    pub fn scids_left(&self) -> usize {
        0
    }
    /// Retire a DCID by sequence (minimal: record in retired_scids)
    #[cfg(any(test, feature = "rust-tests"))]
    pub fn retire_dcid(&mut self, _dcid_seq: u64) -> Result<(), crate::error::ConnectionError> {
        self.retired_scids.push_back(self.scid);
        Ok(())
    }
    /// Iterate paths (minimal: return peer addr once)
    #[cfg(any(test, feature = "rust-tests"))]
    pub fn paths_iter(&self, _from: SocketAddr) -> impl Iterator<Item = SocketAddr> {
        std::iter::once(self.peer_addr)
    }
    /// Send an ACK-eliciting frame hint (mark ACK needed)
    #[cfg(any(test, feature = "rust-tests"))]
    pub fn send_ack_eliciting(&mut self) -> Result<(), crate::error::ConnectionError> {
        self.pkt_spaces[2].ack_elicited = true;
        Ok(())
    }
    /// Send ACK-eliciting on a path (ignored in minimal impl)
    #[cfg(any(test, feature = "rust-tests"))]
    pub fn send_ack_eliciting_on_path(
        &mut self,
        _from: SocketAddr,
    ) -> Result<(), crate::error::ConnectionError> {
        self.send_ack_eliciting()
    }
    /// Retired scids count
    #[cfg(any(test, feature = "rust-tests"))]
    pub fn retired_scids(&self) -> usize {
        self.retired_scids.len()
    }
    /// Next retired scid if any
    #[cfg(any(test, feature = "rust-tests"))]
    pub fn retired_scid_next(&mut self) -> Option<ConnectionId> {
        if self.retired_scids.is_empty() {
            None
        } else {
            self.retired_scids.pop_front()
        }
    }
    /// Available dcids (minimal: 0)
    #[cfg(any(test, feature = "rust-tests"))]
    pub fn available_dcids(&self) -> usize {
        0
    }
}

#[cfg(any(test, feature = "benches"))]
/// Client/server transport pair with 1-RTT keys installed for criterion benches.
pub struct BenchConnectionPair {
    pub client: Connection,
    pub server: Connection,
    pub recv_info: RecvInfo,
}

#[cfg(any(test, feature = "benches"))]
/// Build a matched client/server pair ready for 1-RTT send/recv micro-benchmarks.
pub fn bench_paired_1rtt_connections() -> BenchConnectionPair {
    bench_paired_1rtt_connections_stealth(false)
}

#[cfg(any(test, feature = "benches"))]
/// Build a matched client/server pair for 1-RTT benches with stealth knobs toggled.
pub fn bench_paired_1rtt_connections_stealth(stealth_on: bool) -> BenchConnectionPair {
    use std::net::{Ipv4Addr, SocketAddr};

    use crate::crypto::aead::{Algorithm, KeyScheduleHooks, Level};

    let local_client = SocketAddr::from((Ipv4Addr::LOCALHOST, 29101));
    let peer_client = SocketAddr::from((Ipv4Addr::LOCALHOST, 29102));
    let local_server = peer_client;
    let peer_server = local_client;

    let mut config =
        Config::new_with_version(crate::transport::PROTOCOL_VERSION).expect("bench config");
    config.stealth_timing_enabled = stealth_on;
    config.stealth_timing_max_jitter_us = if stealth_on { 2_500 } else { 0 };
    config.stealth_padding_enabled = stealth_on;
    config.stealth_padding_strategy = if stealth_on { 3 } else { 0 };
    config.stealth_padding_max_size = if stealth_on { 256 } else { 0 };
    config.external_pacing = !stealth_on;

    let client_scid = [0x11u8; 8];
    let server_scid = [0x22u8; 8];
    let client_write = [0xAAu8; 32];
    let server_write = [0xBBu8; 32];

    let mut client =
        Connection::new_client(&client_scid, local_client, peer_client, config.clone());
    let mut server = Connection::new_server(&server_scid, local_server, peer_server, config);

    client.set_destination_cid(ConnectionId::from_vec(server_scid.to_vec()));
    server.set_destination_cid(ConnectionId::from_vec(client_scid.to_vec()));

    {
        let mut crypto = client.crypto.write();
        crypto.set_write_secret(Level::OneRTT, Algorithm::AES128_GCM, &client_write);
        crypto.set_read_secret(Level::OneRTT, Algorithm::AES128_GCM, &server_write);
    }
    client.refresh_short_header_tag_reserve();
    {
        let mut crypto = server.crypto.write();
        crypto.set_write_secret(Level::OneRTT, Algorithm::AES128_GCM, &server_write);
        crypto.set_read_secret(Level::OneRTT, Algorithm::AES128_GCM, &client_write);
    }
    server.refresh_short_header_tag_reserve();

    client.is_established = true;
    server.is_established = true;
    client.stats.recv = 1;
    server.stats.recv = 1;
    client.stats.sent = 1;
    server.stats.sent = 1;

    let recv_info = RecvInfo { from: peer_server, to: local_server, ecn: None };
    BenchConnectionPair { client, server, recv_info }
}

#[cfg(feature = "benches")]
impl Connection {
    /// Configure stealth padding for transport-padding benchmarks.
    pub fn bench_set_stealth_padding(
        &mut self,
        enabled: bool,
        strategy: u8,
        max_size: usize,
        rate: u8,
        granularity: u16,
        mimic_bias: u8,
    ) {
        self.config.set_stealth_padding(enabled, strategy, max_size);
        self.config.set_stealth_padding_rate(rate);
        self.config.set_stealth_adaptive_granularity(granularity);
        self.config.set_stealth_mimic_bias(mimic_bias);
    }

    /// Run the transport stealth-padding decision logic for Criterion benchmarks.
    pub fn bench_compute_stealth_padding(&self, cur_pt_len: usize, budget: usize) -> usize {
        self.compute_stealth_padding(cur_pt_len, budget)
    }

    /// Configure Brain runtime gates for transport/brain benchmarks.
    pub fn bench_set_brain_runtime(
        &mut self,
        enabled: bool,
        permissions: crate::transport::BrainRuntimePermissions,
    ) {
        self.set_intelligent_stealth_runtime(enabled);
        self.set_brain_runtime_permissions(permissions);
    }

    /// Seed the recovery owner's sent state for ACK accounting benchmarks.
    pub fn bench_seed_sent_bytes_by_pn(&mut self, count: u64, bytes_per_pn: usize) {
        self.recovery.discard_space(recovery::PacketSpace::Application);
        let now = Instant::now();
        for pn in 0..count {
            self.recovery.on_packet_sent_in_space(
                recovery::PacketSpace::Application,
                pn,
                bytes_per_pn,
                true,
                true,
                None,
                now,
            );
        }
    }

    /// Run ACK sent-byte accounting (same logic as inbound ACK frame handling).
    pub fn bench_account_ack_ranges(&mut self, ranges: &[(u64, u64)]) {
        let now = Instant::now();
        let outcome = self.recovery.on_ack_received(
            recovery::PacketSpace::Application,
            ranges,
            Duration::ZERO,
            true,
            self.is_server,
            now,
        );
        self.apply_ack_outcome(recovery::PacketSpace::Application, outcome, now);
    }
}

// ============================================================================
// Inline unit tests – no real network or TLS required.
//
// All tests construct a Connection via new_with_role() and exercise internal
// state directly. Private fields are accessible from a #[cfg(test)] module
// nested inside the same source file.
// ============================================================================
#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::ConnectionError;
    use crate::transport::config::Config;
    use crate::transport::PROTOCOL_VERSION;

    fn local() -> std::net::SocketAddr {
        "127.0.0.1:10000".parse().unwrap()
    }
    fn peer() -> std::net::SocketAddr {
        "127.0.0.1:10001".parse().unwrap()
    }
    fn recv_info() -> RecvInfo {
        RecvInfo { from: peer(), to: local(), ecn: None }
    }

    /// Minimal connection used across tests; does not require TLS or sockets.
    fn make_conn() -> Connection {
        Connection::new_with_role(
            b"test_scid_0123456789",
            local(),
            peer(),
            Config::new_with_version(PROTOCOL_VERSION).unwrap(),
            false, // client
        )
    }

    #[test]
    fn last_activity_marker_matches_the_heartbeat_activity_source() {
        let mut connection = make_conn();
        assert_eq!(connection.last_activity_marker(), connection.last_activity);

        connection.last_activity = Instant::now();
        assert_eq!(connection.last_activity_marker(), connection.last_activity);
    }

    /// Install a dummy 32-byte 1-RTT write secret so key_update() can toggle
    /// key_phase without a real TLS handshake.
    fn install_write_secret(c: &mut Connection) {
        c.crypto.write().write_secret_1rtt = Some(vec![0u8; 32]);
    }

    fn make_v2_client() -> Connection {
        let mut config = Config::new_with_version(crate::transport::PROTOCOL_VERSION_V2).unwrap();
        config
            .set_supported_versions(vec![crate::transport::PROTOCOL_VERSION_V2, PROTOCOL_VERSION])
            .unwrap();
        let mut connection =
            Connection::new_with_role(b"client-scid", local(), peer(), config, false);
        connection.set_initial_dcid(ConnectionId::from_vec(b"client-dcid".to_vec()));
        connection
    }

    #[test]
    fn valid_vn_restarts_once_with_preferred_common_version_and_fresh_cids() {
        let mut client = make_v2_client();
        let original_scid = client.scid;
        let original_dcid = client.initial_dcid;
        client.recovery.on_packet_sent_in_space(
            recovery::PacketSpace::Application,
            0,
            1200,
            true,
            true,
            None,
            Instant::now(),
        );
        client.bytes_in_flight = 1200;
        let mut vn = packet::generate_version_negotiation_packet(
            &[],
            &[PROTOCOL_VERSION, super::super::version::generate_reserved_version()],
            original_scid.as_ref(),
            original_dcid.as_ref(),
        );
        assert_eq!(client.recv(&mut vn, &recv_info()), Ok(vn.len()));
        assert_eq!(client.config.version(), PROTOCOL_VERSION);
        assert!(client.version_negotiation.reacted_to_vn);
        assert_ne!(client.scid, original_scid);
        assert_ne!(client.initial_dcid, original_dcid);
        assert!(client.recovery.tracked_sent_pns(recovery::PacketSpace::Application).is_empty());
        assert_eq!(client.bytes_in_flight, 0);

        let selected_scid = client.scid;
        let selected_dcid = client.initial_dcid;
        let mut second = packet::generate_version_negotiation_packet(
            &[],
            &[crate::transport::PROTOCOL_VERSION_V2],
            selected_scid.as_ref(),
            selected_dcid.as_ref(),
        );
        assert_eq!(client.recv(&mut second, &recv_info()), Ok(second.len()));
        assert_eq!(client.config.version(), PROTOCOL_VERSION);
    }

    #[test]
    fn spoofed_or_original_version_vn_is_ignored() {
        let mut client = make_v2_client();
        let original_dcid = client.initial_dcid;
        let mut wrong_cid = packet::generate_version_negotiation_packet(
            &[],
            &[PROTOCOL_VERSION],
            b"wrong",
            original_dcid.as_ref(),
        );
        assert_eq!(client.recv(&mut wrong_cid, &recv_info()), Ok(wrong_cid.len()));
        assert!(!client.version_negotiation.reacted_to_vn);

        let mut injected = packet::generate_version_negotiation_packet(
            &[],
            &[crate::transport::PROTOCOL_VERSION_V2, PROTOCOL_VERSION],
            client.scid.as_ref(),
            original_dcid.as_ref(),
        );
        assert_eq!(client.recv(&mut injected, &recv_info()), Ok(injected.len()));
        assert!(!client.version_negotiation.reacted_to_vn);
        assert_eq!(client.config.version(), crate::transport::PROTOCOL_VERSION_V2);
    }

    #[test]
    fn vn_without_common_version_terminates_connection() {
        let mut client = make_v2_client();
        let mut vn = packet::generate_version_negotiation_packet(
            &[],
            &[super::super::version::generate_reserved_version()],
            client.scid.as_ref(),
            client.initial_dcid.as_ref(),
        );
        assert_eq!(client.recv(&mut vn, &recv_info()), Err(ConnectionError::VersionMismatch));
        assert!(client.is_closed);
    }

    #[test]
    fn authenticated_version_information_rejects_injected_downgrade() {
        let mut client = make_v2_client();
        client.config.select_version(PROTOCOL_VERSION).unwrap();
        client.version_negotiation.chosen = PROTOCOL_VERSION;
        client.version_negotiation.negotiated = PROTOCOL_VERSION;
        client.version_negotiation.reacted_to_vn = true;
        let parameters = super::super::version::VersionInformation {
            chosen: PROTOCOL_VERSION,
            available: vec![crate::transport::PROTOCOL_VERSION_V2, PROTOCOL_VERSION],
        }
        .encode_parameter()
        .unwrap();

        assert!(client.validate_peer_version_information(Some(parameters)).is_err());
        assert!(client.pending_control.iter().any(|frame| matches!(
            frame,
            Frame::ConnectionClose { error_code, .. }
                if *error_code == super::super::version::VERSION_NEGOTIATION_ERROR_CODE
        )));
    }

    #[test]
    fn v2_requires_authenticated_version_information() {
        let mut client = make_v2_client();
        assert!(client.validate_peer_version_information(Some(Vec::new())).is_err());
        assert!(client.is_closed);
    }

    #[test]
    fn server_may_accept_missing_version_information_and_client_accepts_retiring_choice() {
        let mut config = Config::new_with_version(crate::transport::PROTOCOL_VERSION_V2).unwrap();
        config
            .set_supported_versions(vec![crate::transport::PROTOCOL_VERSION_V2, PROTOCOL_VERSION])
            .unwrap();
        let mut server = Connection::new_with_role(b"server-scid", local(), peer(), config, true);
        assert_eq!(server.validate_peer_version_information(Some(Vec::new())), Ok(()));

        let mut client = make_v2_client();
        let parameters = super::super::version::VersionInformation {
            chosen: crate::transport::PROTOCOL_VERSION_V2,
            available: vec![PROTOCOL_VERSION],
        }
        .encode_parameter()
        .unwrap();
        assert_eq!(client.validate_peer_version_information(Some(parameters)), Ok(()));
    }

    #[test]
    fn v1_fallback_accepts_legacy_server_without_version_information() {
        let mut client = make_v2_client();
        client.config.select_version(PROTOCOL_VERSION).unwrap();
        client.version_negotiation.chosen = PROTOCOL_VERSION;
        client.version_negotiation.negotiated = PROTOCOL_VERSION;
        client.version_negotiation.reacted_to_vn = true;
        assert_eq!(client.validate_peer_version_information(Some(Vec::new())), Ok(()));
        assert!(client.version_negotiation.peer_information_validated);
    }

    // ---- Priority 1: Flow Control ----------------------------------------

    #[test]
    fn flow_control_send_blocked_by_peer_max_data() {
        let mut c = make_conn();
        // Force connection window to 10 bytes – smaller than the send payload.
        c.peer_max_data = 10;
        let result = c.stream_send(0, &[0u8; 100], false);
        assert!(result.is_err(), "stream_send must fail when payload exceeds peer_max_data");
    }

    #[test]
    fn flow_control_window_update_unblocks_send() {
        let mut c = make_conn();
        c.peer_max_data = 10;
        assert!(c.stream_send(0, &[0u8; 100], false).is_err(), "precondition: blocked");
        // Simulate peer sending MAX_DATA that opens the window.
        c.peer_max_data = 10_000;
        let sent =
            c.stream_send(0, &[0u8; 100], false).expect("should succeed after window update");
        assert_eq!(sent, 100);
    }

    #[test]
    fn flow_control_data_blocked_frame_queued_on_block() {
        let mut c = make_conn();
        c.peer_max_data = 10;
        let _ = c.stream_send(0, &[0u8; 100], false);
        let has_data_blocked =
            c.pending_control.iter().any(|f| matches!(f, Frame::DataBlocked { .. }));
        assert!(
            has_data_blocked,
            "DataBlocked frame must be queued when connection window is exhausted"
        );
    }

    #[test]
    fn flow_control_stream_window_blocks_independently() {
        let mut c = make_conn();
        // Connection window is generous; stream window is the bottleneck.
        c.peer_max_data = 10_000;
        // Create the stream entry with a send call that succeeds, then tighten stream window.
        c.stream_send(0, b"", false).ok();
        if let Some(s) = c.streams.get_mut(&0) {
            s.max_stream_data_tx = 5;
        }
        let result = c.stream_send(0, &[0u8; 100], false);
        assert!(
            result.is_err(),
            "stream_send must fail when payload exceeds per-stream max_stream_data_tx"
        );
    }

    #[test]
    fn flow_control_stream_data_blocked_frame_queued() {
        let mut c = make_conn();
        c.peer_max_data = 10_000;
        c.stream_send(0, b"", false).ok();
        if let Some(s) = c.streams.get_mut(&0) {
            s.max_stream_data_tx = 5;
        }
        let _ = c.stream_send(0, &[0u8; 100], false);
        let has_stream_blocked =
            c.pending_control.iter().any(|f| matches!(f, Frame::StreamDataBlocked { .. }));
        assert!(
            has_stream_blocked,
            "StreamDataBlocked frame must be queued when stream window is exhausted"
        );
    }

    // ---- Priority 2: State Transitions ------------------------------------

    #[test]
    fn close_sets_closed_and_draining() {
        let mut c = make_conn();
        assert!(!c.is_closed(), "must not be closed initially");
        assert!(!c.is_draining, "must not be draining initially");
        c.close(true, 0, b"done").unwrap();
        assert!(c.is_closed(), "is_closed must be true after close()");
        assert!(c.is_draining, "is_draining must be true after close()");
    }

    #[test]
    fn close_queues_application_close_frame() {
        let mut c = make_conn();
        c.close(true, 42, b"reason").unwrap();
        let has_app_close = c
            .pending_control
            .iter()
            .any(|f| matches!(f, Frame::ApplicationClose { error_code: 42, .. }));
        assert!(has_app_close, "close(app=true) must queue ApplicationClose frame");
    }

    #[test]
    fn on_timeout_increments_count_and_sets_draining() {
        let mut c = make_conn();
        assert!(!c.is_draining());
        assert!(!c.is_timed_out());
        c.on_timeout();
        assert!(c.is_draining(), "on_timeout() must set is_draining");
        assert!(c.is_timed_out(), "on_timeout() must make is_timed_out() return true");
    }

    #[test]
    fn on_timeout_clears_bytes_in_flight() {
        let mut c = make_conn();
        c.bytes_in_flight = 4800;
        c.on_timeout();
        assert_eq!(c.bytes_in_flight, 0, "on_timeout() must zero bytes_in_flight");
    }

    // ---- Priority 3: Key Update ------------------------------------------

    #[test]
    fn key_phase_starts_false() {
        let c = make_conn();
        assert!(!c.key_phase, "initial key_phase must be false (RFC 9001 §5.4)");
    }

    #[test]
    fn key_update_toggles_phase_with_installed_secret() {
        let mut c = make_conn();
        install_write_secret(&mut c);
        assert!(!c.key_phase);
        c.key_update();
        assert!(
            c.key_phase,
            "key_update() must flip key_phase to true when write secret is present"
        );
    }

    #[test]
    fn key_update_twice_restores_phase() {
        let mut c = make_conn();
        install_write_secret(&mut c);
        c.key_update();
        assert!(c.key_phase, "after first update: key_phase = true");
        // The second update derives from the rotated secret – re-install a known secret
        // so the derivation chain can continue without panicking.
        install_write_secret(&mut c);
        c.key_update();
        assert!(!c.key_phase, "after second update: key_phase must return to false");
    }

    // ---- Priority 4: In-Flight / Congestion Control ----------------------

    #[test]
    fn can_send_allows_when_below_cwnd() {
        let c = make_conn();
        // Fresh connection: bytes_in_flight = 0, cwnd = INITIAL_WINDOW.
        assert!(c.can_send(100), "can_send(100) must be true on fresh connection");
    }

    #[test]
    fn can_send_blocks_when_bytes_exceed_cwnd() {
        let mut c = make_conn();
        c.bytes_in_flight = c.cwnd + 1;
        assert!(!c.can_send(1), "can_send must return false when bytes_in_flight exceeds cwnd");
    }

    #[test]
    fn bytes_in_flight_cleared_by_timeout_restores_can_send() {
        let mut c = make_conn();
        // Saturate the congestion window.
        c.bytes_in_flight = c.cwnd + 1;
        assert!(!c.can_send(1), "precondition: window saturated");
        c.on_timeout();
        assert_eq!(c.bytes_in_flight, 0, "on_timeout must clear bytes_in_flight");
        assert!(c.can_send(1), "can_send must be true after timeout clears in-flight");
    }

    // ---- Connection State Transitions ------------------------------------

    #[test]
    fn new_connection_starts_unestablished() {
        let c = make_conn();
        assert!(!c.is_established(), "fresh connection must not be established");
        assert!(!c.is_closed(), "fresh connection must not be closed");
        assert!(!c.is_draining, "fresh connection must not be draining");
    }

    #[test]
    fn post_handshake_envelope_waits_for_pending_handshake_flight() {
        let mut c = make_conn();
        c.is_established = true;
        c.crypto.write().crypto_handshake.send(b"client-finished");

        assert!(!c.post_handshake_datagram_ready().expect("readiness probe"));

        let (_, flight) = c
            .next_crypto_frame(crate::qftls::Level::Handshake, usize::MAX)
            .expect("pending handshake flight");
        assert_eq!(flight, b"client-finished");
        assert!(c.post_handshake_datagram_ready().expect("readiness probe"));
    }

    #[test]
    fn server_role_sets_is_server_flag() {
        let s = Connection::new_with_role(
            b"server_cid_12345678",
            local(),
            peer(),
            Config::new_with_version(PROTOCOL_VERSION).unwrap(),
            true,
        );
        assert!(s.is_server(), "server connection must report is_server=true");
    }

    #[test]
    fn close_transport_queues_connection_close_frame() {
        let mut c = make_conn();
        c.close(false, 0x0a, b"flow_control").unwrap();
        let has_conn_close = c
            .pending_control
            .iter()
            .any(|f| matches!(f, Frame::ConnectionClose { error_code: 0x0a, .. }));
        assert!(has_conn_close, "close(app=false) must queue ConnectionClose frame");
    }

    #[test]
    fn double_close_is_idempotent() {
        let mut c = make_conn();
        c.close(true, 1, b"first").unwrap();
        c.close(true, 2, b"second").unwrap();
        assert!(c.is_closed(), "connection must remain closed after double close");
        assert_eq!(c.pending_control.len(), 2, "both close frames should be queued");
    }

    // ---- Stream Open/Close and Flow Control ------------------------------

    #[test]
    fn stream_send_creates_stream_entry() {
        let mut c = make_conn();
        c.peer_max_data = 10_000;
        c.stream_send(4, b"hello", false).unwrap();
        assert!(c.streams.contains_key(&4), "stream_send must create stream entry");
    }

    #[test]
    fn stream_send_with_fin_marks_send_fin() {
        let mut c = make_conn();
        c.peer_max_data = 10_000;
        c.stream_send(4, b"done", true).unwrap();
        let s = c.streams.get(&4).expect("stream must exist");
        assert!(s.send_fin, "stream must have send_fin set after fin=true");
    }

    #[test]
    fn stream_send_after_fin_returns_final_size_error() {
        let mut c = make_conn();
        c.peer_max_data = 10_000;
        c.stream_send(4, b"done", true).unwrap();
        let err = c.stream_send(4, b"more", false).unwrap_err();
        assert!(
            matches!(err, crate::error::ConnectionError::FinalSize),
            "sending after FIN must return FinalSize error, got {:?}",
            err
        );
    }

    #[test]
    fn stream_writable_list_tracks_active_streams() {
        let mut c = make_conn();
        c.peer_max_data = 10_000;
        c.stream_send(0, b"a", false).unwrap();
        c.stream_send(4, b"b", false).unwrap();
        assert!(c.writable_streams.contains(&0), "stream 0 must be writable");
        assert!(c.writable_streams.contains(&4), "stream 4 must be writable");
    }

    // ---- Error Handling: Transport Errors, Reset -------------------------

    #[test]
    fn local_error_none_on_fresh_connection() {
        let c = make_conn();
        assert!(c.local_error.is_none(), "fresh connection must not have local_error");
    }

    #[test]
    fn close_sets_local_error_application_closed() {
        let mut c = make_conn();
        c.close(true, 0, b"bye").unwrap();
        assert!(
            matches!(c.local_error, Some(crate::error::ConnectionError::ApplicationClosed)),
            "close() must set local_error to ApplicationClosed"
        );
    }

    #[test]
    fn timeout_increments_lost_stats() {
        let mut c = make_conn();
        c.peer_max_data = 10_000;
        // Queue some data to trigger the lost counter in on_timeout
        c.stream_send(0, b"some data for timeout test", false).unwrap();
        let lost_before = c.stats.lost;
        c.on_timeout();
        assert!(
            c.stats.lost > lost_before,
            "on_timeout must increment lost stats when streams have pending data"
        );
    }

    // ---- 0-RTT Early Data Paths ------------------------------------------

    #[test]
    fn is_in_early_data_when_configured() {
        let mut cfg = Config::new_with_version(PROTOCOL_VERSION).unwrap();
        cfg.enable_early_data = true;
        let c = Connection::new_with_role(b"test_scid_0123456789", local(), peer(), cfg, false);
        assert!(
            c.is_in_early_data(),
            "connection with enable_early_data must report is_in_early_data"
        );
    }

    #[test]
    fn not_in_early_data_when_established() {
        let mut cfg = Config::new_with_version(PROTOCOL_VERSION).unwrap();
        cfg.enable_early_data = true;
        let mut c = Connection::new_with_role(b"test_scid_0123456789", local(), peer(), cfg, false);
        c.is_established = true;
        assert!(!c.is_in_early_data(), "established connection must not be in early data");
    }

    #[test]
    fn not_in_early_data_when_disabled() {
        let c = make_conn();
        assert!(
            !c.is_in_early_data(),
            "connection without enable_early_data must not be in early data"
        );
    }

    // ---- Idle Timeout and Keepalive --------------------------------------

    #[test]
    fn timeout_returns_some_duration() {
        let c = make_conn();
        let t = c.timeout();
        assert!(t.is_some(), "timeout() must return Some");
        assert!(t.unwrap() > Duration::from_secs(0), "timeout must be positive");
    }

    #[test]
    fn on_timeout_does_not_inflate_rtt() {
        // RFC 9000 §5.1: RTT estimate is only updated from ACK samples,
        // not from timeout events. The previous code added 100ms on every
        // timeout, causing monotonic RTT inflation (0→385ms on loopback).
        // This test verifies the fix: on_timeout must NOT change self.rtt.
        let mut c = make_conn();
        let rtt_before = c.rtt;
        c.on_timeout();
        assert_eq!(
            c.rtt, rtt_before,
            "on_timeout must NOT inflate RTT - only ACK samples update RTT (RFC 9000 §5.1)"
        );
    }

    #[test]
    fn multiple_timeouts_accumulate() {
        let mut c = make_conn();
        c.on_timeout();
        c.on_timeout();
        assert!(c.timeout_count >= 2, "multiple on_timeout calls must accumulate timeout_count");
    }

    #[test]
    fn ack_updates_rtt_from_send_time() {
        // RFC 9000 §5.1: RTT sample = now - send_time - ack_delay.
        // This test verifies that ACK processing generates a valid RTT sample
        // from the largest acknowledged PN's send time.
        let mut c = make_conn();
        let initial_rtt = c.rtt;

        // Simulate sending packet PN=0 with a known send time in the past.
        let send_time = Instant::now() - Duration::from_millis(50);
        c.recovery.on_packet_sent_in_space(
            recovery::PacketSpace::Application,
            0,
            1200,
            true,
            true,
            None,
            send_time,
        );

        // Process an ACK acknowledging PN=0 (range 0..1).
        let ranges = vec![(0u64, 1u64)];
        let now = Instant::now();
        let outcome = c.recovery.on_ack_received(
            recovery::PacketSpace::Application,
            &ranges,
            Duration::ZERO,
            true,
            c.is_server,
            now,
        );
        c.apply_ack_outcome(recovery::PacketSpace::Application, outcome, now);

        // RTT should now be updated to ~50ms (now - send_time), not the initial value.
        assert!(
            c.rtt < initial_rtt + Duration::from_millis(100),
            "RTT should be updated from ACK sample, not inflated. Got {:?}, initial {:?}",
            c.rtt,
            initial_rtt
        );
        assert!(c.rtt >= Duration::from_millis(40), "RTT sample should be ~50ms. Got {:?}", c.rtt);
    }

    #[test]
    fn fec_feedback_counts_only_transport_classified_acknowledgements_as_clean() {
        let mut c = make_conn();
        let sent_at = Instant::now() - Duration::from_millis(10);
        for packet_number in 0..3 {
            c.recovery.on_packet_sent_in_space(
                recovery::PacketSpace::Application,
                packet_number,
                1200,
                true,
                true,
                None,
                sent_at,
            );
        }

        let sent_feedback = c.take_fec_callback_feedback();
        assert_eq!(sent_feedback.sent_packets, 3);
        assert_eq!(sent_feedback.acked_packets, 0);
        assert_eq!(sent_feedback.lost_packets, 0);

        let now = Instant::now();
        let outcome = c.recovery.on_ack_received(
            recovery::PacketSpace::Application,
            &[(0, 2)],
            Duration::ZERO,
            true,
            c.is_server,
            now,
        );
        c.apply_ack_outcome(recovery::PacketSpace::Application, outcome, now);

        let ack_feedback = c.take_fec_callback_feedback();
        assert_eq!(ack_feedback.sent_packets, 0);
        assert_eq!(ack_feedback.acked_packets, 2);
        assert_eq!(ack_feedback.lost_packets, 0);
    }

    #[test]
    fn ack_with_delay_subtracts_ack_delay() {
        // RTT sample should subtract the peer's ack_delay (RFC 9000 §19.3).
        let mut c = make_conn();
        let send_time = Instant::now() - Duration::from_millis(100);
        c.recovery.on_packet_sent_in_space(
            recovery::PacketSpace::Application,
            0,
            1200,
            true,
            true,
            None,
            send_time,
        );

        let ranges = vec![(0u64, 1u64)];
        let ack_delay = Duration::from_millis(30);
        let now = Instant::now();
        let outcome = c.recovery.on_ack_received(
            recovery::PacketSpace::Application,
            &ranges,
            ack_delay,
            true,
            c.is_server,
            now,
        );
        c.apply_ack_outcome(recovery::PacketSpace::Application, outcome, now);

        // RFC 9002 §5.2/§5.3: the first sample sets min_rtt = latest_rtt, so the
        // adjustment guard (latest >= min_rtt + delay) can never fire for it -
        // the first sample is NOT ack-delay adjusted (RTT ~= 100 ms, not 70 ms).
        assert!(
            c.rtt >= Duration::from_millis(90) && c.rtt <= Duration::from_millis(110),
            "first RTT sample must be unadjusted (~100ms). Got {:?}",
            c.rtt
        );
    }

    #[test]
    fn lost_stream_range_is_retransmitted_with_identical_payload_and_offset() {
        let mut pair = bench_paired_1rtt_connections();
        pair.client.pmtu = PmtuState::new(false, PmtuPolicy::default());
        pair.server.pmtu = PmtuState::new(false, PmtuPolicy::default());
        let payload = b"reliable stream payload across a dropped QUIC packet";
        pair.client.stream_send(0, payload, false).unwrap();
        let mut first_packet = [0u8; 1500];
        let first_pn = pair.client.next_send_pn_by_space[2];
        let (first_size, _) = pair.client.send(&mut first_packet).unwrap();

        pair.client.lose_stream_transmission_packet(first_pn);
        pair.client.recovery.on_loss_packet(first_pn, first_size, Instant::now());

        let mut retransmitted_packet = [0u8; 1500];
        let retransmitted_pn = pair.client.next_send_pn_by_space[2];
        let (retransmitted_len, _) = pair.client.send(&mut retransmitted_packet).unwrap();
        pair.server.recv(&mut retransmitted_packet[..retransmitted_len], &pair.recv_info).unwrap();

        let mut received = vec![0u8; payload.len()];
        let (received_len, fin) = pair.server.stream_recv(0, &mut received).unwrap();
        assert_eq!(&received[..received_len], payload);
        assert!(!fin);
        assert_eq!(pair.client.stream_transmissions.len(), 1);
        assert!(pair.client.stream_transmission_by_pn.contains_key(&retransmitted_pn));
    }

    #[test]
    fn confirmed_pmtu_packets_split_exactly_on_floor_retransmission() {
        let mut pair = bench_paired_1rtt_connections();
        pair.client.dgram_send_max_size = 1500;
        pair.server.dgram_send_max_size = 1500;
        pair.client.pmtu = PmtuState::new(false, PmtuPolicy::default());
        pair.client.pmtu.confirmed_mtu = 1500;
        pair.server.pmtu = PmtuState::new(false, PmtuPolicy::default());
        let payload = (0..1400).map(|index| (index % 251) as u8).collect::<Vec<_>>();
        pair.client.stream_send(0, &payload, false).unwrap();

        let mut packet = [0u8; 1500];
        let original_pn = pair.client.next_send_pn_by_space[2];
        let (original_len, _) = pair.client.send(&mut packet).unwrap();
        assert!(original_len > pair.client.pmtu.min_mtu);
        pair.client.lose_stream_transmission_packet(original_pn);
        pair.client.recovery.on_loss_packet(original_pn, original_len, Instant::now());
        pair.client.pmtu.confirmed_mtu = pair.client.pmtu.min_mtu;

        let mut retransmitted_packet_numbers = Vec::new();
        while !pair.client.stream_retransmit_queue.is_empty() {
            let packet_number = pair.client.next_send_pn_by_space[2];
            let (packet_len, _) = pair.client.send(&mut packet).unwrap();
            assert!(packet_len <= pair.client.pmtu.min_mtu);
            pair.server.recv(&mut packet[..packet_len], &pair.recv_info).unwrap();
            retransmitted_packet_numbers.push(packet_number);
        }
        assert_eq!(retransmitted_packet_numbers.len(), 2);

        let mut received = vec![0u8; payload.len()];
        let (received_len, fin) = pair.server.stream_recv(0, &mut received).unwrap();
        assert_eq!(received_len, payload.len());
        assert_eq!(received, payload);
        assert!(!fin);

        for packet_number in retransmitted_packet_numbers {
            let now = Instant::now();
            let outcome = pair.client.recovery.on_ack_received(
                recovery::PacketSpace::Application,
                &[(packet_number, packet_number + 1)],
                Duration::ZERO,
                true,
                pair.client.is_server,
                now,
            );
            pair.client.apply_ack_outcome(recovery::PacketSpace::Application, outcome, now);
        }
        assert!(pair.client.stream_transmissions.is_empty());
        assert_eq!(pair.client.stream_retransmit_bytes, 0);
    }

    #[test]
    fn late_ack_of_pre_split_packet_retires_every_retransmission_segment() {
        let mut pair = bench_paired_1rtt_connections();
        pair.client.dgram_send_max_size = 1500;
        pair.client.pmtu = PmtuState::new(false, PmtuPolicy::default());
        pair.client.pmtu.confirmed_mtu = 1500;
        pair.client.stream_send(0, &[0xA5; 1400], false).unwrap();

        let mut packet = [0u8; 1500];
        let original_pn = pair.client.next_send_pn_by_space[2];
        let (original_size, _) = pair.client.send(&mut packet).unwrap();
        pair.client.lose_stream_transmission_packet(original_pn);
        pair.client.recovery.on_loss_packet(original_pn, original_size, Instant::now());
        pair.client.pmtu.confirmed_mtu = pair.client.pmtu.min_mtu;

        let retransmitted_pn = pair.client.next_send_pn_by_space[2];
        pair.client.send(&mut packet).unwrap();
        assert_eq!(pair.client.stream_transmissions.len(), 2);
        assert_eq!(pair.client.stream_retransmit_queue.len(), 1);

        pair.client.acknowledge_late_stream_packets(&[(original_pn, original_pn + 1)]);
        let now = Instant::now();
        let outcome = pair.client.recovery.on_ack_received(
            recovery::PacketSpace::Application,
            &[(original_pn, original_pn + 1)],
            Duration::ZERO,
            true,
            pair.client.is_server,
            now,
        );
        pair.client.apply_ack_outcome(recovery::PacketSpace::Application, outcome, now);

        assert!(pair.client.stream_transmissions.is_empty());
        assert!(pair.client.stream_retransmit_queue.is_empty());
        assert!(!pair.client.stream_transmission_by_pn.contains_key(&retransmitted_pn));
        assert!(!pair.client.lost_stream_transmission_by_pn.contains_key(&original_pn));
        assert_eq!(pair.client.stream_retransmit_bytes, 0);
    }

    #[test]
    fn late_ack_of_lost_copy_retires_active_retransmission_exactly_once() {
        let mut pair = bench_paired_1rtt_connections();
        pair.client.pmtu = PmtuState::new(false, PmtuPolicy::default());
        pair.client.stream_send(0, b"late ACK retirement", false).unwrap();
        let mut packet = [0u8; 1500];
        let original_pn = pair.client.next_send_pn_by_space[2];
        pair.client.send(&mut packet).unwrap();

        pair.client.lose_stream_transmission_packet(original_pn);
        let retransmitted_pn = pair.client.next_send_pn_by_space[2];
        pair.client.send(&mut packet).unwrap();
        assert_eq!(pair.client.stream_transmissions.len(), 1);

        pair.client.acknowledge_late_stream_packets(&[(original_pn, original_pn + 1)]);
        let now = Instant::now();
        let outcome = pair.client.recovery.on_ack_received(
            recovery::PacketSpace::Application,
            &[(original_pn, original_pn + 1)],
            Duration::ZERO,
            true,
            pair.client.is_server,
            now,
        );
        pair.client.apply_ack_outcome(recovery::PacketSpace::Application, outcome, now);

        assert!(pair.client.stream_transmissions.is_empty());
        assert!(pair.client.stream_retransmit_queue.is_empty());
        assert!(!pair.client.stream_transmission_by_pn.contains_key(&retransmitted_pn));
        let now = Instant::now();
        let outcome = pair.client.recovery.on_ack_received(
            recovery::PacketSpace::Application,
            &[(retransmitted_pn, retransmitted_pn + 1)],
            Duration::ZERO,
            true,
            pair.client.is_server,
            now,
        );
        pair.client.apply_ack_outcome(recovery::PacketSpace::Application, outcome, now);
        assert!(pair.client.stream_transmissions.is_empty());
    }

    #[test]
    fn send_info_keeps_ack_only_packets_out_of_external_pacing() {
        let mut pair = bench_paired_1rtt_connections();
        pair.server.pmtu = PmtuState::new(false, PmtuPolicy::default());
        assert!(pair.server.pkt_spaces[2].on_packet_recv(7));
        pair.server.pkt_spaces[2].note_ack_eliciting(0, 1);
        let bytes_in_flight = pair.server.recovery.bytes_in_flight;
        let mut packet = [0u8; 1500];

        let (_, send_info) = pair.server.send(&mut packet).expect("ACK must serialize");

        assert!(!send_info.congestion_controlled);
        assert_eq!(pair.server.recovery.bytes_in_flight, bytes_in_flight);
    }

    #[test]
    fn send_info_marks_stream_packets_for_external_pacing() {
        let mut pair = bench_paired_1rtt_connections();
        pair.client.pmtu = PmtuState::new(false, PmtuPolicy::default());
        pair.client.stream_send(0, b"paced stream", false).unwrap();
        let mut packet = [0u8; 1500];

        let (_, send_info) = pair.client.send(&mut packet).expect("STREAM must serialize");

        assert!(send_info.congestion_controlled);
    }

    #[test]
    fn pto_probe_then_time_threshold_requeues_tail_packet() {
        // Canonical RFC 9002 flow for a tail loss without a higher ACK: the PTO
        // fires a probe, the probe's ACK advances largest_acked, and the time
        // threshold then declares the tail packet lost.
        let mut pair = bench_paired_1rtt_connections();
        pair.client.pmtu = PmtuState::new(false, PmtuPolicy::default());
        pair.client.stream_send(0, b"tail loss", false).unwrap();
        let mut packet = [0u8; 1500];
        let packet_number = pair.client.next_send_pn_by_space[2];
        let (packet_size, _) = pair.client.send(&mut packet).unwrap();
        // Age the tail packet beyond the initial loss_delay (9/8 * 333 ms).
        pair.client.recovery.on_packet_sent_in_space(
            recovery::PacketSpace::Application,
            packet_number,
            packet_size,
            true,
            true,
            None,
            Instant::now() - Duration::from_secs(1),
        );

        // 1. Recovery timeout fires the PTO: an Application probe is queued,
        //    nothing is declared lost (RFC 9002 §6.2.4).
        pair.client.on_recovery_timeout(Instant::now());
        assert!(pair.client.pending_probe_spaces.contains(&recovery::PacketSpace::Application));
        assert!(pair
            .client
            .recovery
            .tracks_sent_packet(recovery::PacketSpace::Application, packet_number));

        // 2. The probe (a later packet) is sent and acknowledged; the time
        //    threshold now declares the aged tail packet lost.
        let probe_pn = packet_number + 1;
        pair.client.recovery.on_packet_sent_in_space(
            recovery::PacketSpace::Application,
            probe_pn,
            1200,
            true,
            true,
            None,
            Instant::now(),
        );
        let now = Instant::now();
        let outcome = pair.client.recovery.on_ack_received(
            recovery::PacketSpace::Application,
            &[(probe_pn, probe_pn + 1)],
            Duration::ZERO,
            true,
            pair.client.is_server,
            now,
        );
        pair.client.apply_ack_outcome(recovery::PacketSpace::Application, outcome, now);

        assert!(!pair
            .client
            .recovery
            .tracks_sent_packet(recovery::PacketSpace::Application, packet_number));
        assert_eq!(pair.client.stream_retransmit_queue.len(), 1);
        assert!(pair.client.lost_stream_transmission_by_pn.contains_key(&packet_number));
    }

    #[test]
    fn aged_datagram_survives_pto_without_being_declared_lost() {
        // RFC 9002 §6.2.4: a PTO firing sends probes - it never declares loss.
        let mut pair = bench_paired_1rtt_connections();
        pair.client.pmtu = PmtuState::new(false, PmtuPolicy::default());
        pair.client.enable_datagrams(16, 16);
        pair.client.dgram_send(b"unreliable tail").unwrap();
        let mut packet = [0u8; 1500];
        let packet_number = pair.client.next_send_pn_by_space[2];
        let (packet_size, _) = pair.client.send(&mut packet).unwrap();
        // Age the recorded packet so a time-threshold timer would be expired,
        // then verify the PTO path still does not declare loss (RFC 9002 §6.2.4).
        pair.client.recovery.on_packet_sent_in_space(
            recovery::PacketSpace::Application,
            packet_number,
            packet_size,
            true,
            true,
            None,
            Instant::now() - Duration::from_secs(1),
        );
        let bytes_in_flight_before = pair.client.recovery.bytes_in_flight;

        pair.client.on_recovery_timeout(Instant::now());

        assert!(pair
            .client
            .recovery
            .tracks_sent_packet(recovery::PacketSpace::Application, packet_number));
        assert_eq!(pair.client.recovery.bytes_in_flight, bytes_in_flight_before);
        assert!(pair.client.pending_probe_spaces.contains(&recovery::PacketSpace::Application));
    }

    #[test]
    fn dgram_queue_full_is_retryable_after_send_drains_queue() {
        // A full QUIC DATAGRAM send queue must return DgramQueueFull, not a
        // terminal error, and a subsequent dgram_send must succeed once send()
        // has serialized the queued frame (TODO-559).
        let mut pair = bench_paired_1rtt_connections();
        pair.client.pmtu = PmtuState::new(false, PmtuPolicy::default());
        pair.client.enable_datagrams(0, 1);
        assert_eq!(pair.client.dgram_send_queue_len(), 0);

        pair.client.dgram_send(b"one").unwrap();
        assert_eq!(pair.client.dgram_send_queue_len(), 1);

        let err = pair.client.dgram_send(b"two").unwrap_err();
        assert!(matches!(err, ConnectionError::DgramQueueFull));

        let mut packet = [0u8; 1500];
        let (written, _) = pair.client.send(&mut packet).unwrap();
        assert!(written > 0);
        assert_eq!(pair.client.dgram_send_queue_len(), 0);

        pair.client.dgram_send(b"two").unwrap();
        assert_eq!(pair.client.dgram_send_queue_len(), 1);
    }

    #[test]
    fn pto_probe_bypasses_congestion_gate_and_emits_ack_eliciting_packet() {
        // RFC 9002 §7.5/§6.2.4: a PTO probe bypasses the congestion gate but
        // still counts as in flight (tracked ack-eliciting packet).
        let mut pair = bench_paired_1rtt_connections();
        pair.client.pmtu = PmtuState::new(false, PmtuPolicy::default());
        pair.client.enable_datagrams(16, 16);
        pair.client.dgram_send(b"unreliable tail").unwrap();
        let mut packet = [0u8; 1500];
        pair.client.send(&mut packet).unwrap();
        // Close the congestion gate: no headroom left in cwnd.
        pair.client.recovery.cwnd = pair.client.recovery.bytes_in_flight;
        assert!(!pair.client.recovery.can_send(pair.client.dgram_send_max_size));

        // Without a pending probe the gate rejects the send.
        assert_eq!(pair.client.send(&mut packet).unwrap_err(), crate::error::ConnectionError::Done);

        // A PTO firing queues the probe; the next send emits it despite the gate.
        pair.client.on_recovery_timeout(Instant::now());
        let tracked_before =
            pair.client.recovery.tracked_sent_pns(recovery::PacketSpace::Application).len();
        let (probe_len, probe_info) = pair.client.send(&mut packet).expect("probe must emit");
        assert!(probe_len > 0);
        assert!(probe_info.congestion_controlled); // probes count as in flight (§7.5)
        assert!(!pair.client.pending_probe_spaces.contains(&recovery::PacketSpace::Application));
        let tracked_after =
            pair.client.recovery.tracked_sent_pns(recovery::PacketSpace::Application).len();
        assert_eq!(tracked_after, tracked_before + 1);
    }

    #[test]
    fn packet_threshold_loss_requeues_stream_range() {
        let mut pair = bench_paired_1rtt_connections();
        pair.client.pmtu = PmtuState::new(false, PmtuPolicy::default());
        pair.client.stream_send(0, b"packet threshold loss", false).unwrap();
        let mut packet = [0u8; 1500];
        let stream_packet_number = pair.client.next_send_pn_by_space[2];
        pair.client.send(&mut packet).unwrap();
        let now = Instant::now();
        // The stream packet (PN 0) is already recorded by send(); seed PNs 1-4
        // so that an ACK for PN 4 advances largest_acked and declares PN 0 lost.
        for pn in 1..=4 {
            pair.client.recovery.on_packet_sent_in_space(
                recovery::PacketSpace::Application,
                pn,
                1200,
                true,
                true,
                None,
                now,
            );
        }

        let outcome = pair.client.recovery.on_ack_received(
            recovery::PacketSpace::Application,
            &[(4, 5)],
            Duration::ZERO,
            true,
            pair.client.is_server,
            now,
        );
        pair.client.apply_ack_outcome(recovery::PacketSpace::Application, outcome, now);

        assert_eq!(pair.client.stream_retransmit_queue.len(), 1);
        assert!(pair.client.lost_stream_transmission_by_pn.contains_key(&stream_packet_number));
    }

    #[test]
    fn full_stream_ledger_backpressures_without_emitting_empty_packets() {
        let mut pair = bench_paired_1rtt_connections();
        pair.client.pmtu = PmtuState::new(false, PmtuPolicy::default());
        pair.client.stream_send(0, b"bounded", false).unwrap();
        pair.client.stream_retransmit_bytes = MAX_STREAM_RETRANSMIT_BYTES;
        let packet_number = pair.client.next_send_pn_by_space[2];
        let mut packet = [0u8; 1500];

        let error = pair.client.send(&mut packet).unwrap_err();

        assert_eq!(error, crate::error::ConnectionError::Done);
        assert_eq!(pair.client.next_send_pn_by_space[2], packet_number);
        assert!(pair.client.stream_transmissions.is_empty());
    }

    #[test]
    fn sparse_ack_accounting_removes_acked_and_prunes_packet_threshold_losses() {
        let mut c = make_conn();
        let send_time = Instant::now() - Duration::from_millis(50);
        for pn in 0..12 {
            c.recovery.on_packet_sent_in_space(
                recovery::PacketSpace::Application,
                pn,
                1200,
                true,
                true,
                None,
                send_time,
            );
        }

        let ranges = vec![(0u64, 1u64), (4, 5), (8, 9)];
        let outcome = c.recovery.on_ack_received(
            recovery::PacketSpace::Application,
            &ranges,
            Duration::ZERO,
            true,
            c.is_server,
            Instant::now(),
        );
        c.apply_ack_outcome(recovery::PacketSpace::Application, outcome, Instant::now());

        assert_eq!(c.stats.acked_bytes, 3600);
        assert_eq!(c.stats.lost, 4);
        assert_eq!(c.stats.lost_bytes, 4800);
        let remaining: Vec<u64> = c.recovery.tracked_sent_pns(recovery::PacketSpace::Application);
        assert_eq!(remaining, vec![6, 7, 9, 10, 11]);
    }

    #[test]
    fn sparse_ack_prefix_classification_preserves_ack_loss_and_tail() {
        let mut c = make_conn();
        let send_time = Instant::now() - Duration::from_millis(50);
        for pn in 0..64 {
            c.recovery.on_packet_sent_in_space(
                recovery::PacketSpace::Application,
                pn,
                1200,
                true,
                true,
                None,
                send_time,
            );
        }

        let ranges = (0u64..64).step_by(4).map(|pn| (pn, pn + 1)).collect::<Vec<_>>();
        let outcome = c.recovery.on_ack_received(
            recovery::PacketSpace::Application,
            &ranges,
            Duration::ZERO,
            true,
            c.is_server,
            Instant::now(),
        );
        c.apply_ack_outcome(recovery::PacketSpace::Application, outcome, Instant::now());

        assert_eq!(c.stats.acked_bytes, 16 * 1200);
        assert_eq!(c.stats.lost, 43);
        assert_eq!(c.stats.lost_bytes, 43 * 1200);
        let remaining: Vec<u64> = c.recovery.tracked_sent_pns(recovery::PacketSpace::Application);
        assert_eq!(remaining, vec![58, 59, 61, 62, 63]);
    }

    #[test]
    fn large_contiguous_ack_uses_split_drain_and_preserves_tail() {
        let mut c = make_conn();
        let send_time = Instant::now() - Duration::from_millis(50);
        for pn in 0..96 {
            c.recovery.on_packet_sent_in_space(
                recovery::PacketSpace::Application,
                pn,
                1200,
                true,
                true,
                None,
                send_time,
            );
        }

        let ranges = vec![(16u64, 80u64)];
        let outcome = c.recovery.on_ack_received(
            recovery::PacketSpace::Application,
            &ranges,
            Duration::ZERO,
            true,
            c.is_server,
            Instant::now(),
        );
        c.apply_ack_outcome(recovery::PacketSpace::Application, outcome, Instant::now());

        assert_eq!(c.stats.acked_bytes, 64 * 1200);
        let remaining: Vec<u64> = c.recovery.tracked_sent_pns(recovery::PacketSpace::Application);
        assert_eq!(remaining, (80..96).collect::<Vec<_>>());
    }

    #[test]
    fn large_loss_prefix_uses_split_drain_and_preserves_unlost_tail() {
        let mut c = make_conn();
        let send_time = Instant::now() - Duration::from_millis(50);
        for pn in 0..128 {
            c.recovery.on_packet_sent_in_space(
                recovery::PacketSpace::Application,
                pn,
                1200,
                true,
                true,
                None,
                send_time,
            );
        }

        let ranges = vec![(127u64, 128u64)];
        let outcome = c.recovery.on_ack_received(
            recovery::PacketSpace::Application,
            &ranges,
            Duration::ZERO,
            true,
            c.is_server,
            Instant::now(),
        );
        c.apply_ack_outcome(recovery::PacketSpace::Application, outcome, Instant::now());

        assert_eq!(c.stats.acked_bytes, 1200);
        assert_eq!(c.stats.lost, 125);
        assert_eq!(c.stats.lost_bytes, 125 * 1200);
        let remaining: Vec<u64> = c.recovery.tracked_sent_pns(recovery::PacketSpace::Application);
        assert_eq!(remaining, vec![125, 126]);
    }

    #[test]
    fn timeout_does_not_inflate_rtt_repeatedly() {
        // Verify that repeated timeouts do NOT cause monotonic RTT inflation.
        // This is the regression test for the 0→385ms loopback RTT bug.
        let mut c = make_conn();
        let rtt_before = c.rtt;
        for _ in 0..10 {
            c.on_timeout();
        }
        assert_eq!(
            c.rtt, rtt_before,
            "10 timeouts must not inflate RTT. Got {:?}, expected {:?}",
            c.rtt, rtt_before
        );
    }

    // ---- MAX_STREAMS / MAX_DATA Handling ---------------------------------

    #[test]
    fn peer_max_data_update_monotonic() {
        let mut c = make_conn();
        let initial = c.peer_max_data;
        // Simulate peer sending larger MAX_DATA
        c.peer_max_data = initial + 1000;
        assert_eq!(c.peer_max_data, initial + 1000);
        // Verify peer_max_data was updated to the new value
        assert_eq!(c.peer_max_data, initial + 1000, "peer_max_data must reflect the update");
    }

    #[test]
    fn conn_max_data_initial_matches_config() {
        let cfg = Config::new_with_version(PROTOCOL_VERSION).unwrap();
        let initial_max = cfg.initial_max_data;
        let c = Connection::new_with_role(b"test_scid_0123456789", local(), peer(), cfg, false);
        assert_eq!(
            c.conn_max_data, initial_max,
            "conn_max_data must match config initial_max_data"
        );
    }

    #[test]
    fn max_peer_max_data_cap_prevents_resource_exhaustion() {
        // Verify the cap constant exists and is reasonable
        const { assert!(MAX_PEER_MAX_DATA > 0, "MAX_PEER_MAX_DATA must be positive") };
        assert!(MAX_PEER_MAX_DATA <= 2_u64.pow(30), "MAX_PEER_MAX_DATA must be bounded");
    }

    // ---- Packet Number Space Management ----------------------------------

    #[test]
    fn initial_pn_spaces_start_at_zero() {
        let c = make_conn();
        for (i, &pn) in c.next_send_pn_by_space.iter().enumerate() {
            assert_eq!(pn, 0, "next_send_pn for space {} must start at 0", i);
        }
    }

    #[test]
    fn three_pn_spaces_exist() {
        let c = make_conn();
        assert_eq!(
            c.pkt_spaces.len(),
            3,
            "must have exactly 3 PN spaces (Initial, Handshake, Application)"
        );
        assert_eq!(c.next_send_pn_by_space.len(), 3, "must have 3 next_send_pn counters");
    }

    // ---- Connection Close Frame Generation -------------------------------

    #[test]
    fn close_app_and_transport_produce_different_frames() {
        let mut c1 = make_conn();
        c1.close(true, 42, b"app error").unwrap();
        let has_app =
            c1.pending_control.iter().any(|f| matches!(f, Frame::ApplicationClose { .. }));
        assert!(has_app, "app close must produce ApplicationClose frame");

        let mut c2 = make_conn();
        c2.close(false, 0x01, b"protocol error").unwrap();
        let has_conn =
            c2.pending_control.iter().any(|f| matches!(f, Frame::ConnectionClose { .. }));
        assert!(has_conn, "transport close must produce ConnectionClose frame");
    }

    #[test]
    fn close_reason_preserved_in_frame() {
        let mut c = make_conn();
        c.close(true, 99, b"test reason").unwrap();
        let frame = c.pending_control.back().expect("must have queued frame");
        match frame {
            Frame::ApplicationClose { error_code, reason } => {
                assert_eq!(*error_code, 99);
                assert_eq!(reason.as_ref(), b"test reason");
            }
            _ => panic!("expected ApplicationClose frame"),
        }
    }

    #[test]
    fn peer_close_frames_transition_connection_to_closed() {
        for app_close in [false, true] {
            let mut pair = bench_paired_1rtt_connections();
            pair.client.close(app_close, 42, b"peer shutdown").unwrap();

            let mut packet = [0u8; 1500];
            let (packet_len, _) = pair.client.send(&mut packet).unwrap();
            pair.server.recv(&mut packet[..packet_len], &pair.recv_info).unwrap();

            assert!(pair.server.is_closed(), "peer close frame must close the connection");
            assert!(pair.server.is_draining(), "peer close frame must enter draining state");
        }
    }

    // ---- ECN Counters ----------------------------------------------------

    #[test]
    fn ecn_counters_start_at_zero() {
        let c = make_conn();
        let (ect0, ect1, ce) = c.ecn_counts();
        assert_eq!(ect0, 0);
        assert_eq!(ect1, 0);
        assert_eq!(ce, 0);
    }

    // ---- Stats -----------------------------------------------------------

    #[test]
    fn stats_start_zeroed() {
        let c = make_conn();
        let s = c.stats();
        assert_eq!(s.recv, 0);
        assert_eq!(s.sent, 0);
        assert_eq!(s.lost, 0);
    }

    // ---- Stream Priority -------------------------------------------------

    #[test]
    fn stream_priority_reorders_writable_queue() {
        let mut c = make_conn();
        c.peer_max_data = 100_000;
        c.stream_send(0, b"low", false).unwrap();
        c.stream_send(4, b"high", false).unwrap();
        // Set stream 4 to higher priority (lower urgency number)
        c.stream_priority(4, 1, false).unwrap();
        let first = c.writable_streams.front().copied();
        assert_eq!(first, Some(4), "higher-priority stream must be first in writable queue");
    }

    // ---- Datagram Queues -------------------------------------------------

    #[test]
    fn dgram_send_recv_roundtrip() {
        let mut c = make_conn();
        c.enable_datagrams(16, 16);
        c.dgram_send(b"test_dgram").unwrap();
        assert_eq!(c.dgram_send_queue_len(), 1);
        assert_eq!(c.dgram_send_queue_byte_size(), 10);
    }

    #[test]
    fn outer_framing_reserves_space_for_queued_datagram_after_stream() {
        let mut pair = bench_paired_1rtt_connections();
        pair.client.enable_datagrams(16, 16);
        pair.server.enable_datagrams(16, 16);
        pair.client.dgram_send(&[0xD1; 1100]).expect("datagram enqueue");
        pair.client.stream_send(0, &[0xA5; 1200], false).expect("stream enqueue");
        let mut packet = [0u8; 1280];

        let (written, _) = pair
            .client
            .send_with_datagram_overhead(&mut packet, 36)
            .expect("outer-framed packet must serialize");
        pair.server.recv(&mut packet[..written], &pair.recv_info).expect("packet receive");

        assert_eq!(pair.client.dgram_send_queue_len(), 0);
        assert_eq!(pair.server.dgram_recv_vec().expect("datagram receive"), vec![0xD1; 1100]);
    }

    // ---- Recovery / FEC Escalation ---------------------------------------

    #[test]
    fn fec_escalation_threshold_default() {
        let c = make_conn();
        let thr = c.fec_escalation_threshold();
        assert!(thr > 0.0, "FEC escalation threshold must be positive");
        assert!(thr < 1.0, "FEC escalation threshold must be < 1.0");
    }

    // ---- Brain / Stealth Runtime -----------------------------------------

    #[test]
    fn intelligent_stealth_runtime_default_off() {
        let c = make_conn();
        assert!(
            !c.intelligent_stealth_runtime_enabled_for_test(),
            "intelligent stealth runtime must default to off"
        );
    }

    #[test]
    fn set_intelligent_stealth_runtime_toggle() {
        let mut c = make_conn();
        c.set_intelligent_stealth_runtime_for_test(true);
        assert!(c.intelligent_stealth_runtime_enabled_for_test());
        c.set_intelligent_stealth_runtime_for_test(false);
        assert!(!c.intelligent_stealth_runtime_enabled_for_test());
    }

    #[test]
    fn transport_stealth_jitter_disabled_when_external_pacing() {
        let mut c = make_conn();
        c.set_stealth_timing(true, 5_000);
        c.set_external_pacing_for_test(true);
        assert!(!c.transport_stealth_timing_active());
        assert!(c.transport_stealth_jitter_delay().is_none());
    }

    #[test]
    fn transport_stealth_jitter_bounded_when_gate_active() {
        let mut c = make_conn();
        c.set_stealth_timing(true, 100);
        c.set_external_pacing_for_test(false);
        assert!(c.transport_stealth_timing_active());
        let delay = c
            .transport_stealth_jitter_delay()
            .expect("jitter should be scheduled when gate active");
        assert!(delay <= Duration::from_micros(100));
    }

    #[test]
    fn pmtu_policy_reaches_configured_1500_ceiling() {
        let now = Instant::now();
        let mut state = PmtuState::new(true, PmtuPolicy::default());

        assert_eq!(state.effective_mtu(), 1280);
        assert_eq!(state.probe_size(), Some(1500));
        state.on_probe_sent(1500, now);
        state.on_probe_acked(now);

        assert_eq!(state.effective_mtu(), 1500);
        assert_eq!(state.probe_size(), None);
    }

    #[test]
    fn connection_emits_dedicated_probe_above_confirmed_mtu() {
        let mut pair = bench_paired_1rtt_connections();
        pair.client.dgram_send_max_size = 1500;
        pair.client.pmtu = PmtuState::new(true, PmtuPolicy::default());
        pair.client.recovery.cwnd = 64 * 1024;
        pair.client.recovery.bytes_in_flight = 0;
        let mut packet = [0u8; 1600];
        let bytes_in_flight_before = pair.client.recovery.bytes_in_flight;

        let (packet_len, info) = pair.client.send(&mut packet).expect("PMTU probe must serialize");

        assert_eq!(packet_len, 1500);
        assert!(info.congestion_controlled);
        assert!(pair.client.recovery.bytes_in_flight > bytes_in_flight_before);
        assert!(pair.client.pmtu_probe_pn.is_some());
    }

    #[test]
    fn dedicated_pmtu_probe_bypasses_a_closed_congestion_gate() {
        // RFC 8899 permits a rate-limited PING+PADDING probe outside the
        // congestion window. It must not carry queued application data.
        let mut pair = bench_paired_1rtt_connections();
        pair.client.dgram_send_max_size = 1472;
        pair.client.pmtu =
            PmtuState::new(true, PmtuPolicy { max_mtu: 1472, ..PmtuPolicy::default() });
        pair.client.recovery.cwnd = pair.client.recovery.bytes_in_flight;
        assert!(!pair.client.recovery.can_send(pair.client.dgram_send_max_size));

        let tracked_before =
            pair.client.recovery.tracked_sent_pns(recovery::PacketSpace::Application).len();
        let mut packet = [0u8; 1600];
        let (packet_len, info) =
            pair.client.send(&mut packet).expect("dedicated PMTU probe must emit");

        assert_eq!(packet_len, 1472);
        assert!(info.congestion_controlled);
        assert!(pair.client.pmtu_probe_pn.is_some());
        let tracked_after =
            pair.client.recovery.tracked_sent_pns(recovery::PacketSpace::Application).len();
        assert_eq!(tracked_after, tracked_before + 1);
    }

    #[test]
    fn dedicated_pmtu_probe_respects_congestion_when_interval_is_shorter_than_rtt() {
        let mut pair = bench_paired_1rtt_connections();
        pair.client.dgram_send_max_size = 1472;
        pair.client.pmtu = PmtuState::new(
            true,
            PmtuPolicy {
                max_mtu: 1472,
                probe_interval: Duration::from_millis(1),
                ..PmtuPolicy::default()
            },
        );
        pair.client.recovery.cwnd = pair.client.recovery.bytes_in_flight;
        assert!(!pair.client.recovery.can_send(pair.client.dgram_send_max_size));

        let mut packet = [0u8; 1600];
        assert_eq!(pair.client.send(&mut packet).unwrap_err(), crate::error::ConnectionError::Done);
        assert!(pair.client.pmtu_probe_pn.is_none());
    }

    #[test]
    fn connection_emits_exact_outer_probe_with_datagram_overhead() {
        const FEC_WIRE_OVERHEAD: usize = 18;
        let mut pair = bench_paired_1rtt_connections();
        pair.client.dgram_send_max_size = 1500;
        pair.client.pmtu = PmtuState::new(true, PmtuPolicy::default());
        pair.client.recovery.cwnd = 64 * 1024;
        pair.client.recovery.bytes_in_flight = 0;
        let mut packet = [0u8; 1600];

        let (packet_len, _) = pair
            .client
            .send_with_datagram_overhead(&mut packet, FEC_WIRE_OVERHEAD)
            .expect("PMTU probe with outer framing must serialize");

        assert_eq!(packet_len + FEC_WIRE_OVERHEAD, 1500);
        assert!(pair.client.pmtu_probe_pn.is_some());
    }

    #[test]
    fn unavailable_probe_capacity_does_not_emit_empty_packet() {
        let mut pair = bench_paired_1rtt_connections();
        pair.client.pmtu = PmtuState::new(true, PmtuPolicy::default());
        let packet_number = pair.client.next_send_pn_by_space[2];
        let mut packet = [0u8; 1600];

        let error = pair.client.send(&mut packet).unwrap_err();

        assert_eq!(error, crate::error::ConnectionError::Done);
        assert_eq!(pair.client.next_send_pn_by_space[2], packet_number);
        assert!(pair.client.pmtu_probe_pn.is_none());
    }

    #[test]
    fn pmtu_loss_bisects_configured_bounds() {
        let now = Instant::now();
        let mut state = PmtuState::new(true, PmtuPolicy::default());

        state.on_probe_sent(1500, now);
        state.on_probe_lost();

        assert_eq!(state.probe_size(), Some(1390));
        assert_eq!(state.effective_mtu(), 1280);
    }

    #[test]
    fn smaller_unrelated_ack_does_not_mask_confirmed_mtu_black_hole() {
        let policy =
            PmtuPolicy { black_hole_timeout: Duration::from_millis(10), ..PmtuPolicy::default() };
        let start = Instant::now();
        let mut state = PmtuState::new(true, policy);
        state.on_probe_sent(1500, start);
        state.on_probe_acked(start);
        let large_send = start + Duration::from_millis(1);
        state.on_packet_sent(1400, large_send);
        state.on_packet_acked(1280, start + Duration::from_millis(5));

        assert!(state.check_black_hole(start + Duration::from_millis(12)));
    }

    #[test]
    fn repeated_above_floor_sends_do_not_defer_black_hole_timeout() {
        let policy =
            PmtuPolicy { black_hole_timeout: Duration::from_millis(10), ..PmtuPolicy::default() };
        let start = Instant::now();
        let mut state = PmtuState::new(true, policy);
        state.on_probe_sent(1500, start);
        state.on_probe_acked(start);
        state.on_packet_sent(1400, start + Duration::from_millis(1));
        state.on_packet_sent(1400, start + Duration::from_millis(9));

        assert!(state.check_black_hole(start + Duration::from_millis(12)));
    }

    #[test]
    fn black_hole_reset_recovers_at_floor_then_periodically_reprobes_ceiling() {
        let probe_interval = Duration::from_millis(10);
        let policy = PmtuPolicy {
            probe_interval,
            black_hole_timeout: Duration::from_millis(5),
            ..PmtuPolicy::default()
        };
        let start = Instant::now();
        let mut state = PmtuState::new(true, policy);
        state.on_probe_sent(1500, start);
        state.on_probe_acked(start);
        state.on_packet_sent(1500, start + Duration::from_millis(1));
        let reset_at = start + Duration::from_millis(7);

        assert!(state.check_black_hole(reset_at));
        state.reset_to_minimum(reset_at);
        assert_eq!(state.effective_mtu(), 1280);
        assert!(!state.should_send_probe(reset_at + probe_interval - Duration::from_millis(1)));
        assert!(state.should_send_probe(reset_at + probe_interval));

        let mut probe_at = reset_at + probe_interval;
        for _ in 0..8 {
            let probe_size = state.probe_size().expect("recovery search must retain a target");
            if probe_size == 1500 {
                break;
            }
            state.on_probe_sent(probe_size, probe_at);
            state.on_probe_lost();
            probe_at += probe_interval;
        }

        assert_eq!(state.probe_size(), Some(1500));
        assert!(!state.should_send_probe(probe_at - Duration::from_millis(1)));
        assert!(state.should_send_probe(probe_at));
        state.on_probe_sent(1500, probe_at);
        state.on_probe_acked(probe_at);
        assert_eq!(state.effective_mtu(), 1500);
    }

    #[test]
    fn disabled_pmtu_stays_at_configured_floor() {
        let state = PmtuState::new(false, PmtuPolicy::default());

        assert_eq!(state.effective_mtu(), 1280);
        assert_eq!(state.probe_size(), None);
        assert!(!state.enabled());
    }
}
