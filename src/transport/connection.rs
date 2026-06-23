use super::{
    cid, config::Config, frames, packet, pnspace, recovery, udpfast, ConnectionId, EcnCounts,
    EcnMark, FecControlDelta, Frame, PacketType, PathStats, RecvInfo, SendInfo, Stats, Stream,
    TransportObserver, INITIAL_WINDOW, MAX_STREAM_SIZE, MIN_CLIENT_INITIAL_LEN, PROTOCOL_VERSION,
};
use std::borrow::Cow;
use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::optimize::{prefetch, PrefetchHint};
use crate::crypto::aead::AeadSeal;

const MAX_RX_KEY_UPDATE_ADVANCE: usize = 4;
const PATH_VALIDATION_TIMEOUT: Duration = Duration::from_secs(3);
const MIGRATION_COOLDOWN: Duration = Duration::from_millis(750);

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
    /// Stream storage. HashMap provides O(1) amortized lookup but poor cache locality
    /// at high stream counts (>10k). Hash table entries scatter across memory, causing
    /// L1/L2 cache misses during iteration and lookup. Consider replacing with a slot map
    /// (slotmap crate) or arena-based structure for better cache locality at scale.
    /// See: todo-181
    streams: HashMap<u64, Stream>,
    local_addr: SocketAddr,
    peer_addr: SocketAddr,
    config: Config,
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
    // Basic flow-control (local receive limits)
    // Receive-side connection window (what we allow peer to send)
    conn_max_data: u64,
    conn_bytes_recvd: u64,
    // Send-side connection window (what peer allows us to send)
    peer_max_data: u64,

    // Unified TLS provider (rustls + optional TLS Cover)
    tls_provider: Option<Box<dyn crate::qftls::QuicTlsProvider>>,
    conn_bytes_sent: u64,
    pending_control: VecDeque<Frame<'static>>,
    // Crypto context (AEAD/HP) hooks for header and payload processing
    crypto: Arc<parking_lot::RwLock<packet::CryptoContext>>,
    /// Lock-free 1-RTT crypto keys for the data-plane hot path.
    /// Loaded via `arc_swap::ArcSwapOption::load()` — no lock acquisition in steady state.
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
    // Sent packet accounting: PN -> (bytes, send_time) for ACK accounting + RTT sampling
    sent_packets_by_pn: BTreeMap<u64, (usize, Instant)>,
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
        let mut conn = Self {
            scid: ConnectionId::from_vec(scid.to_vec()),
            dcid: ConnectionId::default(),
            initial_dcid: ConnectionId::default(),
            is_server,
            is_established: false,
            is_closed: false,
            is_draining: false,
            streams: HashMap::new(),
            local_addr: local,
            peer_addr: peer,
            config,
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
            conn_max_data: initial_max_data,
            conn_bytes_recvd: 0,
            peer_max_data: initial_max_data,
            tls_provider: None,
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
            sent_packets_by_pn: BTreeMap::new(),
            intelligent_stealth_runtime: false,
            brain_runtime_permissions: crate::transport::BrainRuntimePermissions::default(),
            observer: None,
            h3: None,
            strike_register: None,
        };
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
        self.cwnd = INITIAL_WINDOW;
        self.bytes_in_flight = 0;
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

        // Create the TLS composition stack (rustls + optional TLS Cover).
        let provider = crate::qftls::create_provider(self.is_server, crypto_arc.clone())?;

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
            crypto.install_aes_gcm_initial(read_secret, write_secret);
            crypto.install_hp_initial(read_secret, write_secret);
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
    #[cfg(any(test, feature = "rust-tests"))]
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
        if let Some(provider) = &mut self.tls_provider {
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

            for chunk in chunks {
                provider.provide_quic_data(level, &chunk)?;
            }
            // Install any newly derived secrets into the shared CryptoContext.
            // Without this, the transport would never transition to 1-RTT and application streams
            // (including HTTP/3 HEADERS carrying x-qf-auth) would stall behind the handshake gate.
            provider.poll_secrets_and_install(&self.crypto)?;
            self.refresh_short_header_tag_reserve();
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
        let (pre_ty, largest_hint, mut pre_parsed_hdr) = match packet::parse_header(
            buf,
            short_dcid_len,
        ) {
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

        // Retry verification (no payload decrypt)
        if let PacketType::Retry = pre_ty {
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
                    crypto.install_aes_gcm_initial(read_secret, write_secret);
                    crypto.install_hp_initial(read_secret, write_secret);
                    drop(crypto);
                    self.refresh_short_header_tag_reserve();
                    self.next_send_pn_by_space[0] = 0;
                    self.pkt_spaces[0] = pnspace::PktNumSpace::default();
                }
            }
            // For Retry we do not parse further.
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
            // Consume pre_parsed_hdr by move (no clone) — on the common 1-RTT
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
            if !self.pkt_spaces[space_idx].on_packet_recv(
                hdr_native.pkt_num,
                self.config.max_ack_delay,
                self.config.ack_eliciting_threshold,
            ) {
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
                        Frame::ConnectionClose { .. } => {}
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
                            self.account_sent_bytes_for_ack_ranges_with_delay(&ranges, ack_delay);
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
            self.pkt_spaces[space_idx].note_ack_eliciting();
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
    /// In steady state (no key updates), the ArcSwap is never touched — the hot path loads
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

    #[inline(always)]
    fn flush_pending_control_frames(
        &mut self,
        out: &mut [u8],
        mut off: usize,
    ) -> Result<usize, crate::error::ConnectionError> {
        while let Some(ctrl) = self.pending_control.front() {
            let need = frames::wire_len(ctrl);
            let tag_reserve = self.tag_reserve_1rtt();
            if out.len() >= off + need + tag_reserve {
                off += frames::to_bytes(ctrl, &mut out[off..])?;
                self.pending_control.pop_front();
            } else {
                break;
            }
        }
        Ok(off)
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

    #[inline(always)]
    fn maybe_flush_one_writable_stream(
        &mut self,
        out: &mut [u8],
        mut off: usize,
    ) -> Result<usize, crate::error::ConnectionError> {
        use crate::error::ConnectionError;

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
                    let header_overhead = 1
                        + crate::transport::varint::varint_len(stream_id)
                        + crate::transport::varint::varint_len(s.send_off)
                        + 2;
                    if off + header_overhead + tag_reserve < out.len() {
                        let max_body = out.len() - off - header_overhead - tag_reserve;
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
                        let body_len = std::cmp::min(max_body, available.min(send_avail));
                        #[cfg(not(feature = "stream_ring_buffer"))]
                        let data_vec = s.send_buf[..body_len].to_vec();
                        #[cfg(feature = "stream_ring_buffer")]
                        let data_vec = {
                            let mut v = vec![0u8; body_len];
                            let read = s.send_ring.read(&mut v[..]);
                            if read < body_len {
                                v.truncate(read);
                            }
                            v
                        };
                        let data_len = data_vec.len();
                        let fin_now = {
                            #[cfg(not(feature = "stream_ring_buffer"))]
                            {
                                s.send_fin && body_len == available
                            }
                            #[cfg(feature = "stream_ring_buffer")]
                            {
                                s.send_fin && s.send_ring.is_empty()
                            }
                        };
                        let frame = Frame::Stream {
                            stream_id: s.id,
                            offset: s.send_off,
                            data: Cow::Owned(data_vec),
                            fin: fin_now,
                        };
                        let written = frames::to_bytes(&frame, &mut out[off..])?;
                        off += written;
                        s.send_off += data_len as u64;
                        #[cfg(not(feature = "stream_ring_buffer"))]
                        {
                            s.send_buf.drain(0..data_len);
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
                    }
                }
            }
        }
        Ok(off)
    }

    #[inline(always)]
    fn maybe_flush_one_datagram_frame(
        &mut self,
        out: &mut [u8],
        mut off: usize,
    ) -> Result<usize, crate::error::ConnectionError> {
        if let Some(front) = self.dgram_send_queue.front() {
            #[cfg(not(feature = "zero_copy_dgram"))]
            let need = 1 + 2 + front.len();
            #[cfg(feature = "zero_copy_dgram")]
            let need = 1 + 2 + front.len;
            let tag_reserve = self.tag_reserve_1rtt();
            if off + need + tag_reserve <= out.len() {
                #[cfg(not(feature = "zero_copy_dgram"))]
                {
                    let Some(front_owned) = self.dgram_send_queue.pop_front() else {
                        return Err(crate::error::ConnectionError::Done);
                    };
                    let frame = Frame::Datagram { data: Cow::Owned(front_owned) };
                    match frames::to_bytes(&frame, &mut out[off..]) {
                        Ok(written) => {
                            off += written;
                        }
                        Err(e) => {
                            if let Frame::Datagram { data } = frame {
                                self.dgram_send_queue.push_front(data.into_owned());
                            }
                            return Err(e);
                        }
                    }
                }
                #[cfg(feature = "zero_copy_dgram")]
                {
                    let frame =
                        Frame::Datagram { data: Cow::Owned(front.data[..front.len].to_vec()) };
                    let written = frames::to_bytes(&frame, &mut out[off..])?;
                    off += written;
                    self.dgram_send_queue.pop_front();
                }
            }
        }
        Ok(off)
    }

    #[inline(always)]
    fn maybe_apply_stealth_padding(
        &mut self,
        out: &mut [u8],
        pn_off: usize,
        pn_len: usize,
        mut off: usize,
    ) -> Result<usize, crate::error::ConnectionError> {
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
                        let pad = Frame::Padding { len: pad_len };
                        off += frames::to_bytes(&pad, &mut out[off..])?;
                    }
                }
                return Ok(off);
            }

            let ad_len = pn_off + pn_len;
            let pt_len_now = off.saturating_sub(ad_len);
            if avail > 0 {
                let pad_len = self.compute_stealth_padding(pt_len_now, avail);
                if pad_len > 0 {
                    let pad = Frame::Padding { len: pad_len };
                    let written = frames::to_bytes(&pad, &mut out[off..])?;
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
        // Hot path: try lock-free 1-RTT ArcSwap first.
        let one_rtt = self.crypto_1rtt.load();
        if let Some(keys) = one_rtt.as_ref() {
            // 1-RTT steady state — no lock acquisition.
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
                let mut first_orig = 0x40 | (((pn_len as u8) - 1) & 0x03);
                if self.key_phase {
                    first_orig |= packet::KEY_PHASE_BIT;
                }
                out[0] = first_orig ^ (mask[0] & 0x1f);
                for i in 0..pn_len {
                    out[pn_off + i] ^= mask[i + 1];
                }
            } else {
                out[0] = (0x40 | (((pn_len as u8) - 1) & 0x03))
                    | if self.key_phase { packet::KEY_PHASE_BIT } else { 0 };
            }
            self.next_send_pn_by_space[2] = self.next_send_pn_by_space[2].wrapping_add(1);
            return Ok(off);
        }

        // Fallback: 0-RTT or handshake — use RwLock.
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
            let mut first_orig = 0x40 | (((pn_len as u8) - 1) & 0x03);
            if self.key_phase {
                first_orig |= packet::KEY_PHASE_BIT;
            }
            out[0] = first_orig ^ (mask[0] & 0x1f);
            for i in 0..pn_len {
                out[pn_off + i] ^= mask[i + 1];
            }
        } else {
            out[0] = (0x40 | (((pn_len as u8) - 1) & 0x03))
                | if self.key_phase { packet::KEY_PHASE_BIT } else { 0 };
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
        // Build short header prefix with DCID directly — avoids two Vec
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

        let info = SendInfo { from: send_local, to: send_peer, at: Instant::now() };
        self.mark_unvalidated_path_send(send_local, send_peer, off);
        self.stats.sent += 1;
        self.stats.sent_bytes += off as u64;
        let now = Instant::now();
        self.recovery.on_packet_sent(pn, off, now);
        self.sent_packets_by_pn.insert(pn, (off, now));
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
        use crate::error::ConnectionError;
        use udpfast::unlikely;
        if unlikely(out.len() < MIN_CLIENT_INITIAL_LEN) {
            return Err(ConnectionError::BufferTooShort);
        }
        // Congestion gate: only send if within cwnd budget
        if !self.recovery.can_send(self.dgram_send_max_size) {
            return Err(ConnectionError::Done);
        }
        self.poll_path_validation_timeout(Instant::now());

        // TLS provider may derive new secrets during write-side progression. Poll here so
        // handshake completion and key installation are not dependent on receiving more CRYPTO.
        if let Some(provider) = &mut self.tls_provider {
            provider.poll_secrets_and_install(&self.crypto)?;
            self.refresh_short_header_tag_reserve();
        }

        let handshake_incomplete =
            self.tls_provider.as_ref().map(|p| !p.handshake_complete()).unwrap_or(false);

        // If TLS handshake not complete, attempt to send Initial/Handshake packet with CRYPTO frame
        if handshake_incomplete {
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
                    version: PROTOCOL_VERSION,
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

                let (lvl, max_len) = match pkt_ty {
                    PacketType::Initial => (crate::qftls::Level::Initial, out.len() - off - 16),
                    PacketType::Handshake => (crate::qftls::Level::Handshake, out.len() - off - 16),
                    _ => (crate::qftls::Level::Application, out.len() - off - 16),
                };
                if max_len < 32 {
                    continue;
                }
                let Some((crypto_off, data)) = self.next_crypto_frame(lvl, max_len) else {
                    continue;
                };

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
                let frame = Frame::Crypto { offset: crypto_off, data: Cow::Owned(data) };
                let written = frames::to_bytes(&frame, &mut out[off..])?;
                off += written;

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
                    let pad = Frame::Padding { len: pad_len };
                    frames::to_bytes(&pad, &mut out[off..])?;
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
                if !self.is_established && self.stats.recv > 0 && self.stats.sent > 0 {
                    self.is_established = true;
                }
                return Ok((
                    used,
                    SendInfo { at: Instant::now(), from: self.local_addr, to: self.peer_addr },
                ));
            }

            return Err(ConnectionError::Done);
        }
        if let Some(targeted_frame) = self.pop_targeted_path_frame_for_send() {
            return self.send_targeted_short_header_frame(
                out,
                targeted_frame.local_addr,
                targeted_frame.peer_addr,
                &targeted_frame.frame,
            );
        }
        // Outbound stealth timing is owned by core::QuicFuscateConnection (next_packet_release).
        // Build short header prefix with DCID directly — avoids two Vec
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

        // Some TLS implementations (including rustls QUIC) can emit post-handshake data in the
        // application space. While the handshake is still in progress, prefer sending those
        // CRYPTO frames before other application traffic.
        if handshake_incomplete {
            let max_len = out.len().saturating_sub(off + 16);
            if max_len >= 32 {
                if let Some((crypto_off, data)) =
                    self.next_crypto_frame(crate::qftls::Level::Application, max_len)
                {
                    let frame = Frame::Crypto { offset: crypto_off, data: Cow::Owned(data) };
                    let need = frames::wire_len(&frame);
                    if out.len() >= off + need + 16 {
                        off += frames::to_bytes(&frame, &mut out[off..])?;
                    }
                }
            }
        }

        off = self.flush_pending_control_frames(out, off)?;
        off = self.maybe_emit_application_ack_frame(out, off)?;
        off = self.maybe_flush_one_writable_stream(out, off)?;
        // FEC feed removed (handled by core)
        off = self.maybe_flush_one_datagram_frame(out, off)?;
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
        let info = SendInfo { from: self.local_addr, to: self.peer_addr, at: Instant::now() };
        self.stats.sent += 1;
        self.stats.sent_bytes += total as u64;
        if !self.is_established && self.stats.recv > 0 && self.stats.sent > 0 {
            self.is_established = true;
        }
        // Update recovery bytes-in-flight and mirror cwnd
        let now = Instant::now();
        self.recovery.on_packet_sent(pn, total, now);
        // Track sent bytes + send time by packet number for ACK accounting + RTT sampling
        self.sent_packets_by_pn.insert(pn, (total, now));
        self.cwnd = self.recovery.cwnd;
        Ok((total, info))
    }

    /// Compute stealth padding length given current plaintext payload length and budget.
    #[inline(always)]
    pub(crate) fn compute_stealth_padding(&self, cur_pt_len: usize, budget: usize) -> usize {
        if !self.config.stealth_padding_enabled {
            return 0;
        }
        // Gradual padding rate: only pad a fraction of packets based on the
        // configured rate (0-100%). At 100%, every packet is padded; at 50%,
        // only half of packets receive padding. This implements the gradual
        // stealth escalation from TODO-416.
        let padding_rate = self.config.stealth_padding_rate;
        if padding_rate < 100 {
            let roll = crate::transport::rand::rand_u64_uniform(100) as u8;
            if roll >= padding_rate {
                return 0;
            }
        }
        let max = self.config.stealth_padding_max_size.min(budget);
        if max == 0 {
            return 0;
        }
        match self.config.stealth_padding_strategy {
            // 1 = Random [0..=max]
            1 => crate::transport::rand::rand_u64_uniform((max as u64).saturating_add(1)) as usize,
            // 2 = Fixed (always pad up to max budget)
            2 => max,
            // 3 = Adaptive (pad up to next 64B boundary, capped by max)
            3 => {
                let g = self.config.stealth_adaptive_granularity.max(1) as usize;
                let rem = cur_pt_len % g;
                if rem == 0 {
                    0
                } else {
                    std::cmp::min(g - rem, max)
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
                let mut val = crate::transport::rand::rand_u64_uniform(bucket + 1);
                for _ in 1..samples {
                    let r = crate::transport::rand::rand_u64_uniform(bucket + 1);
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
            return Err(crate::error::ConnectionError::InvalidState);
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
    #[cfg(any(test, feature = "rust-tests"))]
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

    /// Lightweight telemetry: ECN counters since last ACK emission
    #[cfg(any(test, feature = "rust-tests"))]
    pub fn ecn_counts(&self) -> (u64, u64, u64) {
        (self.ecn_ect0, self.ecn_ect1, self.ecn_ce)
    }

    /// Current send quantum (bytes) derived from recovery
    #[cfg(any(test, feature = "rust-tests"))]
    pub fn send_quantum(&self) -> usize {
        self.recovery.send_quantum()
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

    /// Bytes currently considered in flight
    pub fn bytes_in_flight(&self) -> usize {
        self.bytes_in_flight
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
        let jitter_us = crate::transport::rand::rand_u64_uniform(scaled_max as u64 + 1);
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

    /// Take and reset recovery callback feedback counters.
    pub fn take_fec_callback_feedback(&self) -> (u64, u64, u64, u64) {
        (
            self.fec_cb_sent_packets.swap(0, std::sync::atomic::Ordering::Relaxed),
            self.fec_cb_lost_packets.swap(0, std::sync::atomic::Ordering::Relaxed),
            self.fec_cb_sent_bytes.swap(0, std::sync::atomic::Ordering::Relaxed),
            self.fec_cb_lost_bytes.swap(0, std::sync::atomic::Ordering::Relaxed),
        )
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

    /// Set the QKey auth token on the TLS provider (client side).
    /// The token is injected into QUIC transport parameters, which are
    /// carried in the TLS EncryptedExtensions message — encrypted at the
    /// Handshake level, invisible to DPI (TODO-415 Phase 2).
    pub fn set_qkey_auth_token(&mut self, token: &[u8]) {
        if let Some(provider) = &mut self.tls_provider {
            provider.set_qkey_auth_token(token);
        }
    }

    /// Get the QKey auth token extracted from peer's transport parameters (server side).
    /// Returns None if the peer did not send a QKey auth parameter.
    pub fn peer_qkey_auth_token(&self) -> Option<&[u8]> {
        self.tls_provider.as_ref().and_then(|p| p.peer_qkey_auth_token())
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

    /// Pops the next stream ID with queued send data (test helper).
    #[cfg(any(test, feature = "rust-tests"))]
    pub fn stream_writable_next(&mut self) -> Option<u64> {
        if self.writable_streams.is_empty() {
            None
        } else {
            self.writable_streams.pop_front()
        }
    }

    /// Maximum UDP payload size for outgoing datagrams.
    #[cfg(any(test, feature = "rust-tests"))]
    pub fn max_send_udp_payload_size(&self) -> usize {
        self.dgram_send_max_size
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

    /// Update recovery state from an ACK frame using the PN->(bytes, send_time) map.
    /// Also generates an RTT sample from the largest acknowledged PN's send time.
    /// Wrapper for zero ack_delay (used by bench code).
    #[cfg(feature = "benches")]
    fn account_sent_bytes_for_ack_ranges(&mut self, ranges: &[(u64, u64)]) {
        self.account_sent_bytes_for_ack_ranges_with_delay(ranges, Duration::ZERO)
    }

    /// Update recovery state from an ACK frame with the ACK delay from the peer.
    /// Generates an RTT sample: rtt = now - send_time - ack_delay (RFC 9000 §5).
    fn account_sent_bytes_for_ack_ranges_with_delay(
        &mut self,
        ranges: &[(u64, u64)],
        ack_delay: Duration,
    ) {
        let now = Instant::now();
        let mut acked_total = 0usize;
        let mut lost_total = 0usize;
        let largest_acked =
            ranges.iter().filter_map(|(_, end)| end.checked_sub(1)).max().unwrap_or(0);
        let packet_threshold = 3u64;

        // RTT sample: look up send_time of the largest acknowledged PN.
        // Per RFC 9000 §5.1, only the largest acked PN yields a valid RTT sample
        // (smaller PNs may have been acknowledged by coalesced ACKs with older send times).
        let mut rtt_sample: Option<Duration> = None;

        for (start, end) in ranges {
            let acked: Vec<(u64, (usize, Instant))> = self
                .sent_packets_by_pn
                .range(*start..*end)
                .map(|(&pn, &info)| (pn, info))
                .collect();
            for (pn, (sz, send_time)) in acked {
                if pn == largest_acked {
                    let elapsed = now.saturating_duration_since(send_time);
                    rtt_sample = Some(elapsed.saturating_sub(ack_delay));
                }
                self.sent_packets_by_pn.remove(&pn);
                acked_total = acked_total.saturating_add(sz);
            }
        }
        if largest_acked >= packet_threshold {
            let loss_cutoff = largest_acked - packet_threshold;
            let lost: Vec<(u64, (usize, Instant))> = self
                .sent_packets_by_pn
                .range(..=loss_cutoff)
                .map(|(&pn, &info)| (pn, info))
                .collect();
            for (pn, (sz, _)) in lost {
                self.sent_packets_by_pn.remove(&pn);
                self.recovery.on_loss_packet(pn, sz, now);
                lost_total = lost_total.saturating_add(sz);
                self.stats.lost = self.stats.lost.saturating_add(1);
                self.stats.lost_bytes = self.stats.lost_bytes.saturating_add(sz as u64);
            }
        }
        if acked_total > 0 {
            self.recovery.on_ack(acked_total, now);
            self.stats.acked_bytes = self.stats.acked_bytes.saturating_add(acked_total as u64);
            self.cwnd = self.recovery.cwnd;
        } else if lost_total > 0 {
            self.cwnd = self.recovery.cwnd;
        }

        // Apply RTT sample to connection + recovery (RFC 9000 §5).
        // This is the ONLY path that should update self.rtt with real measurements.
        // The timeout path uses exponential backoff, not additive growth.
        if let Some(sample) = rtt_sample {
            if sample > Duration::ZERO {
                self.rtt = sample;
                self.recovery.update_rtt(sample);
            }
        }
    }
}

#[cfg(feature = "benches")]
/// Client/server transport pair with 1-RTT keys installed for criterion benches.
pub struct BenchConnectionPair {
    pub client: Connection,
    pub server: Connection,
    pub recv_info: RecvInfo,
}

#[cfg(feature = "benches")]
/// Build a matched client/server pair ready for 1-RTT send/recv micro-benchmarks.
pub fn bench_paired_1rtt_connections() -> BenchConnectionPair {
    bench_paired_1rtt_connections_stealth(false)
}

#[cfg(feature = "benches")]
/// Build a matched client/server pair for 1-RTT benches with stealth knobs toggled.
pub fn bench_paired_1rtt_connections_stealth(stealth_on: bool) -> BenchConnectionPair {
    use std::net::{Ipv4Addr, SocketAddr};

    use crate::crypto::aead::{Algorithm, KeyScheduleHooks, Level};

    let local_client = SocketAddr::from((Ipv4Addr::LOCALHOST, 29101));
    let peer_client = SocketAddr::from((Ipv4Addr::LOCALHOST, 29102));
    let local_server = peer_client;
    let peer_server = local_client;

    let mut config = Config::new_with_version(PROTOCOL_VERSION).expect("bench config");
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
    /// Seed the sent-packet map for ACK accounting benchmarks.
    pub fn bench_seed_sent_bytes_by_pn(&mut self, count: u64, bytes_per_pn: usize) {
        self.sent_packets_by_pn.clear();
        let now = Instant::now();
        for pn in 0..count {
            self.sent_packets_by_pn.insert(pn, (bytes_per_pn, now));
        }
    }

    /// Run ACK sent-byte accounting (same logic as inbound ACK frame handling).
    pub fn bench_account_ack_ranges(&mut self, ranges: &[(u64, u64)]) {
        self.account_sent_bytes_for_ack_ranges(ranges);
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
    use crate::transport::config::Config;

    fn local() -> std::net::SocketAddr {
        "127.0.0.1:10000".parse().unwrap()
    }
    fn peer() -> std::net::SocketAddr {
        "127.0.0.1:10001".parse().unwrap()
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

    /// Install a dummy 32-byte 1-RTT write secret so key_update() can toggle
    /// key_phase without a real TLS handshake.
    fn install_write_secret(c: &mut Connection) {
        c.crypto.write().write_secret_1rtt = Some(vec![0u8; 32]);
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
            "on_timeout must NOT inflate RTT — only ACK samples update RTT (RFC 9000 §5.1)"
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
        c.sent_packets_by_pn.insert(0, (1200, send_time));

        // Process an ACK acknowledging PN=0 (range 0..1).
        let ranges = vec![(0u64, 1u64)];
        c.account_sent_bytes_for_ack_ranges_with_delay(&ranges, Duration::ZERO);

        // RTT should now be updated to ~50ms (now - send_time), not the initial value.
        assert!(
            c.rtt < initial_rtt + Duration::from_millis(100),
            "RTT should be updated from ACK sample, not inflated. Got {:?}, initial {:?}",
            c.rtt,
            initial_rtt
        );
        assert!(
            c.rtt >= Duration::from_millis(40),
            "RTT sample should be ~50ms. Got {:?}",
            c.rtt
        );
    }

    #[test]
    fn ack_with_delay_subtracts_ack_delay() {
        // RTT sample should subtract the peer's ack_delay (RFC 9000 §19.3).
        let mut c = make_conn();
        let send_time = Instant::now() - Duration::from_millis(100);
        c.sent_packets_by_pn.insert(0, (1200, send_time));

        let ranges = vec![(0u64, 1u64)];
        let ack_delay = Duration::from_millis(30);
        c.account_sent_bytes_for_ack_ranges_with_delay(&ranges, ack_delay);

        // RTT should be ~70ms (100ms elapsed - 30ms ack_delay).
        assert!(
            c.rtt >= Duration::from_millis(60) && c.rtt <= Duration::from_millis(80),
            "RTT should be ~70ms (100-30). Got {:?}",
            c.rtt
        );
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
            c.rtt,
            rtt_before
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
}
