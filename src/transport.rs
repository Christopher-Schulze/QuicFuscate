use std::borrow::Cow;
use std::collections::BTreeMap;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::ops::{Index, IndexMut};
use std::sync::Arc;
use std::time::{Duration, Instant};

// Explicit rust parity/test-only surface. Not part of the normal runtime API.
/// 0-RTT anti-replay protection via strike register.
pub mod anti_replay;
/// Batch packet processing utilities (test-only).
#[cfg(any(test, feature = "rust-tests"))]
#[doc(hidden)]
pub mod batch;
/// Pluggable congestion control: Reno, BBR3, StealthShaper wrapper.
pub mod cc;
/// QUIC connection configuration and transport parameter setters.
pub mod config;
/// QUIC connection state machine and stream/datagram I/O.
pub mod connection;
/// QUIC frame encoding and decoding.
pub mod frames;
/// HTTP/3 layer over QUIC transport.
pub mod h3;
/// QUIC packet header parsing, protection, and encryption.
pub mod packet;
/// Packet number spaces, connection IDs, varint codec, range sets, and RNG.
pub mod pn;
/// Loss recovery and congestion control integration.
pub mod recovery;
/// High-performance UDP send/recv with GSO/GRO and batch I/O.
pub mod udpfast;
mod xdp;

pub use anti_replay::{AntiReplayConfig, StrikeRegister};
pub use config::Config;
#[cfg(feature = "stream_ring_buffer")]
pub use connection::StreamRingBuffer;
#[cfg(feature = "benches")]
pub use connection::{
    bench_paired_1rtt_connections, bench_paired_1rtt_connections_stealth, BenchConnectionPair,
};
pub use connection::{Connection, PathEvent};
pub use pn::{cid, pnspace, rand, range_buf, ranges, varint};
/// Best-effort socket capability setup shared across runtime hotpaths.
#[doc(hidden)]
pub fn init_socket_acceleration(socket: &std::net::UdpSocket) -> std::io::Result<()> {
    let gso_enabled = crate::accelerate::transport_io::UdpGsoConfig::enable(socket)
        .map(|cfg| cfg.enabled)
        .unwrap_or(false);

    log::info!("Network acceleration initialized:");
    log::info!("  GSO: {}", gso_enabled);

    Ok(())
}

/// Experimental AF_XDP constructor probe kept behind the transport root,
/// which is the sole retained owner for explicit AF_XDP compatibility hooks.
#[cfg(all(
    target_os = "linux",
    any(test, feature = "rust-tests"),
    feature = "internal_af_xdp_experimental"
))]
/// Probes whether AF_XDP sockets are usable on the given NIC queue (experimental).
#[doc(hidden)]
pub fn run_xdp_experimental_socket_probe(
    ifindex: u32,
    queue_id: u32,
    frame_size: usize,
    frame_count: usize,
) -> std::io::Result<()> {
    let _socket = xdp::linux::XdpSocket::new(ifindex, queue_id, frame_size, frame_count)?;
    Ok(())
}

/// Pending FEC parameter changes to be consumed by the adaptive FEC controller.
#[derive(Debug, Clone, Copy, Default)]
pub struct FecControlDelta {
    /// Override for the streaming FEC emission interval (packets between FEC frames).
    pub stream_every: Option<usize>,
    /// Override for FEC redundancy in parts-per-million.
    pub redundancy_ppm: Option<u32>,
    /// When true, forces FEC into streaming mode for minimal latency.
    pub force_streaming: bool,
}

/// Per-connection permission flags controlling which stealth actuators the Brain may adjust.
#[derive(Debug, Clone, Copy)]
pub struct BrainRuntimePermissions {
    /// Allow Brain to adjust the ACK-eliciting threshold.
    pub ack_threshold: bool,
    /// Allow Brain to toggle external pacing control.
    pub external_pacing: bool,
    /// Allow Brain to adjust stealth timing jitter.
    pub timing: bool,
    /// Allow Brain to adjust stealth padding parameters.
    pub padding: bool,
    /// Allow Brain to change the browser mimic bias code.
    pub mimic_bias: bool,
    /// Allow Brain to adjust adaptive padding granularity.
    pub granularity: bool,
    /// Allow Brain to switch the congestion control browser profile.
    pub cc_profile: bool,
}

impl Default for BrainRuntimePermissions {
    fn default() -> Self {
        Self {
            ack_threshold: true,
            external_pacing: true,
            timing: true,
            padding: true,
            mimic_bias: true,
            granularity: true,
            cc_profile: true,
        }
    }
}

/// Snapshot of all stealth runtime parameters for a connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StealthRuntimePolicy {
    /// Whether external pacing control is active.
    pub external_pacing: bool,
    /// Whether stealth timing jitter injection is enabled.
    pub timing_enabled: bool,
    /// Maximum timing jitter in microseconds.
    pub timing_max_jitter_us: u32,
    /// Browser mimic bias code (1=Safari, 2=Firefox, 3=Chromium, 4=Android).
    pub mimic_bias: u8,
    /// Adaptive padding granularity in bytes.
    pub adaptive_granularity: u16,
    /// Congestion control browser profile for traffic shaping.
    pub cc_profile: crate::transport::recovery::BrowserProfile,
    /// Whether stealth padding is enabled.
    pub padding_enabled: bool,
    /// Padding strategy (0=off, 1=random, 2=fixed, 3=adaptive, 4=browser-mimic).
    pub padding_strategy: u8,
    /// Maximum padding size in bytes.
    pub padding_max: usize,
}

/// Incremental stealth parameter update emitted by the Brain sensor-fusion engine.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct StealthRuntimeDelta {
    /// New external pacing toggle, if changed.
    pub external_pacing: Option<bool>,
    /// New timing (enabled, max_jitter_us) pair, if changed.
    pub timing: Option<(bool, u32)>,
    /// New browser mimic bias code, if changed.
    pub mimic_bias: Option<u8>,
    /// New adaptive padding granularity in bytes, if changed.
    pub adaptive_granularity: Option<u16>,
    /// New congestion control browser profile, if changed.
    pub cc_profile: Option<crate::transport::recovery::BrowserProfile>,
    /// New padding (enabled, strategy, max_size) triple, if changed.
    pub padding: Option<(bool, u8, usize)>,
}

// ============================================================================
// Transport configuration and types
// ============================================================================

/// Maximum batch size for sendmmsg/recvmmsg - process 64 packets at once!
pub const MAX_BATCH_SIZE: usize = 64;

/// Optimal packet batch size based on L2 cache
pub const OPTIMAL_BATCH_SIZE: usize = 32;

// Core Constants

/// QUIC protocol version (v1)
pub const PROTOCOL_VERSION: u32 = 0x00000001;

/// Maximum connection ID length
pub const MAX_CONN_ID_LEN: usize = 20;
/// Maximum packet number encoding length in bytes (RFC 9000).
pub const MAX_PKT_NUM_LEN: usize = 4;

// Packet type bits are defined within the `packet` module to avoid duplication

/// Congestion control choices supported by the in-tree QUIC transport.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CongestionControlAlgorithm {
    /// TCP New Reno (RFC 6582) - conservative AIMD baseline.
    Reno,
    /// BBR v2 (IETF draft-ietf-ccwg-bbr) - loss-aware model-based CC.
    BBR2,
    /// BBR v3 with stealth browser-profile shaping (default, recommended).
    BBR3,
}

impl AsRef<[u8]> for ConnectionId {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        &self.buf[..self.len as usize]
    }
}

// =========================================================================
// Integration Hooks (no-op unless set)
// =========================================================================

/// Observer interface for low-cost transport telemetry callbacks.
/// Not used unless explicitly set; all hooks are optional at call sites.
pub trait TransportObserver: Send + Sync {
    /// Called when an ACK frame is emitted (ack_delay in quic units)
    fn on_ack(&self, _ack_delay: u64, _ranges: &[(u64, u64)]) {}
    /// Called when a packet is received (post-decrypt)
    fn on_packet_recv(&self, _pn: u64, _pt_len: usize) {}
    /// Called when ECN counters are updated
    fn on_ecn_update(&self, _ect0: u64, _ect1: u64, _ce: u64) {}
    /// Optional policy hook to tune transport parameters based on telemetry
    fn apply_policy(&self, _conn: &mut crate::transport::Connection) {}
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_conn_with_padding(enabled: bool, strategy: u8, max_size: usize) -> Connection {
        let mut cfg = Config::new_with_version(PROTOCOL_VERSION).unwrap();
        cfg.set_stealth_padding(enabled, strategy, max_size);
        // dummy addresses
        let local: std::net::SocketAddr = "127.0.0.1:0".parse().unwrap();
        let peer: std::net::SocketAddr = "127.0.0.1:4433".parse().unwrap();
        let scid = [0u8; 8];
        packet::connect(None, &scid, local, peer, &mut cfg).unwrap()
    }

    #[test]
    fn test_padding_random_bounds() {
        let conn = make_conn_with_padding(true, 1, 64);
        for _ in 0..16 {
            let v = conn.compute_stealth_padding(100, 1000);
            assert!(v <= 64);
        }
    }

    #[test]
    fn test_padding_fixed_exact_max() {
        let conn = make_conn_with_padding(true, 2, 128);
        let v = conn.compute_stealth_padding(200, 1000);
        assert_eq!(v, 128);
        // Budget caps
        let v2 = conn.compute_stealth_padding(200, 10);
        assert_eq!(v2, 10);
    }

    #[test]
    fn test_padding_adaptive_to_next_64() {
        let conn = make_conn_with_padding(true, 3, 64);
        let v = conn.compute_stealth_padding(48, 1000);
        assert_eq!(v, 16); // 48 -> pad 16 to reach 64 boundary
                           // already aligned => 0
        let v2 = conn.compute_stealth_padding(128, 1000);
        assert_eq!(v2, 0);
        // cap by max
        let v3 = conn.compute_stealth_padding(1, 8);
        assert_eq!(v3, 8);
    }

    #[test]
    fn test_padding_browser_mimic_quarter_cap() {
        let conn = make_conn_with_padding(true, 4, 100);
        for _ in 0..16 {
            let v = conn.compute_stealth_padding(500, 1000);
            assert!(v <= 25);
        }
    }
}

// Additional integrated tests to exercise transport public API used by scripts
#[cfg(test)]
mod core_extra_tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    fn addrs() -> (SocketAddr, SocketAddr) {
        let local = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 44330);
        let peer = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 44331);
        (local, peer)
    }

    #[test]
    fn connection_state_establish_teardown() {
        let (local, peer) = addrs();
        let mut cfg = Config::new_with_version(1).expect("config");
        let scid = ConnectionId::from_ref(&[0; MAX_CONN_ID_LEN]);
        let conn = packet::connect(Some("example.com"), scid.as_ref(), local, peer, &mut cfg)
            .expect("connect");
        assert!(conn.max_send_udp_payload_size() > 0);
        assert!(!conn.is_closed());
    }

    #[test]
    fn stream_multiplex_send_two_streams() {
        let (local, peer) = addrs();
        let mut cfg = Config::new_with_version(1).expect("config");
        let scid = ConnectionId::from_ref(&[1; MAX_CONN_ID_LEN]);
        let mut conn =
            packet::connect(Some("sni"), scid.as_ref(), local, peer, &mut cfg).expect("connect");
        let s1 = 1u64;
        let s2 = 3u64;
        let n1 = conn.stream_send(s1, b"hello", false).expect("stream1 send");
        let n2 = conn.stream_send(s2, b"world", true).expect("stream2 send");
        assert!(n1 > 0 && n2 > 0);
    }

    #[test]
    fn flow_control_basic_caps() {
        let (local, peer) = addrs();
        let mut cfg = Config::new_with_version(1).expect("config");
        cfg.set_initial_max_stream_data_bidi_local(1024);
        cfg.set_initial_max_stream_data_bidi_remote(1024);
        let scid = ConnectionId::from_ref(&[2; MAX_CONN_ID_LEN]);
        let mut conn =
            packet::connect(None, scid.as_ref(), local, peer, &mut cfg).expect("connect");
        let s = 7u64;
        let data = vec![0u8; 256];
        let n = conn.stream_send(s, &data, false).expect("send within window");
        assert!(n > 0);
    }

    #[test]
    fn packet_pacing_toggle() {
        let (local, peer) = addrs();
        let mut cfg = Config::new_with_version(1).expect("config");
        let scid = ConnectionId::from_ref(&[3; MAX_CONN_ID_LEN]);
        let mut conn =
            packet::connect(None, scid.as_ref(), local, peer, &mut cfg).expect("connect");
        conn.set_external_pacing(true);
        assert!(conn.external_pacing_enabled());
    }

    #[test]
    fn loss_recovery_ack_threshold() {
        let (local, peer) = addrs();
        let mut cfg = Config::new_with_version(1).expect("config");
        let scid = ConnectionId::from_ref(&[4; MAX_CONN_ID_LEN]);
        let mut conn =
            packet::connect(None, scid.as_ref(), local, peer, &mut cfg).expect("connect");
        conn.set_ack_eliciting_threshold(4);
        assert!(conn.max_send_udp_payload_size() > 0);
    }

    #[test]
    fn connection_migration_path_id_increments() {
        let (local, peer) = addrs();
        let mut cfg = Config::new_with_version(1).expect("config");
        let scid = ConnectionId::from_ref(&[5; MAX_CONN_ID_LEN]);
        let mut conn =
            packet::connect(None, scid.as_ref(), local, peer, &mut cfg).expect("connect");
        let new_local = SocketAddr::new(Ipv4Addr::new(10, 0, 0, 1).into(), 55555);
        let new_peer = SocketAddr::new(Ipv4Addr::new(10, 0, 0, 2).into(), 44444);
        let new_id = conn.migrate(new_local, new_peer).expect("migrate");
        assert!(new_id > 0);
        assert_eq!(conn.path_stats().next().expect("path").peer_addr, peer);
    }

    #[test]
    fn datagram_frames_basic_send_queue_len() {
        let (local, peer) = addrs();
        let mut cfg = Config::new_with_version(1).expect("config");
        cfg.enable_dgram(8, 8);
        let scid = ConnectionId::from_ref(&[6; MAX_CONN_ID_LEN]);
        let mut conn =
            packet::connect(None, scid.as_ref(), local, peer, &mut cfg).expect("connect");
        let buf = vec![0xAB; 32];
        conn.dgram_send(&buf).expect("queue dgram");
        assert!(conn.dgram_send_queue_len() > 0);
    }
}

/// QUIC connection ID with inline storage (max 20 bytes per RFC 9000).
///
/// Avoids heap allocation by storing the ID in a fixed-size buffer on the stack.
#[derive(Clone, Copy)]
pub struct ConnectionId {
    buf: [u8; MAX_CONN_ID_LEN],
    len: u8,
}

impl Default for ConnectionId {
    #[inline]
    fn default() -> Self {
        Self { buf: [0u8; MAX_CONN_ID_LEN], len: 0 }
    }
}

impl std::fmt::Debug for ConnectionId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ConnectionId({:02x?})", self.as_ref())
    }
}

impl PartialEq for ConnectionId {
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        self.as_ref() == other.as_ref()
    }
}

impl Eq for ConnectionId {}

impl std::hash::Hash for ConnectionId {
    #[inline]
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.as_ref().hash(state);
    }
}

/// Information about a received datagram (source / destination / timestamp)
#[derive(Debug, Clone, Copy)]
pub struct RecvInfo {
    /// Source address of the received datagram.
    pub from: SocketAddr,
    /// Destination address of the received datagram.
    pub to: SocketAddr,
    // Keep extensible; add ECN / timestamp if needed
    /// ECN marking from the IP layer, if available.
    pub ecn: Option<EcnMark>,
}

/// Information about a sent datagram
#[derive(Debug, Clone, Copy)]
pub struct SendInfo {
    /// Local address to send from.
    pub from: SocketAddr,
    /// Peer address to send to.
    pub to: SocketAddr,
    /// Pacing-aware send timestamp.
    pub at: Instant,
}

impl ConnectionId {
    /// Creates a ConnectionId from a borrowed slice.
    ///
    /// # Panics
    /// Panics if `data.len() > MAX_CONN_ID_LEN` (20).
    #[inline]
    pub fn from_ref(data: &[u8]) -> Self {
        assert!(
            data.len() <= MAX_CONN_ID_LEN,
            "ConnectionId too long: {} > {}",
            data.len(),
            MAX_CONN_ID_LEN
        );
        let mut buf = [0u8; MAX_CONN_ID_LEN];
        buf[..data.len()].copy_from_slice(data);
        Self { buf, len: data.len() as u8 }
    }

    /// Creates a ConnectionId from a Vec (convenience wrapper).
    #[inline]
    pub fn from_vec(data: Vec<u8>) -> Self {
        Self::from_ref(&data)
    }

    /// Returns true if the ID is empty.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Returns the length in bytes.
    #[inline]
    pub fn len(&self) -> usize {
        self.len as usize
    }

    /// Converts into an owned Vec<u8>.
    #[inline]
    pub fn to_vec(&self) -> Vec<u8> {
        self.as_ref().to_vec()
    }
}

/// Minimum size of a client Initial packet per RFC 9000 Section 14.1 (1200 bytes).
pub const MIN_CLIENT_INITIAL_LEN: usize = 1200;

/// Representative 1-RTT datagram payload size for data-plane AEAD backend selection.
/// Slightly below typical path MTU (1500) minus IP/UDP/QUIC short-header overhead.
pub const TYPICAL_1RTT_PAYLOAD_LEN: usize = 1400;

/// Initial congestion window size in bytes.
pub const INITIAL_WINDOW: usize = 14720;

/// QUIC stream state including send/receive buffers, offsets, and flow control limits.
#[derive(Debug)]
pub struct Stream {
    id: u64,
    #[cfg(not(feature = "stream_ring_buffer"))]
    send_buf: Vec<u8>,
    #[cfg(not(feature = "stream_ring_buffer"))]
    recv_buf: Vec<u8>,
    #[cfg(feature = "stream_ring_buffer")]
    send_ring: StreamRingBuffer,
    #[cfg(feature = "stream_ring_buffer")]
    recv_ring: StreamRingBuffer,
    send_fin: bool,
    recv_fin: bool,
    send_off: u64,
    /// Highest byte offset observed on the receive side (flow control accounting).
    recv_off: u64,
    /// Next contiguous byte offset available for the application to read.
    recv_next: u64,
    /// Final size of the stream once FIN is received (offset + data_len).
    recv_final_size: Option<u64>,
    /// Out-of-order fragments keyed by starting offset.
    recv_frags: BTreeMap<u64, Vec<u8>>,
    priority_urgency: u8,
    #[cfg(any(test, feature = "rust-tests"))]
    priority_incremental: bool,
    // Receive-side flow control (what we allow peer to send to us)
    max_stream_data_rx: u64,
    // Send-side flow control (what peer allows us to send to them)
    max_stream_data_tx: u64,
}

/// Maximum wire overhead for a CRYPTO frame header (type + offset + length varints).
pub const MAX_CRYPTO_OVERHEAD: usize = 8;
/// Maximum wire overhead for a DATAGRAM frame header.
pub const MAX_DGRAM_OVERHEAD: usize = 2;
/// Maximum wire overhead for a STREAM frame header (type + stream_id + offset + length varints).
pub const MAX_STREAM_OVERHEAD: usize = 12;
/// Maximum stream data offset/size per RFC 9000 (2^62).
pub const MAX_STREAM_SIZE: u64 = 1 << 62;

// ============================================================================
// Error Types
// ============================================================================

/// QUIC packet epoch
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum Epoch {
    /// Initial encryption level (connection establishment).
    Initial = 0,
    /// Handshake encryption level (TLS handshake completion).
    Handshake = 1,
    /// Application data encryption level (1-RTT).
    Application = 2,
}

static EPOCHS: [Epoch; 3] = [Epoch::Initial, Epoch::Handshake, Epoch::Application];

impl Epoch {
    /// Returns a slice of epochs within the given inclusive range.
    pub fn epochs(range: std::ops::RangeInclusive<Epoch>) -> &'static [Epoch] {
        &EPOCHS[*range.start() as usize..=*range.end() as usize]
    }

    /// Total number of QUIC packet epochs (Initial, Handshake, Application).
    pub const fn count() -> usize {
        3
    }
}

impl From<Epoch> for usize {
    fn from(e: Epoch) -> Self {
        e as usize
    }
}

impl<T> Index<Epoch> for [T] {
    type Output = T;
    fn index(&self, index: Epoch) -> &Self::Output {
        self.index(usize::from(index))
    }
}

impl<T> IndexMut<Epoch> for [T] {
    fn index_mut(&mut self, index: Epoch) -> &mut Self::Output {
        self.index_mut(usize::from(index))
    }
}

/// QUIC packet type
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PacketType {
    /// Initial packet (long header, unencrypted).
    Initial,
    /// Retry packet sent by server to provide a token.
    Retry,
    /// Handshake packet (long header, handshake keys).
    Handshake,
    /// 0-RTT early data packet (long header, early data keys).
    ZeroRTT,
    /// Version Negotiation packet (no encryption).
    VersionNegotiation,
    /// Short header packet (1-RTT application data).
    Short,
}

/// ECN marking of received UDP datagrams
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EcnMark {
    /// ECT(0) - ECN-Capable Transport codepoint 0.
    Ect0,
    /// ECT(1) - ECN-Capable Transport codepoint 1.
    Ect1,
    /// CE - Congestion Experienced signal.
    Ce,
}

impl PacketType {
    /// Converts an epoch to the corresponding packet type.
    pub fn from_epoch(e: Epoch) -> PacketType {
        match e {
            Epoch::Initial => PacketType::Initial,
            Epoch::Handshake => PacketType::Handshake,
            Epoch::Application => PacketType::Short,
        }
    }

    /// Converts this packet type to the corresponding epoch, if applicable.
    pub fn to_epoch(self) -> Result<Epoch, Error> {
        match self {
            PacketType::Initial => Ok(Epoch::Initial),
            PacketType::ZeroRTT => Ok(Epoch::Application),
            PacketType::Handshake => Ok(Epoch::Handshake),
            PacketType::Short => Ok(Epoch::Application),
            _ => Err(Error::InvalidPacket),
        }
    }
}

/// QUIC packet header
#[derive(Clone, PartialEq, Eq)]
pub struct Header {
    /// Packet type (Initial, Handshake, Short, etc.).
    pub ty: PacketType,
    /// QUIC version field (0 for short header packets).
    pub version: u32,
    /// Destination Connection ID.
    pub dcid: ConnectionId,
    /// Source Connection ID (empty for short header packets).
    pub scid: ConnectionId,
    /// Decoded packet number.
    pub pkt_num: u64,
    /// On-wire packet number encoding length in bytes (1-4).
    pub pkt_num_len: usize,
    /// Token from Initial or Retry packets.
    pub token: Option<Vec<u8>>,
    /// Supported versions from Version Negotiation packets.
    pub versions: Option<Vec<u32>>,
    /// Key phase bit for short header packets (1-RTT key rotation).
    pub key_phase: bool,
}

/// Transport-layer error codes.
#[derive(Debug, Clone, PartialEq)]
pub enum Error {
    /// Operation would block
    Done,
    /// FEC error
    Fec,
    /// Generic transport backend error
    Transport,

    /// Buffer is too short
    BufferTooShort,

    /// Unknown version
    UnknownVersion,

    /// Invalid frame
    InvalidFrame,

    /// Invalid packet
    InvalidPacket,

    /// Invalid state
    InvalidState,

    /// Invalid stream state
    InvalidStreamState,

    /// Invalid transport parameter
    InvalidTransportParam,

    /// Crypto error
    CryptoFail,

    /// TLS handshake error
    TlsFail,

    /// Flow control error
    FlowControl,

    /// Stream limit error
    StreamLimit,

    /// Stream stopped
    StreamStopped,

    /// Stream was reset by peer
    StreamReset(u64, u64),

    /// Final size error
    FinalSize,

    /// Connection ID limit error
    IdLimit,

    /// Out of identifiers
    OutOfIdentifiers,

    /// Key update error
    KeyUpdate,

    /// AEAD limit reached
    AeadLimitReached,

    /// No viable path
    NoViablePath,

    /// Connection timeout
    TimedOut,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl std::error::Error for Error {}

// ============================================================================
// Frame Types
// ============================================================================

/// QUIC frame types
#[derive(Clone, Debug, PartialEq)]
pub enum Frame<'a> {
    /// PADDING frame (RFC 9000 Section 19.1).
    Padding { len: usize },
    /// PING frame, optionally used as an MTU probe (RFC 9000 Section 19.2).
    Ping { mtu_probe: Option<usize> },
    /// ACK frame acknowledging received packets (RFC 9000 Section 19.3).
    Ack {
        ack_delay: u64,
        ranges: Vec<(u64, u64)>, // Simplified range set
        ecn_counts: Option<EcnCounts>,
    },
    /// RESET_STREAM frame abruptly terminating send-side of a stream.
    ResetStream { stream_id: u64, error_code: u64, final_size: u64 },
    /// STOP_SENDING frame requesting the peer stop sending on a stream.
    StopSending { stream_id: u64, error_code: u64 },
    /// CRYPTO frame carrying TLS handshake data.
    Crypto { offset: u64, data: Cow<'a, [u8]> },
    /// NEW_TOKEN frame providing address validation tokens.
    NewToken { token: Cow<'a, [u8]> },
    /// STREAM frame carrying application data on a stream.
    Stream { stream_id: u64, offset: u64, data: Cow<'a, [u8]>, fin: bool },
    /// MAX_DATA frame advertising increased connection-level flow control limit.
    MaxData { max: u64 },
    /// MAX_STREAM_DATA frame advertising increased per-stream flow control limit.
    MaxStreamData { stream_id: u64, max: u64 },
    /// MAX_STREAMS frame for bidirectional streams.
    MaxStreamsBidi { max: u64 },
    /// MAX_STREAMS frame for unidirectional streams.
    MaxStreamsUni { max: u64 },
    /// DATA_BLOCKED frame signaling connection-level flow control blocking.
    DataBlocked { limit: u64 },
    /// STREAM_DATA_BLOCKED frame signaling per-stream flow control blocking.
    StreamDataBlocked { stream_id: u64, limit: u64 },
    /// STREAMS_BLOCKED frame for bidirectional streams.
    StreamsBlockedBidi { limit: u64 },
    /// STREAMS_BLOCKED frame for unidirectional streams.
    StreamsBlockedUni { limit: u64 },
    /// NEW_CONNECTION_ID frame issuing a new CID with stateless reset token.
    NewConnectionId {
        seq_num: u64,
        retire_prior_to: u64,
        conn_id: Cow<'a, [u8]>,
        reset_token: [u8; 16],
    },
    /// RETIRE_CONNECTION_ID frame retiring a previously issued CID.
    RetireConnectionId { seq_num: u64 },
    /// PATH_CHALLENGE frame for path validation.
    PathChallenge { data: [u8; 8] },
    /// PATH_RESPONSE frame echoing a PATH_CHALLENGE.
    PathResponse { data: [u8; 8] },
    /// CONNECTION_CLOSE frame at the QUIC transport level.
    ConnectionClose { error_code: u64, frame_type: u64, reason: Cow<'a, [u8]> },
    /// APPLICATION_CLOSE frame carrying an application-level error.
    ApplicationClose { error_code: u64, reason: Cow<'a, [u8]> },
    /// DATAGRAM frame carrying unreliable application data (RFC 9221).
    Datagram { data: Cow<'a, [u8]> },
    /// Parsed datagram header only (length known, data not yet read).
    DatagramHeader { length: usize },
}

/// ECN counter values carried in ACK frames (RFC 9000 Section 19.3.2).
#[derive(Debug, Clone, PartialEq)]
pub struct EcnCounts {
    /// Count of packets received with ECT(0) codepoint.
    pub ect0: u64,
    /// Count of packets received with ECT(1) codepoint.
    pub ect1: u64,
    /// Count of packets received with CE (Congestion Experienced) codepoint.
    pub ce: u64,
}

// ============================================================================
// Random Number Generation
// ============================================================================

/// Cumulative QUIC connection statistics (packets, bytes, RTT, CC state).
#[derive(Debug, Clone, Default)]
pub struct Stats {
    /// Number of QUIC packets received
    pub recv: usize,

    /// Number of QUIC packets sent
    pub sent: usize,

    /// Number of QUIC packets lost
    pub lost: usize,

    /// Number of bytes received
    pub recv_bytes: u64,

    /// Number of bytes sent
    pub sent_bytes: u64,

    /// Number of stream bytes received
    pub stream_recv_bytes: u64,

    /// Number of stream bytes sent
    pub stream_sent_bytes: u64,

    /// Estimated round-trip time
    pub rtt: Duration,

    /// Congestion window size
    pub cwnd: usize,

    /// Bytes in flight
    pub bytes_in_flight: usize,

    /// Delivery rate estimate
    pub delivery_rate: u64,
    /// Total number of bytes sent acked
    pub acked_bytes: u64,
    /// Total number of bytes sent lost
    pub lost_bytes: u64,
    /// The number of QUIC packets that were marked as lost but later acked
    pub spurious_lost: usize,
    /// The number of sent QUIC packets with retransmitted data
    pub retrans: usize,
    /// The number of DATAGRAM frames received
    pub dgram_recv: usize,
    /// The number of DATAGRAM frames sent
    pub dgram_sent: usize,
    /// The number of known paths for the connection
    pub paths_count: usize,
    /// The total number of PATH_CHALLENGE frames that were received
    pub path_challenge_rx_count: u64,
    /// The number of streams reset by local
    pub reset_stream_count_local: u64,
    /// The number of streams stopped by local
    pub stopped_stream_count_local: u64,
    /// The number of streams reset by remote
    pub reset_stream_count_remote: u64,
    /// The number of streams stopped by remote
    pub stopped_stream_count_remote: u64,
    /// Total duration during which bytes were in flight
    pub bytes_in_flight_duration: Duration,
    /// The number of stream bytes that were retransmitted
    pub stream_retrans_bytes: u64,
}

/// Path statistics
#[derive(Debug, Clone)]
pub struct PathStats {
    /// Bytes received on this path.
    pub recv: u64,
    /// Bytes sent on this path.
    pub sent: u64,
    /// Packets lost on this path.
    pub lost: u64,
    /// Smoothed round-trip time for this path.
    pub rtt: std::time::Duration,
    /// Congestion window size for this path in bytes.
    pub cwnd: usize,
    /// Estimated delivery rate for this path in bytes/sec.
    pub delivery_rate: u64,
    /// Local socket address for this path.
    pub local_addr: SocketAddr,
    /// Peer socket address for this path.
    pub peer_addr: SocketAddr,
}

impl Default for PathStats {
    fn default() -> Self {
        Self {
            recv: 0,
            sent: 0,
            lost: 0,
            rtt: std::time::Duration::from_millis(0),
            cwnd: 0,
            delivery_rate: 0,
            local_addr: std::net::SocketAddr::from((std::net::Ipv4Addr::UNSPECIFIED, 0)),
            peer_addr: std::net::SocketAddr::from((std::net::Ipv4Addr::UNSPECIFIED, 0)),
        }
    }
}
