//! Transport contracts shared by protocol and runtime layers.
//!
//! These values deliberately contain no connection, FEC, stealth runtime, or optimizer behavior.
//! They form the stable data boundary that later transport and FEC workspace leaves can consume
//! without importing the monolithic root crate; the Brain configuration uses only the shared
//! environment snapshot contract, and the MASQUE queue is a bounded ownership contract.

use std::borrow::Cow;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

#[doc(hidden)]
pub mod brain;
#[doc(hidden)]
pub mod fastpath;
#[doc(hidden)]
pub mod h3;
#[doc(hidden)]
pub mod handlers;
#[doc(hidden)]
pub mod masque;
#[doc(hidden)]
pub mod observer;
#[doc(hidden)]
pub mod path;
#[doc(hidden)]
pub mod protocol;
#[doc(hidden)]
pub mod runtime;
#[doc(hidden)]
pub mod stealth;
#[doc(hidden)]
pub mod traffic;
#[doc(hidden)]
pub mod tun;
pub use brain::StealthBrainConfig;
pub use fastpath::FastpathMode;
pub use handlers::{CapsuleHandler, DatagramHandler};
pub use masque::{MasqueDownlinkQueue, MasqueDownlinkQueueReject};
pub use observer::{TransportObserver, TransportPolicyError, TransportPolicyTarget};
pub use path::PathEvent;
pub use protocol::{Epoch, Header, PacketType, TransportError, QUIC_FIXED_BIT};
pub use runtime::{BrainRuntimePermissions, FecControlDelta, IntelligentLevelHints};
pub use stealth::{BrowserProfile, StealthRuntimeDelta, StealthRuntimePolicy};
pub use traffic::{TrafficAnalysisDefense, TrafficAnalysisPolicy};
pub use tun::{
    register_tun_factory, registered_tun_factory, tun_capabilities, validate_tun_config,
    TunCapabilities, TunConfig, TunDevice, TunError, TunFactory, TunReadContract, TUN_IPV6_MIN_MTU,
    TUN_MIN_MTU, TUN_PACKET_QUEUE_CAPACITY,
};

/// QUIC encryption levels used by the TLS and transport handshake paths.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum QuicEncryptionLevel {
    /// Initial encryption level used during connection establishment.
    Initial = 0,
    /// 0-RTT early-data encryption level.
    EarlyData = 1,
    /// Handshake encryption level used during TLS negotiation.
    Handshake = 2,
    /// Application-data encryption level after the handshake.
    Application = 3,
}

/// Maximum connection ID length from RFC 9000.
pub const MAX_CONN_ID_LEN: usize = 20;

/// Congestion-control choices supported by the in-tree QUIC transport.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CongestionControlAlgorithm {
    /// TCP New Reno (RFC 6582) - conservative AIMD baseline.
    Reno,
    /// CUBIC (RFC 9438) - cubic window growth with TCP friendliness.
    Cubic,
    /// BBR v2 (IETF draft-ietf-ccwg-bbr) - loss-aware model-based CC.
    BBR2,
    /// BBR v3 with stealth browser-profile shaping (default, recommended).
    BBR3,
}

/// QUIC connection ID with inline storage.
///
/// The wire format permits at most 20 bytes, so a fixed-size buffer avoids heap allocation for
/// every packet's connection identifiers while preserving the existing root API semantics.
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
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "ConnectionId({:02x?})", self.as_ref())
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

impl AsRef<[u8]> for ConnectionId {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        &self.buf[..self.len as usize]
    }
}

impl ConnectionId {
    /// Creates a connection ID from a borrowed slice.
    ///
    /// # Panics
    /// Panics if `data.len() > MAX_CONN_ID_LEN`.
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

    /// Creates a connection ID from an owned vector.
    #[inline]
    pub fn from_vec(data: Vec<u8>) -> Self {
        Self::from_ref(&data)
    }

    /// Returns true when the ID is empty.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Returns the ID length in bytes.
    #[inline]
    pub fn len(&self) -> usize {
        self.len as usize
    }

    /// Converts the ID into an owned vector.
    #[inline]
    pub fn to_vec(&self) -> Vec<u8> {
        self.as_ref().to_vec()
    }
}

/// ECN marking of a received UDP datagram.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EcnMark {
    /// ECT(0) - ECN-capable transport codepoint 0.
    Ect0,
    /// ECT(1) - ECN-capable transport codepoint 1.
    Ect1,
    /// CE - Congestion Experienced signal.
    Ce,
}

/// Information about a received datagram.
#[derive(Debug, Clone, Copy)]
pub struct RecvInfo {
    /// Source address of the datagram.
    pub from: SocketAddr,
    /// Destination address of the datagram.
    pub to: SocketAddr,
    /// ECN marking from the IP layer, if available.
    pub ecn: Option<EcnMark>,
}

/// Information about a sent datagram.
#[derive(Debug, Clone, Copy)]
pub struct SendInfo {
    /// Local address used for sending.
    pub from: SocketAddr,
    /// Peer address targeted by the datagram.
    pub to: SocketAddr,
    /// Pacing-aware send timestamp.
    pub at: Instant,
    /// Whether the datagram contains congestion-controlled frames.
    pub congestion_controlled: bool,
    /// Whether the datagram exclusively carries path validation frames.
    pub path_control: bool,
}

/// QUIC frame types.
#[derive(Clone, Debug, PartialEq)]
pub enum Frame<'a> {
    /// PADDING frame (RFC 9000 Section 19.1).
    Padding { len: usize },
    /// PING frame, optionally used as an MTU probe (RFC 9000 Section 19.2).
    Ping { mtu_probe: Option<usize> },
    /// ACK frame acknowledging received packets (RFC 9000 Section 19.3).
    Ack { ack_delay: u64, ranges: Vec<(u64, u64)>, ecn_counts: Option<EcnCounts> },
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

/// Path statistics.
#[derive(Debug, Clone)]
pub struct PathStats {
    /// Bytes received on this path.
    pub recv: u64,
    /// Bytes sent on this path.
    pub sent: u64,
    /// Packets lost on this path.
    pub lost: u64,
    /// Smoothed round-trip time for this path.
    pub rtt: Duration,
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
            rtt: Duration::from_millis(0),
            cwnd: 0,
            delivery_rate: 0,
            local_addr: SocketAddr::from((std::net::Ipv4Addr::UNSPECIFIED, 0)),
            peer_addr: SocketAddr::from((std::net::Ipv4Addr::UNSPECIFIED, 0)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn connection_id_preserves_bytes_and_hash_identity() {
        let id = ConnectionId::from_ref(b"transport-id");
        assert_eq!(id.len(), 12);
        assert_eq!(id.as_ref(), b"transport-id");
        assert_eq!(id.to_vec(), b"transport-id");
        assert!(!id.is_empty());

        let mut ids = HashSet::new();
        assert!(ids.insert(id));
        assert!(ids.contains(&ConnectionId::from_vec(b"transport-id".to_vec())));
    }

    #[test]
    fn connection_id_default_is_empty_and_max_length_is_accepted() {
        assert!(ConnectionId::default().is_empty());
        let max = ConnectionId::from_ref(&[0xA5; MAX_CONN_ID_LEN]);
        assert_eq!(max.len(), MAX_CONN_ID_LEN);
        assert_eq!(max.as_ref(), &[0xA5; MAX_CONN_ID_LEN]);
    }

    #[test]
    fn connection_id_rejects_oversized_input() {
        let result =
            std::panic::catch_unwind(|| ConnectionId::from_ref(&[0u8; MAX_CONN_ID_LEN + 1]));
        assert!(result.is_err());
    }

    #[test]
    fn datagram_contracts_retain_addresses_and_flags() {
        let from = (IpAddr::V4(Ipv4Addr::LOCALHOST), 4000).into();
        let to = (IpAddr::V4(Ipv4Addr::LOCALHOST), 4433).into();
        let recv = RecvInfo { from, to, ecn: Some(EcnMark::Ce) };
        assert_eq!(recv.from, from);
        assert_eq!(recv.to, to);
        assert_eq!(recv.ecn, Some(EcnMark::Ce));

        let send = SendInfo {
            from,
            to,
            at: Instant::now(),
            congestion_controlled: false,
            path_control: true,
        };
        assert!(!send.congestion_controlled);
        assert!(send.path_control);
    }

    #[test]
    fn frame_contract_retains_borrowed_payload_and_ecn_counts() {
        let frame = Frame::Ack {
            ack_delay: 7,
            ranges: vec![(10, 12)],
            ecn_counts: Some(EcnCounts { ect0: 1, ect1: 2, ce: 3 }),
        };
        assert_eq!(
            frame,
            Frame::Ack {
                ack_delay: 7,
                ranges: vec![(10, 12)],
                ecn_counts: Some(EcnCounts { ect0: 1, ect1: 2, ce: 3 }),
            }
        );

        let payload = [0xA5, 0x5A];
        let stream =
            Frame::Stream { stream_id: 3, offset: 9, data: Cow::Borrowed(&payload), fin: true };
        assert!(
            matches!(stream, Frame::Stream { data, fin: true, .. } if data.as_ref() == payload)
        );
    }

    #[test]
    fn statistics_contracts_preserve_defaults_and_addresses() {
        let stats = Stats::default();
        assert_eq!(stats.recv, 0);
        assert_eq!(stats.bytes_in_flight_duration, Duration::ZERO);

        let path = PathStats::default();
        assert_eq!(path.recv, 0);
        assert_eq!(path.rtt, Duration::ZERO);
        assert_eq!(path.local_addr, SocketAddr::from((std::net::Ipv4Addr::UNSPECIFIED, 0)));
        assert_eq!(path.peer_addr, SocketAddr::from((std::net::Ipv4Addr::UNSPECIFIED, 0)));
    }

    #[test]
    fn quic_encryption_levels_keep_wire_discriminants_and_order() {
        assert_eq!(QuicEncryptionLevel::Initial as u8, 0);
        assert_eq!(QuicEncryptionLevel::EarlyData as u8, 1);
        assert_eq!(QuicEncryptionLevel::Handshake as u8, 2);
        assert_eq!(QuicEncryptionLevel::Application as u8, 3);
        assert_ne!(QuicEncryptionLevel::EarlyData, QuicEncryptionLevel::Application);
    }
}
