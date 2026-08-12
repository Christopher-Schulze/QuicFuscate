pub use qf_transport_types::{
    BrainRuntimePermissions, BrowserProfile, CongestionControlAlgorithm, ConnectionId, EcnCounts,
    EcnMark, Epoch, FecControlDelta, Frame, Header, PacketType, PathStats, RecvInfo, SendInfo,
    Stats, StealthRuntimeDelta, StealthRuntimePolicy, TransportError as Error, TransportObserver,
    TransportPolicyError, TransportPolicyTarget, MAX_CONN_ID_LEN,
};
pub use qf_transport_version::{is_supported_version, PROTOCOL_VERSION, PROTOCOL_VERSION_V2};
use std::collections::BTreeMap;

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
/// NAT traversal: STUN (RFC 5389), TURN (RFC 5766), and ICE (RFC 8445).
pub mod nat;
/// QUIC packet header parsing, protection, and encryption.
pub mod packet;
/// Multipath connection management (TODO-449): per-path state and selection.
pub mod path;
/// Path selection scheduler for multipath send distribution (TODO-449).
pub mod path_scheduler;
/// Packet number spaces, connection IDs, varint codec, range sets, and RNG.
pub mod pn;
/// Loss recovery and congestion control integration.
pub mod recovery;
/// High-performance UDP send/recv with GSO/GRO and batch I/O.
pub mod udpfast;
/// QUIC version mapping, negotiation state, downgrade protection, and greasing.
pub mod version;
#[cfg(test)]
mod xdp;

pub use anti_replay::{AntiReplayConfig, StrikeRegister};
pub use config::{
    Config, MigrationPolicy, MigrationProbeTarget, NatDiscoveryReason, NatTraversalConfig,
    NatTraversalMode, PmtuPolicy,
};
#[cfg(feature = "stream_ring_buffer")]
pub use connection::StreamRingBuffer;
#[cfg(feature = "benches")]
pub use connection::{
    bench_paired_1rtt_connections, bench_paired_1rtt_connections_stealth, bench_retry_case,
    BenchConnectionPair, BenchRetryCase,
};
pub use connection::{Connection, PathEvent};
pub use nat::{IceAgent, NatPathDiscovery, StunClient, TurnClient};
pub use pn::{cid, pnspace, rand, range_buf, ranges, varint};
/// Best-effort socket capability setup shared across runtime hotpaths.
#[doc(hidden)]
pub fn init_socket_acceleration(socket: &std::net::UdpSocket) -> std::io::Result<()> {
    let gso_enabled =
        crate::optimize::udp::UdpGsoConfig::enable(socket).map(|cfg| cfg.enabled).unwrap_or(false);

    log::info!("Network acceleration initialized:");
    log::info!("  GSO: {}", gso_enabled);

    Ok(())
}

/// Best-effort socket capability setup for callers that own only a raw socket fd.
#[cfg(target_os = "linux")]
#[doc(hidden)]
pub(crate) fn init_socket_acceleration_fd(socket_fd: std::os::fd::RawFd) -> std::io::Result<()> {
    let gso_enabled = crate::optimize::udp::UdpGsoConfig::enable_fd(socket_fd)
        .map(|cfg| cfg.enabled)
        .unwrap_or(false);

    log::info!("Network acceleration initialized:");
    log::info!("  GSO: {}", gso_enabled);

    Ok(())
}

// ============================================================================
// Transport configuration and types
// ============================================================================

/// Maximum batch size for sendmmsg/recvmmsg - process 64 packets at once!
pub const MAX_BATCH_SIZE: usize = 64;

/// Optimal packet batch size based on L2 cache
pub const OPTIMAL_BATCH_SIZE: usize = 32;

// Core Constants

/// Maximum packet number encoding length in bytes (RFC 9000).
pub const MAX_PKT_NUM_LEN: usize = 4;

// =========================================================================
// Integration Hooks (no-op unless set)
// =========================================================================

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

    fn make_conn_with_defense(mode: config::TrafficAnalysisDefense) -> Connection {
        let mut cfg = Config::new_with_version(PROTOCOL_VERSION).unwrap();
        cfg.set_traffic_analysis_defense(mode);
        // Set a low padding rate to prove FullPadding ignores it.
        cfg.set_stealth_padding_rate(0);
        cfg.set_stealth_padding(true, 1, 64);
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
    fn test_padding_adaptive_non_power_of_two_granularity() {
        let mut cfg = Config::new_with_version(PROTOCOL_VERSION).unwrap();
        cfg.set_stealth_padding(true, 3, 128);
        cfg.set_stealth_adaptive_granularity(30);
        let local: std::net::SocketAddr = "127.0.0.1:0".parse().unwrap();
        let peer: std::net::SocketAddr = "127.0.0.1:4433".parse().unwrap();
        let scid = [0u8; 8];
        let conn = packet::connect(None, &scid, local, peer, &mut cfg).unwrap();

        assert_eq!(conn.compute_stealth_padding(44, 1000), 16);
        assert_eq!(conn.compute_stealth_padding(60, 1000), 0);
        assert_eq!(conn.compute_stealth_padding(61, 8), 8);
    }

    #[test]
    fn test_padding_browser_mimic_quarter_cap() {
        let conn = make_conn_with_padding(true, 4, 100);
        for _ in 0..16 {
            let v = conn.compute_stealth_padding(500, 1000);
            assert!(v <= 25);
        }
    }

    // --- Traffic analysis defense (TODO-455) ---

    #[test]
    fn test_full_padding_pads_all_packets_regardless_of_rate() {
        // FullPadding mode must pad every packet to the full budget, ignoring
        // stealth_padding_rate (set to 0 here, which would skip all padding in
        // the legacy Off path).
        let conn = make_conn_with_defense(config::TrafficAnalysisDefense::FullPadding);
        for _ in 0..32 {
            // Various payload sizes — every call must return the full budget.
            let v = conn.compute_stealth_padding(1, 1000);
            assert_eq!(v, 1000, "FullPadding must pad to full budget");
            let v = conn.compute_stealth_padding(500, 800);
            assert_eq!(v, 800, "FullPadding must pad to full budget");
            let v = conn.compute_stealth_padding(0, 64);
            assert_eq!(v, 64, "FullPadding must pad to full budget even for empty payload");
        }
    }

    #[test]
    fn test_constant_rate_pads_all_packets_regardless_of_rate() {
        let conn = make_conn_with_defense(config::TrafficAnalysisDefense::ConstantRate);
        for _ in 0..16 {
            let v = conn.compute_stealth_padding(100, 512);
            assert_eq!(v, 512, "ConstantRate must pad to full budget at the compute layer");
        }
    }

    #[test]
    fn test_off_mode_preserves_probabilistic_padding() {
        // Off mode with rate 0 should never pad (legacy behavior preserved).
        let conn = make_conn_with_defense(config::TrafficAnalysisDefense::Off);
        for _ in 0..32 {
            let v = conn.compute_stealth_padding(100, 1000);
            assert_eq!(v, 0, "Off mode with rate 0 must not pad");
        }
    }

    // --- QUIC version negotiation (TODO-453) ---

    #[test]
    fn test_is_supported_version_recognizes_v1_and_v2() {
        assert!(is_supported_version(PROTOCOL_VERSION));
        assert!(is_supported_version(PROTOCOL_VERSION_V2));
        assert!(!is_supported_version(0x00000002));
        assert!(!is_supported_version(0xdeadbeef));
        assert!(!is_supported_version(0));
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
/// Maximum UDP datagrams emitted before yielding to receive-side work.
pub const UDP_DATAGRAM_BURST_LIMIT: usize = 64;
/// Requested kernel buffer per UDP direction for sustained tunnel traffic.
pub const UDP_SOCKET_BUFFER_BYTES: usize = 2 * 1024 * 1024;
