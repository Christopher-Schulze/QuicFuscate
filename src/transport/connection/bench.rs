use super::*;

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
/// Build a matched pair using the real rustls standard 1-RTT packet and header keys.
pub fn bench_paired_standard_1rtt_connections(
    suite: crate::qftls::StandardCipherSuite,
) -> BenchConnectionPair {
    let mut pair = bench_paired_1rtt_connections();
    let (client_keys, server_keys) = crate::qftls::bench_standard_one_rtt_key_bundles(suite);
    crate::qftls::QuicTlsKeyInstaller::install_one_rtt_keys(
        pair.client.crypto.as_ref(),
        client_keys,
    );
    crate::qftls::QuicTlsKeyInstaller::install_one_rtt_keys(
        pair.server.crypto.as_ref(),
        server_keys,
    );
    pair.client.refresh_short_header_tag_reserve();
    pair.server.refresh_short_header_tag_reserve();
    pair
}

#[cfg(any(test, feature = "benches"))]
/// Build a matched client/server pair for 1-RTT benches with stealth knobs toggled.
#[allow(clippy::expect_used)]
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
        Connection::new_client(&client_scid, local_client, peer_client, config.clone())
            .expect("valid benchmark client configuration");
    let mut server = Connection::new_server(&server_scid, local_server, peer_server, config)
        .expect("valid benchmark server configuration");

    client.set_initial_dcid(ConnectionId::from_ref(&server_scid));
    server.set_initial_dcid(ConnectionId::from_ref(&server_scid));
    server.set_original_dcid(ConnectionId::from_ref(&server_scid));
    server.set_destination_cid(ConnectionId::from_ref(&client_scid));

    {
        let mut crypto = client.crypto.write();
        crypto
            .set_write_secret(Level::OneRTT, Algorithm::AES128_GCM, &client_write)
            .expect("valid client write secret");
        crypto
            .set_read_secret(Level::OneRTT, Algorithm::AES128_GCM, &server_write)
            .expect("valid server read secret");
    }
    client.refresh_short_header_tag_reserve();
    {
        let mut crypto = server.crypto.write();
        crypto
            .set_write_secret(Level::OneRTT, Algorithm::AES128_GCM, &server_write)
            .expect("valid server write secret");
        crypto
            .set_read_secret(Level::OneRTT, Algorithm::AES128_GCM, &client_write)
            .expect("valid client read secret");
    }
    server.refresh_short_header_tag_reserve();

    client.is_established = true;
    server.is_established = true;
    client.test_only_transport_fixture = true;
    server.test_only_transport_fixture = true;
    client.stats.recv = 1;
    server.stats.recv = 1;
    client.stats.sent = 1;
    server.stats.sent = 1;

    let recv_info = RecvInfo { from: peer_server, to: local_server, ecn: None };
    BenchConnectionPair { client, server, recv_info }
}

#[cfg(feature = "benches")]
#[allow(clippy::expect_used)]
/// Measure a fresh rustls QUIC handshake through the in-memory transport packet pump.
/// The shared benchmark identity (`bench_identity_ca_path`) covers the
/// per-iteration `*.bench.example` SNI, so the client runs full webpki verification
/// and the unique server name prevents TLS session resumption between
/// iterations.
pub fn bench_rustls_quic_handshake_latency(iteration: u64) -> Duration {
    use std::net::{Ipv4Addr, SocketAddr};

    let client_addr = SocketAddr::from((Ipv4Addr::LOCALHOST, 29_101));
    let server_addr = SocketAddr::from((Ipv4Addr::LOCALHOST, 29_102));
    let client_scid = b"qf-bench-client";
    let server_scid = b"qf-bench-server";
    let ca_path = crate::qftls::bench_identity_ca_path();
    let mut client_config =
        Config::new_with_version(crate::transport::PROTOCOL_VERSION).expect("client bench config");
    client_config.load_verify_locations_from_file(ca_path).expect("client benchmark CA bundle");
    let mut server_config =
        Config::new_with_version(crate::transport::PROTOCOL_VERSION).expect("server bench config");

    let mut client = Connection::new_client(client_scid, client_addr, server_addr, client_config)
        .expect("valid benchmark client");
    client.set_initial_dcid(ConnectionId::from_ref(server_scid));
    let mut server = packet::accept(
        server_scid,
        Some(server_scid),
        server_addr,
        client_addr,
        &mut server_config,
    )
    .expect("accept benchmark server");
    server.set_destination_cid(ConnectionId::from_ref(client_scid));

    let environment =
        Arc::new(crate::env_utils::EnvSnapshot::from_pairs([("QUICFUSCATE_TLS_COVER", "0")]));
    client.set_environment_snapshot(Arc::clone(&environment));
    server.set_environment_snapshot(environment);
    client.enable_tls("benchmark").expect("enable benchmark client TLS");
    server.enable_tls("benchmark").expect("enable benchmark server TLS");

    let sni = format!("qf-bench-{:016x}.bench.example", iteration);
    let mut profile = crate::qftls::TlsProfile::chrome_130();
    profile.timing_jitter = None;
    profile.sni = Some(sni.clone());
    client.configure_tls(&profile, &sni).expect("configure benchmark client TLS");
    server.configure_tls(&profile, &sni).expect("configure benchmark server TLS");

    let client_to_server = RecvInfo { from: client_addr, to: server_addr, ecn: None };
    let server_to_client = RecvInfo { from: server_addr, to: client_addr, ecn: None };
    let mut client_packet = [0u8; 4096];
    let mut server_packet = [0u8; 4096];
    let started = Instant::now();
    for _ in 0..64 {
        let mut progressed = false;
        match client.send(&mut client_packet) {
            Ok((length, _)) => {
                server
                    .recv(&mut client_packet[..length], &client_to_server)
                    .expect("open client benchmark flight");
                progressed = true;
            }
            Err(crate::error::ConnectionError::Done) => {}
            Err(error) => panic!("client benchmark flight failed: {error:?}"),
        }
        match server.send(&mut server_packet) {
            Ok((length, _)) => {
                client
                    .recv(&mut server_packet[..length], &server_to_client)
                    .expect("open server benchmark flight");
                progressed = true;
            }
            Err(crate::error::ConnectionError::Done) => {}
            Err(error) => panic!("server benchmark flight failed: {error:?}"),
        }
        if client.tls_handshake_complete() && server.tls_handshake_complete() {
            return started.elapsed();
        }
        assert!(progressed, "in-memory TLS handshake stalled");
    }
    panic!("in-memory TLS handshake exceeded the bounded packet pump")
}

#[cfg(feature = "benches")]
/// Client and authenticated Retry packet for receive-path Criterion benchmarks.
pub struct BenchRetryCase {
    pub client: Connection,
    pub packet: Vec<u8>,
    pub recv_info: RecvInfo,
}

#[cfg(feature = "benches")]
/// Build a client and valid Retry packet without opening a socket.
#[allow(clippy::expect_used)]
pub fn bench_retry_case() -> BenchRetryCase {
    use std::net::{Ipv4Addr, SocketAddr};

    let local = SocketAddr::from((Ipv4Addr::LOCALHOST, 29111));
    let peer = SocketAddr::from((Ipv4Addr::LOCALHOST, 29112));
    let config =
        Config::new_with_version(crate::transport::PROTOCOL_VERSION).expect("bench config");
    let mut client = Connection::new_client(b"retry-client", local, peer, config)
        .expect("valid benchmark client configuration");
    let original_dcid = ConnectionId::from_ref(b"retry-original");
    client.set_initial_dcid(original_dcid);

    let header = packet::Header {
        ty: PacketType::Retry,
        version: crate::transport::PROTOCOL_VERSION,
        dcid: client.scid.as_ref().to_vec(),
        scid: b"retry-server".to_vec(),
        pkt_num: 0,
        pkt_num_len: 0,
        token: Some(vec![0x10, 0x20, 0x30, 0x40]),
        versions: None,
        key_phase: false,
    };
    let mut storage = [0u8; 256];
    let header_len = packet::format_header(&header, &mut storage).expect("format Retry header");
    let mut packet = storage[..header_len].to_vec();
    packet::append_retry_tag(
        &mut packet,
        original_dcid.as_ref(),
        crate::transport::PROTOCOL_VERSION,
    )
    .expect("append Retry integrity tag");

    let recv_info = RecvInfo { from: peer, to: local, ecn: None };
    BenchRetryCase { client, packet, recv_info }
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
    pub fn bench_compute_stealth_padding(&mut self, cur_pt_len: usize, budget: usize) -> usize {
        self.compute_stealth_padding(cur_pt_len, budget)
    }

    /// Configure Brain runtime gates for transport/brain benchmarks.
    pub fn bench_set_brain_runtime(
        &mut self,
        permissions: crate::transport::BrainRuntimePermissions,
    ) {
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
