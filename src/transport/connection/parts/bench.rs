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
