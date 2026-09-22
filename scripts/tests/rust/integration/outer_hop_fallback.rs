//! TODO-1063 acceptance: after the direct UDP dial is blackholed, the armed
//! outer hop carries the inner QUIC connection through a local MASQUE relay.
//!
//! This test owns the post-fallback topology directly (relay -> exit) because
//! the pre-fallback dial and its reachability classifier are covered by the
//! engine unit tests. Everything runs on loopback with real QUIC connections
//! and a real `MasqueRelayOwner` UDP association; nothing touches a public
//! network.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use quicfuscate::core::{MasqueFlowPurpose, MasqueRelayResponseQueue, QuicFuscateConnection};
use quicfuscate::engine::EngineConfig;
use quicfuscate::implementations::client::ClientConnection;
use quicfuscate::implementations::server::masque_relay::{
    MasqueRelayOwner, MasqueRelayPolicy, RelayCidr,
};
use quicfuscate::transport::packet::parse_header;
use quicfuscate::transport::{Config, ConnectionId, PROTOCOL_VERSION};

struct ScopedEnvVar {
    key: &'static str,
    previous: Option<String>,
}

impl ScopedEnvVar {
    fn set(key: &'static str, value: &str) -> Self {
        let previous = std::env::var(key).ok();
        std::env::set_var(key, value);
        Self { key, previous }
    }
}

impl Drop for ScopedEnvVar {
    fn drop(&mut self) {
        if let Some(previous) = &self.previous {
            std::env::set_var(self.key, previous);
        } else {
            std::env::remove_var(self.key);
        }
    }
}

struct TestTlsFiles {
    directory: std::path::PathBuf,
    ca_path: std::path::PathBuf,
}

impl TestTlsFiles {
    fn install() -> Result<Self, String> {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|error| format!("clock failed: {error}"))?
            .as_nanos();
        let directory = std::env::temp_dir()
            .join(format!("quicfuscate-outer-hop-tls-{}-{unique}", std::process::id()));
        std::fs::create_dir(&directory)
            .map_err(|error| format!("TLS fixture directory failed: {error}"))?;

        let cert_path = directory.join("server.crt");
        let key_path = directory.join("server.key");
        let ca_path = directory.join("ca.crt");
        let mut hierarchy = quicfuscate::pki::generate_hierarchy("example.com", "QuicFuscate Test")
            .map_err(|error| format!("TLS hierarchy failed: {error}"))?;
        quicfuscate::pki::write_cert_chain_pem(
            &hierarchy.server_leaf.cert_der,
            &hierarchy.intermediate_ca.cert_der,
            &cert_path,
        )
        .map_err(|error| format!("TLS certificate write failed: {error}"))?;
        quicfuscate::pki::write_key_pem(&mut hierarchy.server_leaf.key_der, &key_path)
            .map_err(|error| format!("TLS key write failed: {error}"))?;
        quicfuscate::pki::write_ca_cert_pem(&hierarchy.root_ca.cert_der, &ca_path)
            .map_err(|error| format!("TLS CA write failed: {error}"))?;
        quicfuscate::qftls::set_tls_cert_key_paths(
            cert_path.to_str().ok_or("non-UTF-8 certificate path")?,
            key_path.to_str().ok_or("non-UTF-8 key path")?,
        );
        Ok(Self { directory, ca_path })
    }
}

/// `set_tls_cert_key_paths` is process-global (OnceLock), so every test in this
/// binary must share one fixture; a second install would be silently ignored
/// and leave the later test with a CA that does not match the live identity.
fn shared_tls() -> Result<&'static TestTlsFiles, String> {
    static SHARED: std::sync::OnceLock<Result<TestTlsFiles, String>> = std::sync::OnceLock::new();
    match SHARED.get_or_init(TestTlsFiles::install) {
        Ok(tls) => Ok(tls),
        Err(error) => Err(error.clone()),
    }
}

/// Sanity probe: a raw client/server handshake must complete in this exact
/// test environment (TLS fixture, clock, tokio runtime) before the circuit
/// machinery is blamed for a stalled hop-0 handshake.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn raw_quic_handshake_completes() -> Result<(), String> {
    let tls = shared_tls()?;
    let server_addr: SocketAddr = "127.0.0.1:9443".parse().map_err(|e| format!("{e}"))?;
    let client_addr: SocketAddr = "127.0.0.1:44445".parse().map_err(|e| format!("{e}"))?;
    let mut client_transport =
        Config::new_with_version(PROTOCOL_VERSION).map_err(|e| format!("{e:?}"))?;
    client_transport
        .load_verify_locations_from_file(tls.ca_path.to_str().ok_or("ca path")?)
        .map_err(|e| format!("{e}"))?;
    client_transport.set_initial_congestion_window_packets(10_000);
    // Same 12-byte qkey-id token the circuit hop embeds into the Initial.
    client_transport.set_initial_token(Some(b"0123456789ab".to_vec()));
    let mut server_transport =
        Config::new_with_version(PROTOCOL_VERSION).map_err(|e| format!("{e:?}"))?;
    server_transport.set_initial_congestion_window_packets(10_000);
    let stealth = quicfuscate::stealth::StealthConfig::default();
    let fec = quicfuscate::fec::FecConfig::product_default();
    let opt = quicfuscate::optimize::OptimizeConfig::default();
    let mut client = QuicFuscateConnection::new_client(
        "example.com",
        client_addr,
        server_addr,
        client_transport,
        stealth.clone(),
        fec.clone(),
        opt,
        None,
        None,
        false,
    )
    .map_err(|e| format!("{e}"))?;
    let mut server: Option<QuicFuscateConnection> = None;
    let mut a = vec![0u8; 262_144];
    let mut b = vec![0u8; 262_144];
    for _ in 0..2000 {
        if client.conn.is_established()
            && server.as_ref().map(|s| s.conn.is_established()).unwrap_or(false)
        {
            return Ok(());
        }
        while let Ok(len) = client.send(&mut a) {
            if len == 0 {
                break;
            }
            if server.is_none() {
                let (hdr, _) = parse_header(&a[..len], 0).map_err(|e| format!("{e:?}"))?;
                let odcid = ConnectionId::from_ref(&hdr.dcid);
                let scid = ConnectionId::from_ref(&[3; quicfuscate::transport::MAX_CONN_ID_LEN]);
                server = Some(
                    QuicFuscateConnection::new_server(
                        &scid,
                        Some(&odcid),
                        server_addr,
                        client_addr,
                        &mut server_transport,
                        stealth.clone(),
                        fec.clone(),
                        opt,
                    )
                    .map_err(|e| format!("{e}"))?,
                );
            }
            let srv = server.as_mut().unwrap();
            match srv.recv(&a[..len]) {
                Ok(_) | Err(quicfuscate::error::ConnectionError::Done) => {}
                Err(e) => return Err(format!("srv recv: {e:?}")),
            }
        }
        if let Some(srv) = server.as_mut() {
            loop {
                match srv.send(&mut b) {
                    Ok(0) | Err(quicfuscate::error::ConnectionError::Done) => break,
                    Ok(len) => match client.recv(&b[..len]) {
                        Ok(_) | Err(quicfuscate::error::ConnectionError::Done) => {}
                        Err(e) => return Err(format!("cli recv: {e:?}")),
                    },
                    Err(e) => return Err(format!("srv send: {e:?}")),
                }
            }
        }
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
    Err(format!(
        "raw handshake stalled: cli_est={} srv_est={}",
        client.conn.is_established(),
        server.as_ref().map(|s| s.conn.is_established()).unwrap_or(false)
    ))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn outer_hop_masque_circuit_carries_inner_quic_bytes() -> Result<(), String> {
    let tls = shared_tls()?;
    let _relay_token = ScopedEnvVar::set("QF_TEST_RELAY_QKEY", &"aa".repeat(32));
    let _exit_token = ScopedEnvVar::set("QF_TEST_EXIT_QKEY", &"bb".repeat(32));

    let exit_socket = std::net::UdpSocket::bind("127.0.0.1:0")
        .map_err(|error| format!("exit socket bind failed: {error}"))?;
    exit_socket
        .set_nonblocking(true)
        .map_err(|error| format!("exit socket nonblocking failed: {error}"))?;
    let exit_addr = exit_socket.local_addr().map_err(|error| error.to_string())?;
    let relay_addr: SocketAddr = "127.0.0.1:9443".parse().map_err(|e| format!("{e}"))?;
    let client_addr: SocketAddr = "127.0.0.1:44445".parse().map_err(|e| format!("{e}"))?;

    // The fallback topology the engine synthesizes after a blackholed direct
    // dial: relay first, the original target as exit.
    let ca = tls.ca_path.to_str().ok_or("non-UTF-8 CA path")?;
    let config = EngineConfig::from_toml(&format!(
        "[engine]\nmode = \"client\"\n\
         [stealth]\nmode = \"stealth\"\n\
         [transport]\nmtu = 1400\nmax_udp_payload = 1400\n\
         [[circuit.hops]]\n\
         label = \"outer MASQUE hop\"\n\
         endpoint = \"{relay_addr}\"\n\
         sni = \"example.com\"\n\
         verify_peer = true\n\
         ca_file = \"{ca}\"\n\
         qkey_id = \"0123456789ab\"\n\
         qkey_token_ref = \"env:QF_TEST_RELAY_QKEY\"\n\
         role = \"relay\"\n\
         [[circuit.hops]]\n\
         label = \"outer-hop exit\"\n\
         endpoint = \"{exit_addr}\"\n\
         sni = \"example.com\"\n\
         verify_peer = true\n\
         ca_file = \"{ca}\"\n\
         qkey_id = \"0123456789cd\"\n\
         qkey_token_ref = \"env:QF_TEST_EXIT_QKEY\"\n\
         role = \"exit\"\n",
    ))
    .map_err(|error| format!("fallback topology parse failed: {error}"))?;
    config.validate().map_err(|error| format!("fallback topology invalid: {error}"))?;

    let mut client = ClientConnection::connect(&config)
        .map_err(|error| format!("client connect failed: {error}"))?;
    assert_eq!(client.peer_addr(), relay_addr, "the physical dial must target the relay");

    let mut relay_policy = MasqueRelayPolicy {
        enabled: true,
        allow_non_global_targets: true,
        ..MasqueRelayPolicy::default()
    };
    relay_policy.allowed_hosts.insert("127.0.0.1".to_string());
    relay_policy.allowed_cidrs.push(RelayCidr::parse("127.0.0.0/8").expect("CIDR"));
    relay_policy.allowed_ports.insert(exit_addr.port());
    let relay_owner =
        MasqueRelayOwner::start(relay_policy).map_err(|e| format!("relay owner: {e}"))?;
    let responses = Arc::new(std::sync::Mutex::new(MasqueRelayResponseQueue::new(16, 1 << 20)));
    let relay_session: u64 = 7;

    // The test servers act as plain QUIC+H3 endpoints: the client keeps its
    // stealth wire image (that is the behavior under test), while the servers
    // run StealthMode::Off. StealthConfig::default() is the Stealth preset,
    // which emits cover requests on server-initiated bidi streams the client
    // H3 layer rejects as StreamCreationError.
    let stealth_config = quicfuscate::stealth::StealthConfig::off();
    let fec_config = quicfuscate::fec::FecConfig::product_default();
    let opt_config = quicfuscate::optimize::OptimizeConfig::default();

    // The circuit hop dials with the configured version preference list
    // (default [v2, v1]); the servers must accept the same set or the v2
    // initial salts will not match.
    let supported: Vec<u32> =
        config.transport.quic_versions.iter().map(|v| v.wire_version()).collect();
    let mut relay_srv: Option<QuicFuscateConnection> = None;
    let mut relay_transport =
        Config::new_with_version(PROTOCOL_VERSION).map_err(|e| format!("{e:?}"))?;
    relay_transport.set_supported_versions(supported.clone()).map_err(|e| format!("{e}"))?;
    relay_transport.set_initial_congestion_window_packets(10_000);
    // The outer hop must carry full-size inner Initials: a 1200-byte inner
    // packet plus the MASQUE flow prefix exceeds the 1200 default datagram
    // budget. Operators face the same constraint; the test advertises the
    // realistic 1400 path both directions.
    relay_transport.set_max_send_udp_payload_size(1400);
    let mut exit_srv: Option<QuicFuscateConnection> = None;
    let mut exit_transport =
        Config::new_with_version(PROTOCOL_VERSION).map_err(|e| format!("{e:?}"))?;
    exit_transport.set_supported_versions(supported).map_err(|e| format!("{e}"))?;
    exit_transport.set_initial_congestion_window_packets(10_000);
    exit_transport.set_max_send_udp_payload_size(1400);

    let mut scratch = vec![0u8; 262_144];
    let mut exit_scratch = [0u8; 65_535];
    let mut exit_peer: Option<SocketAddr> = None;
    let deadline = Instant::now() + Duration::from_secs(20);
    let mut payload_sent = false;
    let mut c2s = 0u64;
    let mut s2c = 0u64;
    let mut srv_recv_ok = 0u64;
    let mut srv_recv_done = 0u64;
    let mut srv_send_zero = 0u64;
    let mut srv_send_done = 0u64;
    let mut first_pkt_ty: Option<quicfuscate::transport::packet::PacketType> = None;
    let mut first_dcid_len = 0usize;
    let mut first_scid_len = 0usize;
    let mut first_token_len = 0usize;

    while Instant::now() < deadline {
        // client -> relay server
        let mut out = vec![0u8; 262_144];
        loop {
            let len = match client.send(&mut out) {
                Ok(0) => break,
                Ok(len) => len,
                Err(error) => {
                    return Err(format!(
                        "client send failed: {error} (c2s={c2s} s2c={s2c} recv_ok={srv_recv_ok} recv_done={srv_recv_done} send_zero={srv_send_zero} send_done={srv_send_done} relay_srv={} exit_srv={} srv_closed={} srv_est={} srv_tls={} first_ty={:?} dcid={} scid={} tok={})",
                        relay_srv.is_some(),
                        exit_srv.is_some(),
                        relay_srv.as_ref().map(|s| s.conn.is_closed()).unwrap_or(false),
                        relay_srv.as_ref().map(|s| s.conn.is_established()).unwrap_or(false),
                        relay_srv.as_ref().map(|s| s.conn.tls_handshake_complete()).unwrap_or(false),
                        first_pkt_ty, first_dcid_len, first_scid_len, first_token_len
                    ))
                }
            };
            c2s += 1;
            if relay_srv.is_none() {
                let (hdr, _) = parse_header(&out[..len], 0)
                    .map_err(|e| format!("relay initial header parse failed: {e:?}"))?;
                first_pkt_ty = Some(hdr.ty);
                first_dcid_len = hdr.dcid.len();
                first_scid_len = hdr.scid.len();
                first_token_len = hdr.token.map(|t| t.len()).unwrap_or(0);
                let odcid = ConnectionId::from_ref(&hdr.dcid);
                let scid = ConnectionId::from_ref(&[9; quicfuscate::transport::MAX_CONN_ID_LEN]);
                let mut srv = QuicFuscateConnection::new_server(
                    &scid,
                    Some(&odcid),
                    relay_addr,
                    client_addr,
                    &mut relay_transport,
                    stealth_config.clone(),
                    fec_config.clone(),
                    opt_config,
                )
                .map_err(|e| format!("relay server connect failed: {e}"))?;
                srv.set_masque_relay_cb(relay_owner.handler(relay_session));
                srv.set_masque_relay_response_queue(Arc::clone(&responses));
                relay_srv = Some(srv);
            }
            let srv = relay_srv.as_mut().expect("relay server");
            match srv.recv(&out[..len]) {
                Ok(n) => srv_recv_ok += 1.max(n) as u64,
                Err(quicfuscate::error::ConnectionError::Done) => srv_recv_done += 1,
                Err(error) => return Err(format!("relay server recv failed: {error:?}")),
            }
        }

        // Relay-side H3: authorize and accept pending CONNECT-UDP flows.
        if let Some(srv) = relay_srv.as_mut() {
            srv.poll_http3().map_err(|e| format!("relay H3 poll failed: {e:?}"))?;
            for (stream_id, target, purpose, circuit_id, hop_budget) in
                srv.pending_peer_masque_flows()
            {
                if purpose != MasqueFlowPurpose::NextHopUdp {
                    continue;
                }
                let (Some(circuit_id), Some(hop_budget), Some(target)) =
                    (circuit_id, hop_budget, target)
                else {
                    continue;
                };
                relay_owner
                    .authorize_flow(
                        relay_session,
                        stream_id / 4,
                        target,
                        circuit_id,
                        hop_budget,
                        Arc::clone(&responses),
                    )
                    .await
                    .map_err(|e| format!("relay admission failed: {e}"))?;
                srv.accept_peer_masque_flow(stream_id)
                    .map_err(|e| format!("relay flow accept failed: {e:?}"))?;
            }
            // Same completion step the live server runs after admitting peer
            // flows: finish the MASQUE data-plane response side.
            let _ = srv.accept_peer_masque_tunnel();
            // Downlink relay responses (exit -> association socket) sit in the
            // shared queue until the connection flushes them into H3 DATAGRAM
            // frames; without this the inner handshake never reaches the client.
            let _ = srv.flush_masque_relay_responses();
        }

        // relay server -> client
        if let Some(srv) = relay_srv.as_mut() {
            loop {
                let len = match srv.send(&mut scratch) {
                    Ok(0) => {
                        srv_send_zero += 1;
                        break;
                    }
                    Ok(len) => len,
                    Err(quicfuscate::error::ConnectionError::Done) => {
                        srv_send_done += 1;
                        break;
                    }
                    Err(error) => return Err(format!("relay server send failed: {error:?}")),
                };
                s2c += 1;
                if let Err(error) = client.recv_mut(&mut scratch[..len]) {
                    // "Connection done" is the benign no-progress signal the
                    // io driver also tolerates while the link warms up.
                    if !matches!(
                        error,
                        quicfuscate::engine::EngineError::Connection(ref message)
                            if message == "Connection done"
                    ) {
                        return Err(format!("client recv failed: {error:?}"));
                    }
                }
            }
        }

        // relay association -> exit server (real UDP on loopback)
        loop {
            match exit_socket.recv_from(&mut exit_scratch) {
                Ok((0, _)) => break,
                Ok((len, from)) => {
                    exit_peer = Some(from);
                    if exit_srv.is_none() {
                        let (hdr, _) = parse_header(&exit_scratch[..len], 0)
                            .map_err(|e| format!("exit initial header parse failed: {e:?}"))?;
                        let odcid = ConnectionId::from_ref(&hdr.dcid);
                        let scid =
                            ConnectionId::from_ref(&[7; quicfuscate::transport::MAX_CONN_ID_LEN]);
                        exit_srv = Some(
                            QuicFuscateConnection::new_server(
                                &scid,
                                Some(&odcid),
                                exit_addr,
                                from,
                                &mut exit_transport,
                                stealth_config.clone(),
                                fec_config.clone(),
                                opt_config,
                            )
                            .map_err(|e| format!("exit server connect failed: {e}"))?,
                        );
                    }
                    let srv = exit_srv.as_mut().expect("exit server");
                    match srv.recv(&exit_scratch[..len]) {
                        Ok(_) | Err(quicfuscate::error::ConnectionError::Done) => {}
                        Err(error) => return Err(format!("exit server recv failed: {error:?}")),
                    }
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(error) => return Err(format!("exit socket recv failed: {error}")),
            }
        }
        // exit server -> relay association
        if let (Some(srv), Some(peer)) = (exit_srv.as_mut(), exit_peer) {
            loop {
                let len = match srv.send(&mut scratch) {
                    Ok(0) => break,
                    Ok(len) => len,
                    Err(quicfuscate::error::ConnectionError::Done) => break,
                    Err(error) => return Err(format!("exit server send failed: {error:?}")),
                };
                exit_socket
                    .send_to(&scratch[..len], peer)
                    .map_err(|e| format!("exit socket send failed: {e}"))?;
            }
            // Inner application bytes must decode on the exit server.
            while let Ok(bytes) = srv.conn.dgram_recv_vec() {
                if bytes == b"outer-hop application bytes" {
                    // The owner task lives until every handler clone is gone;
                    // the relay connection still holds one, so drop it first.
                    drop(relay_srv.take());
                    relay_owner.shutdown().await.map_err(|e| e.to_string())?;
                    return Ok(());
                }
            }
        }

        if client.is_established() && !payload_sent {
            client
                .send_exit_datagram(b"outer-hop application bytes")
                .map_err(|e| format!("exit datagram enqueue failed: {e}"))?;
            payload_sent = true;
        }

        tokio::time::sleep(Duration::from_millis(2)).await;
    }

    let state = client.circuit_lifecycle_state();
    drop(relay_srv.take());
    relay_owner.shutdown().await.map_err(|e| e.to_string())?;
    Err(format!(
        "deadline exceeded (established={}, payload_sent={}, lifecycle={state:?})",
        client.is_established(),
        payload_sent
    ))
}
