use std::cell::Cell;
use std::time::{Duration, Instant};

use quicfuscate::core::QuicFuscateConnection;
use quicfuscate::engine::qkey;
use quicfuscate::error::ConnectionError;
use quicfuscate::fec::FecConfig;
use quicfuscate::implementations::server::qkey_registry::{
    qkey_id as registry_qkey_id, token_sha256_hex_from_token_hex, QKeyRegistry,
};
use quicfuscate::implementations::server::{evaluate_qkey_http3_headers, QKeyHeaderAuthOutcome};
use quicfuscate::optimize::OptimizeConfig;
use quicfuscate::stealth::StealthConfig;
use quicfuscate::transport::packet::PacketType;
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

    fn remove(key: &'static str) -> Self {
        let previous = std::env::var(key).ok();
        std::env::remove_var(key);
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

fn mk_hex(ch: char) -> String {
    std::iter::repeat_n(ch, 64).collect()
}

fn mk_qkey(remote: &str, sni: &str, token_hex: &str) -> String {
    let cfg = qkey::QKeyConfig::new(remote, sni)
        .with_stealth("auto")
        .with_fec("auto")
        .with_token(token_hex);
    qkey::generate(&cfg)
}

#[derive(Debug)]
struct SimResult {
    authed: bool,
    server_closed: bool,
    client_closed: bool,
}

fn simulate_qkey_http3_auth(
    qkey_value: &str,
    client_token_hex: &str,
    expected_token_hex: &str,
) -> Result<SimResult, String> {
    let qkey_cfg = qkey::parse(qkey_value).map_err(|e| format!("qkey parse failed: {e}"))?;
    let server_addr: std::net::SocketAddr =
        qkey_cfg.remote.parse().map_err(|e| format!("remote parse failed: {e}"))?;
    let client_addr: std::net::SocketAddr =
        "127.0.0.1:44444".parse().map_err(|e| format!("client addr parse failed: {e}"))?;

    let qkey_id = qkey::id(qkey_value);
    // Ensure our registry id derivation stays in sync.
    if registry_qkey_id(qkey_value) != qkey_id {
        return Err("qkey id derivation mismatch".to_string());
    }

    let expected_hash = token_sha256_hex_from_token_hex(expected_token_hex)
        .ok_or_else(|| "expected token hash failed".to_string())?;

    let mut reg = QKeyRegistry::new(200, None, None);
    reg.insert(qkey_value.to_string(), expected_token_hex.to_string(), None)
        .map_err(|e| format!("registry insert failed: {e}"))?;
    let record = reg
        .record_for_id_token(qkey_id.as_bytes())
        .ok_or_else(|| "registry lookup failed".to_string())?;
    if record.token_sha256 != expected_hash {
        return Err("registry stored token hash mismatch".to_string());
    }

    let mut client_transport =
        Config::new_with_version(PROTOCOL_VERSION).map_err(|e| format!("{e:?}"))?;
    client_transport.set_initial_token(Some(qkey_id.as_bytes().to_vec()));
    // Tests run in-memory without real pacing. Use a large CWND to avoid artificial stalls.
    client_transport.set_initial_congestion_window_packets(10_000);

    // Exercise the product-default H3 masquerade and QPACK header path. A reduced
    // non-masquerading configuration cannot prove the real CLI authentication path.
    let stealth_config = StealthConfig::default();
    let fec_config = FecConfig::product_default();
    let opt_config = OptimizeConfig::default();

    let sni = if qkey_cfg.sni.trim().is_empty() {
        server_addr.ip().to_string()
    } else {
        qkey_cfg.sni.clone()
    };

    let mut client = QuicFuscateConnection::new_client(
        &sni,
        client_addr,
        server_addr,
        client_transport,
        stealth_config.clone(),
        fec_config.clone(),
        opt_config,
        Some(client_token_hex.trim().to_lowercase()),
        None,
        false,
    )?;

    let mut server: Option<QuicFuscateConnection> = None;
    let mut server_transport =
        Config::new_with_version(PROTOCOL_VERSION).map_err(|e| format!("{e:?}"))?;
    server_transport.set_initial_congestion_window_packets(10_000);

    let mut out_client = vec![0u8; 262_144];
    let mut out_server = vec![0u8; 262_144];

    let deadline = Instant::now() + Duration::from_secs(8);
    let mut http3_sent = false;
    let authed = Cell::new(false);
    let mut c2s_sent = 0u64;
    let mut s2c_sent = 0u64;
    let mut last_h3_err: Option<String> = None;

    loop {
        if Instant::now() > deadline {
            let srv_closed = server.as_ref().map(|s| s.conn.is_closed()).unwrap_or(false);
            let cli_closed = client.conn.is_closed();
            let srv_est = server.as_ref().map(|s| s.conn.is_established()).unwrap_or(false);
            let cli_est = client.conn.is_established();
            let cli_writable = client.conn.writable().count();
            let cli_readable = client.conn.readable().count();
            let srv_readable = server.as_ref().map(|s| s.conn.readable().count()).unwrap_or(0);
            let cli_tls = client.conn.tls_handshake_complete();
            let srv_tls = server.as_ref().map(|s| s.conn.tls_handshake_complete()).unwrap_or(false);
            return Err(format!(
                "timeout (server_created={}, c2s_sent={}, s2c_sent={}, http3_sent={}, authed={}, client_established={}, server_established={}, client_tls={}, server_tls={}, client_closed={}, server_closed={}, cli_writable={}, cli_readable={}, srv_readable={}, last_h3_err={})",
                server.is_some(),
                c2s_sent,
                s2c_sent,
                http3_sent,
                authed.get(),
                cli_est,
                srv_est,
                cli_tls,
                srv_tls,
                cli_closed,
                srv_closed,
                cli_writable,
                cli_readable,
                srv_readable,
                last_h3_err.as_deref().unwrap_or("<none>")
            ));
        }

        // Create server upon first client packet.
        if server.is_none() {
            match client.send(&mut out_client) {
                Ok(len) if len > 0 => {
                    let (hdr, _) =
                        quicfuscate::transport::packet::parse_header(&out_client[..len], 0)
                            .map_err(|e| format!("parse header failed: {e:?}"))?;
                    if hdr.ty != PacketType::Initial {
                        return Err("expected initial packet".to_string());
                    }
                    let token = hdr.token.unwrap_or_default();
                    if token.as_slice() != qkey_id.as_bytes() {
                        return Err("initial token mismatch".to_string());
                    }

                    // Server needs to know the original destination connection ID (client-chosen)
                    // so it can complete the handshake correctly.
                    let odcid = ConnectionId::from_vec(hdr.dcid.clone());
                    let scid =
                        ConnectionId::from_ref(&[1; quicfuscate::transport::MAX_CONN_ID_LEN]);
                    let mut srv = QuicFuscateConnection::new_server(
                        &scid,
                        Some(&odcid),
                        server_addr,
                        client_addr,
                        &mut server_transport,
                        stealth_config.clone(),
                        fec_config.clone(),
                        opt_config,
                    )?;

                    // Feed first packet into server.
                    match srv.recv(&out_client[..len]) {
                        Ok(_) => {}
                        Err(ConnectionError::Done) => {}
                        Err(e) => return Err(format!("server recv failed: {e:?}")),
                    }
                    server = Some(srv);
                }
                Ok(_) => {}
                Err(ConnectionError::Done) => {}
                Err(e) => return Err(format!("client send failed: {e:?}")),
            }
        }

        // Drive client -> server
        for _ in 0..16 {
            let len = match client.send(&mut out_client) {
                Ok(v) => v,
                Err(ConnectionError::Done) => break,
                Err(e) => return Err(format!("client send failed: {e:?}")),
            };
            if len == 0 {
                break;
            }
            if let Some(ref mut srv) = server {
                c2s_sent = c2s_sent.saturating_add(1);
                match srv.recv(&out_client[..len]) {
                    Ok(_) => {}
                    Err(ConnectionError::Done) => {}
                    Err(e) => return Err(format!("server recv failed: {e:?}")),
                }
            }
        }

        // Drive server -> client
        if let Some(ref mut srv) = server {
            for _ in 0..16 {
                let len = match srv.send(&mut out_server) {
                    Ok(v) => v,
                    Err(ConnectionError::Done) => break,
                    Err(e) => return Err(format!("server send failed: {e:?}")),
                };
                if len == 0 {
                    break;
                }
                s2c_sent = s2c_sent.saturating_add(1);
                match client.recv(&out_server[..len]) {
                    Ok(_) => {}
                    Err(ConnectionError::Done) => {}
                    Err(e) => return Err(format!("client recv failed: {e:?}")),
                }
            }
        }

        // Flush client ACKs / responses generated by the server->client flight above.
        if let Some(ref mut srv) = server {
            for _ in 0..16 {
                let len = match client.send(&mut out_client) {
                    Ok(v) => v,
                    Err(ConnectionError::Done) => break,
                    Err(e) => return Err(format!("client send failed: {e:?}")),
                };
                if len == 0 {
                    break;
                }
                c2s_sent = c2s_sent.saturating_add(1);
                match srv.recv(&out_client[..len]) {
                    Ok(_) => {}
                    Err(ConnectionError::Done) => {}
                    Err(e) => return Err(format!("server recv failed: {e:?}")),
                }
            }
        }

        if client.conn.is_established() && !client.conn.tls_handshake_complete() {
            return Err("client reported established before TLS completed".to_string());
        }
        if server
            .as_ref()
            .is_some_and(|srv| srv.conn.is_established() && !srv.conn.tls_handshake_complete())
        {
            return Err("server reported established before TLS completed".to_string());
        }

        if server.is_some() && !http3_sent && client.conn.is_established() {
            match client.send_http3_request("/auth-check") {
                Ok(_) => http3_sent = true,
                Err(e) => last_h3_err = Some(format!("{e:?}")),
            }
        }

        if let Some(ref mut srv) = server {
            let expected = expected_hash.clone();
            let should_close: Cell<Option<&'static [u8]>> = Cell::new(None);

            let poll_res = srv.poll_http3_with_headers(
                |_sid, headers| {
                    if authed.get() {
                        return;
                    }
                    match evaluate_qkey_http3_headers(headers, Some(expected.trim()), false) {
                        QKeyHeaderAuthOutcome::Authenticated => authed.set(true),
                        QKeyHeaderAuthOutcome::Reject(reason) => should_close.set(Some(reason)),
                        QKeyHeaderAuthOutcome::Unchanged => {}
                    }
                },
                |_sid, _data| {
                    // No-op: this test only validates auth on headers.
                },
            );
            if let Err(e) = poll_res {
                last_h3_err = Some(format!("server_h3_poll_failed: {e:?}"));
            }

            if let Some(reason) = should_close.get() {
                let _ = srv.conn.close(true, 0x0, reason);
            }
        }

        if authed.get() {
            let srv_closed = server.as_ref().map(|s| s.conn.is_closed()).unwrap_or(false);
            let cli_closed = client.conn.is_closed();
            return Ok(SimResult {
                authed: true,
                server_closed: srv_closed,
                client_closed: cli_closed,
            });
        }

        let srv_closed = server.as_ref().map(|s| s.conn.is_closed()).unwrap_or(false);
        let cli_closed = client.conn.is_closed();
        if srv_closed || cli_closed {
            return Ok(SimResult {
                authed: false,
                server_closed: srv_closed,
                client_closed: cli_closed,
            });
        }

        client.update_state();
        if let Some(ref mut srv) = server {
            srv.update_state();
        }
        std::thread::sleep(Duration::from_millis(5));
    }
}

#[test]
fn qkey_http3_auth_accepts_valid_and_rejects_invalid_token() {
    // This integration test drives a full QUIC + TLS + HTTP/3 simulation in-memory.
    // Some platforms / toolchains use a relatively small default test thread stack which can
    // overflow under heavy protocol state machines. Run the simulation on a dedicated thread
    // with an explicit stack size so the test is stable and does not rely on env vars.
    let res = std::thread::Builder::new()
        .name("qkey_auth_integration".to_string())
        .stack_size(32 * 1024 * 1024)
        .spawn(|| {
            let good_token = mk_hex('a');
            let bad_token = mk_hex('b');

            let qkey_value = mk_qkey("127.0.0.1:4433", "example.com", &good_token);

            {
                let _verify_guard = ScopedEnvVar::remove("QUICFUSCATE_ALLOW_INVALID_CERTS");
                let error = simulate_qkey_http3_auth(&qkey_value, &good_token, &good_token)
                    .expect_err("untrusted server certificate must fail before HTTP/3 auth");
                assert!(
                    error.contains("invalid peer certificate"),
                    "unexpected certificate failure: {error}"
                );
            }

            let _allow_invalid_guard = ScopedEnvVar::set("QUICFUSCATE_ALLOW_INVALID_CERTS", "1");

            // Valid
            let ok = simulate_qkey_http3_auth(&qkey_value, &good_token, &good_token)
                .expect("simulation must run");
            assert!(ok.authed);
            assert!(!ok.server_closed);

            // Invalid token for auth header (but same initial token id)
            let bad = simulate_qkey_http3_auth(&qkey_value, &bad_token, &good_token)
                .expect("simulation must run");
            assert!(!bad.authed);
            assert!(bad.server_closed || bad.client_closed);
        })
        .expect("spawn simulation thread")
        .join();

    if let Err(panic) = res {
        std::panic::resume_unwind(panic);
    }
}
