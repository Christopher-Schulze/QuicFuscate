//! Minimal E2E client for admin-web tests.
//!
//! Connects to a QuicFuscate server using a QKey and exits once the
//! connection is established or a timeout is reached.

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use quicfuscate::core::QuicFuscateConnection;
use quicfuscate::engine::qkey;
use quicfuscate::error::ConnectionError;
use quicfuscate::fec::FecConfig;
use quicfuscate::optimize::OptimizeConfig;
use quicfuscate::stealth::StealthConfig;
use quicfuscate::transport::{Config, PROTOCOL_VERSION};

const AUTH_CONFIRMATION_GRACE: Duration = Duration::from_secs(1);

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut qkey_value: Option<String> = None;
    let mut timeout_ms: u64 = 8000;
    let mut hold_ms: u64 = 0;
    let mut local_addr: Option<String> = None;
    let mut bearer_token: Option<String> = None;
    let mut initial_token: Option<String> = None;
    let mut initial_only = false;
    let mut ca_file: Option<String> = None;

    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--qkey" => qkey_value = args.next(),
            "--timeout-ms" => {
                if let Some(v) = args.next() {
                    timeout_ms = v.parse::<u64>().unwrap_or(timeout_ms);
                }
            }
            "--hold-ms" => {
                if let Some(v) = args.next() {
                    hold_ms = v.parse::<u64>().unwrap_or(hold_ms);
                }
            }
            "--local" => local_addr = args.next(),
            "--bearer-token" => bearer_token = args.next(),
            "--initial-token" => initial_token = args.next(),
            "--initial-only" => initial_only = true,
            "--ca-file" => ca_file = args.next(),
            "--help" | "-h" => {
                println!(
                    "Usage: qf-e2e-client --qkey QKEY [--timeout-ms MS] [--hold-ms MS] [--local ADDR] [--bearer-token HEX] [--initial-token HEX] [--initial-only] [--ca-file PATH]"
                );
                return Ok(());
            }
            other => {
                eprintln!("Unknown arg: {}", other);
                return Err("invalid args".into());
            }
        }
    }

    let qkey_value = qkey_value.ok_or("missing --qkey")?;
    let qkey_cfg = qkey::parse(&qkey_value).map_err(|e| format!("QKey parse failed: {e}"))?;

    let remote_addr: SocketAddr =
        qkey_cfg.remote.parse().map_err(|e| format!("Invalid remote address: {e}"))?;
    let requested_local: SocketAddr = local_addr
        .unwrap_or_else(|| "0.0.0.0:0".to_string())
        .parse()
        .map_err(|e| format!("Invalid local address: {e}"))?;

    let token_hex = bearer_token
        .as_deref()
        .or(qkey_cfg.token.as_deref())
        .map(str::trim)
        .filter(|token| token.len() == 64 && token.bytes().all(|byte| byte.is_ascii_hexdigit()))
        .ok_or("QKey bearer token must be exactly 64 hexadecimal characters")?;
    let token_hex = qkey::QKeyToken::new(token_hex.to_lowercase());
    let qkey_id = qkey::id(&qkey_value);
    let initial_token = initial_token.as_deref().unwrap_or(&qkey_id).trim().to_ascii_lowercase();
    if initial_token.len() != 12 || !initial_token.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err("QKey Initial token must be exactly 12 hexadecimal characters".into());
    }
    if let Some(path) = ca_file.as_deref() {
        quicfuscate::qftls::set_tls_ca_path(path);
    }

    let mut transport = Config::new_with_version(PROTOCOL_VERSION)
        .map_err(|e| format!("transport config init failed: {e:?}"))?;
    transport.set_initial_token(Some(initial_token.as_bytes().to_vec()));

    let stealth_config = StealthConfig::performance();
    let fec_config = FecConfig::default();
    let opt_config = OptimizeConfig::default();

    let sni = if qkey_cfg.sni.trim().is_empty() {
        remote_addr.ip().to_string()
    } else {
        qkey_cfg.sni.clone()
    };

    let socket = std::net::UdpSocket::bind(requested_local)?;
    socket.connect(remote_addr)?;
    socket.set_nonblocking(true)?;
    let local_addr = socket.local_addr()?;

    let mut conn = QuicFuscateConnection::new_client(
        &sni,
        local_addr,
        remote_addr,
        transport,
        stealth_config,
        fec_config,
        opt_config,
        Some(token_hex.clone()),
        None, // qkey_initial_token
        false,
    )
    .map_err(|e| format!("client init failed: {e}"))?;

    let mut out = vec![0u8; 262144];
    let mut buf = vec![0u8; 65535];
    let deadline = Instant::now() + Duration::from_millis(timeout_ms);
    let mut checked_token = false;
    let mut auth_probe_sent = false;
    let mut auth_probe_sent_at: Option<Instant> = None;
    let mut sent_packets = 0u64;
    let mut recv_packets = 0u64;
    let mut last_recv_err: Option<String> = None;

    loop {
        if conn.conn.is_closed() {
            return Err("connection closed before QKey authentication completed".into());
        }
        if conn.conn.is_established()
            && auth_probe_sent_at
                .is_some_and(|sent_at| sent_at.elapsed() >= AUTH_CONFIRMATION_GRACE)
        {
            println!("connected");
            if hold_ms > 0 {
                std::thread::sleep(Duration::from_millis(hold_ms));
            }
            return Ok(());
        }
        if Instant::now() > deadline {
            let err_suffix = last_recv_err
                .as_deref()
                .map(|e| format!(", last_recv_err={}", e))
                .unwrap_or_default();
            return Err(format!(
                "timeout waiting for connection (sent={}, recv={}, token_checked={}{})",
                sent_packets, recv_packets, checked_token, err_suffix
            )
            .into());
        }

        match conn.send(&mut out) {
            Ok(len) => {
                if len == 0 {
                    // continue polling
                } else {
                    let mut sent_initial = false;
                    if !checked_token {
                        let (hdr, _) = quicfuscate::transport::packet::parse_header(&out[..len], 0)
                            .map_err(|e| format!("parse header failed: {e:?}"))?;
                        if hdr.ty == quicfuscate::transport::PacketType::Initial {
                            let got = hdr.token.unwrap_or_default();
                            if got.as_slice() != initial_token.as_bytes() {
                                return Err("initial token mismatch".into());
                            }
                            checked_token = true;
                            sent_initial = true;
                        }
                    }
                    let written = socket.send(&out[..len])?;
                    if written != len {
                        return Err(
                            format!("short UDP send: wrote {written} of {len} bytes").into()
                        );
                    }
                    sent_packets += 1;
                    if initial_only && sent_initial {
                        println!("initial-sent");
                        return Ok(());
                    }
                }
            }
            Err(e) => return Err(format!("send failed: {e:?}").into()),
        }

        if checked_token && !auth_probe_sent && conn.conn.is_established() {
            match conn.send_http3_request("/qf-e2e-probe") {
                Ok(()) => {
                    auth_probe_sent = true;
                    auth_probe_sent_at = Some(Instant::now());
                }
                Err(ConnectionError::Done) => {}
                Err(error) => {
                    return Err(format!("QKey auth request failed: {error:?}").into());
                }
            }
        }

        match socket.recv(&mut buf) {
            Ok(len) => {
                if len == 0 {
                    continue;
                }
                match conn.recv(&buf[..len]) {
                    Ok(_) => {}
                    Err(e) => {
                        last_recv_err = Some(format!("{:?}", e));
                    }
                }
                recv_packets += 1;
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(e) => return Err(format!("socket recv failed: {e}").into()),
        }
    }
}
