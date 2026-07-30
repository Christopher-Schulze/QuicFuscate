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
const MIGRATION_WINDOW: Duration = Duration::from_millis(250);
const MIGRATION_BASELINE_WINDOWS: usize = 4;
const MIGRATION_RECOVERY_WINDOWS: usize = 8;
const MIGRATION_TRAFFIC_INTERVAL: Duration = Duration::from_millis(5);
const MIGRATION_BODY_BYTES: usize = 1000;
const MIN_TRANSITION_RATIO_PPM: u64 = 500_000;
const MIN_RECOVERY_RATIO_PPM: u64 = 900_000;

fn ratio_ppm(numerator: u64, denominator: u64) -> u64 {
    if denominator == 0 {
        return 0;
    }
    numerator.saturating_mul(1_000_000) / denominator
}

fn measure_authenticated_traffic_window(
    conn: &mut QuicFuscateConnection,
    socket: &std::net::UdpSocket,
    remote_addr: SocketAddr,
    stream_id: u64,
    out: &mut [u8],
    buf: &mut [u8],
) -> Result<u64, Box<dyn std::error::Error>> {
    let payload = [0xA5; MIGRATION_BODY_BYTES];
    let deadline = Instant::now() + MIGRATION_WINDOW;
    let mut next_payload_at = Instant::now();
    let mut sent_bytes = 0u64;

    while Instant::now() < deadline {
        let now = Instant::now();
        let mut progressed = false;
        if now >= next_payload_at {
            match conn.http3_send_body_chunk(stream_id, &payload, false) {
                Ok(()) => {}
                Err(ConnectionError::Done) => {}
                Err(error) => {
                    return Err(format!("migration traffic enqueue failed: {error:?}").into());
                }
            }
            next_payload_at = now + MIGRATION_TRAFFIC_INTERVAL;
        }

        match conn.send(out) {
            Ok(0) => {}
            Ok(len) => {
                let written = socket.send(&out[..len])?;
                if written != len {
                    return Err(format!("short UDP send: wrote {written} of {len} bytes").into());
                }
                sent_bytes = sent_bytes.saturating_add(len as u64);
                progressed = true;
            }
            Err(ConnectionError::Done) => {}
            Err(error) => return Err(format!("migration traffic send failed: {error:?}").into()),
        }

        loop {
            match socket.recv(buf) {
                Ok(0) => break,
                Ok(len) => {
                    match conn.recv_on_path(&buf[..len], remote_addr, socket.local_addr()?) {
                        Ok(_) | Err(ConnectionError::Done) => {}
                        Err(error) => {
                            return Err(
                                format!("migration traffic receive failed: {error:?}").into()
                            );
                        }
                    }
                    progressed = true;
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(error) => return Err(format!("socket receive failed: {error}").into()),
            }
        }

        if !progressed {
            std::thread::sleep(Duration::from_millis(1));
        }
    }

    Ok(sent_bytes)
}

fn run_migration_probe(
    conn: &mut QuicFuscateConnection,
    mut socket: std::net::UdpSocket,
    remote_addr: SocketAddr,
    migration_local: SocketAddr,
    out: &mut [u8],
    buf: &mut [u8],
) -> Result<(), Box<dyn std::error::Error>> {
    let stream_id = conn
        .open_http3_stream_post("/qf-e2e-migration")
        .map_err(|error| format!("migration stream open failed: {error:?}"))?;
    let mut baseline_windows = Vec::with_capacity(MIGRATION_BASELINE_WINDOWS);
    for _ in 0..MIGRATION_BASELINE_WINDOWS {
        baseline_windows.push(measure_authenticated_traffic_window(
            conn,
            &socket,
            remote_addr,
            stream_id,
            out,
            buf,
        )?);
    }
    let baseline_total = baseline_windows.iter().sum::<u64>();
    if baseline_total == 0 {
        return Err("migration baseline produced zero UDP wire bytes".into());
    }

    let old_local = socket.local_addr()?;
    let migrated_socket = std::net::UdpSocket::bind(migration_local)?;
    migrated_socket.connect(remote_addr)?;
    migrated_socket.set_nonblocking(true)?;
    let new_local = migrated_socket.local_addr()?;
    if new_local == old_local {
        return Err("migration socket reused the active local address".into());
    }
    conn.conn
        .migrate(new_local, remote_addr)
        .map_err(|error| format!("migration start failed: {error:?}"))?;
    socket = migrated_socket;

    let migration_started = Instant::now();
    let mut migration_windows = Vec::with_capacity(MIGRATION_RECOVERY_WINDOWS);
    let mut validated_after = None;
    let mut best_recovery_ratio_ppm = 0u64;
    let baseline_window_average = baseline_total / MIGRATION_BASELINE_WINDOWS as u64;
    for _ in 0..MIGRATION_RECOVERY_WINDOWS {
        let sent =
            measure_authenticated_traffic_window(conn, &socket, remote_addr, stream_id, out, buf)?;
        migration_windows.push(sent);
        let active_local = conn
            .conn
            .path_stats()
            .next()
            .map(|path| path.local_addr)
            .ok_or("missing path stats")?;
        if active_local == new_local && validated_after.is_none() {
            validated_after = Some(migration_started.elapsed());
        }
        if validated_after.is_some() {
            best_recovery_ratio_ppm =
                best_recovery_ratio_ppm.max(ratio_ppm(sent, baseline_window_average));
        }
    }

    let validation_elapsed =
        validated_after.ok_or("PATH_CHALLENGE/PATH_RESPONSE migration did not validate")?;
    if validation_elapsed > Duration::from_secs(2) {
        return Err(format!("migration validation exceeded 2s: {validation_elapsed:?}").into());
    }
    let transition_total =
        migration_windows.iter().take(MIGRATION_BASELINE_WINDOWS).copied().sum::<u64>();
    let transition_ratio_ppm = ratio_ppm(transition_total, baseline_total);
    if transition_ratio_ppm < MIN_TRANSITION_RATIO_PPM {
        return Err(format!(
            "migration transition throughput ratio below 50%: {transition_ratio_ppm} ppm"
        )
        .into());
    }
    if best_recovery_ratio_ppm < MIN_RECOVERY_RATIO_PPM {
        return Err(format!(
            "migration recovery throughput ratio below 90% within 2s: {best_recovery_ratio_ppm} ppm"
        )
        .into());
    }

    let _ = conn.http3_send_body_chunk(stream_id, &[], true);
    println!(
        "migration-proof old_local={old_local} new_local={new_local} validation_ms={} baseline_bytes={baseline_total} transition_bytes={transition_total} transition_ratio_ppm={transition_ratio_ppm} best_recovery_ratio_ppm={best_recovery_ratio_ppm} cwnd={}",
        validation_elapsed.as_millis(),
        conn.conn.cwnd()
    );
    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut qkey_value: Option<String> = None;
    let mut timeout_ms: u64 = 8000;
    let mut hold_ms: u64 = 0;
    let mut local_addr: Option<String> = None;
    let mut bearer_token: Option<String> = None;
    let mut initial_token: Option<String> = None;
    let mut initial_only = false;
    let mut ca_file: Option<String> = None;
    let mut migration_local: Option<String> = None;

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
            "--migration-local" => migration_local = args.next(),
            "--help" | "-h" => {
                println!(
                    "Usage: qf-e2e-client --qkey QKEY [--timeout-ms MS] [--hold-ms MS] [--local ADDR] [--bearer-token HEX] [--initial-token HEX] [--initial-only] [--ca-file PATH] [--migration-local ADDR]"
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
    let migration_local = migration_local
        .map(|address| address.parse::<SocketAddr>())
        .transpose()
        .map_err(|e| format!("Invalid migration local address: {e}"))?;

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
            let receive_error = last_recv_err.as_deref().unwrap_or("<none>");
            return Err(format!(
                "connection closed before QKey authentication completed (last_recv_err={receive_error})"
            )
            .into());
        }
        if conn.conn.is_established()
            && auth_probe_sent_at
                .is_some_and(|sent_at| sent_at.elapsed() >= AUTH_CONFIRMATION_GRACE)
        {
            if let Some(migration_local) = migration_local {
                run_migration_probe(
                    &mut conn,
                    socket,
                    remote_addr,
                    migration_local,
                    &mut out,
                    &mut buf,
                )?;
                return Ok(());
            }
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

#[cfg(test)]
mod tests {
    use super::ratio_ppm;

    #[test]
    fn migration_ratio_uses_exact_parts_per_million_boundaries() {
        assert_eq!(ratio_ppm(0, 0), 0);
        assert_eq!(ratio_ppm(50, 100), 500_000);
        assert_eq!(ratio_ppm(90, 100), 900_000);
        assert_eq!(ratio_ppm(100, 100), 1_000_000);
    }
}
