use quicfuscate::core::QuicFuscateConnection;
use quicfuscate::fec::{FecConfig, FecMode};
use quicfuscate::optimize::OptimizeConfig;
use quicfuscate::stealth::StealthConfig;
use quicfuscate::stealth::{BrowserProfile, FingerprintProfile, TlsClientHelloSpoofer};
use quicfuscate::telemetry;
use std::fs::File;
use std::io::Write;
use std::net::UdpSocket;
use std::os::raw::c_void;

#[tokio::test]
async fn client_server_end_to_end() {
    telemetry::serve("127.0.0.1:0");
    let server_socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    server_socket.set_nonblocking(true).unwrap();
    let server_addr = server_socket.local_addr().unwrap();
    let client_socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    client_socket.set_nonblocking(true).unwrap();
    client_socket.connect(server_addr).unwrap();
    let mut client_config = quiche::Config::new(quiche::PROTOCOL_VERSION).unwrap();
    client_config
        .set_application_protos(b"\x0ahq-interop\x05h3-29\x05h3-28\x05h3-27\x08http/0.9")
        .unwrap();
    client_config.set_initial_max_data(1_000_000);
    client_config.set_initial_max_stream_data_bidi_local(1_000_000);
    client_config.set_initial_max_stream_data_bidi_remote(1_000_000);
    client_config.set_initial_max_streams_bidi(100);
    client_config.set_initial_max_streams_uni(100);
    client_config.verify_peer(false);
    let mut stealth_cfg = StealthConfig::default();
    stealth_cfg.enable_domain_fronting = true;
    let mut fec_cfg = FecConfig {
        initial_mode: FecMode::Light,
        ..FecConfig::default()
    };
    let mut client_conn = QuicFuscateConnection::new_client(
        "example.com",
        client_socket.local_addr().unwrap(),
        server_addr,
        client_config,
        stealth_cfg.clone(),
        fec_cfg,
        OptimizeConfig::default(),
        true,
    )
    .unwrap();
    let mut server_config = quiche::Config::new(quiche::PROTOCOL_VERSION).unwrap();
    server_config
        .load_cert_chain_from_pem_file("libs/patched_quiche/quiche/examples/cert.crt")
        .unwrap();
    server_config
        .load_priv_key_from_pem_file("libs/patched_quiche/quiche/examples/cert.key")
        .unwrap();
    server_config
        .set_application_protos(b"\x0ahq-interop\x05h3-29\x05h3-28\x05h3-27\x08http/0.9")
        .unwrap();
    server_config.set_initial_max_data(1_000_000);
    server_config.set_initial_max_stream_data_bidi_local(1_000_000);
    server_config.set_initial_max_stream_data_bidi_remote(1_000_000);
    server_config.set_initial_max_streams_bidi(100);
    server_config.set_initial_max_streams_uni(100);
    let scid = quiche::ConnectionId::from_ref(&[0; quiche::MAX_CONN_ID_LEN]);
    let client_addr = client_socket.local_addr().unwrap();
    let mut fec_cfg_srv = FecConfig {
        initial_mode: FecMode::Light,
        ..FecConfig::default()
    };
    let mut server_conn = QuicFuscateConnection::new_server(
        &scid,
        None,
        server_addr,
        client_addr,
        server_config,
        stealth_cfg,
        fec_cfg_srv,
        OptimizeConfig::default(),
    )
    .unwrap();
    let (sni, host) = server_conn
        .stealth_manager()
        .get_connection_headers("example.com");
    assert_ne!(sni, host);
    assert_eq!(host, server_conn.host_header());
    let mut buf = [0u8; 65535];
    let mut out = [0u8; 65535];
    let mut request_sent = false;
    for _ in 0..200 {
        if let Ok(len) = client_conn.send(&mut out) {
            if len > 0 {
                client_socket.send(&out[..len]).unwrap();
            }
        }
        loop {
            match server_socket.recv_from(&mut buf) {
                Ok((len, _)) => {
                    let _ = server_conn.recv(&mut buf[..len]);
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(e) => panic!("recv_from server: {}", e),
            }
        }
        if client_conn.conn.is_established() && !request_sent {
            client_conn.send_http3_request("/").unwrap();
            request_sent = true;
        }
        server_conn.poll_http3().ok();
        if let Ok(len) = server_conn.send(&mut out) {
            if len > 0 {
                server_socket.send_to(&out[..len], client_addr).unwrap();
            }
        }
        loop {
            match client_socket.recv(&mut buf) {
                Ok(len) => {
                    let _ = client_conn.recv(&mut buf[..len]);
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(e) => panic!("recv client: {}", e),
            }
        }
        client_conn.poll_http3().ok();
        client_conn.update_state();
        server_conn.update_state();
        if client_conn.conn.is_established() && server_conn.conn.is_established() && request_sent {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    assert!(telemetry::ENCODED_PACKETS.get() > 0);
}

#[tokio::test]
async fn tls_custom_clienthello() {
    telemetry::serve("127.0.0.1:0");
    let server_socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    server_socket.set_nonblocking(true).unwrap();
    let server_addr = server_socket.local_addr().unwrap();

    let client_socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    client_socket.set_nonblocking(true).unwrap();
    client_socket.connect(server_addr).unwrap();

    let mut client_config = quiche::Config::new(quiche::PROTOCOL_VERSION).unwrap();
    client_config.verify_peer(false);

    let custom_hello = [1u8, 2, 3, 4, 5];
    unsafe {
        extern "C" {
            fn quiche_config_set_custom_tls(cfg: *mut c_void, hello: *const u8, len: usize);
        }
        quiche_config_set_custom_tls(
            &mut client_config as *mut _ as *mut c_void,
            custom_hello.as_ptr(),
            custom_hello.len(),
        );
    }

    let stealth_cfg = StealthConfig::default();
    let fec_cfg = FecConfig {
        initial_mode: FecMode::Light,
        ..FecConfig::default()
    };
    let mut client_conn = QuicFuscateConnection::new_client(
        "example.com",
        client_socket.local_addr().unwrap(),
        server_addr,
        client_config,
        stealth_cfg.clone(),
        fec_cfg,
        OptimizeConfig::default(),
        true,
    )
    .unwrap();

    let mut server_config = quiche::Config::new(quiche::PROTOCOL_VERSION).unwrap();
    server_config
        .load_cert_chain_from_pem_file("libs/vanilla_quiche/quiche/examples/cert.crt")
        .unwrap();
    server_config
        .load_priv_key_from_pem_file("libs/vanilla_quiche/quiche/examples/cert.key")
        .unwrap();
    server_config.verify_peer(false);

    let scid = quiche::ConnectionId::from_ref(&[0; quiche::MAX_CONN_ID_LEN]);
    let client_addr = client_socket.local_addr().unwrap();
    let fec_cfg_srv = FecConfig {
        initial_mode: FecMode::Light,
        ..FecConfig::default()
    };
    let mut server_conn = QuicFuscateConnection::new_server(
        &scid,
        None,
        server_addr,
        client_addr,
        server_config,
        stealth_cfg,
        fec_cfg_srv,
        OptimizeConfig::default(),
    )
    .unwrap();

    let mut buf = [0u8; 65535];
    let mut out = [0u8; 65535];
    let len = client_conn.send(&mut out).unwrap();
    assert!(out[..len]
        .windows(custom_hello.len())
        .any(|w| w == custom_hello));

    // Process on server so connection completes
    server_socket.send_to(&out[..len], client_addr).unwrap();
    if let Ok((srv_len, _)) = server_socket.recv_from(&mut buf) {
        let _ = client_conn.recv(&mut buf[..srv_len]);
    }
}

#[tokio::test]
async fn profile_rotation_changes_profile() {
    telemetry::serve("127.0.0.1:0");
    let server_socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    server_socket.set_nonblocking(true).unwrap();
    let server_addr = server_socket.local_addr().unwrap();

    let client_socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    client_socket.set_nonblocking(true).unwrap();
    client_socket.connect(server_addr).unwrap();

    let mut client_config = quiche::Config::new(quiche::PROTOCOL_VERSION).unwrap();
    client_config.verify_peer(false);
    let mut stealth_cfg = StealthConfig::default();
    let fec_cfg = FecConfig {
        initial_mode: FecMode::Light,
        ..FecConfig::default()
    };
    let mut client_conn = QuicFuscateConnection::new_client(
        "example.com",
        client_socket.local_addr().unwrap(),
        server_addr,
        client_config,
        stealth_cfg.clone(),
        fec_cfg,
        OptimizeConfig::default(),
        true,
    )
    .unwrap();

    let mut server_config = quiche::Config::new(quiche::PROTOCOL_VERSION).unwrap();
    server_config
        .load_cert_chain_from_pem_file("libs/vanilla_quiche/quiche/examples/cert.crt")
        .unwrap();
    server_config
        .load_priv_key_from_pem_file("libs/vanilla_quiche/quiche/examples/cert.key")
        .unwrap();
    server_config.verify_peer(false);
    let scid = quiche::ConnectionId::from_ref(&[0; quiche::MAX_CONN_ID_LEN]);
    let client_addr = client_socket.local_addr().unwrap();
    let fec_cfg_srv = FecConfig {
        initial_mode: FecMode::Light,
        ..FecConfig::default()
    };
    let mut server_conn = QuicFuscateConnection::new_server(
        &scid,
        None,
        server_addr,
        client_addr,
        server_config,
        stealth_cfg.clone(),
        fec_cfg_srv,
        OptimizeConfig::default(),
    )
    .unwrap();

    let profiles = vec![
        FingerprintProfile::new(BrowserProfile::Chrome, stealth_cfg.os_profile),
        FingerprintProfile::new(BrowserProfile::Firefox, stealth_cfg.os_profile),
    ];
    let sm = client_conn.stealth_manager();
    sm.start_profile_rotation(profiles.clone(), std::time::Duration::from_millis(500));

    let mut buf = [0u8; 65535];
    let mut out = [0u8; 65535];
    // Send data for a short period allowing rotation to occur
    for _ in 0..5 {
        if let Ok(len) = client_conn.send(&mut out) {
            if len > 0 {
                server_socket.send_to(&out[..len], client_addr).unwrap();
            }
        }
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    }

    let current = sm.current_profile();
    assert_eq!(current.browser, BrowserProfile::Firefox);
}

#[test]
fn fec_config_from_file() {
    let toml = "[adaptive_fec]\nlambda = 0.05";
    let path = std::env::temp_dir().join("fec_test.toml");
    let mut file = File::create(&path).unwrap();
    file.write_all(toml.as_bytes()).unwrap();
    let cfg = FecConfig::from_file(&path).unwrap();
    assert!((cfg.lambda - 0.05).abs() < 1e-6);
}

#[tokio::test]
async fn connection_migration_events() {
    telemetry::serve("127.0.0.1:0");

    let primary_socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    primary_socket.set_nonblocking(true).unwrap();
    let primary_addr = primary_socket.local_addr().unwrap();

    let client_socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    client_socket.set_nonblocking(true).unwrap();
    client_socket.connect(primary_addr).unwrap();

    let mut cfg = quiche::Config::new(quiche::PROTOCOL_VERSION).unwrap();
    cfg.verify_peer(false);
    let stealth_cfg = StealthConfig::default();
    let fec_cfg = FecConfig::default();

    let mut client_conn = QuicFuscateConnection::new_client(
        "example.com",
        client_socket.local_addr().unwrap(),
        primary_addr,
        cfg,
        stealth_cfg.clone(),
        fec_cfg.clone(),
        OptimizeConfig::default(),
        true,
    )
    .unwrap();

    let scid = quiche::ConnectionId::from_ref(&[0; quiche::MAX_CONN_ID_LEN]);
    let mut srv_cfg = quiche::Config::new(quiche::PROTOCOL_VERSION).unwrap();
    srv_cfg
        .load_cert_chain_from_pem_file("libs/vanilla_quiche/quiche/examples/cert.crt")
        .unwrap();
    srv_cfg
        .load_priv_key_from_pem_file("libs/vanilla_quiche/quiche/examples/cert.key")
        .unwrap();

    let mut server_conn = QuicFuscateConnection::new_server(
        &scid,
        None,
        primary_addr,
        client_socket.local_addr().unwrap(),
        srv_cfg,
        stealth_cfg,
        fec_cfg,
        OptimizeConfig::default(),
    )
    .unwrap();

    // Basic handshake
    let mut buf = [0u8; 65535];
    let mut out = [0u8; 65535];
    for _ in 0..10 {
        if let Ok(len) = client_conn.send(&mut out) {
            if len > 0 {
                primary_socket.send_to(&out[..len], primary_addr).unwrap();
            }
        }
        if let Ok((len, _)) = primary_socket.recv_from(&mut buf) {
            server_conn.recv(&mut buf[..len]).ok();
        }
        if let Ok(len) = server_conn.send(&mut out) {
            if len > 0 {
                primary_socket
                    .send_to(&out[..len], client_socket.local_addr().unwrap())
                    .unwrap();
            }
        }
        if let Ok(len) = client_socket.recv(&mut buf) {
            client_conn.recv(&mut buf[..len]).ok();
        }
        if client_conn.conn.is_established() && server_conn.conn.is_established() {
            break;
        }
    }

    let new_socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    new_socket.set_nonblocking(true).unwrap();
    let new_addr = new_socket.local_addr().unwrap();

    // Trigger migration on client
    client_conn.migrate_connection(new_addr).ok();

    // Drain path events
    client_conn.update_state();
    while let Some(_e) = client_conn.conn.path_event_next() {
        // just consume for test
    }
    assert!(telemetry::PATH_MIGRATIONS.get() > 0);
}

#[tokio::test]
async fn real_quiche_end_to_end() {
    telemetry::serve("127.0.0.1:0");

    let server_socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    server_socket.set_nonblocking(true).unwrap();
    let server_addr = server_socket.local_addr().unwrap();

    let client_socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    client_socket.set_nonblocking(true).unwrap();
    client_socket.connect(server_addr).unwrap();

    let mut client_config = quiche::Config::new(quiche::PROTOCOL_VERSION).unwrap();
    client_config.verify_peer(false);

    let mut fec_cfg = FecConfig {
        initial_mode: FecMode::Light,
        ..FecConfig::default()
    };

    let mut client_conn = QuicFuscateConnection::new_client(
        "example.com",
        client_socket.local_addr().unwrap(),
        server_addr,
        client_config,
        StealthConfig::default(),
        fec_cfg,
        OptimizeConfig::default(),
        true,
    )
    .unwrap();

    let mut server_config = quiche::Config::new(quiche::PROTOCOL_VERSION).unwrap();
    server_config
        .load_cert_chain_from_pem_file("libs/vanilla_quiche/quiche/examples/cert.crt")
        .unwrap();
    server_config
        .load_priv_key_from_pem_file("libs/vanilla_quiche/quiche/examples/cert.key")
        .unwrap();
    server_config.verify_peer(false);

    let scid = quiche::ConnectionId::from_ref(&[0; quiche::MAX_CONN_ID_LEN]);
    let client_addr = client_socket.local_addr().unwrap();
    let mut server_conn = QuicFuscateConnection::new_server(
        &scid,
        None,
        server_addr,
        client_addr,
        server_config,
        StealthConfig::default(),
        FecConfig::default(),
        OptimizeConfig::default(),
    )
    .unwrap();

    let mut buf = [0u8; 65535];
    let mut out = [0u8; 65535];
    let mut request_sent = false;
    for _ in 0..200 {
        if let Ok(len) = client_conn.send(&mut out) {
            if len > 0 {
                client_socket.send(&out[..len]).unwrap();
            }
        }
        loop {
            match server_socket.recv_from(&mut buf) {
                Ok((len, _)) => {
                    let _ = server_conn.recv(&mut buf[..len]);
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(e) => panic!("recv_from server: {}", e),
            }
        }
        if client_conn.conn.is_established() && !request_sent {
            client_conn.send_http3_request("/").unwrap();
            request_sent = true;
        }
        server_conn.poll_http3().ok();
        if let Ok(len) = server_conn.send(&mut out) {
            if len > 0 {
                server_socket.send_to(&out[..len], client_addr).unwrap();
            }
        }
        loop {
            match client_socket.recv(&mut buf) {
                Ok(len) => {
                    let _ = client_conn.recv(&mut buf[..len]);
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(e) => panic!("recv client: {}", e),
            }
        }
        client_conn.update_state();
        server_conn.update_state();
        if client_conn.conn.is_established() && server_conn.conn.is_established() && request_sent {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }

    assert!(telemetry::ENCODED_PACKETS.get() > 0);
}
