use quicfuscate::core::QuicFuscateConnection;
use quicfuscate::fec::FecMode;
use quicfuscate::stealth::StealthConfig;
use quicfuscate::telemetry;
use std::net::UdpSocket;

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
    let mut client_conn = QuicFuscateConnection::new_client(
        "example.com",
        client_socket.local_addr().unwrap(),
        server_addr,
        client_config,
        stealth_cfg.clone(),
        FecMode::Light,
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
    let mut server_conn = QuicFuscateConnection::new_server(
        &scid,
        None,
        server_addr,
        client_addr,
        server_config,
        stealth_cfg,
        FecMode::Light,
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
