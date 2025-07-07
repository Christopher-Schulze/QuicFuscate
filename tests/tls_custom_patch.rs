use quicfuscate::core::QuicFuscateConnection;
use quicfuscate::fec::FecMode;
use quicfuscate::stealth::StealthConfig;
use std::net::UdpSocket;
use std::os::raw::c_void;
use std::process::Command;

#[tokio::test]
async fn tls_custom_patch() {
    // Prepare quiche sources and apply patches
    let status = Command::new("scripts/quiche_workflow.sh")
        .args(["--step", "fetch"])
        .status()
        .expect("failed to fetch quiche");
    assert!(status.success(), "fetch step failed");

    let status = Command::new("scripts/quiche_workflow.sh")
        .args(["--step", "patch"])
        .status()
        .expect("failed to patch quiche");
    assert!(status.success(), "patch step failed");

    // Create dummy client and server
    let server_socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    server_socket.set_nonblocking(true).unwrap();
    let server_addr = server_socket.local_addr().unwrap();

    let client_socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    client_socket.set_nonblocking(true).unwrap();
    client_socket.connect(server_addr).unwrap();

    let mut client_config = quiche::Config::new(quiche::PROTOCOL_VERSION).unwrap();
    client_config.verify_peer(false);

    let data = std::fs::read_to_string("browser_profiles/chrome_windows.chlo").unwrap();
    let custom_hello = base64::decode(data.trim()).unwrap();
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
        stealth_cfg,
        FecMode::Light,
    )
    .unwrap();

    let mut buf = [0u8; 65535];
    let mut out = [0u8; 65535];
    let len = client_conn.send(&mut out).unwrap();
    assert!(out[..len]
        .windows(custom_hello.len())
        .any(|w| w == custom_hello.as_slice()));

    // Let server process to complete connection
    server_socket.send_to(&out[..len], client_addr).unwrap();
    if let Ok((srv_len, _)) = server_socket.recv_from(&mut buf) {
        let _ = client_conn.recv(&mut buf[..srv_len]);
    }
}
