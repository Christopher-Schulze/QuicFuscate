#![cfg(feature = "quiche")]

use core::{QuicConfig, QuicConnection, CoreError};

#[test]
fn constructible() {
    let cfg = QuicConfig { server_name: "localhost".into(), port: 443 };
    let conn = QuicConnection::new(cfg);
    assert!(conn.is_ok());
}

#[test]
fn connect_success() {
    let cfg = QuicConfig { server_name: "localhost".into(), port: 443 };
    let mut conn = QuicConnection::new(cfg).unwrap();
    assert!(conn.connect("127.0.0.1:443").is_ok());
}

#[test]
fn connect_error() {
    let cfg = QuicConfig { server_name: "localhost".into(), port: 443 };
    let mut conn = QuicConnection::new(cfg).unwrap();
    let err = conn.connect("invalid").unwrap_err();
    assert!(matches!(err, CoreError::Quic(_)));
}

#[test]
fn migration_requires_enable() {
    let cfg = QuicConfig { server_name: "localhost".into(), port: 443 };
    let mut conn = QuicConnection::new(cfg).unwrap();
    assert!(conn.connect("127.0.0.1:443").is_ok());
    let err = conn.migrate("127.0.0.2:443").unwrap_err();
    assert!(matches!(err, CoreError::Quic(_)));
}

#[test]
fn migration_works_when_enabled() {
    let cfg = QuicConfig { server_name: "localhost".into(), port: 443 };
    let mut conn = QuicConnection::new(cfg).unwrap();
    conn.enable_migration(true);
    assert!(conn.connect("127.0.0.1:443").is_ok());
    assert!(conn.migrate("127.0.0.2:443").is_ok());
    assert_eq!(conn.current_path(), Some("127.0.0.2:443"));
}

#[test]
fn enabling_bbr_creates_controller() {
    let cfg = QuicConfig { server_name: "localhost".into(), port: 443 };
    let mut conn = QuicConnection::new(cfg).unwrap();
    conn.enable_bbr_congestion_control(true);
    assert!(conn.is_bbr_enabled());
}

#[test]
fn send_recv_roundtrip() {
    let cfg = QuicConfig { server_name: "localhost".into(), port: 443 };
    let mut server = QuicConnection::new(cfg.clone()).unwrap();
    server.bind("127.0.0.1:0").unwrap();
    let server_addr = server.local_addr().unwrap();
    let mut client = QuicConnection::new(cfg).unwrap();
    client.connect(&server_addr.to_string()).unwrap();
    client.send(b"ping").unwrap();
    std::thread::sleep(std::time::Duration::from_millis(50));
    assert_eq!(server.recv().unwrap(), Some(b"ping".to_vec()));
}

#[cfg(feature = "quiche")]
#[test]
fn send_recv_roundtrip_quiche() {
    let cfg = QuicConfig { server_name: "localhost".into(), port: 443 };
    let mut server = QuicConnection::new(cfg.clone()).unwrap();
    server.bind("127.0.0.1:0").unwrap();
    let server_addr = server.local_addr().unwrap();
    let mut client = QuicConnection::new(cfg).unwrap();
    client.connect(&server_addr.to_string()).unwrap();
    client.send(b"pong").unwrap();
    std::thread::sleep(std::time::Duration::from_millis(50));
    assert_eq!(server.recv().unwrap(), Some(b"pong".to_vec()));
}
