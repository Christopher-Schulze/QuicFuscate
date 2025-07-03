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
