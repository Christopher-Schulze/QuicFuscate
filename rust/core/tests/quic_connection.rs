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
