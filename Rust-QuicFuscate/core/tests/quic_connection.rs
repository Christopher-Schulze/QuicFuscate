use quicfuscate_core::{QuicConfig, QuicConnection};

#[test]
fn constructible() {
    let cfg = QuicConfig { server_name: "localhost".into(), port: 443 };
    let conn = QuicConnection::new(cfg);
    assert!(conn.is_ok());
}
