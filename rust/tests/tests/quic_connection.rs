use core::{QuicConfig, QuicConnection};

#[test]
fn constructible() {
    let cfg = QuicConfig {
        server_name: "localhost".into(),
        port: 443,
    };
    let conn = QuicConnection::new(cfg);
    assert!(conn.is_ok());
}

#[test]
fn zero_copy_configurable() {
    let cfg = QuicConfig {
        server_name: "localhost".into(),
        port: 443,
    };
    let mut conn = QuicConnection::new(cfg).unwrap();
    assert!(!conn.is_zero_copy_enabled());
    conn.configure_zero_copy(core::ZeroCopyConfig {
        enable_send: true,
        enable_recv: false,
    });
    assert!(conn.is_zero_copy_enabled());
}
