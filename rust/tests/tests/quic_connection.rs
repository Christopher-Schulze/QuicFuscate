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
    let cfg = core::ZeroCopyConfig {
        enable_send: true,
        enable_recv: false,
    };
    conn.configure_zero_copy(cfg);
    assert!(conn.is_zero_copy_enabled());
    assert_eq!(conn.zero_copy_config(), cfg);
}
