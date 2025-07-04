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
fn zero_copy_configurable() -> Result<(), Box<dyn std::error::Error>> {
    let cfg = QuicConfig {
        server_name: "localhost".into(),
        port: 443,
    };
    let mut conn = QuicConnection::new(cfg)?;
    assert!(!conn.is_zero_copy_enabled());
    let cfg = core::ZeroCopyConfig {
        enable_send: true,
        enable_recv: false,
    };
    conn.configure_zero_copy(cfg);
    assert!(conn.is_zero_copy_enabled());
    assert!(conn.zero_copy_config().enable_send);
    Ok(())
}

#[test]
fn connect_and_transfer() -> Result<(), Box<dyn std::error::Error>> {
    let cfg = QuicConfig { server_name: "localhost".into(), port: 443 };
    let mut client = QuicConnection::new(cfg.clone())?;
    let mut server = QuicConnection::new(cfg)?;
    client.connect("127.0.0.1:443")?;
    server.connect("127.0.0.1:443")?;
    client.send(b"hello")?;
    assert_eq!(server.recv()?, Some(b"hello".to_vec()));
    Ok(())
}

#[cfg(feature = "quiche")]
#[test]
fn connect_and_transfer_quiche() -> Result<(), Box<dyn std::error::Error>> {
    let cfg = QuicConfig { server_name: "localhost".into(), port: 443 };
    let mut client = QuicConnection::new(cfg.clone())?;
    let mut server = QuicConnection::new(cfg)?;
    client.connect("127.0.0.1:443")?;
    server.connect("127.0.0.1:443")?;
    client.send(b"world")?;
    assert_eq!(server.recv()?, Some(b"world".to_vec()));
    Ok(())
}
