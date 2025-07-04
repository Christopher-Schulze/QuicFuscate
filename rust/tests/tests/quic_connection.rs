#![cfg(feature = "quiche")]

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
    let mut server = QuicConnection::new(cfg.clone())?;
    server.bind("127.0.0.1:0")?;
    let server_addr = server.local_addr().unwrap();
    let mut client = QuicConnection::new(cfg)?;
    client.connect(&server_addr.to_string())?;
    client.send(b"hello")?;
    std::thread::sleep(std::time::Duration::from_millis(50));
    assert_eq!(server.recv()?, Some(b"hello".to_vec()));
    Ok(())
}

#[cfg(feature = "quiche")]
#[test]
fn connect_and_transfer_quiche() -> Result<(), Box<dyn std::error::Error>> {
    let cfg = QuicConfig { server_name: "localhost".into(), port: 443 };
    let mut server = QuicConnection::new(cfg.clone())?;
    server.bind("127.0.0.1:0")?;
    let server_addr = server.local_addr().unwrap();
    let mut client = QuicConnection::new(cfg)?;
    client.connect(&server_addr.to_string())?;
    client.send(b"world")?;
    std::thread::sleep(std::time::Duration::from_millis(50));
    assert_eq!(server.recv()?, Some(b"world".to_vec()));
    Ok(())
}
