use quicfuscate::{core::QuicFuscateConnection, stealth::StealthConfig};
use std::net::{SocketAddr, Ipv4Addr};

#[test]
fn config_enables_bbrv2_and_mtu() {
    let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION).unwrap();
    config.set_cc_algorithm(quiche::CongestionControlAlgorithm::BBRv2);
    config.enable_mtu_probing();
    assert!(config.mtu_probing_enabled());
}

#[test]
fn connection_migration_api() {
    let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION).unwrap();
    let stealth = StealthConfig::default();
    let conn = QuicFuscateConnection::new_client(
        "localhost",
        SocketAddr::from((Ipv4Addr::LOCALHOST, 1234)),
        config,
        stealth,
    );
    assert!(conn.is_ok());
}
