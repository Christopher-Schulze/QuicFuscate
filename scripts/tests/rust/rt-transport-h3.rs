#![cfg(feature = "rust-tests")]

//! External integration tests for the HTTP/3 transport layer (h3.rs).
//! Exercises the public API surface accessible via `quicfuscate::transport::h3`.

use quicfuscate::transport::{h3, packet, Config, PROTOCOL_VERSION};

fn make_client_conn() -> quicfuscate::transport::Connection {
    let mut cfg = Config::new_with_version(PROTOCOL_VERSION).expect("config");
    let local: std::net::SocketAddr = "127.0.0.1:0".parse().expect("local");
    let peer: std::net::SocketAddr = "127.0.0.1:4433".parse().expect("peer");
    let scid = [0u8; 8];
    packet::connect(None, &scid, local, peer, &mut cfg).expect("connect")
}

fn make_h3_pair() -> (quicfuscate::transport::Connection, h3::Connection) {
    let mut conn = make_client_conn();
    let cfg = h3::Config::new().expect("h3 config");
    let h3c = h3::Connection::with_transport(&mut conn, &cfg).expect("h3 conn");
    (conn, h3c)
}

#[test]
fn h3_send_request_returns_stream_id() {
    let (mut conn, mut h3c) = make_h3_pair();
    let headers = vec![
        h3::Header::new(b":method", b"GET"),
        h3::Header::new(b":path", b"/"),
        h3::Header::new(b":scheme", b"https"),
        h3::Header::new(b":authority", b"example.com"),
    ];
    let sid = h3c.send_request(&mut conn, &headers, true).expect("send_request");
    assert!(sid > 0, "stream ID must be positive for non-control streams");
}

#[test]
fn h3_masque_connect_udp_and_datagram() {
    let (mut conn, mut h3c) = make_h3_pair();
    let sid = h3c
        .connect_udp(&mut conn, "proxy.example.com", "target.example.com:443")
        .expect("connect_udp");
    let flow_id = h3c.enable_masque_datagram(&mut conn, sid).expect("enable datagram");
    assert_eq!(flow_id, 0, "default flow_id must be 0");

    h3c.send_masque_datagram(&mut conn, sid, b"test payload").expect("send datagram");
    assert_eq!(conn.dgram_send_queue_len(), 1);
}

#[test]
fn h3_capsule_encode_produces_valid_output() {
    let types_and_payloads: Vec<(u64, Vec<u8>)> = vec![
        (0x00, b"datagram".to_vec()),
        (0x21, b"compressed".to_vec()),
        (0x22, b"dict_compressed".to_vec()),
        (0x30, vec![0, 1, 2, 3]),
        (0xFF, vec![]),
    ];
    for (ctype, payload) in &types_and_payloads {
        let capsule = h3::Connection::encode_capsule(*ctype, payload);
        // Capsule must be at least type_varint + length_varint + payload bytes
        assert!(capsule.len() >= payload.len(), "capsule must include payload");
        // For type < 64, first byte encodes the type directly
        if *ctype < 64 {
            assert_eq!(capsule[0], *ctype as u8, "first byte should be capsule type");
        }
    }
}

#[test]
fn h3_capsule_encode_empty_payload() {
    let capsule = h3::Connection::encode_capsule(0x21, &[]);
    // At minimum: type varint (1 byte for 0x21 < 64) + length varint (1 byte for 0)
    assert!(capsule.len() >= 2, "empty capsule must have at least type+length varints");
}

#[test]
fn h3_header_accessors() {
    let h = h3::Header::new(b"content-type", b"application/json");
    assert_eq!(h.name(), b"content-type");
    assert_eq!(h.value(), b"application/json");

    // Mutable accessors (test-gated)
    let mut h2 = h3::Header::new(b"x-test", b"val");
    h2.name_mut()[0] = b'X';
    assert_eq!(h2.name(), b"X-test");
}

#[test]
fn h3_masque_connect_is_not_ready_before_peer_response() {
    let (mut conn, mut h3c) = make_h3_pair();
    let sid = h3c.connect_udp(&mut conn, "proxy.test", "target.test:443").expect("connect_udp");
    assert!(
        !h3c.masque_established(sid),
        "locally opening CONNECT-UDP must not bypass the peer response"
    );
    assert!(!h3c.masque_established(99999), "non-existent stream returns false");
}

#[test]
fn h3_config_validation_rejects_extremes() {
    let mut conn = make_client_conn();
    let mut cfg = h3::Config::new().expect("cfg");
    cfg.set_max_field_section_size(0);
    assert!(h3::Connection::with_transport(&mut conn, &cfg).is_err());

    let mut cfg2 = h3::Config::new().expect("cfg2");
    cfg2.set_max_field_section_size(32 * 1024 * 1024);
    let mut conn2 = make_client_conn();
    assert!(h3::Connection::with_transport(&mut conn2, &cfg2).is_err());
}
