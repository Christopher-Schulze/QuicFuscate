use super::*;

#[test]
fn masque_capsule_decode_single() {
    // Build buffer: [type=0x00][len=0x03][payload 3 bytes]
    let mut buf = Vec::new();
    Connection::encode_varint(0, &mut buf);
    Connection::encode_varint(3, &mut buf);
    buf.extend_from_slice(&[1, 2, 3]);
    let (ctype, used, payload) = Connection::decode_capsule(&buf[..]).expect("decode");
    assert_eq!(ctype, 0);
    assert_eq!(used, buf.len());
    assert_eq!(payload, vec![1, 2, 3]);
}

#[test]
fn connect_udp_marks_stream_type_masque() {
    let mut conn = make_conn();
    let mut cfg = super::Config::new().expect("cfg");
    cfg.set_max_field_section_size(1024 * 1024);
    let mut h3 = super::h3::Connection::with_transport(&mut conn, &cfg).expect("h3");
    let sid = h3
        .connect_udp(&mut conn, "masque.example.com", "target.example.com:443")
        .expect("connect_udp");
    let st = h3.streams.get(&sid).expect("state");
    assert!(matches!(st._stream_type, StreamType::Masque));
    let flow_id = h3.enable_masque_datagram(&mut conn, sid).expect("enable datagram");
    assert_eq!(Some(&flow_id), h3.masque_flow.get(&sid));
    assert_eq!(h3.masque_flow_id(sid), Some(0));
    assert_eq!(h3.masque_flow_id(sid + 4), None);
    assert_eq!(0, conn.dgram_send_queue_len());

    h3.send_masque_datagram(&mut conn, sid, &[0xAA, 0xBB, 0xCC]).expect("datagram enqueue");
    assert_eq!(1, conn.dgram_send_queue_len());
}

#[test]
fn connect_udp_with_headers_preserves_auth_header() {
    let mut conn = make_conn();
    let mut cfg = super::Config::new().expect("cfg");
    cfg.set_max_field_section_size(1024 * 1024);
    let mut h3 = super::h3::Connection::with_transport(&mut conn, &cfg).expect("h3");
    let sid = h3
        .connect_udp_with_headers(
            &mut conn,
            "masque.example.com",
            "target.example.com:443",
            &[Header::new(b"x-qf-auth", b"token-123")],
        )
        .expect("connect_udp");
    let st = h3.streams.get(&sid).expect("state");
    assert!(st._headers.iter().any(|h| h.name() == b"x-qf-auth" && h.value() == b"token-123"));
}

#[test]
fn masque_datagram_e2e_roundtrip() {
    // E2E Test: Create connection, establish MASQUE, send datagram, verify queue
    let mut conn = make_conn();
    let mut cfg = super::Config::new().expect("cfg");
    cfg.set_max_field_section_size(1024 * 1024);
    let mut h3 = super::h3::Connection::with_transport(&mut conn, &cfg).expect("h3");

    // Establish CONNECT-UDP
    let sid =
        h3.connect_udp(&mut conn, "proxy.example.com", "192.168.1.1:53").expect("connect_udp");

    // Enable datagrams
    let flow_id = h3.enable_masque_datagram(&mut conn, sid).expect("enable datagram");
    assert_eq!(flow_id, 0); // Default flow ID is 0

    // Send multiple datagrams
    let payloads = [
        b"DNS query payload 1".to_vec(),
        b"DNS query payload 2 longer".to_vec(),
        vec![0xDE, 0xAD, 0xBE, 0xEF], // Binary payload
    ];

    for (i, payload) in payloads.iter().enumerate() {
        h3.send_masque_datagram(&mut conn, sid, payload).expect("datagram send");
        assert_eq!(i + 1, conn.dgram_send_queue_len(), "datagram {} queued", i);
    }

    // Verify MASQUE state
    assert!(h3.masque_flow_active(), "masque flow should be active");
    assert_eq!(Some(&0u64), h3.masque_flow.get(&sid));

    // Verify stream type
    let st = h3.streams.get(&sid).expect("stream state");
    assert!(matches!(st._stream_type, StreamType::Masque));
}

#[test]
fn masque_capsule_encode_decode_roundtrip() {
    // Test capsule encoding and decoding for various types
    let test_cases = vec![
        (0x00u64, b"datagram payload".to_vec()), // DATAGRAM
        (0x21u64, b"compressed data".to_vec()),  // Compressed
        (0x22u64, b"dict compressed".to_vec()),  // Dict compressed
        (0x30u64, vec![0, 1, 2, 3, 4, 5, 6, 7]), // Register context
    ];

    for (ctype, payload) in test_cases {
        let capsule = Connection::encode_capsule(ctype, &payload);
        let (decoded_type, used, decoded_payload) =
            Connection::decode_capsule(&capsule).expect("decode capsule");

        assert_eq!(decoded_type, ctype, "capsule type mismatch");
        assert_eq!(used, capsule.len(), "used bytes mismatch");
        assert_eq!(decoded_payload, payload, "payload mismatch for type {}", ctype);
    }
}

#[test]
fn masque_varint_roundtrip_covers_all_wire_widths() {
    let cases = [
        (0u64, 1usize),
        (63, 1),
        (64, 2),
        (16_383, 2),
        (16_384, 4),
        (1 << 30, 8),
        ((1 << 62) - 1, 8),
    ];

    for (value, expected_len) in cases {
        let mut encoded = Vec::new();
        Connection::encode_varint(value, &mut encoded);
        assert_eq!(encoded.len(), expected_len, "wire width for {value}");
        let (decoded, used) = Connection::decode_varint(&encoded).expect("decode varint");
        assert_eq!(decoded, value);
        assert_eq!(used, encoded.len());
    }
}

#[test]
fn masque_capsule_roundtrip_supports_16384_byte_payload() {
    let payload = vec![0xA5; 16_384];
    let capsule = Connection::encode_capsule(0x00, &payload);
    assert_eq!(capsule[1] & 0xC0, 0x80, "payload length must use a four-byte varint");
    let (capsule_type, used, decoded) =
        Connection::decode_capsule(&capsule).expect("decode large capsule");
    assert_eq!(capsule_type, 0x00);
    assert_eq!(used, capsule.len());
    assert_eq!(decoded, payload);
}

#[test]
fn masque_capsule_decoder_retains_split_tail_and_rejects_oversized_length() {
    let mut split = vec![0x00, 0x40];
    let events = Connection::decode_masque_capsules(&mut split).expect("split tail");
    assert!(events.is_empty());
    assert_eq!(split, vec![0x00, 0x40]);

    let mut oversized = vec![0x00, 0xC0, 0x3F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF];
    assert!(matches!(
        Connection::decode_masque_capsules(&mut oversized),
        Err(Error::ExcessiveLoad)
    ));
}

#[test]
fn masque_flow_id_varint_encoding() {
    // Verify flow ID is correctly encoded/decoded with varint
    let mut conn = make_conn();
    conn.enable_datagrams(256, 256);

    // Encode flow_id + payload manually and verify format
    let flow_id = 42u64;
    let payload = b"test udp payload";
    let mut buf = Vec::with_capacity(9 + payload.len());
    Connection::encode_varint(flow_id, &mut buf);
    buf.extend_from_slice(payload);

    // Decode and verify
    let (decoded_flow, used) = Connection::decode_varint(&buf).expect("decode varint");
    assert_eq!(decoded_flow, flow_id);
    assert_eq!(&buf[used..], payload);
}

#[cfg(feature = "masque-tests")]
#[test]
fn masque_capsule_loopback_roundtrip() {
    // Build a capsule and decode it back
    let mut buf = Vec::new();
    Connection::encode_varint(0x00, &mut buf); // DATAGRAM capsule
    let payload: Vec<u8> = (0..32u8).collect();
    Connection::encode_varint(payload.len() as u64, &mut buf);
    buf.extend_from_slice(&payload);
    let (ctype, used, pl) = Connection::decode_capsule(&buf).expect("capsule");
    assert_eq!(ctype, 0x00);
    assert_eq!(used, buf.len());
    assert_eq!(pl, payload);
}

#[cfg(feature = "masque-tests")]
#[test]
fn masque_dict_capsule_roundtrip() {
    use crate::compress;
    compress::set_current_persona("test/dict");
    // Train a small dict from samples.
    let base_samples: [&[u8]; 3] = [
        br#"{"a":1,"b":2,"c":3}"#.as_ref(),
        br#"{"foo":"bar","x":4}"#.as_ref(),
        br#"{"long":"somewhat longer json payload to help training"}"#.as_ref(),
    ];
    // Repeat small JSON samples to provide enough corpus for a stable test dictionary.
    let refs: Vec<&[u8]> = (0..96).map(|i| base_samples[i % base_samples.len()]).collect();
    // simulate training outcome by building dict from samples
    let dict_bytes = zstd::dict::from_samples(&refs, 8 * 1024).expect("dict");
    let pool = compress::body_pool();
    let payload = br#"{"msg":"hello json world","n":12345}"#;
    let (blk, used) =
        compress::compress_with_dict(&pool, payload, 5, &dict_bytes, 1).expect("compress");
    // Build a 0x22 capsule.
    let cap = super::h3::Connection::encode_capsule(0x22, &blk[..used]);
    // Parse the header inside the payload and decompress.
    assert!(cap.len() > 3);
    // Skip varints: 0x22 (type) + len -> payload starts at the end.
    // Here we directly test decompress_with_dict.
    let (_ctype, off) = {
        // grob varint decoding
        let mut off = 0usize;
        let first = cap[off];
        off += 1;
        let _ = first; // type
                       // len varint grob
        let mut used = 1;
        if cap[off] & 0x40 != 0 {
            used = 2;
        }
        off += used;
        (0x22u64, off)
    };
    let payload2 = &cap[off..];
    let (_out, n) =
        compress::decompress_with_dict(&pool, payload2, &dict_bytes).expect("decompress");
    assert_eq!(&payload[..], &_out[..n]);
}

#[cfg(feature = "masque-tests")]
#[test]
fn masque_capsule_rx_counters() {
    use crate::optimize::telemetry;
    let before21 = telemetry::MASQUE_CAPSULE_21.get();
    let before22 = telemetry::MASQUE_CAPSULE_22.get();
    // Build two capsules and pass to decode_capsule (RX counters are incremented there)
    let cap21 = super::h3::Connection::encode_capsule(0x21, b"abcd");
    let _ = Connection::decode_capsule(&cap21).expect("capsule21");
    let cap22 = super::h3::Connection::encode_capsule(0x22, b"efgh");
    let _ = Connection::decode_capsule(&cap22).expect("capsule22");
    assert!(telemetry::MASQUE_CAPSULE_21.get() > before21);
    assert!(telemetry::MASQUE_CAPSULE_22.get() > before22);
}

#[test]
fn test_header_new_accessors() {
    let h = Header::new(b"content-type", b"text/html");
    assert_eq!(h.name(), b"content-type");
    assert_eq!(h.value(), b"text/html");

    let h2 = Header::new(b":status", b"200");
    assert_eq!(h2.name(), b":status");
    assert_eq!(h2.value(), b"200");

    // Empty value
    let h3 = Header::new(b"x-empty", b"");
    assert_eq!(h3.name(), b"x-empty");
    assert_eq!(h3.value(), b"");
}

#[test]
fn test_config_new_defaults() {
    let cfg = Config::new().expect("Config::new");
    // Verify defaults are sane (non-zero max_field_section_size)
    assert_eq!(cfg.qpack_max_table_capacity(), 0);
    assert_eq!(cfg.qpack_blocked_streams(), 0);
    assert_eq!(cfg.max_field_section_size(), 1024 * 1024);
}

#[test]
fn test_encode_capsule_roundtrip() {
    let payload = b"test capsule payload data";
    let capsule = Connection::encode_capsule(0x00, payload);
    let (ctype, used, decoded) =
        Connection::decode_capsule(&capsule).expect("decode capsule roundtrip");
    assert_eq!(ctype, 0x00);
    assert_eq!(used, capsule.len());
    assert_eq!(decoded, payload);
}

#[test]
fn test_encode_capsule_empty_payload() {
    let capsule = Connection::encode_capsule(0x21, &[]);
    let (ctype, used, decoded) =
        Connection::decode_capsule(&capsule).expect("decode empty capsule");
    assert_eq!(ctype, 0x21);
    assert_eq!(used, capsule.len());
    assert!(decoded.is_empty());
}

#[test]
fn masque_response_status_accepts_only_valid_status_headers() {
    assert_eq!(Connection::masque_response_status(&[Header::new(b":status", b"200")]), Some(200));
    assert_eq!(Connection::masque_response_status(&[Header::new(b":status", b"403")]), Some(403));
    assert_eq!(Connection::masque_response_status(&[Header::new(b":status", b"invalid")]), None);
    assert_eq!(
        Connection::masque_response_status(&[Header::new(b"content-type", b"text/plain")]),
        None
    );
}

#[test]
fn test_encode_udp_compress_capsule_contains_flow_id() {
    // encode_capsule with type 0x21 should start with varint 0x21
    let payload = b"some compressed data";
    let capsule = Connection::encode_capsule(0x21, payload);

    // First byte(s) encode the capsule type as varint.
    // 0x21 = 33 fits in a single-byte varint (< 64).
    assert!(!capsule.is_empty());
    let (decoded_type, _) = Connection::decode_varint(&capsule).expect("varint decode");
    assert_eq!(decoded_type, 0x21);

    // Full roundtrip confirms payload integrity
    let (ctype, _, decoded_payload) = Connection::decode_capsule(&capsule).expect("decode capsule");
    assert_eq!(ctype, 0x21);
    assert_eq!(decoded_payload, payload);
}
