#![cfg(feature = "rust-tests")]

use quicfuscate::error::ConnectionError;
use quicfuscate::transport::packet::{
    encode_pkt_num, format_header, format_short_header, parse_header, Header, PacketType,
    MAX_CID_LEN,
};

#[test]
fn short_header_roundtrip() {
    let hdr = Header {
        ty: PacketType::Short,
        version: 0,
        dcid: vec![0xAA, 0xBB, 0xCC, 0xDD],
        scid: Vec::new(),
        pkt_num: 0,
        pkt_num_len: 0,
        token: None,
        versions: None,
        key_phase: true,
    };
    let mut buf = vec![0u8; 64];
    let used = format_header(&hdr, &mut buf).expect("format_header");
    let (parsed, pn_off) = parse_header(&buf[..used], hdr.dcid.len()).expect("parse_header");
    assert_eq!(pn_off, 1 + hdr.dcid.len());
    assert_eq!(parsed.ty, PacketType::Short);
    assert_eq!(parsed.dcid, hdr.dcid);
    assert!(parsed.scid.is_empty());
    assert!(parsed.key_phase);
}

#[test]
fn long_header_roundtrip_initial() {
    let hdr = Header {
        ty: PacketType::Initial,
        version: 0x1,
        dcid: vec![1, 2, 3],
        scid: vec![4, 5],
        pkt_num: 0,
        pkt_num_len: 0,
        token: None,
        versions: None,
        key_phase: false,
    };
    let mut buf = vec![0u8; 64];
    let used = format_header(&hdr, &mut buf).expect("format_header");
    let (parsed, pn_off) = parse_header(&buf[..used], 0).expect("parse_header");
    assert!(pn_off > 0);
    assert_eq!(parsed.ty, PacketType::Initial);
    assert_eq!(parsed.version, hdr.version);
    assert_eq!(parsed.dcid, hdr.dcid);
    assert_eq!(parsed.scid, hdr.scid);
}

#[test]
fn parse_header_rejects_missing_fixed_bit() {
    let buf = [0x00u8, 0x01, 0x02, 0x03];
    let err = parse_header(&buf, 0).expect_err("invalid fixed bit");
    assert!(matches!(err, ConnectionError::InvalidPacket));
}

#[test]
fn encode_packet_number_lengths() {
    let pn = 0xA1B2_C3D4u64;
    let mut out = [0u8; 4];

    let used1 = encode_pkt_num(pn, 1, &mut out[..1]).expect("pn len 1");
    assert_eq!(used1, 1);
    assert_eq!(out[0], (pn & 0xFF) as u8);

    let used2 = encode_pkt_num(pn, 2, &mut out[..2]).expect("pn len 2");
    assert_eq!(used2, 2);
    assert_eq!(&out[..2], &[(pn >> 8) as u8, pn as u8]);

    let used3 = encode_pkt_num(pn, 3, &mut out[..3]).expect("pn len 3");
    assert_eq!(used3, 3);
    assert_eq!(&out[..3], &[(pn >> 16) as u8, (pn >> 8) as u8, pn as u8]);

    let used4 = encode_pkt_num(pn, 4, &mut out[..4]).expect("pn len 4");
    assert_eq!(used4, 4);
    assert_eq!(&out[..4], &(pn as u32).to_be_bytes());
}

#[test]
fn encode_packet_number_rejects_invalid_len() {
    let pn = 0x11u64;
    let mut out = [0u8; 8];
    let err = encode_pkt_num(pn, 5, &mut out).expect_err("invalid length");
    assert!(matches!(err, ConnectionError::InvalidPacket));
}

#[test]
fn encode_packet_number_rejects_short_buffer() {
    let pn = 0x11u64;
    let mut out = [0u8; 1];
    let err = encode_pkt_num(pn, 2, &mut out).expect_err("buffer too short");
    assert!(matches!(err, ConnectionError::BufferTooShort));
}

#[test]
fn malformed_headers_fail_before_output_mutation() {
    let hdr = Header {
        ty: PacketType::Initial,
        version: 1,
        dcid: vec![0xAA; MAX_CID_LEN + 1],
        scid: vec![0xBB],
        pkt_num: 0,
        pkt_num_len: 0,
        token: None,
        versions: None,
        key_phase: false,
    };
    let mut out = [0xA5u8; 64];
    let original = out;
    assert_eq!(format_header(&hdr, &mut out), Err(ConnectionError::InvalidPacket));
    assert_eq!(out, original);
    assert_eq!(
        format_short_header(&[0xCC; MAX_CID_LEN + 1], false, &mut out),
        Err(ConnectionError::InvalidPacket)
    );
    assert_eq!(out, original);
}

#[test]
fn packet_number_encoding_supports_unaligned_output() {
    let mut storage = [0xCCu8; 8];
    assert_eq!(encode_pkt_num(0x01_02_03_04, 4, &mut storage[1..5]), Ok(4));
    assert_eq!(&storage[1..5], &[0x01, 0x02, 0x03, 0x04]);
}

#[cfg(all(target_arch = "x86_64", target_feature = "avx2"))]
#[test]
fn native_avx2_packet_number_encoding_matches_scalar_unaligned() {
    assert!(std::is_x86_feature_detected!("avx2"));
    assert!(
        quicfuscate::optimize::FeatureDetector::instance()
            .features_full()
            .simd_dispatch_matrix()
            .avx2
    );
    for (packet_number, length) in [
        (0x00_00_00_7Fu64, 1usize),
        (0x00_00_A1_B2u64, 2),
        (0x00_C3_D4_E5u64, 3),
        (0xA1_B2_C3_D4u64, 4),
    ] {
        let mut scalar = [0xCCu8; 8];
        let mut actual = [0xCCu8; 8];
        let expected_len = scalar_encode_packet_number(packet_number, length, &mut scalar[1..]);
        assert_eq!(encode_pkt_num(packet_number, length, &mut actual[1..]), Ok(expected_len));
        assert_eq!(&actual[1..=length], &scalar[1..=length]);
        assert_eq!(actual[0], 0xCC);
        assert_eq!(actual[length + 1], 0xCC);
    }
}
