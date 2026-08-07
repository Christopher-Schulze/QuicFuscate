#![cfg(feature = "rust-tests")]

use std::borrow::Cow;

use quicfuscate::error::ConnectionError;
use quicfuscate::transport::frames::{from_bytes, to_bytes, wire_len};
use quicfuscate::transport::{Frame, PacketType};

fn roundtrip(frame: Frame<'_>, pkt: PacketType) {
    let len = wire_len(&frame).expect("valid frame wire length");
    assert!(len > 0, "wire_len must be positive");
    let mut buf = vec![0u8; len];
    let used = to_bytes(&frame, &mut buf).expect("to_bytes");
    assert_eq!(used, len, "encoder must fill the buffer for {:?}", frame);
    let (parsed, used2) = from_bytes(&buf, pkt).expect("from_bytes");
    assert_eq!(parsed, frame, "decoder must match original for {:?} (buf={:02x?})", frame, buf);
    assert_eq!(used2, len, "decoder must consume full frame for {:?} (buf={:02x?})", frame, buf);
}

#[test]
fn roundtrip_basic_frames() {
    let frames = vec![
        Frame::Ping { mtu_probe: None },
        Frame::MaxData { max: 12345 },
        Frame::ResetStream { stream_id: 7, error_code: 1, final_size: 42 },
        Frame::StopSending { stream_id: 9, error_code: 2 },
        Frame::Crypto { offset: 3, data: Cow::Owned(b"crypto".to_vec()) },
        Frame::NewToken { token: Cow::Owned(b"token".to_vec()) },
        Frame::Stream { stream_id: 4, offset: 0, data: Cow::Owned(b"hello".to_vec()), fin: true },
        Frame::ConnectionClose {
            error_code: 0x1a,
            frame_type: 0x01,
            reason: Cow::Owned(b"bye".to_vec()),
        },
        Frame::ApplicationClose { error_code: 0x02, reason: Cow::Owned(b"app".to_vec()) },
        Frame::Datagram { data: Cow::Owned(b"payload".to_vec()) },
        Frame::PathChallenge { data: [0xAB; 8] },
        Frame::PathResponse { data: [0xCD; 8] },
    ];

    for frame in frames {
        roundtrip(frame, PacketType::Short);
    }
}

#[test]
fn datagram_header_requires_payload() {
    let frame = Frame::DatagramHeader { length: 128 };
    let len = wire_len(&frame).expect("valid datagram header wire length");
    let mut buf = vec![0u8; len];
    let used = to_bytes(&frame, &mut buf).expect("to_bytes");
    assert_eq!(used, len, "encoder must fill the buffer for {:?}", frame);
    let err = from_bytes(&buf, PacketType::Short).expect_err("header without payload must fail");
    assert!(matches!(err, ConnectionError::BufferTooShort));
}

#[test]
fn ack_roundtrip_canonicalizes_ranges() {
    let frame =
        Frame::Ack { ack_delay: 5, ranges: vec![(10, 12), (1, 2), (12, 13)], ecn_counts: None };

    let len = wire_len(&frame).expect("valid ACK wire length");
    let mut buf = vec![0u8; len];
    let used = to_bytes(&frame, &mut buf).expect("to_bytes");
    assert_eq!(used, len, "encoder must fill the buffer for {:?}", frame);
    let (parsed, used2) = from_bytes(&buf, PacketType::Short).expect("from_bytes");
    assert_eq!(used2, len, "decoder must consume full frame for {:?} (buf={:02x?})", frame, buf);
    match parsed {
        Frame::Ack { ranges, ecn_counts, .. } => {
            assert!(ecn_counts.is_none());
            assert_eq!(ranges, vec![(1, 2), (10, 13)]);
        }
        _ => panic!("expected ACK frame"),
    }
}

#[test]
fn ack_in_zero_rtt_is_invalid() {
    let frame = Frame::Ack { ack_delay: 1, ranges: vec![(1, 2)], ecn_counts: None };
    let len = wire_len(&frame).expect("valid ACK wire length");
    let mut buf = vec![0u8; len];
    let used = to_bytes(&frame, &mut buf).expect("to_bytes");
    assert_eq!(used, len);

    let err = from_bytes(&buf, PacketType::ZeroRTT).expect_err("ACK in 0-RTT should fail");
    assert!(matches!(err, ConnectionError::InvalidFrame));
}
