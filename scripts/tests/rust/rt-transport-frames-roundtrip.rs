#![cfg(feature = "rust-tests")]

use std::borrow::Cow;
use std::sync::Arc;

use quicfuscate::error::ConnectionError;
use quicfuscate::optimize::MemoryPool;
use quicfuscate::transport::frames::{batch_encode_frames, from_bytes, to_bytes, wire_len};
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

#[test]
fn malformed_ack_ranges_are_rejected_before_serialization() {
    for ranges in [vec![], vec![(5, 5)], vec![(8, 3)], vec![(1, 2), (7, 7)]] {
        let frame = Frame::Ack { ack_delay: 0, ranges, ecn_counts: None };
        let mut out = [0xA5u8; 64];

        assert!(matches!(wire_len(&frame), Err(ConnectionError::InvalidFrame)));
        assert!(matches!(to_bytes(&frame, &mut out), Err(ConnectionError::InvalidFrame)));
        assert!(out.iter().all(|byte| *byte == 0xA5));
    }
}

#[test]
fn malformed_connection_ids_are_rejected_before_serialization() {
    let mut zero_length_cid = vec![0x18, 0, 0, 0];
    zero_length_cid.extend_from_slice(&[0u8; 16]);
    assert!(matches!(
        from_bytes(&zero_length_cid, PacketType::Short),
        Err(ConnectionError::InvalidFrame)
    ));

    let mut oversized_cid = vec![0x18, 0, 0, 21];
    oversized_cid.extend_from_slice(&[0u8; 21]);
    oversized_cid.extend_from_slice(&[0u8; 16]);
    assert!(matches!(
        from_bytes(&oversized_cid, PacketType::Short),
        Err(ConnectionError::InvalidFrame)
    ));

    let frame = Frame::NewConnectionId {
        seq_num: 2,
        retire_prior_to: 3,
        conn_id: Cow::Borrowed(&[1u8, 2, 3]),
        reset_token: [0u8; 16],
    };
    let mut out = [0xA5u8; 64];
    assert!(matches!(wire_len(&frame), Err(ConnectionError::InvalidFrame)));
    assert!(matches!(to_bytes(&frame, &mut out), Err(ConnectionError::InvalidFrame)));
    assert!(out.iter().all(|byte| *byte == 0xA5));
}

#[test]
fn arm_stream_cursor_bounds_are_rejected() {
    for input in [&[0x08u8][..], &[0x0E, 0x40][..], &[0x0E, 0x00, 0x40][..]] {
        assert!(matches!(
            from_bytes(input, PacketType::Short),
            Err(ConnectionError::BufferTooShort)
        ));
    }
}

#[test]
fn batch_encoding_rejects_cumulative_capacity_overflow() {
    let frames = [Frame::Padding { len: 2 }, Frame::Padding { len: 2 }];
    let pool = Arc::new(MemoryPool::new(2, 64));
    let mut out = [0u8; 3];

    assert!(matches!(
        batch_encode_frames(&frames, &mut out, pool),
        Err(ConnectionError::BufferTooShort)
    ));
}
