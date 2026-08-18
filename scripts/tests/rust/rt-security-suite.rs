#![cfg(feature = "rust-tests")]

use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};

use crossbeam_channel::bounded;

use quicfuscate::crypto::aead::{AeadOpen, AeadSeal};
use quicfuscate::crypto::ChaCha20Poly1305;
use quicfuscate::crypto::{install_data_aead_config, select_data_aead, Aegis128LAead};
use quicfuscate::engine::{AeadPreference, CryptoConfig};
use quicfuscate::error::ConnectionError;
use quicfuscate::fec::{Encoder8, FecDecoder8, FecPacket};
use quicfuscate::optimize::{ConstPacketPool, MemoryPool};
use quicfuscate::transport::frames::{from_bytes, to_bytes, wire_len};
use quicfuscate::transport::varint::{
    read_varint, varint_len, write_varint, write_varint_with_len,
};
use quicfuscate::transport::{Frame, PacketType};
use std::borrow::Cow;

fn encode_frame(frame: &Frame<'_>, pkt: PacketType) -> Vec<u8> {
    let len = wire_len(frame).expect("valid frame wire length");
    let mut buf = vec![0u8; len];
    let used = to_bytes(frame, &mut buf).expect("to_bytes");
    assert_eq!(used, len);
    let (decoded, used2) = from_bytes(&buf, pkt).expect("from_bytes");
    assert_eq!(used2, len);
    assert_eq!(&decoded, frame);
    buf
}

#[test]
fn malformed_packet_truncated_varint() {
    let buf = vec![0x40];
    let err = from_bytes(&buf, PacketType::Short).expect_err("truncated varint must fail");
    assert!(matches!(err, ConnectionError::BufferTooShort));
}

#[test]
fn malformed_packet_unknown_frame() {
    let mut buf = vec![0u8; 2];
    let used = write_varint(0x2f, &mut buf).expect("write varint");
    let err = from_bytes(&buf[..used], PacketType::Short).expect_err("unknown frame must fail");
    assert!(matches!(err, ConnectionError::InvalidFrame));
}

#[test]
fn oversized_input_datagram_length() {
    let len = 512u64;
    let mut buf = vec![0u8; 1 + varint_len(len)];
    buf[0] = 0x31;
    write_varint(len, &mut buf[1..]).expect("write length");
    let err = from_bytes(&buf, PacketType::Short).expect_err("oversized datagram must fail");
    assert!(matches!(err, ConnectionError::BufferTooShort));
}

#[test]
fn boundary_conditions_varint_edges() {
    let values =
        [0u64, 0x3f, 0x40, 0x3fff, 0x4000, 0x3fff_ffff, 0x4000_0000, 0x3fff_ffff_ffff_ffff];
    for value in values {
        let mut buf = vec![0u8; varint_len(value)];
        let used = write_varint(value, &mut buf).expect("write varint");
        let (decoded, used2) = read_varint(&buf).expect("read varint");
        assert_eq!(used, used2);
        assert_eq!(decoded, value);
    }
}

#[test]
fn integer_overflow_varint_rejected() {
    let mut buf = vec![0u8; 8];
    let err =
        write_varint_with_len(0x4000_0000_0000_0000, 8, &mut buf).expect_err("overflow must fail");
    assert!(matches!(err, ConnectionError::InvalidPacket));
}

#[test]
fn buffer_overflow_varint_encode_rejected() {
    let mut buf = vec![0u8; 2];
    let err = write_varint(0x4000, &mut buf).expect_err("buffer too short must fail");
    assert!(matches!(err, ConnectionError::BufferTooShort));
}

#[test]
fn use_after_free_pool_clears_len() {
    let mut pool: ConstPacketPool<2, 32> = ConstPacketPool::new();
    let buf_ptr = {
        let buf = pool.alloc().expect("alloc");
        buf.write(b"payload");
        assert_eq!(buf.as_slice(), b"payload");
        buf as *const _
    };
    unsafe {
        pool.free(&*buf_ptr);
    }
    let buf2 = pool.alloc().expect("re-alloc");
    assert!(buf2.as_slice().is_empty());
}

#[test]
fn double_free_guard_prevents_duplicate_allocation() {
    let mut pool: ConstPacketPool<2, 32> = ConstPacketPool::new();
    let buf_ptr = {
        let buf = pool.alloc().expect("alloc");
        buf as *const _
    };
    unsafe {
        pool.free(&*buf_ptr);
        // The second free must be rejected. Otherwise the slot would be handed out twice and the
        // pool would appear to hold three buffers instead of two.
        pool.free(&*buf_ptr);
    }
    assert!(pool.alloc().is_some(), "the freed slot is available again");
    assert!(pool.alloc().is_some(), "the untouched second slot is still available");
    assert!(pool.alloc().is_none(), "a double free must not create a third slot");
}

#[test]
fn resource_exhaustion_prevents_overalloc() {
    // A ConstPacketPool<N, _> yields exactly N buffers. The previous reserved-slot ring silently
    // dropped the last index, so this pool used to hand out only two.
    let mut pool: ConstPacketPool<3, 32> = ConstPacketPool::new();
    assert!(pool.alloc().is_some(), "slot 1 of 3");
    assert!(pool.alloc().is_some(), "slot 2 of 3");
    assert!(pool.alloc().is_some(), "slot 3 of 3 must not be lost to a reserved ring slot");
    assert!(pool.alloc().is_none(), "the fourth allocation must fail");
}

#[test]
fn const_packet_pool_reports_its_full_declared_capacity() {
    let mut single: ConstPacketPool<1, 16> = ConstPacketPool::new();
    assert!(single.alloc().is_some(), "a pool of one must yield one buffer");
    assert!(single.alloc().is_none());

    let mut pair: ConstPacketPool<2, 16> = ConstPacketPool::new();
    assert!(pair.alloc().is_some());
    assert!(pair.alloc().is_some(), "a pool of two must yield two buffers");
    assert!(pair.alloc().is_none());
}

#[test]
fn zero_capacity_pool_is_representable_and_never_allocates() {
    // The old ring computed `(tail + 1) % N` on push, so a zero-capacity pool was a modulo-zero
    // hazard rather than a representable empty pool.
    let mut empty: ConstPacketPool<0, 16> = ConstPacketPool::new();
    assert!(empty.alloc().is_none(), "a zero-capacity pool can never allocate");
    assert!(empty.alloc().is_none(), "and stays deterministic on repeat");
}

#[test]
fn freed_buffers_return_to_the_pool_and_preserve_total_capacity() {
    let mut pool: ConstPacketPool<2, 32> = ConstPacketPool::new();
    let first = pool.alloc().expect("first") as *const _;
    let second = pool.alloc().expect("second") as *const _;
    assert!(pool.alloc().is_none(), "both slots are checked out");

    unsafe {
        pool.free(&*first);
        pool.free(&*second);
    }

    assert!(pool.alloc().is_some(), "slot 1 returns");
    assert!(pool.alloc().is_some(), "slot 2 returns");
    assert!(pool.alloc().is_none(), "capacity is unchanged by a full cycle");
}

#[test]
fn timing_attack_tag_mismatch_rejected() {
    let key = [0x11u8; 32];
    let nonce = [0x22u8; 12];
    let mut buf = vec![0u8; 64 + 16];
    buf[..64].copy_from_slice(&[0xAB; 64]);
    let seal = ChaCha20Poly1305::new(&key, &nonce).expect("exact ChaCha fixture lengths");
    let out_len = seal.seal_with_u64_counter(0, b"aad", &mut buf, 64, None).expect("seal");
    assert_eq!(out_len, 80);
    buf[79] ^= 0x01;
    let open = ChaCha20Poly1305::new(&key, &nonce).expect("exact ChaCha fixture lengths");
    let err = open.open_with_u64_counter(0, b"aad", &mut buf).expect_err("tamper must fail");
    assert!(matches!(err, ConnectionError::CryptoError(_)));
}

#[test]
fn prng_quality_two_draws_differ() {
    let mut a = [0u8; 32];
    let mut b = [0u8; 32];
    quicfuscate::rng::fill_secure_or_abort(
        &mut a,
        "rt-security-suite::prng_quality_two_draws_differ:a",
    );
    quicfuscate::rng::fill_secure_or_abort(
        &mut b,
        "rt-security-suite::prng_quality_two_draws_differ:b",
    );
    assert!(a.iter().any(|v| *v != 0));
    assert!(b.iter().any(|v| *v != 0));
    assert_ne!(a, b);
}

#[test]
fn crypto_properties_roundtrip() {
    let key = [0x5au8; 32];
    let nonce = [0x7bu8; 12];
    let plaintext = b"quicfuscate-crypto-roundtrip";
    let mut buf = vec![0u8; plaintext.len() + 16];
    buf[..plaintext.len()].copy_from_slice(plaintext);
    let seal = ChaCha20Poly1305::new(&key, &nonce).expect("exact ChaCha fixture lengths");
    let sealed_len =
        seal.seal_with_u64_counter(7, b"ad", &mut buf, plaintext.len(), None).expect("seal");
    let open = ChaCha20Poly1305::new(&key, &nonce).expect("exact ChaCha fixture lengths");
    let opened_len = open.open_with_u64_counter(7, b"ad", &mut buf).expect("open");
    assert_eq!(sealed_len, plaintext.len() + 16);
    assert_eq!(opened_len, plaintext.len());
    assert_eq!(&buf[..opened_len], plaintext);
}

fn seal_and_open_via_selected_aead(force_aead: &str, plaintext: &[u8], aad: &[u8]) -> Vec<u8> {
    let mut cfg = CryptoConfig { aead_preference: AeadPreference::Auto, ..Default::default() };
    cfg.force_aead = force_aead.to_string();
    install_data_aead_config(&cfg);

    let key = [0x42u8; 16];
    let iv = [0x24u8; 12];
    let (seal, open) = select_data_aead(&key, &iv).expect("exact data-plane fixture lengths");
    let mut buf = vec![0u8; plaintext.len() + 16];
    buf[..plaintext.len()].copy_from_slice(plaintext);
    let sealed = seal.seal_with_u64_counter(9, aad, &mut buf, plaintext.len(), None).expect("seal");
    let opened = open.open_with_u64_counter(9, aad, &mut buf).expect("open");
    assert_eq!(sealed, plaintext.len() + 16);
    assert_eq!(opened, plaintext.len());
    buf[..opened].to_vec()
}

#[test]
fn data_aead_public_aliases_match_aegis128l_roundtrip() {
    let plaintext = b"quicfuscate-public-aead-alias-roundtrip";
    let aad = b"alias-ad";

    let baseline = seal_and_open_via_selected_aead("aegis-128l", plaintext, aad);
    assert_eq!(baseline, plaintext);

    for alias in ["aegis", "aegis-128x4", "aegis-128x8"] {
        let opened = seal_and_open_via_selected_aead(alias, plaintext, aad);
        assert_eq!(opened, baseline, "alias {alias} diverged from Aegis128L contract");
    }
}

#[test]
fn data_aead_aliases_handle_unaligned_tail_payloads() {
    let key = [0x33u8; 16];
    let iv = [0x55u8; 12];
    let aad = b"unaligned-tail-ad";
    let payload = b"tail-heavy-payload-with-nonmultiple-length";

    let direct = Aegis128LAead::new(&key, &iv).expect("exact AEGIS fixture lengths");
    let mut baseline_buf = vec![0u8; payload.len() + 16];
    baseline_buf[..payload.len()].copy_from_slice(payload);
    let baseline_len = direct
        .seal_with_u64_counter(11, aad, &mut baseline_buf, payload.len(), None)
        .expect("baseline seal");
    let opened_len =
        direct.open_with_u64_counter(11, aad, &mut baseline_buf).expect("baseline open");
    assert_eq!(baseline_len, payload.len() + 16);
    assert_eq!(&baseline_buf[..opened_len], payload);

    for alias in ["aegis-128x4", "aegis-128x8"] {
        let opened = seal_and_open_via_selected_aead(alias, payload, aad);
        assert_eq!(opened, payload, "alias {alias} failed on unaligned tail payload");
    }
}

#[test]
fn data_aead_force_morus_roundtrip() {
    let plaintext = b"quicfuscate-public-morus-roundtrip";
    let aad = b"morus-ad";

    let opened = seal_and_open_via_selected_aead("morus", plaintext, aad);
    assert_eq!(opened, plaintext);
}

#[test]
fn replay_attack_duplicate_ack_ranges_collapsed() {
    let frame =
        Frame::Ack { ack_delay: 2, ranges: vec![(10, 12), (1, 2), (12, 13)], ecn_counts: None };
    let len = wire_len(&frame).expect("valid ACK wire length");
    let mut buf = vec![0u8; len];
    let used = to_bytes(&frame, &mut buf).expect("to_bytes");
    assert_eq!(used, len);
    let (decoded, _) = from_bytes(&buf, PacketType::Short).expect("from_bytes");
    match decoded {
        Frame::Ack { ranges, .. } => {
            assert_eq!(ranges, vec![(1, 2), (10, 13)]);
        }
        _ => panic!("unexpected frame"),
    }
}

#[test]
fn ack_block_overflow_rejected() {
    const MAX_VARINT: u64 = 0x3fff_ffff_ffff_ffff;
    let mut buf = vec![0u8; 1 + varint_len(0) + varint_len(0) + varint_len(MAX_VARINT)];
    let mut off = 0usize;
    off += write_varint(0x02, &mut buf[off..]).expect("type");
    off += write_varint(0, &mut buf[off..]).expect("largest_ack");
    off += write_varint(0, &mut buf[off..]).expect("ack_delay");
    off += write_varint(MAX_VARINT, &mut buf[off..]).expect("num_blocks");
    let err = from_bytes(&buf[..off], PacketType::Short).expect_err("overflow must fail");
    assert!(matches!(err, ConnectionError::InvalidFrame));
}

#[test]
fn amplification_attack_datagram_length_rejected() {
    let len = 10_000u64;
    let mut buf = vec![0u8; 1 + varint_len(len)];
    buf[0] = 0x31;
    write_varint(len, &mut buf[1..]).expect("write len");
    let err = from_bytes(&buf, PacketType::Short).expect_err("datagram length must fail");
    assert!(matches!(err, ConnectionError::BufferTooShort));
}

#[test]
fn transport_invariants_frame_roundtrip() {
    let frame = Frame::Stream {
        stream_id: 4,
        offset: 0,
        data: Cow::Owned(b"payload".to_vec()),
        fin: false,
    };
    let _ = encode_frame(&frame, PacketType::Short);
}

#[test]
fn fec_properties_single_repair_recovers_missing() {
    let pool = Arc::new(MemoryPool::new(32, 256));
    let mut enc = Encoder8::new(4, 6);
    let payloads = [
        (1u64, b"one".to_vec()),
        (2u64, b"two".to_vec()),
        (3u64, b"three".to_vec()),
        (4u64, b"four".to_vec()),
    ];
    for (id, data) in payloads.iter() {
        let pkt = FecPacket::try_new(
            *id,
            Some(pool.alloc_from_slice(data)),
            data.len(),
            true,
            None,
            0,
            Arc::clone(&pool),
        )
        .unwrap();
        enc.take_packet(pkt);
    }
    let repair = enc.generate_repair_packet(0, &pool).expect("repair packet");
    let mut dec = FecDecoder8::new(4, Arc::clone(&pool));
    for (id, data) in payloads.iter() {
        if *id == 2 {
            continue;
        }
        let pkt = FecPacket::try_new(
            *id,
            Some(pool.alloc_from_slice(data)),
            data.len(),
            true,
            None,
            0,
            Arc::clone(&pool),
        )
        .unwrap();
        dec.take_packet(pkt);
    }
    dec.take_packet(repair);
    let recovered = dec.poll_recovered();
    let recovered_two = recovered.into_iter().find(|p| p.id == 2);
    let recovered_two = recovered_two.expect("missing packet recovered");
    let recovered_data = recovered_two.payload_slice().expect("recovered data");
    let recovered_slice = &recovered_data[..payloads[1].1.len()];
    assert_eq!(recovered_slice, payloads[1].1.as_slice());
}

#[test]
fn data_race_parallel_alloc_free() {
    let pool = Arc::new(MemoryPool::new(64, 512));
    let done = Arc::new(AtomicUsize::new(0));
    let (tx, rx) = bounded(8);

    for _ in 0..8 {
        let pool = Arc::clone(&pool);
        let done = Arc::clone(&done);
        let tx = tx.clone();
        std::thread::spawn(move || {
            for _ in 0..200 {
                let buf = pool.alloc();
                done.fetch_add(buf.len(), Ordering::Relaxed);
                pool.free(buf);
            }
            let _ = tx.send(());
        });
    }

    for _ in 0..8 {
        rx.recv_timeout(std::time::Duration::from_secs(5)).expect("thread stalled");
    }
    assert!(done.load(Ordering::Relaxed) > 0);
}

#[test]
fn deadlock_detection_parallel_alloc_free() {
    let pool = Arc::new(MemoryPool::new(32, 256));
    let (tx, rx) = bounded(4);

    for _ in 0..4 {
        let pool = Arc::clone(&pool);
        let tx = tx.clone();
        std::thread::spawn(move || {
            for _ in 0..100 {
                let buf = pool.alloc();
                pool.free(buf);
            }
            let _ = tx.send(());
        });
    }

    for _ in 0..4 {
        rx.recv_timeout(std::time::Duration::from_secs(5)).expect("deadlock detected");
    }
}

#[test]
fn race_conditions_parallel_alloc_free_consistency() {
    let pool = Arc::new(MemoryPool::new(16, 128));
    let (tx, rx) = bounded(6);

    for _ in 0..6 {
        let pool = Arc::clone(&pool);
        let tx = tx.clone();
        std::thread::spawn(move || {
            for _ in 0..150 {
                let buf = pool.alloc();
                assert!(buf.len() >= 128);
                pool.free(buf);
            }
            let _ = tx.send(());
        });
    }

    for _ in 0..6 {
        rx.recv_timeout(std::time::Duration::from_secs(5)).expect("race condition detected");
    }
}
