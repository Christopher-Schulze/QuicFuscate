#![cfg(feature = "rust-tests")]

use std::sync::{Arc, Mutex};

use proptest::prelude::*;
use quicfuscate::crypto::aead::{AeadOpen, AeadSeal};
use quicfuscate::crypto::ChaCha20Poly1305;
use quicfuscate::crypto::{install_data_aead_config, select_data_aead};
use quicfuscate::engine::{AeadPreference, CryptoConfig};
use quicfuscate::fec::{Encoder8, FecDecoder8, FecPacket};
use quicfuscate::optimize::MemoryPool;
use quicfuscate::rng::push_hex_byte;
use quicfuscate::transport::frames::{from_bytes, to_bytes, wire_len};
use quicfuscate::transport::varint::{read_varint, varint_len, write_varint};
use quicfuscate::transport::{ConnectionId, Frame, PacketType};
use std::borrow::Cow;

const MAX_VARINT: u64 = 0x3fff_ffff_ffff_ffff;

static DATA_AEAD_CONFIG_MUTEX: Mutex<()> = Mutex::new(());
const PUBLIC_AEGIS_ALIASES: [&str; 3] = ["aegis", "aegis-128l", "aegis128l"];

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 96,
        failure_persistence: None,
        .. ProptestConfig::default()
    })]

    #[test]
    fn prop_varint_roundtrip(value in 0u64..=MAX_VARINT) {
        let mut buf = vec![0u8; varint_len(value)];
        let used = write_varint(value, &mut buf).expect("write varint");
        let (decoded, used2) = read_varint(&buf).expect("read varint");
        prop_assert_eq!(used, used2);
        prop_assert_eq!(decoded, value);
    }

    #[test]
    fn prop_stream_frame_roundtrip(
        stream_id in 0u64..=1024,
        offset in 0u64..=4096,
        fin in any::<bool>(),
        data in proptest::collection::vec(any::<u8>(), 0..256),
    ) {
        let frame = Frame::Stream { stream_id, offset, data: Cow::Owned(data.clone()), fin };
        let len = wire_len(&frame);
        let mut buf = vec![0u8; len];
        let used = to_bytes(&frame, &mut buf).expect("to_bytes");
        let (decoded, used2) = from_bytes(&buf[..used], PacketType::Short).expect("from_bytes");
        prop_assert_eq!(used, len);
        prop_assert_eq!(used2, len);
        prop_assert_eq!(decoded, frame);
    }

    #[test]
    fn prop_chacha20poly1305_roundtrip(
        counter in any::<u64>(),
        plaintext in proptest::collection::vec(any::<u8>(), 0..256),
        aad in proptest::collection::vec(any::<u8>(), 0..64),
    ) {
        let key = [0xA5u8; 32];
        let nonce = [0x3Cu8; 12];
        let mut buf = vec![0u8; plaintext.len() + 16];
        buf[..plaintext.len()].copy_from_slice(&plaintext);

        let seal = ChaCha20Poly1305::new(&key, &nonce);
        let sealed_len =
            seal.seal_with_u64_counter(counter, &aad, &mut buf, plaintext.len(), None).expect("seal");
        let open = ChaCha20Poly1305::new(&key, &nonce);
        let opened_len = open.open_with_u64_counter(counter, &aad, &mut buf).expect("open");

        prop_assert_eq!(sealed_len, plaintext.len() + 16);
        prop_assert_eq!(opened_len, plaintext.len());
        prop_assert_eq!(&buf[..opened_len], plaintext.as_slice());
    }

    #[test]
    fn prop_data_aead_alias_contract_roundtrip(
        counter in any::<u64>(),
        plaintext in proptest::collection::vec(any::<u8>(), 0..192),
        aad in proptest::collection::vec(any::<u8>(), 0..48),
    ) {
        let _config_lock = DATA_AEAD_CONFIG_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
        let key = [0x11u8; 16];
        let iv = [0x22u8; 12];

        let mut baseline_cfg = CryptoConfig { aead_preference: AeadPreference::Auto, ..Default::default() };
        baseline_cfg.force_aead = "aegis-128l".to_string();
        install_data_aead_config(&baseline_cfg);
        let (baseline_seal, baseline_open) = select_data_aead(&key, &iv);
        let mut baseline_buf = vec![0u8; plaintext.len() + 16];
        baseline_buf[..plaintext.len()].copy_from_slice(&plaintext);
        baseline_seal
            .seal_with_u64_counter(counter, &aad, &mut baseline_buf, plaintext.len(), None)
            .expect("baseline seal");
        let baseline_opened = baseline_open
            .open_with_u64_counter(counter, &aad, &mut baseline_buf)
            .expect("baseline open");
        prop_assert_eq!(&baseline_buf[..baseline_opened], plaintext.as_slice());

        for alias in PUBLIC_AEGIS_ALIASES {
            let mut cfg = CryptoConfig { aead_preference: AeadPreference::Auto, ..Default::default() };
            cfg.force_aead = alias.to_string();
            install_data_aead_config(&cfg);
            let (seal, open) = select_data_aead(&key, &iv);
            let mut buf = vec![0u8; plaintext.len() + 16];
            buf[..plaintext.len()].copy_from_slice(&plaintext);
            seal
                .seal_with_u64_counter(counter, &aad, &mut buf, plaintext.len(), None)
                .expect("alias seal");
            let opened = open
                .open_with_u64_counter(counter, &aad, &mut buf)
                .expect("alias open");
            prop_assert_eq!(
                &buf[..opened],
                &baseline_buf[..baseline_opened],
                "alias {} diverged from public Aegis128L plaintext contract",
                alias
            );
        }
    }

    #[test]
    fn prop_data_aead_alias_ciphertext_matches_public_contract(
        counter in any::<u64>(),
        plaintext in proptest::collection::vec(any::<u8>(), 0..192),
        aad in proptest::collection::vec(any::<u8>(), 0..48),
    ) {
        let _config_lock = DATA_AEAD_CONFIG_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
        let key = [0x51u8; 16];
        let iv = [0x61u8; 12];

        let mut baseline_cfg = CryptoConfig { aead_preference: AeadPreference::Auto, ..Default::default() };
        baseline_cfg.force_aead = "aegis-128l".to_string();
        install_data_aead_config(&baseline_cfg);
        let (baseline_seal, _) = select_data_aead(&key, &iv);
        let mut baseline_buf = vec![0u8; plaintext.len() + 16];
        baseline_buf[..plaintext.len()].copy_from_slice(&plaintext);
        let baseline_len = baseline_seal
            .seal_with_u64_counter(counter, &aad, &mut baseline_buf, plaintext.len(), None)
            .expect("baseline seal");

        for alias in PUBLIC_AEGIS_ALIASES {
            let mut cfg = CryptoConfig { aead_preference: AeadPreference::Auto, ..Default::default() };
            cfg.force_aead = alias.to_string();
            install_data_aead_config(&cfg);
            let (seal, _) = select_data_aead(&key, &iv);
            let mut buf = vec![0u8; plaintext.len() + 16];
            buf[..plaintext.len()].copy_from_slice(&plaintext);
            let alias_len = seal
                .seal_with_u64_counter(counter, &aad, &mut buf, plaintext.len(), None)
                .expect("alias seal");

            prop_assert_eq!(alias_len, baseline_len, "alias {} changed seal length", alias);
            prop_assert_eq!(
                &buf[..alias_len],
                &baseline_buf[..baseline_len],
                "alias {} changed ciphertext/tag bytes",
                alias
            );
        }
    }

    #[test]
    fn prop_data_aead_morus_roundtrip(
        counter in any::<u64>(),
        plaintext in proptest::collection::vec(any::<u8>(), 0..192),
        aad in proptest::collection::vec(any::<u8>(), 0..48),
    ) {
        let _config_lock = DATA_AEAD_CONFIG_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
        let key = [0x77u8; 16];
        let iv = [0x88u8; 12];

        let mut cfg = CryptoConfig { aead_preference: AeadPreference::Auto, ..Default::default() };
        cfg.force_aead = "morus".to_string();
        install_data_aead_config(&cfg);
        let (seal, open) = select_data_aead(&key, &iv);
        let mut buf = vec![0u8; plaintext.len() + 16];
        buf[..plaintext.len()].copy_from_slice(&plaintext);
        let sealed = seal
            .seal_with_u64_counter(counter, &aad, &mut buf, plaintext.len(), None)
            .expect("morus seal");
        let opened = open
            .open_with_u64_counter(counter, &aad, &mut buf)
            .expect("morus open");

        prop_assert_eq!(sealed, plaintext.len() + 16);
        prop_assert_eq!(opened, plaintext.len());
        prop_assert_eq!(&buf[..opened], plaintext.as_slice());
    }

    #[test]
    fn prop_fec_single_repair_recovers_one_loss(
        payloads in proptest::collection::vec(proptest::array::uniform32(any::<u8>()), 4),
        drop_index in 0usize..4,
    ) {
        let pool = Arc::new(MemoryPool::new(64, 256));
        let mut enc = Encoder8::new(4, 6);

        for (idx, payload) in payloads.iter().enumerate() {
            let id = (idx + 1) as u64;
            let pkt = FecPacket::new(
                id,
                Some(pool.alloc_from_slice(payload)),
                payload.len(),
                true,
                None,
                0,
                Arc::clone(&pool),
            );
            enc.take_packet(pkt);
        }

        let repair = enc.generate_repair_packet(0, &pool).expect("repair packet");
        let mut dec = FecDecoder8::new(4, Arc::clone(&pool));

        for (idx, payload) in payloads.iter().enumerate() {
            if idx == drop_index {
                continue;
            }
            let id = (idx + 1) as u64;
            let pkt = FecPacket::new(
                id,
                Some(pool.alloc_from_slice(payload)),
                payload.len(),
                true,
                None,
                0,
                Arc::clone(&pool),
            );
            dec.take_packet(pkt);
        }
        dec.take_packet(repair);

        let expected_id = (drop_index + 1) as u64;
        let recovered = dec.poll_recovered().into_iter().find(|p| p.id == expected_id);
        let recovered = recovered.expect("missing packet should be recovered");
        let recovered_data = recovered.payload_slice().expect("recovered data");
        prop_assert_eq!(&recovered_data[..32], payloads[drop_index].as_slice());
    }

    // ---- New property tests (TODO-268) ----

    /// ConnectionId reflexive equality: constructing from the same bytes always
    /// yields equal IDs, and as_ref() returns the original bytes.
    #[test]
    fn prop_connection_id_equality(
        bytes in proptest::collection::vec(any::<u8>(), 0..=20),
    ) {
        let a = ConnectionId::from_ref(&bytes);
        let b = ConnectionId::from_ref(&bytes);
        // Reflexive: a == a
        prop_assert_eq!(&a, &a);
        // Two IDs from identical bytes are equal
        prop_assert_eq!(&a, &b);
        // as_ref round-trip preserves bytes
        prop_assert_eq!(a.as_ref(), bytes.as_slice());
        // to_vec round-trip preserves bytes
        prop_assert_eq!(a.to_vec(), bytes.clone());
        // from_vec also produces the same ID
        let c = ConnectionId::from_vec(bytes);
        prop_assert_eq!(&a, &c);
    }

    /// push_hex_byte produces exactly 2 lowercase hex characters per byte,
    /// and the output decodes back to the original byte.
    #[test]
    fn prop_hex_byte_roundtrip(byte in any::<u8>()) {
        let mut out = String::new();
        push_hex_byte(&mut out, byte);
        // Exactly 2 characters
        prop_assert_eq!(out.len(), 2);
        // All characters are lowercase hex digits
        for ch in out.chars() {
            prop_assert!(
                ch.is_ascii_hexdigit() && !ch.is_ascii_uppercase(),
                "expected lowercase hex, got '{}'", ch
            );
        }
        // Decoding the hex string recovers the original byte
        let decoded = u8::from_str_radix(&out, 16).expect("valid hex");
        prop_assert_eq!(decoded, byte);
    }

    /// varint_len returns the actual encoded size, and the result is always
    /// one of {1, 2, 4, 8}.
    #[test]
    fn prop_varint_len_matches_encoding(value in 0u64..=MAX_VARINT) {
        let expected_len = varint_len(value);
        // Valid QUIC varint lengths
        prop_assert!(
            matches!(expected_len, 1 | 2 | 4 | 8),
            "varint_len returned {}, expected 1/2/4/8", expected_len
        );
        // Encode and verify actual bytes used matches declared length
        let mut buf = vec![0u8; 8];
        let written = write_varint(value, &mut buf).expect("write varint");
        prop_assert_eq!(written, expected_len);
    }

    /// Crypto frame round-trip: encode then decode preserves offset and data.
    #[test]
    fn prop_crypto_frame_roundtrip(
        offset in 0u64..=4096,
        data in proptest::collection::vec(any::<u8>(), 0..256),
    ) {
        let frame = Frame::Crypto { offset, data: Cow::Owned(data.clone()) };
        let len = wire_len(&frame);
        let mut buf = vec![0u8; len];
        let used = to_bytes(&frame, &mut buf).expect("to_bytes");
        let (decoded, used2) = from_bytes(&buf[..used], PacketType::Initial).expect("from_bytes");
        prop_assert_eq!(used, len);
        prop_assert_eq!(used2, len);
        prop_assert_eq!(decoded, frame);
    }

    /// AEAD tamper detection: flipping any single bit in ciphertext or tag
    /// must cause open to fail.
    #[test]
    fn prop_chacha20poly1305_tamper_detected(
        counter in any::<u64>(),
        plaintext in proptest::collection::vec(any::<u8>(), 1..128),
        aad in proptest::collection::vec(any::<u8>(), 0..32),
        bit_index in 0usize..1024,
    ) {
        let key = [0xBBu8; 32];
        let nonce = [0xCCu8; 12];
        let ct_len = plaintext.len() + 16;
        let mut buf = vec![0u8; ct_len];
        buf[..plaintext.len()].copy_from_slice(&plaintext);

        let seal = ChaCha20Poly1305::new(&key, &nonce);
        let sealed_len = seal
            .seal_with_u64_counter(counter, &aad, &mut buf, plaintext.len(), None)
            .expect("seal");

        // Flip exactly one bit within the sealed output
        let byte_pos = bit_index % sealed_len;
        let bit_pos = (bit_index / sealed_len) % 8;
        buf[byte_pos] ^= 1u8 << bit_pos;

        let open = ChaCha20Poly1305::new(&key, &nonce);
        let result = open.open_with_u64_counter(counter, &aad, &mut buf);
        prop_assert!(result.is_err(), "tampered ciphertext must fail authentication");
    }
}
