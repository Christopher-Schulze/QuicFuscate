use super::chacha20poly1305::ChaCha20Poly1305;
use super::{DATA_AEAD_OVERRIDE_AEGIS_L, DATA_AEAD_OVERRIDE_AUTO};
use crate::crypto::aead::{AeadOpen, AeadOpenItem, AeadSeal, AeadSealItem};
use crate::{CryptoConfig, DataAeadPreference, PacketProtectionMode, PrivateAeadFamily};
use qf_cpu::CryptoAeadPlan;
use std::sync::Mutex;

// DATA_AEAD_OVERRIDE_MODE is process-global. Serialize override tests to avoid races.
static DATA_AEAD_TEST_LOCK: Mutex<()> = Mutex::new(());

fn hex_to_bytes(hex: &str) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(hex.len() / 2);
    let clean = hex.as_bytes();
    for chunk in clean.chunks(2) {
        let hi = (chunk[0] as char).to_digit(16).unwrap();
        let lo = (chunk[1] as char).to_digit(16).unwrap();
        bytes.push(((hi << 4) | lo) as u8);
    }

    bytes
}

#[test]
fn chacha20poly1305_rfc8439_vector() {
    let key = hex_to_bytes("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
    let nonce = hex_to_bytes("000000000000004a00000000");
    let plaintext = hex_to_bytes(concat!(
        "4c616469657320616e642047656e746c656d656e206f662074686520636c617373206f66",
        "202739393a20497420776173207468652062657374206f662074696d65732c2069742077",
        "61732074686520776f727374206f662074696d65732e",
    ));

    let mut buffer = plaintext.clone();
    buffer.resize(plaintext.len() + 16, 0);

    let seal = ChaCha20Poly1305::new(&key, &nonce).expect("valid ChaCha20-Poly1305 material");
    let out_len =
        seal.seal_with_u64_counter(0, &[], buffer.as_mut_slice(), plaintext.len(), None).unwrap();
    assert_eq!(out_len, plaintext.len() + 16);

    let open = ChaCha20Poly1305::new(&key, &nonce).expect("valid ChaCha20-Poly1305 material");
    let pt_len = open.open_with_u64_counter(0, &[], buffer.as_mut_slice()).unwrap();
    assert_eq!(pt_len, plaintext.len());
    assert_eq!(&buffer[..pt_len], plaintext.as_slice());
}

#[test]
fn tag_comparison_rejects_every_mismatch_position() {
    let expected = [0xA5u8; 16];
    assert!(super::subtle_ct_eq(&expected, &expected));

    for index in 0..expected.len() {
        let mut candidate = expected;
        candidate[index] ^= 1;
        assert!(
            !super::subtle_ct_eq(&expected, &candidate),
            "tag mismatch at byte {index} must be rejected"
        );
    }
}

#[test]
fn aead_rejects_packet_numbers_above_quic_limit() {
    let invalid_counter = super::MAX_QUIC_PACKET_NUMBER + 1;
    let key16 = [0x11u8; 16];
    let iv12 = [0x22u8; 12];

    let chacha = ChaCha20Poly1305::new(&[0x33u8; 32], &iv12).expect("valid ChaCha material");
    let mut chacha_buf = vec![0u8; 16];
    assert!(chacha.seal_with_u64_counter(invalid_counter, &[], &mut chacha_buf, 0, None).is_err());
    assert!(chacha.open_with_u64_counter(invalid_counter, &[], &mut chacha_buf).is_err());

    let aes = super::AesGcm128::from_arrays(&key16, &iv12);
    let mut aes_buf = vec![0u8; 16];
    assert!(aes.seal_with_u64_counter(invalid_counter, &[], &mut aes_buf, 0, None).is_err());
    assert!(aes.open_with_u64_counter(invalid_counter, &[], &mut aes_buf).is_err());

    for plan in [
        CryptoAeadPlan::Aegis128L,
        CryptoAeadPlan::Aegis128X4,
        CryptoAeadPlan::Aegis128X8,
        CryptoAeadPlan::Morus,
    ] {
        let (seal, open) = super::build_data_aead(plan, &key16, &iv12);
        let mut data_buf = vec![0u8; 16];
        assert!(seal.seal_with_u64_counter(invalid_counter, &[], &mut data_buf, 0, None).is_err());
        assert!(open.open_with_u64_counter(invalid_counter, &[], &mut data_buf).is_err());
    }
}

#[test]
fn data_aead_config_force_overrides_preference() {
    let _guard = DATA_AEAD_TEST_LOCK.lock().unwrap();
    super::install_data_aead_selection(DataAeadPreference::Morus, "aegis-128l");
    assert_eq!(super::data_aead_override_mode(), DATA_AEAD_OVERRIDE_AEGIS_L);
    super::set_data_aead_override_mode(DATA_AEAD_OVERRIDE_AUTO);
}

#[test]
fn data_aead_config_force_internal_width_aliases_fall_back_to_auto() {
    let _guard = DATA_AEAD_TEST_LOCK.lock().unwrap();
    super::install_data_aead_selection(DataAeadPreference::Auto, "aegis-128x4");
    assert_eq!(super::data_aead_override_mode(), DATA_AEAD_OVERRIDE_AUTO);

    super::install_data_aead_selection(DataAeadPreference::Auto, "aegis-128x8");
    assert_eq!(super::data_aead_override_mode(), DATA_AEAD_OVERRIDE_AUTO);

    super::set_data_aead_override_mode(DATA_AEAD_OVERRIDE_AUTO);
}

#[test]
fn crypto_config_preserves_wire_shape_and_force_validation() {
    let config = CryptoConfig::default();
    assert_eq!(config.packet_protection_mode, PacketProtectionMode::Auto);
    assert_eq!(config.aead_preference, DataAeadPreference::Auto);
    assert!(config.validate().is_ok());

    let encoded = serde_json::to_string(&config).expect("crypto config serializes");
    let decoded: CryptoConfig = serde_json::from_str(&encoded).expect("crypto config parses");
    assert_eq!(decoded, config);

    let mut invalid = config;
    invalid.force_aead = "aegis-128x4".to_string();
    assert!(invalid.validate().is_err());
}

#[test]
fn private_packet_selector_requires_exact_key_and_iv_material() {
    let key = [0x11u8; PrivateAeadFamily::KEY_LEN];
    let iv = [0x22u8; PrivateAeadFamily::IV_LEN];
    let plaintext = b"private-roundtrip";
    for family in [PrivateAeadFamily::Aegis128L, PrivateAeadFamily::Morus1280_128] {
        let (seal, open) =
            super::select_private_packet_data_aead(family, &key, &iv).expect("exact material");
        let mut packet = vec![0u8; plaintext.len() + PrivateAeadFamily::TAG_LEN];
        packet[..plaintext.len()].copy_from_slice(plaintext);
        seal.seal_with_u64_counter(7, b"aad", &mut packet, plaintext.len(), None).expect("seal");
        let length = open.open_with_u64_counter(7, b"aad", &mut packet).expect("open");
        assert_eq!(length, plaintext.len());
        assert_eq!(&packet[..length], plaintext);
        assert!(super::select_private_packet_data_aead(family, &[0u8; 32], &iv).is_err());
        assert!(super::select_private_packet_data_aead(family, &key, &[0u8; 16]).is_err());
    }
}

#[test]
fn packet_protection_mode_validation_is_fail_closed() {
    let mut config = CryptoConfig {
        packet_protection_mode: PacketProtectionMode::Standard,
        ..CryptoConfig::default()
    };
    assert!(config.validate().is_ok());

    config.aead_preference = DataAeadPreference::Aegis128L;
    assert!(config.validate().is_err());

    config.packet_protection_mode = PacketProtectionMode::AdvancedRequired;
    assert!(config.validate().is_ok());

    config.aead_preference = DataAeadPreference::Auto;
    config.force_aead.clear();
    assert!(config.validate().is_err());
}

#[test]
fn data_aead_internal_aegis_x4_backend_roundtrip() {
    let _guard = DATA_AEAD_TEST_LOCK.lock().unwrap();
    let key = [0x11u8; 32];
    let iv = [0x22u8; 16];
    let ad = b"ad";
    let pt = b"hello-quicfuscate";
    let mut k16 = [0u8; 16];
    k16.copy_from_slice(&key[..16]);
    let mut iv12 = [0u8; 12];
    iv12.copy_from_slice(&iv[..12]);

    let (seal, open) = super::build_data_aead(CryptoAeadPlan::Aegis128X4, &k16, &iv12);
    let mut buf = vec![0u8; pt.len() + 16];
    buf[..pt.len()].copy_from_slice(pt);
    let out_len = seal.seal_with_u64_counter(7, ad, buf.as_mut_slice(), pt.len(), None).unwrap();
    assert_eq!(out_len, pt.len() + 16);
    let pt_len = open.open_with_u64_counter(7, ad, buf.as_mut_slice()).unwrap();
    assert_eq!(pt_len, pt.len());
    assert_eq!(&buf[..pt_len], pt);

    super::set_data_aead_override_mode(DATA_AEAD_OVERRIDE_AUTO);
}

#[test]
fn data_aead_x4_batch_seal_open_roundtrip() {
    let _guard = DATA_AEAD_TEST_LOCK.lock().unwrap();
    let key = [0x5Au8; 16];
    let iv = [0x6Bu8; 12];
    let ad = b"transport-batch-ad";
    let pt = b"batch-payload-12345";

    let (seal, open) = super::build_data_aead(CryptoAeadPlan::Aegis128X4, &key, &iv);
    assert!(seal.supports_batch_seal());
    assert!(open.supports_batch_open());

    let mut bufs: Vec<Vec<u8>> = (0..8)
        .map(|_| {
            let mut b = vec![0u8; pt.len() + 16];
            b[..pt.len()].copy_from_slice(pt);
            b
        })
        .collect();
    let mut seal_items: Vec<AeadSealItem<'_>> = bufs
        .iter_mut()
        .enumerate()
        .map(|(i, buf)| AeadSealItem {
            counter: i as u64 + 1,
            ad,
            buf: buf.as_mut_slice(),
            plaintext_len: pt.len(),
        })
        .collect();
    seal.seal_batch(seal_items.as_mut_slice()).unwrap();

    let mut open_items: Vec<AeadOpenItem<'_>> = bufs
        .iter_mut()
        .enumerate()
        .map(|(i, buf)| AeadOpenItem { counter: i as u64 + 1, ad, buf: buf.as_mut_slice() })
        .collect();
    open.open_batch(open_items.as_mut_slice()).unwrap();
    for buf in &bufs {
        assert_eq!(&buf[..pt.len()], pt);
    }

    super::set_data_aead_override_mode(DATA_AEAD_OVERRIDE_AUTO);
}

#[test]
fn data_aead_internal_aegis_x8_backend_roundtrip() {
    let _guard = DATA_AEAD_TEST_LOCK.lock().unwrap();
    let key = [0x33u8; 32];
    let iv = [0x44u8; 16];
    let ad = b"ad";
    let pt = b"hello-quicfuscate-x8";
    let mut k16 = [0u8; 16];
    k16.copy_from_slice(&key[..16]);
    let mut iv12 = [0u8; 12];
    iv12.copy_from_slice(&iv[..12]);

    let (seal, open) = super::build_data_aead(CryptoAeadPlan::Aegis128X8, &k16, &iv12);
    let mut buf = vec![0u8; pt.len() + 16];
    buf[..pt.len()].copy_from_slice(pt);
    let out_len = seal.seal_with_u64_counter(9, ad, buf.as_mut_slice(), pt.len(), None).unwrap();
    assert_eq!(out_len, pt.len() + 16);
    let pt_len = open.open_with_u64_counter(9, ad, buf.as_mut_slice()).unwrap();
    assert_eq!(pt_len, pt.len());
    assert_eq!(&buf[..pt_len], pt);

    super::set_data_aead_override_mode(DATA_AEAD_OVERRIDE_AUTO);
}

#[test]
fn aegis_x_variants_match_aegis128l() {
    // For a fixed key/nonce, all variants must produce identical ciphertext and tag.
    let key = [0x55u8; 16];
    let nonce = [0x66u8; 16];
    let ad = b"associated-data-123";

    for &len in &[0usize, 1, 15, 16, 17, 31, 32, 33, 63, 64, 65, 127, 128, 129, 255] {
        let mut pt = vec![0u8; len];
        for (i, b) in pt.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(31).wrapping_add(7);
        }

        let mut a1 = crate::crypto::Aegis128L::new(&key, &nonce).unwrap();
        let mut c1 = pt.clone();
        let t1 = a1.encrypt_in_place(&mut c1, ad);

        let mut a4 = crate::crypto::Aegis128X4::new(&key, &nonce).unwrap();
        let mut c4 = pt.clone();
        let t4 = a4.encrypt_in_place(&mut c4, ad);
        assert_eq!(c4, c1);
        assert_eq!(t4, t1);

        let mut a8 = crate::crypto::Aegis128X8::new(&key, &nonce).unwrap();
        let mut c8 = pt.clone();
        let t8 = a8.encrypt_in_place(&mut c8, ad);
        assert_eq!(c8, c1);
        assert_eq!(t8, t1);
    }
}

#[test]
fn aegis_x_variants_cross_decrypt() {
    let key = [0x77u8; 16];
    let nonce = [0x88u8; 16];
    let ad = b"ad";
    let mut pt = vec![0u8; 333];
    for (i, b) in pt.iter_mut().enumerate() {
        *b = (i as u8).wrapping_mul(13).wrapping_add(9);
    }

    let mut a1 = crate::crypto::Aegis128L::new(&key, &nonce).unwrap();
    let mut ct = pt.clone();
    let tag = a1.encrypt_in_place(&mut ct, ad);

    let mut a8 = crate::crypto::Aegis128X8::new(&key, &nonce).unwrap();
    let mut dec = ct.clone();
    a8.decrypt_in_place(&mut dec, ad, &tag).unwrap();
    assert_eq!(dec, pt);

    let mut a4 = crate::crypto::Aegis128X4::new(&key, &nonce).unwrap();
    let mut dec2 = ct;
    a4.decrypt_in_place(&mut dec2, ad, &tag).unwrap();
    assert_eq!(dec2, pt);
}

#[test]
fn aegis_x_variants_match_ciphertext_and_tag_across_matrix() {
    let key = [0x91u8; 16];
    let ad_lengths = [0usize, 1, 7, 15, 16, 17, 31, 48];
    let payload_lengths =
        [0usize, 1, 2, 15, 16, 17, 31, 32, 33, 63, 64, 65, 127, 128, 129, 255, 511];

    for nonce_seed in 0u8..4 {
        let nonce = [nonce_seed.wrapping_mul(17).wrapping_add(3); 16];
        for &ad_len in &ad_lengths {
            let mut ad = vec![0u8; ad_len];
            for (idx, byte) in ad.iter_mut().enumerate() {
                *byte = nonce_seed.wrapping_mul(29).wrapping_add(idx as u8);
            }

            for &pt_len in &payload_lengths {
                let mut pt = vec![0u8; pt_len];
                for (idx, byte) in pt.iter_mut().enumerate() {
                    *byte = nonce_seed
                        .wrapping_mul(41)
                        .wrapping_add((idx as u8).wrapping_mul(9))
                        .wrapping_add(ad_len as u8);
                }

                let mut a1 = crate::crypto::Aegis128L::new(&key, &nonce).unwrap();
                let mut c1 = pt.clone();
                let t1 = a1.encrypt_in_place(&mut c1, &ad);

                let mut a4 = crate::crypto::Aegis128X4::new(&key, &nonce).unwrap();
                let mut c4 = pt.clone();
                let t4 = a4.encrypt_in_place(&mut c4, &ad);
                assert_eq!(c4, c1, "x4 ciphertext diverged for pt_len={pt_len} ad_len={ad_len}");
                assert_eq!(t4, t1, "x4 tag diverged for pt_len={pt_len} ad_len={ad_len}");

                let mut a8 = crate::crypto::Aegis128X8::new(&key, &nonce).unwrap();
                let mut c8 = pt.clone();
                let t8 = a8.encrypt_in_place(&mut c8, &ad);
                assert_eq!(c8, c1, "x8 ciphertext diverged for pt_len={pt_len} ad_len={ad_len}");
                assert_eq!(t8, t1, "x8 tag diverged for pt_len={pt_len} ad_len={ad_len}");
            }
        }
    }
}

#[test]
fn data_aead_config_preference_is_conditional() {
    let _guard = DATA_AEAD_TEST_LOCK.lock().unwrap();
    super::install_data_aead_selection(DataAeadPreference::Aegis128L, "");
    // On platforms without hardware AES, preference should not override defaults.
    // On platforms with hardware AES, preference activates AEGIS-128L.
    let mode = super::data_aead_override_mode();
    assert!(mode == DATA_AEAD_OVERRIDE_AUTO || mode == DATA_AEAD_OVERRIDE_AEGIS_L);
    super::set_data_aead_override_mode(DATA_AEAD_OVERRIDE_AUTO);
}

#[test]
fn aes_gcm128_matches_nist_single_block_vector() {
    let key = [0u8; 16];
    let iv = [0u8; 12];
    let mut buffer = [0u8; 32];
    let expected = hex_to_bytes(concat!(
        "0388dace60b6a392f328c2b971b2fe78",
        "ab6e47d42cec13bdf53a67b21257bddf",
    ));

    let seal = super::AesGcm128::new(&key, &iv).expect("valid AES-128-GCM material");
    let sealed_len = seal
        .seal_with_u64_counter(0, &[], &mut buffer, 16, None)
        .expect("NIST AES-GCM sealing must succeed");
    assert_eq!(sealed_len, expected.len());
    assert_eq!(buffer.as_slice(), expected.as_slice());

    let open = super::AesGcm128::new(&key, &iv).expect("valid AES-128-GCM material");
    let plaintext_len =
        open.open_with_u64_counter(0, &[], &mut buffer).expect("NIST AES-GCM opening must succeed");
    assert_eq!(plaintext_len, 16);
    assert_eq!(&buffer[..plaintext_len], &[0u8; 16]);
}

// --- Header Protection Tests ---

#[test]
fn aes_hp_matches_fips197_block_vector() {
    use crate::crypto::aead::AesHp;
    use crate::crypto::aead::PacketHeaderProtector;

    let key: [u8; 16] =
        hex_to_bytes("000102030405060708090a0b0c0d0e0f").try_into().expect("16-byte key");
    let sample: [u8; 16] =
        hex_to_bytes("00112233445566778899aabbccddeeff").try_into().expect("16-byte sample");
    let hp = AesHp::new(&key).expect("valid AES-128-HP secret");

    assert_eq!(
        hp.new_mask(&sample).expect("valid header-protection sample"),
        [0x69, 0xc4, 0xe0, 0xd8, 0x6a]
    );
}

#[test]
fn aes_hp_new_mask_deterministic() {
    use crate::crypto::aead::AesHp;
    use crate::crypto::aead::PacketHeaderProtector;

    let key = [0x42u8; 16];
    let hp = AesHp::new(&key).expect("valid AES-128-HP secret");
    let sample = [0x01u8; 16];

    let mask1 = hp.new_mask(&sample).expect("valid header-protection sample");
    let mask2 = hp.new_mask(&sample).expect("valid header-protection sample");
    assert_eq!(mask1, mask2, "same key+sample must produce identical masks");
    // Mask must not be all zeros (that would be a no-op)
    assert_ne!(mask1, [0u8; 5], "mask should not be all zeros");
}

#[test]
fn aes_hp_different_samples_produce_different_masks() {
    use crate::crypto::aead::AesHp;
    use crate::crypto::aead::PacketHeaderProtector;

    let key = [0xABu8; 16];
    let hp = AesHp::new(&key).expect("valid AES-128-HP secret");

    let mask_a = hp.new_mask(&[0x01; 16]).expect("valid header-protection sample");
    let mask_b = hp.new_mask(&[0x02; 16]).expect("valid header-protection sample");
    assert_ne!(mask_a, mask_b, "different samples must produce different masks");
}

#[test]
fn aes_hp_apply_remove_roundtrip() {
    use crate::crypto::aead::AesHp;
    use crate::crypto::aead::HeaderProtector;

    let key = [0x55u8; 16];
    let hp = AesHp::new(&key).expect("valid AES-128-HP secret");
    let sample = [0x99u8; 16];

    let original = [0x11, 0x22, 0x33, 0x44, 0x55];
    let mut buf = original;
    hp.apply(&sample, &mut buf).expect("valid header-protection inputs");
    assert_ne!(buf, original, "apply must change the buffer");
    hp.remove(&sample, &mut buf).expect("valid header-protection inputs");
    assert_eq!(buf, original, "remove must restore original (XOR self-inverse)");
}

#[test]
fn aes_hp_different_keys_produce_different_masks() {
    use crate::crypto::aead::AesHp;
    use crate::crypto::aead::PacketHeaderProtector;

    let hp_a = AesHp::new(&[0x11; 16]).expect("valid AES-128-HP secret");
    let hp_b = AesHp::new(&[0x22; 16]).expect("valid AES-128-HP secret");
    let sample = [0x00; 16];

    let mask_a = hp_a.new_mask(&sample).expect("valid header-protection sample");
    let mask_b = hp_b.new_mask(&sample).expect("valid header-protection sample");
    assert_ne!(mask_a, mask_b, "different keys must produce different masks");
}

#[test]
fn aes_hp_rejects_invalid_sample_and_mask_lengths() {
    use crate::crypto::aead::PacketHeaderProtector;
    use crate::crypto::aead::{AesHp, HeaderProtector};

    let hp = AesHp::new(&[0xA5; 16]).expect("valid AES-128-HP secret");
    assert!(hp.new_mask(&[0x11; 15]).is_err());
    assert!(hp.new_mask(&[0x11; 17]).is_err());

    let mut mask = [0u8; 5];
    assert!(hp.apply(&[0x22; 15], &mut mask).is_err());
    assert!(hp.apply(&[0x22; 17], &mut mask).is_err());

    let mut oversized_mask = [0u8; 6];
    assert!(hp.apply(&[0x22; 16], &mut oversized_mask).is_err());
}

#[test]
fn crypto_constructors_reject_invalid_key_and_iv_lengths() {
    assert!(ChaCha20Poly1305::new(&[0u8; 31], &[0u8; 12]).is_err());
    assert!(ChaCha20Poly1305::new(&[0u8; 33], &[0u8; 12]).is_err());
    assert!(ChaCha20Poly1305::new(&[0u8; 32], &[0u8; 11]).is_err());
    assert!(ChaCha20Poly1305::new(&[0u8; 32], &[0u8; 13]).is_err());

    assert!(super::AesGcm128::new(&[0u8; 15], &[0u8; 12]).is_err());
    assert!(super::AesGcm128::new(&[0u8; 17], &[0u8; 12]).is_err());
    assert!(super::AesGcm128::new(&[0u8; 16], &[0u8; 11]).is_err());
    assert!(super::AesGcm128::new(&[0u8; 16], &[0u8; 13]).is_err());

    assert!(super::Aegis128LAead::new(&[0u8; 15], &[0u8; 12]).is_err());
    assert!(super::Aegis128LAead::new(&[0u8; 17], &[0u8; 12]).is_err());
    assert!(super::Aegis128X4Aead::new(&[0u8; 16], &[0u8; 11]).is_err());
    assert!(super::Aegis128X8Aead::new(&[0u8; 16], &[0u8; 13]).is_err());

    assert!(super::MorusAead::new(&[0u8; 15], &[0u8; 12]).is_err());
    assert!(super::MorusAead::new(&[0u8; 17], &[0u8; 12]).is_err());
    assert!(super::MorusAead::new(&[0u8; 16], &[0u8; 11]).is_err());
    assert!(super::MorusAead::new(&[0u8; 16], &[0u8; 13]).is_err());

    assert!(super::aegis::Aegis128L::new(&[0u8; 15], &[0u8; 16]).is_err());
    assert!(super::aegis::Aegis128L::new(&[0u8; 16], &[0u8; 15]).is_err());
    assert!(super::aead::AesHp::new(&[0u8; 15]).is_err());
    assert!(super::aead::AesHp::new(&[0u8; 32]).is_ok());

    assert!(super::select_data_aead(&[0u8; 15], &[0u8; 12]).is_err());
    assert!(super::select_data_aead(&[0u8; 16], &[0u8; 13]).is_err());
}

/// AEAD length arithmetic must be checked before it can wrap.
///
/// Every seal path computed `len + 16` directly. On a caller-supplied length near `usize::MAX`
/// that wraps in release builds and panics in debug ones, and a wrapped total can pass the
/// capacity comparison guarding `split_at_mut`, turning a malformed length into an in-process
/// abort instead of a typed error.
#[cfg(test)]
mod aead_length_bounds {
    use crate::crypto::{checked_seal_capacity, sealed_len, AEAD_TAG_LEN};
    use crate::error::ConnectionError;

    #[test]
    fn sealed_length_is_checked_rather_than_wrapping() {
        assert_eq!(sealed_len(0), Ok(AEAD_TAG_LEN), "an empty plaintext still needs a tag");
        assert_eq!(sealed_len(1), Ok(AEAD_TAG_LEN + 1));
        assert_eq!(sealed_len(1500), Ok(1516));

        // The exact boundary where the tag still fits.
        let largest = usize::MAX - AEAD_TAG_LEN;
        assert_eq!(sealed_len(largest), Ok(usize::MAX));

        // One past it must be a typed error, not a wrapped small number.
        assert_eq!(sealed_len(largest + 1), Err(ConnectionError::BufferTooShort));
        assert_eq!(sealed_len(usize::MAX), Err(ConnectionError::BufferTooShort));
    }

    #[test]
    fn seal_capacity_rejects_overflow_before_comparing_against_the_buffer() {
        // A generous buffer must still not admit an overflowing length. Before the fix,
        // `usize::MAX + 16` wrapped to 15, which is smaller than almost any buffer, so the
        // capacity test passed and `split_at_mut(usize::MAX)` was reached.
        assert_eq!(
            checked_seal_capacity(64 * 1024, usize::MAX),
            Err(ConnectionError::BufferTooShort),
            "an overflowing length must be refused regardless of buffer size"
        );

        // Exact capacity is accepted and reports the sealed length.
        assert_eq!(checked_seal_capacity(1516, 1500), Ok(1516));
        // One byte short is refused.
        assert_eq!(checked_seal_capacity(1515, 1500), Err(ConnectionError::BufferTooShort));
        // Zero-length plaintext needs exactly the tag.
        assert_eq!(checked_seal_capacity(AEAD_TAG_LEN, 0), Ok(AEAD_TAG_LEN));
        assert_eq!(
            checked_seal_capacity(AEAD_TAG_LEN - 1, 0),
            Err(ConnectionError::BufferTooShort)
        );
    }

    /// The wrapped value the old arithmetic produced would have passed the capacity test.
    #[test]
    fn the_previous_wrapping_arithmetic_would_have_admitted_an_overflowing_length() {
        let buffer_len = 64 * 1024usize;
        let malformed = usize::MAX;
        // What the old code computed.
        let wrapped = malformed.wrapping_add(AEAD_TAG_LEN);
        assert!(
            buffer_len >= wrapped,
            "the wrapped total is smaller than the buffer, which is exactly why the old capacity \
             test passed and reached split_at_mut"
        );
        // What the checked path does instead.
        assert_eq!(
            checked_seal_capacity(buffer_len, malformed),
            Err(ConnectionError::BufferTooShort)
        );
    }

    /// The real seal path must reject an overflowing length with a typed error, not panic.
    #[test]
    fn chacha_seal_rejects_an_overflowing_plaintext_length() {
        use crate::crypto::aead::AeadSeal;

        let key = [0x42u8; 32];
        let nonce = [0x24u8; 12];
        let seal = crate::crypto::ChaCha20Poly1305::new(&key, &nonce).expect("exact key sizes");
        let mut buf = vec![0u8; 4096];

        assert_eq!(
            seal.seal_with_u64_counter(0, b"ad", &mut buf, usize::MAX, None),
            Err(ConnectionError::BufferTooShort),
            "an overflowing plaintext length must be a typed error"
        );

        // A length that merely exceeds the buffer is the same typed error, not a panic.
        assert_eq!(
            seal.seal_with_u64_counter(0, b"ad", &mut buf, 5000, None),
            Err(ConnectionError::BufferTooShort)
        );

        // A valid length still seals and reports plaintext plus tag.
        assert_eq!(
            seal.seal_with_u64_counter(0, b"ad", &mut buf, 100, None),
            Ok(100 + AEAD_TAG_LEN)
        );
    }
}
