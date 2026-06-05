use super::chacha20poly1305::ChaCha20Poly1305;
use super::{
    DATA_AEAD_OVERRIDE_AEGIS_L, DATA_AEAD_OVERRIDE_AEGIS_X4, DATA_AEAD_OVERRIDE_AEGIS_X8,
    DATA_AEAD_OVERRIDE_AUTO,
};
use crate::crypto::aead::{AeadOpen, AeadOpenItem, AeadSeal, AeadSealItem};
use crate::engine::{AeadPreference, CryptoConfig};
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

    let seal = ChaCha20Poly1305::new(&key, &nonce);
    let out_len =
        seal.seal_with_u64_counter(0, &[], buffer.as_mut_slice(), plaintext.len(), None).unwrap();
    assert_eq!(out_len, plaintext.len() + 16);

    let open = ChaCha20Poly1305::new(&key, &nonce);
    let pt_len = open.open_with_u64_counter(0, &[], buffer.as_mut_slice()).unwrap();
    assert_eq!(pt_len, plaintext.len());
    assert_eq!(&buffer[..pt_len], plaintext.as_slice());
}

#[test]
fn data_aead_config_force_overrides_preference() {
    let _guard = DATA_AEAD_TEST_LOCK.lock().unwrap();
    let cfg = CryptoConfig {
        aead_preference: AeadPreference::Morus,
        force_aead: "aegis-128l".to_string(),
    };
    super::install_data_aead_config(&cfg);
    assert_eq!(super::data_aead_override_mode(), DATA_AEAD_OVERRIDE_AEGIS_L);
    super::set_data_aead_override_mode(DATA_AEAD_OVERRIDE_AUTO);
}

#[test]
fn data_aead_config_force_aegis_x4_x8_use_distinct_overrides() {
    let _guard = DATA_AEAD_TEST_LOCK.lock().unwrap();
    let mut cfg = CryptoConfig {
        aead_preference: AeadPreference::Auto,
        force_aead: "aegis-128x4".to_string(),
    };
    super::install_data_aead_config(&cfg);
    assert_eq!(super::data_aead_override_mode(), DATA_AEAD_OVERRIDE_AEGIS_X4);

    cfg.force_aead = "aegis-128x8".to_string();
    super::install_data_aead_config(&cfg);
    assert_eq!(super::data_aead_override_mode(), DATA_AEAD_OVERRIDE_AEGIS_X8);

    super::set_data_aead_override_mode(DATA_AEAD_OVERRIDE_AUTO);
}

#[test]
fn data_aead_force_aegis_x4_alias_roundtrip() {
    let _guard = DATA_AEAD_TEST_LOCK.lock().unwrap();
    let cfg = CryptoConfig {
        aead_preference: AeadPreference::Auto,
        force_aead: "aegis-128x4".to_string(),
    };
    super::install_data_aead_config(&cfg);

    let key = [0x11u8; 32];
    let iv = [0x22u8; 16];
    let ad = b"ad";
    let pt = b"hello-quicfuscate";

    let (seal, open) = super::select_data_aead(&key, &iv);
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
    let cfg = CryptoConfig {
        aead_preference: AeadPreference::Auto,
        force_aead: "aegis-128x4".to_string(),
    };
    super::install_data_aead_config(&cfg);

    let key = [0x5Au8; 32];
    let iv = [0x6Bu8; 16];
    let ad = b"transport-batch-ad";
    let pt = b"batch-payload-12345";

    let (seal, open) = super::select_data_aead(&key, &iv);
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
fn data_aead_force_aegis_x8_alias_roundtrip() {
    let _guard = DATA_AEAD_TEST_LOCK.lock().unwrap();
    let cfg = CryptoConfig {
        aead_preference: AeadPreference::Auto,
        force_aead: "aegis-128x8".to_string(),
    };
    super::install_data_aead_config(&cfg);

    let key = [0x33u8; 32];
    let iv = [0x44u8; 16];
    let ad = b"ad";
    let pt = b"hello-quicfuscate-x8";

    let (seal, open) = super::select_data_aead(&key, &iv);
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
    let cfg =
        CryptoConfig { aead_preference: AeadPreference::Aegis128L, force_aead: String::new() };
    super::install_data_aead_config(&cfg);
    // On platforms without hardware AES, preference should not override defaults.
    // On platforms with hardware AES, preference activates AEGIS-128L.
    let mode = super::data_aead_override_mode();
    assert!(mode == DATA_AEAD_OVERRIDE_AUTO || mode == DATA_AEAD_OVERRIDE_AEGIS_L);
    super::set_data_aead_override_mode(DATA_AEAD_OVERRIDE_AUTO);
}

// --- Header Protection Tests ---

#[test]
fn aes_hp_new_mask_deterministic() {
    use crate::crypto::aead::AesHp;
    use crate::transport::packet::HeaderProtector;

    let key = [0x42u8; 16];
    let hp = AesHp::new(&key);
    let sample = [0x01u8; 16];

    let mask1 = hp.new_mask(&sample);
    let mask2 = hp.new_mask(&sample);
    assert_eq!(mask1, mask2, "same key+sample must produce identical masks");
    // Mask must not be all zeros (that would be a no-op)
    assert_ne!(mask1, [0u8; 5], "mask should not be all zeros");
}

#[test]
fn aes_hp_different_samples_produce_different_masks() {
    use crate::crypto::aead::AesHp;
    use crate::transport::packet::HeaderProtector;

    let key = [0xABu8; 16];
    let hp = AesHp::new(&key);

    let mask_a = hp.new_mask(&[0x01; 16]);
    let mask_b = hp.new_mask(&[0x02; 16]);
    assert_ne!(mask_a, mask_b, "different samples must produce different masks");
}

#[test]
fn aes_hp_apply_remove_roundtrip() {
    use crate::crypto::aead::AesHp;
    use crate::crypto::aead::HeaderProtector;

    let key = [0x55u8; 16];
    let hp = AesHp::new(&key);
    let sample = [0x99u8; 16];

    let original = [0x11, 0x22, 0x33, 0x44, 0x55];
    let mut buf = original;
    hp.apply(&sample, &mut buf);
    assert_ne!(buf, original, "apply must change the buffer");
    hp.remove(&sample, &mut buf);
    assert_eq!(buf, original, "remove must restore original (XOR self-inverse)");
}

#[test]
fn aes_hp_different_keys_produce_different_masks() {
    use crate::crypto::aead::AesHp;
    use crate::transport::packet::HeaderProtector;

    let hp_a = AesHp::new(&[0x11; 16]);
    let hp_b = AesHp::new(&[0x22; 16]);
    let sample = [0x00; 16];

    let mask_a = hp_a.new_mask(&sample);
    let mask_b = hp_b.new_mask(&sample);
    assert_ne!(mask_a, mask_b, "different keys must produce different masks");
}
