use super::chacha20poly1305::ChaCha20Poly1305;
use super::{DATA_AEAD_OVERRIDE_AEGIS_L, DATA_AEAD_OVERRIDE_AUTO};
use crate::crypto::aead::{AeadOpen, AeadSeal};
use crate::{
    CryptoConfig, DataAeadPreference, LibAegis128Variant, PacketProtectionMode, PrivateAeadFamily,
};
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

    for variant in [LibAegis128Variant::L, LibAegis128Variant::X2, LibAegis128Variant::X4] {
        let (seal, open) = super::select_libaegis128_packet(variant, &key16, &iv12);
        let mut data_buf = vec![0u8; 16];
        assert!(seal.seal_with_u64_counter(invalid_counter, &[], &mut data_buf, 0, None).is_err());
        assert!(open.open_with_u64_counter(invalid_counter, &[], &mut data_buf).is_err());
    }
}

#[test]
fn data_aead_config_force_overrides_preference() {
    let _guard = DATA_AEAD_TEST_LOCK.lock().unwrap();
    super::install_data_aead_selection(DataAeadPreference::Auto, "aegis");
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
    assert_eq!(config.packet_protection_mode, PacketProtectionMode::Standard);
    assert_eq!(config.aead_preference, DataAeadPreference::Auto);
    assert!(config.private_family().is_none());
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
    for family in [PrivateAeadFamily::Aegis128L] {
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
fn default_crypto_config_ships_standard_without_private_family() {
    let config = CryptoConfig::default();
    assert_eq!(config.packet_protection_mode, PacketProtectionMode::Standard);
    assert_eq!(config.aead_preference, DataAeadPreference::Auto);
    assert!(config.force_aead.is_empty());
    assert!(config.private_family().is_none());
    assert!(config.validate().is_ok());
    assert_ne!(config.packet_protection_mode, PacketProtectionMode::AdvancedRequired);
}

#[test]
fn ring_aes_gcm128_matches_nist_and_first_party_oracle() {
    let key = [0u8; 16];
    let iv = [0u8; 12];
    let expected = hex_to_bytes(concat!(
        "0388dace60b6a392f328c2b971b2fe78",
        "ab6e47d42cec13bdf53a67b21257bddf",
    ));

    let mut ring_buffer = [0u8; 32];
    let ring_seal = super::RingAesGcm128::new(&key, &iv).expect("valid ring AES-128-GCM material");
    let ring_len = ring_seal
        .seal_with_u64_counter(0, &[], &mut ring_buffer, 16, None)
        .expect("ring NIST AES-GCM sealing must succeed");
    assert_eq!(ring_len, expected.len());
    assert_eq!(ring_buffer.as_slice(), expected.as_slice());

    let mut first_party = [0u8; 32];
    let oracle = super::AesGcm128::new(&key, &iv).expect("valid first-party AES-128-GCM material");
    oracle.seal_with_u64_counter(0, &[], &mut first_party, 16, None).expect("oracle seal");
    assert_eq!(ring_buffer, first_party);

    let ring_open = super::RingAesGcm128::new(&key, &iv).expect("valid ring AES-128-GCM material");
    let plaintext_len = ring_open
        .open_with_u64_counter(0, &[], &mut ring_buffer)
        .expect("ring NIST AES-GCM opening must succeed");
    assert_eq!(plaintext_len, 16);
    assert_eq!(&ring_buffer[..plaintext_len], &[0u8; 16]);
}

#[test]
fn ring_and_first_party_aes_gcm_roundtrip_across_quic_counters() {
    let key = [0x11u8; 16];
    let iv = [0x22u8; 12];
    let ad = b"quic-aad";
    let plaintext = b"initial-payload-bytes";
    let ring = super::RingAesGcm128::from_arrays(&key, &iv).expect("ring AES");
    let oracle = super::AesGcm128::from_arrays(&key, &iv);
    for counter in [0u64, 1, 7, 255, 1 << 20] {
        let mut ring_buf = vec![0u8; plaintext.len() + 16];
        ring_buf[..plaintext.len()].copy_from_slice(plaintext);
        ring.seal_with_u64_counter(counter, ad, &mut ring_buf, plaintext.len(), None)
            .expect("ring seal");
        let mut oracle_buf = vec![0u8; plaintext.len() + 16];
        oracle_buf[..plaintext.len()].copy_from_slice(plaintext);
        oracle
            .seal_with_u64_counter(counter, ad, &mut oracle_buf, plaintext.len(), None)
            .expect("oracle seal");
        assert_eq!(ring_buf, oracle_buf, "ciphertext diverged at counter {counter}");

        let opened =
            ring.open_with_u64_counter(counter, ad, &mut oracle_buf).expect("ring opens oracle");
        assert_eq!(&oracle_buf[..opened], plaintext);
        let opened =
            oracle.open_with_u64_counter(counter, ad, &mut ring_buf).expect("oracle opens ring");
        assert_eq!(&ring_buf[..opened], plaintext);
    }
}

#[test]
fn ring_aes_hp_matches_fips197_and_first_party_oracle() {
    use crate::crypto::aead::{AesHp, PacketHeaderProtector};

    let key: [u8; 16] =
        hex_to_bytes("000102030405060708090a0b0c0d0e0f").try_into().expect("16-byte key");
    let sample: [u8; 16] =
        hex_to_bytes("00112233445566778899aabbccddeeff").try_into().expect("16-byte sample");
    let expected = [0x69, 0xc4, 0xe0, 0xd8, 0x6a];

    let ring = super::RingAesHp::from_key(&key).expect("ring AES-HP");
    let oracle = AesHp::from_key(&key);
    let ring_mask = ring.new_mask(&sample).expect("ring mask");
    let oracle_mask = oracle.new_mask(&sample).expect("oracle mask");
    assert_eq!(ring_mask, expected);
    assert_eq!(ring_mask, oracle_mask);
}

#[test]
fn ring_chacha20poly1305_matches_rfc8439_and_first_party_oracle() {
    let key = hex_to_bytes("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
    let nonce = hex_to_bytes("000000000000004a00000000");
    let plaintext = hex_to_bytes(concat!(
        "4c616469657320616e642047656e746c656d656e206f662074686520636c617373206f66",
        "202739393a20497420776173207468652062657374206f662074696d65732c2069742077",
        "61732074686520776f727374206f662074696d65732e",
    ));

    let mut ring_buf = plaintext.clone();
    ring_buf.resize(plaintext.len() + 16, 0);
    let ring = super::RingChaCha20Poly1305::new(&key, &nonce).expect("ring ChaCha");
    ring.seal_with_u64_counter(0, &[], ring_buf.as_mut_slice(), plaintext.len(), None)
        .expect("ring ChaCha seal");

    let mut oracle_buf = plaintext.clone();
    oracle_buf.resize(plaintext.len() + 16, 0);
    let oracle = ChaCha20Poly1305::new(&key, &nonce).expect("oracle ChaCha");
    oracle
        .seal_with_u64_counter(0, &[], oracle_buf.as_mut_slice(), plaintext.len(), None)
        .expect("oracle ChaCha seal");
    assert_eq!(ring_buf, oracle_buf);

    let opened = ring
        .open_with_u64_counter(0, &[], oracle_buf.as_mut_slice())
        .expect("ring opens oracle ChaCha");
    assert_eq!(&oracle_buf[..opened], plaintext.as_slice());
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
fn payload_protection_pin_follows_stealth_mode() {
    assert_eq!(
        super::payload_protection_pin(true),
        (PacketProtectionMode::Auto, Some(PrivateAeadFamily::Aegis128L))
    );
    assert_eq!(super::payload_protection_pin(false), (PacketProtectionMode::Standard, None));
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
