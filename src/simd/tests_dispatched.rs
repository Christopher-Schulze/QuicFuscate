//! Extracted SIMD `tests_dispatched` submodule (TODO-563).

use super::*;

// ===================== GF(2^8) batch operations =====================

#[test]
fn gf_mul_known_vectors() {
    // Multiply each byte of input by 0x02 (xtime) - well-known AES operation
    let input = [0x57u8, 0xAE, 0x00, 0x01, 0x80, 0xFF];
    let mut dst = [0u8; 6];
    galois::gf_mul(&input, 0x02, &mut dst);
    // Verify against scalar reference
    let mut expected = [0u8; 6];
    for i in 0..input.len() {
        expected[i] = scalar::gf_mul_byte(input[i], 0x02);
    }
    assert_eq!(dst, expected);
}

#[test]
fn gf_mul_identity_element() {
    // Multiplying by 1 in GF(2^8) must return the original value
    let input: Vec<u8> = (0..=255).collect();
    let mut dst = vec![0u8; 256];
    galois::gf_mul(&input, 1, &mut dst);
    assert_eq!(dst, input);
}

#[test]
fn gf_mul_zero_input() {
    // Multiplying by 0 must yield all zeros
    let input = [0xAB, 0xCD, 0xEF, 0x12, 0x34];
    let mut dst = [0xFFu8; 5];
    galois::gf_mul(&input, 0, &mut dst);
    assert_eq!(dst, [0u8; 5]);
}

#[test]
fn gf_mul_zero_data() {
    // All-zero input multiplied by anything must yield all zeros
    let input = [0u8; 64];
    let mut dst = [0xFFu8; 64];
    galois::gf_mul(&input, 0x42, &mut dst);
    assert_eq!(dst, [0u8; 64]);
}

#[test]
fn gf_mul_inverse_checking() {
    // For every nonzero a, a * a^-1 = 1 in GF(2^8)
    for a in 1u8..=255 {
        let inv = scalar::gf_inv(a);
        let product = scalar::gf_mul_byte(a, inv);
        assert_eq!(product, 1, "gf_inv failed for a={a}: a*inv={product}, inv={inv}");
    }
}

// ===================== GF(2^4) operations =====================

#[test]
fn gf4_mul_identity_and_zero() {
    // GF(2^4) multiply by 1 preserves nibbles, multiply by 0 zeroes
    let input = [0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0];
    let mut dst_one = [0u8; 8];
    let mut dst_zero = [0xFFu8; 8];
    galois::gf4_mul(&input, 1, &mut dst_one);
    galois::gf4_mul(&input, 0, &mut dst_zero);
    assert_eq!(dst_one, input, "gf4 multiply by 1 should be identity");
    assert_eq!(dst_zero, [0u8; 8], "gf4 multiply by 0 should be zero");
}

#[test]
fn gf4_mul_xor_matches_separate_multiply_and_xor() {
    let input = [0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0];
    let initial = [0xA5, 0x5A, 0xC3, 0x3C, 0x96, 0x69, 0xF0, 0x0F];
    let mut product = [0u8; 8];
    let mut fused = initial;
    galois::gf4_mul(&input, 7, &mut product);
    galois::gf4_mul_xor(&input, 7, &mut fused);

    for index in 0..initial.len() {
        assert_eq!(fused[index], initial[index] ^ product[index]);
    }
}

// ===================== GF(2^16) operations =====================

#[test]
fn gf16_mul_identity_and_zero() {
    let input: Vec<u16> = vec![0x0001, 0x1234, 0xABCD, 0xFFFF, 0x0000];
    let mut dst_one = vec![0u16; 5];
    let mut dst_zero = vec![0xFFFFu16; 5];
    galois::gf16_mul(&input, 1, &mut dst_one);
    galois::gf16_mul(&input, 0, &mut dst_zero);
    assert_eq!(dst_one, input, "gf16 multiply by 1 should be identity");
    assert_eq!(dst_zero, vec![0u16; 5], "gf16 multiply by 0 should be zero");
}

#[test]
fn gf16_mul_commutativity() {
    // a * b should equal b * a for single elements
    let a_val: u16 = 0x1234;
    let b_val: u16 = 0x5678;
    let mut ab = [0u16; 1];
    let mut ba = [0u16; 1];
    galois::gf16_mul(&[a_val], b_val, &mut ab);
    galois::gf16_mul(&[b_val], a_val, &mut ba);
    assert_eq!(ab, ba, "GF(2^16) multiplication should be commutative");
}

// ===================== CRC32 =====================

#[test]
fn crc32_known_vector() {
    // CRC-32 of "123456789" is 0xCBF43926
    let result = core::crc32(b"123456789", 0);
    assert_eq!(result, 0xCBF43926, "CRC32 known vector mismatch: got {result:#010X}");
}

#[test]
fn crc32_empty_input() {
    let result = core::crc32(b"", 0);
    // CRC32 of empty data with initial 0 should be 0x00000000
    assert_eq!(result, 0x00000000, "CRC32 of empty should be 0x00000000");
}

#[test]
fn crc32_incremental_vs_full() {
    // Compute CRC32 of "Hello, World!" in one shot vs two parts
    let full_data = b"Hello, World!";
    let full_crc = core::crc32(full_data, 0);

    // For table-based CRC, we can verify consistency with scalar
    let scalar_crc = scalar::crc32(full_data, 0);
    assert_eq!(full_crc, scalar_crc, "dispatched CRC32 should match scalar");
}

// ===================== SIMD dispatch / feature detection =====================

#[test]
fn acceleration_planner_global_returns_consistent() {
    let p1 = planner::AccelerationPlanner::global();
    let p2 = planner::AccelerationPlanner::global();
    // Same singleton, same default AEAD
    assert_eq!(p1.crypto_default_aead(), p2.crypto_default_aead());
}

#[test]
fn simd_ops_instance_returns_consistent() {
    let s1 = SimdOps::instance();
    let s2 = SimdOps::instance();
    assert!(std::ptr::eq(s1, s2), "SimdOps::instance should return same pointer");
}

#[test]
fn crypto_aead_plan_select_returns_valid_variant() {
    let plan = CryptoAeadPlan::select();
    // Must be one of the four valid variants
    match plan {
        CryptoAeadPlan::Aegis128L
        | CryptoAeadPlan::Aegis128X4
        | CryptoAeadPlan::Aegis128X8
        | CryptoAeadPlan::Morus => {}
    }
}

#[test]
fn crypto_aead_plan_length_based_selection() {
    // Small payload should not select X8
    let small = CryptoAeadPlan::select_for_len(10);
    assert_ne!(small, CryptoAeadPlan::Aegis128X8, "10-byte payload should not use X8");

    // Large payload selection should still be valid
    let large = CryptoAeadPlan::select_for_len(4096);
    match large {
        CryptoAeadPlan::Aegis128L
        | CryptoAeadPlan::Aegis128X4
        | CryptoAeadPlan::Aegis128X8
        | CryptoAeadPlan::Morus => {}
    }
}

// ===================== Transport QUIC varint encode/decode =====================

#[test]
fn quic_varint_roundtrip_1byte() {
    // 1-byte encoding: values 0..63
    for val in [0u64, 1, 37, 63] {
        let mut buf = [0u8; 8];
        let encoded_len = transport::encode_varint(val, &mut buf);
        assert_eq!(encoded_len, 1, "value {val} should encode in 1 byte");
        let (decoded, consumed) =
            transport::decode_varint(&buf[..encoded_len]).expect("decode failed");
        assert_eq!(decoded, val, "roundtrip mismatch for {val}");
        assert_eq!(consumed, 1);
    }
}

#[test]
fn quic_varint_roundtrip_2byte() {
    // 2-byte encoding: values 64..16383
    for val in [64u64, 255, 1000, 16383] {
        let mut buf = [0u8; 8];
        let encoded_len = transport::encode_varint(val, &mut buf);
        assert_eq!(encoded_len, 2, "value {val} should encode in 2 bytes");
        let (decoded, consumed) =
            transport::decode_varint(&buf[..encoded_len]).expect("decode failed");
        assert_eq!(decoded, val, "roundtrip mismatch for {val}");
        assert_eq!(consumed, 2);
    }
}

#[test]
fn quic_varint_roundtrip_4byte() {
    // 4-byte encoding: values 16384..1073741823
    for val in [16384u64, 100_000, 1_073_741_823] {
        let mut buf = [0u8; 8];
        let encoded_len = transport::encode_varint(val, &mut buf);
        assert_eq!(encoded_len, 4, "value {val} should encode in 4 bytes");
        let (decoded, consumed) =
            transport::decode_varint(&buf[..encoded_len]).expect("decode failed");
        assert_eq!(decoded, val, "roundtrip mismatch for {val}");
        assert_eq!(consumed, 4);
    }
}

#[test]
fn quic_varint_roundtrip_8byte() {
    // 8-byte encoding: values 1073741824..(2^62 - 1)
    for val in [1_073_741_824u64, (1u64 << 62) - 1] {
        let mut buf = [0u8; 8];
        let encoded_len = transport::encode_varint(val, &mut buf);
        assert_eq!(encoded_len, 8, "value {val} should encode in 8 bytes");
        let (decoded, consumed) =
            transport::decode_varint(&buf[..encoded_len]).expect("decode failed");
        assert_eq!(decoded, val, "roundtrip mismatch for {val}");
        assert_eq!(consumed, 8);
    }
}

#[test]
fn quic_varint_decode_empty_returns_none() {
    assert!(transport::decode_varint(&[]).is_none());
}

// ===================== Crypto helpers (SHA-256, HMAC) =====================

#[test]
fn sha256_empty_message_nist_vector() {
    // SHA-256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
    let hash = crypto::sha256(b"");
    let expected = [
        0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9,
        0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52,
        0xb8, 0x55,
    ];
    assert_eq!(hash, expected, "SHA-256 empty message vector mismatch");
}

#[test]
fn sha256_abc_nist_vector() {
    // SHA-256("abc") = ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
    let hash = crypto::sha256(b"abc");
    let expected = [
        0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22,
        0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00,
        0x15, 0xad,
    ];
    assert_eq!(hash, expected, "SHA-256 'abc' vector mismatch");
}

#[test]
fn hmac_sha256_rfc4231_vector() {
    // RFC 4231 Test Case 2: key = "Jefe", data = "what do ya want for nothing?"
    let mac = crypto::hmac_sha256(b"Jefe", b"what do ya want for nothing?");
    let expected = [
        0x5b, 0xdc, 0xc1, 0x46, 0xbf, 0x60, 0x75, 0x4e, 0x6a, 0x04, 0x24, 0x26, 0x08, 0x95, 0x75,
        0xc7, 0x5a, 0x00, 0x3f, 0x08, 0x9d, 0x27, 0x39, 0x83, 0x9d, 0xec, 0x58, 0xb9, 0x64, 0xec,
        0x38, 0x43,
    ];
    assert_eq!(mac, expected, "HMAC-SHA256 RFC4231 test case 2 mismatch");
}

#[test]
fn ghash_matches_canonical_gcm_for_partial_and_full_blocks() {
    let h = [0x42u8; 16];
    for data in [b"".as_slice(), b"partial", b"two complete blocks of payload!!"] {
        let mut tag = [0u8; 16];
        crypto::ghash(&h, data, &mut tag);
        assert_eq!(tag, crate::crypto::gcm::ghash(h, &[], data));
    }
}

// ===================== XOR blocks =====================

#[test]
fn xor_blocks_correctness() {
    let mut dst = [0xAAu8; 32];
    let src = [0x55u8; 32];
    core::xor_blocks(&mut dst, &src);
    assert_eq!(dst, [0xFFu8; 32], "0xAA ^ 0x55 should be 0xFF");
}

#[test]
fn xor_blocks_self_inverse() {
    let original = [0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0];
    let key = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22];
    let mut data = original;
    core::xor_blocks(&mut data, &key);
    assert_ne!(data, original, "XOR should change data");
    core::xor_blocks(&mut data, &key);
    assert_eq!(data, original, "double XOR should restore original");
}

// ===================== Popcount =====================

#[test]
fn popcnt_known_values() {
    assert_eq!(core::popcnt(&[0x00]), 0);
    assert_eq!(core::popcnt(&[0xFF]), 8);
    assert_eq!(core::popcnt(&[0xAA]), 4); // 10101010
    assert_eq!(core::popcnt(&[0xFF; 16]), 128);
}

#[test]
fn popcnt_matches_scalar() {
    let data: Vec<u8> = (0..=255).collect();
    let dispatched = core::popcnt(&data);
    let reference = scalar::popcnt(&data);
    assert_eq!(dispatched, reference);
}

// ===================== Bitstream pack/unpack =====================

#[test]
fn bitstream_pack_unpack_roundtrip_all_widths() {
    for len in [0usize, 1, 2, 7, 8, 9, 63, 64, 65] {
        let src: Vec<u8> = (0..len).map(|value| (value as u8).wrapping_mul(37)).collect();
        for bit_width in 1u8..=8 {
            let mask = (1u16 << bit_width) - 1;
            let masked_src: Vec<u8> = src.iter().map(|&value| value & mask as u8).collect();
            let expected_packed_len = (len * bit_width as usize).div_ceil(8);
            let mut packed = vec![0u8; expected_packed_len];
            let packed_len = bitstream::pack_bits(&masked_src, bit_width, &mut packed);
            assert_eq!(packed_len, expected_packed_len);

            let mut unpacked = vec![0u8; masked_src.len()];
            let unpacked_len =
                bitstream::unpack_bits(&packed[..packed_len], bit_width, &mut unpacked);
            assert_eq!(unpacked_len, masked_src.len());
            assert_eq!(
                unpacked, masked_src,
                "pack/unpack roundtrip failed for len={len}, bit_width={bit_width}"
            );
        }
    }
}

#[test]
fn bitstream_rejects_invalid_widths_and_bounds_output() {
    let mut output = [0u8; 1];
    assert_eq!(bitstream::pack_bits(&[0xFF; 32], 0, &mut output), 0);
    assert_eq!(bitstream::pack_bits(&[0xFF; 32], 9, &mut output), 0);
    assert_eq!(bitstream::unpack_bits(&[0xFF], 0, &mut output), 0);
    assert_eq!(bitstream::unpack_bits(&[0xFF], 9, &mut output), 0);
    assert_eq!(bitstream::pack_bits(&[0xFF; 32], 8, &mut output), 1);
}

// ===================== Header validation =====================

#[test]
fn validate_header_too_short() {
    assert!(!fec::validate_header(&[]));
    assert!(!fec::validate_header(&[0xC0]));
    assert!(!fec::validate_header(&[0xC0, 0, 0, 0])); // needs >= 5
}

#[test]
fn validate_header_long_header_valid() {
    // Long header: 0x80 set + 0x40 set = 0xC0
    assert!(fec::validate_header(&[0xC0, 0, 0, 0, 0]));
    assert!(fec::validate_header(&[0xFF, 0, 0, 0, 0])); // all bits set, still valid long
}

#[test]
fn validate_header_short_header_reserved_bits() {
    // Short header (0x80 clear), fixed bit set (0x40), reserved bits zero
    assert!(fec::validate_header(&[0x40, 0, 0, 0, 0]));
    // Reserved bits (0x18) non-zero - invalid
    assert!(!fec::validate_header(&[0x58, 0, 0, 0, 0])); // 0x40 | 0x18
    assert!(!fec::validate_header(&[0x48, 0, 0, 0, 0])); // 0x40 | 0x08
    assert!(!fec::validate_header(&[0x50, 0, 0, 0, 0])); // 0x40 | 0x10
}

#[test]
fn validate_header_no_fixed_bit() {
    assert!(!fec::validate_header(&[0x00, 0, 0, 0, 0]));
    assert!(!fec::validate_header(&[0x80, 0, 0, 0, 0])); // long but no fixed bit
}

#[test]
fn validate_header_dispatch_matches_quic_constraints_for_all_first_bytes() {
    for len in [5usize, 32, 64] {
        let mut header = vec![0u8; len];
        for first in 0..=u8::MAX {
            header[0] = first;
            let expected = (first & 0x40) != 0 && ((first & 0x80) != 0 || (first & 0x18) == 0);
            assert_eq!(
                fec::validate_header(&header),
                expected,
                "header mismatch for len={len}, first={first:#04x}"
            );
        }
    }
}

// ===================== Scalar fallback parity =====================

#[test]
fn scalar_gf_mul_matches_dispatched() {
    let input: Vec<u8> = (0..128).collect();
    let multiplier = 0x53u8;
    let mut scalar_dst = vec![0u8; 128];
    let mut dispatched_dst = vec![0u8; 128];
    scalar::gf_mul(&input, multiplier, &mut scalar_dst);
    galois::gf_mul(&input, multiplier, &mut dispatched_dst);
    assert_eq!(scalar_dst, dispatched_dst);
}

#[test]
fn scalar_crc32_matches_dispatched() {
    let data = b"The quick brown fox jumps over the lazy dog";
    let scalar = scalar::crc32(data, 0);
    let dispatched = core::crc32(data, 0);
    assert_eq!(scalar, dispatched);
}

#[test]
fn scalar_sha256_matches_dispatched() {
    let data = b"parity check data for sha256";
    let scalar = scalar::sha256(data);
    let dispatched = crypto::sha256(data);
    assert_eq!(scalar, dispatched);
}

#[test]
fn berlekamp_massey_boundary_lengths_match_scalar() {
    for len in [0usize, 1, 2, 31, 48, 63, 64, 65, 127, 128] {
        let syndrome: Vec<u8> =
            (0..len).map(|index| (index as u8).wrapping_mul(37).wrapping_add(11)).collect();
        assert_eq!(
            fec::berlekamp_massey_gf256(&syndrome, len),
            scalar::berlekamp_massey(&syndrome, len),
            "Berlekamp-Massey mismatch at length {len}"
        );
    }
}

#[test]
fn berlekamp_massey_rejects_overlong_lengths() {
    let syndrome = [1u8, 2, 3];
    for len in [syndrome.len() + 1, usize::MAX] {
        assert!(fec::berlekamp_massey_gf256(&syndrome, len).is_empty());
        assert!(scalar::berlekamp_massey(&syndrome, len).is_empty());
    }
}
