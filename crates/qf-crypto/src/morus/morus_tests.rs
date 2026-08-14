use super::*;

#[test]
fn test_morus_roundtrip_empty() {
    let key = [0u8; 16];
    let iv = [0u8; 12];
    let nonce = [0u8; 16];
    let plaintext = b"";
    let ad = b"";

    let morus = MorusAead::from_arrays(&key, &iv);
    let (ciphertext, tag) = morus.encrypt_native(plaintext, ad, &nonce);
    let decrypted = morus.decrypt_native(&ciphertext, &tag, ad, &nonce).unwrap();

    assert_eq!(plaintext, &decrypted[..]);
}

#[test]
fn test_morus_roundtrip_1_byte() {
    let key = [1u8; 16];
    let iv = [2u8; 12];
    let nonce = [3u8; 16];
    let plaintext = b"A";
    let ad = b"associated";

    let morus = MorusAead::from_arrays(&key, &iv);
    let (ciphertext, tag) = morus.encrypt_native(plaintext, ad, &nonce);
    let decrypted = morus.decrypt_native(&ciphertext, &tag, ad, &nonce).unwrap();

    assert_eq!(plaintext, &decrypted[..]);
    assert_ne!(plaintext, &ciphertext[..]);
}

#[test]
fn test_morus_roundtrip_16_bytes() {
    let key = [0x42u8; 16];
    let iv = [0x24u8; 12];
    let nonce = [0x13u8; 16];
    let plaintext = b"0123456789ABCDEF";
    let ad = b"additional_data";

    let morus = MorusAead::from_arrays(&key, &iv);
    let (ciphertext, tag) = morus.encrypt_native(plaintext, ad, &nonce);
    let decrypted = morus.decrypt_native(&ciphertext, &tag, ad, &nonce).unwrap();

    assert_eq!(plaintext, &decrypted[..]);
    assert_eq!(ciphertext.len(), plaintext.len());
}

#[test]
fn test_morus_roundtrip_17_bytes() {
    let key = [0xAAu8; 16];
    let iv = [0x55u8; 12];
    let nonce = [0xCCu8; 16];
    let plaintext = b"0123456789ABCDEFG";
    let ad = b"";

    let morus = MorusAead::from_arrays(&key, &iv);
    let (ciphertext, tag) = morus.encrypt_native(plaintext, ad, &nonce);
    let decrypted = morus.decrypt_native(&ciphertext, &tag, ad, &nonce).unwrap();

    assert_eq!(plaintext, &decrypted[..]);
}

#[test]
fn test_morus_roundtrip_32_bytes() {
    let key = [0xDEu8; 16];
    let iv = [0xADu8; 12];
    let nonce = [0xBEu8; 16];
    let plaintext = b"0123456789ABCDEF0123456789ABCDEF";
    let ad = b"long_associated_data_for_testing";

    let morus = MorusAead::from_arrays(&key, &iv);
    let (ciphertext, tag) = morus.encrypt_native(plaintext, ad, &nonce);
    let decrypted = morus.decrypt_native(&ciphertext, &tag, ad, &nonce).unwrap();

    assert_eq!(plaintext, &decrypted[..]);
}

#[test]
fn test_morus_roundtrip_64_bytes() {
    let key = [0x11u8; 16];
    let iv = [0x22u8; 12];
    let nonce = [0x33u8; 16];
    let plaintext = b"0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF";
    let ad = b"associated_data_64_byte_boundary_test";

    let morus = MorusAead::from_arrays(&key, &iv);
    let (ciphertext, tag) = morus.encrypt_native(plaintext, ad, &nonce);
    let decrypted = morus.decrypt_native(&ciphertext, &tag, ad, &nonce).unwrap();

    assert_eq!(plaintext, &decrypted[..]);
}

#[test]
fn test_morus_roundtrip_large() {
    let key = [0x77u8; 16];
    let iv = [0x88u8; 12];
    let nonce = [0x99u8; 16];
    let plaintext = vec![0x5Au8; 1337]; // Prime number for good measure
    let ad = b"large_buffer_test_with_simd_optimization";

    let morus = MorusAead::from_arrays(&key, &iv);
    let (ciphertext, tag) = morus.encrypt_optimized(&plaintext, ad, &nonce);
    let decrypted = morus.decrypt_optimized(&ciphertext, &tag, ad, &nonce).unwrap();

    assert_eq!(plaintext, decrypted);
    assert_eq!(ciphertext.len(), plaintext.len());
}

#[test]
fn test_morus_authentication_failure() {
    let key = [0xFFu8; 16];
    let iv = [0x00u8; 12];
    let nonce = [0xF0u8; 16];
    let plaintext = b"secret_message";
    let ad = b"authenticated_data";

    let morus = MorusAead::from_arrays(&key, &iv);
    let (mut ciphertext, tag) = morus.encrypt_optimized(plaintext, ad, &nonce);

    // Corrupt ciphertext
    ciphertext[0] ^= 1;

    let result = morus.decrypt_optimized(&ciphertext, &tag, ad, &nonce);
    assert!(result.is_err());
}

#[test]
fn test_morus_tag_verification_failure() {
    let key = [0x12u8; 16];
    let iv = [0x34u8; 12];
    let nonce = [0x56u8; 16];
    let plaintext = b"another_secret";
    let ad = b"more_auth_data";

    let morus = MorusAead::from_arrays(&key, &iv);
    let (ciphertext, mut tag) = morus.encrypt_optimized(plaintext, ad, &nonce);

    // Corrupt tag
    tag[0] ^= 1;

    let result = morus.decrypt_optimized(&ciphertext, &tag, ad, &nonce);
    assert!(result.is_err());
}

#[test]
fn test_morus_different_keys() {
    let key1 = [0xABu8; 16];
    let key2 = [0xCDu8; 16];
    let iv = [0xEFu8; 12];
    let nonce = [0x01u8; 16];
    let plaintext = b"cross_key_test";
    let ad = b"";

    let morus1 = MorusAead::from_arrays(&key1, &iv);
    let morus2 = MorusAead::from_arrays(&key2, &iv);

    let (ciphertext, tag) = morus1.encrypt_optimized(plaintext, ad, &nonce);
    let result = morus2.decrypt_optimized(&ciphertext, &tag, ad, &nonce);

    assert!(result.is_err());
}

#[test]
fn test_morus_simd_vs_scalar_consistency() {
    let key = [0x42u8; 16];
    let iv = [0x24u8; 12];
    let nonce = [0x13u8; 16];
    let plaintext = b"simd_scalar_consistency_test_with_longer_message_for_coverage";
    let ad = b"associated_data_for_consistency";

    let morus = MorusAead::from_arrays(&key, &iv);

    // Test that optimized path can decrypt its own output (self-consistency)
    let (ct_opt, tag_opt) = morus.encrypt_optimized(plaintext, ad, &nonce);
    let pt_opt = morus.decrypt_optimized(&ct_opt, &tag_opt, ad, &nonce).unwrap();
    assert_eq!(plaintext, &pt_opt[..]);

    // Test that native path can decrypt its own output (self-consistency)
    let (ct_native, tag_native) = morus.encrypt_native(plaintext, ad, &nonce);
    let pt_native = morus.decrypt_native(&ct_native, &tag_native, ad, &nonce).unwrap();
    assert_eq!(plaintext, &pt_native[..]);

    // Cross-compatibility must hold: optimized and native paths must interoperate.
    let pt_cross_native = morus.decrypt_native(&ct_opt, &tag_opt, ad, &nonce).unwrap();
    assert_eq!(plaintext, &pt_cross_native[..]);

    let pt_cross_opt = morus.decrypt_optimized(&ct_native, &tag_native, ad, &nonce).unwrap();
    assert_eq!(plaintext, &pt_cross_opt[..]);
}

#[test]
fn test_morus_native_vs_optimized_matrix() {
    let key = [0x39u8; 16];
    let iv = [0x5Au8; 12];
    let lengths = [0usize, 1, 2, 15, 16, 17, 31, 32, 33, 63, 64, 65, 127, 128, 129, 255, 511];
    let ad_lengths = [0usize, 1, 7, 15, 16, 17, 31];

    for nonce_seed in 0u8..4 {
        let nonce = [nonce_seed.wrapping_mul(11).wrapping_add(7); 16];
        let morus = MorusAead::from_arrays(&key, &iv);

        for &ad_len in &ad_lengths {
            let mut ad = vec![0u8; ad_len];
            for (idx, byte) in ad.iter_mut().enumerate() {
                *byte = nonce_seed.wrapping_mul(13).wrapping_add(idx as u8);
            }

            for &len in &lengths {
                let mut plaintext = vec![0u8; len];
                for (idx, byte) in plaintext.iter_mut().enumerate() {
                    *byte = nonce_seed
                        .wrapping_mul(19)
                        .wrapping_add((idx as u8).wrapping_mul(5))
                        .wrapping_add(ad_len as u8);
                }

                let (ct_native, tag_native) = morus.encrypt_native(&plaintext, &ad, &nonce);
                let (ct_opt, tag_opt) = morus.encrypt_optimized(&plaintext, &ad, &nonce);

                assert_eq!(
                    ct_opt, ct_native,
                    "optimized MORUS ciphertext diverged for len={len} ad_len={ad_len}"
                );
                assert_eq!(
                    tag_opt, tag_native,
                    "optimized MORUS tag diverged for len={len} ad_len={ad_len}"
                );

                let pt_native = morus.decrypt_native(&ct_opt, &tag_opt, &ad, &nonce).unwrap();
                assert_eq!(pt_native, plaintext);
                let pt_opt = morus.decrypt_optimized(&ct_native, &tag_native, &ad, &nonce).unwrap();
                assert_eq!(pt_opt, plaintext);
            }
        }
    }
}

#[test]
fn test_morus_new_rejects_short_key() {
    let short_key = [0xABu8; 8];
    let iv = [0x10u8; 12];
    assert!(MorusAead::new(&short_key, &iv).is_err());
}

#[test]
fn test_morus_nonce_sensitivity() {
    let key = [0x42u8; 16];
    let iv = [0x24u8; 12];
    let nonce_a = [0x01u8; 16];
    let nonce_b = [0x02u8; 16];
    let plaintext = b"nonce sensitivity test payload";
    let ad = b"";

    let morus = MorusAead::from_arrays(&key, &iv);
    let (ct_a, tag_a) = morus.encrypt_native(plaintext, ad, &nonce_a);
    let (ct_b, tag_b) = morus.encrypt_native(plaintext, ad, &nonce_b);

    // Same plaintext, different nonces must produce different ciphertexts
    assert_ne!(ct_a, ct_b, "different nonces must produce different ciphertexts");
    assert_ne!(tag_a, tag_b, "different nonces must produce different tags");
}

#[test]
fn test_morus_ad_affects_tag() {
    let key = [0x55u8; 16];
    let iv = [0x66u8; 12];
    let nonce = [0x77u8; 16];
    let plaintext = b"same plaintext for both";
    let ad_a = b"associated data A";
    let ad_b = b"associated data B";

    let morus = MorusAead::from_arrays(&key, &iv);
    let (ct_a, tag_a) = morus.encrypt_native(plaintext, ad_a, &nonce);
    let (ct_b, tag_b) = morus.encrypt_native(plaintext, ad_b, &nonce);

    // MORUS XORs ciphertext stream from state - AD changes state, so tags differ.
    // Ciphertext may or may not differ depending on stream cipher properties,
    // but tags MUST differ when AD differs.
    assert_ne!(tag_a, tag_b, "different AD must produce different authentication tags");
    // Verify cross-decryption fails: tag from ad_a cannot authenticate ad_b
    let result = morus.decrypt_native(&ct_b, &tag_a, ad_b, &nonce);
    assert!(result.is_err(), "tag from ad_a must not authenticate ad_b");
    let _ = ct_a; // suppress unused warning
}

#[test]
fn test_morus_tag_determinism() {
    let key = [0x88u8; 16];
    let iv = [0x99u8; 12];
    let nonce = [0xAAu8; 16];
    let plaintext = b"determinism check payload";
    let ad = b"determinism ad";

    let morus = MorusAead::from_arrays(&key, &iv);
    let (ct1, tag1) = morus.encrypt_native(plaintext, ad, &nonce);
    let (ct2, tag2) = morus.encrypt_native(plaintext, ad, &nonce);

    assert_eq!(ct1, ct2, "encrypting same data twice must produce identical ciphertext");
    assert_eq!(tag1, tag2, "encrypting same data twice must produce identical tags");
}

#[test]
fn test_morus_decrypt_error_type() {
    let key = [0xBBu8; 16];
    let iv = [0xCCu8; 12];
    let nonce = [0xDDu8; 16];
    let plaintext = b"error type check";
    let ad = b"";

    let morus = MorusAead::from_arrays(&key, &iv);
    let (ciphertext, _tag) = morus.encrypt_native(plaintext, ad, &nonce);

    // Provide a wrong tag
    let wrong_tag = [0xFFu8; 16];
    let mut buf = ciphertext.clone();
    let result = morus.decrypt_in_place(&mut buf, &wrong_tag, ad, &nonce);
    assert_eq!(result, Err(AeadError::TagMismatch));
}

#[test]
fn test_morus_new_rejects_oversized_key() {
    let full_key = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E,
        0x1F, 0x20,
    ]; // 32 bytes
    let iv = [0x30u8; 12];
    assert!(MorusAead::new(&full_key, &iv).is_err());
}

#[test]
fn test_morus_in_place_roundtrip() {
    let key = [0x13u8; 16];
    let iv = [0x37u8; 12];
    let nonce = [0x42u8; 16];
    let ad = b"in_place_associated_data";
    let mut plaintext = vec![0u8; 256];
    for (idx, byte) in plaintext.iter_mut().enumerate() {
        *byte = (idx as u8).wrapping_mul(31);
    }

    let morus = MorusAead::from_arrays(&key, &iv);
    let (expected_ct, expected_tag) = morus.encrypt_native(&plaintext, ad, &nonce);

    let mut in_place_buf = plaintext.clone();
    let tag = morus.encrypt_in_place(&mut in_place_buf, ad, &nonce);
    assert_eq!(expected_ct, in_place_buf);
    assert_eq!(expected_tag, tag);

    let mut decrypt_buf = expected_ct.clone();
    morus
        .decrypt_in_place(&mut decrypt_buf, &expected_tag, ad, &nonce)
        .expect("decrypt_in_place should succeed");
    assert_eq!(decrypt_buf, plaintext);
}

#[test]
fn morus_official_caesar_morus1280_128_vectors() {
    // Pinned from the final MORUS v2 reference package:
    // https://personal.ntu.edu.sg/wuhj/research/caesar/finalist_code/morusv2_code.zip
    // SHA-256: 1f21f972d10e9303358fa88ee46c961d501653b73ea33047ebe83d4388fa9bbf
    let vectors = [
        (
            "zero-empty",
            "00000000000000000000000000000000",
            "00000000000000000000000000000000",
            "",
            "",
            "",
            "5bd2cba68ea7e72f6b3d0c155f39f962",
        ),
        (
            "zero-one",
            "00000000000000000000000000000000",
            "00000000000000000000000000000000",
            "",
            "01",
            "ba",
            "ec1942a315a84695432a1255e6197878",
        ),
        (
            "zero-ad",
            "00000000000000000000000000000000",
            "00000000000000000000000000000000",
            "01",
            "",
            "",
            "590caa148b848d7614315685377a0d42",
        ),
        (
            "range-16",
            "000102030405060708090a0b0c0d0e0f",
            "101112131415161718191a1b1c1d1e1f",
            "202122232425262728292a2b2c2d2e2f",
            "303132333435363738393a3b3c3d3e3f",
            "2adad1acf5919eb5f51b3db3a56769d4",
            "e670904fdc83e35d2b06f163bc3c58c5",
        ),
        (
            "range-33",
            "000102030405060708090a0b0c0d0e0f",
            "101112131415161718191a1b1c1d1e1f",
            "202122232425262728292a2b2c2d2e2f",
            "303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f50",
            "2adad1acf5919eb5f51b3db3a56769d4ae579f726ed07bc199024ea626f20f4a9c",
            "53063a3be3a06f73b7414b99dbd50b4b",
        ),
        (
            "reference-regression",
            "000102030405060708090a0b0c0d0e0f",
            "0f0e0d0c0b0a09080706050403020100",
            "101112131415161718191a1b1c1d1e1f",
            "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f",
            "6086380dd1bbf8c220b50156e97a47a2260491450e01f8e946fb1b7fc0bba8bf",
            "32c2889e4293c6d0979078ec8cc6685d",
        ),
    ];

    for (name, key_hex, nonce_hex, ad_hex, plaintext_hex, expected_ct_hex, expected_tag_hex) in
        vectors
    {
        let key: [u8; 16] = hex::decode(key_hex).unwrap().try_into().unwrap();
        let nonce: [u8; 16] = hex::decode(nonce_hex).unwrap().try_into().unwrap();
        let ad = hex::decode(ad_hex).unwrap();
        let plaintext = hex::decode(plaintext_hex).unwrap();
        let expected_ct = hex::decode(expected_ct_hex).unwrap();
        let expected_tag: [u8; 16] = hex::decode(expected_tag_hex).unwrap().try_into().unwrap();
        let morus = MorusAead::from_arrays(&key, &[0u8; 12]);

        let (native_ct, native_tag) = morus.encrypt_native(&plaintext, &ad, &nonce);
        assert_eq!(native_ct, expected_ct, "native ciphertext mismatch: {name}");
        assert_eq!(native_tag, expected_tag, "native tag mismatch: {name}");
        assert_eq!(morus.decrypt_native(&native_ct, &native_tag, &ad, &nonce).unwrap(), plaintext);

        let (optimized_ct, optimized_tag) = morus.encrypt_optimized(&plaintext, &ad, &nonce);
        assert_eq!(optimized_ct, expected_ct, "optimized ciphertext mismatch: {name}");
        assert_eq!(optimized_tag, expected_tag, "optimized tag mismatch: {name}");
        assert_eq!(
            morus.decrypt_optimized(&optimized_ct, &optimized_tag, &ad, &nonce).unwrap(),
            plaintext
        );

        let mut forged_tag = expected_tag;
        forged_tag[0] ^= 1;
        assert!(morus.decrypt_native(&expected_ct, &forged_tag, &ad, &nonce).is_err());
    }
}

// TODO-395: regression guard — the AeadSeal/AeadOpen trait path must
// operate in-place on the caller buffer (no intermediate Vec) and produce
// output identical to the native in-place encrypt/decrypt path.
#[test]
fn morus_trait_path_matches_in_place_and_roundtrips() {
    use super::{AeadOpen, AeadSeal};

    let key = [0x5eu8; 16];
    let iv = [0x2cu8; 12];
    let ad = b"trait-path-ad";
    let pt: Vec<u8> = (0u8..200).map(|i| i.wrapping_mul(7)).collect();

    let morus = MorusAead::from_arrays(&key, &iv);

    for counter in 1u64..=16 {
        let nonce16 = super::super::make_nonce16(&iv, counter).expect("bounded test counter");

        // Reference: native in-place path.
        let mut ref_buf = pt.clone();
        let ref_tag = morus.encrypt_in_place(&mut ref_buf, ad, &nonce16);

        // Trait path: seal_with_u64_counter (must be in-place, no to_vec).
        let mut trait_buf = vec![0u8; pt.len() + 16];
        trait_buf[..pt.len()].copy_from_slice(&pt);
        let sealed_len = morus
            .seal_with_u64_counter(counter, ad, trait_buf.as_mut_slice(), pt.len(), None)
            .unwrap();
        assert_eq!(sealed_len, pt.len() + 16);
        assert_eq!(&trait_buf[..pt.len()], ref_buf.as_slice());
        assert_eq!(&trait_buf[pt.len()..], &ref_tag);

        // Trait path: open_with_u64_counter must recover plaintext in-place.
        let pt_len = morus.open_with_u64_counter(counter, ad, trait_buf.as_mut_slice()).unwrap();
        assert_eq!(pt_len, pt.len());
        assert_eq!(&trait_buf[..pt_len], pt.as_slice());
    }

    // Forgery: a flipped ciphertext bit must fail authentication on the trait path.
    let mut bad = vec![0u8; pt.len() + 16];
    bad[..pt.len()].copy_from_slice(&pt);
    morus.seal_with_u64_counter(99, ad, bad.as_mut_slice(), pt.len(), None).unwrap();
    bad[0] ^= 0xff;
    assert!(
        morus.open_with_u64_counter(99, ad, bad.as_mut_slice()).is_err(),
        "tampered ciphertext must fail authentication"
    );
}
