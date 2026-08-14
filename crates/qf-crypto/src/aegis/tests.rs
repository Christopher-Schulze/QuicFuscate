use super::{Aegis128L, Aegis128X4, Aegis128X8, AegisError};

// Fixed key/nonce used across all inline tests.
const KEY: [u8; 16] = [
    0x10, 0x01, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];
const NONCE: [u8; 16] = [
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
];

// Encrypt with Aegis128L; returns (ciphertext, tag).
fn enc(msg: &[u8], ad: &[u8]) -> (Vec<u8>, [u8; 16]) {
    let mut buf = msg.to_vec();
    let tag = Aegis128L::new(&KEY, &NONCE).unwrap().encrypt_in_place(&mut buf, ad);
    (buf, tag)
}

// Decrypt with Aegis128L; returns plaintext or error.
fn dec(ct: &[u8], ad: &[u8], tag: &[u8; 16]) -> Result<Vec<u8>, AegisError> {
    Aegis128L::new(&KEY, &NONCE).unwrap().decrypt_verified(ct, ad, tag)
}

#[test]
fn aegis128l_matches_pinned_cfrg_vectors() {
    // Pinned CFRG vectors from commit 8e289c40:
    // https://raw.githubusercontent.com/cfrg/draft-irtf-cfrg-aegis-aead/8e289c40/test-vectors/aegis-128l-test-vectors.json
    let vectors = [
        (
            "Test Vector 1",
            "10010000000000000000000000000000",
            "10000200000000000000000000000000",
            "",
            "00000000000000000000000000000000",
            "c1c0e58bd913006feba00f4b3cc3594e",
            "abe0ece80c24868a226a35d16bdae37a",
        ),
        (
            "Test Vector 2",
            "10010000000000000000000000000000",
            "10000200000000000000000000000000",
            "",
            "",
            "",
            "c2b879a67def9d74e6c14f708bbcc9b4",
        ),
        (
            "Test Vector 3",
            "10010000000000000000000000000000",
            "10000200000000000000000000000000",
            "0001020304050607",
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
            "79d94593d8c2119d7e8fd9b8fc77845c5c077a05b2528b6ac54b563aed8efe84",
            "cc6f3372f6aa1bb82388d695c3962d9a",
        ),
        (
            "Test Vector 4",
            "10010000000000000000000000000000",
            "10000200000000000000000000000000",
            "0001020304050607",
            "000102030405060708090a0b0c0d",
            "79d94593d8c2119d7e8fd9b8fc77",
            "5c04b3dba849b2701effbe32c7f0fab7",
        ),
        (
            "Test Vector 5",
            "10010000000000000000000000000000",
            "10000200000000000000000000000000",
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20212223242526272829",
            "101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f3031323334353637",
            "b31052ad1cca4e291abcf2df3502e6bdb1bfd6db36798be3607b1f94d34478aa7ede7f7a990fec10",
            "7542a745733014f9474417b337399507",
        ),
    ];

    for (name, key_hex, nonce_hex, ad_hex, msg_hex, expected_ct_hex, expected_tag_hex) in vectors {
        let key: [u8; 16] = hex::decode(key_hex).unwrap().try_into().unwrap();
        let nonce: [u8; 16] = hex::decode(nonce_hex).unwrap().try_into().unwrap();
        let ad = hex::decode(ad_hex).unwrap();
        let msg = hex::decode(msg_hex).unwrap();
        let expected_ct = hex::decode(expected_ct_hex).unwrap();
        let expected_tag: [u8; 16] = hex::decode(expected_tag_hex).unwrap().try_into().unwrap();

        let mut l_ciphertext = msg.clone();
        let l_tag = Aegis128L::new(&key, &nonce).unwrap().encrypt_in_place(&mut l_ciphertext, &ad);
        assert_eq!(l_ciphertext, expected_ct, "L ciphertext mismatch: {name}");
        assert_eq!(l_tag, expected_tag, "L tag mismatch: {name}");

        let mut x4_ciphertext = msg.clone();
        let x4_tag =
            Aegis128X4::new(&key, &nonce).unwrap().encrypt_in_place(&mut x4_ciphertext, &ad);
        assert_eq!(x4_ciphertext, expected_ct, "X4 ciphertext mismatch: {name}");
        assert_eq!(x4_tag, expected_tag, "X4 tag mismatch: {name}");

        let mut x8_ciphertext = msg.clone();
        let x8_tag =
            Aegis128X8::new(&key, &nonce).unwrap().encrypt_in_place(&mut x8_ciphertext, &ad);
        assert_eq!(x8_ciphertext, expected_ct, "X8 ciphertext mismatch: {name}");
        assert_eq!(x8_tag, expected_tag, "X8 tag mismatch: {name}");

        let mut verifier = Aegis128L::new(&key, &nonce).unwrap();
        assert_eq!(verifier.decrypt_verified(&expected_ct, &ad, &expected_tag).unwrap(), msg);
    }
}

#[test]
fn aegis128l_rejects_pinned_cfrg_failure_vectors() {
    // The failure cases are part of the same pinned CFRG vector file and mutate
    // key, ciphertext, associated data, or the 128-bit tag.
    let vectors = [
        (
            "key",
            "10000200000000000000000000000000",
            "10010000000000000000000000000000",
            "0001020304050607",
            "79d94593d8c2119d7e8fd9b8fc77",
            "5c04b3dba849b2701effbe32c7f0fab7",
        ),
        (
            "ciphertext",
            "10010000000000000000000000000000",
            "10000200000000000000000000000000",
            "0001020304050607",
            "79d94593d8c2119d7e8fd9b8fc78",
            "5c04b3dba849b2701effbe32c7f0fab7",
        ),
        (
            "associated data",
            "10010000000000000000000000000000",
            "10000200000000000000000000000000",
            "0001020304050608",
            "79d94593d8c2119d7e8fd9b8fc77",
            "5c04b3dba849b2701effbe32c7f0fab7",
        ),
        (
            "tag",
            "10010000000000000000000000000000",
            "10000200000000000000000000000000",
            "0001020304050607",
            "79d94593d8c2119d7e8fd9b8fc77",
            "6c04b3dba849b2701effbe32c7f0fab8",
        ),
    ];

    for (mutation, key_hex, nonce_hex, ad_hex, ciphertext_hex, tag_hex) in vectors {
        let key: [u8; 16] = hex::decode(key_hex).unwrap().try_into().unwrap();
        let nonce: [u8; 16] = hex::decode(nonce_hex).unwrap().try_into().unwrap();
        let ad = hex::decode(ad_hex).unwrap();
        let ciphertext = hex::decode(ciphertext_hex).unwrap();
        let tag: [u8; 16] = hex::decode(tag_hex).unwrap().try_into().unwrap();
        let mut verifier = Aegis128L::new(&key, &nonce).unwrap();
        assert_eq!(
            verifier.decrypt_verified(&ciphertext, &ad, &tag),
            Err(AegisError::InvalidTag),
            "CFRG failure vector unexpectedly verified: {mutation}"
        );
    }
}

// ---- Roundtrip ----

#[test]
fn aegis128l_roundtrip_empty_msg() {
    let (ct, tag) = enc(b"", b"");
    assert!(ct.is_empty());
    assert_eq!(dec(&ct, b"", &tag).unwrap(), b"");
}

#[test]
fn aegis128l_roundtrip_one_byte() {
    let msg = [0x42u8];
    let (ct, tag) = enc(&msg, b"ad");
    assert_eq!(ct.len(), 1);
    // Encryption must change the byte.
    assert_ne!(ct[0], msg[0]);
    assert_eq!(dec(&ct, b"ad", &tag).unwrap(), msg);
}

#[test]
fn aegis128l_roundtrip_block_aligned_32() {
    let msg = [0xabu8; 32];
    let (ct, tag) = enc(&msg, b"");
    assert_eq!(ct.len(), 32);
    assert_eq!(dec(&ct, b"", &tag).unwrap().as_slice(), &msg[..]);
}

#[test]
fn aegis128l_roundtrip_unaligned_33() {
    let msg: Vec<u8> = (0u8..33).collect();
    let (ct, tag) = enc(&msg, b"hdr");
    assert_eq!(ct.len(), 33);
    assert_eq!(dec(&ct, b"hdr", &tag).unwrap(), msg);
}

// ---- Associated data ----

#[test]
fn aegis128l_empty_ad_accepted() {
    let msg = b"hello world12345";
    let (ct, tag) = enc(msg, b"");
    assert_eq!(dec(&ct, b"", &tag).unwrap().as_slice(), msg);
}

#[test]
fn aegis128l_different_ad_changes_tag() {
    let msg = b"same plaintext!!";
    let (_, t1) = enc(msg, b"ad-one");
    let (_, t2) = enc(msg, b"ad-two");
    assert_ne!(t1, t2);
}

#[test]
fn aegis128l_wrong_ad_fails_authentication() {
    let msg = b"confidential msg";
    let (ct, tag) = enc(msg, b"correct-ad");
    assert_eq!(dec(&ct, b"wrong-ad", &tag), Err(AegisError::InvalidTag));
}

// ---- Forgery detection ----

#[test]
fn aegis128l_ciphertext_bit_flip_detected() {
    let msg = b"protect this msg";
    let (mut ct, tag) = enc(msg, b"");
    ct[0] ^= 0x01;
    assert_eq!(dec(&ct, b"", &tag), Err(AegisError::InvalidTag));
}

#[test]
fn aegis128l_tag_bit_flip_detected() {
    let msg = b"another message!";
    let (ct, mut tag) = enc(msg, b"");
    tag[0] ^= 0x01;
    assert_eq!(dec(&ct, b"", &tag), Err(AegisError::InvalidTag));
}

// ---- Nonce sensitivity ----

#[test]
fn aegis128l_different_nonce_different_ciphertext() {
    let msg = b"same plaintext!!";
    let alt_nonce = [0u8; 16]; // different from NONCE
    let (ct1, _) = enc(msg, b"");
    let mut buf = msg.to_vec();
    Aegis128L::new(&KEY, &alt_nonce).unwrap().encrypt_in_place(&mut buf, b"");
    assert_ne!(ct1, buf);
}

// ---- decrypt_verified API ----

#[test]
fn aegis128l_decrypt_verified_ok() {
    let msg = b"verified message";
    let (ct, tag) = enc(msg, b"ad");
    let pt = Aegis128L::new(&KEY, &NONCE).unwrap().decrypt_verified(&ct, b"ad", &tag).unwrap();
    assert_eq!(pt.as_slice(), msg);
}

#[test]
fn aegis128l_decrypt_verified_returns_err_on_forgery() {
    let msg = b"do not leak this";
    let (mut ct, tag) = enc(msg, b"");
    ct[0] ^= 0xff;
    let result = Aegis128L::new(&KEY, &NONCE).unwrap().decrypt_verified(&ct, b"", &tag);
    assert_eq!(result, Err(AegisError::InvalidTag));
}

// ---- Determinism ----

#[test]
fn aegis128l_same_inputs_same_output() {
    let msg = b"deterministic!!!";
    let (ct1, tag1) = enc(msg, b"ad");
    let (ct2, tag2) = enc(msg, b"ad");
    assert_eq!(ct1, ct2);
    assert_eq!(tag1, tag2);
}

// ---- Large message exercises all hot paths ----

#[test]
fn aegis128l_roundtrip_large_multi_path() {
    // 300 bytes exercises all three hot-path levels (64-byte, 32-byte, tail) in Aegis128L
    let msg: Vec<u8> = (0u8..=255).cycle().take(300).collect();
    let ad = b"large-msg-ad";
    let (ct, tag) = enc(&msg, ad);
    assert_eq!(ct.len(), 300);
    assert_eq!(dec(&ct, ad, &tag).unwrap(), msg);
}

// ---- X4/X8 variant consistency (inline check; full matrix is in crypto/tests.rs) ----

#[test]
fn aegis128x4_roundtrip_and_matches_base() {
    let msg: Vec<u8> = (0u8..=100).collect();
    let ad = b"x4-ad";

    let (ct_base, tag_base) = enc(&msg, ad);

    let mut buf = msg.clone();
    let tag_x4 = Aegis128X4::new(&KEY, &NONCE).unwrap().encrypt_in_place(&mut buf, ad);
    assert_eq!(buf, ct_base, "X4 ciphertext must equal Aegis128L");
    assert_eq!(tag_x4, tag_base, "X4 tag must equal Aegis128L");

    // Decrypt X4-produced ciphertext back to plaintext.
    let pt = dec(&ct_base, ad, &tag_base).unwrap();
    assert_eq!(pt, msg);
}

#[test]
fn aegis128x4_batch_seal_matches_single() {
    use super::{AeadSeal, AeadSealItem, Aegis128X4Aead};

    let key = [0x77u8; 16];
    let iv = [0x88u8; 12];
    let ad = b"batch-ad";
    let pt = b"homogeneous-payload!!";
    let seal = Aegis128X4Aead::from_arrays(&key, &iv);

    let mut batch_bufs = (0..4u64)
        .map(|_| {
            let mut b = vec![0u8; pt.len() + 16];
            b[..pt.len()].copy_from_slice(pt);
            b
        })
        .collect::<Vec<_>>();
    let mut items = batch_bufs
        .iter_mut()
        .enumerate()
        .map(|(i, buf)| AeadSealItem {
            counter: i as u64 + 1,
            ad,
            buf: buf.as_mut_slice(),
            plaintext_len: pt.len(),
        })
        .collect::<Vec<_>>();
    seal.seal_batch(items.as_mut_slice()).unwrap();

    for (i, buf) in batch_bufs.iter().enumerate() {
        let mut single = vec![0u8; pt.len() + 16];
        single[..pt.len()].copy_from_slice(pt);
        let single_len = seal
            .seal_with_u64_counter(i as u64 + 1, ad, single.as_mut_slice(), pt.len(), None)
            .unwrap();
        assert_eq!(buf.len(), single_len);
        assert_eq!(buf, &single);
    }
}

#[test]
fn aegis128x8_batch_open_matches_single() {
    use super::{AeadOpen, AeadOpenItem, AeadSeal, AeadSealItem, Aegis128X8Aead};

    let key = [0x99u8; 16];
    let iv = [0xAAu8; 12];
    let ad = b"open-batch";
    let pt = b"decrypt-me-please!!";
    let seal = Aegis128X8Aead::from_arrays(&key, &iv);
    let open = Aegis128X8Aead::from_arrays(&key, &iv);

    let mut sealed = vec![0u8; pt.len() + 16];
    sealed[..pt.len()].copy_from_slice(pt);
    let mut seal_item =
        AeadSealItem { counter: 42, ad, buf: sealed.as_mut_slice(), plaintext_len: pt.len() };
    seal.seal_batch(core::slice::from_mut(&mut seal_item)).unwrap();

    let mut single = sealed.clone();
    let pt_len = open.open_with_u64_counter(42, ad, single.as_mut_slice()).unwrap();
    assert_eq!(pt_len, pt.len());
    assert_eq!(&single[..pt_len], pt);

    let mut batch_bufs = (0..3usize)
        .map(|i| {
            let mut buf = vec![0u8; pt.len() + 16];
            buf[..pt.len()].copy_from_slice(pt);
            let mut item = AeadSealItem {
                counter: 100 + i as u64,
                ad,
                buf: buf.as_mut_slice(),
                plaintext_len: pt.len(),
            };
            seal.seal_batch(core::slice::from_mut(&mut item)).unwrap();
            buf
        })
        .collect::<Vec<_>>();
    let mut open_items = batch_bufs
        .iter_mut()
        .enumerate()
        .map(|(i, buf)| AeadOpenItem { counter: 100 + i as u64, ad, buf: buf.as_mut_slice() })
        .collect::<Vec<_>>();
    open.open_batch(open_items.as_mut_slice()).unwrap();
    for buf in &batch_bufs {
        assert_eq!(&buf[..pt.len()], pt);
    }
}

#[test]
fn aegis128x8_roundtrip_and_matches_base() {
    // 256 bytes = exactly 2 hot-path chunks for X8
    let msg: Vec<u8> = (0u8..=255).collect();
    let ad = b"x8-ad";

    let (ct_base, tag_base) = enc(&msg, ad);

    let mut buf = msg.clone();
    let tag_x8 = Aegis128X8::new(&KEY, &NONCE).unwrap().encrypt_in_place(&mut buf, ad);
    assert_eq!(buf, ct_base, "X8 ciphertext must equal Aegis128L");
    assert_eq!(tag_x8, tag_base, "X8 tag must equal Aegis128L");

    let pt = dec(&ct_base, ad, &tag_base).unwrap();
    assert_eq!(pt, msg);
}

// TODO-393: differential test — the AEAD wrapper reuses cipher state via
// `reinit` after the first packet. Output must be byte-identical to a fresh
// `Aegis128L::new` per packet (the pre-optimization baseline).
#[test]
fn aegis128l_aead_reinit_matches_fresh_new_per_packet() {
    use super::super::make_nonce16;
    use super::{AeadOpen, AeadSeal, Aegis128LAead};

    let key = [0x7au8; 16];
    let iv = [0x1bu8; 12];
    let ad = b"diff-ad";
    let pt = b"reinit-state-reuse-payload";

    let seal = Aegis128LAead::from_arrays(&key, &iv);
    let open = Aegis128LAead::from_arrays(&key, &iv);

    for counter in 1u64..=64 {
        // Reference: fresh cipher per packet (baseline).
        let nonce16 = make_nonce16(&iv, counter).expect("bounded test counter");
        let mut ref_buf = vec![0u8; pt.len() + 16];
        ref_buf[..pt.len()].copy_from_slice(pt);
        let ref_tag =
            Aegis128L::new(&key, &nonce16).unwrap().encrypt_in_place(&mut ref_buf[..pt.len()], ad);
        ref_buf[pt.len()..].copy_from_slice(&ref_tag);

        // Optimized: AEAD wrapper (reinit after first packet).
        let mut opt_buf = vec![0u8; pt.len() + 16];
        opt_buf[..pt.len()].copy_from_slice(pt);
        let opt_len = seal
            .seal_with_u64_counter(counter, ad, opt_buf.as_mut_slice(), pt.len(), None)
            .unwrap();
        assert_eq!(opt_len, pt.len() + 16);
        assert_eq!(opt_buf, ref_buf, "ciphertext/tag diverged at counter {counter}");

        // Decrypt via the wrapper must recover plaintext.
        let pt_len = open.open_with_u64_counter(counter, ad, opt_buf.as_mut_slice()).unwrap();
        assert_eq!(pt_len, pt.len());
        assert_eq!(&opt_buf[..pt_len], pt);
    }
}

#[test]
fn aegis_wrapper_drop_erases_keys_and_ivs() {
    use super::{AeadSeal, Aegis128LAead, Aegis128X4Aead, Aegis128X8Aead};
    use std::sync::{Arc, Mutex};

    let events = Arc::new(Mutex::new(Vec::<(&'static str, Vec<u8>)>::new()));
    let observed = Arc::clone(&events);
    let _observer = crate::secret::test_observation::install(Arc::new(move |label, bytes| {
        observed.lock().expect("erasure event lock").push((label, bytes.to_vec()));
    }));

    let key = [0xA5u8; 16];
    let iv = [0x5Au8; 12];
    for seal in [
        Box::new(Aegis128LAead::from_arrays(&key, &iv)) as Box<dyn AeadSeal + Send + Sync>,
        Box::new(Aegis128X4Aead::from_arrays(&key, &iv)),
        Box::new(Aegis128X8Aead::from_arrays(&key, &iv)),
    ] {
        let mut buffer = vec![0xC3u8; 48];
        seal.seal_with_u64_counter(7, b"drop-proof", &mut buffer, 32, None)
            .expect("initialize wrapper state");
    }

    let events = events.lock().expect("erasure events");
    for (label, expected_len) in [
        ("aegis_l_wrapper_key", 16),
        ("aegis_l_wrapper_iv", 12),
        ("aegis_l_inner_state", 128),
        ("aegis_x4_wrapper_key", 16),
        ("aegis_x4_wrapper_iv", 12),
        ("aegis_x4_inner_state", 128),
        ("aegis_x8_wrapper_key", 16),
        ("aegis_x8_wrapper_iv", 12),
        ("aegis_x8_inner_state", 128),
    ] {
        let bytes = events
            .iter()
            .find_map(|(event_label, bytes)| (*event_label == label).then_some(bytes))
            .unwrap_or_else(|| panic!("missing erasure event: {label}"));
        assert_eq!(bytes.len(), expected_len, "wrong erased range for {label}");
        assert!(bytes.iter().all(|byte| *byte == 0), "non-zero byte retained by {label}");
    }
}

#[test]
fn aegis_replacement_and_partial_wrapper_drop_are_erased() {
    use super::{AeadSeal, Aegis128LAead};
    use std::sync::{Arc, Mutex};

    let events = Arc::new(Mutex::new(Vec::<(&'static str, Vec<u8>)>::new()));
    let observed = Arc::clone(&events);
    let _observer = crate::secret::test_observation::install(Arc::new(move |label, bytes| {
        observed.lock().expect("erasure event lock").push((label, bytes.to_vec()));
    }));

    let mut retained = Some(Aegis128LAead::from_arrays(&[0x3C; 16], &[0xC3; 12]));
    let mut buffer = vec![0xA7; 48];
    retained
        .as_ref()
        .expect("retained wrapper")
        .seal_with_u64_counter(9, b"replacement-proof", &mut buffer, 32, None)
        .expect("initialize retained wrapper state");
    drop(retained.replace(Aegis128LAead::from_arrays(&[0x6D; 16], &[0xD6; 12])));
    assert!(Aegis128LAead::new(&[0xD4; 7], &[0x4D; 5]).is_err());

    let events = events.lock().expect("erasure events");
    for (label, expected_count) in
        [("aegis_l_wrapper_key", 1), ("aegis_l_wrapper_iv", 1), ("aegis_l_inner_state", 1)]
    {
        let matching =
            events.iter().filter(|(event_label, _)| *event_label == label).collect::<Vec<_>>();
        assert_eq!(matching.len(), expected_count, "wrong erasure event count for {label}");
        for (_, bytes) in matching {
            assert!(!bytes.is_empty(), "erased range must be observable for {label}");
            assert!(bytes.iter().all(|byte| *byte == 0), "non-zero byte retained by {label}");
        }
    }
    for label in ["aegis_l_wrapper_key", "aegis_l_wrapper_iv"] {
        let bytes = events
            .iter()
            .find_map(|(event_label, bytes)| (*event_label == label).then_some(bytes))
            .unwrap_or_else(|| panic!("missing erasure event: {label}"));
        assert!(bytes.iter().all(|byte| *byte == 0), "partial wrapper retained {label}");
    }
}

#[test]
fn aegis_wrapper_supports_concurrent_packets() {
    use super::{AeadSeal, Aegis128LAead};
    use std::sync::Arc;
    use std::thread;

    let key = [0x42u8; 16];
    let iv = [0x24u8; 12];
    let ad = b"concurrent-aegis";
    let plaintext = b"same-wrapper-independent-state";
    let seal = Arc::new(Aegis128LAead::from_arrays(&key, &iv));
    let handles = (1u64..=8)
        .map(|counter| {
            let seal = Arc::clone(&seal);
            thread::spawn(move || {
                let mut buf = vec![0u8; plaintext.len() + 16];
                buf[..plaintext.len()].copy_from_slice(plaintext);
                seal.seal_with_u64_counter(counter, ad, &mut buf, plaintext.len(), None)
                    .expect("concurrent seal");
                (counter, buf)
            })
        })
        .collect::<Vec<_>>();

    for handle in handles {
        let (counter, actual) = handle.join().expect("concurrent worker");
        let nonce16 = super::super::make_nonce16(&iv, counter).expect("bounded test counter");
        let mut expected = plaintext.to_vec();
        let tag = Aegis128L::new(&key, &nonce16)
            .expect("reference cipher")
            .encrypt_in_place(&mut expected, ad);
        expected.extend_from_slice(&tag);
        assert_eq!(actual, expected, "counter {counter} diverged");
    }
}
