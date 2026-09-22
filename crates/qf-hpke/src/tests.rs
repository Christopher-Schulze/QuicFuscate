//! Provider tests: per-suite roundtrips, failure modes, and adapter-mapping
//! checks against the underlying hpke-rs API.

use super::*;

fn each_suite() -> impl Iterator<Item = &'static &'static dyn Hpke> {
    ALL_SUPPORTED_SUITES.iter()
}

#[test]
fn all_suites_roundtrip_single_shot() {
    let info = b"qf-ech";
    let aad = b"aad";
    let pt = b"encrypted client hello payload";
    for suite in each_suite() {
        let (pk, sk) = suite.generate_key_pair().unwrap();
        let (enc, ct) = suite.seal(info, aad, pt, &pk).unwrap();
        let out = suite.open(&enc, info, aad, &ct, &sk).unwrap();
        assert_eq!(out, pt, "{:?}", suite.suite());
    }
}

#[test]
fn all_suites_roundtrip_context() {
    let info = b"qf-ech";
    for suite in each_suite() {
        let (pk, sk) = suite.generate_key_pair().unwrap();
        let (enc, mut sealer) = suite.setup_sealer(info, &pk).unwrap();
        let ct0 = sealer.seal(b"a", b"one").unwrap();
        let ct1 = sealer.seal(b"a", b"two").unwrap();
        assert_ne!(ct0, ct1);
        let mut opener = suite.setup_opener(&enc, info, &sk).unwrap();
        assert_eq!(opener.open(b"a", &ct0).unwrap(), b"one");
        assert_eq!(opener.open(b"a", &ct1).unwrap(), b"two");
    }
}

#[test]
fn wrong_key_fails() {
    let suite = DH_KEM_X25519_HKDF_SHA256_AES_128;
    let (pk, _sk) = suite.generate_key_pair().unwrap();
    let (_pk2, sk2) = suite.generate_key_pair().unwrap();
    let (enc, ct) = suite.seal(b"i", b"a", b"x", &pk).unwrap();
    assert!(suite.open(&enc, b"i", b"a", &ct, &sk2).is_err());
}

#[test]
fn wrong_aad_and_info_fail() {
    let suite = DH_KEM_X25519_HKDF_SHA256_AES_128;
    let (pk, sk) = suite.generate_key_pair().unwrap();
    let (enc, ct) = suite.seal(b"i", b"a", b"x", &pk).unwrap();
    assert!(suite.open(&enc, b"i", b"WRONG", &ct, &sk).is_err());
    assert!(suite.open(&enc, b"WRONG", b"a", &ct, &sk).is_err());
}

#[test]
fn key_sizes_match_kem() {
    // X25519 keys are 32 bytes; P-256 private keys are 32 bytes.
    let (pk, sk) = DH_KEM_X25519_HKDF_SHA256_AES_128.generate_key_pair().unwrap();
    assert_eq!(pk.0.len(), 32);
    assert_eq!(sk.secret_bytes().len(), 32);
    let (pk, sk) = DH_KEM_P256_HKDF_SHA256_AES_128.generate_key_pair().unwrap();
    assert!(!pk.0.is_empty());
    assert!(!sk.secret_bytes().is_empty());
}

#[test]
fn suite_reports_wire_ids() {
    assert_eq!(
        DH_KEM_X25519_HKDF_SHA256_AES_128.suite(),
        HpkeSuite {
            kem: HpkeKem::DHKEM_X25519_HKDF_SHA256,
            sym: HpkeSymmetricCipherSuite {
                kdf_id: HpkeKdf::HKDF_SHA256,
                aead_id: HpkeAead::AES_128_GCM,
            },
        }
    );
    // Table covers the same suite set as the aws-lc provider minus P-521 (unsupported by the rustcrypto backend).
    assert_eq!(ALL_SUPPORTED_SUITES.len(), 9);
}

/// The adapter must hand `info`/`aad`/`enc` through to hpke-rs un-mangled:
/// ciphertext produced through the rustls trait must decrypt through the
/// hpke-rs API with the same arguments.
#[test]
fn adapter_mapping_matches_hpke_rs_api() {
    let suite = DH_KEM_X25519_HKDF_SHA256_AES_128;
    let mut hpke = RsHpke::<Backend>::new(
        Mode::Base,
        KemAlgorithm::DhKem25519,
        KdfAlgorithm::HkdfSha256,
        AeadAlgorithm::Aes128Gcm,
    );
    let (sk, pk) = hpke.generate_key_pair().unwrap().into_keys();

    let (enc, ct) =
        suite.seal(b"i", b"a", b"payload", &HpkePublicKey(pk.as_slice().to_vec())).unwrap();

    let out = hpke.open(&enc.0, &sk, b"i", b"a", &ct, None, None, None).unwrap();
    assert_eq!(out, b"payload");
}

/// Same check in the other direction: hpke-rs seals, rustls trait opens.
#[test]
fn hpke_rs_ciphertext_opens_through_trait() {
    let suite = DH_KEM_P256_HKDF_SHA256_AES_128;
    let mut hpke = RsHpke::<Backend>::new(
        Mode::Base,
        KemAlgorithm::DhKemP256,
        KdfAlgorithm::HkdfSha256,
        AeadAlgorithm::Aes128Gcm,
    );
    let (sk, pk) = hpke.generate_key_pair().unwrap().into_keys();

    let (enc, ct) = hpke.seal(&pk, b"i", b"a", b"payload", None, None, None).unwrap();

    let out = suite
        .open(
            &EncapsulatedSecret(enc),
            b"i",
            b"a",
            &ct,
            &HpkePrivateKey::from(sk.as_slice().to_vec()),
        )
        .unwrap();
    assert_eq!(out, b"payload");
}
