use super::hkdf::{hkdf_expand, hkdf_extract};

const TRAFFIC_SECRET_LEN: usize = 32;

fn traffic_secret_array(
    secret: &[u8],
) -> Result<[u8; TRAFFIC_SECRET_LEN], super::aead::KeyMaterialError> {
    super::aead::require_exact_length(
        "QUIC KDF",
        "traffic secret",
        TRAFFIC_SECRET_LEN,
        secret.len(),
    )?;
    let mut secret_array = [0u8; TRAFFIC_SECRET_LEN];
    secret_array.copy_from_slice(secret);
    Ok(secret_array)
}

fn hkdf_expand_label(prk: &[u8; 32], label: &[u8], out_len: usize) -> Vec<u8> {
    let full_label_len = b"tls13 ".len() + label.len();
    let mut info = Vec::with_capacity(2 + 1 + full_label_len + 1);
    info.extend_from_slice(&(out_len as u16).to_be_bytes());
    info.push(full_label_len as u8);
    info.extend_from_slice(b"tls13 ");
    info.extend_from_slice(label);
    info.push(0);
    hkdf_expand(prk, &info, out_len)
}

fn packet_labels(version: u32) -> (&'static [u8], &'static [u8], &'static [u8], &'static [u8]) {
    match version {
        0x6b3343cf => (b"quicv2 key", b"quicv2 iv", b"quicv2 hp", b"quicv2 ku"),
        _ => (b"quic key", b"quic iv", b"quic hp", b"quic ku"),
    }
}

/// QUIC version 1 initial salt (RFC 9001, Section 5.2)
pub const INITIAL_SALT_V1: [u8; 20] = [
    0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad,
    0xcc, 0xbb, 0x7f, 0x0a,
];

/// QUIC version 2 initial salt (RFC 9369)
pub const INITIAL_SALT_V2: [u8; 20] = [
    0x0d, 0xed, 0xe3, 0xde, 0xf7, 0x00, 0xa6, 0xdb, 0x81, 0x93, 0x81, 0xbe, 0x6e, 0x26, 0x9d, 0xcb,
    0xf9, 0xbd, 0x2e, 0xd9,
];

/// Derive the initial secret from the destination connection ID
pub fn derive_initial_secret(dcid: &[u8], version: u32) -> [u8; 32] {
    let salt = match version {
        0x00000001 => &INITIAL_SALT_V1[..], // QUIC v1 (RFC 9001)
        0x6b3343cf => &INITIAL_SALT_V2[..], // QUIC v2 (RFC 9369)
        _ => &INITIAL_SALT_V1[..],          // default to v1 for unknown versions
    };
    hkdf_extract(salt, dcid)
}

/// Derive client initial secret from an exact 32-byte initial secret.
pub fn derive_client_initial_secret(
    initial_secret: &[u8],
) -> Result<Vec<u8>, super::aead::KeyMaterialError> {
    let prk = traffic_secret_array(initial_secret)?;
    Ok(hkdf_expand_label(&prk, b"client in", TRAFFIC_SECRET_LEN))
}

/// Derive server initial secret from an exact 32-byte initial secret.
pub fn derive_server_initial_secret(
    initial_secret: &[u8],
) -> Result<Vec<u8>, super::aead::KeyMaterialError> {
    let prk = traffic_secret_array(initial_secret)?;
    Ok(hkdf_expand_label(&prk, b"server in", TRAFFIC_SECRET_LEN))
}

/// Derive packet protection key from an exact 32-byte traffic secret.
pub fn derive_pkt_key(
    secret: &[u8],
    key_len: usize,
) -> Result<Vec<u8>, super::aead::KeyMaterialError> {
    derive_pkt_key_for_version(secret, key_len, 0x00000001)
}

/// Derive a version-specific QUIC packet protection key.
pub fn derive_pkt_key_for_version(
    secret: &[u8],
    key_len: usize,
    version: u32,
) -> Result<Vec<u8>, super::aead::KeyMaterialError> {
    let prk = traffic_secret_array(secret)?;
    Ok(hkdf_expand_label(&prk, packet_labels(version).0, key_len))
}

/// Derive packet protection IV from an exact 32-byte traffic secret.
pub fn derive_pkt_iv(
    secret: &[u8],
    iv_len: usize,
) -> Result<Vec<u8>, super::aead::KeyMaterialError> {
    derive_pkt_iv_for_version(secret, iv_len, 0x00000001)
}

/// Derive a version-specific QUIC packet protection IV.
pub fn derive_pkt_iv_for_version(
    secret: &[u8],
    iv_len: usize,
    version: u32,
) -> Result<Vec<u8>, super::aead::KeyMaterialError> {
    let prk = traffic_secret_array(secret)?;
    Ok(hkdf_expand_label(&prk, packet_labels(version).1, iv_len))
}

/// Derive header protection key from an exact 32-byte traffic secret.
pub fn derive_hdr_key(
    secret: &[u8],
    key_len: usize,
) -> Result<Vec<u8>, super::aead::KeyMaterialError> {
    derive_hdr_key_for_version(secret, key_len, 0x00000001)
}

/// Derive a version-specific QUIC header protection key.
pub fn derive_hdr_key_for_version(
    secret: &[u8],
    key_len: usize,
    version: u32,
) -> Result<Vec<u8>, super::aead::KeyMaterialError> {
    let prk = traffic_secret_array(secret)?;
    Ok(hkdf_expand_label(&prk, packet_labels(version).2, key_len))
}

/// Derive next secret for key update from an exact 32-byte traffic secret (RFC 9001, Section 6).
pub fn derive_next_secret(secret: &[u8]) -> Result<Vec<u8>, super::aead::KeyMaterialError> {
    derive_next_secret_for_version(secret, 0x00000001)
}

/// Derive the next traffic secret with the version-specific QUIC label.
pub fn derive_next_secret_for_version(
    secret: &[u8],
    version: u32,
) -> Result<Vec<u8>, super::aead::KeyMaterialError> {
    let prk = traffic_secret_array(secret)?;
    Ok(hkdf_expand_label(&prk, packet_labels(version).3, TRAFFIC_SECRET_LEN))
}

/// Helper to derive all keys from a secret at once
pub struct DerivedKeys {
    /// Packet protection key.
    pub key: Vec<u8>,
    /// Packet protection IV/nonce.
    pub iv: Vec<u8>,
    /// Header protection key.
    pub hp: Vec<u8>,
}

/// Derive all keys (key, iv, hp) from an exact 32-byte traffic secret.
pub fn derive_keys(
    secret: &[u8],
    key_len: usize,
    iv_len: usize,
    hp_len: usize,
) -> Result<DerivedKeys, super::aead::KeyMaterialError> {
    Ok(DerivedKeys {
        key: derive_pkt_key(secret, key_len)?,
        iv: derive_pkt_iv(secret, iv_len)?,
        hp: derive_hdr_key(secret, hp_len)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::aead::KeyMaterialError;

    // ---------------------------------------------------------------
    // RFC 9001 Appendix A - Initial Secrets test vector
    // DCID = 0x8394c8f03e515708 (the example from the RFC)
    // ---------------------------------------------------------------
    const RFC9001_DCID: [u8; 8] = [0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08];

    #[test]
    fn initial_secret_v1_deterministic() {
        let s1 = derive_initial_secret(&RFC9001_DCID, 0x00000001);
        let s2 = derive_initial_secret(&RFC9001_DCID, 0x00000001);
        assert_eq!(s1, s2, "same input must produce identical initial secret");
        assert_ne!(s1, [0u8; 32], "initial secret must not be all zeros");
    }

    #[test]
    fn initial_secret_v1_matches_rfc9001() {
        // RFC 9001, Section A.1: initial_secret from DCID 0x8394c8f03e515708
        // HKDF-Extract(initial_salt, cid) yields a known 32-byte PRK.
        // The expected value is taken from RFC 9001 Appendix A.1:
        let expected: [u8; 32] = [
            0x7d, 0xb5, 0xdf, 0x06, 0xe7, 0xa6, 0x9e, 0x43, 0x24, 0x96, 0xad, 0xed, 0xb0, 0x08,
            0x51, 0x92, 0x35, 0x95, 0x22, 0x15, 0x96, 0xae, 0x2a, 0xe9, 0xfb, 0x81, 0x15, 0xc1,
            0xe9, 0xed, 0x0a, 0x44,
        ];
        let actual = derive_initial_secret(&RFC9001_DCID, 0x00000001);
        assert_eq!(actual, expected, "must match RFC 9001 Appendix A.1 initial_secret");
    }

    #[test]
    fn client_initial_secret_deterministic_snapshot() {
        let initial_secret = derive_initial_secret(&RFC9001_DCID, 0x00000001);
        let client_secret =
            derive_client_initial_secret(&initial_secret).expect("valid initial secret");
        assert_eq!(
            hex::encode(client_secret),
            "c00cf151ca5be075ed0ebfb5c80323c42d6b7db67881289af4008f1f6c357aea"
        );
    }

    #[test]
    fn server_initial_secret_deterministic_snapshot() {
        let initial_secret = derive_initial_secret(&RFC9001_DCID, 0x00000001);
        let server_secret =
            derive_server_initial_secret(&initial_secret).expect("valid initial secret");
        assert_eq!(
            hex::encode(server_secret),
            "3c199828fd139efd216c155ad844cc81fb82fa8d7446fa7d78be803acdda951b"
        );
    }

    #[test]
    fn client_server_secrets_differ() {
        let initial_secret = derive_initial_secret(&RFC9001_DCID, 0x00000001);
        let client = derive_client_initial_secret(&initial_secret).expect("valid initial secret");
        let server = derive_server_initial_secret(&initial_secret).expect("valid initial secret");
        assert_ne!(client, server, "client and server secrets must differ");
    }

    #[test]
    fn different_dcid_produces_different_secret() {
        let s1 = derive_initial_secret(&[0x01, 0x02, 0x03, 0x04], 0x00000001);
        let s2 = derive_initial_secret(&[0x05, 0x06, 0x07, 0x08], 0x00000001);
        assert_ne!(s1, s2, "different DCIDs must produce different secrets");
    }

    #[test]
    fn v1_and_v2_salts_produce_different_secrets() {
        let s1 = derive_initial_secret(&RFC9001_DCID, 0x00000001);
        let s2 = derive_initial_secret(&RFC9001_DCID, 0x6b3343cf);
        assert_ne!(s1, s2, "v1 and v2 must use different salts");
    }

    #[test]
    fn unknown_version_falls_back_to_v1() {
        let v1 = derive_initial_secret(&RFC9001_DCID, 0x00000001);
        let unknown = derive_initial_secret(&RFC9001_DCID, 0xdeadbeef);
        assert_eq!(v1, unknown, "unknown version must fall back to v1 salt");
    }

    #[test]
    fn v2_uses_v2_salt() {
        // RFC 9369: version 0x6b3343cf is QUIC v2 and must use the v2 salt,
        // distinct from v1.
        let v1 = derive_initial_secret(&RFC9001_DCID, 0x00000001);
        let v2 = derive_initial_secret(&RFC9001_DCID, 0x6b3343cf);
        assert_ne!(v1, v2, "v2 (0x6b3343cf) must use the v2 salt, not v1");
    }

    #[test]
    fn v2_initial_material_matches_rfc9369_appendix_a() {
        let initial = derive_initial_secret(&RFC9001_DCID, 0x6b3343cf);
        assert_eq!(
            hex::encode(initial),
            "2062e8b3cd8d52092614b8071d0aa1fb7c2e3ac193f78b280e72d8f5751f6aba"
        );
        let client = derive_client_initial_secret(&initial).expect("valid initial secret");
        let server = derive_server_initial_secret(&initial).expect("valid initial secret");
        assert_eq!(
            hex::encode(&client),
            "14ec9d6eb9fd7af83bf5a668bc17a7e283766aade7ecd0891f70f9ff7f4bf47b"
        );
        assert_eq!(
            hex::encode(
                derive_pkt_key_for_version(&client, 16, 0x6b3343cf).expect("valid client secret"),
            ),
            "8b1a0bc121284290a29e0971b5cd045d"
        );
        assert_eq!(
            hex::encode(
                derive_pkt_iv_for_version(&client, 12, 0x6b3343cf).expect("valid client secret"),
            ),
            "91f73e2351d8fa91660e909f"
        );
        assert_eq!(
            hex::encode(
                derive_hdr_key_for_version(&client, 16, 0x6b3343cf).expect("valid client secret"),
            ),
            "45b95e15235d6f45a6b19cbcb0294ba9"
        );
        assert_eq!(
            hex::encode(&server),
            "0263db1782731bf4588e7e4d93b7463907cb8cd8200b5da55a8bd488eafc37c1"
        );
        assert_eq!(
            hex::encode(
                derive_pkt_key_for_version(&server, 16, 0x6b3343cf).expect("valid server secret"),
            ),
            "82db637861d55e1d011f19ea71d5d2a7"
        );
        assert_eq!(
            hex::encode(
                derive_pkt_iv_for_version(&server, 12, 0x6b3343cf).expect("valid server secret"),
            ),
            "dd13c276499c0249d3310652"
        );
        assert_eq!(
            hex::encode(
                derive_hdr_key_for_version(&server, 16, 0x6b3343cf).expect("valid server secret"),
            ),
            "edf6d05c83121201b436e16877593c3a"
        );
    }

    // ---------------------------------------------------------------
    // Key derivation output lengths
    // ---------------------------------------------------------------

    #[test]
    fn derive_pkt_key_length_aes128() {
        let secret = derive_initial_secret(&RFC9001_DCID, 1);
        let client_secret = derive_client_initial_secret(&secret).expect("valid initial secret");
        let key = derive_pkt_key(&client_secret, 16).expect("valid client secret");
        assert_eq!(key.len(), 16, "AES-128-GCM key must be 16 bytes");
    }

    #[test]
    fn derive_pkt_key_length_aes256() {
        let secret = [0xABu8; 32];
        let key = derive_pkt_key(&secret, 32).expect("valid secret");
        assert_eq!(key.len(), 32, "AES-256-GCM key must be 32 bytes");
    }

    #[test]
    fn derive_pkt_iv_length() {
        let secret = derive_initial_secret(&RFC9001_DCID, 1);
        let client_secret = derive_client_initial_secret(&secret).expect("valid initial secret");
        let iv = derive_pkt_iv(&client_secret, 12).expect("valid client secret");
        assert_eq!(iv.len(), 12, "AEAD nonce/IV must be 12 bytes");
    }

    #[test]
    fn derive_hdr_key_length() {
        let secret = derive_initial_secret(&RFC9001_DCID, 1);
        let client_secret = derive_client_initial_secret(&secret).expect("valid initial secret");
        let hp = derive_hdr_key(&client_secret, 16).expect("valid client secret");
        assert_eq!(hp.len(), 16, "header protection key must be 16 bytes");
    }

    // ---------------------------------------------------------------
    // RFC 9001 Appendix A.1 - Full client Initial key/iv/hp vectors
    // ---------------------------------------------------------------

    #[test]
    fn client_initial_keys_lengths_and_uniqueness() {
        // Derive full key material from client initial secret and verify
        // correct sizes and that key/iv/hp are all distinct material.
        let initial = derive_initial_secret(&RFC9001_DCID, 1);
        let client_secret = derive_client_initial_secret(&initial).expect("valid initial secret");
        let keys = derive_keys(&client_secret, 16, 12, 16).expect("valid client secret");

        assert_eq!(keys.key.len(), 16, "client key must be 16 bytes");
        assert_eq!(keys.iv.len(), 12, "client IV must be 12 bytes");
        assert_eq!(keys.hp.len(), 16, "client HP must be 16 bytes");

        // All three must be non-zero and distinct from each other
        assert_ne!(keys.key, vec![0u8; 16]);
        assert_ne!(keys.iv, vec![0u8; 12]);
        assert_ne!(keys.hp, vec![0u8; 16]);
        assert_ne!(keys.key, keys.hp, "key and hp must differ");

        // Deterministic
        let keys2 = derive_keys(&client_secret, 16, 12, 16).expect("valid client secret");
        assert_eq!(keys.key, keys2.key);
        assert_eq!(keys.iv, keys2.iv);
        assert_eq!(keys.hp, keys2.hp);
    }

    #[test]
    fn server_initial_keys_differ_from_client() {
        let initial = derive_initial_secret(&RFC9001_DCID, 1);
        let client_secret = derive_client_initial_secret(&initial).expect("valid initial secret");
        let server_secret = derive_server_initial_secret(&initial).expect("valid initial secret");

        let client_keys = derive_keys(&client_secret, 16, 12, 16).expect("valid client secret");
        let server_keys = derive_keys(&server_secret, 16, 12, 16).expect("valid server secret");

        assert_ne!(client_keys.key, server_keys.key, "client and server packet keys must differ");
        assert_ne!(client_keys.iv, server_keys.iv, "client and server IVs must differ");
        assert_ne!(client_keys.hp, server_keys.hp, "client and server HP keys must differ");
    }

    // ---------------------------------------------------------------
    // derive_keys struct consistency
    // ---------------------------------------------------------------

    #[test]
    fn derive_keys_matches_individual_calls() {
        let secret = [0x42u8; 32];
        let keys = derive_keys(&secret, 16, 12, 16).expect("valid secret");
        assert_eq!(keys.key, derive_pkt_key(&secret, 16).expect("valid secret"));
        assert_eq!(keys.iv, derive_pkt_iv(&secret, 12).expect("valid secret"));
        assert_eq!(keys.hp, derive_hdr_key(&secret, 16).expect("valid secret"));
    }

    // ---------------------------------------------------------------
    // Key update (derive_next_secret)
    // ---------------------------------------------------------------

    #[test]
    fn derive_next_secret_changes_value() {
        let initial = derive_initial_secret(&RFC9001_DCID, 1);
        let client = derive_client_initial_secret(&initial).expect("valid initial secret");
        let next = derive_next_secret(&client).expect("valid client secret");
        assert_ne!(next.as_slice(), client.as_slice(), "key update must produce different secret");
        assert_eq!(next.len(), 32, "next secret must be 32 bytes");
    }

    #[test]
    fn derive_next_secret_deterministic() {
        let secret = [0xBBu8; 32];
        let n1 = derive_next_secret(&secret).expect("valid secret");
        let n2 = derive_next_secret(&secret).expect("valid secret");
        assert_eq!(n1, n2, "same input must yield same next secret");
    }

    #[test]
    fn key_update_chain_produces_unique_secrets() {
        let initial = derive_initial_secret(&RFC9001_DCID, 1);
        let client = derive_client_initial_secret(&initial).expect("valid initial secret");
        let mut current = client.clone();
        let mut seen = std::collections::HashSet::new();
        seen.insert(current.clone());
        for _ in 0..10 {
            current = derive_next_secret(&current).expect("valid key update secret");
            assert!(
                seen.insert(current.clone()),
                "key update chain must produce unique secrets at each step"
            );
        }
    }

    // ---------------------------------------------------------------
    // Edge cases
    // ---------------------------------------------------------------

    #[test]
    fn empty_dcid_produces_valid_secret() {
        let s = derive_initial_secret(&[], 1);
        assert_ne!(s, [0u8; 32], "empty DCID must still produce non-zero secret");
    }

    #[test]
    fn invalid_secret_lengths_are_rejected() {
        fn assert_invalid_secret<T>(result: Result<T, KeyMaterialError>, actual: usize) {
            let error = match result {
                Ok(_) => panic!("invalid traffic secret length was accepted"),
                Err(error) => error,
            };
            assert_eq!(
                error,
                KeyMaterialError::Length {
                    algorithm: "QUIC KDF",
                    material: "traffic secret",
                    expected: 32,
                    actual,
                    minimum: false,
                }
            );
        }

        for actual in [0, 4, 31, 33] {
            let secret = vec![0xAA; actual];
            assert_invalid_secret(derive_client_initial_secret(&secret), actual);
            assert_invalid_secret(derive_server_initial_secret(&secret), actual);
            assert_invalid_secret(derive_pkt_key(&secret, 16), actual);
            assert_invalid_secret(derive_pkt_key_for_version(&secret, 16, 0x00000001), actual);
            assert_invalid_secret(derive_pkt_iv(&secret, 12), actual);
            assert_invalid_secret(derive_pkt_iv_for_version(&secret, 12, 0x00000001), actual);
            assert_invalid_secret(derive_hdr_key(&secret, 16), actual);
            assert_invalid_secret(derive_hdr_key_for_version(&secret, 16, 0x00000001), actual);
            assert_invalid_secret(derive_next_secret(&secret), actual);
            assert_invalid_secret(derive_next_secret_for_version(&secret, 0x00000001), actual);
            assert_invalid_secret(derive_keys(&secret, 16, 12, 16), actual);
        }
    }

    #[test]
    fn exact_32_byte_secret() {
        let exact = [0xFFu8; 32];
        let key = derive_pkt_key(&exact, 16).expect("valid exact secret");
        assert_eq!(key.len(), 16);
        // Ensure it takes the fast path (exact copy) and produces valid output
        let key2 = derive_pkt_key(&exact, 16).expect("valid exact secret");
        assert_eq!(key, key2, "exact-32-byte path must be deterministic");
    }

    #[test]
    fn hkdf_expand_label_binds_output_length() {
        // TLS 1.3 encodes the requested output length in HkdfLabel, so the
        // 16-byte and 32-byte derivations intentionally use different info.
        let secret = [0xCCu8; 32];
        let key16 = derive_pkt_key(&secret, 16).expect("valid secret");
        let key32 = derive_pkt_key(&secret, 32).expect("valid secret");
        assert_ne!(&key32[..16], key16.as_slice());
        assert_ne!(&key32[16..], &[0u8; 16], "extended key material must not be all zeros");
    }

    #[test]
    fn key_iv_hp_are_all_different() {
        let secret = [0x11u8; 32];
        let key = derive_pkt_key(&secret, 16).expect("valid secret");
        let iv = derive_pkt_iv(&secret, 16).expect("valid secret"); // same length for comparison
        let hp = derive_hdr_key(&secret, 16).expect("valid secret");
        assert_ne!(key, iv, "key and iv labels differ - output must differ");
        assert_ne!(key, hp, "key and hp labels differ - output must differ");
        assert_ne!(iv, hp, "iv and hp labels differ - output must differ");
    }

    #[test]
    fn salt_constants_are_correct_length() {
        assert_eq!(INITIAL_SALT_V1.len(), 20, "v1 salt must be 20 bytes (SHA-1 output size)");
        assert_eq!(INITIAL_SALT_V2.len(), 20, "v2 salt must be 20 bytes");
        assert_ne!(INITIAL_SALT_V1, INITIAL_SALT_V2, "v1 and v2 salts must differ");
    }
}
