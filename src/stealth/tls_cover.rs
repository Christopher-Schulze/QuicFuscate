/// Minimal TLS Cover builder used to craft synthetic TLS records for DPI evasion.
///
/// The `TlsCover` utilities generate compact ClientHello/ServerHello records and
/// optional certificate frames which resemble a TLS handshake without establishing
/// a real session. This is used when `StealthConfig::use_tls_cover` is enabled to
/// decouple QUIC transport from observable TLS handshakes.
/// Owned variant of [`ServerHelloParams`] for storing in fingerprint profiles.
#[derive(Debug, Clone)]
pub struct ServerHelloParamsOwned {
    /// TLS protocol version (e.g. `0x0303` for TLS 1.2 compat).
    pub tls_version: u16,
    /// Negotiated cipher suite IANA identifier.
    pub cipher_suite: u16,
    /// Raw extension bytes for the ServerHello record.
    pub extensions: Vec<u8>,
}

/// Parameters used to craft a minimal ClientHello message.
#[derive(Clone, Copy)]
pub(super) struct ClientHelloParams<'a> {
    /// TLS protocol version (e.g. `0x0303` for TLS 1.2).
    pub tls_version: u16,
    /// List of cipher suites encoded as IANA identifiers.
    pub cipher_suites: &'a [u16],
    /// Raw extension block to append after the compression method.
    pub extensions: &'a [u8],
}

/// Helper functions for TLS extension building
pub(super) fn u16be(v: u16) -> [u8; 2] {
    v.to_be_bytes()
}

pub(super) fn grease_value(idx: usize) -> u16 {
    let base: u16 = 0x0a0a;
    let step: u16 = 0x1010;
    base.wrapping_add(step.wrapping_mul(idx as u16))
}

pub(super) fn grease_ext(seed: u16) -> Vec<u8> {
    let idx = (seed & 0x000f) as usize;
    let t = grease_value(idx);
    let mut ext = Vec::with_capacity(4);
    ext.extend_from_slice(&t.to_be_bytes());
    ext.extend_from_slice(&0u16.to_be_bytes());
    ext
}

/// Returns true for cipher suites excluded from the real TLS ClientHello policy.
/// TLS Cover record encryption remains separately configurable.
pub(super) fn is_client_hello_cipher_removed(cipher_suite: u16) -> bool {
    matches!(cipher_suite, 0x1303 | 0xCCA8 | 0xCCA9)
}

pub(super) fn alpn_ext(protocols: &[&str]) -> Vec<u8> {
    let mut names = Vec::new();
    for p in protocols {
        names.push(p.len() as u8);
        names.extend_from_slice(p.as_bytes());
    }
    let mut ext = Vec::with_capacity(4 + 2 + names.len());
    ext.extend_from_slice(&0x0010u16.to_be_bytes());
    let list_len = names.len() as u16;
    ext.extend_from_slice(&(list_len + 2).to_be_bytes());
    ext.extend_from_slice(&list_len.to_be_bytes());
    ext.extend_from_slice(&names);
    ext
}

pub(super) fn supported_versions_ext(versions: &[u16]) -> Vec<u8> {
    let mut body = Vec::with_capacity(1 + 2 * versions.len());
    body.push((versions.len() * 2) as u8);
    for v in versions {
        body.extend_from_slice(&u16be(*v));
    }
    let mut ext = Vec::with_capacity(4 + body.len());
    ext.extend_from_slice(&0x002Bu16.to_be_bytes());
    ext.extend_from_slice(&(body.len() as u16).to_be_bytes());
    ext.extend_from_slice(&body);
    ext
}

pub(super) fn signature_algorithms_ext(schemes: &[u16]) -> Vec<u8> {
    let mut body = Vec::with_capacity(2 + 2 * schemes.len());
    body.extend_from_slice(&u16be((schemes.len() * 2) as u16));
    for s in schemes {
        body.extend_from_slice(&u16be(*s));
    }
    let mut ext = Vec::with_capacity(4 + body.len());
    ext.extend_from_slice(&0x000Du16.to_be_bytes());
    ext.extend_from_slice(&(body.len() as u16).to_be_bytes());
    ext.extend_from_slice(&body);
    ext
}

pub(super) fn signature_algorithms_cert_ext(schemes: &[u16]) -> Vec<u8> {
    let mut body = Vec::with_capacity(2 + 2 * schemes.len());
    body.extend_from_slice(&u16be((schemes.len() * 2) as u16));
    for s in schemes {
        body.extend_from_slice(&u16be(*s));
    }
    let mut ext = Vec::with_capacity(4 + body.len());
    ext.extend_from_slice(&0x0032u16.to_be_bytes());
    ext.extend_from_slice(&(body.len() as u16).to_be_bytes());
    ext.extend_from_slice(&body);
    ext
}

pub(super) fn supported_groups_ext(groups: &[u16]) -> Vec<u8> {
    let mut body = Vec::with_capacity(2 + 2 * groups.len());
    body.extend_from_slice(&u16be((groups.len() * 2) as u16));
    for g in groups {
        body.extend_from_slice(&u16be(*g));
    }
    let mut ext = Vec::with_capacity(4 + body.len());
    ext.extend_from_slice(&0x000Au16.to_be_bytes());
    ext.extend_from_slice(&(body.len() as u16).to_be_bytes());
    ext.extend_from_slice(&body);
    ext
}

pub(super) fn psk_key_exchange_modes_ext(modes: &[u8]) -> Vec<u8> {
    let mut body = Vec::with_capacity(1 + modes.len());
    body.push(modes.len() as u8);
    body.extend_from_slice(modes);
    let mut ext = Vec::with_capacity(4 + body.len());
    ext.extend_from_slice(&0x002Du16.to_be_bytes());
    ext.extend_from_slice(&(body.len() as u16).to_be_bytes());
    ext.extend_from_slice(&body);
    ext
}

pub(super) fn key_share_ext(group: u16, seed: u64) -> Vec<u8> {
    let kx_len = 32usize;
    let mut kx = vec![0u8; kx_len];
    let mut x = seed ^ 0x9E3779B97F4A7C15u64;
    for b in &mut kx {
        x ^= x << 7;
        x ^= x >> 9;
        x ^= x << 8;
        *b = (x & 0xFF) as u8;
    }
    let mut entry = Vec::with_capacity(4 + kx_len);
    entry.extend_from_slice(&u16be(group));
    entry.extend_from_slice(&u16be(kx_len as u16));
    entry.extend_from_slice(&kx);
    let mut body = Vec::with_capacity(2 + entry.len());
    body.extend_from_slice(&u16be(entry.len() as u16));
    body.extend_from_slice(&entry);
    let mut ext = Vec::with_capacity(4 + body.len());
    ext.extend_from_slice(&0x0033u16.to_be_bytes());
    ext.extend_from_slice(&(body.len() as u16).to_be_bytes());
    ext.extend_from_slice(&body);
    ext
}

/// TLS 1.3 padding extension (type 0x0015). Fills with zeros.
pub(super) fn padding_ext(pad_len: usize) -> Vec<u8> {
    let pad_len = pad_len.min(256);
    let mut ext = Vec::with_capacity(4 + pad_len);
    ext.extend_from_slice(&0x0015u16.to_be_bytes());
    ext.extend_from_slice(&(pad_len as u16).to_be_bytes());
    if pad_len > 0 {
        let zeros = vec![0u8; pad_len];
        ext.extend_from_slice(&zeros);
    }
    ext
}

/// ECH GREASE (draft) extension: 0xFE0D with random payload (TLS Cover only)
pub(super) fn ech_grease_ext(seed: u16) -> Vec<u8> {
    let mut x = (seed as u64) ^ 0xD15E_A5E5_F00D_F00D_u64;
    // Pseudo-random length in 8..40
    x ^= x.rotate_left(13);
    let len = 8 + (x as usize & 0x1F);
    let mut body = vec![0u8; len];
    for b in &mut body {
        x ^= x << 7;
        x ^= x >> 9;
        x ^= x << 8;
        *b = (x & 0xFF) as u8;
    }
    let mut ext = Vec::with_capacity(4 + len);
    ext.extend_from_slice(&0xFE0Du16.to_be_bytes());
    ext.extend_from_slice(&(len as u16).to_be_bytes());
    ext.extend_from_slice(&body);
    ext
}

pub(super) fn sni_ext(host: &str) -> Vec<u8> {
    let name_bytes = host.as_bytes();
    let mut name = Vec::with_capacity(3 + name_bytes.len());
    name.push(0u8);
    name.extend_from_slice(&(name_bytes.len() as u16).to_be_bytes());
    name.extend_from_slice(name_bytes);
    let mut body = Vec::with_capacity(2 + name.len());
    body.extend_from_slice(&(name.len() as u16).to_be_bytes());
    body.extend_from_slice(&name);
    let mut ext = Vec::with_capacity(4 + body.len());
    ext.extend_from_slice(&0x0000u16.to_be_bytes());
    ext.extend_from_slice(&(body.len() as u16).to_be_bytes());
    ext.extend_from_slice(&body);
    ext
}

/// Entry point for constructing synthetic TLS records (TLS Cover).
/// Provides helpers to emit ClientHello/ServerHello and certificate frames
/// for DPI evasion without establishing a real TLS session.
pub struct TlsCover;

impl TlsCover {
    /// Generate sophisticated ClientHello with browser-specific extensions
    pub fn generate_client_hello(
        browser: super::BrowserProfile,
        os: super::OsProfile,
        sni: Option<&str>,
    ) -> Vec<u8> {
        let seed = (browser as u16) ^ ((os as u16) << 8);
        let enable_grease = !matches!(browser, super::BrowserProfile::Safari);

        // Browser-specific cipher suites
        let mut ciphers = match browser {
            super::BrowserProfile::Firefox => vec![
                0x1301, 0x1303, 0x1302, 0xC02B, 0xC02F, 0xCCA9, 0xCCA8, 0xC02C, 0xC030, 0xC013,
                0xC014,
            ],
            _ => vec![
                0x1301, 0x1302, 0x1303, 0xC02B, 0xC02F, 0xC02C, 0xC030, 0xCCA9, 0xCCA8, 0xC013,
                0xC014,
            ],
        };

        // The real TLS policy removes ChaCha from every deterministic ClientHello.
        // Synthetic TLS Cover record encryption is a separate, explicit choice.
        ciphers.retain(|cipher_suite| !is_client_hello_cipher_removed(*cipher_suite));

        // Add GREASE cipher if enabled
        if enable_grease {
            let grease = grease_value(seed as usize);
            if !ciphers.contains(&grease) {
                ciphers.insert(0, grease);
            }
        }

        // Build extensions in browser-specific order
        let mut exts = Vec::with_capacity(512);
        let ext_order = match browser {
            super::BrowserProfile::Chrome | super::BrowserProfile::Edge => &[
                "grease",
                "sni",
                "supported_versions",
                "key_share",
                "psk_modes",
                "signature_algorithms",
                "signature_algorithms_cert",
                "supported_groups",
                "alpn",
            ][..],
            super::BrowserProfile::Firefox => &[
                "grease",
                "sni",
                "signature_algorithms",
                "signature_algorithms_cert",
                "supported_groups",
                "key_share",
                "supported_versions",
                "psk_modes",
                "alpn",
            ][..],
            super::BrowserProfile::Safari => &[
                "sni",
                "supported_versions",
                "signature_algorithms",
                "signature_algorithms_cert",
                "supported_groups",
                "key_share",
                "alpn",
            ][..],
        };

        // OS-specific ALPN
        let alpns = match (browser, os) {
            (super::BrowserProfile::Safari, super::OsProfile::IOS) => vec!["h3", "http/1.1"],
            _ => vec!["h3", "h2", "http/1.1"],
        };

        let seed_for_key =
            ((browser as u64) * 0x9E37 + (os as u64) * 0xC2B2) ^ 0xA5A5_5A5A_F0F0_0F0F;

        for name in ext_order {
            match *name {
                "grease" => {
                    if enable_grease {
                        exts.extend_from_slice(&grease_ext(seed));
                    }
                }
                "sni" => {
                    if let Some(host) = sni {
                        exts.extend_from_slice(&sni_ext(host));
                    }
                }
                "alpn" => exts.extend_from_slice(&alpn_ext(&alpns)),
                "supported_versions" => {
                    let mut versions = vec![0x0304u16, 0x0303u16];
                    if enable_grease {
                        let gv = grease_value(seed as usize);
                        if !versions.contains(&gv) {
                            versions.insert(0, gv);
                        }
                    }
                    exts.extend_from_slice(&supported_versions_ext(&versions));
                }
                "signature_algorithms" => {
                    let sigs = [0x0403u16, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501];
                    exts.extend_from_slice(&signature_algorithms_ext(&sigs));
                }
                "signature_algorithms_cert" => {
                    let sigs = [0x0403u16, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501];
                    exts.extend_from_slice(&signature_algorithms_cert_ext(&sigs));
                }
                "supported_groups" => {
                    let mut groups = vec![0x001D, 0x0017, 0x0018];
                    if enable_grease {
                        let g = grease_value(seed as usize);
                        if !groups.contains(&g) {
                            groups.insert(0, g);
                        }
                    }
                    exts.extend_from_slice(&supported_groups_ext(&groups));
                }
                "psk_modes" => exts.extend_from_slice(&psk_key_exchange_modes_ext(&[0x01])),
                "key_share" => exts.extend_from_slice(&key_share_ext(0x001D, seed_for_key)),
                _ => {}
            }
        }

        // Optional ULTRA extras: ECH-GREASE + padding to smooth lengths
        let ultra = super::TlsCoverProvider::ultra_enabled();
        if ultra {
            exts.extend_from_slice(&ech_grease_ext(seed));
            // Pad to pseudo-random target within a narrow band
            let tgt = 16 + ((seed as usize) & 0x1F); // 16..47
            exts.extend_from_slice(&padding_ext(tgt));
        }

        // Session ID behavior: Chrome/Edge/Safari often include 32B; Firefox empty
        match browser {
            super::BrowserProfile::Firefox => Self::client_hello_custom_with_sid(
                ClientHelloParams {
                    tls_version: 0x0303,
                    cipher_suites: &ciphers,
                    extensions: &exts,
                },
                None,
            ),
            _ => {
                let mut buf = [0u8; 32];
                // Derive pseudo-random SID from seed and optional SNI to keep determinism
                let mut x = (seed as u64) ^ 0xC3_1D_00_5D_A5_5Au64 ^ (seed_for_key.rotate_left(17));
                for b in &mut buf {
                    x ^= x << 7;
                    x ^= x >> 9;
                    x ^= x << 8;
                    *b = (x & 0xFF) as u8;
                }
                Self::client_hello_custom_with_sid(
                    ClientHelloParams {
                        tls_version: 0x0303,
                        cipher_suites: &ciphers,
                        extensions: &exts,
                    },
                    Some(&buf[..]),
                )
            }
        }
    }

    /// Helper to build a TLS handshake record for the given handshake type and
    /// payload.
    fn record(htype: u8, payload: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(payload.len() + 9);
        out.extend_from_slice(&[0x16, 0x03, 0x03]); // Handshake record, TLS 1.2
        let len = payload.len() + 4;
        out.extend_from_slice(&(len as u16).to_be_bytes());
        out.push(htype);
        let l = (payload.len() as u32).to_be_bytes();
        out.extend_from_slice(&l[1..]);
        out.extend_from_slice(payload);
        out
    }

    /// Builds a minimal ClientHello record using the provided parameters.
    pub(super) fn client_hello_custom(params: ClientHelloParams) -> Vec<u8> {
        Self::client_hello_custom_with_sid(params, None)
    }

    /// Builds a ClientHello with optional Session ID (for fingerprint parity per browser).
    pub(super) fn client_hello_custom_with_sid(
        params: ClientHelloParams,
        session_id: Option<&[u8]>,
    ) -> Vec<u8> {
        let mut payload = Vec::new();
        payload.extend_from_slice(&params.tls_version.to_be_bytes());
        payload.extend_from_slice(&[0u8; 32]); // random
        match session_id {
            Some(sid) => {
                payload.push(sid.len() as u8);
                payload.extend_from_slice(sid);
            }
            None => {
                payload.push(0);
            }
        }
        payload.extend_from_slice(&((params.cipher_suites.len() * 2) as u16).to_be_bytes());
        for cs in params.cipher_suites {
            payload.extend_from_slice(&cs.to_be_bytes());
        }
        payload.push(1); // compression methods len
        payload.push(0); // null compression
        payload.extend_from_slice(&(params.extensions.len() as u16).to_be_bytes());
        payload.extend_from_slice(params.extensions);
        Self::record(0x01, &payload)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_u16be_encoding() {
        assert_eq!(u16be(0x0303), [0x03, 0x03]);
        assert_eq!(u16be(0x1301), [0x13, 0x01]);
        assert_eq!(u16be(0x0000), [0x00, 0x00]);
        assert_eq!(u16be(0xFFFF), [0xFF, 0xFF]);
    }

    #[test]
    fn test_grease_value_pattern() {
        // GREASE values follow the pattern 0x?A?A where nibbles match
        for idx in 0..16 {
            let v = grease_value(idx);
            let hi = (v >> 8) as u8;
            let lo = (v & 0xFF) as u8;
            // Both bytes should have the same low nibble 0xA
            assert_eq!(
                hi & 0x0F,
                0x0A,
                "GREASE high byte low nibble should be 0xA for idx={}",
                idx
            );
            assert_eq!(lo & 0x0F, 0x0A, "GREASE low byte low nibble should be 0xA for idx={}", idx);
            // High nibbles match each other
            assert_eq!(hi >> 4, lo >> 4, "GREASE nibble pattern mismatch for idx={}", idx);
        }
    }

    #[test]
    fn test_grease_ext_structure() {
        let ext = grease_ext(0x1234);
        // GREASE extension: 2 bytes type + 2 bytes length (0)
        assert_eq!(ext.len(), 4);
        // Last 2 bytes are length = 0
        assert_eq!(&ext[2..4], &[0x00, 0x00]);
    }

    #[test]
    fn test_sni_ext_structure() {
        let ext = sni_ext("example.com");
        // Extension type 0x0000 (SNI)
        assert_eq!(ext[0], 0x00);
        assert_eq!(ext[1], 0x00);
        // Verify the hostname appears in the extension
        let host_bytes = b"example.com";
        let found = ext.windows(host_bytes.len()).any(|w| w == host_bytes);
        assert!(found, "hostname bytes should appear in SNI extension");
    }

    #[test]
    fn test_alpn_ext_contains_protocols() {
        let ext = alpn_ext(&["h3", "h2", "http/1.1"]);
        // Extension type 0x0010 (ALPN)
        assert_eq!(ext[0], 0x00);
        assert_eq!(ext[1], 0x10);
        // Verify each protocol name appears in the extension
        for proto in &["h3", "h2", "http/1.1"] {
            let proto_bytes = proto.as_bytes();
            let found = ext.windows(proto_bytes.len()).any(|w| w == proto_bytes);
            assert!(found, "protocol '{}' should appear in ALPN extension", proto);
        }
    }

    #[test]
    fn test_supported_versions_ext_contains_values() {
        let ext = supported_versions_ext(&[0x0304, 0x0303]);
        // Extension type 0x002B
        assert_eq!(ext[0], 0x00);
        assert_eq!(ext[1], 0x2B);
        // TLS 1.3 (0x0304) and TLS 1.2 (0x0303) should appear
        assert!(ext.windows(2).any(|w| w == [0x03, 0x04]));
        assert!(ext.windows(2).any(|w| w == [0x03, 0x03]));
    }

    #[test]
    fn test_padding_ext_correct_size() {
        let ext = padding_ext(32);
        // Type 0x0015 + 2 bytes length + 32 bytes padding = 36
        assert_eq!(ext.len(), 4 + 32);
        assert_eq!(ext[0], 0x00);
        assert_eq!(ext[1], 0x15);
        // Length field
        let len = u16::from_be_bytes([ext[2], ext[3]]);
        assert_eq!(len, 32);
        // All padding bytes should be zero
        assert!(ext[4..].iter().all(|&b| b == 0));
    }

    #[test]
    fn test_padding_ext_capped_at_256() {
        let ext = padding_ext(1000);
        // Should be capped at 256
        let len = u16::from_be_bytes([ext[2], ext[3]]);
        assert_eq!(len, 256);
        assert_eq!(ext.len(), 4 + 256);
    }

    #[test]
    fn test_padding_ext_zero_length() {
        let ext = padding_ext(0);
        // Type + length header only, no padding bytes
        assert_eq!(ext.len(), 4);
        let len = u16::from_be_bytes([ext[2], ext[3]]);
        assert_eq!(len, 0);
    }

    #[test]
    fn test_client_hello_record_format() {
        let params = ClientHelloParams {
            tls_version: 0x0303,
            cipher_suites: &[0x1301, 0x1302],
            extensions: &[],
        };
        let record = TlsCover::client_hello_custom(params);
        // TLS record header: content_type=0x16 (handshake), version=0x0303
        assert_eq!(record[0], 0x16);
        assert_eq!(record[1], 0x03);
        assert_eq!(record[2], 0x03);
        // Handshake type at offset 5 = 0x01 (ClientHello)
        assert_eq!(record[5], 0x01);
        // Record length (2 bytes at [3..5]) should match remaining data
        let record_len = u16::from_be_bytes([record[3], record[4]]) as usize;
        assert_eq!(record_len, record.len() - 5);
    }

    #[test]
    fn test_client_hello_with_session_id() {
        let params =
            ClientHelloParams { tls_version: 0x0303, cipher_suites: &[0x1301], extensions: &[] };
        let sid = [0xAA; 32];
        let with_sid = TlsCover::client_hello_custom_with_sid(params, Some(&sid));
        let without_sid = TlsCover::client_hello_custom(ClientHelloParams {
            tls_version: 0x0303,
            cipher_suites: &[0x1301],
            extensions: &[],
        });
        // Record with session ID should be longer (32 bytes for SID)
        assert!(with_sid.len() > without_sid.len());
        assert_eq!(with_sid.len() - without_sid.len(), 32);
    }

    #[test]
    fn test_generate_client_hello_chrome_valid_tls_record() {
        let record = TlsCover::generate_client_hello(
            super::super::BrowserProfile::Chrome,
            super::super::OsProfile::Windows,
            Some("example.com"),
        );
        // Must be a valid TLS handshake record
        assert_eq!(record[0], 0x16, "content type should be Handshake");
        assert_eq!(record[5], 0x01, "handshake type should be ClientHello");
        // Should contain SNI
        assert!(
            record.windows(b"example.com".len()).any(|w| w == b"example.com"),
            "record should contain SNI hostname"
        );
    }

    #[test]
    fn test_generate_client_hello_firefox_no_session_id() {
        let record = TlsCover::generate_client_hello(
            super::super::BrowserProfile::Firefox,
            super::super::OsProfile::Linux,
            None,
        );
        // Valid TLS record
        assert_eq!(record[0], 0x16);
        assert_eq!(record[5], 0x01);
        // Firefox: session_id_length should be 0 (at offset 9+32 = byte after 32-byte random)
        // Offset: [0..5] record header, [5] handshake type, [6..9] length, [9..11] version, [11..43] random, [43] sid_len
        assert_eq!(record[43], 0, "Firefox should have empty session ID");
    }

    #[test]
    fn test_generate_client_hello_safari_no_grease() {
        let record = TlsCover::generate_client_hello(
            super::super::BrowserProfile::Safari,
            super::super::OsProfile::MacOS,
            Some("apple.com"),
        );
        // Safari does not use GREASE - first cipher suite after sid should NOT be a GREASE value
        assert_eq!(record[0], 0x16);
        // Session ID for Safari: 32 bytes
        // offset 43 = sid_len (32 for non-Firefox), skip 32 bytes, then cipher suites length
        let sid_len = record[43] as usize;
        assert_eq!(sid_len, 32, "Safari should have 32-byte session ID");
        let cs_offset = 44 + sid_len;
        let cs_len = u16::from_be_bytes([record[cs_offset], record[cs_offset + 1]]) as usize;
        assert!(cs_len > 0, "cipher suites should not be empty");
        // First cipher suite should NOT be a GREASE value (GREASE has pattern 0x?A?A)
        let first_cs = u16::from_be_bytes([record[cs_offset + 2], record[cs_offset + 3]]);
        let is_grease =
            (first_cs & 0x0F0F) == 0x0A0A && ((first_cs >> 4) & 0x0F) == ((first_cs >> 12) & 0x0F);
        assert!(
            !is_grease,
            "Safari should not have GREASE cipher suite first, got 0x{:04X}",
            first_cs
        );
    }

    #[test]
    fn test_ech_grease_ext_deterministic() {
        let ext1 = ech_grease_ext(42);
        let ext2 = ech_grease_ext(42);
        assert_eq!(ext1, ext2, "same seed should produce same ECH GREASE");
        // Extension type 0xFE0D
        assert_eq!(ext1[0], 0xFE);
        assert_eq!(ext1[1], 0x0D);
        // Body length in 8..40 range
        let body_len = u16::from_be_bytes([ext1[2], ext1[3]]) as usize;
        assert!(
            (8..=40).contains(&body_len),
            "ECH GREASE body length {} out of expected range",
            body_len
        );
        assert_eq!(ext1.len(), 4 + body_len);
    }

    #[test]
    fn test_key_share_ext_deterministic_and_valid() {
        let ext = key_share_ext(0x001D, 12345);
        // Extension type 0x0033
        assert_eq!(ext[0], 0x00);
        assert_eq!(ext[1], 0x33);
        // Deterministic: same seed produces same output
        let ext2 = key_share_ext(0x001D, 12345);
        assert_eq!(ext, ext2);
        // Different seed produces different key material
        let ext3 = key_share_ext(0x001D, 99999);
        assert_ne!(ext, ext3);
    }
}
