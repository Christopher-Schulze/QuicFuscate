//! Minimal TLS Cover builder used to craft synthetic TLS records for DPI evasion.
//!
//! The `TlsCover` utilities generate compact ClientHello/ServerHello records and
//! optional certificate frames which resemble a TLS handshake without establishing
//! a real session. This is used when `StealthConfig::use_tls_cover` is enabled to
//! decouple QUIC transport from observable TLS handshakes.

use zeroize::Zeroize;

const TLS_COVER_HKDF_SALT: &[u8] = b"quicfuscate:tls-cover:salt:v2";
const TLS_COVER_KEY_LEN: usize = 32;
const TLS_COVER_IV_LEN: usize = 12;
const TLS_COVER_MATERIAL_LEN: usize = TLS_COVER_KEY_LEN + TLS_COVER_IV_LEN;

/// Derive fresh connection-local TLS Cover key and IV material from OS entropy.
#[doc(hidden)]
pub fn derive_tls_cover_material(
    profile: &str,
    is_server: bool,
) -> std::io::Result<([u8; TLS_COVER_KEY_LEN], [u8; TLS_COVER_IV_LEN])> {
    let mut entropy = [0u8; TLS_COVER_KEY_LEN];
    qf_common::rng::fill_secure(&mut entropy)?;
    let material = derive_tls_cover_material_from_entropy(profile, is_server, &entropy);
    entropy.zeroize();
    material
}

/// Deterministically derive TLS Cover material from explicit entropy.
#[doc(hidden)]
pub fn derive_tls_cover_material_from_entropy(
    profile: &str,
    is_server: bool,
    entropy: &[u8; TLS_COVER_KEY_LEN],
) -> std::io::Result<([u8; TLS_COVER_KEY_LEN], [u8; TLS_COVER_IV_LEN])> {
    let mut prk = qf_crypto::hkdf::hkdf_extract(TLS_COVER_HKDF_SALT, entropy);
    let info = format!(
        "quicfuscate:tls-cover:{}:{}",
        profile,
        if is_server { "server" } else { "client" }
    );
    let expanded = qf_crypto::hkdf::hkdf_expand(&prk, info.as_bytes(), TLS_COVER_MATERIAL_LEN);
    prk.zeroize();
    let mut output = expanded.map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "TLS Cover HKDF-Expand rejected a legal length",
        )
    })?;
    let mut key = [0u8; TLS_COVER_KEY_LEN];
    let mut iv = [0u8; TLS_COVER_IV_LEN];
    key.copy_from_slice(&output[..TLS_COVER_KEY_LEN]);
    iv.copy_from_slice(&output[TLS_COVER_KEY_LEN..]);
    prk.zeroize();
    output.zeroize();
    Ok((key, iv))
}

/// Plaintext and timing plan for one synthetic encrypted TLS Cover record.
#[doc(hidden)]
pub struct TlsCoverRecordPlan {
    /// TLS record header authenticated by the root encryption context.
    pub header: [u8; 5],
    /// Synthetic handshake plaintext encrypted by the root context.
    pub payload: Vec<u8>,
    /// Optional synchronous delay applied after encryption on the dedicated cover path.
    pub jitter: Option<std::time::Duration>,
}

/// Bounded planning failure before any encryption or sequence mutation occurs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[doc(hidden)]
pub enum TlsCoverRecordPlanError {
    /// A checked record-length calculation exceeded the platform integer range.
    LengthOverflow,
}

/// Plan one synthetic TLS Cover record without accessing root crypto state.
#[doc(hidden)]
pub fn plan_tls_cover_record(
    max_len: usize,
    performance_mode: bool,
    is_server: bool,
    fingerprint_profile: &str,
    environment: &qf_common::env_utils::EnvSnapshot,
) -> Result<Option<TlsCoverRecordPlan>, TlsCoverRecordPlanError> {
    use rand::Rng;

    const TLS_RECORD_HEADER_LEN: usize = 5;
    const AEAD_TAG_LEN: usize = 16;
    let record_overhead = TLS_RECORD_HEADER_LEN + AEAD_TAG_LEN;
    if max_len < record_overhead {
        return Ok(None);
    }

    let payload_capacity = max_len - record_overhead;
    let max_payload = payload_capacity.min(u16::MAX as usize - AEAD_TAG_LEN);
    let mut rng = rand::rng();
    let mut payload_size = if performance_mode {
        max_payload.min(if is_server { 800 } else { 1200 })
    } else {
        let upper = max_payload.min(if is_server { 700 } else { 800 });
        let lower = max_payload.min(if is_server { 150 } else { 200 });
        let base_size = if max_payload > 1000 {
            rng.random_range(lower..=upper)
        } else if lower == upper {
            lower
        } else {
            rng.random_range(lower..=upper)
        };
        base_size
            .checked_add(rng.random_range(0..50))
            .ok_or(TlsCoverRecordPlanError::LengthOverflow)?
            .min(max_payload)
    };

    if !performance_mode {
        let padding_cap = environment
            .parse_first(["QUICFUSCATE_STEALTH_PADDING_MAX", "QUICFUSCATE_STEALTH_MAX_PADDING"])
            .unwrap_or(0usize);
        let headroom = max_payload.saturating_sub(payload_size);
        if padding_cap > 0 && headroom > 0 {
            payload_size = payload_size
                .checked_add(rng.random_range(0..=padding_cap.min(headroom)))
                .ok_or(TlsCoverRecordPlanError::LengthOverflow)?;
        }
    }

    let cipher_len =
        payload_size.checked_add(AEAD_TAG_LEN).ok_or(TlsCoverRecordPlanError::LengthOverflow)?;
    let cipher_len =
        u16::try_from(cipher_len).map_err(|_| TlsCoverRecordPlanError::LengthOverflow)?;
    let cipher_len_bytes = cipher_len.to_be_bytes();
    let header = [0x16, 0x03, 0x03, cipher_len_bytes[0], cipher_len_bytes[1]];

    let mut payload = vec![0u8; payload_size];
    rng.fill(&mut payload[..]);
    if payload_size > 10 {
        payload[0] = 0x01;
        payload[1..4].copy_from_slice(&((payload_size - 4) as u32).to_be_bytes()[1..]);
        payload[4..6].copy_from_slice(&[0x03, 0x03]);
        let profile_tag = match fingerprint_profile {
            "chrome" => 0xC0,
            "firefox" => 0xF0,
            "safari" => 0xA0,
            "edge" => 0xE0,
            _ => 0x90,
        };
        let tag_index = 6.min(payload.len() - 1);
        payload[tag_index] ^= profile_tag;
    }

    let jitter = if performance_mode {
        None
    } else {
        environment
            .parse_first::<u64, 1>(["QUICFUSCATE_STEALTH_JITTER_US"])
            .filter(|maximum| *maximum > 0)
            .map(|maximum| std::time::Duration::from_micros(rng.random_range(1..=maximum)))
    };

    Ok(Some(TlsCoverRecordPlan { header, payload, jitter }))
}

/// Cipher suite used by the TLS Cover provider for encrypting synthetic records.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[doc(hidden)]
pub enum TlsCoverCipherSuite {
    /// ChaCha20-Poly1305 (preferred on platforms without hardware AES).
    ChaCha20Poly1305,
    /// AES-128-GCM (preferred when hardware AES acceleration is available).
    Aes128Gcm,
}

impl TlsCoverCipherSuite {
    /// Returns the stable operator-facing name used by TLS Cover diagnostics.
    #[doc(hidden)]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ChaCha20Poly1305 => "chacha20-poly1305",
            Self::Aes128Gcm => "aes-128-gcm",
        }
    }

    /// Returns the TLS wire-format cipher suite ID (for ServerHello).
    #[doc(hidden)]
    pub fn tls_id(self) -> u16 {
        match self {
            Self::ChaCha20Poly1305 => 0x1303,
            Self::Aes128Gcm => 0x1301,
        }
    }
}

/// Owned synthetic ServerHello parameters for storing in fingerprint profiles.
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
pub(crate) struct ClientHelloParams<'a> {
    /// TLS protocol version (e.g. `0x0303` for TLS 1.2).
    pub tls_version: u16,
    /// List of cipher suites encoded as IANA identifiers.
    pub cipher_suites: &'a [u16],
    /// Raw extension block to append after the compression method.
    pub extensions: &'a [u8],
}

/// Helper functions for TLS extension building
#[doc(hidden)]
pub fn u16be(v: u16) -> [u8; 2] {
    v.to_be_bytes()
}

#[doc(hidden)]
pub fn grease_value(idx: usize) -> u16 {
    let base: u16 = 0x0a0a;
    let step: u16 = 0x1010;
    base.wrapping_add(step.wrapping_mul(idx as u16))
}

#[doc(hidden)]
pub fn grease_ext(seed: u16) -> Vec<u8> {
    let idx = (seed & 0x000f) as usize;
    let t = grease_value(idx);
    let mut ext = Vec::with_capacity(4);
    ext.extend_from_slice(&t.to_be_bytes());
    ext.extend_from_slice(&0u16.to_be_bytes());
    ext
}

#[doc(hidden)]
pub fn alpn_ext(protocols: &[&str]) -> Vec<u8> {
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

#[doc(hidden)]
pub fn supported_versions_ext(versions: &[u16]) -> Vec<u8> {
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

#[doc(hidden)]
pub fn signature_algorithms_ext(schemes: &[u16]) -> Vec<u8> {
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

#[doc(hidden)]
pub fn signature_algorithms_cert_ext(schemes: &[u16]) -> Vec<u8> {
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

#[doc(hidden)]
pub fn supported_groups_ext(groups: &[u16]) -> Vec<u8> {
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

#[doc(hidden)]
pub fn psk_key_exchange_modes_ext(modes: &[u8]) -> Vec<u8> {
    let mut body = Vec::with_capacity(1 + modes.len());
    body.push(modes.len() as u8);
    body.extend_from_slice(modes);
    let mut ext = Vec::with_capacity(4 + body.len());
    ext.extend_from_slice(&0x002Du16.to_be_bytes());
    ext.extend_from_slice(&(body.len() as u16).to_be_bytes());
    ext.extend_from_slice(&body);
    ext
}

#[doc(hidden)]
pub fn key_share_ext(group: u16, seed: u64) -> Vec<u8> {
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

/// Multi-entry key_share extension (type 0x0033). Each entry is
/// `(group, share_len)`; share bytes are xorshift-expanded from
/// `seed ^ index` so a single per-call seed yields independent-looking
/// shares. Used to emit the modern Chrome/Firefox pair
/// `X25519MLKEM768 (1216 B) + X25519 (32 B)`.
#[doc(hidden)]
pub fn key_share_ext_multi(entries: &[(u16, u16)], seed: u64) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&[0, 0]); // client_shares length, filled below
    for (idx, (group, share_len)) in entries.iter().enumerate() {
        let mut kx = vec![0u8; *share_len as usize];
        let mut x =
            seed.wrapping_add(idx as u64).rotate_left(idx as u32 & 63) ^ 0x9E3779B97F4A7C15u64;
        for b in &mut kx {
            x ^= x << 7;
            x ^= x >> 9;
            x ^= x << 8;
            *b = (x & 0xFF) as u8;
        }
        body.extend_from_slice(&u16be(*group));
        body.extend_from_slice(&u16be(*share_len));
        body.extend_from_slice(&kx);
    }
    let shares_len = (body.len() - 2) as u16;
    body[0] = (shares_len >> 8) as u8;
    body[1] = (shares_len & 0xFF) as u8;
    let mut ext = Vec::with_capacity(4 + body.len());
    ext.extend_from_slice(&0x0033u16.to_be_bytes());
    ext.extend_from_slice(&(body.len() as u16).to_be_bytes());
    ext.extend_from_slice(&body);
    ext
}

/// TLS 1.3 padding extension (type 0x0015). Fills with zeros.
#[doc(hidden)]
pub fn padding_ext(pad_len: usize) -> Vec<u8> {
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
#[doc(hidden)]
pub fn ech_grease_ext(seed: u16) -> Vec<u8> {
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

/// QUIC transport_parameters extension (0x0039, RFC 9000 §18). Mandatory in
/// every real QUIC ClientHello - a hello carrying h3 ALPN without it fails
/// QUIC-aware DPI parsing immediately. Values mirror current Chrome h3.
#[doc(hidden)]
pub fn quic_transport_params_ext(scid_seed: u64) -> Vec<u8> {
    fn qvarint_len(v: u64) -> u64 {
        if v < 64 {
            1
        } else if v < 16384 {
            2
        } else if v < (1 << 30) {
            4
        } else {
            8
        }
    }
    fn qvarint(out: &mut Vec<u8>, v: u64) {
        if v < 64 {
            out.push(v as u8);
        } else if v < 16384 {
            out.extend_from_slice(&((v as u16) | 0x4000).to_be_bytes());
        } else if v < (1 << 30) {
            out.extend_from_slice(&((v as u32) | 0x8000_0000).to_be_bytes());
        } else {
            out.extend_from_slice(&(v | 0xC000_0000_0000_0000).to_be_bytes());
        }
    }
    fn tp(body: &mut Vec<u8>, id: u64, val: u64) {
        qvarint(body, id);
        qvarint(body, qvarint_len(val));
        qvarint(body, val);
    }
    let mut body = Vec::with_capacity(96);
    tp(&mut body, 0x01, 30_000); // max_idle_timeout
    tp(&mut body, 0x03, 1_472); // max_udp_payload_size
    tp(&mut body, 0x04, 15_728_640); // initial_max_data
    tp(&mut body, 0x05, 6_291_456); // initial_max_stream_data_bidi_local
    tp(&mut body, 0x06, 6_291_456); // initial_max_stream_data_bidi_remote
    tp(&mut body, 0x07, 6_291_456); // initial_max_stream_data_uni
    tp(&mut body, 0x08, 100); // initial_max_streams_bidi
    tp(&mut body, 0x09, 103); // initial_max_streams_uni
    tp(&mut body, 0x0A, 3); // ack_delay_exponent
    tp(&mut body, 0x0B, 25); // max_ack_delay
    qvarint(&mut body, 0x0C); // disable_active_migration: empty value
    qvarint(&mut body, 0);
    tp(&mut body, 0x0E, 8); // active_connection_id_limit
    qvarint(&mut body, 0x0F); // initial_source_connection_id: 8 fresh bytes
    qvarint(&mut body, 8);
    body.extend_from_slice(&scid_seed.to_be_bytes());
    tp(&mut body, 0x20, 65_536); // max_datagram_frame_size
    let mut ext = Vec::with_capacity(4 + body.len());
    ext.extend_from_slice(&0x0039u16.to_be_bytes());
    ext.extend_from_slice(&(body.len() as u16).to_be_bytes());
    ext.extend_from_slice(&body);
    ext
}

/// ALPS application_settings extension (0x4469) as Chrome emits for h3:
/// a u8-length-prefixed list of u8-length-prefixed protocol names.
#[doc(hidden)]
pub fn application_settings_h3_ext() -> Vec<u8> {
    let body = [0x03u8, 0x02, b'h', b'3'];
    let mut ext = Vec::with_capacity(4 + body.len());
    ext.extend_from_slice(&0x4469u16.to_be_bytes());
    ext.extend_from_slice(&(body.len() as u16).to_be_bytes());
    ext.extend_from_slice(&body);
    ext
}

/// compress_certificate extension (0x001B): u8-length-prefixed u16 algorithm
/// list. Chrome offers brotli (0x0002); Firefox brotli + zstd.
#[doc(hidden)]
pub fn compress_certificate_ext(algos: &[u16]) -> Vec<u8> {
    let mut body = Vec::with_capacity(1 + 2 * algos.len());
    body.push((algos.len() * 2) as u8);
    for a in algos {
        body.extend_from_slice(&u16be(*a));
    }
    let mut ext = Vec::with_capacity(4 + body.len());
    ext.extend_from_slice(&0x001Bu16.to_be_bytes());
    ext.extend_from_slice(&(body.len() as u16).to_be_bytes());
    ext.extend_from_slice(&body);
    ext
}

#[doc(hidden)]
pub fn sni_ext(host: &str) -> Vec<u8> {
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
        browser: crate::BrowserProfile,
        os: crate::OsProfile,
        sni: Option<&str>,
    ) -> Vec<u8> {
        let environment = qf_common::env_utils::EnvSnapshot::capture();
        Self::generate_client_hello_with_snapshot(browser, os, sni, &environment)
    }

    #[doc(hidden)]
    pub fn generate_client_hello_with_snapshot(
        browser: crate::BrowserProfile,
        os: crate::OsProfile,
        sni: Option<&str>,
        environment: &qf_common::env_utils::EnvSnapshot,
    ) -> Vec<u8> {
        // Per-call entropy: every synthetic hello draws fresh randomness for
        // the ClientHello random field, session ID, key shares, GREASE value
        // selection, and ECH/padding payloads. The persona seed previously
        // made every connection with the same persona byte-identical - an
        // immediate synthetic-traffic tell (TODO-1009).
        use rand::Rng;
        let mut rng = rand::rng();
        let hello_random: [u8; 32] = rng.random();
        let grease_cipher_idx = rng.random_range(0..16usize);
        let grease_version_idx = rng.random_range(0..16usize);
        let grease_group_idx = rng.random_range(0..16usize);
        let grease_ext_seed: u16 = rng.random();
        let key_share_seed: u64 = rng.random();
        let ech_grease_seed: u16 = rng.random();
        let qtp_scid_seed: u64 = rng.random();
        let ultra_pad_len = rng.random_range(16..48usize);
        let enable_grease = !matches!(browser, crate::BrowserProfile::Safari);

        // Browser-specific cipher suites
        let mut ciphers = match browser {
            crate::BrowserProfile::Firefox => vec![
                0x1301, 0x1303, 0x1302, 0xC02B, 0xC02F, 0xCCA9, 0xCCA8, 0xC02C, 0xC030, 0xC013,
                0xC014,
            ],
            _ => vec![
                0x1301, 0x1302, 0x1303, 0xC02B, 0xC02F, 0xC02C, 0xC030, 0xCCA9, 0xCCA8, 0xC013,
                0xC014,
            ],
        };

        // NOTE: the real-handshake cipher policy (ChaCha removal) does NOT
        // apply here - this is the synthetic cover hello whose whole job is
        // byte-level browser mimicry, and every real browser offers
        // TLS_CHACHA20_POLY1305_SHA256 (0x1303).

        // OS-specific ALPN
        let alpns = match (browser, os) {
            (crate::BrowserProfile::Safari, crate::OsProfile::IOS) => vec!["h3", "http/1.1"],
            _ => vec!["h3", "h2", "http/1.1"],
        };

        // An h3-first ALPN emulates a QUIC ClientHello: QUIC can only run
        // TLS 1.3, so TLS 1.2 cipher suites in the list would be a shape no
        // real browser emits (JA4-visible, TODO-1009). Real Chrome QUIC
        // sends exactly [1301, 1302, 1303].
        if alpns.first() == Some(&"h3") {
            ciphers.retain(|cs| (0x1301..=0x1305).contains(cs));
        }

        // Add GREASE cipher if enabled
        if enable_grease {
            let grease = grease_value(grease_cipher_idx);
            if !ciphers.contains(&grease) {
                ciphers.insert(0, grease);
            }
        }

        // Build extensions in browser-specific order
        let mut exts = Vec::with_capacity(512);
        let ext_order = match browser {
            crate::BrowserProfile::Chrome | crate::BrowserProfile::Edge => &[
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
            crate::BrowserProfile::Firefox => &[
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
            crate::BrowserProfile::Safari => &[
                "sni",
                "supported_versions",
                "signature_algorithms",
                "signature_algorithms_cert",
                "supported_groups",
                "key_share",
                "alpn",
            ][..],
        };

        for name in ext_order {
            match *name {
                "grease" => {
                    if enable_grease {
                        exts.extend_from_slice(&grease_ext(grease_ext_seed));
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
                        let gv = grease_value(grease_version_idx);
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
                    // Post-quantum hybrid key exchange is the modern browser
                    // shape: Chrome/Firefox offer X25519MLKEM768 first, then
                    // X25519 + NIST curves. Safari stays on the classic list.
                    let mut groups = match browser {
                        crate::BrowserProfile::Safari => vec![0x001D, 0x0017, 0x0018],
                        _ => vec![0x11EC, 0x001D, 0x0017, 0x0018],
                    };
                    if enable_grease {
                        let g = grease_value(grease_group_idx);
                        if !groups.contains(&g) {
                            groups.insert(0, g);
                        }
                    }
                    exts.extend_from_slice(&supported_groups_ext(&groups));
                }
                "psk_modes" => exts.extend_from_slice(&psk_key_exchange_modes_ext(&[0x01])),
                "key_share" => {
                    // Chrome/Edge/Firefox send the X25519MLKEM768 hybrid share
                    // (1216 B) followed by X25519 (32 B); Safari still sends a
                    // bare X25519 share.
                    match browser {
                        crate::BrowserProfile::Safari => {
                            exts.extend_from_slice(&key_share_ext(0x001D, key_share_seed));
                        }
                        _ => exts.extend_from_slice(&key_share_ext_multi(
                            &[(0x11EC, 1216), (0x001D, 32)],
                            key_share_seed,
                        )),
                    }
                }
                _ => {}
            }
        }

        // QUIC transport parameters (0x0039) are mandatory in every real
        // QUIC ClientHello (RFC 9001) - an h3-ALPN hello without them is an
        // immediate synthetic tell to QUIC-aware DPI. Chrome additionally
        // sends ALPS (0x4469) and compress_certificate (0x001B), Firefox
        // only compress_certificate; Safari sends neither beyond QTP.
        if alpns.first() == Some(&"h3") {
            exts.extend_from_slice(&quic_transport_params_ext(qtp_scid_seed));
            match browser {
                crate::BrowserProfile::Chrome | crate::BrowserProfile::Edge => {
                    exts.extend_from_slice(&application_settings_h3_ext());
                    exts.extend_from_slice(&compress_certificate_ext(&[0x0002]));
                }
                crate::BrowserProfile::Firefox => {
                    exts.extend_from_slice(&compress_certificate_ext(&[0x0002, 0x0003]));
                }
                _ => {}
            }
        }

        // ECH GREASE (0xFE0D) is unconditional browser behavior since 2023
        // (Chrome/Edge/Firefox always; Safari since iOS 17.5/macOS 14.5) -
        // its absence is a JA4-visible synthetic tell (TODO-1009). ULTRA only
        // adds the smoothing padding extension on top.
        exts.extend_from_slice(&ech_grease_ext(ech_grease_seed));
        let ultra = environment.flag("QUICFUSCATE_TLS_COVER_ULTRA", false);
        if ultra {
            // Pad to a random target within a narrow band
            exts.extend_from_slice(&padding_ext(ultra_pad_len));
        }

        // Session ID behavior: Chrome/Edge/Safari often include 32B; Firefox empty
        match browser {
            crate::BrowserProfile::Firefox => Self::client_hello_custom_with_sid(
                ClientHelloParams {
                    tls_version: 0x0303,
                    cipher_suites: &ciphers,
                    extensions: &exts,
                },
                None,
                &hello_random,
            ),
            _ => {
                // Fresh random session ID per hello - real browsers draw a new
                // one per connection, so persona-derived determinism was a
                // fingerprint tell.
                let sid: [u8; 32] = rng.random();
                Self::client_hello_custom_with_sid(
                    ClientHelloParams {
                        tls_version: 0x0303,
                        cipher_suites: &ciphers,
                        extensions: &exts,
                    },
                    Some(&sid[..]),
                    &hello_random,
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
    #[cfg(test)]
    pub(super) fn client_hello_custom(params: ClientHelloParams) -> Vec<u8> {
        Self::client_hello_custom_with_sid(params, None, &[0u8; 32])
    }

    /// Builds a ClientHello with optional Session ID (for fingerprint parity per browser).
    pub(super) fn client_hello_custom_with_sid(
        params: ClientHelloParams,
        session_id: Option<&[u8]>,
        hello_random: &[u8; 32],
    ) -> Vec<u8> {
        let mut payload = Vec::new();
        payload.extend_from_slice(&params.tls_version.to_be_bytes());
        payload.extend_from_slice(hello_random);
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
        let with_sid = TlsCover::client_hello_custom_with_sid(params, Some(&sid), &[0u8; 32]);
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
            crate::BrowserProfile::Chrome,
            crate::OsProfile::Windows,
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
            crate::BrowserProfile::Firefox,
            crate::OsProfile::Linux,
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
            crate::BrowserProfile::Safari,
            crate::OsProfile::MacOS,
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

    /// Dumps one synthetic ClientHello per persona as hex lines for external
    /// JA4/fingerprint tooling (`--nocapture`). The output feeds
    /// `scripts/audits/` capture comparisons (TODO-1009).
    #[test]
    fn dump_persona_client_hellos_as_hex() {
        let personas: [(&str, crate::BrowserProfile, crate::OsProfile); 5] = [
            ("chrome-win", crate::BrowserProfile::Chrome, crate::OsProfile::Windows),
            ("edge-win", crate::BrowserProfile::Edge, crate::OsProfile::Windows),
            ("firefox-linux", crate::BrowserProfile::Firefox, crate::OsProfile::Linux),
            ("safari-macos", crate::BrowserProfile::Safari, crate::OsProfile::MacOS),
            ("safari-ios", crate::BrowserProfile::Safari, crate::OsProfile::IOS),
        ];
        for (name, browser, os) in personas {
            let record = TlsCover::generate_client_hello(browser, os, Some("example.com"));
            let hex: String = record.iter().map(|b| format!("{b:02x}")).collect();
            println!("PERSONA_HELLO {name} {hex}");
        }
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

    #[test]
    fn tls_cover_cipher_suite_wire_contract_is_stable() {
        assert_eq!(TlsCoverCipherSuite::Aes128Gcm.as_str(), "aes-128-gcm");
        assert_eq!(TlsCoverCipherSuite::Aes128Gcm.tls_id(), 0x1301);
        assert_eq!(TlsCoverCipherSuite::ChaCha20Poly1305.as_str(), "chacha20-poly1305");
        assert_eq!(TlsCoverCipherSuite::ChaCha20Poly1305.tls_id(), 0x1303);
    }

    #[test]
    fn tls_cover_material_derivation_is_deterministic_and_domain_separated() {
        let entropy = [0x5a; TLS_COVER_KEY_LEN];
        let client = derive_tls_cover_material_from_entropy("chrome", false, &entropy)
            .expect("legal TLS Cover length");
        assert_eq!(
            client,
            derive_tls_cover_material_from_entropy("chrome", false, &entropy)
                .expect("legal TLS Cover length")
        );
        assert_ne!(
            client,
            derive_tls_cover_material_from_entropy("chrome", true, &entropy)
                .expect("legal TLS Cover length")
        );
        assert_ne!(
            client,
            derive_tls_cover_material_from_entropy("firefox", false, &entropy)
                .expect("legal TLS Cover length")
        );
    }

    #[test]
    fn fresh_tls_cover_material_is_not_reused_between_connections() {
        let first = derive_tls_cover_material("chrome", false).expect("first material");
        let second = derive_tls_cover_material("chrome", false).expect("second material");
        assert_ne!(first, second);
    }

    #[test]
    fn performance_record_plan_is_role_bounded_and_has_no_jitter() {
        let environment = qf_common::env_utils::EnvSnapshot::from_pairs([]);
        let client = plan_tls_cover_record(4096, true, false, "chrome", &environment)
            .expect("plan")
            .expect("record");
        let server = plan_tls_cover_record(4096, true, true, "firefox", &environment)
            .expect("plan")
            .expect("record");
        assert_eq!(client.payload.len(), 1200);
        assert_eq!(server.payload.len(), 800);
        assert!(client.jitter.is_none());
        assert!(server.jitter.is_none());
    }

    #[test]
    fn record_plan_respects_tls_u16_length_under_large_padding_cap() {
        let environment = qf_common::env_utils::EnvSnapshot::from_pairs([
            ("QUICFUSCATE_STEALTH_PADDING_MAX", "100000"),
            ("QUICFUSCATE_STEALTH_JITTER_US", "25"),
        ]);
        let plan = plan_tls_cover_record(100_000, false, false, "edge", &environment)
            .expect("plan")
            .expect("record");
        let encoded_len = u16::from_be_bytes([plan.header[3], plan.header[4]]) as usize;
        assert_eq!(encoded_len, plan.payload.len() + 16);
        assert!(plan.payload.len() <= u16::MAX as usize - 16);
        assert!(plan.jitter.is_some_and(|jitter| jitter.as_micros() <= 25));
    }

    #[test]
    fn record_plan_rejects_capacity_smaller_than_header_and_tag() {
        let environment = qf_common::env_utils::EnvSnapshot::from_pairs([]);
        assert!(plan_tls_cover_record(20, false, false, "chrome", &environment)
            .expect("plan")
            .is_none());
    }

    #[test]
    fn generate_client_hello_per_call_entropy_varies_random_sid_and_key_share() {
        // Regression for TODO-1009: persona-seeded determinism made every
        // hello from the same profile byte-identical. Two consecutive hellos
        // must now differ in the random field, session ID, and key share
        // while keeping identical record structure.
        let a = TlsCover::generate_client_hello(
            crate::BrowserProfile::Chrome,
            crate::OsProfile::Windows,
            Some("example.com"),
        );
        let b = TlsCover::generate_client_hello(
            crate::BrowserProfile::Chrome,
            crate::OsProfile::Windows,
            Some("example.com"),
        );
        assert_eq!(a[0], 0x16);
        assert_eq!(a[5], 0x01);
        assert_ne!(a, b, "two hellos from one persona must never be byte-identical");
        // hello random: bytes 11..43 of the record
        assert_ne!(&a[11..43], &[0u8; 32], "hello random must not be the zero placeholder");
        assert_ne!(&a[11..43], &b[11..43], "hello random must vary per call");
        // session id: sid_len at 43, sid at 44..44+sid_len
        let sid_len = a[43] as usize;
        assert_eq!(sid_len, 32, "Chrome persona carries a 32-byte session ID");
        assert_ne!(&a[44..44 + sid_len], &b[44..44 + sid_len], "session ID must vary per call");
    }

    #[test]
    fn generate_client_hello_modern_key_share_shape() {
        // Chrome-family hellos must offer the X25519MLKEM768 hybrid share
        // (0x11EC, 1216 B) followed by X25519 (0x001D, 32 B) - a bare-X25519
        // hello is a stale pre-PQ fingerprint.
        let record = TlsCover::generate_client_hello(
            crate::BrowserProfile::Chrome,
            crate::OsProfile::Windows,
            None,
        );
        assert!(
            record.windows(2).any(|w| w == [0x11, 0xEC]),
            "key_share must contain the X25519MLKEM768 group 0x11EC"
        );
        // key_share extension type 0x0033 must be present
        assert!(
            record.windows(2).any(|w| w == [0x00, 0x33]),
            "key_share extension 0x0033 must be present"
        );
    }

    /// Parse a TLS-record ClientHello into (cipher suites, extension types).
    fn parse_hello(record: &[u8]) -> (Vec<u16>, Vec<u16>) {
        // record header (5) + handshake header (4) + version (2) + random (32)
        let mut p = 5 + 4 + 2 + 32;
        let sid_len = record[p] as usize;
        p += 1 + sid_len;
        let cs_len = u16::from_be_bytes([record[p], record[p + 1]]) as usize;
        p += 2;
        let ciphers = record[p..p + cs_len]
            .as_chunks::<2>()
            .0
            .iter()
            .map(|c| u16::from_be_bytes(*c))
            .collect();
        p += cs_len;
        p += 1 + record[p] as usize; // compression methods
        let ext_total = u16::from_be_bytes([record[p], record[p + 1]]) as usize;
        p += 2;
        let end = p + ext_total;
        let mut exts = Vec::new();
        while p + 4 <= end {
            let ty = u16::from_be_bytes([record[p], record[p + 1]]);
            let ln = u16::from_be_bytes([record[p + 2], record[p + 3]]) as usize;
            exts.push(ty);
            p += 4 + ln;
        }
        (ciphers, exts)
    }

    #[test]
    fn h3_first_hello_advertises_tls13_only_and_quic_transport_params() {
        // Regression guard (TODO-1009): an h3-ALPN hello must carry only
        // TLS 1.3 cipher suites plus the mandatory quic_transport_params
        // extension (RFC 9001) - legacy suites or a missing 0x0039 are
        // immediate synthetic tells.
        for browser in [
            crate::BrowserProfile::Chrome,
            crate::BrowserProfile::Edge,
            crate::BrowserProfile::Firefox,
            crate::BrowserProfile::Safari,
        ] {
            for os in [crate::OsProfile::Windows, crate::OsProfile::IOS] {
                let record = TlsCover::generate_client_hello(browser, os, None);
                let (ciphers, exts) = parse_hello(&record);
                assert!(
                    ciphers.iter().all(|c| (0x1301..=0x1305).contains(c) || (c & 0x0F0F) == 0x0A0A),
                    "h3 hello must only carry TLS 1.3 or GREASE ciphers: {ciphers:?}"
                );
                assert!(
                    exts.contains(&0x0039),
                    "h3 hello must carry quic_transport_params (0x0039)"
                );
                assert!(exts.contains(&0xFE0D), "hello must carry ECH-GREASE (0xFE0D)");
            }
        }
    }

    #[test]
    fn chrome_hello_matches_browser_quic_extension_shape() {
        let record = TlsCover::generate_client_hello(
            crate::BrowserProfile::Chrome,
            crate::OsProfile::Windows,
            Some("cdn.example"),
        );
        let (_ciphers, exts) = parse_hello(&record);
        // Chrome h3 shape: QTP + ALPS + compress_certificate alongside the
        // base extension set (FoxIO Chrome QUIC reference: 12 non-GREASE).
        for want in [0x0039u16, 0x4469, 0x001B] {
            assert!(exts.contains(&want), "Chrome h3 hello missing ext {want:#06x}");
        }
        let non_grease = exts.iter().filter(|e| (*e & 0x0F0F) != 0x0A0A).count();
        assert_eq!(non_grease, 12, "Chrome h3 should emit 12 non-GREASE extensions");
    }
}
