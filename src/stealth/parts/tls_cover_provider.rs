// --- Inlined: tls_cover.rs ---
// Minimal TLS Cover record layer for fingerprinting
// Generates a forged ClientHello and synthetic server response without
// establishing a real TLS session.
// Ultra-sophisticated TLS Cover Provider for maximum stealth
/// Cipher suite used by the TLS Cover provider for encrypting synthetic records.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsCoverCipherSuite {
    /// ChaCha20-Poly1305 (preferred on platforms without hardware AES).
    ChaCha20Poly1305,
    /// AES-128-GCM (preferred when hardware AES acceleration is available).
    Aes128Gcm,
}

impl TlsCoverCipherSuite {
    fn as_str(&self) -> &'static str {
        match self {
            TlsCoverCipherSuite::ChaCha20Poly1305 => "chacha20-poly1305",
            TlsCoverCipherSuite::Aes128Gcm => "aes-128-gcm",
        }
    }

    /// Returns the TLS wire-format cipher suite ID (for ServerHello).
    pub(crate) fn tls_id(&self) -> u16 {
        match self {
            TlsCoverCipherSuite::ChaCha20Poly1305 => 0x1303,
            TlsCoverCipherSuite::Aes128Gcm => 0x1301,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TlsCoverCipherPreference {
    Auto,
    ChaCha20Poly1305,
    Aes128Gcm,
}

use crate::env_utils;

impl TlsCoverCipherPreference {
    fn parse(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "auto" | "" => Some(Self::Auto),
            "chacha" | "chacha20" | "chacha20poly1305" => Some(Self::ChaCha20Poly1305),
            "aes" | "aesgcm" | "aes-gcm" | "aes128gcm" | "aes-128-gcm" | "ctr" | "aesctr" => {
                Some(Self::Aes128Gcm)
            }
            _ => None,
        }
    }
}

/// Manages synthetic TLS record generation for DPI evasion on a per-connection basis.
pub(crate) struct TlsCoverProvider {
    crypto: Arc<parking_lot::RwLock<crate::transport::packet::CryptoContext>>,
    is_server: bool,
    handshake_complete: bool,
    ch_template: Vec<u8>,
    performance_mode: bool, // When true, disable padding/jitter/timing features
    fingerprint_profile: String,
}

impl TlsCoverProvider {
    fn padding_cap_override() -> Option<usize> {
        env_utils::env_first(["QUICFUSCATE_STEALTH_PADDING_MAX", "QUICFUSCATE_STEALTH_MAX_PADDING"])
            .and_then(|v| v.parse::<usize>().ok())
    }

    fn jitter_override_us() -> Option<u64> {
        env_utils::env_first(["QUICFUSCATE_STEALTH_JITTER_US"]).and_then(|v| v.parse::<u64>().ok())
    }

    fn cipher_preference_from_env() -> TlsCoverCipherPreference {
        env_utils::env_first(["QUICFUSCATE_TLS_COVER_CIPHER"])
            .and_then(|value| TlsCoverCipherPreference::parse(&value))
            .unwrap_or(TlsCoverCipherPreference::Auto)
    }

    fn tls_cover_profile_name() -> String {
        env_utils::env_first(["QUICFUSCATE_TLS_COVER_PROFILE"])
            .unwrap_or_else(|| "chrome".to_string())
    }

    fn ultra_enabled() -> bool {
        env_utils::env_flag("QUICFUSCATE_TLS_COVER_ULTRA", false)
    }

    fn has_hardware_aes() -> bool {
        let detector = crate::optimize::FeatureDetector::instance();
        detector.has_feature(crate::optimize::CpuFeature::AESNI)
            || detector.has_feature(crate::optimize::CpuFeature::VAES)
            || detector.has_feature(crate::optimize::CpuFeature::AES)
    }

    fn resolve_cipher_suite(pref: TlsCoverCipherPreference) -> TlsCoverCipherSuite {
        match pref {
            TlsCoverCipherPreference::Auto => {
                if Self::has_hardware_aes() {
                    TlsCoverCipherSuite::Aes128Gcm
                } else {
                    TlsCoverCipherSuite::ChaCha20Poly1305
                }
            }
            TlsCoverCipherPreference::ChaCha20Poly1305 => TlsCoverCipherSuite::ChaCha20Poly1305,
            TlsCoverCipherPreference::Aes128Gcm => {
                if !Self::has_hardware_aes() {
                    log::warn!(
                        "TLS Cover AES-128-GCM requested but hardware lacks AES acceleration; using scalar fallback"
                    );
                }
                TlsCoverCipherSuite::Aes128Gcm
            }
        }
    }

    /// Constructs a provider for the given role, deriving cover-traffic key material.
    pub(crate) fn new(
        is_server: bool,
        crypto: Arc<parking_lot::RwLock<crate::transport::packet::CryptoContext>>,
    ) -> Result<Self, crate::error::ConnectionError> {
        // Load profile from ENV
        let profile = Self::tls_cover_profile_name();

        let (tls_cover_key, tls_cover_iv) = Self::derive_tls_cover_material(&profile, is_server)?;

        let cipher_preference = Self::cipher_preference_from_env();
        let cipher_suite = Self::resolve_cipher_suite(cipher_preference);

        {
            let mut ctx = crypto.write();
            match cipher_suite {
                TlsCoverCipherSuite::ChaCha20Poly1305 => {
                    ctx.install_tls_cover_cipher(
                        crate::transport::packet::TlsCoverKeyMaterial::ChaCha20Poly1305 {
                            key: &tls_cover_key,
                            iv: &tls_cover_iv,
                        },
                    )?;
                }
                TlsCoverCipherSuite::Aes128Gcm => {
                    let mut aes_key = [0u8; 16];
                    aes_key.copy_from_slice(&tls_cover_key[..16]);
                    ctx.install_tls_cover_cipher(
                        crate::transport::packet::TlsCoverKeyMaterial::Aes128Gcm {
                            key: &aes_key,
                            iv: &tls_cover_iv,
                        },
                    )?;
                }
            }
        }

        log::info!(
            "TLS Cover cipher suite selected: {} ({})",
            cipher_suite.as_str(),
            match cipher_preference {
                TlsCoverCipherPreference::Auto => "auto",
                TlsCoverCipherPreference::ChaCha20Poly1305 => "forced",
                TlsCoverCipherPreference::Aes128Gcm => "forced",
            }
        );

        if matches!(cipher_suite, TlsCoverCipherSuite::ChaCha20Poly1305) && Self::has_hardware_aes()
        {
            log::debug!("Hardware AES available but TLS Cover cipher forced to ChaCha20-Poly1305");
        }

        // Generate initial CH template based on profile
        let ch_template = Self::generate_ch_template(&profile);

        Ok(Self {
            crypto,
            is_server,
            handshake_complete: false,
            ch_template,
            performance_mode: false,
            fingerprint_profile: profile,
        })
    }

    /// Generate ultra-sophisticated ClientHello template based on profile
    fn generate_ch_template(profile: &str) -> Vec<u8> {
        match profile {
            "chrome" => Self::chrome_ch_template(),
            "firefox" => Self::firefox_ch_template(),
            "safari" => Self::safari_ch_template(),
            "edge" => Self::edge_ch_template(),
            "random" => Self::random_ch_template(),
            _ => Self::chrome_ch_template(),
        }
    }

    fn derive_tls_cover_material(
        profile: &str,
        is_server: bool,
    ) -> Result<([u8; 32], [u8; 12]), crate::error::ConnectionError> {
        use zeroize::Zeroize;

        let mut entropy = [0u8; 32];
        crate::rng::fill_secure(&mut entropy).map_err(|_| {
            crate::error::ConnectionError::CryptoError(
                "TLS cover entropy source unavailable".to_string(),
            )
        })?;
        let result = Self::derive_tls_cover_material_from_entropy(profile, is_server, &entropy);
        entropy.zeroize();
        Ok(result)
    }

    fn derive_tls_cover_material_from_entropy(
        profile: &str,
        is_server: bool,
        entropy: &[u8; 32],
    ) -> ([u8; 32], [u8; 12]) {
        use zeroize::Zeroize;

        let mut prk = hkdf_extract(b"quicfuscate:tls-cover:salt:v2", entropy);
        let info = format!(
            "quicfuscate:tls-cover:{}:{}",
            profile,
            if is_server { "server" } else { "client" }
        );
        let mut okm = hkdf_expand(&prk, info.as_bytes(), 44);
        let mut key = [0u8; 32];
        let mut iv = [0u8; 12];
        key.copy_from_slice(&okm[..32]);
        iv.copy_from_slice(&okm[32..44]);
        prk.zeroize();
        okm.zeroize();
        (key, iv)
    }

    fn chrome_ch_template() -> Vec<u8> {
        // Ultra-realistic Chrome 130 ClientHello
        let mut ch = Vec::new();

        // TLS 1.3 ClientHello structure
        ch.extend_from_slice(&[
            0x01, 0x00, 0x01, 0xfc, // Handshake Type: ClientHello, Length
            0x03, 0x03, // Version: TLS 1.2 (for compatibility)
        ]);

        // Random (32 bytes) - Chrome-specific pattern
        use rand::Rng;
        let mut rng = rand::rng();
        let mut random = [0u8; 32];
        rng.fill(&mut random[..]);
        ch.extend_from_slice(&random);

        // Session ID (32 bytes for Chrome)
        ch.push(0x20);
        let mut session_id = [0u8; 32];
        rng.fill(&mut session_id[..]);
        ch.extend_from_slice(&session_id);

        // Cipher Suites - Chrome order (includes ChaCha for fingerprint realism)
        ch.extend_from_slice(&[
            0x00, 0x20, // Length: 32 bytes (16 suites)
            0x13, 0x01, // TLS_AES_128_GCM_SHA256
            0x13, 0x02, // TLS_AES_256_GCM_SHA384
            0x13, 0x03, // TLS_CHACHA20_POLY1305_SHA256
            0xc0, 0x2b, // TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
            0xc0, 0x2f, // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
            0xc0, 0x2c, // TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
            0xc0, 0x30, // TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
            0xcc, 0xa9, // TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
            0xcc, 0xa8, // TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
            0xc0, 0x13, // TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
            0xc0, 0x14, // TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA
            0x00, 0x9c, // TLS_RSA_WITH_AES_128_GCM_SHA256
            0x00, 0x9d, // TLS_RSA_WITH_AES_256_GCM_SHA384
            0x00, 0x2f, // TLS_RSA_WITH_AES_128_CBC_SHA
            0x00, 0x35, // TLS_RSA_WITH_AES_256_CBC_SHA
            0x00, 0x0a, // TLS_RSA_WITH_3DES_EDE_CBC_SHA
        ]);

        // Compression Methods
        ch.extend_from_slice(&[0x01, 0x00]); // No compression

        // Extensions - Chrome-specific order and values
        Self::add_chrome_extensions(&mut ch);

        ch
    }

    fn firefox_ch_template() -> Vec<u8> {
        // Ultra-realistic Firefox 133 ClientHello
        let mut ch = Vec::new();

        // Similar structure but Firefox-specific ordering
        ch.extend_from_slice(&[0x01, 0x00, 0x01, 0xf8, 0x03, 0x03]);

        use rand::Rng;
        let mut rng = rand::rng();
        let mut random = [0u8; 32];
        rng.fill(&mut random[..]);
        ch.extend_from_slice(&random);

        // Firefox uses empty session ID
        ch.push(0x00);

        // Firefox cipher suite order (includes ChaCha for fingerprint realism)
        ch.extend_from_slice(&[
            0x00, 0x1e, // Length (30 bytes, 15 suites)
            0x13, 0x01, // TLS_AES_128_GCM_SHA256
            0x13, 0x03, // TLS_CHACHA20_POLY1305_SHA256
            0x13, 0x02, // TLS_AES_256_GCM_SHA384
            0xc0, 0x2b, // TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
            0xc0, 0x2f, // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
            0xcc, 0xa9, // TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
            0xcc, 0xa8, // TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
            0xc0, 0x2c, // TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
            0xc0, 0x30, // TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
            0xc0, 0x13, // TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
            0xc0, 0x14, // TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA
            0x00, 0x33, // TLS_DHE_RSA_WITH_AES_128_CBC_SHA
            0x00, 0x39, // TLS_DHE_RSA_WITH_AES_256_CBC_SHA
            0x00, 0x2f, // TLS_RSA_WITH_AES_128_CBC_SHA
            0x00, 0x35, // TLS_RSA_WITH_AES_256_CBC_SHA
        ]);

        ch.extend_from_slice(&[0x01, 0x00]);

        Self::add_firefox_extensions(&mut ch);

        ch
    }

    fn safari_ch_template() -> Vec<u8> {
        // Ultra-realistic Safari 18 ClientHello
        let mut ch = Vec::new();

        ch.extend_from_slice(&[0x01, 0x00, 0x01, 0xe8, 0x03, 0x03]);

        use rand::Rng;
        let mut rng = rand::rng();
        let mut random = [0u8; 32];
        rng.fill(&mut random[..]);
        ch.extend_from_slice(&random);

        // Safari uses 32-byte session ID
        ch.push(0x20);
        let mut session_id = [0u8; 32];
        rng.fill(&mut session_id[..]);
        ch.extend_from_slice(&session_id);

        // Safari cipher suite order (minimal set)
        ch.extend_from_slice(&[
            0x00, 0x0a, // Length
            0x13, 0x01, // TLS_AES_128_GCM_SHA256
            0x13, 0x02, // TLS_AES_256_GCM_SHA384
            0xc0, 0x2b, // TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
            0xc0, 0x2c, // TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
            0xc0, 0x2f, // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
        ]);

        ch.extend_from_slice(&[0x01, 0x00]);

        Self::add_safari_extensions(&mut ch);

        ch
    }

    fn edge_ch_template() -> Vec<u8> {
        // Edge uses Chrome engine but with slight differences
        // Modify some bytes to make it Edge-specific in future if needed
        // Edge has different extension ordering
        Self::chrome_ch_template()
    }

    fn random_ch_template() -> Vec<u8> {
        // Randomly select a profile for variety
        use rand::Rng;
        let mut rng = rand::rng();
        match rng.random_range(0..4) {
            0 => Self::chrome_ch_template(),
            1 => Self::firefox_ch_template(),
            2 => Self::safari_ch_template(),
            _ => Self::edge_ch_template(),
        }
    }

    const CLIENT_HELLO_SNI: &'static [u8] = b"cdn.cloudflare.com";

    fn append_server_name_extension(ext: &mut Vec<u8>, host: &[u8]) {
        let host_len = host.len();
        if host_len > u16::MAX as usize {
            return;
        }
        let list_len = 1 + 2 + host_len;
        if list_len > u16::MAX as usize {
            return;
        }
        let ext_len = 2 + list_len;
        if ext_len > u16::MAX as usize {
            return;
        }

        ext.extend_from_slice(&[0x00, 0x00]); // server_name
        ext.extend_from_slice(&(ext_len as u16).to_be_bytes());
        ext.extend_from_slice(&(list_len as u16).to_be_bytes());
        ext.push(0x00); // host_name
        ext.extend_from_slice(&(host_len as u16).to_be_bytes());
        ext.extend_from_slice(host);
    }

    fn add_chrome_extensions(ch: &mut Vec<u8>) {
        // Add Chrome-specific extensions in exact order
        let mut ext = Vec::new();

        // GREASE extension (Chrome always starts with GREASE)
        ext.extend_from_slice(&[0x0a, 0x0a, 0x00, 0x00]);

        // Server Name (SNI)
        Self::append_server_name_extension(&mut ext, Self::CLIENT_HELLO_SNI);

        // Supported Groups
        ext.extend_from_slice(&[
            0x00, 0x0a, // Extension type: supported_groups
            0x00, 0x08, // Length
            0x00, 0x06, // Groups length
            0x00, 0x1d, // x25519
            0x00, 0x17, // secp256r1
            0x00, 0x18, // secp384r1
        ]);

        // EC Point Formats
        ext.extend_from_slice(&[
            0x00, 0x0b, // Extension type: ec_point_formats
            0x00, 0x02, // Length
            0x01, // Formats length
            0x00, // uncompressed
        ]);

        // Signature Algorithms
        ext.extend_from_slice(&[
            0x00, 0x0d, // Extension type: signature_algorithms
            0x00, 0x0e, // Length
            0x00, 0x0c, // Algorithms length
            0x04, 0x03, // ecdsa_secp256r1_sha256
            0x08, 0x04, // rsa_pss_rsae_sha256
            0x04, 0x01, // rsa_pkcs1_sha256
            0x05, 0x03, // ecdsa_secp384r1_sha384
            0x08, 0x05, // rsa_pss_rsae_sha384
            0x05, 0x01, // rsa_pkcs1_sha384
        ]);

        // ALPN
        ext.extend_from_slice(&[
            0x00, 0x10, // Extension type: ALPN
            0x00, 0x0e, // Length
            0x00, 0x0c, // ALPN list length
            0x02, b'h', b'3', // h3
            0x08, b'h', b't', b't', b'p', b'/', b'1', b'.', b'1', // http/1.1
        ]);

        // Supported Versions
        ext.extend_from_slice(&[
            0x00, 0x2b, // Extension type: supported_versions
            0x00, 0x03, // Length
            0x02, // Versions length
            0x03, 0x04, // TLS 1.3
        ]);

        // PSK Key Exchange Modes
        ext.extend_from_slice(&[
            0x00, 0x2d, // Extension type: psk_key_exchange_modes
            0x00, 0x02, // Length
            0x01, // Modes length
            0x01, // psk_dhe_ke
        ]);

        // Key Share
        ext.extend_from_slice(&[
            0x00, 0x33, // Extension type: key_share
            0x00, 0x26, // Length
            0x00, 0x24, // Key share entries length
            0x00, 0x1d, // Group: x25519
            0x00, 0x20, // Key exchange length
        ]);

        // Generate random key
        use rand::Rng;
        let mut rng = rand::rng();
        let mut key = [0u8; 32];
        rng.fill(&mut key[..]);
        ext.extend_from_slice(&key);

        // Add extension length to CH
        ch.extend_from_slice(&((ext.len() as u16).to_be_bytes()));
        ch.extend_from_slice(&ext);
    }

    fn add_firefox_extensions(ch: &mut Vec<u8>) {
        // Firefox has different extension order and doesn't use GREASE
        let mut ext = Vec::new();

        // Server Name (Firefox starts with SNI)
        Self::append_server_name_extension(&mut ext, Self::CLIENT_HELLO_SNI);

        // Extended Master Secret
        ext.extend_from_slice(&[0x00, 0x17, 0x00, 0x00]);

        // Renegotiation Info
        ext.extend_from_slice(&[0xff, 0x01, 0x00, 0x01, 0x00]);

        // Supported Groups
        ext.extend_from_slice(&[
            0x00, 0x0a, 0x00, 0x0a, 0x00, 0x08, 0x00, 0x1d, 0x00, 0x17, 0x00, 0x1e, 0x00, 0x18,
        ]);

        // EC Point Formats
        ext.extend_from_slice(&[0x00, 0x0b, 0x00, 0x02, 0x01, 0x00]);

        // Session Ticket
        ext.extend_from_slice(&[0x00, 0x23, 0x00, 0x00]);

        // ALPN
        ext.extend_from_slice(&[
            0x00, 0x10, 0x00, 0x0e, 0x00, 0x0c, 0x02, b'h', b'3', 0x08, b'h', b't', b't', b'p',
            b'/', b'1', b'.', b'1',
        ]);

        // Status Request
        ext.extend_from_slice(&[0x00, 0x05, 0x00, 0x05, 0x01, 0x00, 0x00, 0x00, 0x00]);

        // Signature Algorithms
        ext.extend_from_slice(&[
            0x00, 0x0d, 0x00, 0x12, 0x00, 0x10, 0x04, 0x03, 0x08, 0x04, 0x04, 0x01, 0x05, 0x03,
            0x08, 0x05, 0x05, 0x01, 0x08, 0x06, 0x06, 0x01, 0x02, 0x01,
        ]);

        // Supported Versions
        ext.extend_from_slice(&[0x00, 0x2b, 0x00, 0x05, 0x04, 0x03, 0x04, 0x03, 0x03]);

        // PSK Key Exchange Modes
        ext.extend_from_slice(&[0x00, 0x2d, 0x00, 0x02, 0x01, 0x01]);

        // Key Share
        ext.extend_from_slice(&[0x00, 0x33, 0x00, 0x26, 0x00, 0x24, 0x00, 0x1d, 0x00, 0x20]);

        use rand::Rng;
        let mut rng = rand::rng();
        let mut key = [0u8; 32];
        rng.fill(&mut key[..]);
        ext.extend_from_slice(&key);

        ch.extend_from_slice(&((ext.len() as u16).to_be_bytes()));
        ch.extend_from_slice(&ext);
    }

    fn add_safari_extensions(ch: &mut Vec<u8>) {
        // Safari has minimal extensions
        let mut ext = Vec::new();

        // Server Name
        Self::append_server_name_extension(&mut ext, Self::CLIENT_HELLO_SNI);

        // Supported Groups (Safari uses fewer groups)
        ext.extend_from_slice(&[0x00, 0x0a, 0x00, 0x06, 0x00, 0x04, 0x00, 0x1d, 0x00, 0x17]);

        // Signature Algorithms (Safari minimal set)
        ext.extend_from_slice(&[
            0x00, 0x0d, 0x00, 0x08, 0x00, 0x06, 0x04, 0x03, 0x05, 0x03, 0x06, 0x03,
        ]);

        // ALPN
        ext.extend_from_slice(&[0x00, 0x10, 0x00, 0x05, 0x00, 0x03, 0x02, b'h', b'3']);

        // Supported Versions
        ext.extend_from_slice(&[0x00, 0x2b, 0x00, 0x03, 0x02, 0x03, 0x04]);

        // Key Share
        ext.extend_from_slice(&[0x00, 0x33, 0x00, 0x26, 0x00, 0x24, 0x00, 0x1d, 0x00, 0x20]);

        use rand::Rng;
        let mut rng = rand::rng();
        let mut key = [0u8; 32];
        rng.fill(&mut key[..]);
        ext.extend_from_slice(&key);

        ch.extend_from_slice(&((ext.len() as u16).to_be_bytes()));
        ch.extend_from_slice(&ext);
    }

    /// Replaces the ClientHello template with externally-provided bytes.
    pub(crate) fn apply_ch_override(
        &mut self,
        template: &[u8],
    ) -> Result<(), crate::error::ConnectionError> {
        self.ch_template = template.to_vec();
        Ok(())
    }

    /// Enable/disable performance mode
    /// Performance mode: Full TLS Cover traffic but NO artificial delays/padding/jitter
    /// Stealth mode: Full sophistication including timing variations and padding
    pub(crate) fn set_performance_mode(&mut self, enabled: bool) {
        self.performance_mode = enabled;
        if enabled {
            log::debug!("TLS Cover performance mode: Full cover traffic, no artificial delays");
        } else {
            log::debug!("TLS Cover stealth mode: Full sophistication with timing/padding");
        }
    }

    /// Ingests inbound QUIC crypto data and updates handshake state.
    pub(crate) fn provide_quic_data(
        &mut self,
        level: crate::qftls::Level,
        data: &[u8],
    ) -> Result<(), crate::error::ConnectionError> {
        // Usage of is_server/crypto: telemetry and handshake status.
        let _guard = self.crypto.read();
        crate::telemetry::BYTES_RECEIVED.inc_by(data.len() as u64);
        if matches!(level, crate::qftls::Level::Handshake) && self.is_server {
            self.handshake_complete = true;
        }
        Ok(())
    }

    /// Produces the next synthetic TLS Cover crypto frame for outbound traffic.
    pub(crate) fn next_crypto_frame(
        &mut self,
        _level: crate::qftls::Level,
        max_len: usize,
    ) -> Option<(u64, Vec<u8>)> {
        // Generate sophisticated TLS Cover frames for cover traffic
        if !self.handshake_complete {
            let frame = self.generate_fake_crypto_frame(max_len);
            if !frame.is_empty() {
                return Some((0, frame));
            }
        }
        None
    }

    /// Generate sophisticated fake crypto frame based on stealth mode
    fn generate_fake_crypto_frame(&self, max_len: usize) -> Vec<u8> {
        // In performance mode: Full TLS Cover but no artificial delays/padding/jitter
        // We still generate realistic TLS frames for cover traffic!

        // Stealth mode: full sophistication
        use rand::Rng;
        let mut rng = rand::rng();

        // Generate realistic TLS record structure
        let mut frame = Vec::with_capacity(5 + max_len.min(1300));

        // TLS Record Header (5 bytes): Type(1) + Version(2) + Length(2)
        frame.push(0x16); // Handshake
        frame.extend_from_slice(&[0x03, 0x03]); // TLS 1.2

        // Calculate realistic payload size; account for server/client role.
        let mut payload_size = if self.performance_mode {
            // Performance mode: choose an optimal size depending on role.
            let base = if self.is_server { 800 } else { 1200 };
            max_len.min(base).saturating_sub(5)
        } else {
            // Stealth mode: realistische Variation
            let base_range = if self.is_server { 150..700 } else { 200..800 };
            let base_size = if max_len > 1000 {
                rng.random_range(base_range)
            } else {
                rng.random_range(50..max_len.min(300))
            };
            let jitter = rng.random_range(0..50);
            (base_size + jitter).min(max_len.saturating_sub(5))
        };

        // Optional extra padding for cover traffic (stealth mode only)
        if !self.performance_mode {
            let pad_max_env = Self::padding_cap_override().unwrap_or(0);
            if pad_max_env > 0 {
                let headroom = max_len.saturating_sub(5).saturating_sub(payload_size);
                if headroom > 0 {
                    let pad = rng.random_range(0..=pad_max_env.min(headroom));
                    payload_size = payload_size.saturating_add(pad);
                }
            }
        }

        frame.extend_from_slice(&(payload_size as u16).to_be_bytes());

        // Generate realistic handshake payload
        let mut payload = vec![0u8; payload_size];
        rng.fill(&mut payload[..]);

        // Add realistic handshake message structure
        if payload_size > 10 {
            payload[0] = 0x01; // ClientHello
            payload[1..4].copy_from_slice(&((payload_size - 4) as u32).to_be_bytes()[1..]);
            payload[4..6].copy_from_slice(&[0x03, 0x03]); // TLS version
                                                          // Subtle per-profile tag to influence payload fingerprint a tiny bit
            let tag: u8 = match self.fingerprint_profile.as_str() {
                "chrome" => 0xC0,
                "firefox" => 0xF0,
                "safari" => 0xA0,
                "edge" => 0xE0,
                _ => 0x90,
            };
            // XOR into a safe byte position within header body area
            let idx = 6.min(payload.len() - 1);
            payload[idx] ^= tag;
        }

        let cipher_len = payload_size + 16;
        let mut header = frame;
        if header.len() >= 5 {
            header[3..5].copy_from_slice(&(cipher_len as u16).to_be_bytes());
        }

        // Installation is constructor-owned. If the shared context is cleared or
        // replaced unexpectedly, encryption fails closed instead of reinstalling
        // session material and risking sequence-number reuse.
        let ciphertext = self.crypto.write().encrypt_tls_cover_record(&header, &payload);

        let mut frame_out = header;
        match ciphertext {
            Ok(ct) => frame_out.extend_from_slice(&ct),
            Err(_) => {
                // Encryption failed: discard this cover frame entirely rather than
                // sending a structurally anomalous TLS record with unencrypted payload,
                // which would be trivially detectable by DPI.
                return Vec::new();
            }
        }

        if !self.performance_mode {
            // Runtime-configurable jitter in microseconds (0 disables).
            // Intentional sync sleep for timing-channel mitigation in stealth mode.
            // This runs on a dedicated sync path, NOT inside an async task.
            let jitter_us_max = Self::jitter_override_us().unwrap_or(0);
            if jitter_us_max > 0 {
                let jitter = rng.random_range(1..=jitter_us_max);
                std::thread::sleep(std::time::Duration::from_micros(jitter));
            }
        }

        frame_out
    }

    /// Marks the TLS Cover handshake as complete once transport secrets are ready.
    pub(crate) fn poll_secrets_and_install(
        &mut self,
        _crypto: &Arc<parking_lot::RwLock<crate::transport::packet::CryptoContext>>,
    ) -> Result<(), crate::error::ConnectionError> {
        self.handshake_complete = true;
        Ok(())
    }
}
