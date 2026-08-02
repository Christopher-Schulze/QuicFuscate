// --- Inlined: tls_cover.rs ---
// Minimal TLS Cover record layer for fingerprinting
// Generates synthetic handshake-shaped records without establishing a real
// TLS session or owning the protocol ClientHello.
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

        Ok(Self {
            crypto,
            is_server,
            handshake_complete: false,
            performance_mode: false,
            fingerprint_profile: profile,
        })
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
            payload[0] = 0x01; // Synthetic ClientHello handshake marker
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
