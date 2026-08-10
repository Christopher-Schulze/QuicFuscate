// --- Inlined: tls_cover.rs ---
// Minimal TLS Cover record layer for fingerprinting
// Generates synthetic handshake-shaped records without establishing a real
// TLS session or owning the protocol ClientHello.
// Ultra-sophisticated TLS Cover Provider for maximum stealth
/// Manages synthetic TLS record generation for DPI evasion on a per-connection basis.
pub(crate) struct TlsCoverProvider {
    crypto: Arc<parking_lot::RwLock<crate::transport::packet::CryptoContext>>,
    environment: Arc<crate::env_utils::EnvSnapshot>,
    is_server: bool,
    handshake_complete: bool,
    performance_mode: bool, // When true, disable padding/jitter/timing features
    fingerprint_profile: String,
}

impl TlsCoverProvider {
    fn padding_cap_override(environment: &crate::env_utils::EnvSnapshot) -> Option<usize> {
        environment.parse_first([
            "QUICFUSCATE_STEALTH_PADDING_MAX",
            "QUICFUSCATE_STEALTH_MAX_PADDING",
        ])
    }

    fn jitter_override_us(environment: &crate::env_utils::EnvSnapshot) -> Option<u64> {
        environment.parse_first(["QUICFUSCATE_STEALTH_JITTER_US"])
    }

    #[cfg(test)]
    fn cipher_preference_from_env() -> TlsCoverCipherPreference {
        let environment = crate::env_utils::EnvSnapshot::capture();
        Self::cipher_preference_from_env_with_snapshot(&environment)
    }

    fn cipher_preference_from_env_with_snapshot(
        environment: &crate::env_utils::EnvSnapshot,
    ) -> TlsCoverCipherPreference {
        TlsCoverCipherPreference::from_snapshot(environment)
    }

    fn tls_cover_profile_name(environment: &crate::env_utils::EnvSnapshot) -> String {
        environment
            .first(["QUICFUSCATE_TLS_COVER_PROFILE"])
            .unwrap_or_else(|| "chrome".to_string())
    }

    fn has_hardware_aes() -> bool {
        TlsCoverCipherPreference::has_hardware_aes()
    }

    fn resolve_cipher_suite(pref: TlsCoverCipherPreference) -> TlsCoverCipherSuite {
        pref.resolve()
    }

    /// Constructs a provider for the given role, deriving cover-traffic key material.
    #[allow(dead_code)]
    pub(crate) fn new(
        is_server: bool,
        crypto: Arc<parking_lot::RwLock<crate::transport::packet::CryptoContext>>,
    ) -> Result<Self, crate::error::ConnectionError> {
        let environment = crate::env_utils::EnvSnapshot::capture();
        Self::new_with_snapshot(is_server, crypto, &environment)
    }

    pub(crate) fn new_with_snapshot(
        is_server: bool,
        crypto: Arc<parking_lot::RwLock<crate::transport::packet::CryptoContext>>,
        environment: &crate::env_utils::EnvSnapshot,
    ) -> Result<Self, crate::error::ConnectionError> {
        // Load profile from ENV
        let profile = Self::tls_cover_profile_name(environment);

        let (tls_cover_key, tls_cover_iv) = Self::derive_tls_cover_material(&profile, is_server)?;

        let cipher_preference = Self::cipher_preference_from_env_with_snapshot(environment);
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
            environment: Arc::new(environment.clone()),
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
        qf_stealth::derive_tls_cover_material(profile, is_server).map_err(|_| {
            crate::error::ConnectionError::CryptoError(
                "TLS cover entropy source unavailable".to_string(),
            )
        })
    }

    #[cfg(test)]
    fn derive_tls_cover_material_from_entropy(
        profile: &str,
        is_server: bool,
        entropy: &[u8; 32],
    ) -> ([u8; 32], [u8; 12]) {
        qf_stealth::derive_tls_cover_material_from_entropy(profile, is_server, entropy)
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
    ) -> Result<Option<(u64, Vec<u8>)>, crate::error::ConnectionError> {
        // Generate sophisticated TLS Cover frames for cover traffic
        if !self.handshake_complete {
            let frame = self.generate_fake_crypto_frame(max_len)?;
            if !frame.is_empty() {
                return Ok(Some((0, frame)));
            }
        }
        Ok(None)
    }

    /// Generate sophisticated fake crypto frame based on stealth mode
    fn generate_fake_crypto_frame(
        &self,
        max_len: usize,
    ) -> Result<Vec<u8>, crate::error::ConnectionError> {
        // In performance mode: Full TLS Cover but no artificial delays/padding/jitter
        // We still generate realistic TLS frames for cover traffic!

        // Stealth mode: full sophistication
        use rand::Rng;
        let mut rng = rand::rng();
        const TLS_RECORD_HEADER_LEN: usize = 5;
        const AEAD_TAG_LEN: usize = 16;
        let record_overhead = TLS_RECORD_HEADER_LEN + AEAD_TAG_LEN;
        if max_len < record_overhead {
            return Ok(Vec::new());
        }
        let payload_capacity = max_len - record_overhead;
        let max_payload = payload_capacity.min(u16::MAX as usize - AEAD_TAG_LEN);

        // Generate realistic TLS record structure
        let mut frame = Vec::with_capacity(TLS_RECORD_HEADER_LEN);

        // TLS Record Header (5 bytes): Type(1) + Version(2) + Length(2)
        frame.push(0x16); // Handshake
        frame.extend_from_slice(&[0x03, 0x03]); // TLS 1.2

        // Calculate realistic payload size; account for server/client role.
        let mut payload_size = if self.performance_mode {
            // Performance mode: choose an optimal size depending on role.
            let base = if self.is_server { 800 } else { 1200 };
            max_payload.min(base)
        } else {
            // Stealth mode: realistische Variation
            let upper = max_payload.min(if self.is_server { 700 } else { 800 });
            let lower = max_payload.min(if self.is_server { 150 } else { 200 });
            let base_size = if max_payload > 1000 {
                rng.random_range(lower..=upper)
            } else if lower == upper {
                lower
            } else {
                rng.random_range(lower..=upper)
            };
            let jitter = rng.random_range(0..50);
            base_size
                .checked_add(jitter)
                .ok_or(crate::error::ConnectionError::InvalidPacket)?
                .min(max_payload)
        };

        // Optional extra padding for cover traffic (stealth mode only)
        if !self.performance_mode {
            let pad_max_env = Self::padding_cap_override(&self.environment).unwrap_or(0);
            if pad_max_env > 0 {
                let headroom = payload_capacity.saturating_sub(payload_size);
                if headroom > 0 {
                    let pad = rng.random_range(0..=pad_max_env.min(headroom));
                    payload_size = payload_size
                        .checked_add(pad)
                        .ok_or(crate::error::ConnectionError::InvalidPacket)?;
                }
            }
        }

        let cipher_len = payload_size
            .checked_add(AEAD_TAG_LEN)
            .ok_or(crate::error::ConnectionError::InvalidPacket)?;
        frame.extend_from_slice(&(cipher_len as u16).to_be_bytes());

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

        let header = frame;

        // Installation is constructor-owned. If the shared context is cleared or
        // replaced unexpectedly, encryption fails closed instead of reinstalling
        // session material and risking sequence-number reuse.
        let ciphertext = self
            .crypto
            .write()
            .encrypt_tls_cover_record(&header, &payload)?;

        let mut frame_out = header;
        frame_out.extend_from_slice(&ciphertext);

        if !self.performance_mode {
            // Runtime-configurable jitter in microseconds (0 disables).
            // Intentional sync sleep for timing-channel mitigation in stealth mode.
            // This runs on a dedicated sync path, NOT inside an async task.
            let jitter_us_max = Self::jitter_override_us(&self.environment).unwrap_or(0);
            if jitter_us_max > 0 {
                let jitter = rng.random_range(1..=jitter_us_max);
                std::thread::sleep(std::time::Duration::from_micros(jitter));
            }
        }

        Ok(frame_out)
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
