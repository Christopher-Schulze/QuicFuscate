// --- Inlined: tls_cover.rs ---
// Minimal TLS Cover record layer for fingerprinting
// Generates synthetic handshake-shaped records without establishing a real
// TLS session or owning the protocol ClientHello.
// Ultra-sophisticated TLS Cover Provider for maximum stealth
use std::sync::Arc;

use qf_stealth::{TlsCoverCipherPreference, TlsCoverCipherSuite};

/// Manages synthetic TLS record generation for DPI evasion on a per-connection basis.
pub(crate) struct TlsCoverProvider {
    cipher: qf_crypto::TlsCoverCipherState,
    write_sequence: u64,
    environment: Arc<crate::env_utils::EnvSnapshot>,
    is_server: bool,
    handshake_complete: bool,
    performance_mode: bool, // When true, disable padding/jitter/timing features
    fingerprint_profile: String,
}

impl TlsCoverProvider {
    #[cfg(test)]
    pub(crate) fn cipher_preference_from_env() -> TlsCoverCipherPreference {
        let environment = crate::env_utils::EnvSnapshot::capture();
        Self::cipher_preference_from_env_with_snapshot(&environment)
    }

    fn cipher_preference_from_env_with_snapshot(
        environment: &crate::env_utils::EnvSnapshot,
    ) -> TlsCoverCipherPreference {
        TlsCoverCipherPreference::from_snapshot(environment)
    }

    fn tls_cover_profile_name(environment: &crate::env_utils::EnvSnapshot) -> String {
        environment.first(["QUICFUSCATE_TLS_COVER_PROFILE"]).unwrap_or_else(|| "chrome".to_string())
    }

    fn has_hardware_aes() -> bool {
        TlsCoverCipherPreference::has_hardware_aes()
    }

    pub(crate) fn resolve_cipher_suite(pref: TlsCoverCipherPreference) -> TlsCoverCipherSuite {
        pref.resolve()
    }

    /// Constructs a provider for the given role, deriving cover-traffic key material.
    #[allow(dead_code)]
    pub(crate) fn new(is_server: bool) -> Result<Self, crate::error::ConnectionError> {
        let environment = crate::env_utils::EnvSnapshot::capture();
        Self::new_with_snapshot(is_server, &environment)
    }

    pub(crate) fn new_with_snapshot(
        is_server: bool,
        environment: &crate::env_utils::EnvSnapshot,
    ) -> Result<Self, crate::error::ConnectionError> {
        // Load profile from ENV
        let profile = Self::tls_cover_profile_name(environment);

        let (tls_cover_key, tls_cover_iv) = Self::derive_tls_cover_material(&profile, is_server)?;

        let cipher_preference = Self::cipher_preference_from_env_with_snapshot(environment);
        let cipher_suite = Self::resolve_cipher_suite(cipher_preference);

        let mut cipher = qf_crypto::TlsCoverCipherState::default();
        let mut write_sequence = 0;
        let mut read_sequence = 0;
        match cipher_suite {
            TlsCoverCipherSuite::ChaCha20Poly1305 => {
                cipher.install(
                    qf_crypto::TlsCoverKeyMaterial::ChaCha20Poly1305 {
                        key: &tls_cover_key,
                        iv: &tls_cover_iv,
                    },
                    &mut write_sequence,
                    &mut read_sequence,
                )?;
            }
            TlsCoverCipherSuite::Aes128Gcm => {
                let mut aes_key = [0u8; 16];
                aes_key.copy_from_slice(&tls_cover_key[..16]);
                cipher.install(
                    qf_crypto::TlsCoverKeyMaterial::Aes128Gcm { key: &aes_key, iv: &tls_cover_iv },
                    &mut write_sequence,
                    &mut read_sequence,
                )?;
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
            cipher,
            write_sequence,
            environment: Arc::new(environment.clone()),
            is_server,
            handshake_complete: false,
            performance_mode: false,
            fingerprint_profile: profile,
        })
    }

    pub(crate) fn derive_tls_cover_material(
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
    pub(crate) fn derive_tls_cover_material_from_entropy(
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
        level: qf_transport_types::QuicEncryptionLevel,
        data: &[u8],
    ) -> Result<(), crate::error::ConnectionError> {
        crate::telemetry::BYTES_RECEIVED.inc_by(data.len() as u64);
        if matches!(level, qf_transport_types::QuicEncryptionLevel::Handshake) && self.is_server {
            self.handshake_complete = true;
        }
        Ok(())
    }

    /// Produces the next synthetic TLS Cover crypto frame for outbound traffic.
    pub(crate) fn next_crypto_frame(
        &mut self,
        _level: qf_transport_types::QuicEncryptionLevel,
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
        &mut self,
        max_len: usize,
    ) -> Result<Vec<u8>, crate::error::ConnectionError> {
        let Some(plan) = qf_stealth::plan_tls_cover_record(
            max_len,
            self.performance_mode,
            self.is_server,
            &self.fingerprint_profile,
            &self.environment,
        )
        .map_err(|_| crate::error::ConnectionError::InvalidPacket)?
        else {
            return Ok(Vec::new());
        };

        // Installation is constructor-owned. The connection-local cipher state is never
        // reinstalled while records are in flight, preventing sequence-number reuse.
        let ciphertext =
            self.cipher.encrypt_record(&mut self.write_sequence, &plan.header, &plan.payload)?;

        let mut frame_out = Vec::with_capacity(plan.header.len() + ciphertext.len());
        frame_out.extend_from_slice(&plan.header);
        frame_out.extend_from_slice(&ciphertext);

        if let Some(jitter) = plan.jitter {
            // Intentional sync sleep for timing-channel mitigation in stealth mode.
            // This runs on a dedicated sync path, NOT inside an async task.
            std::thread::sleep(jitter);
        }

        Ok(frame_out)
    }

    /// Marks the TLS Cover handshake as complete once transport secrets are ready.
    pub(crate) fn poll_secrets_and_install(&mut self) -> Result<(), crate::error::ConnectionError> {
        self.handshake_complete = true;
        Ok(())
    }
}
