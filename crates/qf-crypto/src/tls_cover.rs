//! Connection-local TLS Cover record-cipher state.

use crate::aead::{AeadOpen, AeadSeal};
use crate::{AesGcm128, ChaCha20Poly1305};
use qf_error::ConnectionError;

const TLS_COVER_TAG_LENGTH: usize = 16;

/// Identifies the AEAD algorithm used for TLS Cover records.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsCoverCipherKind {
    /// ChaCha20-Poly1305 AEAD.
    ChaCha20Poly1305,
    /// AES-128-GCM AEAD.
    Aes128Gcm,
}

/// Borrowed TLS Cover key material accepted by the installation contract.
#[derive(Clone, Copy)]
pub enum TlsCoverKeyMaterial<'a> {
    /// ChaCha20-Poly1305 with a 256-bit key and 96-bit base IV.
    ChaCha20Poly1305 { key: &'a [u8; 32], iv: &'a [u8; 12] },
    /// AES-128-GCM with a 128-bit key and 96-bit base IV.
    Aes128Gcm { key: &'a [u8; 16], iv: &'a [u8; 12] },
}

impl TlsCoverKeyMaterial<'_> {
    fn identity(self) -> [u8; 32] {
        let mut encoded = [0u8; 45];
        let encoded_length = match self {
            Self::ChaCha20Poly1305 { key, iv } => {
                encoded[0] = 1;
                encoded[1..33].copy_from_slice(key);
                encoded[33..45].copy_from_slice(iv);
                45
            }
            Self::Aes128Gcm { key, iv } => {
                encoded[0] = 2;
                encoded[1..17].copy_from_slice(key);
                encoded[17..29].copy_from_slice(iv);
                29
            }
        };
        crate::hkdf::sha256(&encoded[..encoded_length])
    }

    fn cipher_pair(self) -> (TlsCoverCipher, TlsCoverCipher) {
        match self {
            Self::ChaCha20Poly1305 { key, iv } => (
                TlsCoverCipher::ChaCha(ChaCha20Poly1305::from_arrays(key, iv)),
                TlsCoverCipher::ChaCha(ChaCha20Poly1305::from_arrays(key, iv)),
            ),
            Self::Aes128Gcm { key, iv } => (
                TlsCoverCipher::AesGcm(AesGcm128::from_arrays(key, iv)),
                TlsCoverCipher::AesGcm(AesGcm128::from_arrays(key, iv)),
            ),
        }
    }
}

/// Result of a TLS Cover key installation request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsCoverInstallOutcome {
    /// Fresh material replaced the active cipher pair.
    Installed,
    /// The active material was already installed and counters were preserved.
    Unchanged,
}

enum TlsCoverCipher {
    ChaCha(ChaCha20Poly1305),
    AesGcm(AesGcm128),
}

impl TlsCoverCipher {
    fn kind(&self) -> TlsCoverCipherKind {
        match self {
            Self::ChaCha(_) => TlsCoverCipherKind::ChaCha20Poly1305,
            Self::AesGcm(_) => TlsCoverCipherKind::Aes128Gcm,
        }
    }

    fn seal(
        &self,
        sequence: u64,
        aad: &[u8],
        buffer: &mut [u8],
        plaintext_length: usize,
    ) -> Result<usize, ConnectionError> {
        match self {
            Self::ChaCha(cipher) => {
                cipher.seal_with_u64_counter(sequence, aad, buffer, plaintext_length, None)
            }
            Self::AesGcm(cipher) => {
                cipher.seal_with_u64_counter(sequence, aad, buffer, plaintext_length, None)
            }
        }
    }

    fn open(&self, sequence: u64, aad: &[u8], buffer: &mut [u8]) -> Result<usize, ConnectionError> {
        match self {
            Self::ChaCha(cipher) => cipher.open_with_u64_counter(sequence, aad, buffer),
            Self::AesGcm(cipher) => cipher.open_with_u64_counter(sequence, aad, buffer),
        }
    }
}

/// Cipher ownership and anti-reinstallation ledger for one TLS Cover connection.
#[derive(Default)]
pub struct TlsCoverCipherState {
    seal: Option<TlsCoverCipher>,
    open: Option<TlsCoverCipher>,
    active_identity: Option<[u8; 32]>,
    retired_identities: Vec<[u8; 32]>,
}

impl TlsCoverCipherState {
    /// Install fresh material, preserving counters for an idempotent active reinstall.
    pub fn install(
        &mut self,
        material: TlsCoverKeyMaterial<'_>,
        write_sequence: &mut u64,
        read_sequence: &mut u64,
    ) -> Result<TlsCoverInstallOutcome, ConnectionError> {
        let identity = material.identity();
        if self.active_identity == Some(identity) {
            return Ok(TlsCoverInstallOutcome::Unchanged);
        }
        if self.retired_identities.contains(&identity) {
            return Err(ConnectionError::KeyUpdateError);
        }

        let (seal, open) = material.cipher_pair();
        if let Some(active_identity) = self.active_identity.replace(identity) {
            self.retired_identities.push(active_identity);
        }
        self.seal = Some(seal);
        self.open = Some(open);
        *write_sequence = 0;
        *read_sequence = 0;
        Ok(TlsCoverInstallOutcome::Installed)
    }

    /// Return the installed cipher algorithm, if any.
    pub fn cipher_kind(&self) -> Option<TlsCoverCipherKind> {
        self.seal.as_ref().map(TlsCoverCipher::kind)
    }

    /// Return the number of retired material identities retained by the anti-reuse ledger.
    pub fn retired_identity_count(&self) -> usize {
        self.retired_identities.len()
    }

    /// Encrypt one record and advance the write sequence only after success.
    pub fn encrypt_record(
        &self,
        write_sequence: &mut u64,
        aad: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, ConnectionError> {
        let cipher = self
            .seal
            .as_ref()
            .ok_or_else(|| ConnectionError::CryptoError("crypto failure".to_string()))?;
        let sequence = *write_sequence;
        let next_sequence = sequence.checked_add(1).ok_or(ConnectionError::AeadLimitReached)?;
        let ciphertext_length = plaintext
            .len()
            .checked_add(TLS_COVER_TAG_LENGTH)
            .ok_or(ConnectionError::InvalidPacket)?;
        let mut buffer = Vec::with_capacity(ciphertext_length);
        buffer.extend_from_slice(plaintext);
        buffer.resize(ciphertext_length, 0);

        let result = cipher.seal(sequence, aad, &mut buffer, plaintext.len());
        match result {
            Ok(_) => match cipher {
                TlsCoverCipher::ChaCha(_) => crate::telemetry::FAKETLS_CHACHA_OPS.inc(),
                TlsCoverCipher::AesGcm(_) => crate::telemetry::FAKETLS_AES_GCM_OPS.inc(),
            },
            Err(_) => crate::telemetry::FAKETLS_CIPHER_FAILURES.inc(),
        }
        result?;
        *write_sequence = next_sequence;
        Ok(buffer)
    }

    /// Decrypt one record and advance the read sequence only after success.
    pub fn decrypt_record(
        &self,
        read_sequence: &mut u64,
        aad: &[u8],
        ciphertext: &mut [u8],
    ) -> Result<usize, ConnectionError> {
        let cipher = self
            .open
            .as_ref()
            .ok_or_else(|| ConnectionError::CryptoError("crypto failure".to_string()))?;
        let sequence = *read_sequence;
        let next_sequence = sequence.checked_add(1).ok_or(ConnectionError::AeadLimitReached)?;
        match cipher.open(sequence, aad, ciphertext) {
            Ok(length) => {
                *read_sequence = next_sequence;
                Ok(length)
            }
            Err(error) => {
                crate::telemetry::FAKETLS_CIPHER_FAILURES.inc();
                Err(error)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn active_reinstall_preserves_sequences_and_retired_material_cannot_return() {
        let chacha_key = [0x11; 32];
        let chacha_iv = [0x22; 12];
        let aes_key = [0x33; 16];
        let aes_iv = [0x44; 12];
        let chacha = TlsCoverKeyMaterial::ChaCha20Poly1305 { key: &chacha_key, iv: &chacha_iv };
        let aes = TlsCoverKeyMaterial::Aes128Gcm { key: &aes_key, iv: &aes_iv };
        let mut state = TlsCoverCipherState::default();
        let mut write_sequence = 7;
        let mut read_sequence = 9;

        assert_eq!(
            state.install(chacha, &mut write_sequence, &mut read_sequence),
            Ok(TlsCoverInstallOutcome::Installed)
        );
        assert_eq!((write_sequence, read_sequence), (0, 0));
        write_sequence = 3;
        read_sequence = 4;
        assert_eq!(
            state.install(chacha, &mut write_sequence, &mut read_sequence),
            Ok(TlsCoverInstallOutcome::Unchanged)
        );
        assert_eq!((write_sequence, read_sequence), (3, 4));

        assert_eq!(
            state.install(aes, &mut write_sequence, &mut read_sequence),
            Ok(TlsCoverInstallOutcome::Installed)
        );
        assert_eq!(state.cipher_kind(), Some(TlsCoverCipherKind::Aes128Gcm));
        assert_eq!(state.retired_identity_count(), 1);
        assert_eq!(
            state.install(chacha, &mut write_sequence, &mut read_sequence),
            Err(ConnectionError::KeyUpdateError)
        );
    }

    #[test]
    fn record_roundtrip_advances_directional_sequences_only_after_success() {
        let key = [0x51; 32];
        let iv = [0x61; 12];
        let mut state = TlsCoverCipherState::default();
        let mut write_sequence = 0;
        let mut read_sequence = 0;
        state
            .install(
                TlsCoverKeyMaterial::ChaCha20Poly1305 { key: &key, iv: &iv },
                &mut write_sequence,
                &mut read_sequence,
            )
            .expect("install TLS Cover material");

        let mut ciphertext = state
            .encrypt_record(&mut write_sequence, b"header", b"payload")
            .expect("encrypt TLS Cover record");
        let plaintext_length = state
            .decrypt_record(&mut read_sequence, b"header", &mut ciphertext)
            .expect("decrypt TLS Cover record");
        assert_eq!(&ciphertext[..plaintext_length], b"payload");
        assert_eq!((write_sequence, read_sequence), (1, 1));

        let mut tampered = ciphertext;
        tampered[0] ^= 0x80;
        assert!(state.decrypt_record(&mut read_sequence, b"header", &mut tampered).is_err());
        assert_eq!(read_sequence, 1);
    }

    #[test]
    fn exhausted_directional_sequences_fail_closed_without_mutation() {
        let key = [0x71; 16];
        let iv = [0x81; 12];
        let mut state = TlsCoverCipherState::default();
        let mut write_sequence = 0;
        let mut read_sequence = 0;
        state
            .install(
                TlsCoverKeyMaterial::Aes128Gcm { key: &key, iv: &iv },
                &mut write_sequence,
                &mut read_sequence,
            )
            .expect("install TLS Cover material");
        write_sequence = u64::MAX;
        read_sequence = u64::MAX;

        assert_eq!(
            state.encrypt_record(&mut write_sequence, b"header", b"payload"),
            Err(ConnectionError::AeadLimitReached)
        );
        let mut ciphertext = [0u8; TLS_COVER_TAG_LENGTH];
        assert_eq!(
            state.decrypt_record(&mut read_sequence, b"header", &mut ciphertext),
            Err(ConnectionError::AeadLimitReached)
        );
        assert_eq!((write_sequence, read_sequence), (u64::MAX, u64::MAX));
    }
}
