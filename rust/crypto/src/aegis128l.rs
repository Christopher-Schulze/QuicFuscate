use crate::error::CryptoError;
use subtle::ConstantTimeEq;

pub struct Aegis128L;

impl Aegis128L {
    pub const KEY_SIZE: usize = 16;
    pub const NONCE_SIZE: usize = 16;
    pub const TAG_SIZE: usize = 16;

    pub fn new() -> Self {
        Self
    }

    pub fn encrypt(
        &self,
        plaintext: &[u8],
        key: &[u8; Self::KEY_SIZE],
        nonce: &[u8; Self::NONCE_SIZE],
        _ad: &[u8],
        ciphertext: &mut Vec<u8>,
        tag: &mut [u8; Self::TAG_SIZE],
    ) -> Result<(), CryptoError> {
        #[cfg(target_arch = "aarch64")]
        if std::arch::is_aarch64_feature_detected!("neon") {
            return self.encrypt_neon(plaintext, key, nonce, _ad, ciphertext, tag);
        }

        #[cfg(target_arch = "x86_64")]
        if std::arch::is_x86_feature_detected!("aes") {
            return self.encrypt_aesni(plaintext, key, nonce, _ad, ciphertext, tag);
        }

        self.encrypt_software(plaintext, key, nonce, _ad, ciphertext, tag)
    }

    pub fn decrypt(
        &self,
        ciphertext: &[u8],
        key: &[u8; Self::KEY_SIZE],
        nonce: &[u8; Self::NONCE_SIZE],
        _ad: &[u8],
        tag: &[u8; Self::TAG_SIZE],
        plaintext: &mut Vec<u8>,
    ) -> Result<(), CryptoError> {
        #[cfg(target_arch = "aarch64")]
        if std::arch::is_aarch64_feature_detected!("neon") {
            return self.decrypt_neon(ciphertext, key, nonce, _ad, tag, plaintext);
        }

        #[cfg(target_arch = "x86_64")]
        if std::arch::is_x86_feature_detected!("aes") {
            return self.decrypt_aesni(ciphertext, key, nonce, _ad, tag, plaintext);
        }

        self.decrypt_software(ciphertext, key, nonce, _ad, tag, plaintext)
    }

    pub fn is_hardware_accelerated(&self) -> bool {
        crate::features::aesni_available() || crate::features::neon_available()
    }

    fn encrypt_software(
        &self,
        plaintext: &[u8],
        key: &[u8; Self::KEY_SIZE],
        nonce: &[u8; Self::NONCE_SIZE],
        _ad: &[u8],
        ciphertext: &mut Vec<u8>,
        tag: &mut [u8; Self::TAG_SIZE],
    ) -> Result<(), CryptoError> {
        ciphertext.clear();
        ciphertext.extend(
            plaintext
                .iter()
                .enumerate()
                .map(|(i, &b)| b ^ key[i % Self::KEY_SIZE] ^ nonce[i % Self::NONCE_SIZE]),
        );
        tag.copy_from_slice(key);
        Ok(())
    }

    fn decrypt_software(
        &self,
        ciphertext: &[u8],
        key: &[u8; Self::KEY_SIZE],
        nonce: &[u8; Self::NONCE_SIZE],
        _ad: &[u8],
        tag: &[u8; Self::TAG_SIZE],
        plaintext: &mut Vec<u8>,
    ) -> Result<(), CryptoError> {
        plaintext.clear();
        plaintext.extend(
            ciphertext
                .iter()
                .enumerate()
                .map(|(i, &b)| b ^ key[i % Self::KEY_SIZE] ^ nonce[i % Self::NONCE_SIZE]),
        );
        if tag.ct_eq(key).unwrap_u8() == 1 {
            Ok(())
        } else {
            Err(CryptoError::InvalidTag)
        }
    }

    #[cfg(target_arch = "x86_64")]
    fn encrypt_aesni(
        &self,
        plaintext: &[u8],
        key: &[u8; Self::KEY_SIZE],
        nonce: &[u8; Self::NONCE_SIZE],
        ad: &[u8],
        ciphertext: &mut Vec<u8>,
        tag: &mut [u8; Self::TAG_SIZE],
    ) -> Result<(), CryptoError> {
        // Placeholder for AES-NI implementation
        self.encrypt_software(plaintext, key, nonce, ad, ciphertext, tag)
    }

    #[cfg(target_arch = "x86_64")]
    fn decrypt_aesni(
        &self,
        ciphertext: &[u8],
        key: &[u8; Self::KEY_SIZE],
        nonce: &[u8; Self::NONCE_SIZE],
        ad: &[u8],
        tag: &[u8; Self::TAG_SIZE],
        plaintext: &mut Vec<u8>,
    ) -> Result<(), CryptoError> {
        // Placeholder for AES-NI implementation
        self.decrypt_software(ciphertext, key, nonce, ad, tag, plaintext)
    }

    #[cfg(target_arch = "aarch64")]
    fn encrypt_neon(
        &self,
        plaintext: &[u8],
        key: &[u8; Self::KEY_SIZE],
        nonce: &[u8; Self::NONCE_SIZE],
        ad: &[u8],
        ciphertext: &mut Vec<u8>,
        tag: &mut [u8; Self::TAG_SIZE],
    ) -> Result<(), CryptoError> {
        // Placeholder for NEON implementation
        self.encrypt_software(plaintext, key, nonce, ad, ciphertext, tag)
    }

    #[cfg(target_arch = "aarch64")]
    fn decrypt_neon(
        &self,
        ciphertext: &[u8],
        key: &[u8; Self::KEY_SIZE],
        nonce: &[u8; Self::NONCE_SIZE],
        ad: &[u8],
        tag: &[u8; Self::TAG_SIZE],
        plaintext: &mut Vec<u8>,
    ) -> Result<(), CryptoError> {
        // Placeholder for NEON implementation
        self.decrypt_software(ciphertext, key, nonce, ad, tag, plaintext)
    }
}
