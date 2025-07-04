use crate::error::{CryptoError, Result};
use aegis::aegis128l as ref_impl;

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
        ad: &[u8],
        ciphertext: &mut Vec<u8>,
        tag: &mut [u8; Self::TAG_SIZE],
    ) -> Result<()> {
        let (ct, tg) = ref_impl::Aegis128L::<16>::new(key, nonce).encrypt(plaintext, ad);
        ciphertext.clear();
        ciphertext.extend_from_slice(&ct);
        tag.copy_from_slice(&tg);
        Ok(())
    }

    pub fn decrypt(
        &self,
        ciphertext: &[u8],
        key: &[u8; Self::KEY_SIZE],
        nonce: &[u8; Self::NONCE_SIZE],
        ad: &[u8],
        tag: &[u8; Self::TAG_SIZE],
        plaintext: &mut Vec<u8>,
    ) -> Result<()> {
        match ref_impl::Aegis128L::<16>::new(key, nonce).decrypt(ciphertext, tag, ad) {
            Ok(pt) => {
                plaintext.clear();
                plaintext.extend_from_slice(&pt);
                Ok(())
            }
            Err(ref_impl::Error::InvalidTag) => Err(CryptoError::InvalidTag),
        }
    }

    pub fn is_hardware_accelerated(&self) -> bool {
        #[cfg(target_arch = "x86_64")]
        if std::is_x86_feature_detected!("aes") {
            return true;
        }
        #[cfg(target_arch = "aarch64")]
        if std::arch::is_aarch64_feature_detected!("aes") {
            return true;
        }
        false
    }
}
