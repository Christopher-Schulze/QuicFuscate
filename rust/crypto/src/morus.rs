use crate::error::{CryptoError, Result};
use morus as ref_impl;

pub struct Morus;

impl Morus {
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
        let (ct, tg) = ref_impl::Morus::new(nonce, key).encrypt(plaintext, ad);
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
        match ref_impl::Morus::new(nonce, key).decrypt(ciphertext, tag, ad) {
            Ok(pt) => {
                plaintext.clear();
                plaintext.extend_from_slice(&pt);
                Ok(())
            }
            Err(ref_impl::Error::InvalidTag) => Err(CryptoError::InvalidTag),
        }
    }
}
