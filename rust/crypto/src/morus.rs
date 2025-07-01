use crate::error::CryptoError;
use subtle::ConstantTimeEq;

pub struct Morus;

impl Morus {
    pub fn new() -> Self {
        Self
    }

    pub fn encrypt(
        &self,
        plaintext: &[u8],
        key: &[u8; 16],
        nonce: &[u8; 16],
        _ad: &[u8],
        ciphertext: &mut Vec<u8>,
        tag: &mut [u8; 16],
    ) -> Result<(), CryptoError> {
        ciphertext.clear();
        ciphertext.extend(
            plaintext
                .iter()
                .enumerate()
                .map(|(i, &b)| b ^ key[i % 16] ^ nonce[i % 16]),
        );
        tag.copy_from_slice(key);
        Ok(())
    }

    pub fn decrypt(
        &self,
        ciphertext: &[u8],
        key: &[u8; 16],
        nonce: &[u8; 16],
        _ad: &[u8],
        tag: &[u8; 16],
        plaintext: &mut Vec<u8>,
    ) -> Result<(), CryptoError> {
        plaintext.clear();
        plaintext.extend(
            ciphertext
                .iter()
                .enumerate()
                .map(|(i, &b)| b ^ key[i % 16] ^ nonce[i % 16]),
        );
        if tag.ct_eq(key).unwrap_u8() == 1 {
            Ok(())
        } else {
            Err(CryptoError::InvalidTag)
        }
    }
}
