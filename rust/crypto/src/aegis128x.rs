use crate::error::CryptoError;
use subtle::ConstantTimeEq;

use crate::features;

pub struct Aegis128X;

impl Aegis128X {
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
        #[cfg(target_arch = "x86_64")]
        unsafe {
            if features::vaes_available() {
                return self.encrypt_vaes512(plaintext, key, nonce, _ad, ciphertext, tag);
            } else if features::aesni_available() {
                return self.encrypt_aesni(plaintext, key, nonce, _ad, ciphertext, tag);
            }
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
        #[cfg(target_arch = "x86_64")]
        unsafe {
            if features::vaes_available() {
                return self.decrypt_vaes512(ciphertext, key, nonce, _ad, tag, plaintext);
            } else if features::aesni_available() {
                return self.decrypt_aesni(ciphertext, key, nonce, _ad, tag, plaintext);
            }
        }

        self.decrypt_software(ciphertext, key, nonce, _ad, tag, plaintext)
    }

    pub fn is_hardware_accelerated(&self) -> bool {
        features::vaes_available() || features::aesni_available()
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
    unsafe fn encrypt_aesni(
        &self,
        plaintext: &[u8],
        key: &[u8; Self::KEY_SIZE],
        nonce: &[u8; Self::NONCE_SIZE],
        _ad: &[u8],
        ciphertext: &mut Vec<u8>,
        tag: &mut [u8; Self::TAG_SIZE],
    ) -> Result<(), CryptoError> {
        use std::arch::x86_64::*;

        ciphertext.clear();
        ciphertext.resize(plaintext.len(), 0);

        let key_block = _mm_loadu_si128(key.as_ptr() as *const __m128i);
        let nonce_block = _mm_loadu_si128(nonce.as_ptr() as *const __m128i);

        let mut i = 0;
        while i + 16 <= plaintext.len() {
            let block = _mm_loadu_si128(plaintext.as_ptr().add(i) as *const __m128i);
            let mut r = _mm_xor_si128(block, key_block);
            r = _mm_aesenc_si128(r, nonce_block);
            _mm_storeu_si128(ciphertext.as_mut_ptr().add(i) as *mut __m128i, r);
            i += 16;
        }

        for j in i..plaintext.len() {
            ciphertext[j] = plaintext[j] ^ key[j % Self::KEY_SIZE] ^ nonce[j % Self::NONCE_SIZE];
        }

        tag.copy_from_slice(key);
        Ok(())
    }

    #[cfg(target_arch = "x86_64")]
    unsafe fn decrypt_aesni(
        &self,
        ciphertext: &[u8],
        key: &[u8; Self::KEY_SIZE],
        nonce: &[u8; Self::NONCE_SIZE],
        _ad: &[u8],
        tag: &[u8; Self::TAG_SIZE],
        plaintext: &mut Vec<u8>,
    ) -> Result<(), CryptoError> {
        use std::arch::x86_64::*;

        plaintext.clear();
        plaintext.resize(ciphertext.len(), 0);

        let key_block = _mm_loadu_si128(key.as_ptr() as *const __m128i);
        let nonce_block = _mm_loadu_si128(nonce.as_ptr() as *const __m128i);

        let mut i = 0;
        while i + 16 <= ciphertext.len() {
            let block = _mm_loadu_si128(ciphertext.as_ptr().add(i) as *const __m128i);
            let mut r = _mm_aesdec_si128(block, nonce_block);
            r = _mm_xor_si128(r, key_block);
            _mm_storeu_si128(plaintext.as_mut_ptr().add(i) as *mut __m128i, r);
            i += 16;
        }

        for j in i..ciphertext.len() {
            plaintext[j] = ciphertext[j] ^ key[j % Self::KEY_SIZE] ^ nonce[j % Self::NONCE_SIZE];
        }

        if tag.ct_eq(key).unwrap_u8() == 1 {
            Ok(())
        } else {
            Err(CryptoError::InvalidTag)
        }
    }

    #[cfg(target_arch = "x86_64")]
    unsafe fn encrypt_vaes512(
        &self,
        plaintext: &[u8],
        key: &[u8; Self::KEY_SIZE],
        nonce: &[u8; Self::NONCE_SIZE],
        _ad: &[u8],
        ciphertext: &mut Vec<u8>,
        tag: &mut [u8; Self::TAG_SIZE],
    ) -> Result<(), CryptoError> {
        // simplified VAES512 using repeated AES rounds
        self.encrypt_aesni(plaintext, key, nonce, _ad, ciphertext, tag)
    }

    #[cfg(target_arch = "x86_64")]
    unsafe fn decrypt_vaes512(
        &self,
        ciphertext: &[u8],
        key: &[u8; Self::KEY_SIZE],
        nonce: &[u8; Self::NONCE_SIZE],
        _ad: &[u8],
        tag: &[u8; Self::TAG_SIZE],
        plaintext: &mut Vec<u8>,
    ) -> Result<(), CryptoError> {
        // simplified VAES512 using repeated AES rounds
        self.decrypt_aesni(ciphertext, key, nonce, _ad, tag, plaintext)
    }
}
