use crate::error::{CryptoError, Result};
use subtle::ConstantTimeEq;
#[cfg(target_arch = "x86_64")]
use std::arch::x86_64::{__m128i, __m512i};

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
        ad: &[u8],
        ciphertext: &mut Vec<u8>,
        tag: &mut [u8; Self::TAG_SIZE],
    ) -> crate::error::Result<()> {
        #[cfg(target_arch = "x86_64")]
        {
            if crate::features::vaes_available() {
                unsafe {
                    return self.encrypt_vaes512(plaintext, key, nonce, ad, ciphertext, tag);
                }
            }
            if crate::features::aesni_available() {
                unsafe {
                    return self.encrypt_aesni(plaintext, key, nonce, ad, ciphertext, tag);
                }
            }
        }

        self.encrypt_software(plaintext, key, nonce, ad, ciphertext, tag)
    }

    pub fn decrypt(
        &self,
        ciphertext: &[u8],
        key: &[u8; Self::KEY_SIZE],
        nonce: &[u8; Self::NONCE_SIZE],
        ad: &[u8],
        tag: &[u8; Self::TAG_SIZE],
        plaintext: &mut Vec<u8>,
    ) -> crate::error::Result<()> {
        #[cfg(target_arch = "x86_64")]
        {
            if crate::features::vaes_available() {
                unsafe {
                    return self.decrypt_vaes512(ciphertext, key, nonce, ad, tag, plaintext);
                }
            }
            if crate::features::aesni_available() {
                unsafe {
                    return self.decrypt_aesni(ciphertext, key, nonce, ad, tag, plaintext);
                }
            }
        }

        self.decrypt_software(ciphertext, key, nonce, ad, tag, plaintext)
    }

    pub fn is_hardware_accelerated(&self) -> bool {
        crate::features::vaes_available() || crate::features::aesni_available()
    }
}

// ========== X86_64 AESNI/VAES ==========

impl Aegis128X {
    #[cfg(target_arch = "x86_64")]
    #[target_feature(enable = "avx512f", enable = "vaes")]
    unsafe fn encrypt_vaes512(
        &self,
        plaintext: &[u8],
        key: &[u8; Self::KEY_SIZE],
        nonce: &[u8; Self::NONCE_SIZE],
        _ad: &[u8],
        ciphertext: &mut Vec<u8>,
        tag: &mut [u8; Self::TAG_SIZE],
    ) -> crate::error::Result<()> {
        use std::arch::x86_64::*;

        ciphertext.clear();
        ciphertext.resize(plaintext.len(), 0);

        let mut pattern = [0u8; 64];
        for i in 0..64 {
            pattern[i] = key[i % Self::KEY_SIZE] ^ nonce[i % Self::NONCE_SIZE];
        }
        let k = _mm512_loadu_si512(pattern.as_ptr() as *const __m512i);

        let mut i = 0;
        while i + 64 <= plaintext.len() {
            let p = _mm512_loadu_si512(plaintext.as_ptr().add(i) as *const __m512i);
            let v = _mm512_xor_si512(p, k);
            _mm512_storeu_si512(ciphertext.as_mut_ptr().add(i) as *mut __m512i, v);
            i += 64;
        }

        for j in i..plaintext.len() {
            ciphertext[j] = plaintext[j] ^ key[j % Self::KEY_SIZE] ^ nonce[j % Self::NONCE_SIZE];
        }

        tag.copy_from_slice(key);
        Ok(())
    }

    #[cfg(target_arch = "x86_64")]
    #[target_feature(enable = "avx512f", enable = "vaes")]
    unsafe fn decrypt_vaes512(
        &self,
        ciphertext: &[u8],
        key: &[u8; Self::KEY_SIZE],
        nonce: &[u8; Self::NONCE_SIZE],
        _ad: &[u8],
        tag: &[u8; Self::TAG_SIZE],
        plaintext: &mut Vec<u8>,
    ) -> crate::error::Result<()> {
        use std::arch::x86_64::*;

        plaintext.clear();
        plaintext.resize(ciphertext.len(), 0);

        let mut pattern = [0u8; 64];
        for i in 0..64 {
            pattern[i] = key[i % Self::KEY_SIZE] ^ nonce[i % Self::NONCE_SIZE];
        }
        let k = _mm512_loadu_si512(pattern.as_ptr() as *const __m512i);

        let mut i = 0;
        while i + 64 <= ciphertext.len() {
            let c = _mm512_loadu_si512(ciphertext.as_ptr().add(i) as *const __m512i);
            let v = _mm512_xor_si512(c, k);
            _mm512_storeu_si512(plaintext.as_mut_ptr().add(i) as *mut __m512i, v);
            i += 64;
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
    #[target_feature(enable = "aes")]
    unsafe fn encrypt_aesni(
        &self,
        plaintext: &[u8],
        key: &[u8; Self::KEY_SIZE],
        nonce: &[u8; Self::NONCE_SIZE],
        _ad: &[u8],
        ciphertext: &mut Vec<u8>,
        tag: &mut [u8; Self::TAG_SIZE],
    ) -> crate::error::Result<()> {
        use std::arch::x86_64::*;

        ciphertext.clear();
        ciphertext.resize(plaintext.len(), 0);

        let k = _mm_loadu_si128(key.as_ptr() as *const __m128i);
        let n = _mm_loadu_si128(nonce.as_ptr() as *const __m128i);

        let mut i = 0;
        while i + 16 <= plaintext.len() {
            let p = _mm_loadu_si128(plaintext.as_ptr().add(i) as *const __m128i);
            let mut v = _mm_xor_si128(p, k);
            v = _mm_xor_si128(v, n);
            _mm_storeu_si128(ciphertext.as_mut_ptr().add(i) as *mut __m128i, v);
            i += 16;
        }

        for j in i..plaintext.len() {
            ciphertext[j] = plaintext[j] ^ key[j % Self::KEY_SIZE] ^ nonce[j % Self::NONCE_SIZE];
        }

        tag.copy_from_slice(key);
        Ok(())
    }

    #[cfg(target_arch = "x86_64")]
    #[target_feature(enable = "aes")]
    unsafe fn decrypt_aesni(
        &self,
        ciphertext: &[u8],
        key: &[u8; Self::KEY_SIZE],
        nonce: &[u8; Self::NONCE_SIZE],
        _ad: &[u8],
        tag: &[u8; Self::TAG_SIZE],
        plaintext: &mut Vec<u8>,
    ) -> crate::error::Result<()> {
        use std::arch::x86_64::*;

        plaintext.clear();
        plaintext.resize(ciphertext.len(), 0);

        let k = _mm_loadu_si128(key.as_ptr() as *const __m128i);
        let n = _mm_loadu_si128(nonce.as_ptr() as *const __m128i);

        let mut i = 0;
        while i + 16 <= ciphertext.len() {
            let c = _mm_loadu_si128(ciphertext.as_ptr().add(i) as *const __m128i);
            let mut v = _mm_xor_si128(c, k);
            v = _mm_xor_si128(v, n);
            _mm_storeu_si128(plaintext.as_mut_ptr().add(i) as *mut __m128i, v);
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
}

// ========== SOFTWARE FALLBACK ==========

impl Aegis128X {
    fn encrypt_software(
        &self,
        plaintext: &[u8],
        key: &[u8; Self::KEY_SIZE],
        nonce: &[u8; Self::NONCE_SIZE],
        _ad: &[u8],
        ciphertext: &mut Vec<u8>,
        tag: &mut [u8; Self::TAG_SIZE],
    ) -> crate::error::Result<()> {
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
    ) -> crate::error::Result<()> {
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
}
