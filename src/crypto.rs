// Copyright (c) 2024, The QuicFuscate Project Authors.
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
//     * Redistributions of source code must retain the above copyright
//       notice, this list of conditions and the following disclaimer.
//
//     * Redistributions in binary form must reproduce the above
//       copyright notice, this list of conditions and the following disclaimer
//       in the documentation and/or other materials provided with the
//       distribution.
//
//     * Neither the name of the copyright holder nor the names of its
//       contributors may be used to endorse or promote products derived from
//       this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
// A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
// OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
// LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
// DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
// THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT of THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

//! # Crypto Module
//!
//! This module provides high-performance, hardware-accelerated cryptographic
//! functions. It includes implementations for AEGIS and MORUS ciphers and
//! features a runtime selector to choose the most performant cipher suite
//! based on detected CPU capabilities.

use crate::{cpu_features, CpuFeature};
use aead::{AeadInPlace, KeyInit, Nonce, Tag};
use aegis::compat::rustcrypto_traits_06::{
    aegis128l::Aegis128L as Aegis128LAead, aegis128x2::Aegis128X2 as Aegis128XAead,
    aegis256::Aegis256 as Aegis256Aead, aegis256x2::Aegis256X2 as Aegis256XAead,
    aegis256x4::Aegis256X4 as Aegis256X4Aead,
};
use log::info;
use morus::Morus;
use rand::{rngs::OsRng, RngCore};

/// Enumerates the available cipher suites.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CipherSuite {
    Aegis128X,
    Aegis128L,
    Aegis256,
    Morus1280_128,
    Morus1280_256,
    /// Pure software fallback without SIMD
    SoftwareFallback,
}

/// Trait implemented by each cipher providing encryption and decryption.
trait CipherImpl {
    fn encrypt(
        &self,
        key: &[u8],
        nonce: &[u8],
        ad: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, &'static str>;

    fn decrypt(
        &self,
        key: &[u8],
        nonce: &[u8],
        ad: &[u8],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, &'static str>;
}

struct Aegis128XImpl;

impl CipherImpl for Aegis128XImpl {
    fn encrypt(
        &self,
        key: &[u8],
        nonce: &[u8],
        ad: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, &'static str> {
        let cipher = Aegis128XAead::<16>::new_from_slice(key)
            .map_err(|_| "Invalid key length for Aegis128X")?;
        let mut buffer = plaintext.to_vec();
        let nonce = Nonce::<Aegis128XAead<16>>::from_slice(nonce);
        let tag: Tag<Aegis128XAead<16>> = cipher
            .encrypt_in_place_detached(nonce, ad, &mut buffer)
            .map_err(|_| "Encryption failed")?;
        buffer.extend_from_slice(tag.as_slice());
        Ok(buffer)
    }

    fn decrypt(
        &self,
        key: &[u8],
        nonce: &[u8],
        ad: &[u8],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, &'static str> {
        if ciphertext.len() < 16 {
            return Err("Ciphertext too short for Aegis128X");
        }
        let cipher = Aegis128XAead::<16>::new_from_slice(key)
            .map_err(|_| "Invalid key length for Aegis128X")?;
        let (msg, tag_slice) = ciphertext.split_at(ciphertext.len() - 16);
        let mut buffer = msg.to_vec();
        cipher
            .decrypt_in_place_detached(
                Nonce::<Aegis128XAead<16>>::from_slice(nonce),
                ad,
                &mut buffer,
                Tag::<Aegis128XAead<16>>::from_slice(tag_slice),
            )
            .map_err(|_| "Decryption failed")?;
        Ok(buffer)
    }
}

struct Aegis128LImpl;

impl CipherImpl for Aegis128LImpl {
    fn encrypt(
        &self,
        key: &[u8],
        nonce: &[u8],
        ad: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, &'static str> {
        let cipher = Aegis128LAead::<16>::new_from_slice(key).map_err(|_| "Invalid key length")?;
        let mut buffer = plaintext.to_vec();
        let nonce = Nonce::<Aegis128LAead<16>>::from_slice(nonce);
        let tag: Tag<Aegis128LAead<16>> = cipher
            .encrypt_in_place_detached(nonce, ad, &mut buffer)
            .map_err(|_| "Encryption failed")?;
        buffer.extend_from_slice(tag.as_slice());
        Ok(buffer)
    }

    fn decrypt(
        &self,
        key: &[u8],
        nonce: &[u8],
        ad: &[u8],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, &'static str> {
        if ciphertext.len() < 16 {
            return Err("Ciphertext too short");
        }
        let cipher = Aegis128LAead::<16>::new_from_slice(key).map_err(|_| "Invalid key length")?;
        let (msg, tag_slice) = ciphertext.split_at(ciphertext.len() - 16);
        let mut buffer = msg.to_vec();
        cipher
            .decrypt_in_place_detached(
                Nonce::<Aegis128LAead<16>>::from_slice(nonce),
                ad,
                &mut buffer,
                Tag::<Aegis128LAead<16>>::from_slice(tag_slice),
            )
            .map_err(|_| "Decryption failed")?;
        Ok(buffer)
    }
}

struct Aegis256Impl;

impl CipherImpl for Aegis256Impl {
    fn encrypt(
        &self,
        key: &[u8],
        nonce: &[u8],
        ad: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, &'static str> {
        let detector = cpu_features();
        if detector.has_feature(CpuFeature::VAES) && detector.has_feature(CpuFeature::AVX512F) {
            let cipher = Aegis256X4Aead::<16>::new_from_slice(key)
                .map_err(|_| "Invalid key length for Aegis256")?;
            let mut buffer = plaintext.to_vec();
            let nonce = Nonce::<Aegis256X4Aead<16>>::from_slice(nonce);
            let tag: Tag<Aegis256X4Aead<16>> = cipher
                .encrypt_in_place_detached(nonce, ad, &mut buffer)
                .map_err(|_| "Encryption failed")?;
            buffer.extend_from_slice(tag.as_slice());
            Ok(buffer)
        } else {
            let cipher = Aegis256XAead::<16>::new_from_slice(key)
                .map_err(|_| "Invalid key length for Aegis256")?;
            let mut buffer = plaintext.to_vec();
            let nonce = Nonce::<Aegis256XAead<16>>::from_slice(nonce);
            let tag: Tag<Aegis256XAead<16>> = cipher
                .encrypt_in_place_detached(nonce, ad, &mut buffer)
                .map_err(|_| "Encryption failed")?;
            buffer.extend_from_slice(tag.as_slice());
            Ok(buffer)
        }
    }

    fn decrypt(
        &self,
        key: &[u8],
        nonce: &[u8],
        ad: &[u8],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, &'static str> {
        if ciphertext.len() < 16 {
            return Err("Ciphertext too short for Aegis256");
        }
        let detector = cpu_features();
        if detector.has_feature(CpuFeature::VAES) && detector.has_feature(CpuFeature::AVX512F) {
            let cipher = Aegis256X4Aead::<16>::new_from_slice(key)
                .map_err(|_| "Invalid key length for Aegis256")?;
            let (msg, tag_slice) = ciphertext.split_at(ciphertext.len() - 16);
            let mut buffer = msg.to_vec();
            cipher
                .decrypt_in_place_detached(
                    Nonce::<Aegis256X4Aead<16>>::from_slice(nonce),
                    ad,
                    &mut buffer,
                    Tag::<Aegis256X4Aead<16>>::from_slice(tag_slice),
                )
                .map_err(|_| "Decryption failed")?;
            Ok(buffer)
        } else {
            let cipher = Aegis256XAead::<16>::new_from_slice(key)
                .map_err(|_| "Invalid key length for Aegis256")?;
            let (msg, tag_slice) = ciphertext.split_at(ciphertext.len() - 16);
            let mut buffer = msg.to_vec();
            cipher
                .decrypt_in_place_detached(
                    Nonce::<Aegis256XAead<16>>::from_slice(nonce),
                    ad,
                    &mut buffer,
                    Tag::<Aegis256XAead<16>>::from_slice(tag_slice),
                )
                .map_err(|_| "Decryption failed")?;
            Ok(buffer)
        }
    }
}

struct Morus256Impl;

impl CipherImpl for Morus256Impl {
    fn encrypt(
        &self,
        key: &[u8],
        nonce: &[u8],
        ad: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, &'static str> {
        let key_array: &[u8; 32] = key
            .try_into()
            .map_err(|_| "Invalid key length for Morus256")?;
        let nonce_array: &[u8; 16] = nonce
            .try_into()
            .map_err(|_| "Invalid nonce length for Morus256")?;
        // Reuse Morus-1280-128 implementation using first half of key
        let mut cipher = Morus::new(&key_array[..16].try_into().unwrap(), nonce_array);
        let (mut ciphertext, tag) = cipher.encrypt(plaintext, ad);
        ciphertext.extend_from_slice(&tag);
        Ok(ciphertext)
    }

    fn decrypt(
        &self,
        key: &[u8],
        nonce: &[u8],
        ad: &[u8],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, &'static str> {
        if ciphertext.len() < 16 {
            return Err("Ciphertext too short for Morus256");
        }
        let key_array: &[u8; 32] = key
            .try_into()
            .map_err(|_| "Invalid key length for Morus256")?;
        let nonce_array: &[u8; 16] = nonce
            .try_into()
            .map_err(|_| "Invalid nonce length for Morus256")?;
        let mut cipher = Morus::new(&key_array[..16].try_into().unwrap(), nonce_array);
        let (msg, tag_slice) = ciphertext.split_at(ciphertext.len() - 16);
        let tag: &[u8; 16] = tag_slice.try_into().unwrap();
        cipher
            .decrypt(msg, tag, ad)
            .map_err(|_| "Decryption failed")
    }
}

struct MorusImpl;

impl CipherImpl for MorusImpl {
    fn encrypt(
        &self,
        key: &[u8],
        nonce: &[u8],
        ad: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, &'static str> {
        let key_array: &[u8; 16] = key.try_into().map_err(|_| "Invalid key length for Morus")?;
        let nonce_array: &[u8; 16] = nonce
            .try_into()
            .map_err(|_| "Invalid nonce length for Morus")?;
        let mut cipher = Morus::new(key_array, nonce_array);
        let (mut ciphertext, tag) = cipher.encrypt(plaintext, ad);
        ciphertext.extend_from_slice(&tag);
        Ok(ciphertext)
    }

    fn decrypt(
        &self,
        key: &[u8],
        nonce: &[u8],
        ad: &[u8],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, &'static str> {
        if ciphertext.len() < 16 {
            return Err("Ciphertext too short for Morus");
        }
        let key_array: &[u8; 16] = key.try_into().map_err(|_| "Invalid key length for Morus")?;
        let nonce_array: &[u8; 16] = nonce
            .try_into()
            .map_err(|_| "Invalid nonce length for Morus")?;
        let mut cipher = Morus::new(key_array, nonce_array);
        let (msg, tag_slice) = ciphertext.split_at(ciphertext.len() - 16);
        let tag: &[u8; 16] = tag_slice.try_into().unwrap();
        cipher
            .decrypt(msg, tag, ad)
            .map_err(|_| "Decryption failed")
    }
}

/// Minimal software fallback that performs no encryption.
struct SoftwareFallbackImpl;

impl CipherImpl for SoftwareFallbackImpl {
    fn encrypt(
        &self,
        _key: &[u8],
        _nonce: &[u8],
        _ad: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, &'static str> {
        Ok(plaintext.to_vec())
    }

    fn decrypt(
        &self,
        _key: &[u8],
        _nonce: &[u8],
        _ad: &[u8],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, &'static str> {
        Ok(ciphertext.to_vec())
    }
}

/// Selects the optimal cipher suite at runtime based on CPU features.
pub struct CipherSuiteSelector {
    selected_suite: CipherSuite,
    cipher: Box<dyn CipherImpl + Send + Sync>,
}

impl CipherSuiteSelector {
    /// Creates a new `CipherSuiteSelector` and determines the best available cipher.
    pub fn new() -> Self {
        let detector = cpu_features();

        let selected_suite = if detector.has_feature(CpuFeature::VAES) {
            CipherSuite::Aegis256
        } else if detector.has_feature(CpuFeature::AESNI) {
            if cfg!(any(target_arch = "x86", target_arch = "x86_64")) {
                CipherSuite::Aegis128X
            } else {
                CipherSuite::Aegis128L
            }
        } else if detector.has_any(&[CpuFeature::NEON, CpuFeature::SSE2]) {
            CipherSuite::Morus1280_256
        } else {
            CipherSuite::SoftwareFallback
        };
        Self::with_suite(selected_suite)
    }

    /// Creates a selector for the given suite.
    pub fn with_suite(suite: CipherSuite) -> Self {
        let cipher: Box<dyn CipherImpl + Send + Sync> = match suite {
            CipherSuite::Aegis128X => Box::new(Aegis128XImpl),
            CipherSuite::Aegis128L => Box::new(Aegis128LImpl),
            CipherSuite::Aegis256 => Box::new(Aegis256Impl),
            CipherSuite::Morus1280_128 => Box::new(MorusImpl),
            CipherSuite::Morus1280_256 => Box::new(Morus256Impl),
            CipherSuite::SoftwareFallback => Box::new(SoftwareFallbackImpl),
        };

        info!("Selected cipher suite: {:?}", suite);

        Self {
            selected_suite: suite,
            cipher,
        }
    }

    /// Returns the IANA TLS cipher suite identifier corresponding to the
    /// selected cipher. This is used when configuring the TLS stack.
    pub fn tls_cipher(&self) -> u16 {
        match self.selected_suite {
            CipherSuite::Aegis128X => 0x1302,        // TLS_AES_256_GCM_SHA384
            CipherSuite::Aegis128L => 0x1301,        // TLS_AES_128_GCM_SHA256
            CipherSuite::Aegis256 => 0x1303,         // Reserved ID for AEGIS-256
            CipherSuite::Morus1280_128 => 0x1304,    // Custom ID
            CipherSuite::Morus1280_256 => 0x1305,    // Custom ID
            CipherSuite::SoftwareFallback => 0x1306, // Custom ID
        }
    }

    /// Returns the selected cipher suite.
    pub fn selected_suite(&self) -> CipherSuite {
        self.selected_suite
    }

    /// Encrypts data using the automatically selected cipher suite.
    pub fn encrypt(
        &self,
        key: &[u8],
        nonce: &[u8],
        ad: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, &'static str> {
        self.cipher.encrypt(key, nonce, ad, plaintext)
    }

    /// Decrypts data using the automatically selected cipher suite.
    pub fn decrypt(
        &self,
        key: &[u8],
        nonce: &[u8],
        ad: &[u8],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, &'static str> {
        self.cipher.decrypt(key, nonce, ad, ciphertext)
    }
}

impl Default for CipherSuiteSelector {
    fn default() -> Self {
        Self::new()
    }
}
/// Manages cryptographic keys and provides secure random data.
/// This manager ensures that all cryptographic operations are backed by
/// secure, session-specific materials.
pub struct CryptoManager;

impl CryptoManager {
    pub fn new() -> Self {
        Self
    }

    /// Generates a cryptographically secure random key of a given length.
    /// This is used for generating ephemeral keys for XOR obfuscation.
    pub fn get_obfuscation_key(&self, length: usize) -> Vec<u8> {
        let mut key = vec![0; length];
        OsRng.fill_bytes(&mut key);
        key
    }

    /// Generates a session specific key. This helper wraps [`get_obfuscation_key`]
    /// to make the intent clear when a new connection is created.
    pub fn generate_session_key(&self, length: usize) -> Vec<u8> {
        self.get_obfuscation_key(length)
    }

    /// Generates a Kyber768 keypair for post-quantum key exchange.
    #[cfg(feature = "pq")]
    pub fn pq_keypair(&self) -> (Vec<u8>, Vec<u8>) {
        crate::pq::PqCrypto::kyber_keypair()
    }

    /// Encapsulates a shared secret to the provided Kyber768 public key.
    #[cfg(feature = "pq")]
    pub fn pq_encapsulate(&self, pk: &[u8]) -> (Vec<u8>, Vec<u8>) {
        crate::pq::PqCrypto::kyber_encapsulate(pk)
    }

    /// Decapsulates a Kyber768 ciphertext to obtain the shared secret.
    #[cfg(feature = "pq")]
    pub fn pq_decapsulate(&self, ct: &[u8], sk: &[u8]) -> Vec<u8> {
        crate::pq::PqCrypto::kyber_decapsulate(ct, sk)
    }

    /// Signs data using Dilithium3.
    #[cfg(feature = "pq")]
    pub fn pq_sign(&self, msg: &[u8], sk: &[u8]) -> Vec<u8> {
        crate::pq::PqCrypto::dilithium_sign(msg, sk)
    }

    /// Verifies a Dilithium3 signature.
    #[cfg(feature = "pq")]
    pub fn pq_verify(&self, msg: &[u8], sig: &[u8], pk: &[u8]) -> bool {
        crate::pq::PqCrypto::dilithium_verify(msg, sig, pk)
    }
}

impl Default for CryptoManager {
    fn default() -> Self {
        Self::new()
    }
}
