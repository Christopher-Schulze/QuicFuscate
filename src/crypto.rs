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

use crate::optimize::{CpuFeature, FeatureDetector};
use aead::{Aead, KeyInit, Nonce, Payload};
use aegis::{aegis128l::Aegis128L, aegis128x::Aegis128X};
use morus::Morus;
use rand::{RngCore, rngs::OsRng};

/// Enumerates the available cipher suites.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CipherSuite {
    Aegis128X,
    Aegis128L,
    Morus1280_128,
}

/// Selects the optimal cipher suite at runtime based on CPU features.
pub struct CipherSuiteSelector {
    selected_suite: CipherSuite,
}

impl CipherSuiteSelector {
    /// Creates a new `CipherSuiteSelector` and determines the best available cipher.
    pub fn new() -> Self {
        let detector = FeatureDetector::instance();
        
        let selected_suite = if detector.has_feature(CpuFeature::VAES) {
            CipherSuite::Aegis128X
        } else if detector.has_feature(CpuFeature::AESNI) || detector.has_feature(CpuFeature::NEON) {
            CipherSuite::Aegis128L
        } else {
            CipherSuite::Morus1280_128
        };

        Self { selected_suite }
    }

    /// Returns the selected cipher suite.
    pub fn selected_suite(&self) -> CipherSuite {
        self.selected_suite
    }

    /// Encrypts data using the automatically selected cipher suite.
    pub fn encrypt(&self, key: &[u8], nonce: &[u8], ad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, &'static str> {
        match self.selected_suite {
            CipherSuite::Aegis128X => {
                let key_array: &[u8; 32] = key.try_into().map_err(|_| "Invalid key length for Aegis128X")?;
                let nonce_array: &[u8; 32] = nonce.try_into().map_err(|_| "Invalid nonce length for Aegis128X")?;
                let cipher = Aegis128X::new(key_array, nonce_array);
                let (mut ciphertext, tag) = cipher.encrypt(plaintext, ad);
                ciphertext.extend_from_slice(&tag);
                Ok(ciphertext)
            },
            CipherSuite::Aegis128L => {
                let key_array: &[u8; 16] = key.try_into().map_err(|_| "Invalid key length for Aegis")?;
                let nonce_array: &[u8; 16] = nonce.try_into().map_err(|_| "Invalid nonce length for Aegis")?;
                let cipher = Aegis128L::new(key_array, nonce_array);
                let (mut ciphertext, tag) = cipher.encrypt(plaintext, ad);
                ciphertext.extend_from_slice(&tag);
                Ok(ciphertext)
            },
            CipherSuite::Morus1280_128 => {
                let key_array: &[u8; 16] = key.try_into().map_err(|_| "Invalid key length for Morus")?;
                let nonce_array: &[u8; 16] = nonce.try_into().map_err(|_| "Invalid nonce length for Morus")?;
                let mut cipher = Morus::new(key_array, nonce_array);
                let (mut ciphertext, tag) = cipher.encrypt(plaintext, ad);
                ciphertext.extend_from_slice(&tag);
                Ok(ciphertext)
            },
        }
    }

    /// Decrypts data using the automatically selected cipher suite.
    pub fn decrypt(&self, key: &[u8], nonce: &[u8], ad: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, &'static str> {
        let payload = Payload { msg: ciphertext, aad: ad };
        match self.selected_suite {
            CipherSuite::Aegis128X => {
                if payload.msg.len() < 16 { return Err("Ciphertext too short for Aegis128X"); }
                let key_array: &[u8; 32] = key.try_into().map_err(|_| "Invalid key length for Aegis128X")?;
                let nonce_array: &[u8; 32] = nonce.try_into().map_err(|_| "Invalid nonce length for Aegis128X")?;
                let cipher = Aegis128X::new(key_array, nonce_array);
                let (ciphertext, tag_slice) = payload.msg.split_at(payload.msg.len() - 16);
                let tag = aegis::Tag::from_slice(tag_slice);
                cipher.decrypt(ciphertext, &tag, payload.aad).map_err(|_| "Decryption failed")
            },
            CipherSuite::Aegis128L => {
                if payload.msg.len() < 16 { return Err("Ciphertext too short"); }
                let key_array: &[u8; 16] = key.try_into().map_err(|_| "Invalid key length")?;
                let nonce_array: &[u8; 16] = nonce.try_into().map_err(|_| "Invalid nonce length")?;
                let cipher = Aegis128L::new(key_array, nonce_array);
                let (ciphertext, tag_slice) = payload.msg.split_at(payload.msg.len() - 16);
                let tag = aegis::Tag::from_slice(tag_slice);
                cipher.decrypt(ciphertext, &tag, payload.aad).map_err(|_| "Decryption failed")
            },
            CipherSuite::Morus1280_128 => {
                if payload.msg.len() < 16 { return Err("Ciphertext too short for Morus"); }
                let key_array: &[u8; 16] = key.try_into().map_err(|_| "Invalid key length for Morus")?;
                let nonce_array: &[u8; 16] = nonce.try_into().map_err(|_| "Invalid nonce length for Morus")?;
                let mut cipher = Morus::new(key_array, nonce_array);
                let (ciphertext, tag_slice) = payload.msg.split_at(payload.msg.len() - 16);
                let tag: &[u8; 16] = tag_slice.try_into().unwrap();
                cipher.decrypt(ciphertext, tag, payload.aad).map_err(|_| "Decryption failed")
            },
        }
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
}

impl Default for CryptoManager {
    fn default() -> Self {
        Self::new()
    }
}