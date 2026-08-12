#![allow(unexpected_cfgs)]
//! AEGIS-128L/X4/X8 AEAD cipher implementation.
//!
//! Internal consolidated implementation with hardware-dispatched AES rounds.
//! No external crate dependency.

use crate::crypto::aead::{
    require_exact_key_iv, AeadOpen, AeadOpenItem, AeadSeal, AeadSealItem, KeyMaterialError,
};
use std::sync::atomic::Ordering;
use zeroize::Zeroize;

/// AEGIS-128L AEAD wrapper for the data-plane AEAD trait.
pub struct Aegis128LAead {
    key: [u8; 16],
    iv: [u8; 12],
}

impl Aegis128LAead {
    /// Create a new AEGIS-128L AEAD instance with exact key and IV material.
    pub fn new(aead_key: &[u8], iv: &[u8]) -> Result<Self, KeyMaterialError> {
        require_exact_key_iv("AEGIS-128L", aead_key, 16, iv, 12)?;
        let mut key = [0u8; 16];
        key.copy_from_slice(aead_key);
        let mut iv_array = [0u8; 12];
        iv_array.copy_from_slice(iv);
        Ok(Self::from_arrays(&key, &iv_array))
    }

    pub(crate) fn from_arrays(aead_key: &[u8; 16], iv: &[u8; 12]) -> Self {
        Self { key: *aead_key, iv: *iv }
    }
}

pub(crate) struct Aegis128X4Aead {
    key: [u8; 16],
    iv: [u8; 12],
}

impl Aegis128X4Aead {
    #[allow(dead_code)]
    pub(crate) fn new(aead_key: &[u8], iv: &[u8]) -> Result<Self, KeyMaterialError> {
        require_exact_key_iv("AEGIS-128X4", aead_key, 16, iv, 12)?;
        let mut key = [0u8; 16];
        key.copy_from_slice(aead_key);
        let mut iv_array = [0u8; 12];
        iv_array.copy_from_slice(iv);
        Ok(Self::from_arrays(&key, &iv_array))
    }

    pub(crate) fn from_arrays(aead_key: &[u8; 16], iv: &[u8; 12]) -> Self {
        Self { key: *aead_key, iv: *iv }
    }
}

pub(crate) struct Aegis128X8Aead {
    key: [u8; 16],
    iv: [u8; 12],
}

impl Aegis128X8Aead {
    #[allow(dead_code)]
    pub(crate) fn new(aead_key: &[u8], iv: &[u8]) -> Result<Self, KeyMaterialError> {
        require_exact_key_iv("AEGIS-128X8", aead_key, 16, iv, 12)?;
        let mut key = [0u8; 16];
        key.copy_from_slice(aead_key);
        let mut iv_array = [0u8; 12];
        iv_array.copy_from_slice(iv);
        Ok(Self::from_arrays(&key, &iv_array))
    }

    pub(crate) fn from_arrays(aead_key: &[u8; 16], iv: &[u8; 12]) -> Self {
        Self { key: *aead_key, iv: *iv }
    }
}

impl Drop for Aegis128LAead {
    fn drop(&mut self) {
        self.key.zeroize();
        crate::secret::observe_erasure("aegis_l_wrapper_key", &self.key);
        self.iv.zeroize();
        crate::secret::observe_erasure("aegis_l_wrapper_iv", &self.iv);
    }
}

impl Drop for Aegis128X4Aead {
    fn drop(&mut self) {
        self.key.zeroize();
        crate::secret::observe_erasure("aegis_x4_wrapper_key", &self.key);
        self.iv.zeroize();
        crate::secret::observe_erasure("aegis_x4_wrapper_iv", &self.iv);
    }
}

impl Drop for Aegis128X8Aead {
    fn drop(&mut self) {
        self.key.zeroize();
        crate::secret::observe_erasure("aegis_x8_wrapper_key", &self.key);
        self.iv.zeroize();
        crate::secret::observe_erasure("aegis_x8_wrapper_iv", &self.iv);
    }
}

// ============================================================================
// AEGIS Internal Implementation (consolidated internal; no external dependency)
// ============================================================================

/// AEGIS authentication/decryption error.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum AegisError {
    /// Authentication tag verification failed during decryption.
    InvalidTag,
    /// The supplied key has an invalid length.
    InvalidKeyLength { expected: usize, actual: usize },
    /// The supplied nonce has an invalid length.
    InvalidNonceLength { expected: usize, actual: usize },
}

#[cfg(feature = "std")]
impl std::fmt::Display for AegisError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AegisError::InvalidTag => write!(f, "Invalid tag"),
            AegisError::InvalidKeyLength { expected, actual } => {
                write!(f, "AEGIS key must be exactly {expected} bytes, got {actual}")
            }
            AegisError::InvalidNonceLength { expected, actual } => {
                write!(f, "AEGIS nonce must be exactly {expected} bytes, got {actual}")
            }
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for AegisError {}

// AES block used by the AEGIS-128L implementation.
//
// We always compile a portable software AESENC equivalent, and optionally dispatch
// to architecture-specific AES instructions via #[target_feature] when available.
mod aegis_aes_block;

use aegis_aes_block::AesBlock;

fn zeroize_aegis_state(state: &mut [AesBlock; 8], label: &'static str) {
    for block in state.iter_mut() {
        block.zeroize();
    }
    #[cfg(test)]
    {
        let mut snapshot = [0u8; 128];
        for (destination, block) in snapshot.chunks_exact_mut(16).zip(state.iter()) {
            destination.copy_from_slice(&block.to_bytes());
        }
        crate::secret::observe_erasure(label, &snapshot);
    }
    #[cfg(not(test))]
    {
        let _ = label;
    }
}

#[inline(always)]
fn aegis128l_update(state: &mut [AesBlock; 8], d0: AesBlock, d1: AesBlock) {
    super::prefetch_aegis_state(state.as_ptr() as *const u8);

    // Snapshot old state: the AEGIS update step is defined over the previous
    // state words, so all AESENC operations are independent and can be scheduled
    // in any order (including VAES batching).
    let old = state.clone();

    // Prepare inputs/round-keys for the 8 AESENC operations.
    // new7 = AESENC(old7, old6)
    // new6 = AESENC(old6, old5)
    // new5 = AESENC(old5, old4)
    // new4 = AESENC(old4, old3)
    // new3 = AESENC(old3, old2)
    // new2 = AESENC(old2, old1)
    // new1 = AESENC(old1, old0)
    // new0 = AESENC(old0, old7)
    let in_b = [
        old[0].to_bytes(),
        old[1].to_bytes(),
        old[2].to_bytes(),
        old[3].to_bytes(),
        old[4].to_bytes(),
        old[5].to_bytes(),
        old[6].to_bytes(),
        old[7].to_bytes(),
    ];
    let in_rk = [
        old[7].to_bytes(),
        old[0].to_bytes(),
        old[1].to_bytes(),
        old[2].to_bytes(),
        old[3].to_bytes(),
        old[4].to_bytes(),
        old[5].to_bytes(),
        old[6].to_bytes(),
    ];

    // Run the 8 AESENC operations with the best available backend.
    let out = aegis_aes_block::aesenc8_update_inputs(&in_b, &in_rk);

    state[0] = AesBlock::from_bytes(&out[0]).xor(&d0);
    state[1] = AesBlock::from_bytes(&out[1]);
    state[2] = AesBlock::from_bytes(&out[2]);
    state[3] = AesBlock::from_bytes(&out[3]);
    state[4] = AesBlock::from_bytes(&out[4]).xor(&d1);
    state[5] = AesBlock::from_bytes(&out[5]);
    state[6] = AesBlock::from_bytes(&out[6]);
    state[7] = AesBlock::from_bytes(&out[7]);
}

fn aegis128l_init_state(key: &[u8], nonce: &[u8]) -> Result<[AesBlock; 8], AegisError> {
    if key.len() != Aegis128L::KEY_SIZE {
        return Err(AegisError::InvalidKeyLength {
            expected: Aegis128L::KEY_SIZE,
            actual: key.len(),
        });
    }
    if nonce.len() != Aegis128L::NONCE_SIZE {
        return Err(AegisError::InvalidNonceLength {
            expected: Aegis128L::NONCE_SIZE,
            actual: nonce.len(),
        });
    }

    let mut key_arr = [0u8; 16];
    key_arr.copy_from_slice(key);
    let mut nonce_arr = [0u8; 16];
    nonce_arr.copy_from_slice(nonce);
    let key_block = AesBlock::from_bytes(&key_arr);
    let nonce_block = AesBlock::from_bytes(&nonce_arr);

    let c0 = AesBlock::from_bytes(&[
        0x00, 0x01, 0x01, 0x02, 0x03, 0x05, 0x08, 0x0d, 0x15, 0x22, 0x37, 0x59, 0x90, 0xe9, 0x79,
        0x62,
    ]);
    let c1 = AesBlock::from_bytes(&[
        0xdb, 0x3d, 0x18, 0x55, 0x6d, 0xc2, 0x2f, 0xf1, 0x20, 0x11, 0x31, 0x42, 0x73, 0xb5, 0x28,
        0xdd,
    ]);

    let kxn = key_block.xor(&nonce_block);
    let mut state = [
        kxn.clone(),
        c1.clone(),
        c0.clone(),
        c1.clone(),
        kxn.clone(),
        key_block.xor(&c0),
        key_block.xor(&c1),
        kxn,
    ];

    // Initialization rounds.
    for _ in 0..10 {
        aegis128l_update(&mut state, nonce_block.clone(), key_block.clone());
    }

    // Each update performs 8 AESENC rounds over the 8-word state.
    // Count initialization work as well, but aggregate to a single atomic add.
    aegis_aes_block::add_aesenc_ops(10 * 8);
    Ok(state)
}

/// AEGIS-128L AEAD cipher with 8-word AES state (pure Rust, hardware-dispatched AES rounds).
pub struct Aegis128L {
    state: [AesBlock; 8],
}

impl Drop for Aegis128L {
    fn drop(&mut self) {
        self.zeroize_state("aegis_l_inner_state");
    }
}

impl Aegis128L {
    const KEY_SIZE: usize = 16;
    const NONCE_SIZE: usize = 16;

    /// Create a new AEGIS-128L instance from a 16-byte key and 16-byte nonce.
    pub fn new(key: &[u8], nonce: &[u8]) -> Result<Self, AegisError> {
        let state = aegis128l_init_state(key, nonce)?;
        Ok(Self { state })
    }

    /// Re-initialize cipher state for a new nonce, reusing the state allocation.
    #[inline]
    pub fn reinit(&mut self, key: &[u8], nonce: &[u8]) -> Result<(), AegisError> {
        self.state = aegis128l_init_state(key, nonce)?;
        Ok(())
    }

    fn zeroize_state(&mut self, label: &'static str) {
        zeroize_aegis_state(&mut self.state, label);
    }

    #[inline(always)]
    fn update(state: &mut [AesBlock; 8], d0: AesBlock, d1: AesBlock) {
        aegis128l_update(state, d0, d1);
    }

    /// Encrypt plaintext in place with associated data; returns the 16-byte tag.
    #[inline(always)]
    pub fn encrypt_in_place(&mut self, plaintext: &mut [u8], associated_data: &[u8]) -> [u8; 16] {
        // Telemetry: each update performs 8 AESENC rounds.
        let ad_updates = (associated_data.len() as u64).div_ceil(32);
        let msg_updates = (plaintext.len() as u64).div_ceil(32);
        let fin_updates = 7u64;
        aegis_aes_block::add_aesenc_ops((ad_updates + msg_updates + fin_updates) * 8);

        // Process associated data
        for chunk in associated_data.chunks(32) {
            let mut ad0 = [0u8; 16];
            let mut ad1 = [0u8; 16];

            if chunk.len() >= 16 {
                ad0.copy_from_slice(&chunk[..16]);
                if chunk.len() >= 32 {
                    ad1.copy_from_slice(&chunk[16..32]);
                } else if chunk.len() > 16 {
                    ad1[..chunk.len() - 16].copy_from_slice(&chunk[16..]);
                }
            } else {
                ad0[..chunk.len()].copy_from_slice(chunk);
            }

            Self::update(&mut self.state, AesBlock::from_bytes(&ad0), AesBlock::from_bytes(&ad1));
        }

        // Hot path: process 64-byte chunks (two 32-byte rounds) for better ILP on aarch64 NEON and x86_64
        let mut i = 0usize;
        while i + 64 <= plaintext.len() {
            // First 32 bytes
            let z0 = self.state[6].xor(&self.state[1]).xor(&self.state[2].and(&self.state[3]));
            let z1 = self.state[2].xor(&self.state[5]).xor(&self.state[6].and(&self.state[7]));
            let mut msg0 = [0u8; 16];
            let mut msg1 = [0u8; 16];
            msg0.copy_from_slice(&plaintext[i..i + 16]);
            msg1.copy_from_slice(&plaintext[i + 16..i + 32]);
            let msg0_block = AesBlock::from_bytes(&msg0);
            let msg1_block = AesBlock::from_bytes(&msg1);
            let c0 = msg0_block.xor(&z0);
            let c1 = msg1_block.xor(&z1);
            plaintext[i..i + 16].copy_from_slice(&c0.to_bytes());
            plaintext[i + 16..i + 32].copy_from_slice(&c1.to_bytes());
            Self::update(&mut self.state, msg0_block, msg1_block);

            // Second 32 bytes
            let z0b = self.state[6].xor(&self.state[1]).xor(&self.state[2].and(&self.state[3]));
            let z1b = self.state[2].xor(&self.state[5]).xor(&self.state[6].and(&self.state[7]));
            let mut msg2 = [0u8; 16];
            let mut msg3 = [0u8; 16];
            msg2.copy_from_slice(&plaintext[i + 32..i + 48]);
            msg3.copy_from_slice(&plaintext[i + 48..i + 64]);
            let msg2_block = AesBlock::from_bytes(&msg2);
            let msg3_block = AesBlock::from_bytes(&msg3);
            let c2 = msg2_block.xor(&z0b);
            let c3 = msg3_block.xor(&z1b);
            plaintext[i + 32..i + 48].copy_from_slice(&c2.to_bytes());
            plaintext[i + 48..i + 64].copy_from_slice(&c3.to_bytes());
            Self::update(&mut self.state, msg2_block, msg3_block);

            i += 64;
        }
        // Tail handling: 32, 16..31, <16
        while i < plaintext.len() {
            let rem = plaintext.len() - i;
            let z0 = self.state[6].xor(&self.state[1]).xor(&self.state[2].and(&self.state[3]));
            let z1 = self.state[2].xor(&self.state[5]).xor(&self.state[6].and(&self.state[7]));
            if rem >= 32 {
                let mut msg0 = [0u8; 16];
                let mut msg1 = [0u8; 16];
                msg0.copy_from_slice(&plaintext[i..i + 16]);
                msg1.copy_from_slice(&plaintext[i + 16..i + 32]);
                let msg0_block = AesBlock::from_bytes(&msg0);
                let msg1_block = AesBlock::from_bytes(&msg1);
                let c0 = msg0_block.xor(&z0);
                let c1 = msg1_block.xor(&z1);
                plaintext[i..i + 16].copy_from_slice(&c0.to_bytes());
                plaintext[i + 16..i + 32].copy_from_slice(&c1.to_bytes());
                Self::update(&mut self.state, msg0_block, msg1_block);
                i += 32;
            } else if rem >= 16 {
                let mut msg0 = [0u8; 16];
                let mut msg1 = [0u8; 16];
                msg0.copy_from_slice(&plaintext[i..i + 16]);
                msg1[..rem - 16].copy_from_slice(&plaintext[i + 16..i + rem]);
                let msg0_block = AesBlock::from_bytes(&msg0);
                let msg1_block = AesBlock::from_bytes(&msg1);
                let c0 = msg0_block.xor(&z0);
                let c1 = msg1_block.xor(&z1);
                plaintext[i..i + 16].copy_from_slice(&c0.to_bytes());
                let remaining = rem - 16;
                plaintext[i + 16..i + 16 + remaining].copy_from_slice(&c1.to_bytes()[..remaining]);
                Self::update(&mut self.state, msg0_block, msg1_block);
                i += rem; // done
            } else {
                let mut msg0 = [0u8; 16];
                msg0[..rem].copy_from_slice(&plaintext[i..i + rem]);
                let msg0_block = AesBlock::from_bytes(&msg0);
                let c0 = msg0_block.xor(&z0);
                plaintext[i..i + rem].copy_from_slice(&c0.to_bytes()[..rem]);
                Self::update(&mut self.state, msg0_block, AesBlock::from_bytes(&[0u8; 16]));
                i += rem;
            }
        }

        // Finalization: mix lengths (bits) for AD and message, then 7 rounds
        let ad_bits = (associated_data.len() as u64).wrapping_mul(8);
        let msg_bits = (plaintext.len() as u64).wrapping_mul(8);
        let mut len_block = [0u8; 16];
        len_block[..8].copy_from_slice(&ad_bits.to_le_bytes());
        len_block[8..16].copy_from_slice(&msg_bits.to_le_bytes());
        let l0 = AesBlock::from_bytes(&len_block);
        let l1 = l0.clone();
        for _ in 0..7 {
            Self::update(&mut self.state, l0.clone(), l1.clone());
        }

        // Generate tag: XOR all 8 state words
        self.state[0]
            .xor(&self.state[1])
            .xor(&self.state[2])
            .xor(&self.state[3])
            .xor(&self.state[4])
            .xor(&self.state[5])
            .xor(&self.state[6])
            .xor(&self.state[7])
            .to_bytes()
    }

    /// Decrypts ciphertext in-place.
    ///
    /// # Security
    ///
    /// **CRITICAL**: If this returns `Err`, the buffer may contain partially processed data.
    /// The caller MUST discard the buffer on authentication failure and MUST NOT use it
    /// as plaintext. Use `decrypt_verified()` for automatic secure handling.
    pub(crate) fn decrypt_in_place(
        &mut self,
        ciphertext: &mut [u8],
        associated_data: &[u8],
        tag: &[u8; 16],
    ) -> Result<(), AegisError> {
        // Telemetry: each update performs 8 AESENC rounds.
        let ad_updates = (associated_data.len() as u64).div_ceil(32);
        let msg_updates = (ciphertext.len() as u64).div_ceil(32);
        let fin_updates = 7u64;
        aegis_aes_block::add_aesenc_ops((ad_updates + msg_updates + fin_updates) * 8);

        // Process associated data (same as encrypt)
        for chunk in associated_data.chunks(32) {
            let mut ad0 = [0u8; 16];
            let mut ad1 = [0u8; 16];

            if chunk.len() >= 16 {
                ad0.copy_from_slice(&chunk[..16]);
                if chunk.len() >= 32 {
                    ad1.copy_from_slice(&chunk[16..32]);
                } else if chunk.len() > 16 {
                    ad1[..chunk.len() - 16].copy_from_slice(&chunk[16..]);
                }
            } else {
                ad0[..chunk.len()].copy_from_slice(chunk);
            }
            Self::update(&mut self.state, AesBlock::from_bytes(&ad0), AesBlock::from_bytes(&ad1));
        }
        // Decrypt ciphertext: 64-byte hot path (two 32-byte rounds)
        let mut i = 0usize;
        while i + 64 <= ciphertext.len() {
            // First 32 bytes
            let z0 = self.state[6].xor(&self.state[1]).xor(&self.state[2].and(&self.state[3]));
            let z1 = self.state[2].xor(&self.state[5]).xor(&self.state[6].and(&self.state[7]));
            let mut c0 = [0u8; 16];
            let mut c1 = [0u8; 16];
            c0.copy_from_slice(&ciphertext[i..i + 16]);
            c1.copy_from_slice(&ciphertext[i + 16..i + 32]);
            let p0 = AesBlock::from_bytes(&c0).xor(&z0).to_bytes();
            let p1 = AesBlock::from_bytes(&c1).xor(&z1).to_bytes();
            ciphertext[i..i + 16].copy_from_slice(&p0);
            ciphertext[i + 16..i + 32].copy_from_slice(&p1);
            let msg0_block = AesBlock::from_bytes(&p0);
            let msg1_block = AesBlock::from_bytes(&p1);
            Self::update(&mut self.state, msg0_block, msg1_block);

            // Second 32 bytes
            let z0b = self.state[6].xor(&self.state[1]).xor(&self.state[2].and(&self.state[3]));
            let z1b = self.state[2].xor(&self.state[5]).xor(&self.state[6].and(&self.state[7]));
            let mut c2 = [0u8; 16];
            let mut c3 = [0u8; 16];
            c2.copy_from_slice(&ciphertext[i + 32..i + 48]);
            c3.copy_from_slice(&ciphertext[i + 48..i + 64]);
            let p2 = AesBlock::from_bytes(&c2).xor(&z0b).to_bytes();
            let p3 = AesBlock::from_bytes(&c3).xor(&z1b).to_bytes();
            ciphertext[i + 32..i + 48].copy_from_slice(&p2);
            ciphertext[i + 48..i + 64].copy_from_slice(&p3);
            let msg2_block = AesBlock::from_bytes(&p2);
            let msg3_block = AesBlock::from_bytes(&p3);
            Self::update(&mut self.state, msg2_block, msg3_block);

            i += 64;
        }
        // Tail handling
        while i < ciphertext.len() {
            let rem = ciphertext.len() - i;
            let z0 = self.state[6].xor(&self.state[1]).xor(&self.state[2].and(&self.state[3]));
            let z1 = self.state[2].xor(&self.state[5]).xor(&self.state[6].and(&self.state[7]));
            if rem >= 32 {
                let mut c0 = [0u8; 16];
                let mut c1 = [0u8; 16];
                c0.copy_from_slice(&ciphertext[i..i + 16]);
                c1.copy_from_slice(&ciphertext[i + 16..i + 32]);
                let p0 = AesBlock::from_bytes(&c0).xor(&z0).to_bytes();
                let p1 = AesBlock::from_bytes(&c1).xor(&z1).to_bytes();
                ciphertext[i..i + 16].copy_from_slice(&p0);
                ciphertext[i + 16..i + 32].copy_from_slice(&p1);
                let msg0_block = AesBlock::from_bytes(&p0);
                let msg1_block = AesBlock::from_bytes(&p1);
                Self::update(&mut self.state, msg0_block, msg1_block);
                i += 32;
            } else if rem >= 16 {
                let mut c0 = [0u8; 16];
                let mut c1 = [0u8; 16];
                c0.copy_from_slice(&ciphertext[i..i + 16]);
                c1[..rem - 16].copy_from_slice(&ciphertext[i + 16..i + rem]);
                let p0 = AesBlock::from_bytes(&c0).xor(&z0).to_bytes();
                let p1_full = AesBlock::from_bytes(&c1).xor(&z1).to_bytes();
                ciphertext[i..i + 16].copy_from_slice(&p0);
                let remaining = rem - 16;
                ciphertext[i + 16..i + 16 + remaining].copy_from_slice(&p1_full[..remaining]);
                let msg0_block = AesBlock::from_bytes(&p0);
                // State update must use plaintext padded with zeros beyond 'remaining'
                let mut p1_padded = [0u8; 16];
                p1_padded[..remaining].copy_from_slice(&p1_full[..remaining]);
                let msg1_block = AesBlock::from_bytes(&p1_padded);
                Self::update(&mut self.state, msg0_block, msg1_block);
                i += rem; // done
            } else {
                let mut c0 = [0u8; 16];
                c0[..rem].copy_from_slice(&ciphertext[i..i + rem]);
                let p0_full = AesBlock::from_bytes(&c0).xor(&z0).to_bytes();
                ciphertext[i..i + rem].copy_from_slice(&p0_full[..rem]);
                // Zero-pad tail plaintext for state update
                let mut p0_padded = [0u8; 16];
                p0_padded[..rem].copy_from_slice(&p0_full[..rem]);
                let msg0_block = AesBlock::from_bytes(&p0_padded);
                Self::update(&mut self.state, msg0_block, AesBlock::from_bytes(&[0u8; 16]));
                i += rem;
            }
        }

        // Finalization: mix lengths (bits) for AD and message, then 7 rounds
        let ad_bits = (associated_data.len() as u64).wrapping_mul(8);
        let msg_bits = (ciphertext.len() as u64).wrapping_mul(8);
        let mut len_block = [0u8; 16];
        len_block[..8].copy_from_slice(&ad_bits.to_le_bytes());
        len_block[8..16].copy_from_slice(&msg_bits.to_le_bytes());
        let l0 = AesBlock::from_bytes(&len_block);
        let l1 = l0.clone();
        for _ in 0..7 {
            Self::update(&mut self.state, l0.clone(), l1.clone());
        }

        // Verify tag: XOR all 8 state words
        let computed_tag = self.state[0]
            .xor(&self.state[1])
            .xor(&self.state[2])
            .xor(&self.state[3])
            .xor(&self.state[4])
            .xor(&self.state[5])
            .xor(&self.state[6])
            .xor(&self.state[7])
            .to_bytes();

        if !super::subtle_ct_eq(&computed_tag, tag) {
            return Err(AegisError::InvalidTag);
        }

        Ok(())
    }

    /// Decrypts into a new buffer and returns `Ok(plaintext)` if the `tag` verifies.
    /// On failure, the temporary buffer is zeroized and `Err(InvalidTag)` is returned.
    pub fn decrypt_verified(
        &mut self,
        ciphertext: &[u8],
        associated_data: &[u8],
        tag: &[u8; 16],
    ) -> Result<Vec<u8>, AegisError> {
        let mut buf = ciphertext.to_vec();
        match self.decrypt_in_place(&mut buf, associated_data, tag) {
            Ok(()) => Ok(buf),
            Err(e) => {
                buf.fill(0);
                Err(e)
            }
        }
    }
}

// AEGIS-128 variants for higher throughput via loop unrolling.
//
// These are not separate algorithms. They are the same AEGIS-128L core with a
// wider hot loop (4 or 8 sequential 32-byte rounds per iteration) to increase
// instruction-level parallelism and reduce loop overhead on modern CPUs.

pub(crate) struct Aegis128X4 {
    state: [AesBlock; 8],
}

impl Drop for Aegis128X4 {
    fn drop(&mut self) {
        self.zeroize_state("aegis_x4_inner_state");
    }
}

impl Aegis128X4 {
    pub(crate) fn new(key: &[u8], nonce: &[u8]) -> Result<Self, AegisError> {
        let state = aegis128l_init_state(key, nonce)?;
        Ok(Self { state })
    }

    /// Re-initialize cipher state for a new nonce, reusing the state allocation.
    #[inline]
    pub(crate) fn reinit(&mut self, key: &[u8], nonce: &[u8]) -> Result<(), AegisError> {
        self.state = aegis128l_init_state(key, nonce)?;
        Ok(())
    }

    fn zeroize_state(&mut self, label: &'static str) {
        zeroize_aegis_state(&mut self.state, label);
    }

    #[inline(always)]
    fn update(state: &mut [AesBlock; 8], d0: AesBlock, d1: AesBlock) {
        aegis128l_update(state, d0, d1);
    }

    #[inline(always)]
    pub(crate) fn encrypt_in_place(
        &mut self,
        plaintext: &mut [u8],
        associated_data: &[u8],
    ) -> [u8; 16] {
        let ad_updates = (associated_data.len() as u64).div_ceil(32);
        let msg_updates = (plaintext.len() as u64).div_ceil(32);
        let fin_updates = 7u64;
        aegis_aes_block::add_aesenc_ops((ad_updates + msg_updates + fin_updates) * 8);

        // Process associated data.
        for chunk in associated_data.chunks(32) {
            let mut ad0 = [0u8; 16];
            let mut ad1 = [0u8; 16];

            if chunk.len() >= 16 {
                ad0.copy_from_slice(&chunk[..16]);
                if chunk.len() >= 32 {
                    ad1.copy_from_slice(&chunk[16..32]);
                } else if chunk.len() > 16 {
                    ad1[..chunk.len() - 16].copy_from_slice(&chunk[16..]);
                }
            } else {
                ad0[..chunk.len()].copy_from_slice(chunk);
            }

            Self::update(&mut self.state, AesBlock::from_bytes(&ad0), AesBlock::from_bytes(&ad1));
        }

        let mut i = 0usize;

        // Hot path: 128-byte chunks (four 32-byte rounds).
        while i + 128 <= plaintext.len() {
            for r in 0..4 {
                let off = i + r * 32;
                let z0 = self.state[6].xor(&self.state[1]).xor(&self.state[2].and(&self.state[3]));
                let z1 = self.state[2].xor(&self.state[5]).xor(&self.state[6].and(&self.state[7]));
                let mut msg0 = [0u8; 16];
                let mut msg1 = [0u8; 16];
                msg0.copy_from_slice(&plaintext[off..off + 16]);
                msg1.copy_from_slice(&plaintext[off + 16..off + 32]);
                let msg0_block = AesBlock::from_bytes(&msg0);
                let msg1_block = AesBlock::from_bytes(&msg1);
                let c0 = msg0_block.xor(&z0);
                let c1 = msg1_block.xor(&z1);
                plaintext[off..off + 16].copy_from_slice(&c0.to_bytes());
                plaintext[off + 16..off + 32].copy_from_slice(&c1.to_bytes());
                Self::update(&mut self.state, msg0_block, msg1_block);
            }
            i += 128;
        }

        // Fallback hot path: 64-byte chunks.
        while i + 64 <= plaintext.len() {
            // First 32 bytes.
            let z0 = self.state[6].xor(&self.state[1]).xor(&self.state[2].and(&self.state[3]));
            let z1 = self.state[2].xor(&self.state[5]).xor(&self.state[6].and(&self.state[7]));
            let mut msg0 = [0u8; 16];
            let mut msg1 = [0u8; 16];
            msg0.copy_from_slice(&plaintext[i..i + 16]);
            msg1.copy_from_slice(&plaintext[i + 16..i + 32]);
            let msg0_block = AesBlock::from_bytes(&msg0);
            let msg1_block = AesBlock::from_bytes(&msg1);
            let c0 = msg0_block.xor(&z0);
            let c1 = msg1_block.xor(&z1);
            plaintext[i..i + 16].copy_from_slice(&c0.to_bytes());
            plaintext[i + 16..i + 32].copy_from_slice(&c1.to_bytes());
            Self::update(&mut self.state, msg0_block, msg1_block);

            // Second 32 bytes.
            let z0b = self.state[6].xor(&self.state[1]).xor(&self.state[2].and(&self.state[3]));
            let z1b = self.state[2].xor(&self.state[5]).xor(&self.state[6].and(&self.state[7]));
            let mut msg2 = [0u8; 16];
            let mut msg3 = [0u8; 16];
            msg2.copy_from_slice(&plaintext[i + 32..i + 48]);
            msg3.copy_from_slice(&plaintext[i + 48..i + 64]);
            let msg2_block = AesBlock::from_bytes(&msg2);
            let msg3_block = AesBlock::from_bytes(&msg3);
            let c2 = msg2_block.xor(&z0b);
            let c3 = msg3_block.xor(&z1b);
            plaintext[i + 32..i + 48].copy_from_slice(&c2.to_bytes());
            plaintext[i + 48..i + 64].copy_from_slice(&c3.to_bytes());
            Self::update(&mut self.state, msg2_block, msg3_block);

            i += 64;
        }

        // Tail handling: 32, 16..31, <16.
        while i < plaintext.len() {
            let rem = plaintext.len() - i;
            let z0 = self.state[6].xor(&self.state[1]).xor(&self.state[2].and(&self.state[3]));
            let z1 = self.state[2].xor(&self.state[5]).xor(&self.state[6].and(&self.state[7]));
            if rem >= 32 {
                let mut msg0 = [0u8; 16];
                let mut msg1 = [0u8; 16];
                msg0.copy_from_slice(&plaintext[i..i + 16]);
                msg1.copy_from_slice(&plaintext[i + 16..i + 32]);
                let msg0_block = AesBlock::from_bytes(&msg0);
                let msg1_block = AesBlock::from_bytes(&msg1);
                let c0 = msg0_block.xor(&z0);
                let c1 = msg1_block.xor(&z1);
                plaintext[i..i + 16].copy_from_slice(&c0.to_bytes());
                plaintext[i + 16..i + 32].copy_from_slice(&c1.to_bytes());
                Self::update(&mut self.state, msg0_block, msg1_block);
                i += 32;
            } else if rem >= 16 {
                let mut msg0 = [0u8; 16];
                let mut msg1 = [0u8; 16];
                msg0.copy_from_slice(&plaintext[i..i + 16]);
                msg1[..rem - 16].copy_from_slice(&plaintext[i + 16..i + rem]);
                let msg0_block = AesBlock::from_bytes(&msg0);
                let msg1_block = AesBlock::from_bytes(&msg1);
                let c0 = msg0_block.xor(&z0);
                let c1 = msg1_block.xor(&z1);
                plaintext[i..i + 16].copy_from_slice(&c0.to_bytes());
                let remaining = rem - 16;
                plaintext[i + 16..i + 16 + remaining].copy_from_slice(&c1.to_bytes()[..remaining]);
                Self::update(&mut self.state, msg0_block, msg1_block);
                i += rem;
            } else {
                let mut msg0 = [0u8; 16];
                msg0[..rem].copy_from_slice(&plaintext[i..i + rem]);
                let msg0_block = AesBlock::from_bytes(&msg0);
                let c0 = msg0_block.xor(&z0);
                plaintext[i..i + rem].copy_from_slice(&c0.to_bytes()[..rem]);
                Self::update(&mut self.state, msg0_block, AesBlock::from_bytes(&[0u8; 16]));
                i += rem;
            }
        }

        // Finalization: mix lengths (bits) for AD and message, then 7 rounds.
        let ad_bits = (associated_data.len() as u64).wrapping_mul(8);
        let msg_bits = (plaintext.len() as u64).wrapping_mul(8);
        let mut len_block = [0u8; 16];
        len_block[..8].copy_from_slice(&ad_bits.to_le_bytes());
        len_block[8..16].copy_from_slice(&msg_bits.to_le_bytes());
        let l0 = AesBlock::from_bytes(&len_block);
        let l1 = l0.clone();
        for _ in 0..7 {
            Self::update(&mut self.state, l0.clone(), l1.clone());
        }

        self.state[0]
            .xor(&self.state[1])
            .xor(&self.state[2])
            .xor(&self.state[3])
            .xor(&self.state[4])
            .xor(&self.state[5])
            .xor(&self.state[6])
            .xor(&self.state[7])
            .to_bytes()
    }

    pub(crate) fn decrypt_in_place(
        &mut self,
        ciphertext: &mut [u8],
        associated_data: &[u8],
        tag: &[u8; 16],
    ) -> Result<(), AegisError> {
        let ad_updates = (associated_data.len() as u64).div_ceil(32);
        let msg_updates = (ciphertext.len() as u64).div_ceil(32);
        let fin_updates = 7u64;
        aegis_aes_block::add_aesenc_ops((ad_updates + msg_updates + fin_updates) * 8);

        for chunk in associated_data.chunks(32) {
            let mut ad0 = [0u8; 16];
            let mut ad1 = [0u8; 16];

            if chunk.len() >= 16 {
                ad0.copy_from_slice(&chunk[..16]);
                if chunk.len() >= 32 {
                    ad1.copy_from_slice(&chunk[16..32]);
                } else if chunk.len() > 16 {
                    ad1[..chunk.len() - 16].copy_from_slice(&chunk[16..]);
                }
            } else {
                ad0[..chunk.len()].copy_from_slice(chunk);
            }
            Self::update(&mut self.state, AesBlock::from_bytes(&ad0), AesBlock::from_bytes(&ad1));
        }

        let mut i = 0usize;

        // Hot path: 128-byte chunks (four 32-byte rounds).
        while i + 128 <= ciphertext.len() {
            for r in 0..4 {
                let off = i + r * 32;
                let z0 = self.state[6].xor(&self.state[1]).xor(&self.state[2].and(&self.state[3]));
                let z1 = self.state[2].xor(&self.state[5]).xor(&self.state[6].and(&self.state[7]));
                let mut c0 = [0u8; 16];
                let mut c1 = [0u8; 16];
                c0.copy_from_slice(&ciphertext[off..off + 16]);
                c1.copy_from_slice(&ciphertext[off + 16..off + 32]);
                let p0 = AesBlock::from_bytes(&c0).xor(&z0).to_bytes();
                let p1 = AesBlock::from_bytes(&c1).xor(&z1).to_bytes();
                ciphertext[off..off + 16].copy_from_slice(&p0);
                ciphertext[off + 16..off + 32].copy_from_slice(&p1);
                let msg0_block = AesBlock::from_bytes(&p0);
                let msg1_block = AesBlock::from_bytes(&p1);
                Self::update(&mut self.state, msg0_block, msg1_block);
            }
            i += 128;
        }

        // Fallback hot path: 64-byte chunks.
        while i + 64 <= ciphertext.len() {
            // First 32 bytes.
            let z0 = self.state[6].xor(&self.state[1]).xor(&self.state[2].and(&self.state[3]));
            let z1 = self.state[2].xor(&self.state[5]).xor(&self.state[6].and(&self.state[7]));
            let mut c0 = [0u8; 16];
            let mut c1 = [0u8; 16];
            c0.copy_from_slice(&ciphertext[i..i + 16]);
            c1.copy_from_slice(&ciphertext[i + 16..i + 32]);
            let p0 = AesBlock::from_bytes(&c0).xor(&z0).to_bytes();
            let p1 = AesBlock::from_bytes(&c1).xor(&z1).to_bytes();
            ciphertext[i..i + 16].copy_from_slice(&p0);
            ciphertext[i + 16..i + 32].copy_from_slice(&p1);
            let msg0_block = AesBlock::from_bytes(&p0);
            let msg1_block = AesBlock::from_bytes(&p1);
            Self::update(&mut self.state, msg0_block, msg1_block);

            // Second 32 bytes.
            let z0b = self.state[6].xor(&self.state[1]).xor(&self.state[2].and(&self.state[3]));
            let z1b = self.state[2].xor(&self.state[5]).xor(&self.state[6].and(&self.state[7]));
            let mut c2 = [0u8; 16];
            let mut c3 = [0u8; 16];
            c2.copy_from_slice(&ciphertext[i + 32..i + 48]);
            c3.copy_from_slice(&ciphertext[i + 48..i + 64]);
            let p2 = AesBlock::from_bytes(&c2).xor(&z0b).to_bytes();
            let p3 = AesBlock::from_bytes(&c3).xor(&z1b).to_bytes();
            ciphertext[i + 32..i + 48].copy_from_slice(&p2);
            ciphertext[i + 48..i + 64].copy_from_slice(&p3);
            let msg2_block = AesBlock::from_bytes(&p2);
            let msg3_block = AesBlock::from_bytes(&p3);
            Self::update(&mut self.state, msg2_block, msg3_block);

            i += 64;
        }

        // Tail handling.
        while i < ciphertext.len() {
            let rem = ciphertext.len() - i;
            let z0 = self.state[6].xor(&self.state[1]).xor(&self.state[2].and(&self.state[3]));
            let z1 = self.state[2].xor(&self.state[5]).xor(&self.state[6].and(&self.state[7]));
            if rem >= 32 {
                let mut c0 = [0u8; 16];
                let mut c1 = [0u8; 16];
                c0.copy_from_slice(&ciphertext[i..i + 16]);
                c1.copy_from_slice(&ciphertext[i + 16..i + 32]);
                let p0 = AesBlock::from_bytes(&c0).xor(&z0).to_bytes();
                let p1 = AesBlock::from_bytes(&c1).xor(&z1).to_bytes();
                ciphertext[i..i + 16].copy_from_slice(&p0);
                ciphertext[i + 16..i + 32].copy_from_slice(&p1);
                let msg0_block = AesBlock::from_bytes(&p0);
                let msg1_block = AesBlock::from_bytes(&p1);
                Self::update(&mut self.state, msg0_block, msg1_block);
                i += 32;
            } else if rem >= 16 {
                let mut c0 = [0u8; 16];
                let mut c1 = [0u8; 16];
                c0.copy_from_slice(&ciphertext[i..i + 16]);
                c1[..rem - 16].copy_from_slice(&ciphertext[i + 16..i + rem]);
                let p0 = AesBlock::from_bytes(&c0).xor(&z0).to_bytes();
                let p1_full = AesBlock::from_bytes(&c1).xor(&z1).to_bytes();
                ciphertext[i..i + 16].copy_from_slice(&p0);
                let remaining = rem - 16;
                ciphertext[i + 16..i + 16 + remaining].copy_from_slice(&p1_full[..remaining]);
                let msg0_block = AesBlock::from_bytes(&p0);
                let mut p1_padded = [0u8; 16];
                p1_padded[..remaining].copy_from_slice(&p1_full[..remaining]);
                let msg1_block = AesBlock::from_bytes(&p1_padded);
                Self::update(&mut self.state, msg0_block, msg1_block);
                i += rem;
            } else {
                let mut c0 = [0u8; 16];
                c0[..rem].copy_from_slice(&ciphertext[i..i + rem]);
                let p0_full = AesBlock::from_bytes(&c0).xor(&z0).to_bytes();
                ciphertext[i..i + rem].copy_from_slice(&p0_full[..rem]);
                let mut p0_padded = [0u8; 16];
                p0_padded[..rem].copy_from_slice(&p0_full[..rem]);
                let msg0_block = AesBlock::from_bytes(&p0_padded);
                Self::update(&mut self.state, msg0_block, AesBlock::from_bytes(&[0u8; 16]));
                i += rem;
            }
        }

        let ad_bits = (associated_data.len() as u64).wrapping_mul(8);
        let msg_bits = (ciphertext.len() as u64).wrapping_mul(8);
        let mut len_block = [0u8; 16];
        len_block[..8].copy_from_slice(&ad_bits.to_le_bytes());
        len_block[8..16].copy_from_slice(&msg_bits.to_le_bytes());
        let l0 = AesBlock::from_bytes(&len_block);
        let l1 = l0.clone();
        for _ in 0..7 {
            Self::update(&mut self.state, l0.clone(), l1.clone());
        }

        let computed_tag = self.state[0]
            .xor(&self.state[1])
            .xor(&self.state[2])
            .xor(&self.state[3])
            .xor(&self.state[4])
            .xor(&self.state[5])
            .xor(&self.state[6])
            .xor(&self.state[7])
            .to_bytes();

        if !super::subtle_ct_eq(&computed_tag, tag) {
            return Err(AegisError::InvalidTag);
        }

        Ok(())
    }
}

pub(crate) struct Aegis128X8 {
    state: [AesBlock; 8],
}

impl Drop for Aegis128X8 {
    fn drop(&mut self) {
        self.zeroize_state("aegis_x8_inner_state");
    }
}

impl Aegis128X8 {
    pub(crate) fn new(key: &[u8], nonce: &[u8]) -> Result<Self, AegisError> {
        let state = aegis128l_init_state(key, nonce)?;
        Ok(Self { state })
    }

    /// Re-initialize cipher state for a new nonce, reusing the state allocation.
    #[inline]
    pub(crate) fn reinit(&mut self, key: &[u8], nonce: &[u8]) -> Result<(), AegisError> {
        self.state = aegis128l_init_state(key, nonce)?;
        Ok(())
    }

    fn zeroize_state(&mut self, label: &'static str) {
        zeroize_aegis_state(&mut self.state, label);
    }

    #[inline(always)]
    fn update(state: &mut [AesBlock; 8], d0: AesBlock, d1: AesBlock) {
        aegis128l_update(state, d0, d1);
    }

    #[inline(always)]
    pub(crate) fn encrypt_in_place(
        &mut self,
        plaintext: &mut [u8],
        associated_data: &[u8],
    ) -> [u8; 16] {
        let ad_updates = (associated_data.len() as u64).div_ceil(32);
        let msg_updates = (plaintext.len() as u64).div_ceil(32);
        let fin_updates = 7u64;
        aegis_aes_block::add_aesenc_ops((ad_updates + msg_updates + fin_updates) * 8);

        for chunk in associated_data.chunks(32) {
            let mut ad0 = [0u8; 16];
            let mut ad1 = [0u8; 16];

            if chunk.len() >= 16 {
                ad0.copy_from_slice(&chunk[..16]);
                if chunk.len() >= 32 {
                    ad1.copy_from_slice(&chunk[16..32]);
                } else if chunk.len() > 16 {
                    ad1[..chunk.len() - 16].copy_from_slice(&chunk[16..]);
                }
            } else {
                ad0[..chunk.len()].copy_from_slice(chunk);
            }

            Self::update(&mut self.state, AesBlock::from_bytes(&ad0), AesBlock::from_bytes(&ad1));
        }

        let mut i = 0usize;

        // Hot path: 256-byte chunks (eight 32-byte rounds).
        while i + 256 <= plaintext.len() {
            for r in 0..8 {
                let off = i + r * 32;
                let z0 = self.state[6].xor(&self.state[1]).xor(&self.state[2].and(&self.state[3]));
                let z1 = self.state[2].xor(&self.state[5]).xor(&self.state[6].and(&self.state[7]));
                let mut msg0 = [0u8; 16];
                let mut msg1 = [0u8; 16];
                msg0.copy_from_slice(&plaintext[off..off + 16]);
                msg1.copy_from_slice(&plaintext[off + 16..off + 32]);
                let msg0_block = AesBlock::from_bytes(&msg0);
                let msg1_block = AesBlock::from_bytes(&msg1);
                let c0 = msg0_block.xor(&z0);
                let c1 = msg1_block.xor(&z1);
                plaintext[off..off + 16].copy_from_slice(&c0.to_bytes());
                plaintext[off + 16..off + 32].copy_from_slice(&c1.to_bytes());
                Self::update(&mut self.state, msg0_block, msg1_block);
            }
            i += 256;
        }

        // Next: 128-byte chunks.
        while i + 128 <= plaintext.len() {
            for r in 0..4 {
                let off = i + r * 32;
                let z0 = self.state[6].xor(&self.state[1]).xor(&self.state[2].and(&self.state[3]));
                let z1 = self.state[2].xor(&self.state[5]).xor(&self.state[6].and(&self.state[7]));
                let mut msg0 = [0u8; 16];
                let mut msg1 = [0u8; 16];
                msg0.copy_from_slice(&plaintext[off..off + 16]);
                msg1.copy_from_slice(&plaintext[off + 16..off + 32]);
                let msg0_block = AesBlock::from_bytes(&msg0);
                let msg1_block = AesBlock::from_bytes(&msg1);
                let c0 = msg0_block.xor(&z0);
                let c1 = msg1_block.xor(&z1);
                plaintext[off..off + 16].copy_from_slice(&c0.to_bytes());
                plaintext[off + 16..off + 32].copy_from_slice(&c1.to_bytes());
                Self::update(&mut self.state, msg0_block, msg1_block);
            }
            i += 128;
        }

        // Fallback: 64-byte chunks.
        while i + 64 <= plaintext.len() {
            // First 32 bytes.
            let z0 = self.state[6].xor(&self.state[1]).xor(&self.state[2].and(&self.state[3]));
            let z1 = self.state[2].xor(&self.state[5]).xor(&self.state[6].and(&self.state[7]));
            let mut msg0 = [0u8; 16];
            let mut msg1 = [0u8; 16];
            msg0.copy_from_slice(&plaintext[i..i + 16]);
            msg1.copy_from_slice(&plaintext[i + 16..i + 32]);
            let msg0_block = AesBlock::from_bytes(&msg0);
            let msg1_block = AesBlock::from_bytes(&msg1);
            let c0 = msg0_block.xor(&z0);
            let c1 = msg1_block.xor(&z1);
            plaintext[i..i + 16].copy_from_slice(&c0.to_bytes());
            plaintext[i + 16..i + 32].copy_from_slice(&c1.to_bytes());
            Self::update(&mut self.state, msg0_block, msg1_block);

            // Second 32 bytes.
            let z0b = self.state[6].xor(&self.state[1]).xor(&self.state[2].and(&self.state[3]));
            let z1b = self.state[2].xor(&self.state[5]).xor(&self.state[6].and(&self.state[7]));
            let mut msg2 = [0u8; 16];
            let mut msg3 = [0u8; 16];
            msg2.copy_from_slice(&plaintext[i + 32..i + 48]);
            msg3.copy_from_slice(&plaintext[i + 48..i + 64]);
            let msg2_block = AesBlock::from_bytes(&msg2);
            let msg3_block = AesBlock::from_bytes(&msg3);
            let c2 = msg2_block.xor(&z0b);
            let c3 = msg3_block.xor(&z1b);
            plaintext[i + 32..i + 48].copy_from_slice(&c2.to_bytes());
            plaintext[i + 48..i + 64].copy_from_slice(&c3.to_bytes());
            Self::update(&mut self.state, msg2_block, msg3_block);

            i += 64;
        }

        while i < plaintext.len() {
            let rem = plaintext.len() - i;
            let z0 = self.state[6].xor(&self.state[1]).xor(&self.state[2].and(&self.state[3]));
            let z1 = self.state[2].xor(&self.state[5]).xor(&self.state[6].and(&self.state[7]));
            if rem >= 32 {
                let mut msg0 = [0u8; 16];
                let mut msg1 = [0u8; 16];
                msg0.copy_from_slice(&plaintext[i..i + 16]);
                msg1.copy_from_slice(&plaintext[i + 16..i + 32]);
                let msg0_block = AesBlock::from_bytes(&msg0);
                let msg1_block = AesBlock::from_bytes(&msg1);
                let c0 = msg0_block.xor(&z0);
                let c1 = msg1_block.xor(&z1);
                plaintext[i..i + 16].copy_from_slice(&c0.to_bytes());
                plaintext[i + 16..i + 32].copy_from_slice(&c1.to_bytes());
                Self::update(&mut self.state, msg0_block, msg1_block);
                i += 32;
            } else if rem >= 16 {
                let mut msg0 = [0u8; 16];
                let mut msg1 = [0u8; 16];
                msg0.copy_from_slice(&plaintext[i..i + 16]);
                msg1[..rem - 16].copy_from_slice(&plaintext[i + 16..i + rem]);
                let msg0_block = AesBlock::from_bytes(&msg0);
                let msg1_block = AesBlock::from_bytes(&msg1);
                let c0 = msg0_block.xor(&z0);
                let c1 = msg1_block.xor(&z1);
                plaintext[i..i + 16].copy_from_slice(&c0.to_bytes());
                let remaining = rem - 16;
                plaintext[i + 16..i + 16 + remaining].copy_from_slice(&c1.to_bytes()[..remaining]);
                Self::update(&mut self.state, msg0_block, msg1_block);
                i += rem;
            } else {
                let mut msg0 = [0u8; 16];
                msg0[..rem].copy_from_slice(&plaintext[i..i + rem]);
                let msg0_block = AesBlock::from_bytes(&msg0);
                let c0 = msg0_block.xor(&z0);
                plaintext[i..i + rem].copy_from_slice(&c0.to_bytes()[..rem]);
                Self::update(&mut self.state, msg0_block, AesBlock::from_bytes(&[0u8; 16]));
                i += rem;
            }
        }

        let ad_bits = (associated_data.len() as u64).wrapping_mul(8);
        let msg_bits = (plaintext.len() as u64).wrapping_mul(8);
        let mut len_block = [0u8; 16];
        len_block[..8].copy_from_slice(&ad_bits.to_le_bytes());
        len_block[8..16].copy_from_slice(&msg_bits.to_le_bytes());
        let l0 = AesBlock::from_bytes(&len_block);
        let l1 = l0.clone();
        for _ in 0..7 {
            Self::update(&mut self.state, l0.clone(), l1.clone());
        }

        self.state[0]
            .xor(&self.state[1])
            .xor(&self.state[2])
            .xor(&self.state[3])
            .xor(&self.state[4])
            .xor(&self.state[5])
            .xor(&self.state[6])
            .xor(&self.state[7])
            .to_bytes()
    }

    /// Decrypt ciphertext in place with associated data and verify the tag.
    pub fn decrypt_in_place(
        &mut self,
        ciphertext: &mut [u8],
        associated_data: &[u8],
        tag: &[u8; 16],
    ) -> Result<(), AegisError> {
        let ad_updates = (associated_data.len() as u64).div_ceil(32);
        let msg_updates = (ciphertext.len() as u64).div_ceil(32);
        let fin_updates = 7u64;
        aegis_aes_block::add_aesenc_ops((ad_updates + msg_updates + fin_updates) * 8);

        for chunk in associated_data.chunks(32) {
            let mut ad0 = [0u8; 16];
            let mut ad1 = [0u8; 16];

            if chunk.len() >= 16 {
                ad0.copy_from_slice(&chunk[..16]);
                if chunk.len() >= 32 {
                    ad1.copy_from_slice(&chunk[16..32]);
                } else if chunk.len() > 16 {
                    ad1[..chunk.len() - 16].copy_from_slice(&chunk[16..]);
                }
            } else {
                ad0[..chunk.len()].copy_from_slice(chunk);
            }
            Self::update(&mut self.state, AesBlock::from_bytes(&ad0), AesBlock::from_bytes(&ad1));
        }

        let mut i = 0usize;

        while i + 256 <= ciphertext.len() {
            for r in 0..8 {
                let off = i + r * 32;
                let z0 = self.state[6].xor(&self.state[1]).xor(&self.state[2].and(&self.state[3]));
                let z1 = self.state[2].xor(&self.state[5]).xor(&self.state[6].and(&self.state[7]));
                let mut c0 = [0u8; 16];
                let mut c1 = [0u8; 16];
                c0.copy_from_slice(&ciphertext[off..off + 16]);
                c1.copy_from_slice(&ciphertext[off + 16..off + 32]);
                let p0 = AesBlock::from_bytes(&c0).xor(&z0).to_bytes();
                let p1 = AesBlock::from_bytes(&c1).xor(&z1).to_bytes();
                ciphertext[off..off + 16].copy_from_slice(&p0);
                ciphertext[off + 16..off + 32].copy_from_slice(&p1);
                let msg0_block = AesBlock::from_bytes(&p0);
                let msg1_block = AesBlock::from_bytes(&p1);
                Self::update(&mut self.state, msg0_block, msg1_block);
            }
            i += 256;
        }

        while i + 128 <= ciphertext.len() {
            for r in 0..4 {
                let off = i + r * 32;
                let z0 = self.state[6].xor(&self.state[1]).xor(&self.state[2].and(&self.state[3]));
                let z1 = self.state[2].xor(&self.state[5]).xor(&self.state[6].and(&self.state[7]));
                let mut c0 = [0u8; 16];
                let mut c1 = [0u8; 16];
                c0.copy_from_slice(&ciphertext[off..off + 16]);
                c1.copy_from_slice(&ciphertext[off + 16..off + 32]);
                let p0 = AesBlock::from_bytes(&c0).xor(&z0).to_bytes();
                let p1 = AesBlock::from_bytes(&c1).xor(&z1).to_bytes();
                ciphertext[off..off + 16].copy_from_slice(&p0);
                ciphertext[off + 16..off + 32].copy_from_slice(&p1);
                let msg0_block = AesBlock::from_bytes(&p0);
                let msg1_block = AesBlock::from_bytes(&p1);
                Self::update(&mut self.state, msg0_block, msg1_block);
            }
            i += 128;
        }

        while i + 64 <= ciphertext.len() {
            let z0 = self.state[6].xor(&self.state[1]).xor(&self.state[2].and(&self.state[3]));
            let z1 = self.state[2].xor(&self.state[5]).xor(&self.state[6].and(&self.state[7]));
            let mut c0 = [0u8; 16];
            let mut c1 = [0u8; 16];
            c0.copy_from_slice(&ciphertext[i..i + 16]);
            c1.copy_from_slice(&ciphertext[i + 16..i + 32]);
            let p0 = AesBlock::from_bytes(&c0).xor(&z0).to_bytes();
            let p1 = AesBlock::from_bytes(&c1).xor(&z1).to_bytes();
            ciphertext[i..i + 16].copy_from_slice(&p0);
            ciphertext[i + 16..i + 32].copy_from_slice(&p1);
            let msg0_block = AesBlock::from_bytes(&p0);
            let msg1_block = AesBlock::from_bytes(&p1);
            Self::update(&mut self.state, msg0_block, msg1_block);

            let z0b = self.state[6].xor(&self.state[1]).xor(&self.state[2].and(&self.state[3]));
            let z1b = self.state[2].xor(&self.state[5]).xor(&self.state[6].and(&self.state[7]));
            let mut c2 = [0u8; 16];
            let mut c3 = [0u8; 16];
            c2.copy_from_slice(&ciphertext[i + 32..i + 48]);
            c3.copy_from_slice(&ciphertext[i + 48..i + 64]);
            let p2 = AesBlock::from_bytes(&c2).xor(&z0b).to_bytes();
            let p3 = AesBlock::from_bytes(&c3).xor(&z1b).to_bytes();
            ciphertext[i + 32..i + 48].copy_from_slice(&p2);
            ciphertext[i + 48..i + 64].copy_from_slice(&p3);
            let msg2_block = AesBlock::from_bytes(&p2);
            let msg3_block = AesBlock::from_bytes(&p3);
            Self::update(&mut self.state, msg2_block, msg3_block);

            i += 64;
        }

        while i < ciphertext.len() {
            let rem = ciphertext.len() - i;
            let z0 = self.state[6].xor(&self.state[1]).xor(&self.state[2].and(&self.state[3]));
            let z1 = self.state[2].xor(&self.state[5]).xor(&self.state[6].and(&self.state[7]));
            if rem >= 32 {
                let mut c0 = [0u8; 16];
                let mut c1 = [0u8; 16];
                c0.copy_from_slice(&ciphertext[i..i + 16]);
                c1.copy_from_slice(&ciphertext[i + 16..i + 32]);
                let p0 = AesBlock::from_bytes(&c0).xor(&z0).to_bytes();
                let p1 = AesBlock::from_bytes(&c1).xor(&z1).to_bytes();
                ciphertext[i..i + 16].copy_from_slice(&p0);
                ciphertext[i + 16..i + 32].copy_from_slice(&p1);
                let msg0_block = AesBlock::from_bytes(&p0);
                let msg1_block = AesBlock::from_bytes(&p1);
                Self::update(&mut self.state, msg0_block, msg1_block);
                i += 32;
            } else if rem >= 16 {
                let mut c0 = [0u8; 16];
                let mut c1 = [0u8; 16];
                c0.copy_from_slice(&ciphertext[i..i + 16]);
                c1[..rem - 16].copy_from_slice(&ciphertext[i + 16..i + rem]);
                let p0 = AesBlock::from_bytes(&c0).xor(&z0).to_bytes();
                let p1_full = AesBlock::from_bytes(&c1).xor(&z1).to_bytes();
                ciphertext[i..i + 16].copy_from_slice(&p0);
                let remaining = rem - 16;
                ciphertext[i + 16..i + 16 + remaining].copy_from_slice(&p1_full[..remaining]);
                let msg0_block = AesBlock::from_bytes(&p0);
                let mut p1_padded = [0u8; 16];
                p1_padded[..remaining].copy_from_slice(&p1_full[..remaining]);
                let msg1_block = AesBlock::from_bytes(&p1_padded);
                Self::update(&mut self.state, msg0_block, msg1_block);
                i += rem;
            } else {
                let mut c0 = [0u8; 16];
                c0[..rem].copy_from_slice(&ciphertext[i..i + rem]);
                let p0_full = AesBlock::from_bytes(&c0).xor(&z0).to_bytes();
                ciphertext[i..i + rem].copy_from_slice(&p0_full[..rem]);
                let mut p0_padded = [0u8; 16];
                p0_padded[..rem].copy_from_slice(&p0_full[..rem]);
                let msg0_block = AesBlock::from_bytes(&p0_padded);
                Self::update(&mut self.state, msg0_block, AesBlock::from_bytes(&[0u8; 16]));
                i += rem;
            }
        }

        let ad_bits = (associated_data.len() as u64).wrapping_mul(8);
        let msg_bits = (ciphertext.len() as u64).wrapping_mul(8);
        let mut len_block = [0u8; 16];
        len_block[..8].copy_from_slice(&ad_bits.to_le_bytes());
        len_block[8..16].copy_from_slice(&msg_bits.to_le_bytes());
        let l0 = AesBlock::from_bytes(&len_block);
        let l1 = l0.clone();
        for _ in 0..7 {
            Self::update(&mut self.state, l0.clone(), l1.clone());
        }

        let computed_tag = self.state[0]
            .xor(&self.state[1])
            .xor(&self.state[2])
            .xor(&self.state[3])
            .xor(&self.state[4])
            .xor(&self.state[5])
            .xor(&self.state[6])
            .xor(&self.state[7])
            .to_bytes();

        if !super::subtle_ct_eq(&computed_tag, tag) {
            return Err(AegisError::InvalidTag);
        }

        Ok(())
    }
}

#[inline]
fn aegis_batch_homogeneous_seal(items: &[AeadSealItem<'_>]) -> bool {
    if items.len() <= 1 {
        return false;
    }
    let first = &items[0];
    items[1..]
        .iter()
        .all(|it| it.plaintext_len == first.plaintext_len && it.ad.len() == first.ad.len())
}

#[inline]
fn aegis_batch_homogeneous_open(items: &[AeadOpenItem<'_>]) -> bool {
    if items.len() <= 1 {
        return false;
    }
    let first = &items[0];
    items[1..].iter().all(|it| it.buf.len() == first.buf.len() && it.ad.len() == first.ad.len())
}

#[inline]
fn record_aegis_batch_ops(count: usize, homogeneous: bool) {
    if count > 1 && homogeneous {
        qf_telemetry::AEGIS_BATCH_OPS.fetch_add(count as u64, Ordering::Relaxed);
    }
}

// Implement AeadSeal and AeadOpen for Aegis128LAead
impl AeadSeal for Aegis128LAead {
    fn seal_with_u64_counter(
        &self,
        counter: u64,
        ad: &[u8],
        buf: &mut [u8],
        len: usize,
        _extra_in: Option<&[u8]>,
    ) -> Result<usize, crate::error::ConnectionError> {
        use crate::error::ConnectionError;
        let sealed = crate::crypto::checked_seal_capacity(buf.len(), len)?;
        let nonce16 = super::make_nonce16(&self.iv, counter)?;
        let mut cipher = crate::crypto::Aegis128L::new(&self.key, &nonce16)
            .map_err(|_| ConnectionError::CryptoError("crypto failure".into()))?;
        let (pt, rest) = buf.split_at_mut(len);
        let tag = cipher.encrypt_in_place(pt, ad);
        rest[..16].copy_from_slice(&tag);
        Ok(sealed)
    }

    fn supports_batch_seal(&self) -> bool {
        true
    }

    fn seal_batch(
        &self,
        items: &mut [AeadSealItem<'_>],
    ) -> Result<(), crate::error::ConnectionError> {
        use crate::error::ConnectionError;
        if items.is_empty() {
            return Ok(());
        }
        let homogeneous = aegis_batch_homogeneous_seal(items);
        let first = &items[0];
        if first.buf.len() < crate::crypto::sealed_len(first.plaintext_len)? {
            return Err(ConnectionError::BufferTooShort);
        }
        let first_nonce = super::make_nonce16(&self.iv, first.counter)?;
        let mut cipher = Aegis128L::new(&self.key, &first_nonce)
            .map_err(|_| ConnectionError::CryptoError("crypto failure".into()))?;
        for (index, item) in items.iter_mut().enumerate() {
            if index > 0 {
                if item.buf.len() < crate::crypto::sealed_len(item.plaintext_len)? {
                    return Err(ConnectionError::BufferTooShort);
                }
                let nonce16 = super::make_nonce16(&self.iv, item.counter)?;
                cipher
                    .reinit(&self.key, &nonce16)
                    .map_err(|_| ConnectionError::CryptoError("crypto failure".into()))?;
            }
            let (pt, rest) = item.buf.split_at_mut(item.plaintext_len);
            let tag = cipher.encrypt_in_place(pt, item.ad);
            rest[..16].copy_from_slice(&tag);
        }
        record_aegis_batch_ops(items.len(), homogeneous);
        Ok(())
    }
}

impl AeadOpen for Aegis128LAead {
    fn open_with_u64_counter(
        &self,
        counter: u64,
        ad: &[u8],
        buf: &mut [u8],
    ) -> Result<usize, crate::error::ConnectionError> {
        use crate::error::ConnectionError;
        if buf.len() < 16 {
            return Err(ConnectionError::BufferTooShort);
        }
        let ct_len = buf.len() - 16;
        let (ct, tag_in) = buf.split_at_mut(ct_len);
        let mut tag = [0u8; 16];
        tag.copy_from_slice(&tag_in[..16]);
        let nonce16 = super::make_nonce16(&self.iv, counter)?;
        let mut cipher = crate::crypto::Aegis128L::new(&self.key, &nonce16)
            .map_err(|_| ConnectionError::CryptoError("crypto failure".into()))?;
        cipher
            .decrypt_in_place(ct, ad, &tag)
            .map_err(|_| ConnectionError::CryptoError("crypto failure".into()))?;
        Ok(ct_len)
    }

    fn supports_batch_open(&self) -> bool {
        true
    }

    fn open_batch(
        &self,
        items: &mut [AeadOpenItem<'_>],
    ) -> Result<(), crate::error::ConnectionError> {
        use crate::error::ConnectionError;
        if items.is_empty() {
            return Ok(());
        }
        let homogeneous = aegis_batch_homogeneous_open(items);
        let first = &items[0];
        if first.buf.len() < 16 {
            return Err(ConnectionError::BufferTooShort);
        }
        let first_nonce = super::make_nonce16(&self.iv, first.counter)?;
        let mut cipher = Aegis128L::new(&self.key, &first_nonce)
            .map_err(|_| ConnectionError::CryptoError("crypto failure".into()))?;
        for (index, item) in items.iter_mut().enumerate() {
            if index > 0 {
                if item.buf.len() < 16 {
                    return Err(ConnectionError::BufferTooShort);
                }
                let nonce16 = super::make_nonce16(&self.iv, item.counter)?;
                cipher
                    .reinit(&self.key, &nonce16)
                    .map_err(|_| ConnectionError::CryptoError("crypto failure".into()))?;
            }
            let ct_len = item.buf.len() - 16;
            let (ct, tag_in) = item.buf.split_at_mut(ct_len);
            let mut tag = [0u8; 16];
            tag.copy_from_slice(&tag_in[..16]);
            cipher
                .decrypt_in_place(ct, item.ad, &tag)
                .map_err(|_| ConnectionError::CryptoError("crypto failure".into()))?;
        }
        record_aegis_batch_ops(items.len(), homogeneous);
        Ok(())
    }
}

impl AeadSeal for Aegis128X4Aead {
    fn seal_with_u64_counter(
        &self,
        counter: u64,
        ad: &[u8],
        buf: &mut [u8],
        len: usize,
        _extra_in: Option<&[u8]>,
    ) -> Result<usize, crate::error::ConnectionError> {
        let sealed = crate::crypto::sealed_len(len)?;
        let mut item = AeadSealItem { counter, ad, buf, plaintext_len: len };
        self.seal_batch(core::slice::from_mut(&mut item))?;
        Ok(sealed)
    }

    fn supports_batch_seal(&self) -> bool {
        true
    }

    fn seal_batch(
        &self,
        items: &mut [AeadSealItem<'_>],
    ) -> Result<(), crate::error::ConnectionError> {
        aegis_x4_seal_batch(&self.key, &self.iv, items)
    }
}

impl AeadOpen for Aegis128X4Aead {
    fn open_with_u64_counter(
        &self,
        counter: u64,
        ad: &[u8],
        buf: &mut [u8],
    ) -> Result<usize, crate::error::ConnectionError> {
        use crate::error::ConnectionError;
        if buf.len() < 16 {
            return Err(ConnectionError::BufferTooShort);
        }
        let ct_len = buf.len() - 16;
        let mut item = AeadOpenItem { counter, ad, buf };
        self.open_batch(core::slice::from_mut(&mut item))?;
        Ok(ct_len)
    }

    fn supports_batch_open(&self) -> bool {
        true
    }

    fn open_batch(
        &self,
        items: &mut [AeadOpenItem<'_>],
    ) -> Result<(), crate::error::ConnectionError> {
        aegis_x4_open_batch(&self.key, &self.iv, items)
    }
}

impl AeadSeal for Aegis128X8Aead {
    fn seal_with_u64_counter(
        &self,
        counter: u64,
        ad: &[u8],
        buf: &mut [u8],
        len: usize,
        _extra_in: Option<&[u8]>,
    ) -> Result<usize, crate::error::ConnectionError> {
        let sealed = crate::crypto::sealed_len(len)?;
        let mut item = AeadSealItem { counter, ad, buf, plaintext_len: len };
        self.seal_batch(core::slice::from_mut(&mut item))?;
        Ok(sealed)
    }

    fn supports_batch_seal(&self) -> bool {
        true
    }

    fn seal_batch(
        &self,
        items: &mut [AeadSealItem<'_>],
    ) -> Result<(), crate::error::ConnectionError> {
        aegis_x8_seal_batch(&self.key, &self.iv, items)
    }
}

impl AeadOpen for Aegis128X8Aead {
    fn open_with_u64_counter(
        &self,
        counter: u64,
        ad: &[u8],
        buf: &mut [u8],
    ) -> Result<usize, crate::error::ConnectionError> {
        use crate::error::ConnectionError;
        if buf.len() < 16 {
            return Err(ConnectionError::BufferTooShort);
        }
        let ct_len = buf.len() - 16;
        let mut item = AeadOpenItem { counter, ad, buf };
        self.open_batch(core::slice::from_mut(&mut item))?;
        Ok(ct_len)
    }

    fn supports_batch_open(&self) -> bool {
        true
    }

    fn open_batch(
        &self,
        items: &mut [AeadOpenItem<'_>],
    ) -> Result<(), crate::error::ConnectionError> {
        aegis_x8_open_batch(&self.key, &self.iv, items)
    }
}

fn aegis_x4_seal_batch(
    key: &[u8; 16],
    iv: &[u8; 12],
    items: &mut [AeadSealItem<'_>],
) -> Result<(), crate::error::ConnectionError> {
    use crate::error::ConnectionError;
    if items.is_empty() {
        return Ok(());
    }
    let homogeneous = aegis_batch_homogeneous_seal(items);
    let first = &items[0];
    if first.buf.len() < crate::crypto::sealed_len(first.plaintext_len)? {
        return Err(ConnectionError::BufferTooShort);
    }
    let first_nonce = super::make_nonce16(iv, first.counter)?;
    let mut cipher = Aegis128X4::new(key, &first_nonce)
        .map_err(|_| ConnectionError::CryptoError("crypto failure".into()))?;
    for (index, item) in items.iter_mut().enumerate() {
        if index > 0 {
            if item.buf.len() < crate::crypto::sealed_len(item.plaintext_len)? {
                return Err(ConnectionError::BufferTooShort);
            }
            let nonce16 = super::make_nonce16(iv, item.counter)?;
            cipher
                .reinit(key, &nonce16)
                .map_err(|_| ConnectionError::CryptoError("crypto failure".into()))?;
        }
        let (pt, rest) = item.buf.split_at_mut(item.plaintext_len);
        let tag = cipher.encrypt_in_place(pt, item.ad);
        rest[..16].copy_from_slice(&tag);
    }
    record_aegis_batch_ops(items.len(), homogeneous);
    Ok(())
}

fn aegis_x4_open_batch(
    key: &[u8; 16],
    iv: &[u8; 12],
    items: &mut [AeadOpenItem<'_>],
) -> Result<(), crate::error::ConnectionError> {
    use crate::error::ConnectionError;
    if items.is_empty() {
        return Ok(());
    }
    let homogeneous = aegis_batch_homogeneous_open(items);
    let first = &items[0];
    if first.buf.len() < 16 {
        return Err(ConnectionError::BufferTooShort);
    }
    let first_nonce = super::make_nonce16(iv, first.counter)?;
    let mut cipher = Aegis128X4::new(key, &first_nonce)
        .map_err(|_| ConnectionError::CryptoError("crypto failure".into()))?;
    for (index, item) in items.iter_mut().enumerate() {
        if index > 0 {
            if item.buf.len() < 16 {
                return Err(ConnectionError::BufferTooShort);
            }
            let nonce16 = super::make_nonce16(iv, item.counter)?;
            cipher
                .reinit(key, &nonce16)
                .map_err(|_| ConnectionError::CryptoError("crypto failure".into()))?;
        }
        let ct_len = item.buf.len() - 16;
        let (ct, tag_in) = item.buf.split_at_mut(ct_len);
        let mut tag = [0u8; 16];
        tag.copy_from_slice(&tag_in[..16]);
        cipher
            .decrypt_in_place(ct, item.ad, &tag)
            .map_err(|_| ConnectionError::CryptoError("crypto failure".into()))?;
    }
    record_aegis_batch_ops(items.len(), homogeneous);
    Ok(())
}

fn aegis_x8_seal_batch(
    key: &[u8; 16],
    iv: &[u8; 12],
    items: &mut [AeadSealItem<'_>],
) -> Result<(), crate::error::ConnectionError> {
    use crate::error::ConnectionError;
    if items.is_empty() {
        return Ok(());
    }
    let homogeneous = aegis_batch_homogeneous_seal(items);
    let first = &items[0];
    if first.buf.len() < crate::crypto::sealed_len(first.plaintext_len)? {
        return Err(ConnectionError::BufferTooShort);
    }
    let first_nonce = super::make_nonce16(iv, first.counter)?;
    let mut cipher = Aegis128X8::new(key, &first_nonce)
        .map_err(|_| ConnectionError::CryptoError("crypto failure".into()))?;
    for (index, item) in items.iter_mut().enumerate() {
        if index > 0 {
            if item.buf.len() < crate::crypto::sealed_len(item.plaintext_len)? {
                return Err(ConnectionError::BufferTooShort);
            }
            let nonce16 = super::make_nonce16(iv, item.counter)?;
            cipher
                .reinit(key, &nonce16)
                .map_err(|_| ConnectionError::CryptoError("crypto failure".into()))?;
        }
        let (pt, rest) = item.buf.split_at_mut(item.plaintext_len);
        let tag = cipher.encrypt_in_place(pt, item.ad);
        rest[..16].copy_from_slice(&tag);
    }
    record_aegis_batch_ops(items.len(), homogeneous);
    Ok(())
}

fn aegis_x8_open_batch(
    key: &[u8; 16],
    iv: &[u8; 12],
    items: &mut [AeadOpenItem<'_>],
) -> Result<(), crate::error::ConnectionError> {
    use crate::error::ConnectionError;
    if items.is_empty() {
        return Ok(());
    }
    let homogeneous = aegis_batch_homogeneous_open(items);
    let first = &items[0];
    if first.buf.len() < 16 {
        return Err(ConnectionError::BufferTooShort);
    }
    let first_nonce = super::make_nonce16(iv, first.counter)?;
    let mut cipher = Aegis128X8::new(key, &first_nonce)
        .map_err(|_| ConnectionError::CryptoError("crypto failure".into()))?;
    for (index, item) in items.iter_mut().enumerate() {
        if index > 0 {
            if item.buf.len() < 16 {
                return Err(ConnectionError::BufferTooShort);
            }
            let nonce16 = super::make_nonce16(iv, item.counter)?;
            cipher
                .reinit(key, &nonce16)
                .map_err(|_| ConnectionError::CryptoError("crypto failure".into()))?;
        }
        let ct_len = item.buf.len() - 16;
        let (ct, tag_in) = item.buf.split_at_mut(ct_len);
        let mut tag = [0u8; 16];
        tag.copy_from_slice(&tag_in[..16]);
        cipher
            .decrypt_in_place(ct, item.ad, &tag)
            .map_err(|_| ConnectionError::CryptoError("crypto failure".into()))?;
    }
    record_aegis_batch_ops(items.len(), homogeneous);
    Ok(())
}

#[cfg(test)]
mod tests;
