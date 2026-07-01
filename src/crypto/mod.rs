#![allow(unexpected_cfgs)]
//! # Crypto Module
//!
//! This module owns QuicFuscate's retained custom data-plane crypto machine room.
//! The public runtime contract is intentionally narrow:
//! - `Aegis128L`
//! - `Morus1280_128`
//!
//! Internal backend width selection (`Aegis128X4` / `Aegis128X8`) remains an
//! implementation detail chosen by the planner and hardware detection logic.
//!
//! External crates may appear in tests or baseline oracles, but they are not
//! the canonical runtime providers for the retained data-plane AEAD contract.

use crate::optimize::{CpuFeature, FeatureDetector};
use crate::simd::CryptoAeadPlan;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::OnceLock;
use zeroize::Zeroize;

// Removed: rand::rngs::OsRng + RngCore. Callers now use crate::rng::fill_secure_or_abort
// which wraps getrandom directly and avoids coupling to any rand_core version.

const DATA_AEAD_OVERRIDE_AUTO: u8 = 0;
const DATA_AEAD_OVERRIDE_AEGIS_L: u8 = 1;
const DATA_AEAD_OVERRIDE_MORUS: u8 = 2;

static DATA_AEAD_OVERRIDE_MODE: AtomicU8 = AtomicU8::new(DATA_AEAD_OVERRIDE_AUTO);

/// Representative payload length used to auto-select the data-plane AEAD
/// backend width for 0-RTT/1-RTT packet protection.
///
/// This is intentionally distinct from QUIC Initial packet sizing
/// (`crate::transport::MIN_CLIENT_INITIAL_LEN`, ~1200 B). Typical 1-RTT
/// datagrams carry a payload close to the path MTU (~1400 B), and the
/// X4/X8 wide backends are only selected once the workload crosses the
/// planner's length thresholds. Feeding an Initial-sized length would
/// under-select the wide backends on AVX/VAES-capable hosts.
///
/// Forced product-family overrides (`force_aead` / `AeadPreference`) bypass
/// this length entirely, so changing it never affects explicit family pinning.
/// Internal AEGIS width backends remain planner-owned implementation details.
pub(crate) const DEFAULT_DATA_PLANE_AEAD_LEN: usize = 1400;

#[cfg(target_arch = "x86_64")]
#[inline(always)]
fn prefetch_aegis_state(ptr: *const u8) {
    if FeatureDetector::instance().has_feature(CpuFeature::SSE42) {
        crate::optimize::prefetch(ptr, crate::optimize::PrefetchHint::T0);
    }
}

#[cfg(not(target_arch = "x86_64"))]
#[inline(always)]
fn prefetch_aegis_state(_ptr: *const u8) {}

#[cfg(target_arch = "x86_64")]
#[inline(always)]
fn prefetch_morus_buffer(ptr: *const u8, len: usize) {
    if len > 64 {
        crate::optimize::prefetch(ptr, crate::optimize::PrefetchHint::T0);
    }
}

#[cfg(not(target_arch = "x86_64"))]
#[inline(always)]
#[allow(dead_code)]
fn prefetch_morus_buffer(_ptr: *const u8, _len: usize) {}

// aarch64 intrinsics are imported locally where used via core::arch::aarch64

// ============================================================================
// Hardware-accelerated crypto with AES-NI for AEGIS and MORUS
// ============================================================================

// ============================================================================
// AEGIS-128 RUNTIME DISPATCH SYSTEM
// ============================================================================
// Selector logic centralized in simd::CryptoAeadPlan (SSOT).

// Note: keep tests focused on functional behavior; avoid hygiene-only symbol touches.

#[cfg(test)]
mod tests;

pub(crate) mod chacha20poly1305 {
    use super::chacha;
    use super::poly1305;
    use crate::crypto::aead::{AeadOpen, AeadSeal};
    use crate::error::ConnectionError;
    use zeroize::Zeroize;

    /// ChaCha20-Poly1305 AEAD cipher (RFC 8439).
    #[derive(Clone)]
    pub struct ChaCha20Poly1305 {
        key: [u8; 32],
        nonce: [u8; 12],
    }

    impl ChaCha20Poly1305 {
        /// Create a new instance from a 32-byte key and 12-byte IV/nonce.
        pub fn new(key: &[u8], iv: &[u8]) -> Self {
            let mut k = [0u8; 32];
            let mut n = [0u8; 12];
            for (i, kb) in k.iter_mut().enumerate() {
                *kb = key.get(i).copied().unwrap_or(0);
            }
            for (i, nb) in n.iter_mut().enumerate() {
                *nb = iv.get(i).copied().unwrap_or(0);
            }
            Self { key: k, nonce: n }
        }

        #[inline(always)]
        fn make_nonce(&self, counter: u64) -> [u8; 12] {
            // QUIC/TLS style nonce construction: nonce = base_iv XOR packet_number.
            let mut nonce = self.nonce;
            let seq = counter.to_be_bytes();
            for (idx, b) in seq.iter().enumerate() {
                nonce[4 + idx] ^= *b;
            }
            nonce
        }

        #[inline(always)]
        fn one_time_key(&self, counter: u32, nonce12: &[u8; 12]) -> [u8; 32] {
            let block0 = chacha::chacha20_block(&self.key, counter, nonce12);
            let mut poly_key = [0u8; 32];
            poly_key.copy_from_slice(&block0[..32]);
            poly_key
        }

        #[inline(always)]
        fn process_in_place(&self, counter: u32, nonce12: &[u8; 12], buf: &mut [u8]) {
            chacha::xor_keystream_in_place(&self.key, counter, nonce12, buf);
        }
    }

    // MORUS SSSE3 wrappers are defined in impl MorusAead (outside this module)

    impl Drop for ChaCha20Poly1305 {
        fn drop(&mut self) {
            self.key.zeroize();
        }
    }

    impl AeadSeal for ChaCha20Poly1305 {
        fn seal_with_u64_counter(
            &self,
            counter: u64,
            ad: &[u8],
            buf: &mut [u8],
            len: usize,
            _extra_in: Option<&[u8]>,
        ) -> Result<usize, ConnectionError> {
            if buf.len() < len + 16 {
                return Err(ConnectionError::BufferTooShort);
            }
            let (pt, rest) = buf.split_at_mut(len);

            let nonce12 = self.make_nonce(counter);
            let poly_key = self.one_time_key(0, &nonce12);

            self.process_in_place(1, &nonce12, pt);

            let tag = poly1305::aead_tag_chacha20poly1305(ad, pt, &poly_key);
            rest[..16].copy_from_slice(&tag);
            Ok(len + 16)
        }
    }

    impl AeadOpen for ChaCha20Poly1305 {
        fn open_with_u64_counter(
            &self,
            counter: u64,
            ad: &[u8],
            buf: &mut [u8],
        ) -> Result<usize, ConnectionError> {
            if buf.len() < 16 {
                return Err(ConnectionError::BufferTooShort);
            }
            let ct_len = buf.len() - 16;
            let (ct, tag_in) = buf.split_at_mut(ct_len);
            let mut tag = [0u8; 16];
            tag.copy_from_slice(&tag_in[..16]);

            let nonce12 = self.make_nonce(counter);
            let poly_key = self.one_time_key(0, &nonce12);

            let tag_calc = poly1305::aead_tag_chacha20poly1305(ad, ct, &poly_key);
            if !crate::crypto::subtle_ct_eq(&tag_calc, &tag) {
                return Err(ConnectionError::CryptoError("crypto failure".into()));
            }

            self.process_in_place(1, &nonce12, ct);
            Ok(ct_len)
        }
    }
}

/// Re-export of the ChaCha20-Poly1305 AEAD cipher (RFC 8439).
pub use chacha20poly1305::ChaCha20Poly1305;

// ============================================================================
// AEGIS helpers and hardware-accelerated primitives live in this module.
// Keep selection logic centralized in simd::CryptoAeadPlan.
// ============================================================================

/// Cross-platform fast AES-128 encrypt for a single block.
/// Uses AES-NI on x86_64 if available; falls back to software elsewhere.
#[inline]
fn aes128_encrypt_block_fast(key: &[u8; 16], block: &[u8; 16]) -> [u8; 16] {
    #[cfg(target_arch = "x86_64")]
    // SAFETY: runtime feature detection in the if-guard ensures AES-NI is present
    // before calling expand_aes128_schedule / aes128_encrypt_block_rk. Both take
    // fixed-size stack values (&[u8; 16]), so no dangling pointers or length mismatches.
    unsafe {
        if FeatureDetector::instance().has_feature(CpuFeature::AESNI) {
            // SAFETY:
            // - runtime feature detection guarantees AESNI before entering the
            //   accelerated round-key path below
            // - inputs are fixed-size stack values, so the helper never sees
            //   invalid lengths or dangling pointers
            let rk = expand_aes128_schedule(key);
            let mut out = *block;
            aes128_encrypt_block_rk(&rk, &mut out);
            return out;
        }
    }
    #[cfg(target_arch = "aarch64")]
    // SAFETY: runtime feature detection in the if-guard ensures NEON/AES instructions
    // are present before calling aes128_encrypt_block_arm. key and block are
    // fixed-size references (&[u8; 16]) owned by the caller.
    unsafe {
        if FeatureDetector::instance().has_feature(CpuFeature::AES) {
            // SAFETY:
            // - runtime feature detection gates the ARM AES fast path
            // - `key` and `block` are fixed-size references owned by the caller
            // - the accelerated helper does not retain pointers past the call
            return aes128_encrypt_block_arm(key, block);
        }
    }
    crate::crypto::aes::aes128_encrypt_block(key, block)
}

#[cfg(target_arch = "aarch64")]
#[inline]
#[target_feature(enable = "aes")]
/// # Safety
/// Requires aarch64 with AES instructions available (checked by caller via runtime detection).
/// `key` and `block` must point to valid 16-byte aligned data readable by the function.
unsafe fn aes128_encrypt_block_arm(key: &[u8; 16], block: &[u8; 16]) -> [u8; 16] {
    use core::arch::aarch64::*;
    let rk_bytes = crate::crypto::aes::key_expansion(key);
    // Load round keys into NEON vectors
    let mut k0 = [0u8; 16];
    k0.copy_from_slice(&rk_bytes[0..16]);
    let rk0 = vld1q_u8(k0.as_ptr());
    let mut k1 = [0u8; 16];
    k1.copy_from_slice(&rk_bytes[16..32]);
    let rk1 = vld1q_u8(k1.as_ptr());
    let mut k2 = [0u8; 16];
    k2.copy_from_slice(&rk_bytes[32..48]);
    let rk2 = vld1q_u8(k2.as_ptr());
    let mut k3 = [0u8; 16];
    k3.copy_from_slice(&rk_bytes[48..64]);
    let rk3 = vld1q_u8(k3.as_ptr());
    let mut k4 = [0u8; 16];
    k4.copy_from_slice(&rk_bytes[64..80]);
    let rk4 = vld1q_u8(k4.as_ptr());
    let mut k5 = [0u8; 16];
    k5.copy_from_slice(&rk_bytes[80..96]);
    let rk5 = vld1q_u8(k5.as_ptr());
    let mut k6 = [0u8; 16];
    k6.copy_from_slice(&rk_bytes[96..112]);
    let rk6 = vld1q_u8(k6.as_ptr());
    let mut k7 = [0u8; 16];
    k7.copy_from_slice(&rk_bytes[112..128]);
    let rk7 = vld1q_u8(k7.as_ptr());
    let mut k8 = [0u8; 16];
    k8.copy_from_slice(&rk_bytes[128..144]);
    let rk8 = vld1q_u8(k8.as_ptr());
    let mut k9 = [0u8; 16];
    k9.copy_from_slice(&rk_bytes[144..160]);
    let rk9 = vld1q_u8(k9.as_ptr());
    let mut k10 = [0u8; 16];
    k10.copy_from_slice(&rk_bytes[160..176]);
    let rk10 = vld1q_u8(k10.as_ptr());

    // Encrypt one block with AESE/AESMC
    let mut state = vld1q_u8(block.as_ptr());
    state = veorq_u8(state, rk0);
    state = vaeseq_u8(state, rk1);
    state = vaesmcq_u8(state);
    state = vaeseq_u8(state, rk2);
    state = vaesmcq_u8(state);
    state = vaeseq_u8(state, rk3);
    state = vaesmcq_u8(state);
    state = vaeseq_u8(state, rk4);
    state = vaesmcq_u8(state);
    state = vaeseq_u8(state, rk5);
    state = vaesmcq_u8(state);
    state = vaeseq_u8(state, rk6);
    state = vaesmcq_u8(state);
    state = vaeseq_u8(state, rk7);
    state = vaesmcq_u8(state);
    state = vaeseq_u8(state, rk8);
    state = vaesmcq_u8(state);
    state = vaeseq_u8(state, rk9);
    state = vaesmcq_u8(state);
    state = vaeseq_u8(state, rk10);

    let mut out = [0u8; 16];
    vst1q_u8(out.as_mut_ptr(), state);
    out
}

/// AEGIS-128L/X4/X8 AEAD cipher.
pub mod aegis;
pub use self::aegis::*;

/// MORUS-1280-128 AEAD cipher.
pub mod morus;
pub use self::morus::*;

/// Manages cryptographic keys and provides secure random data.
/// This manager ensures that all cryptographic operations are backed by
/// secure, session-specific materials.
///
/// Actively used by `StealthManager`, `CoreConnection`, and client subsystems
/// as a dependency-injection point for cryptographic key generation.
/// Methods use `OsRng` for CSPRNG-backed key generation; the struct itself
/// is zero-sized and carries no state (acts as a capability token).
pub struct CryptoManager;

impl CryptoManager {
    /// Create a new zero-sized crypto capability token.
    pub fn new() -> Self {
        Self
    }

    /// Generates a cryptographically secure random key of a given length.
    /// This is used for generating ephemeral keys for XOR obfuscation.
    #[cfg(any(test, feature = "rust-tests"))]
    pub fn get_obfuscation_key(&self, length: usize) -> Vec<u8> {
        let mut key = vec![0; length];
        crate::rng::fill_secure_or_abort(&mut key, "CryptoManager::get_obfuscation_key");
        key
    }

    /// Generates a session specific key. This helper wraps [`Self::get_obfuscation_key`]
    /// to make the intent clear when a new connection is created.
    #[cfg(any(test, feature = "rust-tests"))]
    pub fn generate_session_key(&self, length: usize) -> Vec<u8> {
        self.get_obfuscation_key(length)
    }
}

impl Default for CryptoManager {
    fn default() -> Self {
        Self::new()
    }
}

// -----------------------------------------------------------------------------
// QUIC AEAD/HP and supporting primitives (moved from native.rs)
// -----------------------------------------------------------------------------

/// Software AES-128 implementation (S-box, key expansion, encryption, CTR mode).
pub mod aes;

/// ChaCha20 stream cipher core with SIMD-dispatched keystream generation.
pub mod chacha;

/// Poly1305 one-time MAC (RFC 7539) with SIMD-dispatched accumulation.
pub mod poly1305;

/// AES-GCM authenticated encryption with SIMD-dispatched GHASH.
pub mod gcm;

/// SHA-256, HMAC-SHA-256, and HKDF (RFC 5869) key derivation.
pub mod hkdf;

/// RFC 9001 compliant QUIC key derivation functions
pub mod quic_kdf;

/// AEAD/header-protection trait abstractions for QUIC packet protection.
pub mod aead;

#[cfg(target_arch = "x86_64")]
#[inline]
// SAFETY: requires AES-NI (caller ensures). `rk` is &[__m128i; 11]; indexing 0..=10
// stays within bounds. `block` is &mut [u8; 16]; _mm_loadu_si128 reads 16 bytes,
// _mm_storeu_si128 writes 16 bytes back. Exclusive borrow prevents aliasing.
unsafe fn aes128_encrypt_block_rk(rk: &[core::arch::x86_64::__m128i; 11], block: &mut [u8; 16]) {
    use core::arch::x86_64::*;
    let mut state = _mm_loadu_si128(block.as_ptr() as *const __m128i);
    state = _mm_xor_si128(state, rk[0]);
    for r in 1..10 {
        state = _mm_aesenc_si128(state, rk[r]);
    }
    state = _mm_aesenclast_si128(state, rk[10]);
    _mm_storeu_si128(block.as_mut_ptr() as *mut __m128i, state);
}

#[cfg(target_arch = "x86_64")]
// SAFETY: requires AES-NI (caller ensures). `key` is &[u8; 16]; _mm_loadu_si128
// reads exactly 16 bytes. rk is stack-owned [__m128i; 11]; all 11 slots written
// via aes_128_key_expansion. _mm_aeskeygenassist_si128 and _mm_slli_si128 are
// register-to-register. rcon values are exhaustively matched (10 AES-128 rounds).
unsafe fn expand_aes128_schedule(key: &[u8; 16]) -> [core::arch::x86_64::__m128i; 11] {
    use core::arch::x86_64::*;
    #[inline]
    // SAFETY: requires AES-NI (caller ensures). All operations are register-to-register
    // (_mm_aeskeygenassist_si128). rcon must be one of the 10 AES-128 round constants;
    // unreachable_unchecked is sound because the match covers all values passed by
    // expand_aes128_schedule.
    unsafe fn aeskeygenassist_si128_rcon(key: __m128i, rcon: i32) -> __m128i {
        match rcon {
            0x01 => _mm_aeskeygenassist_si128(key, 0x01),
            0x02 => _mm_aeskeygenassist_si128(key, 0x02),
            0x04 => _mm_aeskeygenassist_si128(key, 0x04),
            0x08 => _mm_aeskeygenassist_si128(key, 0x08),
            0x10 => _mm_aeskeygenassist_si128(key, 0x10),
            0x20 => _mm_aeskeygenassist_si128(key, 0x20),
            0x40 => _mm_aeskeygenassist_si128(key, 0x40),
            0x80 => _mm_aeskeygenassist_si128(key, 0x80),
            0x1B => _mm_aeskeygenassist_si128(key, 0x1B),
            0x36 => _mm_aeskeygenassist_si128(key, 0x36),
            _ => core::hint::unreachable_unchecked(),
        }
    }

    #[inline]
    // SAFETY: requires AES-NI (caller ensures). All operations are register-to-register:
    // _mm_shuffle_epi32, _mm_slli_si128, _mm_xor_si128. aeskeygenassist_si128_rcon
    // has the same AES-NI requirement. Returns pair of by-value __m128i.
    unsafe fn aes_128_key_expansion(mut key: __m128i, rcon: i32) -> (__m128i, __m128i) {
        let mut temp2 = aeskeygenassist_si128_rcon(key, rcon);
        temp2 = _mm_shuffle_epi32(temp2, 0xff);
        let mut temp1 = key;
        let mut temp3 = _mm_slli_si128(temp1, 4);
        temp1 = _mm_xor_si128(temp1, temp3);
        temp3 = _mm_slli_si128(temp3, 4);
        temp1 = _mm_xor_si128(temp1, temp3);
        temp3 = _mm_slli_si128(temp3, 4);
        temp1 = _mm_xor_si128(temp1, temp3);
        key = _mm_xor_si128(temp1, temp2);
        (key, key)
    }

    let mut rk: [__m128i; 11] = [_mm_setzero_si128(); 11];
    let mut k0 = _mm_loadu_si128(key.as_ptr() as *const __m128i);
    rk[0] = k0;
    let (k1, v1) = aes_128_key_expansion(k0, 0x01);
    rk[1] = v1;
    k0 = k1;
    let (k2, v2) = aes_128_key_expansion(k0, 0x02);
    rk[2] = v2;
    k0 = k2;
    let (k3, v3) = aes_128_key_expansion(k0, 0x04);
    rk[3] = v3;
    k0 = k3;
    let (k4, v4) = aes_128_key_expansion(k0, 0x08);
    rk[4] = v4;
    k0 = k4;
    let (k5, v5) = aes_128_key_expansion(k0, 0x10);
    rk[5] = v5;
    k0 = k5;
    let (k6, v6) = aes_128_key_expansion(k0, 0x20);
    rk[6] = v6;
    k0 = k6;
    let (k7, v7) = aes_128_key_expansion(k0, 0x40);
    rk[7] = v7;
    k0 = k7;
    let (k8, v8) = aes_128_key_expansion(k0, 0x80);
    rk[8] = v8;
    k0 = k8;
    let (k9, v9) = aes_128_key_expansion(k0, 0x1B);
    rk[9] = v9;
    k0 = k9;
    let (_k10, v10) = aes_128_key_expansion(k0, 0x36);
    rk[10] = v10;
    rk
}

/// AES-128-GCM AEAD with optional AES-NI pre-expanded round keys.
pub struct AesGcm128 {
    key: [u8; 16],
    iv: [u8; 12],
    #[cfg(target_arch = "x86_64")]
    rk: Option<[core::arch::x86_64::__m128i; 11]>,
}

impl AesGcm128 {
    /// Create a new AES-128-GCM instance from a 16-byte key and 12-byte IV.
    pub fn new(aead_key: &[u8], iv: &[u8]) -> Self {
        let mut k = [0u8; 16];
        for (i, kb) in k.iter_mut().enumerate() {
            *kb = aead_key.get(i).copied().unwrap_or(0);
        }
        let mut v = [0u8; 12];
        for (i, vb) in v.iter_mut().enumerate() {
            *vb = iv.get(i).copied().unwrap_or(0);
        }
        // SAFETY: AES-NI feature checked before calling expand_aes128_schedule.
        // k is [u8; 16] - valid 128-bit key. expand_aes128_schedule requires AES-NI.
        #[cfg(target_arch = "x86_64")]
        let rk = unsafe {
            if FeatureDetector::instance().has_feature(CpuFeature::AESNI) {
                Some(expand_aes128_schedule(&k))
            } else {
                None
            }
        };
        #[cfg(not(target_arch = "x86_64"))]
        let _rk: Option<()> = None;
        #[cfg(target_arch = "x86_64")]
        {
            Self { key: k, iv: v, rk }
        }
        #[cfg(not(target_arch = "x86_64"))]
        {
            Self { key: k, iv: v }
        }
    }

    #[inline]
    fn gen_keystream(&self, ctr: &[u8; 16]) -> [u8; 16] {
        // SAFETY: self.rk is Some only when AES-NI was detected at construction.
        // rk is &[__m128i; 11], out is stack-owned [u8; 16] copied from ctr.
        // aes128_encrypt_block_rk requires AES-NI and reads/writes exactly 16 bytes.
        #[cfg(target_arch = "x86_64")]
        unsafe {
            if let Some(rk) = &self.rk {
                let mut out = *ctr;
                aes128_encrypt_block_rk(rk, &mut out);
                return out;
            }
        }
        aes128_encrypt_block_fast(&self.key, ctr)
    }
}

impl Drop for AesGcm128 {
    fn drop(&mut self) {
        self.key.zeroize();
        self.iv.zeroize();
        // The expanded round keys also contain key material.
        #[cfg(target_arch = "x86_64")]
        if let Some(rk) = &mut self.rk {
            for word in rk.iter_mut() {
                // SAFETY: __m128i is a 128-bit opaque type; storing zeros via
                // _mm_setzero_si128 is the canonical way to zero it.
                unsafe {
                    *word = core::arch::x86_64::_mm_setzero_si128();
                }
            }
        }
    }
}

fn subtle_ct_eq(a: &[u8; 16], b: &[u8; 16]) -> bool {
    let mut diff = 0u8;
    for i in 0..16 {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

fn inc32(counter_block: &mut [u8; 16]) {
    let mut n = u32::from_be_bytes([
        counter_block[12],
        counter_block[13],
        counter_block[14],
        counter_block[15],
    ]);
    n = n.wrapping_add(1);
    let b = n.to_be_bytes();
    counter_block[12] = b[0];
    counter_block[13] = b[1];
    counter_block[14] = b[2];
    counter_block[15] = b[3];
}

use crate::crypto::aead::{AeadOpen, AeadSeal};

// Implement AeadSeal and AeadOpen for AesGcm128 (Initial/Handshake only)
impl AeadSeal for AesGcm128 {
    fn seal_with_u64_counter(
        &self,
        counter: u64,
        ad: &[u8],
        buf: &mut [u8],
        len: usize,
        _extra_in: Option<&[u8]>,
    ) -> Result<usize, crate::error::ConnectionError> {
        use crate::error::ConnectionError;
        if buf.len() < len + 16 {
            return Err(ConnectionError::BufferTooShort);
        }
        let (pt, rest) = buf.split_at_mut(len);

        // Use QUIC-compliant nonce construction via make_nonce16
        let nonce16 = make_nonce16(&self.iv, counter);

        // Form J0 per RFC 3610 for AES-GCM with 96-bit IV
        let mut j0 = [0u8; 16];
        j0[..12].copy_from_slice(&nonce16[..12]); // Use first 12 bytes of QUIC nonce
        j0[15] = 1; // Initial counter value

        // CTR encrypt in place
        let mut ctr = j0;
        inc32(&mut ctr);
        let mut off = 0usize;
        while off < pt.len() {
            let ks = self.gen_keystream(&ctr);
            let n = core::cmp::min(16, pt.len() - off);
            for i in 0..n {
                pt[off + i] ^= ks[i];
            }
            off += n;
            inc32(&mut ctr);
        }

        // Compute tag = E(K, J0) XOR GHASH(H, AAD, CT)
        let h = aes128_encrypt_block_fast(&self.key, &[0u8; 16]);
        let s = crate::crypto::gcm::ghash(h, ad, pt);
        let s_enc = self.gen_keystream(&j0);
        let mut tag = [0u8; 16];
        for i in 0..16 {
            tag[i] = s_enc[i] ^ s[i];
        }
        rest[..16].copy_from_slice(&tag);
        Ok(len + 16)
    }
}

impl AeadOpen for AesGcm128 {
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

        // Use QUIC-compliant nonce construction via make_nonce16
        let nonce16 = make_nonce16(&self.iv, counter);

        // Form J0 per RFC 3610 for AES-GCM with 96-bit IV
        let mut j0 = [0u8; 16];
        j0[..12].copy_from_slice(&nonce16[..12]); // Use first 12 bytes of QUIC nonce
        j0[15] = 1; // Initial counter value

        let h = aes128_encrypt_block_fast(&self.key, &[0u8; 16]);
        let s = crate::crypto::gcm::ghash(h, ad, ct);
        let s_enc = self.gen_keystream(&j0);
        let mut tag_calc = [0u8; 16];
        for i in 0..16 {
            tag_calc[i] = s_enc[i] ^ s[i];
        }
        if !subtle_ct_eq(&tag_calc, &tag) {
            return Err(ConnectionError::CryptoError("crypto failure".into()));
        }

        // Decrypt in place
        let mut ctr = j0;
        inc32(&mut ctr);
        let mut off = 0usize;
        while off < ct.len() {
            let ks = self.gen_keystream(&ctr);
            let n = core::cmp::min(16, ct.len() - off);
            for i in 0..n {
                ct[off + i] ^= ks[i];
            }
            off += n;
            inc32(&mut ctr);
        }
        Ok(ct_len)
    }
}

fn make_nonce16(iv: &[u8; 12], counter: u64) -> [u8; 16] {
    // QUIC-style nonce derivation for 96-bit IV: XOR 64-bit packet number
    // into the last 8 bytes of the 12-byte IV. Produce a 16-byte nonce by
    // copying the 12-byte IV into the first 12 bytes and leaving the last
    // 4 bytes as 0. This avoids 32-bit truncation and ensures uniqueness
    // up to 2^64 packets (subject to IV uniqueness from HKDF).
    let mut nonce16 = [0u8; 16];
    nonce16[..12].copy_from_slice(iv);
    let pn = counter.to_be_bytes(); // 8 bytes
    for i in 0..8 {
        // XOR into bytes 4..12 (the last 8 bytes of the 12-byte IV)
        nonce16[4 + i] ^= pn[i];
    }
    nonce16
}

#[inline(always)]
fn build_aegis_data_aead(
    plan: CryptoAeadPlan,
    key: &[u8; 16],
    iv: &[u8; 12],
) -> (Box<dyn AeadSeal + Send + Sync>, Box<dyn AeadOpen + Send + Sync>) {
    match plan {
        CryptoAeadPlan::Aegis128L => (
            Box::new(Aegis128LAead::new(key, iv)) as Box<dyn AeadSeal + Send + Sync>,
            Box::new(Aegis128LAead::new(key, iv)) as Box<dyn AeadOpen + Send + Sync>,
        ),
        CryptoAeadPlan::Aegis128X4 => (
            Box::new(Aegis128X4Aead::new(key, iv)) as Box<dyn AeadSeal + Send + Sync>,
            Box::new(Aegis128X4Aead::new(key, iv)) as Box<dyn AeadOpen + Send + Sync>,
        ),
        CryptoAeadPlan::Aegis128X8 => (
            Box::new(Aegis128X8Aead::new(key, iv)) as Box<dyn AeadSeal + Send + Sync>,
            Box::new(Aegis128X8Aead::new(key, iv)) as Box<dyn AeadOpen + Send + Sync>,
        ),
        CryptoAeadPlan::Morus => unreachable!("MORUS is built through build_morus_data_aead"),
    }
}

#[inline(always)]
fn build_morus_data_aead(
    key: &[u8; 16],
    iv: &[u8; 12],
) -> (Box<dyn AeadSeal + Send + Sync>, Box<dyn AeadOpen + Send + Sync>) {
    (
        Box::new(MorusAead::new(key, iv)) as Box<dyn AeadSeal + Send + Sync>,
        Box::new(MorusAead::new(key, iv)) as Box<dyn AeadOpen + Send + Sync>,
    )
}

/// Concrete data-plane AEAD dispatch without vtable calls for retained backends.
pub(crate) enum DataAead {
    Aegis128L(Aegis128LAead),
    Aegis128X4(Aegis128X4Aead),
    Aegis128X8(Aegis128X8Aead),
    Morus(MorusAead),
}

impl DataAead {
    #[inline(always)]
    fn new(plan: CryptoAeadPlan, key: &[u8; 16], iv: &[u8; 12]) -> Self {
        match plan {
            CryptoAeadPlan::Aegis128L => Self::Aegis128L(Aegis128LAead::new(key, iv)),
            CryptoAeadPlan::Aegis128X4 => Self::Aegis128X4(Aegis128X4Aead::new(key, iv)),
            CryptoAeadPlan::Aegis128X8 => Self::Aegis128X8(Aegis128X8Aead::new(key, iv)),
            CryptoAeadPlan::Morus => Self::Morus(MorusAead::new(key, iv)),
        }
    }
}

impl AeadSeal for DataAead {
    #[inline(always)]
    fn seal_with_u64_counter(
        &self,
        counter: u64,
        ad: &[u8],
        buf: &mut [u8],
        len: usize,
        extra_in: Option<&[u8]>,
    ) -> Result<usize, crate::error::ConnectionError> {
        match self {
            Self::Aegis128L(aead) => aead.seal_with_u64_counter(counter, ad, buf, len, extra_in),
            Self::Aegis128X4(aead) => aead.seal_with_u64_counter(counter, ad, buf, len, extra_in),
            Self::Aegis128X8(aead) => aead.seal_with_u64_counter(counter, ad, buf, len, extra_in),
            Self::Morus(aead) => aead.seal_with_u64_counter(counter, ad, buf, len, extra_in),
        }
    }

    #[inline(always)]
    fn supports_batch_seal(&self) -> bool {
        match self {
            Self::Aegis128L(aead) => aead.supports_batch_seal(),
            Self::Aegis128X4(aead) => aead.supports_batch_seal(),
            Self::Aegis128X8(aead) => aead.supports_batch_seal(),
            Self::Morus(aead) => aead.supports_batch_seal(),
        }
    }

    #[inline(always)]
    fn seal_batch(
        &self,
        items: &mut [crate::crypto::aead::AeadSealItem<'_>],
    ) -> Result<(), crate::error::ConnectionError> {
        match self {
            Self::Aegis128L(aead) => aead.seal_batch(items),
            Self::Aegis128X4(aead) => aead.seal_batch(items),
            Self::Aegis128X8(aead) => aead.seal_batch(items),
            Self::Morus(aead) => aead.seal_batch(items),
        }
    }
}

impl AeadOpen for DataAead {
    #[inline(always)]
    fn open_with_u64_counter(
        &self,
        counter: u64,
        ad: &[u8],
        buf: &mut [u8],
    ) -> Result<usize, crate::error::ConnectionError> {
        match self {
            Self::Aegis128L(aead) => aead.open_with_u64_counter(counter, ad, buf),
            Self::Aegis128X4(aead) => aead.open_with_u64_counter(counter, ad, buf),
            Self::Aegis128X8(aead) => aead.open_with_u64_counter(counter, ad, buf),
            Self::Morus(aead) => aead.open_with_u64_counter(counter, ad, buf),
        }
    }

    #[inline(always)]
    fn supports_batch_open(&self) -> bool {
        match self {
            Self::Aegis128L(aead) => aead.supports_batch_open(),
            Self::Aegis128X4(aead) => aead.supports_batch_open(),
            Self::Aegis128X8(aead) => aead.supports_batch_open(),
            Self::Morus(aead) => aead.supports_batch_open(),
        }
    }

    #[inline(always)]
    fn open_batch(
        &self,
        items: &mut [crate::crypto::aead::AeadOpenItem<'_>],
    ) -> Result<(), crate::error::ConnectionError> {
        match self {
            Self::Aegis128L(aead) => aead.open_batch(items),
            Self::Aegis128X4(aead) => aead.open_batch(items),
            Self::Aegis128X8(aead) => aead.open_batch(items),
            Self::Morus(aead) => aead.open_batch(items),
        }
    }
}

pub(crate) enum PacketAeadSeal {
    Data(DataAead),
    Dynamic(Box<dyn AeadSeal + Send + Sync>),
}

impl AeadSeal for PacketAeadSeal {
    #[inline(always)]
    fn seal_with_u64_counter(
        &self,
        counter: u64,
        ad: &[u8],
        buf: &mut [u8],
        len: usize,
        extra_in: Option<&[u8]>,
    ) -> Result<usize, crate::error::ConnectionError> {
        match self {
            Self::Data(aead) => aead.seal_with_u64_counter(counter, ad, buf, len, extra_in),
            Self::Dynamic(aead) => aead.seal_with_u64_counter(counter, ad, buf, len, extra_in),
        }
    }

    #[inline(always)]
    fn supports_batch_seal(&self) -> bool {
        match self {
            Self::Data(aead) => aead.supports_batch_seal(),
            Self::Dynamic(aead) => aead.supports_batch_seal(),
        }
    }

    #[inline(always)]
    fn seal_batch(
        &self,
        items: &mut [crate::crypto::aead::AeadSealItem<'_>],
    ) -> Result<(), crate::error::ConnectionError> {
        match self {
            Self::Data(aead) => aead.seal_batch(items),
            Self::Dynamic(aead) => aead.seal_batch(items),
        }
    }
}

pub(crate) enum PacketAeadOpen {
    Data(DataAead),
    Dynamic(Box<dyn AeadOpen + Send + Sync>),
}

impl AeadOpen for PacketAeadOpen {
    #[inline(always)]
    fn open_with_u64_counter(
        &self,
        counter: u64,
        ad: &[u8],
        buf: &mut [u8],
    ) -> Result<usize, crate::error::ConnectionError> {
        match self {
            Self::Data(aead) => aead.open_with_u64_counter(counter, ad, buf),
            Self::Dynamic(aead) => aead.open_with_u64_counter(counter, ad, buf),
        }
    }

    #[inline(always)]
    fn supports_batch_open(&self) -> bool {
        match self {
            Self::Data(aead) => aead.supports_batch_open(),
            Self::Dynamic(aead) => aead.supports_batch_open(),
        }
    }

    #[inline(always)]
    fn open_batch(
        &self,
        items: &mut [crate::crypto::aead::AeadOpenItem<'_>],
    ) -> Result<(), crate::error::ConnectionError> {
        match self {
            Self::Data(aead) => aead.open_batch(items),
            Self::Dynamic(aead) => aead.open_batch(items),
        }
    }
}

/// Data-plane AEAD backend selector for benchmarks.
#[cfg(feature = "benches")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BenchDataAeadBackend {
    /// AEGIS-128L (single-lane AES-based AEAD).
    Aegis128L,
    /// AEGIS-128X4 (4-lane parallel AEGIS).
    Aegis128X4,
    /// AEGIS-128X8 (8-lane parallel AEGIS).
    Aegis128X8,
    /// MORUS-1280-128 (lightweight AEAD, no AES dependency).
    Morus,
}

#[cfg(feature = "benches")]
impl BenchDataAeadBackend {
    /// Returns the canonical lowercase name of this AEAD backend.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Aegis128L => "aegis128l",
            Self::Aegis128X4 => "aegis128x4",
            Self::Aegis128X8 => "aegis128x8",
            Self::Morus => "morus1280_128",
        }
    }
}

#[inline(always)]
fn record_data_aead_plan(plan: CryptoAeadPlan) {
    let width = match plan {
        CryptoAeadPlan::Aegis128L => 1,
        CryptoAeadPlan::Aegis128X4 => 4,
        CryptoAeadPlan::Aegis128X8 => 8,
        CryptoAeadPlan::Morus => 0,
    };
    crate::telemetry::AEGIS_PLAN.store(width, std::sync::atomic::Ordering::Relaxed);
    match plan {
        CryptoAeadPlan::Aegis128L => {
            crate::optimize::telemetry::DATA_AEAD_BACKEND_AEGIS_L_TOTAL.inc()
        }
        CryptoAeadPlan::Aegis128X4 => {
            crate::optimize::telemetry::DATA_AEAD_BACKEND_AEGIS_X4_TOTAL.inc()
        }
        CryptoAeadPlan::Aegis128X8 => {
            crate::optimize::telemetry::DATA_AEAD_BACKEND_AEGIS_X8_TOTAL.inc()
        }
        CryptoAeadPlan::Morus => crate::optimize::telemetry::DATA_AEAD_BACKEND_MORUS_TOTAL.inc(),
    }
}

#[inline(always)]
fn resolve_data_aead_plan(default_workload_len: usize) -> CryptoAeadPlan {
    match data_aead_override_mode() {
        DATA_AEAD_OVERRIDE_AEGIS_L => CryptoAeadPlan::Aegis128L,
        DATA_AEAD_OVERRIDE_MORUS => CryptoAeadPlan::Morus,
        _ => CryptoAeadPlan::select_for_len(default_workload_len),
    }
}

#[inline(always)]
fn build_data_aead(
    plan: CryptoAeadPlan,
    key: &[u8; 16],
    iv: &[u8; 12],
) -> (Box<dyn AeadSeal + Send + Sync>, Box<dyn AeadOpen + Send + Sync>) {
    record_data_aead_plan(plan);
    match plan {
        CryptoAeadPlan::Morus => build_morus_data_aead(key, iv),
        CryptoAeadPlan::Aegis128L | CryptoAeadPlan::Aegis128X4 | CryptoAeadPlan::Aegis128X8 => {
            build_aegis_data_aead(plan, key, iv)
        }
    }
}

#[inline(always)]
fn build_packet_data_aead(
    plan: CryptoAeadPlan,
    key: &[u8; 16],
    iv: &[u8; 12],
) -> (PacketAeadSeal, PacketAeadOpen) {
    record_data_aead_plan(plan);
    (
        PacketAeadSeal::Data(DataAead::new(plan, key, iv)),
        PacketAeadOpen::Data(DataAead::new(plan, key, iv)),
    )
}

/// Constructs a boxed seal/open AEAD pair for the given benchmark backend.
#[cfg(feature = "benches")]
pub fn build_data_aead_for_benches(
    backend: BenchDataAeadBackend,
    key: &[u8],
    iv: &[u8],
) -> (Box<dyn AeadSeal + Send + Sync>, Box<dyn AeadOpen + Send + Sync>) {
    let mut k16 = [0u8; 16];
    k16.copy_from_slice(&key[..16]);
    let mut iv12 = [0u8; 12];
    iv12.copy_from_slice(&iv[..12]);
    let plan = match backend {
        BenchDataAeadBackend::Aegis128L => CryptoAeadPlan::Aegis128L,
        BenchDataAeadBackend::Aegis128X4 => CryptoAeadPlan::Aegis128X4,
        BenchDataAeadBackend::Aegis128X8 => CryptoAeadPlan::Aegis128X8,
        BenchDataAeadBackend::Morus => CryptoAeadPlan::Morus,
    };
    build_data_aead(plan, &k16, &iv12)
}

/// Selects the optimal data-plane AEAD backend and returns a seal/open pair.
pub fn select_data_aead(
    key: &[u8],
    iv: &[u8],
) -> (Box<dyn AeadSeal + Send + Sync>, Box<dyn AeadOpen + Send + Sync>) {
    // Normalize key/iv materials
    let mut k16 = [0u8; 16];
    k16.copy_from_slice(&key[..16]);
    let mut iv12 = [0u8; 12];
    iv12.copy_from_slice(&iv[..12]);

    let plan = resolve_data_aead_plan(DEFAULT_DATA_PLANE_AEAD_LEN);
    build_data_aead(plan, &k16, &iv12)
}

/// Selects the data-plane AEAD backend for packet hot paths without boxed dispatch.
pub(crate) fn select_packet_data_aead(key: &[u8], iv: &[u8]) -> (PacketAeadSeal, PacketAeadOpen) {
    let mut k16 = [0u8; 16];
    k16.copy_from_slice(&key[..16]);
    let mut iv12 = [0u8; 12];
    iv12.copy_from_slice(&iv[..12]);

    let plan = resolve_data_aead_plan(DEFAULT_DATA_PLANE_AEAD_LEN);
    build_packet_data_aead(plan, &k16, &iv12)
}

fn data_aead_override_mode() -> u8 {
    DATA_AEAD_OVERRIDE_MODE.load(Ordering::Relaxed)
}

fn set_data_aead_override_mode(mode: u8) {
    DATA_AEAD_OVERRIDE_MODE.store(mode, Ordering::Relaxed);
}

/// Apply data-plane AEAD settings from config.
///
/// This affects 0-RTT/1-RTT packet protection selection in the forked transport layer.
/// It is a fork-specific data-plane decision, not a TLS cipher-suite decision, and is valid only under the explicit full-fork assumption.
/// The config surface selects product AEAD families only; internal AEGIS width backends are planner-owned implementation details.
/// It is not an upstream QUIC interoperability claim.
/// Initial/Handshake remain AES-GCM at the QUIC/TLS boundary.
pub fn install_data_aead_config(cfg: &crate::engine::CryptoConfig) {
    let has_hw_aes = {
        #[cfg(target_arch = "x86_64")]
        {
            crate::optimize::FeatureDetector::instance()
                .has_feature(crate::optimize::CpuFeature::AESNI)
        }
        #[cfg(target_arch = "aarch64")]
        {
            crate::optimize::FeatureDetector::instance()
                .has_feature(crate::optimize::CpuFeature::AES)
        }
        #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
        {
            false
        }
    };

    // Highest priority: explicit string override.
    let force = cfg.force_aead.trim();
    if !force.is_empty() {
        let v = force.to_ascii_lowercase();
        match v.as_str() {
            "auto" => set_data_aead_override_mode(DATA_AEAD_OVERRIDE_AUTO),
            "aegis-128l" | "aegis128l" | "aegis" => {
                set_data_aead_override_mode(DATA_AEAD_OVERRIDE_AEGIS_L)
            }
            "morus" | "morus-1280-128" | "morus1280-128" => {
                set_data_aead_override_mode(DATA_AEAD_OVERRIDE_MORUS)
            }
            _ => {
                // Validation should reject unknown values; keep runtime behavior stable.
                set_data_aead_override_mode(DATA_AEAD_OVERRIDE_AUTO);
            }
        }
        return;
    }

    // Preference-based override.
    match cfg.aead_preference {
        crate::engine::AeadPreference::Auto => set_data_aead_override_mode(DATA_AEAD_OVERRIDE_AUTO),
        crate::engine::AeadPreference::Aegis128L => {
            // Preference: only take effect when AES hardware is available; otherwise keep auto.
            if has_hw_aes {
                set_data_aead_override_mode(DATA_AEAD_OVERRIDE_AEGIS_L);
            } else {
                set_data_aead_override_mode(DATA_AEAD_OVERRIDE_AUTO);
            }
        }
        crate::engine::AeadPreference::Morus => {
            set_data_aead_override_mode(DATA_AEAD_OVERRIDE_MORUS)
        }
    }
}

// ============================================================================
// CRYPTO SUBMODULES: AEAD traits/HP, HKDF KDF, minimal GCM helper
// ============================================================================

/// Re-export of QUIC key derivation (HKDF-based Initial/Handshake/1-RTT key schedule).
pub use self::quic_kdf as kdf;
