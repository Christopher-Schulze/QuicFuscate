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

use qf_cpu::CryptoAeadPlan;
#[cfg(target_arch = "x86_64")]
use qf_cpu::FeatureDetector;
#[cfg(target_arch = "x86_64")]
use qf_cpu::{prefetch, PrefetchHint};
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::OnceLock;
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

// Internal compatibility aliases keep the moved source readable while making the crate boundary
// explicit: crypto owns the machine room and consumes only common, error, CPU, and telemetry
// contracts. No root product module is reachable from this crate.
pub(crate) use crate as crypto;
#[cfg(any(test, feature = "rust-tests"))]
pub(crate) use qf_common::rng;
pub(crate) use qf_common::{env_utils, secret};
pub(crate) use qf_error as error;
pub(crate) use qf_telemetry as telemetry;

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
/// (approximately 1200 bytes). Typical 1-RTT
/// datagrams carry a payload close to the path MTU (~1400 B), and the
/// X4/X8 wide backends are only selected once the workload crosses the
/// planner's length thresholds. Feeding an Initial-sized length would
/// under-select the wide backends on AVX/VAES-capable hosts.
///
/// Forced product-family overrides (`force_aead` / `AeadPreference`) bypass
/// this length entirely, so changing it never affects explicit family pinning.
/// Internal AEGIS width backends remain planner-owned implementation details.
pub(crate) use qf_cpu::DEFAULT_DATA_PLANE_AEAD_LEN;

#[cfg(target_arch = "x86_64")]
#[inline(always)]
fn prefetch_aegis_state(ptr: *const u8) {
    prefetch(ptr, PrefetchHint::T0);
}

#[cfg(not(target_arch = "x86_64"))]
#[inline(always)]
fn prefetch_aegis_state(_ptr: *const u8) {}

#[cfg(target_arch = "x86_64")]
#[inline(always)]
fn prefetch_morus_buffer(ptr: *const u8, len: usize) {
    if len > 64 {
        prefetch(ptr, PrefetchHint::T0);
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
mod tls_cover;

pub use tls_cover::{
    TlsCoverCipherKind, TlsCoverCipherState, TlsCoverInstallOutcome, TlsCoverKeyMaterial,
};

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
        pub fn new(key: &[u8], iv: &[u8]) -> Result<Self, crate::crypto::aead::KeyMaterialError> {
            crate::crypto::aead::require_exact_key_iv("ChaCha20-Poly1305", key, 32, iv, 12)?;
            let mut key_array = [0u8; 32];
            key_array.copy_from_slice(key);
            let mut iv_array = [0u8; 12];
            iv_array.copy_from_slice(iv);
            let cipher = Self::from_arrays(&key_array, &iv_array);
            key_array.zeroize();
            iv_array.zeroize();
            Ok(cipher)
        }

        pub fn from_arrays(key: &[u8; 32], iv: &[u8; 12]) -> Self {
            Self { key: *key, nonce: *iv }
        }

        #[inline(always)]
        fn make_nonce(&self, counter: u64) -> Result<[u8; 12], ConnectionError> {
            super::validate_packet_number(counter)?;
            // QUIC/TLS style nonce construction: nonce = base_iv XOR packet_number.
            let mut nonce = self.nonce;
            let seq = counter.to_be_bytes();
            for (idx, b) in seq.iter().enumerate() {
                nonce[4 + idx] ^= *b;
            }
            Ok(nonce)
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
            self.nonce.zeroize();
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
            let sealed = crate::crypto::checked_seal_capacity(buf.len(), len)?;
            let (pt, rest) = buf.split_at_mut(len);

            let mut nonce12 = self.make_nonce(counter)?;
            let mut poly_key = self.one_time_key(0, &nonce12);

            self.process_in_place(1, &nonce12, pt);

            let tag = poly1305::aead_tag_chacha20poly1305(ad, pt, &poly_key);
            poly_key.zeroize();
            nonce12.zeroize();
            rest[..16].copy_from_slice(&tag);
            Ok(sealed)
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

            let mut nonce12 = self.make_nonce(counter)?;
            let mut poly_key = self.one_time_key(0, &nonce12);

            let tag_calc = poly1305::aead_tag_chacha20poly1305(ad, ct, &poly_key);
            poly_key.zeroize();
            if !crate::crypto::subtle_ct_eq(&tag_calc, &tag) {
                nonce12.zeroize();
                return Err(ConnectionError::CryptoError("crypto failure".into()));
            }

            self.process_in_place(1, &nonce12, ct);
            nonce12.zeroize();
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

/// Cross-platform AES-128 encryption for a single block.
///
/// The x86_64 path keeps its pre-existing AES-NI shortcut. Every other
/// architecture uses the canonical runtime dispatcher in `crypto::aes` so
/// packet protection and header protection cannot drift from its validated
/// round implementation.
#[inline]
fn aes128_encrypt_block_fast(key: &[u8; 16], block: &[u8; 16]) -> [u8; 16] {
    #[cfg(target_arch = "x86_64")]
    // SAFETY: runtime feature detection in the if-guard ensures AES-NI is present
    // before calling expand_aes128_schedule / aes128_encrypt_block_rk. Both take
    // fixed-size stack values (&[u8; 16]), so no dangling pointers or length mismatches.
    unsafe {
        if FeatureDetector::instance().features_full().aesni {
            // SAFETY:
            // - runtime feature detection guarantees AESNI before entering the
            //   accelerated round-key path below
            // - inputs are fixed-size stack values, so the helper never sees
            //   invalid lengths or dangling pointers
            let mut rk = expand_aes128_schedule(key);
            let mut out = *block;
            aes128_encrypt_block_rk(&rk, &mut out);
            zeroize_aes128_schedule(&mut rk);
            return out;
        }
    }
    crate::crypto::aes::aes128_encrypt_block(key, block)
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
/// Length of an AEAD authentication tag across every retained construction here.
pub(crate) const AEAD_TAG_LEN: usize = 16;

/// Total sealed length for `plaintext_len` bytes plus an authentication tag.
///
/// Returns `BufferTooShort` on overflow rather than wrapping. Every seal path used to compute
/// `len + 16` directly, so a caller-supplied length near `usize::MAX` wrapped in release builds
/// and panicked in debug ones. A wrapped total can also pass the capacity comparison that guards
/// `split_at_mut`, which turns a malformed length into an in-process abort instead of a typed
/// error.
#[inline]
pub(crate) fn sealed_len(plaintext_len: usize) -> Result<usize, crate::error::ConnectionError> {
    plaintext_len.checked_add(AEAD_TAG_LEN).ok_or(crate::error::ConnectionError::BufferTooShort)
}

/// Validate that `buf` can hold `plaintext_len` bytes plus a tag, returning the sealed length.
#[inline]
pub(crate) fn checked_seal_capacity(
    buf_len: usize,
    plaintext_len: usize,
) -> Result<usize, crate::error::ConnectionError> {
    let required = sealed_len(plaintext_len)?;
    if buf_len < required {
        return Err(crate::error::ConnectionError::BufferTooShort);
    }
    Ok(required)
}

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
    for round_key in rk.iter().take(10).skip(1) {
        state = _mm_aesenc_si128(state, *round_key);
    }
    state = _mm_aesenclast_si128(state, rk[10]);
    _mm_storeu_si128(block.as_mut_ptr() as *mut __m128i, state);
}

#[cfg(target_arch = "x86_64")]
fn zeroize_aes128_schedule(rk: &mut [core::arch::x86_64::__m128i; 11]) {
    for word in rk {
        // SAFETY: __m128i is an opaque 128-bit value and zero is a valid bit
        // pattern. The schedule contains no borrowed pointers.
        unsafe {
            *word = core::arch::x86_64::_mm_setzero_si128();
        }
    }
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
    pub fn new(aead_key: &[u8], iv: &[u8]) -> Result<Self, crate::crypto::aead::KeyMaterialError> {
        crate::crypto::aead::require_exact_key_iv("AES-128-GCM", aead_key, 16, iv, 12)?;
        let mut key = [0u8; 16];
        key.copy_from_slice(aead_key);
        let mut iv_array = [0u8; 12];
        iv_array.copy_from_slice(iv);
        let cipher = Self::from_arrays(&key, &iv_array);
        key.zeroize();
        iv_array.zeroize();
        Ok(cipher)
    }

    pub fn from_arrays(aead_key: &[u8; 16], iv: &[u8; 12]) -> Self {
        let k = *aead_key;
        let v = *iv;
        // SAFETY: AES-NI feature checked before calling expand_aes128_schedule.
        // k is [u8; 16] - valid 128-bit key. expand_aes128_schedule requires AES-NI.
        #[cfg(target_arch = "x86_64")]
        let rk = unsafe {
            if FeatureDetector::instance().features_full().aesni {
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
            zeroize_aes128_schedule(rk);
        }
    }
}

fn subtle_ct_eq(a: &[u8; 16], b: &[u8; 16]) -> bool {
    bool::from(a.ct_eq(b))
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
        let sealed = crate::crypto::checked_seal_capacity(buf.len(), len)?;
        let (pt, rest) = buf.split_at_mut(len);

        // Use QUIC-compliant nonce construction via make_nonce16
        let nonce16 = make_nonce16(&self.iv, counter)?;

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
        Ok(sealed)
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
        let nonce16 = make_nonce16(&self.iv, counter)?;

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

const MAX_QUIC_PACKET_NUMBER: u64 = (1 << 62) - 1;

fn validate_packet_number(counter: u64) -> Result<(), crate::error::ConnectionError> {
    if counter > MAX_QUIC_PACKET_NUMBER {
        return Err(crate::error::ConnectionError::CryptoError(
            "packet number exceeds the QUIC 62-bit limit".into(),
        ));
    }
    Ok(())
}

fn make_nonce16(iv: &[u8; 12], counter: u64) -> Result<[u8; 16], crate::error::ConnectionError> {
    validate_packet_number(counter)?;
    // QUIC-style nonce derivation for 96-bit IV: XOR 64-bit packet number
    // into the last 8 bytes of the 12-byte IV. Produce a 16-byte nonce by
    // copying the 12-byte IV into the first 12 bytes and leaving the last
    // 4 bytes as 0. This avoids 32-bit truncation. The primitive is stateless,
    // while this boundary still rejects packet numbers beyond QUIC's 62-bit
    // limit before deriving a nonce. The connection owner remains responsible
    // for traffic-secret uniqueness and monotonic key-update counters.
    let mut nonce16 = [0u8; 16];
    nonce16[..12].copy_from_slice(iv);
    let pn = counter.to_be_bytes(); // 8 bytes
    for i in 0..8 {
        // XOR into bytes 4..12 (the last 8 bytes of the 12-byte IV)
        nonce16[4 + i] ^= pn[i];
    }
    Ok(nonce16)
}

pub type BoxedDataAeadPair = (Box<dyn AeadSeal + Send + Sync>, Box<dyn AeadOpen + Send + Sync>);

#[inline(always)]
fn build_aegis_data_aead(plan: CryptoAeadPlan, key: &[u8; 16], iv: &[u8; 12]) -> BoxedDataAeadPair {
    match plan {
        CryptoAeadPlan::Aegis128L => (
            Box::new(Aegis128LAead::from_arrays(key, iv)) as Box<dyn AeadSeal + Send + Sync>,
            Box::new(Aegis128LAead::from_arrays(key, iv)) as Box<dyn AeadOpen + Send + Sync>,
        ),
        CryptoAeadPlan::Aegis128X4 => (
            Box::new(Aegis128X4Aead::from_arrays(key, iv)) as Box<dyn AeadSeal + Send + Sync>,
            Box::new(Aegis128X4Aead::from_arrays(key, iv)) as Box<dyn AeadOpen + Send + Sync>,
        ),
        CryptoAeadPlan::Aegis128X8 => (
            Box::new(Aegis128X8Aead::from_arrays(key, iv)) as Box<dyn AeadSeal + Send + Sync>,
            Box::new(Aegis128X8Aead::from_arrays(key, iv)) as Box<dyn AeadOpen + Send + Sync>,
        ),
        CryptoAeadPlan::Morus => unreachable!("MORUS is built through build_morus_data_aead"),
    }
}

#[inline(always)]
fn build_morus_data_aead(key: &[u8; 16], iv: &[u8; 12]) -> BoxedDataAeadPair {
    (
        Box::new(MorusAead::from_arrays(key, iv)) as Box<dyn AeadSeal + Send + Sync>,
        Box::new(MorusAead::from_arrays(key, iv)) as Box<dyn AeadOpen + Send + Sync>,
    )
}

/// Concrete data-plane AEAD dispatch without vtable calls for retained backends.
enum DataAead {
    Aegis128L(Aegis128LAead),
    Aegis128X4(Aegis128X4Aead),
    Aegis128X8(Aegis128X8Aead),
    Morus(MorusAead),
}

impl DataAead {
    #[inline(always)]
    fn new(plan: CryptoAeadPlan, key: &[u8; 16], iv: &[u8; 12]) -> Self {
        match plan {
            CryptoAeadPlan::Aegis128L => Self::Aegis128L(Aegis128LAead::from_arrays(key, iv)),
            CryptoAeadPlan::Aegis128X4 => Self::Aegis128X4(Aegis128X4Aead::from_arrays(key, iv)),
            CryptoAeadPlan::Aegis128X8 => Self::Aegis128X8(Aegis128X8Aead::from_arrays(key, iv)),
            CryptoAeadPlan::Morus => Self::Morus(MorusAead::from_arrays(key, iv)),
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

enum PacketAeadSealInner {
    Data(DataAead),
    Dynamic(Box<dyn AeadSeal + Send + Sync>),
}

/// Packet seal dispatch used by the transport hot path.
pub struct PacketAeadSeal(PacketAeadSealInner);

impl PacketAeadSeal {
    fn data(aead: DataAead) -> Self {
        Self(PacketAeadSealInner::Data(aead))
    }

    /// Wrap a TLS/provider-owned packet seal implementation.
    pub fn dynamic(aead: Box<dyn AeadSeal + Send + Sync>) -> Self {
        Self(PacketAeadSealInner::Dynamic(aead))
    }
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
        match &self.0 {
            PacketAeadSealInner::Data(aead) => {
                aead.seal_with_u64_counter(counter, ad, buf, len, extra_in)
            }
            PacketAeadSealInner::Dynamic(aead) => {
                aead.seal_with_u64_counter(counter, ad, buf, len, extra_in)
            }
        }
    }

    #[inline(always)]
    fn supports_batch_seal(&self) -> bool {
        match &self.0 {
            PacketAeadSealInner::Data(aead) => aead.supports_batch_seal(),
            PacketAeadSealInner::Dynamic(aead) => aead.supports_batch_seal(),
        }
    }

    #[inline(always)]
    fn seal_batch(
        &self,
        items: &mut [crate::crypto::aead::AeadSealItem<'_>],
    ) -> Result<(), crate::error::ConnectionError> {
        match &self.0 {
            PacketAeadSealInner::Data(aead) => aead.seal_batch(items),
            PacketAeadSealInner::Dynamic(aead) => aead.seal_batch(items),
        }
    }
}

enum PacketAeadOpenInner {
    Data(DataAead),
    Dynamic(Box<dyn AeadOpen + Send + Sync>),
}

/// Packet open dispatch used by the transport hot path.
pub struct PacketAeadOpen(PacketAeadOpenInner);

impl PacketAeadOpen {
    fn data(aead: DataAead) -> Self {
        Self(PacketAeadOpenInner::Data(aead))
    }

    /// Wrap a TLS/provider-owned packet open implementation.
    pub fn dynamic(aead: Box<dyn AeadOpen + Send + Sync>) -> Self {
        Self(PacketAeadOpenInner::Dynamic(aead))
    }
}

impl AeadOpen for PacketAeadOpen {
    #[inline(always)]
    fn open_with_u64_counter(
        &self,
        counter: u64,
        ad: &[u8],
        buf: &mut [u8],
    ) -> Result<usize, crate::error::ConnectionError> {
        match &self.0 {
            PacketAeadOpenInner::Data(aead) => aead.open_with_u64_counter(counter, ad, buf),
            PacketAeadOpenInner::Dynamic(aead) => aead.open_with_u64_counter(counter, ad, buf),
        }
    }

    #[inline(always)]
    fn supports_batch_open(&self) -> bool {
        match &self.0 {
            PacketAeadOpenInner::Data(aead) => aead.supports_batch_open(),
            PacketAeadOpenInner::Dynamic(aead) => aead.supports_batch_open(),
        }
    }

    #[inline(always)]
    fn open_batch(
        &self,
        items: &mut [crate::crypto::aead::AeadOpenItem<'_>],
    ) -> Result<(), crate::error::ConnectionError> {
        match &self.0 {
            PacketAeadOpenInner::Data(aead) => aead.open_batch(items),
            PacketAeadOpenInner::Dynamic(aead) => aead.open_batch(items),
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
        CryptoAeadPlan::Aegis128L => qf_telemetry::DATA_AEAD_BACKEND_AEGIS_L_TOTAL.inc(),
        CryptoAeadPlan::Aegis128X4 => qf_telemetry::DATA_AEAD_BACKEND_AEGIS_X4_TOTAL.inc(),
        CryptoAeadPlan::Aegis128X8 => qf_telemetry::DATA_AEAD_BACKEND_AEGIS_X8_TOTAL.inc(),
        CryptoAeadPlan::Morus => qf_telemetry::DATA_AEAD_BACKEND_MORUS_TOTAL.inc(),
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
fn build_data_aead(plan: CryptoAeadPlan, key: &[u8; 16], iv: &[u8; 12]) -> BoxedDataAeadPair {
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
        PacketAeadSeal::data(DataAead::new(plan, key, iv)),
        PacketAeadOpen::data(DataAead::new(plan, key, iv)),
    )
}

/// Constructs a boxed seal/open AEAD pair for the given benchmark backend.
#[cfg(feature = "benches")]
pub fn build_data_aead_for_benches(
    backend: BenchDataAeadBackend,
    key: &[u8],
    iv: &[u8],
) -> Result<BoxedDataAeadPair, crate::crypto::aead::KeyMaterialError> {
    crate::crypto::aead::require_exact_key_iv("data-plane AEAD", key, 16, iv, 12)?;
    let mut k16 = [0u8; 16];
    k16.copy_from_slice(key);
    let mut iv12 = [0u8; 12];
    iv12.copy_from_slice(iv);
    let plan = match backend {
        BenchDataAeadBackend::Aegis128L => CryptoAeadPlan::Aegis128L,
        BenchDataAeadBackend::Aegis128X4 => CryptoAeadPlan::Aegis128X4,
        BenchDataAeadBackend::Aegis128X8 => CryptoAeadPlan::Aegis128X8,
        BenchDataAeadBackend::Morus => CryptoAeadPlan::Morus,
    };
    Ok(build_data_aead(plan, &k16, &iv12))
}

/// Selects the optimal data-plane AEAD backend and returns a seal/open pair.
pub fn select_data_aead(
    key: &[u8],
    iv: &[u8],
) -> Result<BoxedDataAeadPair, crate::crypto::aead::KeyMaterialError> {
    crate::crypto::aead::require_exact_key_iv("data-plane AEAD", key, 16, iv, 12)?;
    let mut k16 = [0u8; 16];
    k16.copy_from_slice(key);
    let mut iv12 = [0u8; 12];
    iv12.copy_from_slice(iv);

    let plan = resolve_data_aead_plan(DEFAULT_DATA_PLANE_AEAD_LEN);
    Ok(build_data_aead(plan, &k16, &iv12))
}

/// Selects the data-plane AEAD backend for packet hot paths without boxed dispatch.
pub fn select_packet_data_aead(key: &[u8; 32], iv: &[u8; 12]) -> (PacketAeadSeal, PacketAeadOpen) {
    let mut k16 = [0u8; 16];
    k16.copy_from_slice(&key[..16]);
    let mut iv12 = [0u8; 12];
    iv12.copy_from_slice(iv);

    let plan = resolve_data_aead_plan(DEFAULT_DATA_PLANE_AEAD_LEN);
    build_packet_data_aead(plan, &k16, &iv12)
}

/// Product-level private packet-AEAD family exposed to the authenticated negotiation layer.
///
/// Internal AEGIS width variants remain planner-owned and cannot appear in this contract.
#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum PrivateAeadFamily {
    /// AEGIS-128L with the exact 128-bit key profile.
    Aegis128L,
    /// MORUS-1280-128 with the exact 128-bit key profile.
    #[serde(rename = "morus-1280-128")]
    Morus1280_128,
}

impl PrivateAeadFamily {
    /// Exact key length required by the private wire contract.
    pub const KEY_LEN: usize = 16;
    /// Exact packet IV length required by the private wire contract.
    pub const IV_LEN: usize = 12;
    /// Exact authentication tag length shared with the QUIC packet shape.
    pub const TAG_LEN: usize = 16;

    /// Stable protocol identifier. Internal SIMD widths deliberately have no identifier.
    pub const fn protocol_id(self) -> u8 {
        match self {
            Self::Aegis128L => 1,
            Self::Morus1280_128 => 2,
        }
    }

    /// Stable low-cardinality diagnostic label.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Aegis128L => "aegis-128l",
            Self::Morus1280_128 => "morus-1280-128",
        }
    }
}

/// Select a private packet AEAD with exact key and IV lengths.
///
/// This API is intentionally separate from the retained legacy selector, whose 32-byte input
/// represents a TLS-derived secret and historically feeds the first 16 bytes to the product
/// backend. Private negotiation must never silently truncate material, so it accepts only the
/// exact 128-bit family key and 96-bit packet IV.
pub fn select_private_packet_data_aead(
    family: PrivateAeadFamily,
    key: &[u8],
    iv: &[u8],
) -> Result<(PacketAeadSeal, PacketAeadOpen), crate::error::ConnectionError> {
    crate::crypto::aead::require_exact_key_iv(
        family.as_str(),
        key,
        PrivateAeadFamily::KEY_LEN,
        iv,
        PrivateAeadFamily::IV_LEN,
    )?;
    let mut key16 = [0u8; PrivateAeadFamily::KEY_LEN];
    key16.copy_from_slice(key);
    let mut iv12 = [0u8; PrivateAeadFamily::IV_LEN];
    iv12.copy_from_slice(iv);
    let plan = match family {
        PrivateAeadFamily::Aegis128L => CryptoAeadPlan::Aegis128L,
        PrivateAeadFamily::Morus1280_128 => CryptoAeadPlan::Morus,
    };
    Ok(build_packet_data_aead(plan, &key16, &iv12))
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
/// Product-level data-plane AEAD preference supplied by the root configuration adapter.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum DataAeadPreference {
    /// Select the backend from hardware and workload characteristics.
    #[default]
    Auto,
    /// Prefer the AEGIS-128L product family when hardware permits it.
    #[serde(rename = "aegis-128l")]
    Aegis128L,
    /// Prefer MORUS-1280-128.
    Morus,
}

impl DataAeadPreference {
    /// Convert the retained operator preference to the product-level private family contract.
    pub const fn private_family(self) -> Option<PrivateAeadFamily> {
        match self {
            Self::Auto => None,
            Self::Aegis128L => Some(PrivateAeadFamily::Aegis128L),
            Self::Morus => Some(PrivateAeadFamily::Morus1280_128),
        }
    }
}

/// Packet-protection policy for the authenticated private data-plane upgrade.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum PacketProtectionMode {
    /// Keep the complete connection on standards-compatible rustls QUIC keys.
    Standard,
    /// Use standard protection unless a future authenticated private upgrade proves safe.
    #[default]
    Auto,
    /// Require a completed authenticated private upgrade and fail closed otherwise.
    AdvancedRequired,
}

impl PacketProtectionMode {
    /// Stable low-cardinality diagnostic label.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Standard => "standard",
            Self::Auto => "auto",
            Self::AdvancedRequired => "advanced-required",
        }
    }
}

/// Cryptographic configuration projected from the engine boundary.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct CryptoConfig {
    /// Authenticated private packet-protection policy.
    pub packet_protection_mode: PacketProtectionMode,
    /// AEAD cipher preference.
    pub aead_preference: DataAeadPreference,
    /// Force a supported product-family AEAD name.
    pub force_aead: String,
}

impl Default for CryptoConfig {
    fn default() -> Self {
        Self {
            packet_protection_mode: PacketProtectionMode::Auto,
            aead_preference: DataAeadPreference::Auto,
            force_aead: String::new(),
        }
    }
}

impl CryptoConfig {
    /// Resolve the configured product family without exposing internal backend widths.
    pub fn private_family(&self) -> Option<PrivateAeadFamily> {
        let force = self.force_aead.trim().to_ascii_lowercase();
        match force.as_str() {
            "aegis-128l" | "aegis128l" | "aegis" => Some(PrivateAeadFamily::Aegis128L),
            "morus" | "morus-1280-128" | "morus1280-128" => Some(PrivateAeadFamily::Morus1280_128),
            _ => self.aead_preference.private_family(),
        }
    }

    /// Validate the operator-facing product-family override.
    pub fn validate(&self) -> Result<(), String> {
        let force = self.force_aead.trim();
        if !force.is_empty() {
            let value = force.to_ascii_lowercase();
            let supported = matches!(
                value.as_str(),
                "auto"
                    | "aegis-128l"
                    | "aegis128l"
                    | "aegis"
                    | "morus"
                    | "morus-1280-128"
                    | "morus1280-128"
            );
            if !supported {
                return Err(format!("crypto.force_aead has unsupported value: {force}"));
            }
        }
        let private_requested = self.aead_preference != DataAeadPreference::Auto
            || !matches!(force.to_ascii_lowercase().as_str(), "" | "auto");
        match self.packet_protection_mode {
            PacketProtectionMode::Standard if private_requested => {
                return Err(
                    "crypto.packet_protection_mode=standard conflicts with a private AEAD selection"
                        .to_string(),
                );
            }
            PacketProtectionMode::AdvancedRequired if !private_requested => {
                return Err(
                    "crypto.packet_protection_mode=advanced-required requires an explicit private AEAD selection"
                        .to_string(),
                );
            }
            _ => {}
        }
        Ok(())
    }
}

/// Install data-plane AEAD selection without depending on the root engine configuration.
pub fn install_data_aead_selection(preference: DataAeadPreference, force_aead: &str) {
    let has_hw_aes = {
        #[cfg(target_arch = "x86_64")]
        {
            qf_cpu::FeatureDetector::instance().features_full().aesni
        }
        #[cfg(target_arch = "aarch64")]
        {
            qf_cpu::FeatureDetector::instance().features_full().aes
        }
        #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
        {
            false
        }
    };

    // Highest priority: explicit string override.
    let force = force_aead.trim();
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
    match preference {
        DataAeadPreference::Auto => set_data_aead_override_mode(DATA_AEAD_OVERRIDE_AUTO),
        DataAeadPreference::Aegis128L => {
            // Preference: only take effect when AES hardware is available; otherwise keep auto.
            if has_hw_aes {
                set_data_aead_override_mode(DATA_AEAD_OVERRIDE_AEGIS_L);
            } else {
                set_data_aead_override_mode(DATA_AEAD_OVERRIDE_AUTO);
            }
        }
        DataAeadPreference::Morus => set_data_aead_override_mode(DATA_AEAD_OVERRIDE_MORUS),
    }
}

// ============================================================================
// CRYPTO SUBMODULES: AEAD traits/HP, HKDF KDF, minimal GCM helper
// ============================================================================

/// Re-export of QUIC key derivation (HKDF-based Initial/Handshake/1-RTT key schedule).
pub use self::quic_kdf as kdf;
