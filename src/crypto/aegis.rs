#![allow(unexpected_cfgs)]
//! AEGIS-128L/X4/X8 AEAD cipher implementation.
//!
//! Internal consolidated implementation with hardware-dispatched AES rounds.
//! No external crate dependency.

use crate::crypto::aead::{AeadOpen, AeadOpenItem, AeadSeal, AeadSealItem};
use std::sync::atomic::Ordering;
use zeroize::Zeroize;

/// AEGIS-128L AEAD wrapper for the data-plane AEAD trait.
pub struct Aegis128LAead {
    key: [u8; 16],
    iv: [u8; 12],
}

/// Generate a `new(aead_key, iv)` constructor that copies key/IV bytes into
/// fixed-size arrays. All Aegis variants share identical field layout so one
/// macro covers all three.
impl Aegis128LAead {
    /// Create a new AEGIS-128L AEAD instance with copied key and IV material.
    pub fn new(aead_key: &[u8], iv: &[u8]) -> Self {
        let mut k = [0u8; 16];
        let klen = aead_key.len().min(16);
        k[..klen].copy_from_slice(&aead_key[..klen]);
        let mut v = [0u8; 12];
        let vlen = iv.len().min(12);
        v[..vlen].copy_from_slice(&iv[..vlen]);
        Self { key: k, iv: v }
    }
}

pub(crate) struct Aegis128X4Aead {
    key: [u8; 16],
    iv: [u8; 12],
}

impl Aegis128X4Aead {
    pub(crate) fn new(aead_key: &[u8], iv: &[u8]) -> Self {
        let mut k = [0u8; 16];
        let klen = aead_key.len().min(16);
        k[..klen].copy_from_slice(&aead_key[..klen]);
        let mut v = [0u8; 12];
        let vlen = iv.len().min(12);
        v[..vlen].copy_from_slice(&iv[..vlen]);
        Self { key: k, iv: v }
    }
}

pub(crate) struct Aegis128X8Aead {
    key: [u8; 16],
    iv: [u8; 12],
}

impl Aegis128X8Aead {
    pub(crate) fn new(aead_key: &[u8], iv: &[u8]) -> Self {
        let mut k = [0u8; 16];
        let klen = aead_key.len().min(16);
        k[..klen].copy_from_slice(&aead_key[..klen]);
        let mut v = [0u8; 12];
        let vlen = iv.len().min(12);
        v[..vlen].copy_from_slice(&iv[..vlen]);
        Self { key: k, iv: v }
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
}

#[cfg(feature = "std")]
impl std::fmt::Display for AegisError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AegisError::InvalidTag => write!(f, "Invalid tag"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for AegisError {}

// AES block used by the AEGIS-128L implementation.
//
// We always compile a portable software AESENC equivalent, and optionally dispatch
// to architecture-specific AES instructions via #[target_feature] when available.
mod aegis_aes_block {
    use std::sync::OnceLock;
    use zeroize::Zeroize;

    #[derive(Copy, Clone, Debug, Default)]
    pub(crate) struct AesBlock([u8; 16]);

    #[derive(Copy, Clone, Debug, PartialEq, Eq)]
    enum AesEncBackend {
        #[cfg(target_arch = "x86_64")]
        Vaes512,
        #[cfg(target_arch = "x86_64")]
        Vaes256,
        #[cfg(target_arch = "x86_64")]
        Aesni,
        #[cfg(target_arch = "aarch64")]
        Aese,
        Scalar,
    }

    fn aes_backend() -> AesEncBackend {
        static BACKEND: OnceLock<AesEncBackend> = OnceLock::new();
        *BACKEND.get_or_init(|| {
            #[cfg(target_arch = "x86_64")]
            {
                if crate::optimize::FeatureDetector::instance()
                    .has_feature(crate::optimize::CpuFeature::AESNI)
                {
                    let det = crate::optimize::FeatureDetector::instance();
                    if det.has_feature(crate::optimize::CpuFeature::VAES)
                        && det.has_feature(crate::optimize::CpuFeature::AVX512F)
                        && det.has_feature(crate::optimize::CpuFeature::AVX512VL)
                    {
                        return AesEncBackend::Vaes512;
                    }
                    if det.has_feature(crate::optimize::CpuFeature::VAES)
                        && det.has_feature(crate::optimize::CpuFeature::AVX2)
                    {
                        return AesEncBackend::Vaes256;
                    }
                    return AesEncBackend::Aesni;
                }
            }

            #[cfg(target_arch = "aarch64")]
            {
                if crate::optimize::FeatureDetector::instance()
                    .has_feature(crate::optimize::CpuFeature::AES)
                {
                    return AesEncBackend::Aese;
                }
            }

            AesEncBackend::Scalar
        })
    }

    fn aesenc_round_cached(block: &[u8; 16], round_key: &[u8; 16]) -> [u8; 16] {
        match aes_backend() {
            #[cfg(target_arch = "x86_64")]
            // SAFETY: aes_backend() guarantees AES-NI detected at runtime. block and
            // round_key are &[u8; 16] with valid provenance.
            AesEncBackend::Vaes512 | AesEncBackend::Vaes256 | AesEncBackend::Aesni => unsafe {
                aesenc_round_aesni(block, round_key)
            },
            #[cfg(target_arch = "aarch64")]
            // SAFETY: aes_backend() guarantees AES feature detected at runtime. block and
            // round_key are &[u8; 16] with valid provenance.
            AesEncBackend::Aese => unsafe { aesenc_round_armcrypto(block, round_key) },
            AesEncBackend::Scalar => crate::crypto::aes::aesenc_round(block, round_key),
        }
    }

    pub(crate) fn add_aesenc_ops(ops: u64) {
        use crate::optimize::telemetry;
        match aes_backend() {
            #[cfg(target_arch = "x86_64")]
            AesEncBackend::Vaes512 | AesEncBackend::Vaes256 => {
                telemetry::AES_BLOCK_VAES_OPS.inc_by(ops)
            }
            #[cfg(target_arch = "x86_64")]
            AesEncBackend::Aesni => telemetry::AES_BLOCK_AESNI_OPS.inc_by(ops),
            #[cfg(target_arch = "aarch64")]
            AesEncBackend::Aese => telemetry::AES_BLOCK_AESE_OPS.inc_by(ops),
            AesEncBackend::Scalar => telemetry::AES_BLOCK_SCALAR_OPS.inc_by(ops),
        }
    }

    #[cfg(target_arch = "x86_64")]
    #[target_feature(enable = "vaes,avx2")]
    // SAFETY: target_feature gate ensures VAES+AVX2. All inputs are &[u8; 16]
    // references (16 bytes each); _mm_loadu_si128 reads exactly 16 bytes from each.
    // Outputs are stack-owned [u8; 16] arrays. No out-of-bounds access possible.
    unsafe fn aesenc2_vaes256(
        b0: &[u8; 16],
        rk0: &[u8; 16],
        b1: &[u8; 16],
        rk1: &[u8; 16],
    ) -> ([u8; 16], [u8; 16]) {
        use core::arch::x86_64::*;
        let x0 = _mm_loadu_si128(b0.as_ptr() as *const __m128i);
        let x1 = _mm_loadu_si128(b1.as_ptr() as *const __m128i);
        let k0 = _mm_loadu_si128(rk0.as_ptr() as *const __m128i);
        let k1 = _mm_loadu_si128(rk1.as_ptr() as *const __m128i);

        let x = _mm256_set_m128i(x1, x0);
        let k = _mm256_set_m128i(k1, k0);
        let y = _mm256_aesenc_epi128(x, k);

        let y0 = _mm256_extracti128_si256(y, 0);
        let y1 = _mm256_extracti128_si256(y, 1);
        let mut o0 = [0u8; 16];
        let mut o1 = [0u8; 16];
        _mm_storeu_si128(o0.as_mut_ptr() as *mut __m128i, y0);
        _mm_storeu_si128(o1.as_mut_ptr() as *mut __m128i, y1);
        (o0, o1)
    }

    #[cfg(target_arch = "x86_64")]
    #[target_feature(enable = "vaes,avx512f,avx512vl")]
    // SAFETY: target_feature gate ensures VAES+AVX512F+AVX512VL. All inputs are
    // &[u8; 16] references; _mm_loadu_si128 reads exactly 16 bytes from each.
    // Outputs are stack-owned [u8; 16] arrays. No out-of-bounds access possible.
    unsafe fn aesenc4_vaes512(
        b0: &[u8; 16],
        rk0: &[u8; 16],
        b1: &[u8; 16],
        rk1: &[u8; 16],
        b2: &[u8; 16],
        rk2: &[u8; 16],
        b3: &[u8; 16],
        rk3: &[u8; 16],
    ) -> ([u8; 16], [u8; 16], [u8; 16], [u8; 16]) {
        use core::arch::x86_64::*;
        let x0 = _mm_loadu_si128(b0.as_ptr() as *const __m128i);
        let x1 = _mm_loadu_si128(b1.as_ptr() as *const __m128i);
        let x2 = _mm_loadu_si128(b2.as_ptr() as *const __m128i);
        let x3 = _mm_loadu_si128(b3.as_ptr() as *const __m128i);
        let k0 = _mm_loadu_si128(rk0.as_ptr() as *const __m128i);
        let k1 = _mm_loadu_si128(rk1.as_ptr() as *const __m128i);
        let k2 = _mm_loadu_si128(rk2.as_ptr() as *const __m128i);
        let k3 = _mm_loadu_si128(rk3.as_ptr() as *const __m128i);

        let mut x = _mm512_castsi128_si512(x0);
        x = _mm512_inserti32x4(x, x1, 1);
        x = _mm512_inserti32x4(x, x2, 2);
        x = _mm512_inserti32x4(x, x3, 3);

        let mut k = _mm512_castsi128_si512(k0);
        k = _mm512_inserti32x4(k, k1, 1);
        k = _mm512_inserti32x4(k, k2, 2);
        k = _mm512_inserti32x4(k, k3, 3);

        let y = _mm512_aesenc_epi128(x, k);

        let y0 = _mm512_extracti32x4_epi32(y, 0);
        let y1 = _mm512_extracti32x4_epi32(y, 1);
        let y2 = _mm512_extracti32x4_epi32(y, 2);
        let y3 = _mm512_extracti32x4_epi32(y, 3);

        let mut o0 = [0u8; 16];
        let mut o1 = [0u8; 16];
        let mut o2 = [0u8; 16];
        let mut o3 = [0u8; 16];
        _mm_storeu_si128(o0.as_mut_ptr() as *mut __m128i, y0);
        _mm_storeu_si128(o1.as_mut_ptr() as *mut __m128i, y1);
        _mm_storeu_si128(o2.as_mut_ptr() as *mut __m128i, y2);
        _mm_storeu_si128(o3.as_mut_ptr() as *mut __m128i, y3);
        (o0, o1, o2, o3)
    }

    pub(crate) fn aesenc8_update_inputs(
        in_b: &[[u8; 16]; 8],
        in_rk: &[[u8; 16]; 8],
    ) -> [[u8; 16]; 8] {
        match aes_backend() {
            #[cfg(target_arch = "x86_64")]
            // SAFETY: aes_backend() selected Vaes512 only after runtime detection
            // confirmed AVX512F+VAES. All in_b/in_rk elements are [u8; 16] arrays
            // passed by reference - no out-of-bounds access possible.
            AesEncBackend::Vaes512 => unsafe {
                let (o7, o6, o5, o4) = aesenc4_vaes512(
                    &in_b[7], &in_rk[7], &in_b[6], &in_rk[6], &in_b[5], &in_rk[5], &in_b[4],
                    &in_rk[4],
                );
                let (o3, o2, o1, o0) = aesenc4_vaes512(
                    &in_b[3], &in_rk[3], &in_b[2], &in_rk[2], &in_b[1], &in_rk[1], &in_b[0],
                    &in_rk[0],
                );
                return [o0, o1, o2, o3, o4, o5, o6, o7];
            },
            #[cfg(target_arch = "x86_64")]
            // SAFETY: aes_backend() selected Vaes256 only after runtime detection
            // confirmed AVX2+VAES. All in_b/in_rk elements are [u8; 16] arrays.
            AesEncBackend::Vaes256 => unsafe {
                let (o7, o6) = aesenc2_vaes256(&in_b[7], &in_rk[7], &in_b[6], &in_rk[6]);
                let (o5, o4) = aesenc2_vaes256(&in_b[5], &in_rk[5], &in_b[4], &in_rk[4]);
                let (o3, o2) = aesenc2_vaes256(&in_b[3], &in_rk[3], &in_b[2], &in_rk[2]);
                let (o1, o0) = aesenc2_vaes256(&in_b[1], &in_rk[1], &in_b[0], &in_rk[0]);
                return [o0, o1, o2, o3, o4, o5, o6, o7];
            },
            _ => {}
        }

        // Fallback: scalar dispatch per block (still uses cached backend).
        let mut out = [[0u8; 16]; 8];
        for i in 0..8 {
            out[i] = aesenc_round_cached(&in_b[i], &in_rk[i]);
        }
        out
    }

    impl AesBlock {
        pub(crate) fn from_bytes(bytes: &[u8; 16]) -> Self {
            Self(*bytes)
        }

        pub(crate) fn into_bytes(self) -> [u8; 16] {
            self.0
        }

        /// Zeroize the internal block bytes in place.
        pub(crate) fn zeroize(&mut self) {
            self.0.zeroize();
        }

        #[inline(always)]
        pub(crate) fn xor(&self, other: Self) -> Self {
            #[cfg(target_arch = "x86_64")]
            // SAFETY: SSE2 is baseline x86_64. `self.0` and `other.0` are [u8; 16];
            // _mm_loadu_si128 reads exactly 16 bytes from each. `out` is a stack-owned
            // [u8; 16]; _mm_storeu_si128 writes exactly 16 bytes. All within bounds.
            unsafe {
                use core::arch::x86_64::*;
                let a = _mm_loadu_si128(self.0.as_ptr() as *const __m128i);
                let b = _mm_loadu_si128(other.0.as_ptr() as *const __m128i);
                let x = _mm_xor_si128(a, b);
                let mut out = [0u8; 16];
                _mm_storeu_si128(out.as_mut_ptr() as *mut __m128i, x);
                return Self(out);
            }

            #[cfg(target_arch = "aarch64")]
            // SAFETY: NEON is baseline aarch64. `self.0` and `other.0` are [u8; 16];
            // vld1q_u8 reads exactly 16 bytes. `out` is stack-owned [u8; 16].
            unsafe {
                use core::arch::aarch64::*;
                let a = vld1q_u8(self.0.as_ptr());
                let b = vld1q_u8(other.0.as_ptr());
                let x = veorq_u8(a, b);
                let mut out = [0u8; 16];
                vst1q_u8(out.as_mut_ptr(), x);
                return Self(out);
            }

            #[allow(unreachable_code)]
            {
                let mut out = [0u8; 16];
                for (i, o) in out.iter_mut().enumerate() {
                    *o = self.0[i] ^ other.0[i];
                }
                Self(out)
            }
        }

        #[inline(always)]
        pub(crate) fn and(&self, other: Self) -> Self {
            #[cfg(target_arch = "x86_64")]
            // SAFETY: SSE2 is baseline x86_64. Same invariants as xor(): `self.0` and
            // `other.0` are [u8; 16], `out` is stack-owned [u8; 16]. All 16-byte
            // unaligned loads/stores stay within bounds.
            unsafe {
                use core::arch::x86_64::*;
                let a = _mm_loadu_si128(self.0.as_ptr() as *const __m128i);
                let b = _mm_loadu_si128(other.0.as_ptr() as *const __m128i);
                let x = _mm_and_si128(a, b);
                let mut out = [0u8; 16];
                _mm_storeu_si128(out.as_mut_ptr() as *mut __m128i, x);
                return Self(out);
            }

            #[cfg(target_arch = "aarch64")]
            // SAFETY: NEON is baseline aarch64. Same invariants as xor() NEON path.
            unsafe {
                use core::arch::aarch64::*;
                let a = vld1q_u8(self.0.as_ptr());
                let b = vld1q_u8(other.0.as_ptr());
                let x = vandq_u8(a, b);
                let mut out = [0u8; 16];
                vst1q_u8(out.as_mut_ptr(), x);
                return Self(out);
            }

            #[allow(unreachable_code)]
            {
                let mut out = [0u8; 16];
                for (i, o) in out.iter_mut().enumerate() {
                    *o = self.0[i] & other.0[i];
                }
                Self(out)
            }
        }

        // aes_round is intentionally not exposed anymore. The AEGIS hot path uses
        // the batched update helper to leverage VAES when available.
    }

    #[cfg(target_arch = "x86_64")]
    #[target_feature(enable = "aes")]
    // SAFETY: target_feature gate ensures AES-NI. `block` and `round_key` are
    // &[u8; 16]; _mm_loadu_si128 reads exactly 16 bytes. `out` is stack-owned [u8; 16].
    unsafe fn aesenc_round_aesni(block: &[u8; 16], round_key: &[u8; 16]) -> [u8; 16] {
        use core::arch::x86_64::*;
        let b = _mm_loadu_si128(block.as_ptr() as *const __m128i);
        let rk = _mm_loadu_si128(round_key.as_ptr() as *const __m128i);
        let e = _mm_aesenc_si128(b, rk);
        let mut out = [0u8; 16];
        _mm_storeu_si128(out.as_mut_ptr() as *mut __m128i, e);
        out
    }

    #[cfg(target_arch = "aarch64")]
    #[target_feature(enable = "aes")]
    // SAFETY: target_feature gate ensures ARM AES. `block` and `round_key` are
    // &[u8; 16]; vld1q_u8 reads exactly 16 bytes. `out` is stack-owned [u8; 16].
    unsafe fn aesenc_round_armcrypto(block: &[u8; 16], round_key: &[u8; 16]) -> [u8; 16] {
        use core::arch::aarch64::*;
        let b = vld1q_u8(block.as_ptr());
        let rk = vld1q_u8(round_key.as_ptr());
        let e = vaeseq_u8(b, rk);
        let m = vaesmcq_u8(e);
        let mut out = [0u8; 16];
        vst1q_u8(out.as_mut_ptr(), m);
        out
    }
}

use aegis_aes_block::AesBlock;

fn zeroize_aegis_state(state: &mut [AesBlock; 8], label: &'static str) {
    for block in state.iter_mut() {
        block.zeroize();
    }
    #[cfg(test)]
    {
        let mut snapshot = [0u8; 128];
        for (destination, block) in snapshot.chunks_exact_mut(16).zip(state.iter()) {
            destination.copy_from_slice(&block.into_bytes());
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
    let old = *state;

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
        old[0].into_bytes(),
        old[1].into_bytes(),
        old[2].into_bytes(),
        old[3].into_bytes(),
        old[4].into_bytes(),
        old[5].into_bytes(),
        old[6].into_bytes(),
        old[7].into_bytes(),
    ];
    let in_rk = [
        old[7].into_bytes(),
        old[0].into_bytes(),
        old[1].into_bytes(),
        old[2].into_bytes(),
        old[3].into_bytes(),
        old[4].into_bytes(),
        old[5].into_bytes(),
        old[6].into_bytes(),
    ];

    // Run the 8 AESENC operations with the best available backend.
    let out = aegis_aes_block::aesenc8_update_inputs(&in_b, &in_rk);

    state[0] = AesBlock::from_bytes(&out[0]).xor(d0);
    state[1] = AesBlock::from_bytes(&out[1]);
    state[2] = AesBlock::from_bytes(&out[2]);
    state[3] = AesBlock::from_bytes(&out[3]);
    state[4] = AesBlock::from_bytes(&out[4]).xor(d1);
    state[5] = AesBlock::from_bytes(&out[5]);
    state[6] = AesBlock::from_bytes(&out[6]);
    state[7] = AesBlock::from_bytes(&out[7]);
}

fn aegis128l_init_state(key: &[u8], nonce: &[u8]) -> Result<[AesBlock; 8], AegisError> {
    if key.len() != Aegis128L::KEY_SIZE || nonce.len() != Aegis128L::NONCE_SIZE {
        return Err(AegisError::InvalidTag);
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

    let kxn = key_block.xor(nonce_block);
    let mut state = [kxn, c1, c0, c1, kxn, key_block.xor(c0), key_block.xor(c1), kxn];

    // Initialization rounds.
    for _ in 0..10 {
        aegis128l_update(&mut state, nonce_block, key_block);
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
            let z0 = self.state[6].xor(self.state[1]).xor(self.state[2].and(self.state[3]));
            let z1 = self.state[2].xor(self.state[5]).xor(self.state[6].and(self.state[7]));
            let mut msg0 = [0u8; 16];
            let mut msg1 = [0u8; 16];
            msg0.copy_from_slice(&plaintext[i..i + 16]);
            msg1.copy_from_slice(&plaintext[i + 16..i + 32]);
            let msg0_block = AesBlock::from_bytes(&msg0);
            let msg1_block = AesBlock::from_bytes(&msg1);
            let c0 = msg0_block.xor(z0);
            let c1 = msg1_block.xor(z1);
            plaintext[i..i + 16].copy_from_slice(&c0.into_bytes());
            plaintext[i + 16..i + 32].copy_from_slice(&c1.into_bytes());
            Self::update(&mut self.state, msg0_block, msg1_block);

            // Second 32 bytes
            let z0b = self.state[6].xor(self.state[1]).xor(self.state[2].and(self.state[3]));
            let z1b = self.state[2].xor(self.state[5]).xor(self.state[6].and(self.state[7]));
            let mut msg2 = [0u8; 16];
            let mut msg3 = [0u8; 16];
            msg2.copy_from_slice(&plaintext[i + 32..i + 48]);
            msg3.copy_from_slice(&plaintext[i + 48..i + 64]);
            let msg2_block = AesBlock::from_bytes(&msg2);
            let msg3_block = AesBlock::from_bytes(&msg3);
            let c2 = msg2_block.xor(z0b);
            let c3 = msg3_block.xor(z1b);
            plaintext[i + 32..i + 48].copy_from_slice(&c2.into_bytes());
            plaintext[i + 48..i + 64].copy_from_slice(&c3.into_bytes());
            Self::update(&mut self.state, msg2_block, msg3_block);

            i += 64;
        }
        // Tail handling: 32, 16..31, <16
        while i < plaintext.len() {
            let rem = plaintext.len() - i;
            let z0 = self.state[6].xor(self.state[1]).xor(self.state[2].and(self.state[3]));
            let z1 = self.state[2].xor(self.state[5]).xor(self.state[6].and(self.state[7]));
            if rem >= 32 {
                let mut msg0 = [0u8; 16];
                let mut msg1 = [0u8; 16];
                msg0.copy_from_slice(&plaintext[i..i + 16]);
                msg1.copy_from_slice(&plaintext[i + 16..i + 32]);
                let msg0_block = AesBlock::from_bytes(&msg0);
                let msg1_block = AesBlock::from_bytes(&msg1);
                let c0 = msg0_block.xor(z0);
                let c1 = msg1_block.xor(z1);
                plaintext[i..i + 16].copy_from_slice(&c0.into_bytes());
                plaintext[i + 16..i + 32].copy_from_slice(&c1.into_bytes());
                Self::update(&mut self.state, msg0_block, msg1_block);
                i += 32;
            } else if rem >= 16 {
                let mut msg0 = [0u8; 16];
                let mut msg1 = [0u8; 16];
                msg0.copy_from_slice(&plaintext[i..i + 16]);
                msg1[..rem - 16].copy_from_slice(&plaintext[i + 16..i + rem]);
                let msg0_block = AesBlock::from_bytes(&msg0);
                let msg1_block = AesBlock::from_bytes(&msg1);
                let c0 = msg0_block.xor(z0);
                let c1 = msg1_block.xor(z1);
                plaintext[i..i + 16].copy_from_slice(&c0.into_bytes());
                let remaining = rem - 16;
                plaintext[i + 16..i + 16 + remaining]
                    .copy_from_slice(&c1.into_bytes()[..remaining]);
                Self::update(&mut self.state, msg0_block, msg1_block);
                i += rem; // done
            } else {
                let mut msg0 = [0u8; 16];
                msg0[..rem].copy_from_slice(&plaintext[i..i + rem]);
                let msg0_block = AesBlock::from_bytes(&msg0);
                let c0 = msg0_block.xor(z0);
                plaintext[i..i + rem].copy_from_slice(&c0.into_bytes()[..rem]);
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
        let l1 = l0;
        for _ in 0..7 {
            Self::update(&mut self.state, l0, l1);
        }

        // Generate tag: XOR all 8 state words
        self.state[0]
            .xor(self.state[1])
            .xor(self.state[2])
            .xor(self.state[3])
            .xor(self.state[4])
            .xor(self.state[5])
            .xor(self.state[6])
            .xor(self.state[7])
            .into_bytes()
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
            let z0 = self.state[6].xor(self.state[1]).xor(self.state[2].and(self.state[3]));
            let z1 = self.state[2].xor(self.state[5]).xor(self.state[6].and(self.state[7]));
            let mut c0 = [0u8; 16];
            let mut c1 = [0u8; 16];
            c0.copy_from_slice(&ciphertext[i..i + 16]);
            c1.copy_from_slice(&ciphertext[i + 16..i + 32]);
            let p0 = AesBlock::from_bytes(&c0).xor(z0).into_bytes();
            let p1 = AesBlock::from_bytes(&c1).xor(z1).into_bytes();
            ciphertext[i..i + 16].copy_from_slice(&p0);
            ciphertext[i + 16..i + 32].copy_from_slice(&p1);
            let msg0_block = AesBlock::from_bytes(&p0);
            let msg1_block = AesBlock::from_bytes(&p1);
            Self::update(&mut self.state, msg0_block, msg1_block);

            // Second 32 bytes
            let z0b = self.state[6].xor(self.state[1]).xor(self.state[2].and(self.state[3]));
            let z1b = self.state[2].xor(self.state[5]).xor(self.state[6].and(self.state[7]));
            let mut c2 = [0u8; 16];
            let mut c3 = [0u8; 16];
            c2.copy_from_slice(&ciphertext[i + 32..i + 48]);
            c3.copy_from_slice(&ciphertext[i + 48..i + 64]);
            let p2 = AesBlock::from_bytes(&c2).xor(z0b).into_bytes();
            let p3 = AesBlock::from_bytes(&c3).xor(z1b).into_bytes();
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
            let z0 = self.state[6].xor(self.state[1]).xor(self.state[2].and(self.state[3]));
            let z1 = self.state[2].xor(self.state[5]).xor(self.state[6].and(self.state[7]));
            if rem >= 32 {
                let mut c0 = [0u8; 16];
                let mut c1 = [0u8; 16];
                c0.copy_from_slice(&ciphertext[i..i + 16]);
                c1.copy_from_slice(&ciphertext[i + 16..i + 32]);
                let p0 = AesBlock::from_bytes(&c0).xor(z0).into_bytes();
                let p1 = AesBlock::from_bytes(&c1).xor(z1).into_bytes();
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
                let p0 = AesBlock::from_bytes(&c0).xor(z0).into_bytes();
                let p1_full = AesBlock::from_bytes(&c1).xor(z1).into_bytes();
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
                let p0_full = AesBlock::from_bytes(&c0).xor(z0).into_bytes();
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
        let l1 = l0;
        for _ in 0..7 {
            Self::update(&mut self.state, l0, l1);
        }

        // Verify tag: XOR all 8 state words
        let computed_tag = self.state[0]
            .xor(self.state[1])
            .xor(self.state[2])
            .xor(self.state[3])
            .xor(self.state[4])
            .xor(self.state[5])
            .xor(self.state[6])
            .xor(self.state[7])
            .into_bytes();

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
                let z0 = self.state[6].xor(self.state[1]).xor(self.state[2].and(self.state[3]));
                let z1 = self.state[2].xor(self.state[5]).xor(self.state[6].and(self.state[7]));
                let mut msg0 = [0u8; 16];
                let mut msg1 = [0u8; 16];
                msg0.copy_from_slice(&plaintext[off..off + 16]);
                msg1.copy_from_slice(&plaintext[off + 16..off + 32]);
                let msg0_block = AesBlock::from_bytes(&msg0);
                let msg1_block = AesBlock::from_bytes(&msg1);
                let c0 = msg0_block.xor(z0);
                let c1 = msg1_block.xor(z1);
                plaintext[off..off + 16].copy_from_slice(&c0.into_bytes());
                plaintext[off + 16..off + 32].copy_from_slice(&c1.into_bytes());
                Self::update(&mut self.state, msg0_block, msg1_block);
            }
            i += 128;
        }

        // Fallback hot path: 64-byte chunks.
        while i + 64 <= plaintext.len() {
            // First 32 bytes.
            let z0 = self.state[6].xor(self.state[1]).xor(self.state[2].and(self.state[3]));
            let z1 = self.state[2].xor(self.state[5]).xor(self.state[6].and(self.state[7]));
            let mut msg0 = [0u8; 16];
            let mut msg1 = [0u8; 16];
            msg0.copy_from_slice(&plaintext[i..i + 16]);
            msg1.copy_from_slice(&plaintext[i + 16..i + 32]);
            let msg0_block = AesBlock::from_bytes(&msg0);
            let msg1_block = AesBlock::from_bytes(&msg1);
            let c0 = msg0_block.xor(z0);
            let c1 = msg1_block.xor(z1);
            plaintext[i..i + 16].copy_from_slice(&c0.into_bytes());
            plaintext[i + 16..i + 32].copy_from_slice(&c1.into_bytes());
            Self::update(&mut self.state, msg0_block, msg1_block);

            // Second 32 bytes.
            let z0b = self.state[6].xor(self.state[1]).xor(self.state[2].and(self.state[3]));
            let z1b = self.state[2].xor(self.state[5]).xor(self.state[6].and(self.state[7]));
            let mut msg2 = [0u8; 16];
            let mut msg3 = [0u8; 16];
            msg2.copy_from_slice(&plaintext[i + 32..i + 48]);
            msg3.copy_from_slice(&plaintext[i + 48..i + 64]);
            let msg2_block = AesBlock::from_bytes(&msg2);
            let msg3_block = AesBlock::from_bytes(&msg3);
            let c2 = msg2_block.xor(z0b);
            let c3 = msg3_block.xor(z1b);
            plaintext[i + 32..i + 48].copy_from_slice(&c2.into_bytes());
            plaintext[i + 48..i + 64].copy_from_slice(&c3.into_bytes());
            Self::update(&mut self.state, msg2_block, msg3_block);

            i += 64;
        }

        // Tail handling: 32, 16..31, <16.
        while i < plaintext.len() {
            let rem = plaintext.len() - i;
            let z0 = self.state[6].xor(self.state[1]).xor(self.state[2].and(self.state[3]));
            let z1 = self.state[2].xor(self.state[5]).xor(self.state[6].and(self.state[7]));
            if rem >= 32 {
                let mut msg0 = [0u8; 16];
                let mut msg1 = [0u8; 16];
                msg0.copy_from_slice(&plaintext[i..i + 16]);
                msg1.copy_from_slice(&plaintext[i + 16..i + 32]);
                let msg0_block = AesBlock::from_bytes(&msg0);
                let msg1_block = AesBlock::from_bytes(&msg1);
                let c0 = msg0_block.xor(z0);
                let c1 = msg1_block.xor(z1);
                plaintext[i..i + 16].copy_from_slice(&c0.into_bytes());
                plaintext[i + 16..i + 32].copy_from_slice(&c1.into_bytes());
                Self::update(&mut self.state, msg0_block, msg1_block);
                i += 32;
            } else if rem >= 16 {
                let mut msg0 = [0u8; 16];
                let mut msg1 = [0u8; 16];
                msg0.copy_from_slice(&plaintext[i..i + 16]);
                msg1[..rem - 16].copy_from_slice(&plaintext[i + 16..i + rem]);
                let msg0_block = AesBlock::from_bytes(&msg0);
                let msg1_block = AesBlock::from_bytes(&msg1);
                let c0 = msg0_block.xor(z0);
                let c1 = msg1_block.xor(z1);
                plaintext[i..i + 16].copy_from_slice(&c0.into_bytes());
                let remaining = rem - 16;
                plaintext[i + 16..i + 16 + remaining]
                    .copy_from_slice(&c1.into_bytes()[..remaining]);
                Self::update(&mut self.state, msg0_block, msg1_block);
                i += rem;
            } else {
                let mut msg0 = [0u8; 16];
                msg0[..rem].copy_from_slice(&plaintext[i..i + rem]);
                let msg0_block = AesBlock::from_bytes(&msg0);
                let c0 = msg0_block.xor(z0);
                plaintext[i..i + rem].copy_from_slice(&c0.into_bytes()[..rem]);
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
        let l1 = l0;
        for _ in 0..7 {
            Self::update(&mut self.state, l0, l1);
        }

        self.state[0]
            .xor(self.state[1])
            .xor(self.state[2])
            .xor(self.state[3])
            .xor(self.state[4])
            .xor(self.state[5])
            .xor(self.state[6])
            .xor(self.state[7])
            .into_bytes()
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
                let z0 = self.state[6].xor(self.state[1]).xor(self.state[2].and(self.state[3]));
                let z1 = self.state[2].xor(self.state[5]).xor(self.state[6].and(self.state[7]));
                let mut c0 = [0u8; 16];
                let mut c1 = [0u8; 16];
                c0.copy_from_slice(&ciphertext[off..off + 16]);
                c1.copy_from_slice(&ciphertext[off + 16..off + 32]);
                let p0 = AesBlock::from_bytes(&c0).xor(z0).into_bytes();
                let p1 = AesBlock::from_bytes(&c1).xor(z1).into_bytes();
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
            let z0 = self.state[6].xor(self.state[1]).xor(self.state[2].and(self.state[3]));
            let z1 = self.state[2].xor(self.state[5]).xor(self.state[6].and(self.state[7]));
            let mut c0 = [0u8; 16];
            let mut c1 = [0u8; 16];
            c0.copy_from_slice(&ciphertext[i..i + 16]);
            c1.copy_from_slice(&ciphertext[i + 16..i + 32]);
            let p0 = AesBlock::from_bytes(&c0).xor(z0).into_bytes();
            let p1 = AesBlock::from_bytes(&c1).xor(z1).into_bytes();
            ciphertext[i..i + 16].copy_from_slice(&p0);
            ciphertext[i + 16..i + 32].copy_from_slice(&p1);
            let msg0_block = AesBlock::from_bytes(&p0);
            let msg1_block = AesBlock::from_bytes(&p1);
            Self::update(&mut self.state, msg0_block, msg1_block);

            // Second 32 bytes.
            let z0b = self.state[6].xor(self.state[1]).xor(self.state[2].and(self.state[3]));
            let z1b = self.state[2].xor(self.state[5]).xor(self.state[6].and(self.state[7]));
            let mut c2 = [0u8; 16];
            let mut c3 = [0u8; 16];
            c2.copy_from_slice(&ciphertext[i + 32..i + 48]);
            c3.copy_from_slice(&ciphertext[i + 48..i + 64]);
            let p2 = AesBlock::from_bytes(&c2).xor(z0b).into_bytes();
            let p3 = AesBlock::from_bytes(&c3).xor(z1b).into_bytes();
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
            let z0 = self.state[6].xor(self.state[1]).xor(self.state[2].and(self.state[3]));
            let z1 = self.state[2].xor(self.state[5]).xor(self.state[6].and(self.state[7]));
            if rem >= 32 {
                let mut c0 = [0u8; 16];
                let mut c1 = [0u8; 16];
                c0.copy_from_slice(&ciphertext[i..i + 16]);
                c1.copy_from_slice(&ciphertext[i + 16..i + 32]);
                let p0 = AesBlock::from_bytes(&c0).xor(z0).into_bytes();
                let p1 = AesBlock::from_bytes(&c1).xor(z1).into_bytes();
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
                let p0 = AesBlock::from_bytes(&c0).xor(z0).into_bytes();
                let p1_full = AesBlock::from_bytes(&c1).xor(z1).into_bytes();
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
                let p0_full = AesBlock::from_bytes(&c0).xor(z0).into_bytes();
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
        let l1 = l0;
        for _ in 0..7 {
            Self::update(&mut self.state, l0, l1);
        }

        let computed_tag = self.state[0]
            .xor(self.state[1])
            .xor(self.state[2])
            .xor(self.state[3])
            .xor(self.state[4])
            .xor(self.state[5])
            .xor(self.state[6])
            .xor(self.state[7])
            .into_bytes();

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
                let z0 = self.state[6].xor(self.state[1]).xor(self.state[2].and(self.state[3]));
                let z1 = self.state[2].xor(self.state[5]).xor(self.state[6].and(self.state[7]));
                let mut msg0 = [0u8; 16];
                let mut msg1 = [0u8; 16];
                msg0.copy_from_slice(&plaintext[off..off + 16]);
                msg1.copy_from_slice(&plaintext[off + 16..off + 32]);
                let msg0_block = AesBlock::from_bytes(&msg0);
                let msg1_block = AesBlock::from_bytes(&msg1);
                let c0 = msg0_block.xor(z0);
                let c1 = msg1_block.xor(z1);
                plaintext[off..off + 16].copy_from_slice(&c0.into_bytes());
                plaintext[off + 16..off + 32].copy_from_slice(&c1.into_bytes());
                Self::update(&mut self.state, msg0_block, msg1_block);
            }
            i += 256;
        }

        // Next: 128-byte chunks.
        while i + 128 <= plaintext.len() {
            for r in 0..4 {
                let off = i + r * 32;
                let z0 = self.state[6].xor(self.state[1]).xor(self.state[2].and(self.state[3]));
                let z1 = self.state[2].xor(self.state[5]).xor(self.state[6].and(self.state[7]));
                let mut msg0 = [0u8; 16];
                let mut msg1 = [0u8; 16];
                msg0.copy_from_slice(&plaintext[off..off + 16]);
                msg1.copy_from_slice(&plaintext[off + 16..off + 32]);
                let msg0_block = AesBlock::from_bytes(&msg0);
                let msg1_block = AesBlock::from_bytes(&msg1);
                let c0 = msg0_block.xor(z0);
                let c1 = msg1_block.xor(z1);
                plaintext[off..off + 16].copy_from_slice(&c0.into_bytes());
                plaintext[off + 16..off + 32].copy_from_slice(&c1.into_bytes());
                Self::update(&mut self.state, msg0_block, msg1_block);
            }
            i += 128;
        }

        // Fallback: 64-byte chunks.
        while i + 64 <= plaintext.len() {
            // First 32 bytes.
            let z0 = self.state[6].xor(self.state[1]).xor(self.state[2].and(self.state[3]));
            let z1 = self.state[2].xor(self.state[5]).xor(self.state[6].and(self.state[7]));
            let mut msg0 = [0u8; 16];
            let mut msg1 = [0u8; 16];
            msg0.copy_from_slice(&plaintext[i..i + 16]);
            msg1.copy_from_slice(&plaintext[i + 16..i + 32]);
            let msg0_block = AesBlock::from_bytes(&msg0);
            let msg1_block = AesBlock::from_bytes(&msg1);
            let c0 = msg0_block.xor(z0);
            let c1 = msg1_block.xor(z1);
            plaintext[i..i + 16].copy_from_slice(&c0.into_bytes());
            plaintext[i + 16..i + 32].copy_from_slice(&c1.into_bytes());
            Self::update(&mut self.state, msg0_block, msg1_block);

            // Second 32 bytes.
            let z0b = self.state[6].xor(self.state[1]).xor(self.state[2].and(self.state[3]));
            let z1b = self.state[2].xor(self.state[5]).xor(self.state[6].and(self.state[7]));
            let mut msg2 = [0u8; 16];
            let mut msg3 = [0u8; 16];
            msg2.copy_from_slice(&plaintext[i + 32..i + 48]);
            msg3.copy_from_slice(&plaintext[i + 48..i + 64]);
            let msg2_block = AesBlock::from_bytes(&msg2);
            let msg3_block = AesBlock::from_bytes(&msg3);
            let c2 = msg2_block.xor(z0b);
            let c3 = msg3_block.xor(z1b);
            plaintext[i + 32..i + 48].copy_from_slice(&c2.into_bytes());
            plaintext[i + 48..i + 64].copy_from_slice(&c3.into_bytes());
            Self::update(&mut self.state, msg2_block, msg3_block);

            i += 64;
        }

        while i < plaintext.len() {
            let rem = plaintext.len() - i;
            let z0 = self.state[6].xor(self.state[1]).xor(self.state[2].and(self.state[3]));
            let z1 = self.state[2].xor(self.state[5]).xor(self.state[6].and(self.state[7]));
            if rem >= 32 {
                let mut msg0 = [0u8; 16];
                let mut msg1 = [0u8; 16];
                msg0.copy_from_slice(&plaintext[i..i + 16]);
                msg1.copy_from_slice(&plaintext[i + 16..i + 32]);
                let msg0_block = AesBlock::from_bytes(&msg0);
                let msg1_block = AesBlock::from_bytes(&msg1);
                let c0 = msg0_block.xor(z0);
                let c1 = msg1_block.xor(z1);
                plaintext[i..i + 16].copy_from_slice(&c0.into_bytes());
                plaintext[i + 16..i + 32].copy_from_slice(&c1.into_bytes());
                Self::update(&mut self.state, msg0_block, msg1_block);
                i += 32;
            } else if rem >= 16 {
                let mut msg0 = [0u8; 16];
                let mut msg1 = [0u8; 16];
                msg0.copy_from_slice(&plaintext[i..i + 16]);
                msg1[..rem - 16].copy_from_slice(&plaintext[i + 16..i + rem]);
                let msg0_block = AesBlock::from_bytes(&msg0);
                let msg1_block = AesBlock::from_bytes(&msg1);
                let c0 = msg0_block.xor(z0);
                let c1 = msg1_block.xor(z1);
                plaintext[i..i + 16].copy_from_slice(&c0.into_bytes());
                let remaining = rem - 16;
                plaintext[i + 16..i + 16 + remaining]
                    .copy_from_slice(&c1.into_bytes()[..remaining]);
                Self::update(&mut self.state, msg0_block, msg1_block);
                i += rem;
            } else {
                let mut msg0 = [0u8; 16];
                msg0[..rem].copy_from_slice(&plaintext[i..i + rem]);
                let msg0_block = AesBlock::from_bytes(&msg0);
                let c0 = msg0_block.xor(z0);
                plaintext[i..i + rem].copy_from_slice(&c0.into_bytes()[..rem]);
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
        let l1 = l0;
        for _ in 0..7 {
            Self::update(&mut self.state, l0, l1);
        }

        self.state[0]
            .xor(self.state[1])
            .xor(self.state[2])
            .xor(self.state[3])
            .xor(self.state[4])
            .xor(self.state[5])
            .xor(self.state[6])
            .xor(self.state[7])
            .into_bytes()
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
                let z0 = self.state[6].xor(self.state[1]).xor(self.state[2].and(self.state[3]));
                let z1 = self.state[2].xor(self.state[5]).xor(self.state[6].and(self.state[7]));
                let mut c0 = [0u8; 16];
                let mut c1 = [0u8; 16];
                c0.copy_from_slice(&ciphertext[off..off + 16]);
                c1.copy_from_slice(&ciphertext[off + 16..off + 32]);
                let p0 = AesBlock::from_bytes(&c0).xor(z0).into_bytes();
                let p1 = AesBlock::from_bytes(&c1).xor(z1).into_bytes();
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
                let z0 = self.state[6].xor(self.state[1]).xor(self.state[2].and(self.state[3]));
                let z1 = self.state[2].xor(self.state[5]).xor(self.state[6].and(self.state[7]));
                let mut c0 = [0u8; 16];
                let mut c1 = [0u8; 16];
                c0.copy_from_slice(&ciphertext[off..off + 16]);
                c1.copy_from_slice(&ciphertext[off + 16..off + 32]);
                let p0 = AesBlock::from_bytes(&c0).xor(z0).into_bytes();
                let p1 = AesBlock::from_bytes(&c1).xor(z1).into_bytes();
                ciphertext[off..off + 16].copy_from_slice(&p0);
                ciphertext[off + 16..off + 32].copy_from_slice(&p1);
                let msg0_block = AesBlock::from_bytes(&p0);
                let msg1_block = AesBlock::from_bytes(&p1);
                Self::update(&mut self.state, msg0_block, msg1_block);
            }
            i += 128;
        }

        while i + 64 <= ciphertext.len() {
            let z0 = self.state[6].xor(self.state[1]).xor(self.state[2].and(self.state[3]));
            let z1 = self.state[2].xor(self.state[5]).xor(self.state[6].and(self.state[7]));
            let mut c0 = [0u8; 16];
            let mut c1 = [0u8; 16];
            c0.copy_from_slice(&ciphertext[i..i + 16]);
            c1.copy_from_slice(&ciphertext[i + 16..i + 32]);
            let p0 = AesBlock::from_bytes(&c0).xor(z0).into_bytes();
            let p1 = AesBlock::from_bytes(&c1).xor(z1).into_bytes();
            ciphertext[i..i + 16].copy_from_slice(&p0);
            ciphertext[i + 16..i + 32].copy_from_slice(&p1);
            let msg0_block = AesBlock::from_bytes(&p0);
            let msg1_block = AesBlock::from_bytes(&p1);
            Self::update(&mut self.state, msg0_block, msg1_block);

            let z0b = self.state[6].xor(self.state[1]).xor(self.state[2].and(self.state[3]));
            let z1b = self.state[2].xor(self.state[5]).xor(self.state[6].and(self.state[7]));
            let mut c2 = [0u8; 16];
            let mut c3 = [0u8; 16];
            c2.copy_from_slice(&ciphertext[i + 32..i + 48]);
            c3.copy_from_slice(&ciphertext[i + 48..i + 64]);
            let p2 = AesBlock::from_bytes(&c2).xor(z0b).into_bytes();
            let p3 = AesBlock::from_bytes(&c3).xor(z1b).into_bytes();
            ciphertext[i + 32..i + 48].copy_from_slice(&p2);
            ciphertext[i + 48..i + 64].copy_from_slice(&p3);
            let msg2_block = AesBlock::from_bytes(&p2);
            let msg3_block = AesBlock::from_bytes(&p3);
            Self::update(&mut self.state, msg2_block, msg3_block);

            i += 64;
        }

        while i < ciphertext.len() {
            let rem = ciphertext.len() - i;
            let z0 = self.state[6].xor(self.state[1]).xor(self.state[2].and(self.state[3]));
            let z1 = self.state[2].xor(self.state[5]).xor(self.state[6].and(self.state[7]));
            if rem >= 32 {
                let mut c0 = [0u8; 16];
                let mut c1 = [0u8; 16];
                c0.copy_from_slice(&ciphertext[i..i + 16]);
                c1.copy_from_slice(&ciphertext[i + 16..i + 32]);
                let p0 = AesBlock::from_bytes(&c0).xor(z0).into_bytes();
                let p1 = AesBlock::from_bytes(&c1).xor(z1).into_bytes();
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
                let p0 = AesBlock::from_bytes(&c0).xor(z0).into_bytes();
                let p1_full = AesBlock::from_bytes(&c1).xor(z1).into_bytes();
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
                let p0_full = AesBlock::from_bytes(&c0).xor(z0).into_bytes();
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
        let l1 = l0;
        for _ in 0..7 {
            Self::update(&mut self.state, l0, l1);
        }

        let computed_tag = self.state[0]
            .xor(self.state[1])
            .xor(self.state[2])
            .xor(self.state[3])
            .xor(self.state[4])
            .xor(self.state[5])
            .xor(self.state[6])
            .xor(self.state[7])
            .into_bytes();

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
        crate::optimize::telemetry::AEGIS_BATCH_OPS.fetch_add(count as u64, Ordering::Relaxed);
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
        if buf.len() < len + 16 {
            return Err(ConnectionError::BufferTooShort);
        }
        let nonce16 = super::make_nonce16(&self.iv, counter);
        let mut cipher = crate::crypto::Aegis128L::new(&self.key, &nonce16)
            .map_err(|_| ConnectionError::CryptoError("crypto failure".into()))?;
        let (pt, rest) = buf.split_at_mut(len);
        let tag = cipher.encrypt_in_place(pt, ad);
        rest[..16].copy_from_slice(&tag);
        Ok(len + 16)
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
        if first.buf.len() < first.plaintext_len + 16 {
            return Err(ConnectionError::BufferTooShort);
        }
        let first_nonce = super::make_nonce16(&self.iv, first.counter);
        let mut cipher = Aegis128L::new(&self.key, &first_nonce)
            .map_err(|_| ConnectionError::CryptoError("crypto failure".into()))?;
        for (index, item) in items.iter_mut().enumerate() {
            if index > 0 {
                if item.buf.len() < item.plaintext_len + 16 {
                    return Err(ConnectionError::BufferTooShort);
                }
                let nonce16 = super::make_nonce16(&self.iv, item.counter);
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
        let nonce16 = super::make_nonce16(&self.iv, counter);
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
        let first_nonce = super::make_nonce16(&self.iv, first.counter);
        let mut cipher = Aegis128L::new(&self.key, &first_nonce)
            .map_err(|_| ConnectionError::CryptoError("crypto failure".into()))?;
        for (index, item) in items.iter_mut().enumerate() {
            if index > 0 {
                if item.buf.len() < 16 {
                    return Err(ConnectionError::BufferTooShort);
                }
                let nonce16 = super::make_nonce16(&self.iv, item.counter);
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
        let mut item = AeadSealItem { counter, ad, buf, plaintext_len: len };
        self.seal_batch(core::slice::from_mut(&mut item))?;
        Ok(len + 16)
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
        let mut item = AeadSealItem { counter, ad, buf, plaintext_len: len };
        self.seal_batch(core::slice::from_mut(&mut item))?;
        Ok(len + 16)
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
    if first.buf.len() < first.plaintext_len + 16 {
        return Err(ConnectionError::BufferTooShort);
    }
    let first_nonce = super::make_nonce16(iv, first.counter);
    let mut cipher = Aegis128X4::new(key, &first_nonce)
        .map_err(|_| ConnectionError::CryptoError("crypto failure".into()))?;
    for (index, item) in items.iter_mut().enumerate() {
        if index > 0 {
            if item.buf.len() < item.plaintext_len + 16 {
                return Err(ConnectionError::BufferTooShort);
            }
            let nonce16 = super::make_nonce16(iv, item.counter);
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
    let first_nonce = super::make_nonce16(iv, first.counter);
    let mut cipher = Aegis128X4::new(key, &first_nonce)
        .map_err(|_| ConnectionError::CryptoError("crypto failure".into()))?;
    for (index, item) in items.iter_mut().enumerate() {
        if index > 0 {
            if item.buf.len() < 16 {
                return Err(ConnectionError::BufferTooShort);
            }
            let nonce16 = super::make_nonce16(iv, item.counter);
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
    if first.buf.len() < first.plaintext_len + 16 {
        return Err(ConnectionError::BufferTooShort);
    }
    let first_nonce = super::make_nonce16(iv, first.counter);
    let mut cipher = Aegis128X8::new(key, &first_nonce)
        .map_err(|_| ConnectionError::CryptoError("crypto failure".into()))?;
    for (index, item) in items.iter_mut().enumerate() {
        if index > 0 {
            if item.buf.len() < item.plaintext_len + 16 {
                return Err(ConnectionError::BufferTooShort);
            }
            let nonce16 = super::make_nonce16(iv, item.counter);
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
    let first_nonce = super::make_nonce16(iv, first.counter);
    let mut cipher = Aegis128X8::new(key, &first_nonce)
        .map_err(|_| ConnectionError::CryptoError("crypto failure".into()))?;
    for (index, item) in items.iter_mut().enumerate() {
        if index > 0 {
            if item.buf.len() < 16 {
                return Err(ConnectionError::BufferTooShort);
            }
            let nonce16 = super::make_nonce16(iv, item.counter);
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
mod tests {
    use super::{Aegis128L, Aegis128X4, Aegis128X8, AegisError};

    // Fixed key/nonce used across all inline tests.
    const KEY: [u8; 16] = [
        0x10, 0x01, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00,
    ];
    const NONCE: [u8; 16] = [
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e,
        0x1f,
    ];

    // Encrypt with Aegis128L; returns (ciphertext, tag).
    fn enc(msg: &[u8], ad: &[u8]) -> (Vec<u8>, [u8; 16]) {
        let mut buf = msg.to_vec();
        let tag = Aegis128L::new(&KEY, &NONCE).unwrap().encrypt_in_place(&mut buf, ad);
        (buf, tag)
    }

    // Decrypt with Aegis128L; returns plaintext or error.
    fn dec(ct: &[u8], ad: &[u8], tag: &[u8; 16]) -> Result<Vec<u8>, AegisError> {
        Aegis128L::new(&KEY, &NONCE).unwrap().decrypt_verified(ct, ad, tag)
    }

    // ---- Roundtrip ----

    #[test]
    fn aegis128l_roundtrip_empty_msg() {
        let (ct, tag) = enc(b"", b"");
        assert!(ct.is_empty());
        assert_eq!(dec(&ct, b"", &tag).unwrap(), b"");
    }

    #[test]
    fn aegis128l_roundtrip_one_byte() {
        let msg = [0x42u8];
        let (ct, tag) = enc(&msg, b"ad");
        assert_eq!(ct.len(), 1);
        // Encryption must change the byte.
        assert_ne!(ct[0], msg[0]);
        assert_eq!(dec(&ct, b"ad", &tag).unwrap(), msg);
    }

    #[test]
    fn aegis128l_roundtrip_block_aligned_32() {
        let msg = [0xabu8; 32];
        let (ct, tag) = enc(&msg, b"");
        assert_eq!(ct.len(), 32);
        assert_eq!(dec(&ct, b"", &tag).unwrap().as_slice(), &msg[..]);
    }

    #[test]
    fn aegis128l_roundtrip_unaligned_33() {
        let msg: Vec<u8> = (0u8..33).collect();
        let (ct, tag) = enc(&msg, b"hdr");
        assert_eq!(ct.len(), 33);
        assert_eq!(dec(&ct, b"hdr", &tag).unwrap(), msg);
    }

    // ---- Associated data ----

    #[test]
    fn aegis128l_empty_ad_accepted() {
        let msg = b"hello world12345";
        let (ct, tag) = enc(msg, b"");
        assert_eq!(dec(&ct, b"", &tag).unwrap().as_slice(), msg);
    }

    #[test]
    fn aegis128l_different_ad_changes_tag() {
        let msg = b"same plaintext!!";
        let (_, t1) = enc(msg, b"ad-one");
        let (_, t2) = enc(msg, b"ad-two");
        assert_ne!(t1, t2);
    }

    #[test]
    fn aegis128l_wrong_ad_fails_authentication() {
        let msg = b"confidential msg";
        let (ct, tag) = enc(msg, b"correct-ad");
        assert_eq!(dec(&ct, b"wrong-ad", &tag), Err(AegisError::InvalidTag));
    }

    // ---- Forgery detection ----

    #[test]
    fn aegis128l_ciphertext_bit_flip_detected() {
        let msg = b"protect this msg";
        let (mut ct, tag) = enc(msg, b"");
        ct[0] ^= 0x01;
        assert_eq!(dec(&ct, b"", &tag), Err(AegisError::InvalidTag));
    }

    #[test]
    fn aegis128l_tag_bit_flip_detected() {
        let msg = b"another message!";
        let (ct, mut tag) = enc(msg, b"");
        tag[0] ^= 0x01;
        assert_eq!(dec(&ct, b"", &tag), Err(AegisError::InvalidTag));
    }

    // ---- Nonce sensitivity ----

    #[test]
    fn aegis128l_different_nonce_different_ciphertext() {
        let msg = b"same plaintext!!";
        let alt_nonce = [0u8; 16]; // different from NONCE
        let (ct1, _) = enc(msg, b"");
        let mut buf = msg.to_vec();
        Aegis128L::new(&KEY, &alt_nonce).unwrap().encrypt_in_place(&mut buf, b"");
        assert_ne!(ct1, buf);
    }

    // ---- decrypt_verified API ----

    #[test]
    fn aegis128l_decrypt_verified_ok() {
        let msg = b"verified message";
        let (ct, tag) = enc(msg, b"ad");
        let pt = Aegis128L::new(&KEY, &NONCE).unwrap().decrypt_verified(&ct, b"ad", &tag).unwrap();
        assert_eq!(pt.as_slice(), msg);
    }

    #[test]
    fn aegis128l_decrypt_verified_returns_err_on_forgery() {
        let msg = b"do not leak this";
        let (mut ct, tag) = enc(msg, b"");
        ct[0] ^= 0xff;
        let result = Aegis128L::new(&KEY, &NONCE).unwrap().decrypt_verified(&ct, b"", &tag);
        assert_eq!(result, Err(AegisError::InvalidTag));
    }

    // ---- Determinism ----

    #[test]
    fn aegis128l_same_inputs_same_output() {
        let msg = b"deterministic!!!";
        let (ct1, tag1) = enc(msg, b"ad");
        let (ct2, tag2) = enc(msg, b"ad");
        assert_eq!(ct1, ct2);
        assert_eq!(tag1, tag2);
    }

    // ---- Large message exercises all hot paths ----

    #[test]
    fn aegis128l_roundtrip_large_multi_path() {
        // 300 bytes exercises all three hot-path levels (64-byte, 32-byte, tail) in Aegis128L
        let msg: Vec<u8> = (0u8..=255).cycle().take(300).collect();
        let ad = b"large-msg-ad";
        let (ct, tag) = enc(&msg, ad);
        assert_eq!(ct.len(), 300);
        assert_eq!(dec(&ct, ad, &tag).unwrap(), msg);
    }

    // ---- X4/X8 variant consistency (inline check; full matrix is in crypto/tests.rs) ----

    #[test]
    fn aegis128x4_roundtrip_and_matches_base() {
        let msg: Vec<u8> = (0u8..=100).collect();
        let ad = b"x4-ad";

        let (ct_base, tag_base) = enc(&msg, ad);

        let mut buf = msg.clone();
        let tag_x4 = Aegis128X4::new(&KEY, &NONCE).unwrap().encrypt_in_place(&mut buf, ad);
        assert_eq!(buf, ct_base, "X4 ciphertext must equal Aegis128L");
        assert_eq!(tag_x4, tag_base, "X4 tag must equal Aegis128L");

        // Decrypt X4-produced ciphertext back to plaintext.
        let pt = dec(&ct_base, ad, &tag_base).unwrap();
        assert_eq!(pt, msg);
    }

    #[test]
    fn aegis128x4_batch_seal_matches_single() {
        use super::{AeadSeal, AeadSealItem, Aegis128X4Aead};

        let key = [0x77u8; 16];
        let iv = [0x88u8; 12];
        let ad = b"batch-ad";
        let pt = b"homogeneous-payload!!";
        let seal = Aegis128X4Aead::new(&key, &iv);

        let mut batch_bufs = (0..4u64)
            .map(|_| {
                let mut b = vec![0u8; pt.len() + 16];
                b[..pt.len()].copy_from_slice(pt);
                b
            })
            .collect::<Vec<_>>();
        let mut items = batch_bufs
            .iter_mut()
            .enumerate()
            .map(|(i, buf)| AeadSealItem {
                counter: i as u64 + 1,
                ad,
                buf: buf.as_mut_slice(),
                plaintext_len: pt.len(),
            })
            .collect::<Vec<_>>();
        seal.seal_batch(items.as_mut_slice()).unwrap();

        for (i, buf) in batch_bufs.iter().enumerate() {
            let mut single = vec![0u8; pt.len() + 16];
            single[..pt.len()].copy_from_slice(pt);
            let single_len = seal
                .seal_with_u64_counter(i as u64 + 1, ad, single.as_mut_slice(), pt.len(), None)
                .unwrap();
            assert_eq!(buf.len(), single_len);
            assert_eq!(buf, &single);
        }
    }

    #[test]
    fn aegis128x8_batch_open_matches_single() {
        use super::{AeadOpen, AeadOpenItem, AeadSeal, AeadSealItem, Aegis128X8Aead};

        let key = [0x99u8; 16];
        let iv = [0xAAu8; 12];
        let ad = b"open-batch";
        let pt = b"decrypt-me-please!!";
        let seal = Aegis128X8Aead::new(&key, &iv);
        let open = Aegis128X8Aead::new(&key, &iv);

        let mut sealed = vec![0u8; pt.len() + 16];
        sealed[..pt.len()].copy_from_slice(pt);
        let mut seal_item =
            AeadSealItem { counter: 42, ad, buf: sealed.as_mut_slice(), plaintext_len: pt.len() };
        seal.seal_batch(core::slice::from_mut(&mut seal_item)).unwrap();

        let mut single = sealed.clone();
        let pt_len = open.open_with_u64_counter(42, ad, single.as_mut_slice()).unwrap();
        assert_eq!(pt_len, pt.len());
        assert_eq!(&single[..pt_len], pt);

        let mut batch_bufs = (0..3usize)
            .map(|i| {
                let mut buf = vec![0u8; pt.len() + 16];
                buf[..pt.len()].copy_from_slice(pt);
                let mut item = AeadSealItem {
                    counter: 100 + i as u64,
                    ad,
                    buf: buf.as_mut_slice(),
                    plaintext_len: pt.len(),
                };
                seal.seal_batch(core::slice::from_mut(&mut item)).unwrap();
                buf
            })
            .collect::<Vec<_>>();
        let mut open_items = batch_bufs
            .iter_mut()
            .enumerate()
            .map(|(i, buf)| AeadOpenItem { counter: 100 + i as u64, ad, buf: buf.as_mut_slice() })
            .collect::<Vec<_>>();
        open.open_batch(open_items.as_mut_slice()).unwrap();
        for buf in &batch_bufs {
            assert_eq!(&buf[..pt.len()], pt);
        }
    }

    #[test]
    fn aegis128x8_roundtrip_and_matches_base() {
        // 256 bytes = exactly 2 hot-path chunks for X8
        let msg: Vec<u8> = (0u8..=255).collect();
        let ad = b"x8-ad";

        let (ct_base, tag_base) = enc(&msg, ad);

        let mut buf = msg.clone();
        let tag_x8 = Aegis128X8::new(&KEY, &NONCE).unwrap().encrypt_in_place(&mut buf, ad);
        assert_eq!(buf, ct_base, "X8 ciphertext must equal Aegis128L");
        assert_eq!(tag_x8, tag_base, "X8 tag must equal Aegis128L");

        let pt = dec(&ct_base, ad, &tag_base).unwrap();
        assert_eq!(pt, msg);
    }

    // TODO-393: differential test — the AEAD wrapper reuses cipher state via
    // `reinit` after the first packet. Output must be byte-identical to a fresh
    // `Aegis128L::new` per packet (the pre-optimization baseline).
    #[test]
    fn aegis128l_aead_reinit_matches_fresh_new_per_packet() {
        use super::super::make_nonce16;
        use super::{AeadOpen, AeadSeal, Aegis128LAead};

        let key = [0x7au8; 16];
        let iv = [0x1bu8; 12];
        let ad = b"diff-ad";
        let pt = b"reinit-state-reuse-payload";

        let seal = Aegis128LAead::new(&key, &iv);
        let open = Aegis128LAead::new(&key, &iv);

        for counter in 1u64..=64 {
            // Reference: fresh cipher per packet (baseline).
            let nonce16 = make_nonce16(&iv, counter);
            let mut ref_buf = vec![0u8; pt.len() + 16];
            ref_buf[..pt.len()].copy_from_slice(pt);
            let ref_tag = Aegis128L::new(&key, &nonce16)
                .unwrap()
                .encrypt_in_place(&mut ref_buf[..pt.len()], ad);
            ref_buf[pt.len()..].copy_from_slice(&ref_tag);

            // Optimized: AEAD wrapper (reinit after first packet).
            let mut opt_buf = vec![0u8; pt.len() + 16];
            opt_buf[..pt.len()].copy_from_slice(pt);
            let opt_len = seal
                .seal_with_u64_counter(counter, ad, opt_buf.as_mut_slice(), pt.len(), None)
                .unwrap();
            assert_eq!(opt_len, pt.len() + 16);
            assert_eq!(opt_buf, ref_buf, "ciphertext/tag diverged at counter {counter}");

            // Decrypt via the wrapper must recover plaintext.
            let pt_len = open.open_with_u64_counter(counter, ad, opt_buf.as_mut_slice()).unwrap();
            assert_eq!(pt_len, pt.len());
            assert_eq!(&opt_buf[..pt_len], pt);
        }
    }

    #[test]
    fn aegis_wrapper_drop_erases_keys_and_ivs() {
        use super::{AeadSeal, Aegis128LAead, Aegis128X4Aead, Aegis128X8Aead};
        use std::sync::{Arc, Mutex};

        let events = Arc::new(Mutex::new(Vec::<(&'static str, Vec<u8>)>::new()));
        let observed = Arc::clone(&events);
        let _observer = crate::secret::test_observation::install(Arc::new(move |label, bytes| {
            observed.lock().expect("erasure event lock").push((label, bytes.to_vec()));
        }));

        let key = [0xA5u8; 16];
        let iv = [0x5Au8; 12];
        for seal in [
            Box::new(Aegis128LAead::new(&key, &iv)) as Box<dyn AeadSeal + Send + Sync>,
            Box::new(Aegis128X4Aead::new(&key, &iv)),
            Box::new(Aegis128X8Aead::new(&key, &iv)),
        ] {
            let mut buffer = vec![0xC3u8; 48];
            seal.seal_with_u64_counter(7, b"drop-proof", &mut buffer, 32, None)
                .expect("initialize wrapper state");
        }

        let events = events.lock().expect("erasure events");
        for (label, expected_len) in [
            ("aegis_l_wrapper_key", 16),
            ("aegis_l_wrapper_iv", 12),
            ("aegis_l_inner_state", 128),
            ("aegis_x4_wrapper_key", 16),
            ("aegis_x4_wrapper_iv", 12),
            ("aegis_x4_inner_state", 128),
            ("aegis_x8_wrapper_key", 16),
            ("aegis_x8_wrapper_iv", 12),
            ("aegis_x8_inner_state", 128),
        ] {
            let bytes = events
                .iter()
                .find_map(|(event_label, bytes)| (*event_label == label).then_some(bytes))
                .unwrap_or_else(|| panic!("missing erasure event: {label}"));
            assert_eq!(bytes.len(), expected_len, "wrong erased range for {label}");
            assert!(bytes.iter().all(|byte| *byte == 0), "non-zero byte retained by {label}");
        }
    }

    #[test]
    fn aegis_replacement_and_partial_wrapper_drop_are_erased() {
        use super::{AeadSeal, Aegis128LAead};
        use std::sync::{Arc, Mutex};

        let events = Arc::new(Mutex::new(Vec::<(&'static str, Vec<u8>)>::new()));
        let observed = Arc::clone(&events);
        let _observer = crate::secret::test_observation::install(Arc::new(move |label, bytes| {
            observed.lock().expect("erasure event lock").push((label, bytes.to_vec()));
        }));

        let mut retained = Some(Aegis128LAead::new(&[0x3C; 16], &[0xC3; 12]));
        let mut buffer = vec![0xA7; 48];
        retained
            .as_ref()
            .expect("retained wrapper")
            .seal_with_u64_counter(9, b"replacement-proof", &mut buffer, 32, None)
            .expect("initialize retained wrapper state");
        drop(retained.replace(Aegis128LAead::new(&[0x6D; 16], &[0xD6; 12])));
        drop(Aegis128LAead::new(&[0xD4; 7], &[0x4D; 5]));

        let events = events.lock().expect("erasure events");
        for (label, expected_count) in
            [("aegis_l_wrapper_key", 2), ("aegis_l_wrapper_iv", 2), ("aegis_l_inner_state", 1)]
        {
            let matching =
                events.iter().filter(|(event_label, _)| *event_label == label).collect::<Vec<_>>();
            assert_eq!(matching.len(), expected_count, "wrong erasure event count for {label}");
            for (_, bytes) in matching {
                assert!(!bytes.is_empty(), "erased range must be observable for {label}");
                assert!(bytes.iter().all(|byte| *byte == 0), "non-zero byte retained by {label}");
            }
        }
        for label in ["aegis_l_wrapper_key", "aegis_l_wrapper_iv"] {
            let bytes = events
                .iter()
                .find_map(|(event_label, bytes)| (*event_label == label).then_some(bytes))
                .unwrap_or_else(|| panic!("missing erasure event: {label}"));
            assert!(bytes.iter().all(|byte| *byte == 0), "partial wrapper retained {label}");
        }
    }

    #[test]
    fn aegis_wrapper_supports_concurrent_packets() {
        use super::{AeadSeal, Aegis128LAead};
        use std::sync::Arc;
        use std::thread;

        let key = [0x42u8; 16];
        let iv = [0x24u8; 12];
        let ad = b"concurrent-aegis";
        let plaintext = b"same-wrapper-independent-state";
        let seal = Arc::new(Aegis128LAead::new(&key, &iv));
        let handles = (1u64..=8)
            .map(|counter| {
                let seal = Arc::clone(&seal);
                thread::spawn(move || {
                    let mut buf = vec![0u8; plaintext.len() + 16];
                    buf[..plaintext.len()].copy_from_slice(plaintext);
                    seal.seal_with_u64_counter(counter, ad, &mut buf, plaintext.len(), None)
                        .expect("concurrent seal");
                    (counter, buf)
                })
            })
            .collect::<Vec<_>>();

        for handle in handles {
            let (counter, actual) = handle.join().expect("concurrent worker");
            let nonce16 = super::super::make_nonce16(&iv, counter);
            let mut expected = plaintext.to_vec();
            let tag = Aegis128L::new(&key, &nonce16)
                .expect("reference cipher")
                .encrypt_in_place(&mut expected, ad);
            expected.extend_from_slice(&tag);
            assert_eq!(actual, expected, "counter {counter} diverged");
        }
    }
}
