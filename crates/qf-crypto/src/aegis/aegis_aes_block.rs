use std::sync::OnceLock;
use zeroize::Zeroize;

#[derive(Clone, Debug, Default)]
pub(crate) struct AesBlock([u8; 16]);

impl Drop for AesBlock {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

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
            let features = qf_cpu::FeatureDetector::instance().features_full();
            if features.aesni {
                if features.vaes && features.avx512f && features.avx512vl {
                    return AesEncBackend::Vaes512;
                }
                if features.vaes && features.avx2 {
                    return AesEncBackend::Vaes256;
                }
                return AesEncBackend::Aesni;
            }
        }

        #[cfg(target_arch = "aarch64")]
        {
            if qf_cpu::FeatureDetector::instance().features_full().aes {
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
    use qf_telemetry as telemetry;
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
    blocks: [&[u8; 16]; 4],
    round_keys: [&[u8; 16]; 4],
) -> ([u8; 16], [u8; 16], [u8; 16], [u8; 16]) {
    use core::arch::x86_64::*;
    let x0 = _mm_loadu_si128(blocks[0].as_ptr() as *const __m128i);
    let x1 = _mm_loadu_si128(blocks[1].as_ptr() as *const __m128i);
    let x2 = _mm_loadu_si128(blocks[2].as_ptr() as *const __m128i);
    let x3 = _mm_loadu_si128(blocks[3].as_ptr() as *const __m128i);
    let k0 = _mm_loadu_si128(round_keys[0].as_ptr() as *const __m128i);
    let k1 = _mm_loadu_si128(round_keys[1].as_ptr() as *const __m128i);
    let k2 = _mm_loadu_si128(round_keys[2].as_ptr() as *const __m128i);
    let k3 = _mm_loadu_si128(round_keys[3].as_ptr() as *const __m128i);

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

pub(crate) fn aesenc8_update_inputs(in_b: &[[u8; 16]; 8], in_rk: &[[u8; 16]; 8]) -> [[u8; 16]; 8] {
    match aes_backend() {
        #[cfg(target_arch = "x86_64")]
        // SAFETY: aes_backend() selected Vaes512 only after runtime detection
        // confirmed AVX512F+VAES. All in_b/in_rk elements are [u8; 16] arrays
        // passed by reference - no out-of-bounds access possible.
        AesEncBackend::Vaes512 => unsafe {
            let (o7, o6, o5, o4) = aesenc4_vaes512(
                [&in_b[7], &in_b[6], &in_b[5], &in_b[4]],
                [&in_rk[7], &in_rk[6], &in_rk[5], &in_rk[4]],
            );
            let (o3, o2, o1, o0) = aesenc4_vaes512(
                [&in_b[3], &in_b[2], &in_b[1], &in_b[0]],
                [&in_rk[3], &in_rk[2], &in_rk[1], &in_rk[0]],
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

    pub(crate) fn to_bytes(&self) -> [u8; 16] {
        self.0
    }

    /// Zeroize the internal block bytes in place.
    pub(crate) fn zeroize(&mut self) {
        self.0.zeroize();
    }

    #[inline(always)]
    pub(crate) fn xor(&self, other: &Self) -> Self {
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
    pub(crate) fn and(&self, other: &Self) -> Self {
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
