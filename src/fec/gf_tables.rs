use crate::optimize::{self, SimdPolicy};
use rayon::prelude::*;

#[inline(always)]
pub(crate) unsafe fn prefetch_log(idx: usize) {
    #[cfg(target_arch = "x86_64")]
    {
        use std::arch::x86_64::{_mm_prefetch, _MM_HINT_T0};
        _mm_prefetch(LOG_TABLE.as_ptr().add(idx) as *const i8, _MM_HINT_T0);
    }
    #[cfg(target_arch = "aarch64")]
    {
        use std::arch::aarch64::__prefetch;
        __prefetch(LOG_TABLE.as_ptr().add(idx));
    }
}

#[inline(always)]
pub(crate) unsafe fn prefetch_exp(idx: usize) {
    #[cfg(target_arch = "x86_64")]
    {
        use std::arch::x86_64::{_mm_prefetch, _MM_HINT_T0};
        _mm_prefetch(EXP_TABLE.as_ptr().add(idx) as *const i8, _MM_HINT_T0);
    }
    #[cfg(target_arch = "aarch64")]
    {
        use std::arch::aarch64::__prefetch;
        __prefetch(EXP_TABLE.as_ptr().add(idx));
    }
}

#[inline(always)]
pub(crate) unsafe fn prefetch_data(ptr: *const u8) {
    #[cfg(target_arch = "x86_64")]
    {
        use std::arch::x86_64::{_mm_prefetch, _MM_HINT_T0};
        _mm_prefetch(ptr as *const i8, _MM_HINT_T0);
    }
    #[cfg(target_arch = "aarch64")]
    {
        use std::arch::aarch64::__prefetch;
        __prefetch(ptr);
    }
}

#[inline(always)]
pub(crate) fn gf_mul_table(a: u8, b: u8) -> u8 {
    if a == 0 || b == 0 {
        return 0;
    }
    unsafe {
        let log_a = LOG_TABLE[a as usize] as u16;
        let log_b = LOG_TABLE[b as usize] as u16;
        let sum_log = log_a + log_b;
        EXP_TABLE[sum_log as usize]
    }
}

#[inline(always)]
fn gf_mul_shift(mut a: u8, mut b: u8) -> u8 {
    let mut res = 0u8;
    while b != 0 {
        if b & 1 != 0 {
            res ^= a;
        }
        let carry = a & 0x80;
        a <<= 1;
        if carry != 0 {
            a ^= IRREDUCIBLE_POLY as u8;
        }
        b >>= 1;
    }
    res
}

#[cfg(all(target_arch = "x86_64"))]
#[target_feature(enable = "avx512f,avx512vbmi,pclmulqdq")]
pub(crate) unsafe fn gf_mul_bitsliced_avx512(a: u8, b: u8) -> u8 {
    use std::arch::x86_64::*;

    // Broadcast inputs across all lanes and perform carry-less multiplication
    let a128 = _mm_set_epi64x(0, a as i64);
    let b128 = _mm_set_epi64x(0, b as i64);
    let va = _mm512_broadcast_i64x2(a128);
    let vb = _mm512_broadcast_i64x2(b128);
    let prod = _mm512_clmulepi64_epi128(va, vb, 0x00);
    let low = _mm512_castsi512_si128(prod);
    let mut t = _mm_extract_epi16(low, 0) as u16;
    t ^= t >> 8;
    t ^= t >> 4;
    t ^= t >> 2;
    t ^= t >> 1;
    (t & 0xFF) as u8
}

#[cfg(all(target_arch = "x86_64"))]
#[target_feature(enable = "avx512f,avx512vbmi")]
pub(crate) unsafe fn gf_mul_avx512(a: u8, b: u8) -> u8 {
    gf_mul_bitsliced_avx512(a, b)
}

#[cfg(all(target_arch = "x86_64"))]
#[target_feature(enable = "avx2,pclmulqdq")]
pub(crate) unsafe fn gf_mul_bitsliced_avx2(a: u8, b: u8) -> u8 {
    use std::arch::x86_64::*;

    let a128 = _mm_set_epi64x(0, a as i64);
    let b128 = _mm_set_epi64x(0, b as i64);
    let va = _mm256_broadcastsi128_si256(a128);
    let vb = _mm256_broadcastsi128_si256(b128);
    let prod = _mm256_clmulepi64_epi128(va, vb, 0x00);
    let low = _mm256_castsi256_si128(prod);
    let mut t = _mm_extract_epi16(low, 0) as u16;
    t ^= t >> 8;
    t ^= t >> 4;
    t ^= t >> 2;
    t ^= t >> 1;
    (t & 0xFF) as u8
}

#[cfg(all(target_arch = "x86_64"))]
#[target_feature(enable = "avx2")]
pub(crate) unsafe fn gf_mul_avx2(a: u8, b: u8) -> u8 {
    gf_mul_bitsliced_avx2(a, b)
}

#[cfg(all(target_arch = "x86_64"))]
#[target_feature(enable = "sse2,pclmulqdq")]
pub(crate) unsafe fn gf_mul_bitsliced_sse2(a: u8, b: u8) -> u8 {
    use std::arch::x86_64::*;

    let a_v = _mm_set_epi64x(0, a as i64);
    let b_v = _mm_set_epi64x(0, b as i64);
    let res_v = _mm_clmulepi64_si128(a_v, b_v, 0x00);
    let res16 = _mm_extract_epi16(res_v, 0) as u16;
    let t = res16 ^ (res16 >> 8);
    let t = t ^ (t >> 4);
    let t = t ^ (t >> 2);
    let t = t ^ (t >> 1);
    (t & 0xFF) as u8
}

#[cfg(target_arch = "aarch64")]
#[target_feature(enable = "neon,pmull")]
pub(crate) unsafe fn gf_mul_bitsliced_neon(a: u8, b: u8) -> u8 {
    use std::arch::aarch64::*;

    // Use polynomial multiplication (PMULL) on the lowest lane
    let a_vec = vreinterpret_p8_u8(vdup_n_u8(a));
    let b_vec = vreinterpret_p8_u8(vdup_n_u8(b));
    let prod: poly16x8_t = vmull_p8(a_vec, b_vec);
    let mut t = vgetq_lane_u16(vreinterpretq_u16_p16(prod), 0);
    t ^= t >> 8;
    t ^= t >> 4;
    t ^= t >> 2;
    t ^= t >> 1;
    (t & 0xFF) as u8
}

#[cfg(target_arch = "aarch64")]
#[target_feature(enable = "neon")]
pub(crate) unsafe fn gf_mul_neon(a: u8, b: u8) -> u8 {
    gf_mul_bitsliced_neon(a, b)
}

// Vectorized slice multiplication ------------------------------------------------

#[cfg(all(target_arch = "x86_64"))]
#[target_feature(enable = "avx512f,avx512vbmi,pclmulqdq")]
unsafe fn gf_mul_slice_avx512(a: &[u8], b: &[u8], out: &mut [u8]) {
    for i in 0..a.len() {
        out[i] = gf_mul_bitsliced_avx512(a[i], b[i]);
    }
}

#[cfg(all(target_arch = "x86_64"))]
#[target_feature(enable = "avx2,pclmulqdq")]
unsafe fn gf_mul_slice_avx2(a: &[u8], b: &[u8], out: &mut [u8]) {
    for i in 0..a.len() {
        out[i] = gf_mul_bitsliced_avx2(a[i], b[i]);
    }
}

#[cfg(all(target_arch = "x86_64"))]
#[target_feature(enable = "sse2,pclmulqdq")]
unsafe fn gf_mul_slice_sse2(a: &[u8], b: &[u8], out: &mut [u8]) {
    for i in 0..a.len() {
        out[i] = gf_mul_bitsliced_sse2(a[i], b[i]);
    }
}

#[cfg(target_arch = "aarch64")]
#[target_feature(enable = "neon,pmull")]
unsafe fn gf_mul_slice_neon(a: &[u8], b: &[u8], out: &mut [u8]) {
    for i in 0..a.len() {
        out[i] = gf_mul_bitsliced_neon(a[i], b[i]);
    }
}

/// Element-wise multiplication of two equally sized slices.
///
/// The appropriate SIMD implementation is chosen at runtime via `optimize`.
pub(crate) fn gf_mul_slice(a: &[u8], b: &[u8], out: &mut [u8]) {
    assert_eq!(a.len(), b.len());
    assert_eq!(out.len(), a.len());

    optimize::dispatch_bitslice(|policy| {
        match policy {
            #[cfg(target_arch = "x86_64")]
            &optimize::Avx512 => unsafe { gf_mul_slice_avx512(a, b, out) },
            #[cfg(target_arch = "x86_64")]
            &optimize::Avx2 => unsafe { gf_mul_slice_avx2(a, b, out) },
            #[cfg(target_arch = "x86_64")]
            &optimize::Sse2 => unsafe { gf_mul_slice_sse2(a, b, out) },
            #[cfg(target_arch = "aarch64")]
            &optimize::Neon => unsafe { gf_mul_slice_neon(a, b, out) },
            _ => {
                for i in 0..a.len() {
                    out[i] = gf_mul_table(a[i], b[i]);
                }
            }
        }
    });
}
// --- High-Performance Finite Field Arithmetic (GF(2^8)) ---

/// A dispatching wrapper for Galois Field (GF(2^8)) multiplication.
///
/// This function uses the `optimize::dispatch` mechanism to select the most
/// performant implementation of GF(2^8)) multiplication available on the current CPU
/// architecture, ranging from table-lookups to SIMD-accelerated versions (PCLMULQDQ, NEON).
#[inline(always)]
pub(crate) fn gf_mul(a: u8, b: u8) -> u8 {
    let mut result = 0;
    optimize::dispatch_bitslice(|policy| {
        result = match policy {
            #[cfg(target_arch = "x86_64")]
            &optimize::Avx512 => unsafe { gf_mul_avx512(a, b) },
            #[cfg(target_arch = "x86_64")]
            &optimize::Avx2 => unsafe { gf_mul_avx2(a, b) },
            #[cfg(target_arch = "x86_64")]
            &optimize::Sse2 => unsafe { gf_mul_bitsliced_sse2(a, b) },
            #[cfg(target_arch = "aarch64")]
            &optimize::Neon => unsafe { gf_mul_neon(a, b) },
            // Fallback to table-based multiplication if no specific SIMD is available.
            _ => gf_mul_table(a, b),
        }
    });
    result
}

/// Computes the multiplicative inverse of a in GF(2^8)).
#[inline(always)]
pub(crate) fn gf_inv(a: u8) -> u8 {
    if a == 0 {
        panic!("Inverse of 0 is undefined in GF(2^8))");
    }
    unsafe { EXP_TABLE[255 - LOG_TABLE[a as usize] as usize] }
}

#[inline(always)]
pub(crate) fn gf_inv_prefetch(a: u8) -> u8 {
    if a == 0 {
        panic!("Inverse of 0 is undefined in GF(2^8))");
    }
    unsafe {
        prefetch_log(a as usize);
        let log_a = LOG_TABLE[a as usize];
        let exp_idx = 255 - log_a as usize;
        prefetch_exp(exp_idx);
        EXP_TABLE[exp_idx]
    }
}

/// Performs `a * b + c` in GF(2^8)).
#[inline(always)]
pub(crate) fn gf_mul_add(a: u8, b: u8, c: u8) -> u8 {
    gf_mul(a, b) ^ c
}

// --- GF(2^16) Arithmetic for Extreme Mode ---

const GF16_POLY: u32 = 0x1100b;

#[inline(always)]
pub(crate) fn gf16_mul(mut a: u16, mut b: u16) -> u16 {
    let mut res: u16 = 0;
    optimize::dispatch(|_policy| {
        // SIMD accelerated implementations could be plugged in here. For now we
        // use the classic shift-and-add approach which is efficient for the
        // small field size.
        while b != 0 {
            if (b & 1) != 0 {
                res ^= a;
            }
            b >>= 1;
            a <<= 1;
            if (a & 0x10000) != 0 {
                a ^= GF16_POLY as u16;
            }
        }
    });
    res
}

#[inline(always)]
pub(crate) fn gf16_pow(mut x: u16, mut power: u32) -> u16 {
    let mut result: u16 = 1;
    while power > 0 {
        if power & 1 != 0 {
            result = gf16_mul(result, x);
        }
        x = gf16_mul(x, x);
        power >>= 1;
    }
    result
}

#[inline(always)]
pub(crate) fn gf16_inv(x: u16) -> u16 {
    if x == 0 {
        panic!("Inverse of 0")
    }
    gf16_pow(x, 0x1_0000 - 2)
}

#[inline(always)]
pub(crate) fn gf16_mul_add(a: u16, b: u16, c: u16) -> u16 {
    gf16_mul(a, b) ^ c
}

// --- GF(2^8)) Table Initialization ---

const GF_ORDER: usize = 256;
const IRREDUCIBLE_POLY: u16 = 0x11D; // Standard AES polynomial: x^8 + x^4 + x^3 + x^2 + 1

static mut LOG_TABLE: [u8; GF_ORDER] = [0; GF_ORDER];
static mut EXP_TABLE: [u8; GF_ORDER * 2] = [0; GF_ORDER * 2];

/// Initializes the Galois Field log/exp tables for fast arithmetic.
/// This is a fallback for when SIMD is not available.
pub fn init_gf_tables() {
    static GF_INIT: std::sync::Once = std::sync::Once::new();
    GF_INIT.call_once(|| {
        unsafe {
            let mut x: u16 = 1;
            for i in 0..255 {
                EXP_TABLE[i] = x as u8;
                EXP_TABLE[i + 255] = x as u8; // For handling wrap-around
                LOG_TABLE[x as usize] = i as u8;
                x <<= 1;
                if x >= 256 {
                    x ^= IRREDUCIBLE_POLY;
                }
            }
        }
    });
}
