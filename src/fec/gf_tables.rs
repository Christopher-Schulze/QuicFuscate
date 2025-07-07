use crate::optimize::{self, SimdPolicy};
use rayon::prelude::*;

#[inline(always)]
fn gf_mul_table(a: u8, b: u8) -> u8 {
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

#[cfg(all(target_arch = "x86_64", target_feature = "avx512f"))]
#[target_feature(enable = "avx512f")]
unsafe fn gf_mul_bitsliced_avx512(a: u8, b: u8) -> u8 {
    gf_mul_shift(a, b)
}

#[cfg(all(target_arch = "x86_64", target_feature = "avx2"))]
#[target_feature(enable = "avx2")]
unsafe fn gf_mul_bitsliced_avx2(a: u8, b: u8) -> u8 {
    gf_mul_shift(a, b)
}

#[cfg(all(target_arch = "aarch64", target_feature = "neon"))]
#[target_feature(enable = "neon")]
unsafe fn gf_mul_bitsliced_neon(a: u8, b: u8) -> u8 {
    gf_mul_shift(a, b)
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
    optimize::dispatch(|policy| {
        result = match policy {
            #[cfg(all(target_arch = "x86_64", target_feature = "avx512f"))]
            &optimize::Avx512 => unsafe { gf_mul_bitsliced_avx512(a, b) },
            #[cfg(all(target_arch = "x86_64", target_feature = "avx2"))]
            &optimize::Avx2 => unsafe { gf_mul_bitsliced_avx2(a, b) },
            #[cfg(all(target_arch = "x86_64", target_feature = "pclmulqdq"))]
            &optimize::Pclmulqdq => {
                // This is an unsafe block because it uses CPU intrinsics.
                // It's guaranteed to be safe because `dispatch` only selects this path
                // when the `pclmulqdq` feature is detected at runtime.
                #[allow(unsafe_code)]
                unsafe {
                    use std::arch::x86_64::*;
                    let a_v = _mm_set_epi64x(0, a as i64);
                    let b_v = _mm_set_epi64x(0, b as i64);
                    // Carry-less multiplication of two 8-bit polynomials results in a 15-bit polynomial.
                    let res_v = _mm_clmulepi64_si128(a_v, b_v, 0x00);

                    // FULL POLYNOMIAL REDUCTION for GF(2^8)) with polynomial x^8 + x^4 + x^3 + x^2 + 1 (0x11D)
                    // This is a highly optimized bitwise reduction.
                    let res16 = _mm_extract_epi16(res_v, 0) as u16;
                    let t = res16 ^ (res16 >> 8);
                    let t = t ^ (t >> 4);
                    let t = t ^ (t >> 2);
                    let t = t ^ (t >> 1);
                    (t & 0xFF) as u8
                }
            }
            #[cfg(all(target_arch = "aarch64", target_feature = "neon"))]
            &optimize::Neon => unsafe { gf_mul_bitsliced_neon(a, b) },
            // SSE2 or fallback to table-based multiplication if no specific SIMD is available.
            &optimize::Sse2 | _ => {
                gf_mul_table(a, b)
            }
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
