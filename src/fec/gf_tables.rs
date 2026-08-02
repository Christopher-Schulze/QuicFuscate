use crate::optimize::{self};
use log::warn;
use std::sync::{Once, OnceLock};

// GF(2^8) constants
const IRREDUCIBLE_POLY: u16 = 0x11D;

static LOG_TABLE: OnceLock<[u8; 256]> = OnceLock::new();
static EXP_TABLE: OnceLock<[u8; 512]> = OnceLock::new();
static TABLES_INIT: Once = Once::new();

pub(crate) fn init_tables() {
    TABLES_INIT.call_once(|| {
        let mut log = [0u8; 256];
        let mut exp = [0u8; 512];
        let mut x = 1u8;
        for i in 0..255 {
            exp[i] = x;
            exp[i + 255] = x;
            log[x as usize] = i as u8;
            let mut y = x as u16;
            y = (y << 1) ^ if y & 0x80 != 0 { IRREDUCIBLE_POLY } else { 0 };
            x = y as u8;
        }
        log[0] = 0;
        let _ = LOG_TABLE.set(log);
        let _ = EXP_TABLE.set(exp);
    });
}

#[inline(always)]
fn log_table() -> &'static [u8; 256] {
    LOG_TABLE.get().expect("GF tables not initialized")
}

#[inline(always)]
fn exp_table() -> &'static [u8; 512] {
    EXP_TABLE.get().expect("GF tables not initialized")
}

#[inline(always)]
pub(crate) fn prefetch_gf_log_lookup(idx: usize) {
    #[cfg(target_arch = "x86_64")]
    {
        unsafe {
            crate::optimize::prefetch(
                log_table().as_ptr().add(idx),
                crate::optimize::PrefetchHint::T0,
            );
        }
    }
    #[cfg(target_arch = "aarch64")]
    {
        let _ = idx; // no-op on stable aarch64
    }
}

// Removed prefetch_exp (not used).

#[inline(always)]
pub(crate) fn prefetch_fec_slice(ptr: *const u8) {
    #[cfg(target_arch = "x86_64")]
    {
        crate::optimize::prefetch(ptr, crate::optimize::PrefetchHint::T0);
    }
    #[cfg(target_arch = "aarch64")]
    {
        let _ = ptr; // no-op on stable aarch64
    }
}

#[inline(always)]
pub(crate) fn gf_mul_table(a: u8, b: u8) -> u8 {
    if a == 0 || b == 0 {
        return 0;
    }
    let log_a = log_table()[a as usize] as u16;
    let log_b = log_table()[b as usize] as u16;
    let sum_log = log_a + log_b;
    exp_table()[sum_log as usize]
}

#[inline(always)]
pub(crate) fn gf_inv8(x: u8) -> u8 {
    if x == 0 {
        return 0;
    }
    let lx = log_table()[x as usize] as i32;
    let e = 255 - lx;
    exp_table()[(e as usize) % 255]
}

// Removed gf_exp (not used).

// Removed gf_div8 (not used).

// NEON smoke test removed (tests only via scripts/ policy)

// Removed gf_mul_slice_sve2 (not used).

#[cfg(target_arch = "aarch64")]
unsafe fn gf_mul_scalar_slice_sve2(coeff: u8, src: &[u8], out_xor: &mut [u8]) {
    #[cfg(target_feature = "sve2")]
    {
        use std::arch::aarch64::*;

        debug_assert_eq!(src.len(), out_xor.len());
        let len = src.len();
        if len == 0 {
            return;
        }

        // Precompute 4-bit nibble tables replicated across the vector length.
        let mut t0_arr = [0u8; 16];
        let mut t1_arr = [0u8; 16];
        for i in 0..16 {
            t0_arr[i] = gf_mul_table(coeff, i as u8);
            t1_arr[i] = gf_mul_table(coeff, (i as u8) << 4);
        }

        let tbl0 = svld1rq_u8(svptrue_b8(), t0_arr.as_ptr());
        let tbl1 = svld1rq_u8(svptrue_b8(), t1_arr.as_ptr());
        let mask0f = svdup_n_u8(0x0f);
        let mut offset = 0usize;
        let vl = svcntb() as usize;
        let pf_dist: usize = if len >= 4096 {
            256
        } else if len >= 1024 {
            192
        } else if len >= 512 {
            128
        } else {
            0
        };

        while offset < len {
            let pg = svwhilelt_b8(offset as u64, len as u64);
            if !svptest_any(svptrue_b8(), pg) {
                break;
            }

            if pf_dist != 0 {
                let pf_idx = offset + pf_dist;
                if pf_idx < len {
                    prefetch_fec_slice(src.as_ptr().add(pf_idx));
                    prefetch_fec_slice(out_xor.as_ptr().add(pf_idx));
                }
            }

            let src_vec = svld1_u8(pg, src.as_ptr().add(offset));
            let lo = svand_u8_x(pg, src_vec, mask0f);
            let hi = svand_u8_x(pg, svlsr_n_u8_z(pg, src_vec, 4), mask0f);

            let prod_lo = svtbl_u8(tbl0, lo);
            let prod_hi = svtbl_u8(tbl1, hi);
            let prod = sveor_u8_m(pg, prod_lo, prod_lo, prod_hi);

            let dst_vec = svld1_u8(pg, out_xor.as_ptr().add(offset));
            let result = sveor_u8_m(pg, dst_vec, dst_vec, prod);
            svst1_u8(pg, out_xor.as_mut_ptr().add(offset), result);

            offset += vl;
        }

        crate::optimize::telemetry::FEC_SVE2_OPS.inc();
        return;
    }

    gf_mul_scalar_slice_neon(coeff, src, out_xor);
}

// Removed gf_mul_slice (not used).

/* removed: gf_mul_slice_gfni */

/* removed: gf_mul_slice_avx512 */

/* removed: gf_mul_slice_avx2 */

/* removed: gf_mul_slice_sse2 */

/* removed: gf_mul_slice_neon */

/// **ULTRA-OPTIMIZED** GF(2^8) scalar multiplication with zero-copy SIMD dispatch
#[inline(always)]
pub(crate) fn gf_mul_scalar_slice(coeff: u8, src: &[u8], out_xor: &mut [u8]) {
    if src.is_empty() || out_xor.is_empty() {
        return;
    }
    let len = src.len().min(out_xor.len());

    // **ZERO-COPY FAST PATHS** for special coefficients
    if coeff == 0 {
        return;
    }
    if coeff == 1 {
        // **ULTRA-FAST XOR**: 64-byte unrolled loop for maximum throughput
        let mut i = 0;
        // Process 64 bytes at a time for maximum cache efficiency
        while i + 64 <= len {
            #[cfg(target_arch = "x86_64")]
            unsafe {
                crate::optimize::prefetch(
                    src.as_ptr().add(i + 64),
                    crate::optimize::PrefetchHint::T0,
                );
            }
            // 64-byte unrolled XOR for maximum ILP (Instruction Level Parallelism)
            for j in 0..64 {
                out_xor[i + j] ^= src[i + j];
            }
            i += 64;
        }
        // Handle remaining bytes with 8-byte chunks
        while i + 8 <= len {
            out_xor[i] ^= src[i];
            out_xor[i + 1] ^= src[i + 1];
            out_xor[i + 2] ^= src[i + 2];
            out_xor[i + 3] ^= src[i + 3];
            out_xor[i + 4] ^= src[i + 4];
            out_xor[i + 5] ^= src[i + 5];
            out_xor[i + 6] ^= src[i + 6];
            out_xor[i + 7] ^= src[i + 7];
            i += 8;
        }
        while i < len {
            out_xor[i] ^= src[i];
            i += 1;
        }
        return;
    }

    // SIMD specialized paths - avoid closure borrowing issues
    let policy = optimize::FeatureDetector::instance();

    #[cfg(target_arch = "x86_64")]
    {
        // Intel GFNI multiplies in the AES 0x11B field, while this codec's
        // wire contract is GF(256)/0x11D. Use the 0x11D nibble-table path.
        if policy.has_feature(optimize::CpuFeature::AVX2) {
            unsafe {
                gf_mul_scalar_slice_avx2(coeff, &src[..len], &mut out_xor[..len]);
            }
            return;
        }
    }
    #[cfg(target_arch = "aarch64")]
    {
        if policy.has_feature(optimize::CpuFeature::SVE2) {
            unsafe {
                gf_mul_scalar_slice_sve2(coeff, &src[..len], &mut out_xor[..len]);
            }
            return;
        }
        if policy.has_feature(optimize::CpuFeature::NEON) {
            unsafe {
                gf_mul_scalar_slice_neon(coeff, &src[..len], &mut out_xor[..len]);
            }
            return;
        }
    }

    // **CACHE-OPTIMIZED** portable fallback: 256-entry LUT with thread-local caching
    // The LUT is rebuilt only when the coefficient changes, avoiding redundant computation
    // on hot paths where the same coefficient is reused across consecutive slices.
    thread_local! {
        static CACHED_LUT: std::cell::RefCell<(Option<u8>, [u8; 256])> = const { std::cell::RefCell::new((None, [0u8; 256])) };
    }
    CACHED_LUT.with(|cell| {
        let mut cached = cell.borrow_mut();
        if cached.0 != Some(coeff) {
            prefetch_gf_log_lookup(coeff as usize);
            let lut = &mut cached.1;
            let mut x = 0;
            while x + 4 <= 256 {
                lut[x] = gf_mul_table(coeff, x as u8);
                lut[x + 1] = gf_mul_table(coeff, (x + 1) as u8);
                lut[x + 2] = gf_mul_table(coeff, (x + 2) as u8);
                lut[x + 3] = gf_mul_table(coeff, (x + 3) as u8);
                x += 4;
            }
            while x < 256 {
                lut[x] = gf_mul_table(coeff, x as u8);
                x += 1;
            }
            cached.0 = Some(coeff);
        }
        let lut = &cached.1;

        // Compute prefetch distance heuristic
        let pf_dist: usize = if len >= 4096 {
            256
        } else if len >= 1024 {
            192
        } else if len >= 512 {
            128
        } else {
            0
        };

        let mut i = 0usize;
        // **CACHE-ALIGNED UNROLLED LOOP** - 64-byte alignment friendly
        while i + 64 <= len {
            if pf_dist != 0 {
                unsafe {
                    let pf_i = i + pf_dist;
                    if pf_i < len {
                        prefetch_fec_slice(src.as_ptr().add(pf_i));
                        prefetch_fec_slice(out_xor.as_ptr().add(pf_i));
                    }
                }
            }
            for j in 0..64 {
                out_xor[i + j] ^= lut[src[i + j] as usize];
            }
            i += 64;
        }

        while i + 8 <= len {
            out_xor[i] ^= lut[src[i] as usize];
            out_xor[i + 1] ^= lut[src[i + 1] as usize];
            out_xor[i + 2] ^= lut[src[i + 2] as usize];
            out_xor[i + 3] ^= lut[src[i + 3] as usize];
            out_xor[i + 4] ^= lut[src[i + 4] as usize];
            out_xor[i + 5] ^= lut[src[i + 5] as usize];
            out_xor[i + 6] ^= lut[src[i + 6] as usize];
            out_xor[i + 7] ^= lut[src[i + 7] as usize];
            i += 8;
        }
        while i < len {
            out_xor[i] ^= lut[src[i] as usize];
            i += 1;
        }
    });
}

// --- SIMD scalar x vector mul-add (GF(2^8)) specialized paths ---
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
unsafe fn gf_mul_scalar_slice_avx2(coeff: u8, src: &[u8], out_xor: &mut [u8]) {
    use std::arch::x86_64::*;
    debug_assert_eq!(src.len(), out_xor.len());
    // Precompute 16-entry nibble tables
    let mut t0 = [0u8; 16];
    let mut t1 = [0u8; 16];
    for i in 0..16 {
        t0[i] = gf_mul_table(coeff, i as u8);
        t1[i] = gf_mul_table(coeff, ((i as u8) << 4) as u8);
    }
    let tbl0_128 = _mm_loadu_si128(t0.as_ptr() as *const __m128i);
    let tbl1_128 = _mm_loadu_si128(t1.as_ptr() as *const __m128i);
    let tbl0 = _mm256_broadcastsi128_si256(tbl0_128);
    let tbl1 = _mm256_broadcastsi128_si256(tbl1_128);
    let mask0f = _mm256_set1_epi8(0x0f as i8);

    // Heuristic prefetch distance based on total length
    let pf_dist: usize = if src.len() >= 4096 {
        256
    } else if src.len() >= 1024 {
        192
    } else if src.len() >= 512 {
        128
    } else {
        0
    };

    let mut i = 0usize;
    // Unroll by 2: process 64 bytes per iteration when possible
    while i + 64 <= src.len() {
        if pf_dist != 0 {
            let pf_i = i + pf_dist;
            if pf_i < src.len() {
                prefetch_fec_slice(src.as_ptr().add(pf_i));
                prefetch_fec_slice(out_xor.as_ptr().add(pf_i));
            }
        }
        // First 32B chunk
        let x0 = _mm256_loadu_si256(src.as_ptr().add(i) as *const __m256i);
        let lo0 = _mm256_and_si256(x0, mask0f);
        let hi0 = _mm256_and_si256(_mm256_srli_epi16(x0, 4), mask0f);
        let p0_0 = _mm256_shuffle_epi8(tbl0, lo0);
        let p1_0 = _mm256_shuffle_epi8(tbl1, hi0);
        let prod0 = _mm256_xor_si256(p0_0, p1_0);
        let y0 = _mm256_loadu_si256(out_xor.as_ptr().add(i) as *const __m256i);
        let y2_0 = _mm256_xor_si256(y0, prod0);
        _mm256_storeu_si256(out_xor.as_mut_ptr().add(i) as *mut __m256i, y2_0);

        // Second 32B chunk
        let x1 = _mm256_loadu_si256(src.as_ptr().add(i + 32) as *const __m256i);
        let lo1 = _mm256_and_si256(x1, mask0f);
        let hi1 = _mm256_and_si256(_mm256_srli_epi16(x1, 4), mask0f);
        let p0_1 = _mm256_shuffle_epi8(tbl0, lo1);
        let p1_1 = _mm256_shuffle_epi8(tbl1, hi1);
        let prod1 = _mm256_xor_si256(p0_1, p1_1);
        let y1 = _mm256_loadu_si256(out_xor.as_ptr().add(i + 32) as *const __m256i);
        let y2_1 = _mm256_xor_si256(y1, prod1);
        _mm256_storeu_si256(out_xor.as_mut_ptr().add(i + 32) as *mut __m256i, y2_1);

        i += 64;
    }
    while i + 32 <= src.len() {
        if pf_dist != 0 {
            let pf_i = i + pf_dist;
            if pf_i < src.len() {
                prefetch_fec_slice(src.as_ptr().add(pf_i));
                prefetch_fec_slice(out_xor.as_ptr().add(pf_i));
            }
        }
        let x = _mm256_loadu_si256(src.as_ptr().add(i) as *const __m256i);
        let lo = _mm256_and_si256(x, mask0f);
        let hi = _mm256_and_si256(_mm256_srli_epi16(x, 4), mask0f);
        let p0 = _mm256_shuffle_epi8(tbl0, lo);
        let p1 = _mm256_shuffle_epi8(tbl1, hi);
        let prod = _mm256_xor_si256(p0, p1);
        let y = _mm256_loadu_si256(out_xor.as_ptr().add(i) as *const __m256i);
        let y2 = _mm256_xor_si256(y, prod);
        _mm256_storeu_si256(out_xor.as_mut_ptr().add(i) as *mut __m256i, y2);
        i += 32;
    }
    while i < src.len() {
        let v = src[i];
        let lo = (v & 0x0f) as usize;
        let hi = (v >> 4) as usize;
        out_xor[i] ^= t0[lo] ^ t1[hi];
        i += 1;
    }

    crate::telemetry::FEC_AVX2_GF_OPS.inc();
}

#[cfg(target_arch = "aarch64")]
#[target_feature(enable = "neon")]
unsafe fn gf_mul_scalar_slice_neon(coeff: u8, src: &[u8], out_xor: &mut [u8]) {
    use std::arch::aarch64::*;
    debug_assert_eq!(src.len(), out_xor.len());
    // Precompute 16-entry nibble tables
    let mut t0_arr = [0u8; 16];
    let mut t1_arr = [0u8; 16];
    for i in 0..16 {
        t0_arr[i] = gf_mul_table(coeff, i as u8);
        t1_arr[i] = gf_mul_table(coeff, (i as u8) << 4);
    }
    let t0 = vld1q_u8(t0_arr.as_ptr());
    let t1 = vld1q_u8(t1_arr.as_ptr());
    let mask0f = vdupq_n_u8(0x0f);

    // Heuristic prefetch distance for NEON
    let pf_dist: usize = if src.len() >= 4096 {
        192
    } else if src.len() >= 1024 {
        160
    } else if src.len() >= 512 {
        128
    } else {
        0
    };

    let mut i = 0usize;
    // Unroll by 2: 32 bytes per iteration
    while i + 32 <= src.len() {
        if pf_dist != 0 {
            let pf_i = i + pf_dist;
            if pf_i < src.len() {
                prefetch_fec_slice(src.as_ptr().add(pf_i));
            }
        }
        // First 16B
        let x0 = vld1q_u8(src.as_ptr().add(i));
        let lo0 = vandq_u8(x0, mask0f);
        let hi0 = vandq_u8(vshrq_n_u8(x0, 4), mask0f);
        let p0_0 = vqtbl1q_u8(t0, lo0);
        let p1_0 = vqtbl1q_u8(t1, hi0);
        let prod0 = veorq_u8(p0_0, p1_0);
        let y0 = vld1q_u8(out_xor.as_ptr().add(i));
        let y2_0 = veorq_u8(y0, prod0);
        vst1q_u8(out_xor.as_mut_ptr().add(i), y2_0);

        // Second 16B
        let x1 = vld1q_u8(src.as_ptr().add(i + 16));
        let lo1 = vandq_u8(x1, mask0f);
        let hi1 = vandq_u8(vshrq_n_u8(x1, 4), mask0f);
        let p0_1 = vqtbl1q_u8(t0, lo1);
        let p1_1 = vqtbl1q_u8(t1, hi1);
        let prod1 = veorq_u8(p0_1, p1_1);
        let y1 = vld1q_u8(out_xor.as_ptr().add(i + 16));
        let y2_1 = veorq_u8(y1, prod1);
        vst1q_u8(out_xor.as_mut_ptr().add(i + 16), y2_1);

        i += 32;
    }
    while i + 16 <= src.len() {
        if pf_dist != 0 {
            let pf_i = i + pf_dist;
            if pf_i < src.len() {
                prefetch_fec_slice(src.as_ptr().add(pf_i));
            }
        }
        let x = vld1q_u8(src.as_ptr().add(i));
        let lo = vandq_u8(x, mask0f);
        let hi = vandq_u8(vshrq_n_u8(x, 4), mask0f);
        let p0 = vqtbl1q_u8(t0, lo);
        let p1 = vqtbl1q_u8(t1, hi);
        let prod = veorq_u8(p0, p1);
        let y = vld1q_u8(out_xor.as_ptr().add(i));
        let y2 = veorq_u8(y, prod);
        vst1q_u8(out_xor.as_mut_ptr().add(i), y2);
        i += 16;
    }
    while i < src.len() {
        let v = src[i];
        let lo = (v & 0x0f) as usize;
        let hi = (v >> 4) as usize;
        out_xor[i] ^= t0_arr[lo] ^ t1_arr[hi];
        i += 1;
    }

    crate::optimize::telemetry::FEC_NEON_OPS.inc();
}

// Backward-compat shim for gf16_mul_scalar_slice was removed; use gf_mul_scalar_slice (GF8)

// --- GF(2^16) Arithmetic for Extreme Mode ---
// Using GF16_POLY from gf_tables module

const GF16_FIELD_ORDER: usize = u16::MAX as usize;
const GF16_REDUCTION_POLY: u16 = 0x100B;
static GF16_INVERSE_TABLE: OnceLock<Box<[u16]>> = OnceLock::new();

#[inline]
fn gf16_mul_generator(value: u16) -> u16 {
    let carry = value & 0x8000 != 0;
    let doubled = value << 1;
    if carry {
        doubled ^ GF16_REDUCTION_POLY
    } else {
        doubled
    }
}

fn gf16_inverse_table() -> &'static [u16] {
    GF16_INVERSE_TABLE.get_or_init(|| {
        // 0x1100B is primitive, so repeated multiplication by x (2) visits
        // every non-zero field element exactly once. Build inverses in O(2^16)
        // with no hot-path exponentiation or architecture-dependent dispatch.
        let mut exponents = vec![0u16; GF16_FIELD_ORDER];
        let mut logarithms = vec![0u16; GF16_FIELD_ORDER + 1];
        let mut value = 1u16;
        for (power, exponent) in exponents.iter_mut().enumerate() {
            *exponent = value;
            logarithms[value as usize] = power as u16;
            value = gf16_mul_generator(value);
        }
        debug_assert_eq!(value, 1, "GF16 generator must span the multiplicative group");

        let mut inverses = vec![0u16; GF16_FIELD_ORDER + 1];
        for element in 1..=GF16_FIELD_ORDER {
            let logarithm = logarithms[element] as usize;
            let inverse_power = if logarithm == 0 { 0 } else { GF16_FIELD_ORDER - logarithm };
            inverses[element] = exponents[inverse_power];
        }
        inverses.into_boxed_slice()
    })
}

#[inline(always)]
pub(crate) fn gf16_mul(a: u16, b: u16) -> u16 {
    optimize::dispatch(|policy| {
        #[cfg(target_arch = "x86_64")]
        {
            let _ = policy;
            if optimize::FeatureDetector::instance().has_feature(optimize::CpuFeature::PCLMULQDQ) {
                return unsafe { super::gf16_mul_pclmul(a, b) };
            }
        }
        #[cfg(target_arch = "aarch64")]
        {
            if policy.as_any().is::<optimize::Sve2>() {
                return unsafe { gf16_mul_sve2_impl(a, b) };
            }
            if policy.as_any().is::<optimize::Neon>() {
                return gf16_mul_neon_impl(a, b);
            }
        }
        // Scalar fallback
        let mut aa = a;
        let mut bb = b;
        let mut res: u16 = 0;
        while bb != 0 {
            if (bb & 1) != 0 {
                res ^= aa;
            }
            bb >>= 1;
            let carry = (aa & 0x8000) != 0;
            aa <<= 1;
            if carry {
                aa ^= GF16_REDUCTION_POLY;
            }
        }
        res
    })
}

#[cfg(test)]
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
        warn!("gf16_inv called with 0; returning 0 as safe fallback");
        return 0;
    }
    gf16_inverse_table()[x as usize]
}

#[cfg(target_arch = "aarch64")]
unsafe fn gf16_mul_sve2_impl(a: u16, b: u16) -> u16 {
    #[cfg(target_feature = "sve2")]
    {
        use std::arch::aarch64::*;

        let pg = svptrue_b16();
        let zero = svdup_n_u16(0);
        let poly = svdup_n_u16(GF16_REDUCTION_POLY);
        let msb_mask = svdup_n_u16(0x8000);
        let mut multiplicand = svdup_n_u16(a);
        let mut acc = svdup_n_u16(0);
        let mut factor = b;

        while factor != 0 {
            if (factor & 1) != 0 {
                acc = sveor_u16_z(pg, acc, multiplicand);
            }

            let high = svcmpne_u16(pg, svand_u16_z(pg, multiplicand, msb_mask), zero);
            let doubled = svlsl_n_u16_x(pg, multiplicand, 1);
            multiplicand = sveor_u16_m(high, doubled, doubled, poly);

            factor >>= 1;
        }

        return svlasta_u16(pg, acc);
    }

    gf16_mul_neon_impl(a, b)
}

fn gf16_mul_neon_impl(a: u16, b: u16) -> u16 {
    // Fallback to scalar since ARM SVE2 intrinsics not stable in Rust yet
    let mut aa = a as u32;
    let mut bb = b as u32;
    let mut res = 0u32;

    for _ in 0..16 {
        if bb & 1 != 0 {
            res ^= aa;
        }
        bb >>= 1;
        aa <<= 1;
        if aa & 0x10000 != 0 {
            aa ^= GF16_REDUCTION_POLY as u32;
        }
    }
    res as u16
}

#[inline(always)]
pub(crate) fn gf16_mul_add(a: u16, b: u16, acc: u16) -> u16 {
    // Scalar GF(2^16) multiply with XOR-accumulate
    #[cfg(all(target_arch = "aarch64", target_feature = "sve2"))]
    {
        return unsafe { gf16_mul_sve2_impl(a, b) ^ acc };
    }

    gf16_mul_neon_impl(a, b) ^ acc
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gf_mul_table_identity() {
        init_tables();
        // a * 1 = a for all non-zero a
        for a in 1..=255u8 {
            assert_eq!(gf_mul_table(a, 1), a, "a * 1 should equal a for a={}", a);
        }
    }

    #[test]
    fn test_gf_mul_table_zero() {
        init_tables();
        // a * 0 = 0 for all a
        for a in 0..=255u8 {
            assert_eq!(gf_mul_table(a, 0), 0, "a * 0 should be 0 for a={}", a);
            assert_eq!(gf_mul_table(0, a), 0, "0 * a should be 0 for a={}", a);
        }
    }

    #[test]
    fn test_gf_mul_table_commutativity() {
        init_tables();
        // a * b = b * a for a sampling of values
        for a in [1u8, 2, 3, 17, 42, 128, 200, 255] {
            for b in [1u8, 5, 13, 64, 100, 199, 254, 255] {
                assert_eq!(
                    gf_mul_table(a, b),
                    gf_mul_table(b, a),
                    "commutativity failed for a={}, b={}",
                    a,
                    b
                );
            }
        }
    }

    #[test]
    fn test_gf_mul_table_associativity() {
        init_tables();
        // (a * b) * c = a * (b * c)
        let triples: [(u8, u8, u8); 4] = [(2, 3, 5), (7, 11, 13), (42, 128, 200), (255, 254, 253)];
        for (a, b, c) in triples {
            let lhs = gf_mul_table(gf_mul_table(a, b), c);
            let rhs = gf_mul_table(a, gf_mul_table(b, c));
            assert_eq!(lhs, rhs, "associativity failed for a={}, b={}, c={}", a, b, c);
        }
    }

    #[test]
    fn test_gf_inv8_identity() {
        init_tables();
        // a * a^-1 = 1 for all non-zero a
        for a in 1..=255u8 {
            let inv = gf_inv8(a);
            let product = gf_mul_table(a, inv);
            assert_eq!(product, 1, "a * inv(a) should be 1 for a={} (inv={})", a, inv);
        }
    }

    #[test]
    fn test_gf_inv8_zero() {
        // inv(0) is defined to return 0 as a safe fallback
        assert_eq!(gf_inv8(0), 0);
    }

    #[test]
    fn test_gf_mul_table_known_vectors() {
        init_tables();
        // GF(2^8) with poly 0x11D: known test vectors
        // 0x02 * 0x02 = 0x04 (no reduction)
        assert_eq!(gf_mul_table(0x02, 0x02), 0x04);
        // 0x02 * 0x80 triggers reduction: 0x100 ^ 0x11D = 0x1D (poly low bits)
        assert_eq!(gf_mul_table(0x02, 0x80), 0x1D);
    }

    #[test]
    fn test_gf_scalar_slice_coeff_zero_noop() {
        let src = [1u8, 2, 3, 4, 5, 6, 7, 8];
        let mut out = [0u8; 8];
        gf_mul_scalar_slice(0, &src, &mut out);
        // coeff=0 should leave out unchanged
        assert_eq!(out, [0u8; 8]);
    }

    #[test]
    fn test_gf_scalar_slice_coeff_one_is_xor() {
        let src = [0xAA, 0xBB, 0xCC, 0xDD];
        let mut out = [0u8; 4];
        gf_mul_scalar_slice(1, &src, &mut out);
        // coeff=1 means out[i] ^= src[i], starting from zero so out = src
        assert_eq!(out, src);
    }

    #[test]
    fn test_gf_scalar_slice_xor_accumulate() {
        init_tables();
        let src = [5u8, 10, 15, 20];
        let mut out = [1u8, 2, 3, 4];
        let coeff = 3u8;
        gf_mul_scalar_slice(coeff, &src, &mut out);
        // out[i] should be original_out[i] ^ gf_mul(coeff, src[i])
        let expected: Vec<u8> = src
            .iter()
            .zip([1u8, 2, 3, 4].iter())
            .map(|(&s, &o)| o ^ gf_mul_table(coeff, s))
            .collect();
        assert_eq!(&out[..], &expected[..]);
    }

    #[test]
    fn test_gf16_mul_identity() {
        // a * 1 = a for non-zero a in GF(2^16)
        for &a in &[1u16, 2, 42, 1000, 0x7FFF, 0xFFFF] {
            assert_eq!(gf16_mul(a, 1), a, "gf16 identity failed for a={}", a);
        }
    }

    #[test]
    fn test_gf16_mul_zero() {
        assert_eq!(gf16_mul(0, 0), 0);
        assert_eq!(gf16_mul(0, 12345), 0);
        assert_eq!(gf16_mul(12345, 0), 0);
    }

    #[test]
    fn test_gf16_inv_identity() {
        // a * inv(a) = 1 for non-zero a in GF(2^16)
        for &a in &[1u16, 2, 7, 255, 1000, 0x8000, 0xFFFF] {
            let inv = gf16_inv(a);
            let product = gf16_mul(a, inv);
            assert_eq!(product, 1, "gf16 a * inv(a) should be 1 for a={} (inv={})", a, inv);
        }
    }

    #[test]
    fn test_gf16_inverse_table_covers_entire_nonzero_field() {
        let table = gf16_inverse_table();

        assert_eq!(table.len(), GF16_FIELD_ORDER + 1);
        assert_eq!(table[0], 0);
        for element in 1..=u16::MAX {
            let inverse = table[element as usize];
            assert_ne!(inverse, 0, "non-zero GF16 element must have a non-zero inverse");
            assert_eq!(
                gf16_mul(element, inverse),
                1,
                "GF16 inverse table mismatch for element {element}"
            );
        }
    }

    #[test]
    fn test_gf16_inverse_table_matches_exponentiation_reference() {
        for element in [1u16, 2, 7, 255, 1000, 0x8000, 0xFFFF] {
            assert_eq!(gf16_inv(element), gf16_pow(element, 0x1_0000 - 2));
        }
    }

    #[test]
    fn test_gf16_inv_zero() {
        // inv(0) returns 0 as safe fallback
        assert_eq!(gf16_inv(0), 0);
    }

    #[test]
    fn test_gf16_pow_basic() {
        // a^0 = 1 for non-zero a
        assert_eq!(gf16_pow(42, 0), 1);
        // a^1 = a
        assert_eq!(gf16_pow(42, 1), 42);
        // a^2 = a * a
        let a = 7u16;
        assert_eq!(gf16_pow(a, 2), gf16_mul(a, a));
    }

    #[test]
    fn test_gf_scalar_slice_large_buffer() {
        // Exercise the 64-byte unrolled path
        init_tables();
        let src: Vec<u8> = (0..256).map(|i| i as u8).collect();
        let mut out = vec![0u8; 256];
        let coeff = 7u8;
        gf_mul_scalar_slice(coeff, &src, &mut out);
        for (i, &val) in out.iter().enumerate() {
            let expected = gf_mul_table(coeff, i as u8);
            assert_eq!(val, expected, "mismatch at index {}", i);
        }
    }
}
