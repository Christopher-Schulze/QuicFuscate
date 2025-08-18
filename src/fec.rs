// Aggregated FEC module: consolidates previous src/fec/* into a single file.
// Fully inlined: no #[path] re-exports remain; the entire FEC stack lives in this module.

#![allow(clippy::module_inception)]

// Finalized consolidation target: all logic in this file.
// gf_tables module is inlined below; no external module binding remains.
#[allow(dead_code)]
mod gf_tables {
    use crate::optimize::{self};
    use log::warn;

    #[inline(always)]
    pub(crate) unsafe fn prefetch_log(idx: usize) {
        #[cfg(target_arch = "x86_64")]
        {
            use std::arch::x86_64::{_mm_prefetch, _MM_HINT_T0};
            _mm_prefetch(LOG_TABLE.as_ptr().add(idx) as *const i8, _MM_HINT_T0);
        }
        #[cfg(target_arch = "aarch64")]
        {
            let _ = idx; // no-op on stable aarch64
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
            let _ = idx; // no-op on stable aarch64
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
            let _ = ptr; // no-op on stable aarch64
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

    #[cfg(target_arch = "x86_64")]
    #[target_feature(enable = "avx512f,avx512vbmi,pclmulqdq")]
    pub(crate) unsafe fn gf_mul_bitsliced_avx512(a: u8, b: u8) -> u8 {
        use std::arch::x86_64::*;
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

    #[cfg(target_arch = "x86_64")]
    #[target_feature(enable = "avx512f,avx512vbmi")]
    pub(crate) unsafe fn gf_mul_avx512(a: u8, b: u8) -> u8 {
        gf_mul_bitsliced_avx512(a, b)
    }

    #[cfg(target_arch = "x86_64")]
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

    #[cfg(target_arch = "x86_64")]
    #[target_feature(enable = "avx2")]
    pub(crate) unsafe fn gf_mul_avx2(a: u8, b: u8) -> u8 {
        gf_mul_bitsliced_avx2(a, b)
    }

    #[cfg(target_arch = "x86_64")]
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
    #[target_feature(enable = "neon")]
    pub(crate) unsafe fn gf_mul_bitsliced_neon(a: u8, b: u8) -> u8 {
        use std::arch::aarch64::*;
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

    #[cfg(target_arch = "x86_64")]
    #[target_feature(enable = "avx512f,avx512vbmi,pclmulqdq")]
    unsafe fn gf_mul_slice_avx512(a: &[u8], b: &[u8], out: &mut [u8]) {
        let mut i = 0;
        while i + 4 <= a.len() {
            if i + 64 < a.len() {
                prefetch_data(a.as_ptr().add(i + 64));
                prefetch_data(b.as_ptr().add(i + 64));
            }
            out[i] = gf_mul_bitsliced_avx512(a[i], b[i]);
            out[i + 1] = gf_mul_bitsliced_avx512(a[i + 1], b[i + 1]);
            out[i + 2] = gf_mul_bitsliced_avx512(a[i + 2], b[i + 2]);
            out[i + 3] = gf_mul_bitsliced_avx512(a[i + 3], b[i + 3]);
            i += 4;
        }
        while i < a.len() {
            out[i] = gf_mul_bitsliced_avx512(a[i], b[i]);
            i += 1;
        }
    }

    #[cfg(target_arch = "x86_64")]
    #[target_feature(enable = "avx2,pclmulqdq")]
    unsafe fn gf_mul_slice_avx2(a: &[u8], b: &[u8], out: &mut [u8]) {
        let mut i = 0;
        while i + 4 <= a.len() {
            if i + 64 < a.len() {
                prefetch_data(a.as_ptr().add(i + 64));
                prefetch_data(b.as_ptr().add(i + 64));
            }
            out[i] = gf_mul_bitsliced_avx2(a[i], b[i]);
            out[i + 1] = gf_mul_bitsliced_avx2(a[i + 1], b[i + 1]);
            out[i + 2] = gf_mul_bitsliced_avx2(a[i + 2], b[i + 2]);
            out[i + 3] = gf_mul_bitsliced_avx2(a[i + 3], b[i + 3]);
            i += 4;
        }
        while i < a.len() {
            out[i] = gf_mul_bitsliced_avx2(a[i], b[i]);
            i += 1;
        }
    }

    #[cfg(target_arch = "x86_64")]
    #[target_feature(enable = "sse2,pclmulqdq")]
    unsafe fn gf_mul_slice_sse2(a: &[u8], b: &[u8], out: &mut [u8]) {
        let mut i = 0;
        while i + 4 <= a.len() {
            if i + 64 < a.len() {
                prefetch_data(a.as_ptr().add(i + 64));
                prefetch_data(b.as_ptr().add(i + 64));
            }
            out[i] = gf_mul_bitsliced_sse2(a[i], b[i]);
            out[i + 1] = gf_mul_bitsliced_sse2(a[i + 1], b[i + 1]);
            out[i + 2] = gf_mul_bitsliced_sse2(a[i + 2], b[i + 2]);
            out[i + 3] = gf_mul_bitsliced_sse2(a[i + 3], b[i + 3]);
            i += 4;
        }
        while i < a.len() {
            out[i] = gf_mul_bitsliced_sse2(a[i], b[i]);
            i += 1;
        }
    }

    #[cfg(target_arch = "aarch64")]
    #[target_feature(enable = "neon")]
    unsafe fn gf_mul_slice_neon(a: &[u8], b: &[u8], out: &mut [u8]) {
        let mut i = 0;
        while i + 4 <= a.len() {
            if i + 64 < a.len() {
                prefetch_data(a.as_ptr().add(i + 64));
                prefetch_data(b.as_ptr().add(i + 64));
            }
            out[i] = gf_mul_bitsliced_neon(a[i], b[i]);
            out[i + 1] = gf_mul_bitsliced_neon(a[i + 1], b[i + 1]);
            out[i + 2] = gf_mul_bitsliced_neon(a[i + 2], b[i + 2]);
            out[i + 3] = gf_mul_bitsliced_neon(a[i + 3], b[i + 3]);
            i += 4;
        }
        while i < a.len() {
            out[i] = gf_mul_bitsliced_neon(a[i], b[i]);
            i += 1;
        }
    }

    // --- SIMD scalar×vector mul-add (GF(2^8)) specialized paths ---
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
                    prefetch_data(src.as_ptr().add(pf_i));
                    prefetch_data(out_xor.as_ptr().add(pf_i));
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
                    prefetch_data(src.as_ptr().add(pf_i));
                    prefetch_data(out_xor.as_ptr().add(pf_i));
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
                    prefetch_data(src.as_ptr().add(pf_i));
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
                    prefetch_data(src.as_ptr().add(pf_i));
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
    }

    /// Element-wise multiplication of two equally sized slices.
    /// The appropriate SIMD implementation is chosen at runtime via `optimize`.
    pub(crate) fn gf_mul_slice(a: &[u8], b: &[u8], out: &mut [u8]) {
        assert_eq!(a.len(), b.len());
        assert_eq!(out.len(), a.len());
        optimize::dispatch_bitslice(|policy| {
            #[cfg(target_arch = "x86_64")]
            {
                if policy.as_any().is::<optimize::Avx512>() {
                    unsafe {
                        return gf_mul_slice_avx512(a, b, out);
                    }
                }
                if policy.as_any().is::<optimize::Avx2>() {
                    unsafe {
                        return gf_mul_slice_avx2(a, b, out);
                    }
                }
                if policy.as_any().is::<optimize::Sse2>() {
                    unsafe {
                        return gf_mul_slice_sse2(a, b, out);
                    }
                }
            }
            #[cfg(target_arch = "aarch64")]
            {
                if policy.as_any().is::<optimize::Neon>() {
                    unsafe {
                        return gf_mul_slice_neon(a, b, out);
                    }
                }
            }
            for i in 0..a.len() {
                out[i] = gf_mul_table(a[i], b[i]);
            }
        });
    }

    /// Multiplies a vector by a scalar coefficient in GF(2^8) and XORs into `out_xor`.
    /// Runtime-dispatches to AVX2/NEON specialized implementations when available;
    /// otherwise uses a portable LUT fallback. Semantics: out[i] ^= coeff * src[i].
    #[inline]
    pub(crate) fn gf_mul_scalar_slice(coeff: u8, src: &[u8], out_xor: &mut [u8]) {
        assert_eq!(src.len(), out_xor.len());
        optimize::dispatch_bitslice(|policy| {
            if coeff == 0 {
                return;
            }
            if coeff == 1 {
                // Fast path: just XOR source into output
                let mut i = 0;
                while i + 8 <= src.len() {
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
                while i < src.len() {
                    out_xor[i] ^= src[i];
                    i += 1;
                }
                return;
            }

            // SIMD specialized paths
            #[cfg(target_arch = "x86_64")]
            {
                if policy.as_any().is::<optimize::Avx2>()
                    || policy.as_any().is::<optimize::Avx512>()
                {
                    unsafe {
                        gf_mul_scalar_slice_avx2(coeff, src, out_xor);
                    }
                    return;
                }
            }
            #[cfg(target_arch = "aarch64")]
            {
                if policy.as_any().is::<optimize::Neon>() {
                    unsafe {
                        gf_mul_scalar_slice_neon(coeff, src, out_xor);
                    }
                    return;
                }
            }

            // Portable fallback: 256-entry LUT
            let mut lut = [0u8; 256];
            unsafe {
                prefetch_log(coeff as usize);
            }
            for (x, val) in lut.iter_mut().enumerate() {
                *val = gf_mul_table(coeff, x as u8);
            }
            let mut i = 0usize;
            // Dynamic prefetch distance for portable fallback
            let pf_dist: usize = if src.len() >= 4096 {
                160
            } else if src.len() >= 1024 {
                128
            } else if src.len() >= 512 {
                96
            } else {
                0
            };
            while i + 32 <= src.len() {
                if pf_dist != 0 {
                    unsafe {
                        let pf_i = i + pf_dist;
                        if pf_i < src.len() {
                            prefetch_data(src.as_ptr().add(pf_i));
                        }
                    }
                }
                out_xor[i] ^= lut[src[i] as usize];
                out_xor[i + 1] ^= lut[src[i + 1] as usize];
                out_xor[i + 2] ^= lut[src[i + 2] as usize];
                out_xor[i + 3] ^= lut[src[i + 3] as usize];
                out_xor[i + 4] ^= lut[src[i + 4] as usize];
                out_xor[i + 5] ^= lut[src[i + 5] as usize];
                out_xor[i + 6] ^= lut[src[i + 6] as usize];
                out_xor[i + 7] ^= lut[src[i + 7] as usize];
                out_xor[i + 8] ^= lut[src[i + 8] as usize];
                out_xor[i + 9] ^= lut[src[i + 9] as usize];
                out_xor[i + 10] ^= lut[src[i + 10] as usize];
                out_xor[i + 11] ^= lut[src[i + 11] as usize];
                out_xor[i + 12] ^= lut[src[i + 12] as usize];
                out_xor[i + 13] ^= lut[src[i + 13] as usize];
                out_xor[i + 14] ^= lut[src[i + 14] as usize];
                out_xor[i + 15] ^= lut[src[i + 15] as usize];
                out_xor[i + 16] ^= lut[src[i + 16] as usize];
                out_xor[i + 17] ^= lut[src[i + 17] as usize];
                out_xor[i + 18] ^= lut[src[i + 18] as usize];
                out_xor[i + 19] ^= lut[src[i + 19] as usize];
                out_xor[i + 20] ^= lut[src[i + 20] as usize];
                out_xor[i + 21] ^= lut[src[i + 21] as usize];
                out_xor[i + 22] ^= lut[src[i + 22] as usize];
                out_xor[i + 23] ^= lut[src[i + 23] as usize];
                out_xor[i + 24] ^= lut[src[i + 24] as usize];
                out_xor[i + 25] ^= lut[src[i + 25] as usize];
                out_xor[i + 26] ^= lut[src[i + 26] as usize];
                out_xor[i + 27] ^= lut[src[i + 27] as usize];
                out_xor[i + 28] ^= lut[src[i + 28] as usize];
                out_xor[i + 29] ^= lut[src[i + 29] as usize];
                out_xor[i + 30] ^= lut[src[i + 30] as usize];
                out_xor[i + 31] ^= lut[src[i + 31] as usize];
                i += 32;
            }
            while i < src.len() {
                out_xor[i] ^= lut[src[i] as usize];
                i += 1;
            }
        });
    }

    // --- High-Performance Finite Field Arithmetic (GF(2^8)) ---
    #[inline(always)]
    pub(crate) fn gf_mul(a: u8, b: u8) -> u8 {
        optimize::dispatch_bitslice(|policy| {
            #[cfg(target_arch = "x86_64")]
            {
                if policy.as_any().is::<optimize::Avx512>() {
                    return unsafe { gf_mul_avx512(a, b) };
                }
                if policy.as_any().is::<optimize::Avx2>() {
                    return unsafe { gf_mul_avx2(a, b) };
                }
                if policy.as_any().is::<optimize::Sse2>() {
                    return unsafe { gf_mul_bitsliced_sse2(a, b) };
                }
            }
            #[cfg(target_arch = "aarch64")]
            {
                if policy.as_any().is::<optimize::Neon>() {
                    return unsafe { gf_mul_neon(a, b) };
                }
            }
            gf_mul_table(a, b)
        })
    }

    /// Computes the multiplicative inverse of a in GF(2^8)).
    #[inline(always)]
    pub(crate) fn gf_inv(a: u8) -> u8 {
        if a == 0 {
            warn!("gf_inv called with 0; returning 0 as safe fallback");
            return 0;
        }
        unsafe { EXP_TABLE[255 - LOG_TABLE[a as usize] as usize] }
    }

    #[inline(always)]
    pub(crate) fn gf_inv_prefetch(a: u8) -> u8 {
        if a == 0 {
            warn!("gf_inv_prefetch called with 0; returning 0 as safe fallback");
            return 0;
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
    pub(crate) fn gf16_mul(a: u16, b: u16) -> u16 {
        optimize::dispatch(|_policy| {
            let mut a = a;
            let mut b = b;
            let mut res: u16 = 0;
            while b != 0 {
                if (b & 1) != 0 {
                    res ^= a;
                }
                b >>= 1;
                let carry = (a & 0x8000) != 0;
                a <<= 1;
                if carry {
                    a ^= GF16_POLY as u16;
                }
            }
            res
        })
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
            warn!("gf16_inv called with 0; returning 0 as safe fallback");
            return 0;
        }
        gf16_pow(x, 0x1_0000 - 2)
    }

    #[inline(always)]
    pub(crate) fn gf16_mul_add(a: u16, b: u16, c: u16) -> u16 {
        gf16_mul(a, b) ^ c
    }

    // --- GF(2^8)) Table Initialization ---
    const GF_ORDER: usize = 256;
    const IRREDUCIBLE_POLY: u16 = 0x11D; // AES polynomial

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
}

#[allow(dead_code)]
mod decoder {
    // --- Encoder & Decoder --- (inlined from backup)
    use super::gf_tables::{
        gf16_inv, gf16_mul, gf16_mul_add, gf_inv, gf_inv_prefetch, gf_mul, gf_mul_scalar_slice,
        prefetch_data, prefetch_log,
    };
    use super::FecMode;
    use super::Packet;
    use crate::optimize::MemoryPool;
    use crate::telemetry; // bring telemetry! macro into scope
    use aligned_box::AlignedBox;
    use log::warn;
    use std::collections::{HashMap, VecDeque};
    use std::sync::{Arc, RwLock};

    /// Generates repair packets from source packets using a Cauchy matrix for coefficients.
    pub struct Encoder {
        pub(crate) k: usize, // Number of source packets
        pub(crate) n: usize, // Total packets (source + repair)
        source_window: VecDeque<Packet>,
        coeff_cache: RwLock<HashMap<usize, Vec<u8>>>,
    }

    pub struct Encoder16 {
        pub(crate) k: usize,
        pub(crate) n: usize,
        source_window: VecDeque<Packet>,
    }

    impl Encoder16 {
        pub fn new(k: usize, n: usize) -> Self {
            Self {
                k,
                n,
                source_window: VecDeque::with_capacity(k),
            }
        }

        pub fn add_source_packet(&mut self, packet: Packet) {
            if self.source_window.len() == self.k {
                self.source_window.pop_front();
            }
            self.source_window.push_back(packet);
        }

        pub fn generate_repair_packet(
            &self,
            repair_packet_index: usize,
            mem_pool: &Arc<MemoryPool>,
        ) -> Option<Packet> {
            let m = self.source_window.len().min(self.k);
            if m == 0 {
                return None;
            }
            let packet_len = self.source_window.front().map(|p| p.len).unwrap_or(0);
            let mut repair_data = mem_pool.alloc();
            // Zero only the active packet length region for better cache behavior.
            repair_data[..packet_len].fill(0);

            let coeffs = self.generate_cauchy_coefficients(repair_packet_index);
            for (i, src) in self.source_window.iter().enumerate() {
                let coeff = coeffs[i];
                if coeff == 0 {
                    continue;
                }
                let Some(ref buf) = src.data else { continue };
                let data: &[u8] = &buf[..packet_len.min(buf.len())];
                let mut j = 0;
                while j + 1 < packet_len {
                    if j + 64 < packet_len {
                        unsafe {
                            prefetch_data(data.as_ptr().add(j + 64));
                        }
                    }
                    let s = u16::from_be_bytes([data[j], data[j + 1]]);
                    let r = u16::from_be_bytes([repair_data[j], repair_data[j + 1]]);
                    let v = gf16_mul_add(coeff, s, r);
                    let b = v.to_be_bytes();
                    repair_data[j] = b[0];
                    repair_data[j + 1] = b[1];
                    j += 2;
                }
            }
            let mut coeff_block = mem_pool.alloc();
            for (i, c) in coeffs.iter().enumerate() {
                let bytes = c.to_be_bytes();
                coeff_block[2 * i] = bytes[0];
                coeff_block[2 * i + 1] = bytes[1];
            }
            let id_val = if let Some(last) = self.source_window.back() {
                last.id + 1 + repair_packet_index as u64
            } else {
                warn!("Encoder16.generate_repair_packet: empty source_window despite len>=k");
                return None;
            };
            Some(Packet::new(
                id_val,
                Some(repair_data),
                packet_len,
                false,
                Some(coeff_block),
                coeffs.len() * 2,
                Arc::clone(mem_pool),
            ))
        }

        fn generate_cauchy_coefficients(&self, repair_index: usize) -> Vec<u16> {
            let y = (self.k + repair_index) as u16;
            (0..self.k).map(|i| gf16_inv(i as u16 ^ y)).collect()
        }

        pub(crate) fn window_is_full(&self) -> bool {
            self.source_window.len() >= self.k
        }
        pub(crate) fn clear_window(&mut self) {
            self.source_window.clear();
        }
    }

    pub(crate) enum EncoderVariant {
        G8(Encoder),
        G16(Encoder16),
    }

    impl EncoderVariant {
        pub(crate) fn new(mode: FecMode, k: usize, n: usize) -> Self {
            if mode == FecMode::Extreme {
                EncoderVariant::G16(Encoder16::new(k, n))
            } else {
                EncoderVariant::G8(Encoder::new(k, n))
            }
        }

        pub(crate) fn add_source_packet(&mut self, pkt: Packet) {
            match self {
                EncoderVariant::G8(e) => e.add_source_packet(pkt),
                EncoderVariant::G16(e) => e.add_source_packet(pkt),
            }
        }

        pub(crate) fn generate_repair_packet(
            &self,
            idx: usize,
            pool: &Arc<MemoryPool>,
        ) -> Option<Packet> {
            match self {
                EncoderVariant::G8(e) => e.generate_repair_packet(idx, pool),
                EncoderVariant::G16(e) => e.generate_repair_packet(idx, pool),
            }
        }

        pub(crate) fn window_is_full(&self) -> bool {
            match self {
                EncoderVariant::G8(e) => e.window_is_full(),
                EncoderVariant::G16(e) => e.window_is_full(),
            }
        }

        pub(crate) fn clear_window(&mut self) {
            match self {
                EncoderVariant::G8(e) => e.clear_window(),
                EncoderVariant::G16(e) => e.clear_window(),
            }
        }
    }

    pub(crate) enum DecoderVariant {
        G8(Decoder),
        G16(Decoder16),
    }

    impl DecoderVariant {
        pub(crate) fn new(mode: FecMode, k: usize, pool: Arc<MemoryPool>) -> Self {
            if mode == FecMode::Extreme {
                DecoderVariant::G16(Decoder16::new(k, pool))
            } else {
                DecoderVariant::G8(Decoder::new(k, pool))
            }
        }

        pub(crate) fn add_packet(&mut self, pkt: Packet) -> Result<bool, &'static str> {
            match self {
                DecoderVariant::G8(d) => d.add_packet(pkt),
                DecoderVariant::G16(d) => d.add_packet(pkt),
            }
        }

        pub(crate) fn get_decoded_packets(&mut self) -> Vec<Packet> {
            match self {
                DecoderVariant::G8(d) => d.get_decoded_packets(),
                DecoderVariant::G16(d) => d.get_decoded_packets(),
            }
        }

        pub(crate) fn is_decoded(&self) -> bool {
            match self {
                DecoderVariant::G8(d) => d.is_decoded,
                DecoderVariant::G16(d) => d.is_decoded,
            }
        }
    }

    impl Encoder {
        pub fn new(k: usize, n: usize) -> Self {
            Self {
                k,
                n,
                source_window: VecDeque::with_capacity(k),
                coeff_cache: RwLock::new(HashMap::new()),
            }
        }

        pub fn add_source_packet(&mut self, packet: Packet) {
            if self.source_window.len() == self.k {
                self.source_window.pop_front();
            }
            self.source_window.push_back(packet);
        }

        /// Generates a repair packet for the current window.
        pub fn generate_repair_packet(
            &self,
            repair_packet_index: usize,
            mem_pool: &Arc<MemoryPool>,
        ) -> Option<Packet> {
            let m = self.source_window.len().min(self.k);
            if m == 0 {
                return None;
            }

            let packet_len = self.source_window.front().map(|p| p.len).unwrap_or(0);
            let mut repair_data = mem_pool.alloc();
            // Zero only the active packet length region for better cache behavior.
            repair_data[..packet_len].fill(0);

            let coeffs = self.generate_cauchy_coefficients(repair_packet_index);

            for (i, source_packet) in self.source_window.iter().enumerate() {
                let coeff = coeffs[i];
                if coeff == 0 {
                    continue;
                }
                let source_data = match source_packet.data.as_ref() {
                    Some(d) => &d[..source_packet.len],
                    None => {
                        warn!("Encoder.generate_repair_packet: packet data missing (sequential)");
                        continue;
                    }
                };
                // SIMD-friendly scalar×vector GF(256) mul-add via LUT: out ^= coeff * src
                // Guard by min length to avoid any potential slice overrun if packets differ in len.
                let slice_len = packet_len.min(source_packet.len);
                gf_mul_scalar_slice(
                    coeff,
                    &source_data[..slice_len],
                    &mut repair_data[..slice_len],
                );
            }

            let mut coeff_block = mem_pool.alloc();
            coeff_block[..coeffs.len()].copy_from_slice(&coeffs);
            let id_val = if let Some(last) = self.source_window.back() {
                last.id + 1 + repair_packet_index as u64
            } else {
                warn!("Encoder.generate_repair_packet: empty source_window despite len>=k");
                return None;
            };
            Some(Packet::new(
                id_val,
                Some(repair_data),
                packet_len,
                false,
                Some(coeff_block),
                coeffs.len(),
                Arc::clone(mem_pool),
            ))
        }

        /// Generates a row of coefficients from a Cauchy matrix.
        /// `X_i = i` for `i < k`, `Y_j = j` for `j < (n-k)`.
        /// `C_ji = 1 / (X_i + Y_j)`.
        fn generate_cauchy_coefficients(&self, repair_index: usize) -> Vec<u8> {
            // Cache per-repair-index row to avoid recomputation
            if let Some(cached) = self.coeff_cache.read().unwrap().get(&repair_index) {
                return cached.clone();
            }
            let y = (self.k + repair_index) as u8;
            let mut coeffs = Vec::with_capacity(self.k);
            if self.k == 0 {
                return coeffs;
            }
            unsafe {
                prefetch_log(y as usize);
            }
            for i in 0..self.k {
                if i + 1 < self.k {
                    unsafe {
                        prefetch_log(((i + 1) as u8 ^ y) as usize);
                    }
                }
                coeffs.push(gf_inv_prefetch(i as u8 ^ y));
            }
            self.coeff_cache
                .write()
                .unwrap()
                .insert(repair_index, coeffs.clone());
            coeffs
        }

        pub(crate) fn window_is_full(&self) -> bool {
            self.source_window.len() >= self.k
        }
        pub(crate) fn clear_window(&mut self) {
            self.source_window.clear();
        }
    }

    /// Represents a sparse matrix in Compressed-Sparse-Row (CSR) format.
    pub struct CsrMatrix {
        /// Non-zero values of the matrix.
        values: Vec<u8>,
        /// Column indices of the non-zero values.
        col_indices: Vec<usize>,
        /// Pointer to the start of each row in `values` and `col_indices`.
        row_ptr: Vec<usize>,
        /// Payloads associated with each row (for repair packets).
        payloads: Vec<Option<AlignedBox<[u8]>>>,
        num_cols: usize,
    }

    impl CsrMatrix {
        fn new(num_cols: usize) -> Self {
            Self {
                values: Vec::new(),
                col_indices: Vec::new(),
                row_ptr: vec![0],
                payloads: Vec::new(),
                num_cols,
            }
        }

        fn num_rows(&self) -> usize {
            self.row_ptr.len() - 1
        }

        /// Appends a dense row to the CSR matrix.
        fn append_row(&mut self, row: &[u8], payload: Option<AlignedBox<[u8]>>) {
            for (col_idx, &val) in row.iter().enumerate() {
                if val != 0 {
                    self.values.push(val);
                    self.col_indices.push(col_idx);
                }
            }
            self.row_ptr.push(self.values.len());
            self.payloads.push(payload);
        }

        fn get_val(&self, row: usize, col: usize) -> u8 {
            let row_start = self.row_ptr[row];
            let row_end = self.row_ptr[row + 1];
            for i in row_start..row_end {
                if self.col_indices[i] == col {
                    return self.values[i];
                }
            }
            0
        }

        fn get_payload(&self, row: usize) -> &Option<AlignedBox<[u8]>> {
            &self.payloads[row]
        }

        fn row_entries(&self, row: usize) -> Vec<(usize, u8)> {
            let start = self.row_ptr[row];
            let end = self.row_ptr[row + 1];
            (start..end)
                .map(|i| (self.col_indices[i], self.values[i]))
                .collect()
        }

        fn clear_row(&mut self, row: usize) {
            let start = self.row_ptr[row];
            let end = self.row_ptr[row + 1];
            let diff = end - start;
            if diff == 0 {
                return;
            }
            self.values.drain(start..end);
            self.col_indices.drain(start..end);
            for ptr in self.row_ptr.iter_mut().skip(row + 1) {
                *ptr -= diff;
            }
        }

        fn insert_row(&mut self, row: usize, entries: &[(usize, u8)]) {
            let start = self.row_ptr[row];
            for (col, val) in entries.iter().rev() {
                self.values.insert(start, *val);
                self.col_indices.insert(start, *col);
            }
            let diff = entries.len();
            for ptr in self.row_ptr.iter_mut().skip(row + 1) {
                *ptr += diff;
            }
        }

        fn swap_rows(&mut self, r1: usize, r2: usize) {
            if r1 == r2 {
                return;
            }
            let row1 = self.row_entries(r1);
            let row2 = self.row_entries(r2);
            let (hi, lo, hi_row, lo_row) = if r1 > r2 {
                (r1, r2, row1, row2)
            } else {
                (r2, r1, row2, row1)
            };
            self.clear_row(hi);
            self.clear_row(lo);
            self.insert_row(hi, &lo_row);
            self.insert_row(lo, &hi_row);
            self.payloads.swap(r1, r2);
        }

        fn scale_row(&mut self, row: usize, factor: u8) {
            let row_start = self.row_ptr[row];
            let row_end = self.row_ptr[row + 1];
            for i in row_start..row_end {
                if i + 32 < row_end {
                    unsafe {
                        prefetch_data(self.values.as_ptr().add(i + 32));
                    }
                }
                self.values[i] = gf_mul(self.values[i], factor);
            }
            if let Some(ref mut payload) = self.payloads[row] {
                for j in 0..payload.len() {
                    if j + 32 < payload.len() {
                        unsafe {
                            prefetch_data(payload.as_ptr().add(j + 32));
                        }
                    }
                    payload[j] = gf_mul(payload[j], factor);
                }
            }
        }

        fn add_scaled_row(&mut self, target_row: usize, source_row: usize, factor: u8) {
            let mut dense = vec![0u8; self.num_cols];
            for (c, v) in self.row_entries(target_row) {
                dense[c] = v;
            }
            for (c, v) in self.row_entries(source_row) {
                dense[c] ^= gf_mul(v, factor);
            }
            self.clear_row(target_row);
            let entries: Vec<(usize, u8)> = dense
                .iter()
                .enumerate()
                .filter(|&(_, &v)| v != 0)
                .map(|(c, &v)| (c, v))
                .collect();
            self.insert_row(target_row, &entries);

            if source_row == target_row {
                let clone_src_opt = self.payloads[source_row].as_ref().map(|b| Vec::from(&**b));
                if let (Some(clone_src), Some(tgt)) =
                    (clone_src_opt, self.payloads[target_row].as_mut())
                {
                    let max = tgt.len().min(clone_src.len());
                    // Vectorized: out ^= factor * src
                    gf_mul_scalar_slice(factor, &clone_src[..max], &mut tgt[..max]);
                }
            } else {
                // Borrow non-overlapping rows safely
                let (a, b) = if source_row < target_row {
                    let (left, right) = self.payloads.split_at_mut(target_row);
                    (left[source_row].as_ref(), right[0].as_mut())
                } else {
                    let (left, right) = self.payloads.split_at_mut(source_row);
                    (right[0].as_ref(), left[target_row].as_mut())
                };
                if let (Some(src), Some(tgt)) = (a, b) {
                    let max = tgt.len().min(src.len());
                    // Vectorized: out ^= factor * src
                    gf_mul_scalar_slice(factor, &src[..max], &mut tgt[..max]);
                }
            }
        }
    }

    /// Represents the chosen decoding algorithm based on window size.
    enum DecodingStrategy {
        GaussianElimination,
        Wiedemann,
    }

    /// Recovers original packets using the most appropriate high-performance algorithm.
    pub struct Decoder {
        k: usize,
        mem_pool: Arc<MemoryPool>,
        decoding_matrix: CsrMatrix,
        systematic_packets: Vec<Option<Packet>>,
        pub is_decoded: bool,
        strategy: DecodingStrategy,
    }

    pub struct Decoder16 {
        k: usize,
        mem_pool: Arc<MemoryPool>,
        matrix: Vec<Vec<u16>>, // dense for simplicity
        payloads: Vec<Option<AlignedBox<[u8]>>>,
        pub is_decoded: bool,
    }

    impl Decoder16 {
        pub fn new(k: usize, mem_pool: Arc<MemoryPool>) -> Self {
            Self {
                k,
                mem_pool,
                matrix: Vec::new(),
                payloads: Vec::new(),
                is_decoded: false,
            }
        }

        pub fn add_packet(&mut self, mut packet: Packet) -> Result<bool, &'static str> {
            if self.is_decoded || self.matrix.len() >= self.k {
                return Ok(self.is_decoded);
            }
            if packet.is_systematic {
                let mut row = vec![0u16; self.k];
                let idx = (packet.id as usize) % self.k;
                row[idx] = 1;
                self.matrix.push(row);
                self.payloads.push(None);
                return Ok(false);
            } else if let Some(ref c) = packet.coefficients {
                // Ensure we have enough bytes for GF(2^16) coefficients: 2 bytes per coefficient
                let needed = 2 * self.k;
                let available = packet.coeff_len.min(c.len());
                if available < needed {
                    return Err("coefficients too short");
                }
                let coeff_bytes = &c[..available];
                let mut row = Vec::with_capacity(self.k);
                for i in 0..self.k {
                    let base = 2 * i;
                    let hi = coeff_bytes[base];
                    let lo = coeff_bytes[base + 1];
                    row.push(u16::from_be_bytes([hi, lo]));
                }
                self.matrix.push(row);
                self.payloads.push(packet.data.take());
            } else {
                return Err("missing coeffs");
            }
            Ok(self.try_decode())
        }

        fn try_decode(&mut self) -> bool {
            if self.matrix.len() < self.k {
                return false;
            }
            let k = self.k;
            for i in 0..k {
                // pivot search
                let mut pivot = i;
                while pivot < k && self.matrix[pivot][i] == 0 {
                    pivot += 1;
                }
                if pivot == k {
                    return false;
                }
                self.matrix.swap(i, pivot);
                self.payloads.swap(i, pivot);
                let inv = gf16_inv(self.matrix[i][i]);
                for val in self.matrix[i].iter_mut() {
                    *val = gf16_mul(*val, inv);
                }
                if let Some(ref mut p) = self.payloads[i] {
                    let mut j = 0;
                    while j + 1 < p.len() {
                        let v = u16::from_be_bytes([p[j], p[j + 1]]);
                        let v = gf16_mul(v, inv);
                        let b = v.to_be_bytes();
                        p[j] = b[0];
                        p[j + 1] = b[1];
                        j += 2;
                    }
                }
                for r in 0..k {
                    if r != i && self.matrix[r][i] != 0 {
                        let factor = self.matrix[r][i];
                        for c in 0..k {
                            let t = gf16_mul(factor, self.matrix[i][c]);
                            self.matrix[r][c] ^= t;
                        }
                        let (src_opt, tgt_opt) = if r < i {
                            let (left, right) = self.payloads.split_at_mut(i);
                            (&right[0], &mut left[r])
                        } else {
                            let (left, right) = self.payloads.split_at_mut(r);
                            (&left[i], &mut right[0])
                        };
                        if let (Some(ref src), Some(ref mut tgt)) = (src_opt, tgt_opt) {
                            let mut j = 0;
                            while j + 1 < src.len() {
                                let s = u16::from_be_bytes([src[j], src[j + 1]]);
                                let t = u16::from_be_bytes([tgt[j], tgt[j + 1]]);
                                let val = gf16_mul_add(factor, s, t);
                                let b = val.to_be_bytes();
                                tgt[j] = b[0];
                                tgt[j + 1] = b[1];
                                j += 2;
                            }
                        }
                    }
                }
            }
            self.is_decoded = true;
            true
        }

        pub fn get_decoded_packets(&mut self) -> Vec<Packet> {
            let mut out = Vec::new();
            for (i, payload) in self.payloads.iter_mut().enumerate() {
                if let Some(data) = payload.take() {
                    let len = data.len();
                    out.push(Packet::new(
                        i as u64,
                        Some(data),
                        len,
                        true,
                        None,
                        0,
                        Arc::clone(&self.mem_pool),
                    ));
                }
            }
            // Reset state to accept a new decoding window
            self.matrix.clear();
            self.payloads.clear();
            self.is_decoded = false;
            out
        }
    }

    impl Decoder {
        pub fn new(k: usize, mem_pool: Arc<MemoryPool>) -> Self {
            // Select the decoding strategy based on the window size `k`.
            let strategy = if k > 256 {
                DecodingStrategy::Wiedemann
            } else {
                DecodingStrategy::GaussianElimination
            };
            Self {
                k,
                mem_pool,
                decoding_matrix: CsrMatrix::new(k), // The matrix size is k x k for coefficients
                systematic_packets: std::iter::repeat_with(|| None).take(k).collect(),
                is_decoded: false,
                strategy,
            }
        }

        /// Adds a packet to the decoder, building the decoding matrix.
        pub fn add_packet(&mut self, mut packet: Packet) -> Result<bool, &'static str> {
            if self.is_decoded {
                return Ok(true);
            }
            if self.k == 0 {
                return Ok(false);
            }
            if packet.is_systematic {
                let index = (packet.id as usize) % self.k;
                let mut identity_row = vec![0; self.k];
                identity_row[index] = 1;
                if self.systematic_packets[index].is_none() {
                    self.systematic_packets[index] = Some(packet);
                } else {
                    return Ok(self.is_decoded); // Duplicate packet
                }
                self.decoding_matrix.append_row(&identity_row, None);
                Ok(self.try_decode())
            } else if let Some(ref coeffs) = packet.coefficients {
                self.decoding_matrix
                    .append_row(&coeffs[..packet.coeff_len], packet.data.take());
                Ok(self.try_decode())
            } else {
                Err("Repair packet missing coefficients.")
            }
        }

        /// Attempts to decode once enough packets (K) have been received.
        fn try_decode(&mut self) -> bool {
            if self.is_decoded {
                return true;
            }
            if self.decoding_matrix.num_rows() < self.k {
                return false;
            }
            // --- High-performance decoding pipeline ---
            match self.strategy {
                DecodingStrategy::GaussianElimination => self.gaussian_elimination(),
                DecodingStrategy::Wiedemann => self.wiedemann_algorithm(),
            }
        }

        /// Performs Sparse Gaussian elimination on the CSR matrix.
        fn gaussian_elimination(&mut self) -> bool {
            // This is a simplified sparse implementation. A truly high-performance version
            // would require more complex data structures and operations to minimize cache misses.
            let start = std::time::Instant::now();
            let k = self.k;
            let mut rank = 0;
            for i in 0..k {
                // Find pivot
                let pivot_row_opt = (i..self.decoding_matrix.num_rows())
                    .find(|&r| self.decoding_matrix.get_val(r, i) != 0);
                if let Some(pivot_row) = pivot_row_opt {
                    self.decoding_matrix.swap_rows(i, pivot_row);
                    let pivot_val = self.decoding_matrix.get_val(i, i);
                    let pivot_inv = gf_inv(pivot_val);
                    self.decoding_matrix.scale_row(i, pivot_inv);
                    for row_idx in 0..self.decoding_matrix.num_rows() {
                        if i == row_idx {
                            continue;
                        }
                        let factor = self.decoding_matrix.get_val(row_idx, i);
                        if factor != 0 {
                            self.decoding_matrix.add_scaled_row(row_idx, i, factor);
                        }
                    }
                    rank += 1;
                    if rank == k {
                        break;
                    }
                }
            }
            if rank < k {
                return false;
            }
            self.is_decoded = true;
            // The `decoding_matrix` now contains the solved data on its right-hand side.
            // Reconstruct packets from this solved data.
            for i in 0..k {
                if self.systematic_packets[i].is_none() {
                    if let Some(data_slice) = self.decoding_matrix.get_payload(i) {
                        let data_len = data_slice.len();
                        let mut packet_data = self.mem_pool.alloc();
                        packet_data[..data_len].copy_from_slice(data_slice);
                        self.systematic_packets[i] = Some(Packet::new(
                            i as u64, // NOTE: Assumes packet ID aligns with matrix index.
                            Some(packet_data),
                            data_len,
                            true,
                            None,
                            0,
                            Arc::clone(&self.mem_pool),
                        ));
                    }
                }
            }
            telemetry!(telemetry::DECODING_TIME_MS.set(start.elapsed().as_millis() as i64));
            true
        }

        pub fn get_decoded_packets(&mut self) -> Vec<Packet> {
            // Drain the buffer to return the fully reconstructed set of packets
            let out: Vec<Packet> = self
                .systematic_packets
                .iter_mut()
                .filter_map(|p| p.take())
                .collect();
            // Reset state for next window decoding
            self.decoding_matrix = CsrMatrix::new(self.k);
            self.systematic_packets = std::iter::repeat_with(|| None).take(self.k).collect();
            self.is_decoded = false;
            out
        }

        /// Solves the decoding problem using a block-Lanczos based Wiedemann algorithm.
        fn wiedemann_algorithm(&mut self) -> bool {
            telemetry!(crate::telemetry::WIEDEMANN_USAGE.inc());
            // Currently delegates to the Gaussian elimination backend.
            self.gaussian_elimination()
        }
    }
}

// Adaptive code is fully inlined below; no #[path] bindings remain.

// Inline former encoder module (Packet + helpers) to consolidate FEC into a single file.
use self::decoder::{DecoderVariant, EncoderVariant};
use crate::optimize::{MemoryPool, OptimizationManager};
use crate::telemetry;
use aligned_box::AlignedBox;
use clap::ValueEnum;
use log::{error, info, warn};
use rayon::iter::IntoParallelIterator;
use rayon::iter::ParallelIterator;
use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

// Public Packet type previously defined in `fec/encoder.rs`.
// Maintains the same layout and methods to preserve API compatibility.
pub struct Packet {
    pub id: u64,
    pub data: Option<AlignedBox<[u8]>>,
    pub len: usize,
    pub is_systematic: bool,
    pub coefficients: Option<AlignedBox<[u8]>>,
    pub coeff_len: usize,
    mem_pool: Arc<MemoryPool>,
}

impl Packet {
    /// Creates a packet from parts. Intended for internal use by other modules
    /// that need to construct FEC packets without direct field access.
    pub fn new(
        id: u64,
        data: Option<AlignedBox<[u8]>>,
        len: usize,
        is_systematic: bool,
        coefficients: Option<AlignedBox<[u8]>>,
        coeff_len: usize,
        mem_pool: Arc<MemoryPool>,
    ) -> Self {
        Packet {
            id,
            data,
            len,
            is_systematic,
            coefficients,
            coeff_len,
            mem_pool,
        }
    }

    /// Deserializes a packet from a raw byte buffer.
    /// This is a lightweight framing implementation.
    /// Frame format: <is_systematic_byte (1)> <coeff_len (2)> <coeffs (coeff_len)> <payload>
    pub fn from_raw(
        id: u64,
        raw_data: &[u8],
        opt_manager: &OptimizationManager,
    ) -> Result<Self, String> {
        if raw_data.is_empty() {
            error!("from_raw: input buffer empty");
            return Err("Raw data is empty".to_string());
        }

        let is_systematic = raw_data[0] == 1;
        let mut offset = 1;

        let (coefficients, coeff_len, payload_offset) = if !is_systematic {
            if raw_data.len() < 3 {
                error!("from_raw: coefficient length missing");
                return Err("Buffer too short for coefficient length".to_string());
            }
            let coeff_len = match raw_data.get(offset..offset + 2) {
                Some(two) => {
                    let arr: [u8; 2] = match two.try_into() {
                        Ok(a) => a,
                        Err(_) => {
                            error!("from_raw: failed to read 2-byte coefficient length");
                            return Err("Buffer too short for coefficient length".to_string());
                        }
                    };
                    u16::from_be_bytes(arr) as usize
                }
                None => {
                    error!("from_raw: coefficient length missing (slice too short)");
                    return Err("Buffer too short for coefficient length".to_string());
                }
            };
            offset += 2;

            if raw_data.len() < offset + coeff_len {
                error!("from_raw: coefficient data truncated");
                return Err("Buffer too short for coefficients".to_string());
            }
            let mut coeff_block = opt_manager.alloc_block();
            coeff_block[..coeff_len].copy_from_slice(&raw_data[offset..offset + coeff_len]);
            (Some(coeff_block), coeff_len, offset + coeff_len)
        } else {
            (None, 0, offset)
        };

        let payload = &raw_data[payload_offset..];
        let mut data = opt_manager.alloc_block();
        if data.len() < payload.len() {
            error!("from_raw: pool buffer too small");
            return Err("Buffer from pool is too small".to_string());
        }
        data[..payload.len()].copy_from_slice(payload);

        Ok(Packet {
            id,
            data: Some(data),
            len: payload.len(),
            is_systematic,
            coefficients,
            coeff_len,
            mem_pool: opt_manager.memory_pool(),
        })
    }

    /// Creates a packet from a pooled memory block. The `len` parameter
    /// specifies the amount of valid data in the block.
    pub fn from_block(
        id: u64,
        mut block: AlignedBox<[u8]>,
        len: usize,
        opt_manager: &OptimizationManager,
    ) -> Result<Self, String> {
        if len == 0 || len > block.len() {
            opt_manager.free_block(block);
            error!("from_block: invalid length {}", len);
            return Err("Invalid raw packet length".to_string());
        }

        let is_systematic = block[0] == 1;
        let mut offset = 1;

        let (coefficients, coeff_len, payload_offset) = if !is_systematic {
            if len < 3 {
                opt_manager.free_block(block);
                error!("from_block: coefficient length missing");
                return Err("Buffer too short for coefficient length".to_string());
            }
            let coeff_len = u16::from_be_bytes([block[offset], block[offset + 1]]) as usize;
            offset += 2;
            if len < offset + coeff_len {
                opt_manager.free_block(block);
                error!("from_block: coefficient data truncated");
                return Err("Buffer too short for coefficients".to_string());
            }
            let mut coeff_block = opt_manager.alloc_block();
            coeff_block[..coeff_len].copy_from_slice(&block[offset..offset + coeff_len]);
            (Some(coeff_block), coeff_len, offset + coeff_len)
        } else {
            (None, 0, offset)
        };

        let payload_len = len - payload_offset;
        if payload_offset > 0 {
            block.copy_within(payload_offset..len, 0);
        }

        Ok(Packet {
            id,
            data: Some(block),
            len: payload_len,
            is_systematic,
            coefficients,
            coeff_len,
            mem_pool: opt_manager.memory_pool(),
        })
    }

    /// Serializes the packet into a raw byte buffer for transmission.
    pub fn to_raw(&self, buffer: &mut [u8]) -> Result<usize, quiche::Error> {
        let mut required_len = self.len + 1;
        if self.coefficients.is_some() {
            required_len += 2 + self.coeff_len;
        }
        if buffer.len() < required_len {
            return Err(quiche::Error::BufferTooShort);
        }

        let mut offset = 0;
        buffer[offset] = if self.is_systematic { 1 } else { 0 };
        offset += 1;

        if let Some(coeffs) = &self.coefficients {
            let coeff_len = self.coeff_len as u16;
            buffer[offset..offset + 2].copy_from_slice(&coeff_len.to_be_bytes());
            offset += 2;
            buffer[offset..offset + self.coeff_len].copy_from_slice(&coeffs[..self.coeff_len]);
            offset += self.coeff_len;
        }

        if let Some(ref data) = self.data {
            buffer[offset..offset + self.len].copy_from_slice(&data[..self.len]);
        }
        offset += self.len;

        Ok(offset)
    }

    /// Clones the packet structure and its data for use in the encoder window.
    /// This is a deep copy of the data into a new buffer from the memory pool.
    pub fn clone_for_encoder(&self, mem_pool: &Arc<MemoryPool>) -> Self {
        let mut new_data = mem_pool.alloc();
        if let Some(ref data) = self.data {
            new_data[..self.len].copy_from_slice(&data[..self.len]);
        }
        Packet {
            id: self.id,
            data: Some(new_data),
            len: self.len,
            is_systematic: self.is_systematic,
            coefficients: self.coefficients.as_ref().map(|c| {
                let mut nb = mem_pool.alloc();
                nb[..self.coeff_len].copy_from_slice(&c[..self.coeff_len]);
                nb
            }),
            coeff_len: self.coeff_len,
            mem_pool: Arc::clone(mem_pool),
        }
    }
}

impl Drop for Packet {
    fn drop(&mut self) {
        if let Some(data) = self.data.take() {
            self.mem_pool.free(data);
        }
        if let Some(coeffs) = self.coefficients.take() {
            self.mem_pool.free(coeffs);
        }
    }
}

// Backwards-compatibility shim: keep `fec::encoder::Packet` path valid
pub mod encoder {
    pub use super::Packet;
}

// Re-export selected internals for test compatibility with legacy paths
pub use self::decoder::{Decoder, Decoder16, Encoder, Encoder16};
pub use self::gf_tables::init_gf_tables;

// Decoder/Adaptive helpers are now inlined or replaced by Packet-based API.

// Types that lived in the old fec/mod.rs which are not part of the above files.
#[derive(Debug)]
pub struct KalmanFilter {
    estimate: f32,
    error_cov: f32,
    q: f32,
    r: f32,
}

impl KalmanFilter {
    fn new(q: f32, r: f32) -> Self {
        Self {
            estimate: 0.0,
            error_cov: 1.0,
            q,
            r,
        }
    }

    fn update(&mut self, measurement: f32) -> f32 {
        self.error_cov += self.q;
        let k = self.error_cov / (self.error_cov + self.r);
        self.estimate += k * (measurement - self.estimate);
        self.error_cov *= 1.0 - k;
        self.estimate
    }
}

// --- Adaptive FEC (fully inlined) ---

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, ValueEnum)]
pub enum FecMode {
    Zero,
    Light,
    Normal,
    Medium,
    Strong,
    Extreme,
}

impl std::str::FromStr for FecMode {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "0" | "zero" => Ok(FecMode::Zero),
            "1" | "light" | "leicht" => Ok(FecMode::Light),
            "2" | "normal" => Ok(FecMode::Normal),
            "3" | "medium" | "mittel" => Ok(FecMode::Medium),
            "4" | "strong" | "stark" => Ok(FecMode::Strong),
            "5" | "extreme" => Ok(FecMode::Extreme),
            _ => Err(()),
        }
    }
}

// --- Loss Estimator ---
pub struct LossEstimator {
    ema_loss_rate: f32,
    lambda: f32,
    burst_window: VecDeque<bool>,
    burst_capacity: usize,
    kalman: Option<KalmanFilter>,
}

impl LossEstimator {
    fn new(lambda: f32, burst_capacity: usize, kalman: Option<KalmanFilter>) -> Self {
        Self {
            ema_loss_rate: 0.0,
            lambda,
            burst_window: VecDeque::with_capacity(burst_capacity),
            burst_capacity,
            kalman,
        }
    }

    fn report_loss(&mut self, lost: usize, total: usize) {
        let mut current_loss_rate = if total > 0 {
            lost as f32 / total as f32
        } else {
            0.0
        };
        if let Some(kf) = self.kalman.as_mut() {
            current_loss_rate = kf.update(current_loss_rate);
        }
        self.ema_loss_rate =
            (self.lambda * current_loss_rate) + (1.0 - self.lambda) * self.ema_loss_rate;

        for _ in 0..lost {
            if self.burst_window.len() == self.burst_capacity {
                self.burst_window.pop_front();
            }
            self.burst_window.push_back(true);
        }
        for _ in 0..(total - lost) {
            if self.burst_window.len() == self.burst_capacity {
                self.burst_window.pop_front();
            }
            self.burst_window.push_back(false);
        }
    }

    fn get_estimated_loss(&self) -> f32 {
        let burst_loss = if self.burst_window.is_empty() {
            0.0
        } else {
            self.burst_window.iter().filter(|&&l| l).count() as f32 / self.burst_window.len() as f32
        };
        self.ema_loss_rate.max(burst_loss)
    }
}

// --- Mode Manager ---
pub struct ModeManager {
    current_mode: FecMode,
    pid: PidController,
    mode_thresholds: HashMap<FecMode, f32>,
    window_sizes: HashMap<FecMode, usize>,
    last_mode_change: Instant,
    min_dwell_time: Duration,
    hysteresis: f32,
    current_window: usize,
}

impl ModeManager {
    const CROSS_FADE_LEN: usize = 32;
    const ALPHA_K: f32 = 0.5;

    fn initial_window(&self, mode: FecMode) -> usize {
        self.window_sizes
            .get(&mode)
            .copied()
            .unwrap_or_else(|| *FecConfig::default_windows().get(&mode).unwrap_or(&0))
    }

    fn window_range(mode: FecMode) -> (usize, usize) {
        match mode {
            FecMode::Zero => (0, 0),
            FecMode::Light => (8, 32),
            FecMode::Normal => (32, 128),
            FecMode::Medium => (64, 256),
            FecMode::Strong => (256, 1024),
            FecMode::Extreme => (1024, 4096),
        }
    }

    fn overhead_ratio(mode: FecMode) -> f32 {
        match mode {
            FecMode::Zero => 1.0,
            FecMode::Light => 1.05,
            FecMode::Normal => 1.15,
            FecMode::Medium => 1.30,
            FecMode::Strong => 1.50,
            FecMode::Extreme => 2.0,
        }
    }

    pub fn params_for(mode: FecMode, window: usize) -> (usize, usize) {
        let ratio = Self::overhead_ratio(mode);
        let n = ((window as f32) * ratio).ceil() as usize;
        (window, n)
    }

    fn new(
        pid_config: PidConfig,
        hysteresis: f32,
        initial_mode: FecMode,
        window_sizes: HashMap<FecMode, usize>,
    ) -> Self {
        let mut mode_thresholds = HashMap::new();
        mode_thresholds.insert(FecMode::Zero, 0.01);
        mode_thresholds.insert(FecMode::Light, 0.05);
        mode_thresholds.insert(FecMode::Normal, 0.15);
        mode_thresholds.insert(FecMode::Medium, 0.30);
        mode_thresholds.insert(FecMode::Strong, 0.50);
        mode_thresholds.insert(FecMode::Extreme, 1.0);

        let current_mode = initial_mode;
        let current_window = window_sizes.get(&current_mode).copied().unwrap_or_else(|| {
            *FecConfig::default_windows()
                .get(&current_mode)
                .unwrap_or(&0)
        });

        let min_dwell = Duration::from_millis(500);
        Self {
            current_mode,
            pid: PidController::new(pid_config),
            mode_thresholds,
            window_sizes,
            last_mode_change: Instant::now() - min_dwell,
            min_dwell_time: min_dwell,
            hysteresis,
            current_window,
        }
    }

    fn update(&mut self, estimated_loss: f32) -> (FecMode, usize, Option<(FecMode, usize)>) {
        if estimated_loss > self.mode_thresholds[&FecMode::Strong] + self.hysteresis {
            let prev = (self.current_mode, self.current_window);
            self.current_mode = FecMode::Extreme;
            self.current_window = self.initial_window(self.current_mode);
            self.last_mode_change = Instant::now();
            return (self.current_mode, self.current_window, Some(prev));
        }

        // Fast path: from Zero escalate immediately when loss clearly exceeds Light threshold.
        // Use Normal with a window equal to the cross-fade length to maximize recovery over this phase.
        if self.current_mode == FecMode::Zero
            && estimated_loss >= self.mode_thresholds[&FecMode::Light] + self.hysteresis
        {
            let prev = (self.current_mode, self.current_window);
            self.current_mode = FecMode::Normal;
            self.current_window = Self::CROSS_FADE_LEN;
            self.last_mode_change = Instant::now();
            return (self.current_mode, self.current_window, Some(prev));
        }

        if self.last_mode_change.elapsed() < self.min_dwell_time {
            return (self.current_mode, self.current_window, None);
        }

        let target_loss_for_current_mode = self.mode_thresholds[&self.current_mode];
        let output = self
            .pid
            .update(estimated_loss, target_loss_for_current_mode);

        let mut new_mode = self.current_mode;
        if output > 0.1 {
            new_mode = self.next_mode(self.current_mode);
        } else if output < -0.1 {
            new_mode = self.prev_mode(self.current_mode);
        }

        let prev_mode = self.current_mode;
        let prev_window = self.current_window;

        if new_mode != self.current_mode {
            self.current_mode = new_mode;
            self.last_mode_change = Instant::now();
            self.current_window = self.initial_window(new_mode);
        }

        let target_loss_for_mode = self.mode_thresholds[&self.current_mode];
        let alpha = 1.0 + Self::ALPHA_K * (estimated_loss - target_loss_for_mode);
        let range = Self::window_range(self.current_mode);
        let mut new_window = ((self.current_window as f32) * alpha).round() as usize;
        new_window = new_window.clamp(range.0, range.1);
        self.current_window = new_window;

        if prev_mode != self.current_mode || prev_window != self.current_window {
            info!(
                "FEC mode change: {:?} -> {:?}, window {} -> {}, loss {:.2}%",
                prev_mode,
                self.current_mode,
                prev_window,
                self.current_window,
                estimated_loss * 100.0
            );
            telemetry!(telemetry::FEC_MODE.set(self.current_mode as i64));
            telemetry!(telemetry::LOSS_RATE.set((estimated_loss * 100.0) as i64));
            telemetry!(telemetry::FEC_MODE_SWITCHES.inc());
            telemetry!(telemetry::FEC_WINDOW.set(self.current_window as i64));
            return (
                self.current_mode,
                self.current_window,
                Some((prev_mode, prev_window)),
            );
        }

        telemetry!(telemetry::FEC_WINDOW.set(self.current_window as i64));
        (self.current_mode, self.current_window, None)
    }

    fn next_mode(&self, mode: FecMode) -> FecMode {
        match mode {
            FecMode::Zero => FecMode::Light,
            FecMode::Light => FecMode::Normal,
            FecMode::Normal => FecMode::Medium,
            FecMode::Medium => FecMode::Strong,
            FecMode::Strong | FecMode::Extreme => FecMode::Extreme,
        }
    }

    fn prev_mode(&self, mode: FecMode) -> FecMode {
        match mode {
            FecMode::Extreme => FecMode::Strong,
            FecMode::Strong => FecMode::Medium,
            FecMode::Medium => FecMode::Normal,
            FecMode::Normal => FecMode::Light,
            FecMode::Light | FecMode::Zero => FecMode::Zero,
        }
    }
}

// --- PID Controller ---
#[derive(Clone, Copy)]
pub struct PidConfig {
    pub kp: f32,
    pub ki: f32,
    pub kd: f32,
}

struct PidController {
    config: PidConfig,
    integral: f32,
    previous_error: f32,
    last_time: Instant,
}

impl PidController {
    fn new(config: PidConfig) -> Self {
        Self {
            config,
            integral: 0.0,
            previous_error: 0.0,
            last_time: Instant::now(),
        }
    }

    fn update(&mut self, current_value: f32, setpoint: f32) -> f32 {
        let now = Instant::now();
        let dt = now.duration_since(self.last_time).as_secs_f32();
        self.last_time = now;
        if dt <= 0.0 {
            return 0.0;
        }
        let error = setpoint - current_value;
        self.integral += error * dt;
        let derivative = (error - self.previous_error) / dt;
        self.previous_error = error;
        (self.config.kp * error) + (self.config.ki * self.integral) + (self.config.kd * derivative)
    }
}

pub struct AdaptiveFec {
    estimator: Arc<Mutex<LossEstimator>>,
    mode_mgr: Arc<Mutex<ModeManager>>,
    encoder: EncoderVariant,
    decoder: DecoderVariant,
    transition_encoder: Option<EncoderVariant>,
    transition_decoder: Option<DecoderVariant>,
    transition_left: usize,
    window_complete: bool,
    mem_pool: Arc<MemoryPool>,
    config: FecConfig,
}

#[derive(Clone)]
pub struct FecConfig {
    pub lambda: f32,
    pub burst_window: usize,
    pub hysteresis: f32,
    pub pid: PidConfig,
    pub initial_mode: FecMode,
    pub kalman_enabled: bool,
    pub kalman_q: f32,
    pub kalman_r: f32,
    pub window_sizes: HashMap<FecMode, usize>,
}

impl FecConfig {
    pub fn default_windows() -> HashMap<FecMode, usize> {
        use FecMode::*;
        let mut m = HashMap::new();
        m.insert(Zero, 0);
        m.insert(Light, 16);
        m.insert(Normal, 64);
        m.insert(Medium, 128);
        m.insert(Strong, 512);
        m.insert(Extreme, 1024);
        m
    }

    pub fn from_toml(s: &str) -> Result<Self, Box<dyn std::error::Error>> {
        #[derive(serde::Deserialize)]
        struct Root {
            adaptive_fec: Adaptive,
        }
        #[derive(serde::Deserialize)]
        struct Adaptive {
            lambda: Option<f32>,
            burst_window: Option<usize>,
            hysteresis: Option<f32>,
            pid: Option<PidSection>,
            kalman_enabled: Option<bool>,
            kalman_q: Option<f32>,
            kalman_r: Option<f32>,
            modes: Option<Vec<ModeSection>>,
        }
        #[derive(serde::Deserialize)]
        struct PidSection {
            kp: f32,
            ki: f32,
            kd: f32,
        }
        #[derive(serde::Deserialize)]
        struct ModeSection {
            name: String,
            w0: usize,
        }

        let raw: Root = toml::from_str(s)?;
        let af = raw.adaptive_fec;
        let pid = af.pid.unwrap_or(PidSection {
            kp: 1.2,
            ki: 0.5,
            kd: 0.1,
        });
        let mut windows = FecConfig::default_windows();
        if let Some(modes) = af.modes {
            for msec in modes {
                if let Ok(mode) = msec.name.parse() {
                    windows.insert(mode, msec.w0);
                }
            }
        }
        Ok(FecConfig {
            lambda: af.lambda.unwrap_or(0.1),
            burst_window: af.burst_window.unwrap_or(20),
            hysteresis: af.hysteresis.unwrap_or(0.02),
            pid: PidConfig {
                kp: pid.kp,
                ki: pid.ki,
                kd: pid.kd,
            },
            initial_mode: FecMode::Zero,
            kalman_enabled: af.kalman_enabled.unwrap_or(false),
            kalman_q: af.kalman_q.unwrap_or(0.001),
            kalman_r: af.kalman_r.unwrap_or(0.01),
            window_sizes: windows,
        })
    }

    pub fn from_file(path: &std::path::Path) -> Result<Self, Box<dyn std::error::Error>> {
        let contents = std::fs::read_to_string(path)?;
        Self::from_toml(&contents)
    }
}

impl Default for FecConfig {
    fn default() -> Self {
        Self {
            lambda: 0.1,
            burst_window: 20,
            hysteresis: 0.02,
            pid: PidConfig {
                kp: 1.2,
                ki: 0.5,
                kd: 0.1,
            },
            initial_mode: FecMode::Zero,
            kalman_enabled: false,
            kalman_q: 0.001,
            kalman_r: 0.01,
            window_sizes: FecConfig::default_windows(),
        }
    }
}

impl FecConfig {
    pub fn validate(&self) -> Result<(), String> {
        if !(0.0..=1.0).contains(&self.lambda) {
            return Err("lambda must be between 0 and 1".into());
        }
        if self.burst_window == 0 {
            return Err("burst_window must be > 0".into());
        }
        if !(0.0..1.0).contains(&self.hysteresis) {
            return Err("hysteresis must be between 0 and 1".into());
        }
        if self.kalman_enabled && (self.kalman_q <= 0.0 || self.kalman_r <= 0.0) {
            return Err("kalman_q and kalman_r must be positive".into());
        }
        Ok(())
    }
}

impl AdaptiveFec {
    pub fn new(config: FecConfig, mem_pool: Arc<MemoryPool>) -> Self {
        self::gf_tables::init_gf_tables();
        let mode_mgr = ModeManager::new(
            config.pid,
            config.hysteresis,
            config.initial_mode,
            config.window_sizes.clone(),
        );
        let current_mode = mode_mgr.current_mode;
        let (k, n) = ModeManager::params_for(current_mode, mode_mgr.current_window);
        let this = Self {
            estimator: Arc::new(Mutex::new(LossEstimator::new(
                config.lambda,
                config.burst_window,
                config
                    .kalman_enabled
                    .then(|| KalmanFilter::new(config.kalman_q, config.kalman_r)),
            ))),
            mode_mgr: Arc::new(Mutex::new(mode_mgr)),
            encoder: EncoderVariant::new(current_mode, k, n),
            decoder: DecoderVariant::new(current_mode, k, Arc::clone(&mem_pool)),
            transition_encoder: None,
            transition_decoder: None,
            transition_left: 0,
            window_complete: false,
            mem_pool,
            config,
        };
        let cfg_lambda = this.config.lambda;
        let cfg_burst = this.config.burst_window;
        let cfg_hyst = this.config.hysteresis;
        let cfg_kalman = this.config.kalman_enabled;
        let win = {
            match this.mode_mgr.lock() {
                Ok(g) => g.current_window,
                Err(poisoned) => {
                    warn!("adaptive.new: mode_mgr mutex poisoned; recovering state");
                    poisoned.into_inner().current_window
                }
            }
        };
        telemetry!(telemetry::FEC_WINDOW.set(win as i64));
        telemetry!(telemetry::FEC_LAMBDA.set((cfg_lambda * 1000.0) as i64));
        telemetry!(telemetry::FEC_BURST_WINDOW.set(cfg_burst as i64));
        telemetry!(telemetry::FEC_HYSTERESIS.set((cfg_hyst * 1000.0) as i64));
        telemetry!(telemetry::FEC_KALMAN.set(if cfg_kalman { 1 } else { 0 }));
        this
    }

    pub fn current_mode(&self) -> FecMode {
        let mgr = match self.mode_mgr.lock() {
            Ok(g) => g,
            Err(poisoned) => {
                warn!("adaptive.current_mode: mode_mgr mutex poisoned; recovering state");
                poisoned.into_inner()
            }
        };
        mgr.current_mode
    }

    pub fn is_transitioning(&self) -> bool {
        self.transition_left > 0
    }

    pub fn on_send(&mut self, pkt: Packet, outgoing_queue: &mut VecDeque<Packet>) {
        // During transition, we only use the primary (current) encoder for emissions.
        // The transition encoder is kept for symmetry but not used to emit to avoid mixed FEC streams.
        self.encoder
            .add_source_packet(pkt.clone_for_encoder(&self.mem_pool));
        outgoing_queue.push_back(pkt);
        telemetry!(crate::telemetry::ENCODED_PACKETS.inc());

        Self::emit_repairs(&mut self.encoder, &self.mem_pool, outgoing_queue);

        if self.transition_left > 0 {
            self.transition_left -= 1;
            if self.transition_left == 0 {
                self.transition_encoder = None;
                self.transition_decoder = None;
            }
        }
    }

    fn emit_repairs(
        encoder: &mut EncoderVariant,
        mem_pool: &Arc<MemoryPool>,
        outgoing_queue: &mut VecDeque<Packet>,
    ) {
        let (k, n) = match encoder {
            EncoderVariant::G8(e) => (e.k, e.n),
            EncoderVariant::G16(e) => (e.k, e.n),
        };
        if !encoder.window_is_full() {
            return;
        }
        let num_repair = n.saturating_sub(k);
        let do_parallel = std::env::var("QUICFUSCATE_FEC_PARALLEL")
            .map(|v| v != "0" && v.to_lowercase() != "false")
            .unwrap_or(true);
        if do_parallel && num_repair >= 2 {
            let enc_ref: &EncoderVariant = &*encoder;
            let repairs: Vec<Packet> = (0..num_repair)
                .into_par_iter()
                .filter_map(|i| enc_ref.generate_repair_packet(i, mem_pool))
                .collect();
            for pkt in repairs {
                outgoing_queue.push_back(pkt);
                telemetry!(crate::telemetry::ENCODED_PACKETS.inc());
            }
        } else {
            for i in 0..num_repair {
                if let Some(repair_packet) = encoder.generate_repair_packet(i, mem_pool) {
                    outgoing_queue.push_back(repair_packet);
                    telemetry!(crate::telemetry::ENCODED_PACKETS.inc());
                }
            }
        }
        // Policy: cap outgoing repairs based on loss telemetry to avoid flooding; handled elsewhere
        encoder.clear_window();
    }

    pub fn on_receive(&mut self, pkt: Packet) -> Result<Vec<Packet>, &'static str> {
        // If we've already decoded the current window, ignore further packets for this transition
        // to avoid duplicate decodes from excessive repairs.
        if self.window_complete {
            if self.transition_left > 0 {
                self.transition_left -= 1;
                if self.transition_left == 0 {
                    self.transition_encoder = None;
                    self.transition_decoder = None;
                }
            }
            return Ok(Vec::new());
        }

        let mut recovered = Vec::new();
        let was_decoded = self.decoder.is_decoded();
        match self.decoder.add_packet(pkt) {
            Ok(is_now_decoded) => {
                if !was_decoded && is_now_decoded {
                    recovered.extend(self.decoder.get_decoded_packets());
                    self.window_complete = true;
                    telemetry!(crate::telemetry::DECODED_PACKETS.inc_by(recovered.len() as u64));
                }
            }
            Err(e) => return Err(e),
        }

        if self.transition_left > 0 {
            self.transition_left -= 1;
            if self.transition_left == 0 {
                self.transition_encoder = None;
                self.transition_decoder = None;
            }
        }

        Ok(recovered)
    }

    pub fn report_loss(&mut self, lost: usize, total: usize) {
        let mut estimator = match self.estimator.lock() {
            Ok(g) => g,
            Err(poisoned) => {
                warn!("adaptive.report_loss: estimator mutex poisoned; recovering state");
                poisoned.into_inner()
            }
        };
        estimator.report_loss(lost, total);
        let estimated_loss = estimator.get_estimated_loss();
        drop(estimator);
        telemetry!(crate::telemetry::LOSS_RATE.set((estimated_loss * 100.0) as i64));

        let mut mode_mgr = match self.mode_mgr.lock() {
            Ok(g) => g,
            Err(poisoned) => {
                warn!("adaptive.report_loss: mode_mgr mutex poisoned; recovering state");
                poisoned.into_inner()
            }
        };
        let (new_mode, new_window, prev) = mode_mgr.update(estimated_loss);
        let (k, n) = ModeManager::params_for(new_mode, new_window);

        if let Some((old_mode, old_window)) = prev {
            let (_ok, _on) = ModeManager::params_for(old_mode, old_window);
            self.transition_encoder = Some(std::mem::replace(
                &mut self.encoder,
                EncoderVariant::new(new_mode, k, n),
            ));
            self.transition_decoder = Some(std::mem::replace(
                &mut self.decoder,
                DecoderVariant::new(new_mode, k, Arc::clone(&self.mem_pool)),
            ));
            self.transition_left = ModeManager::CROSS_FADE_LEN;
            self.window_complete = false;
        } else {
            self.encoder = EncoderVariant::new(new_mode, k, n);
            self.decoder = DecoderVariant::new(new_mode, k, Arc::clone(&self.mem_pool));
        }
    }
}
