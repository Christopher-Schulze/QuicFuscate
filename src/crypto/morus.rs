#![allow(unexpected_cfgs)]
//! MORUS-1280-128 AEAD cipher implementation.
//!
//! Specification: <https://competitions.cr.yp.to/round3/morusv2.pdf>

use core::ptr;
use std::sync::OnceLock;

#[cfg(target_arch = "x86_64")]
use std::arch::x86_64::*;

use crate::crypto::aead::{require_exact_key_iv, AeadOpen, AeadSeal, KeyMaterialError};
use zeroize::Zeroize;

// MORUS-1280-128 AEAD cipher implementation
// Specification: https://competitions.cr.yp.to/round3/morusv2.pdf

/// MORUS-1280-128 state: 5 blocks of 256 bits each
#[derive(Clone)]
struct Morus1280State {
    s: [[u64; 4]; 5],
}

impl Drop for Morus1280State {
    fn drop(&mut self) {
        for row in self.s.iter_mut() {
            for word in row.iter_mut() {
                word.zeroize();
            }
        }
    }
}

impl Morus1280State {
    #[cfg_attr(all(target_arch = "aarch64", target_feature = "neon"), allow(dead_code))]
    #[inline(always)]
    fn rotl_words_256(x: [u64; 4], k_words: usize) -> [u64; 4] {
        let k = k_words % 4;
        [x[k % 4], x[(1 + k) % 4], x[(2 + k) % 4], x[(3 + k) % 4]]
    }

    #[cfg(target_arch = "x86_64")]
    #[inline(always)]
    // SAFETY: caller must ensure SSE2 is available (baseline x86_64). `src` is a
    // fixed-size &[u64; 4] (32 bytes); _mm_loadu_si128 reads 16 bytes at offset 0
    // and 16 bytes at offset 16, both within bounds. Unaligned loads are permitted.
    unsafe fn load_u64x4_sse(src: &[u64; 4]) -> (__m128i, __m128i) {
        use core::arch::x86_64::*;
        let lo = _mm_loadu_si128(src.as_ptr() as *const __m128i);
        let hi = _mm_loadu_si128(src.as_ptr().add(2) as *const __m128i);
        (lo, hi)
    }

    #[cfg(target_arch = "x86_64")]
    #[inline(always)]
    // SAFETY: caller must ensure SSE2 is available. `dst` is &mut [u64; 4] (32 bytes);
    // _mm_storeu_si128 writes 16 bytes at offset 0 and 16 bytes at offset 16, both
    // within bounds. Exclusive borrow prevents aliasing. Unaligned stores permitted.
    unsafe fn store_u64x4_sse(dst: &mut [u64; 4], lo: __m128i, hi: __m128i) {
        use core::arch::x86_64::*;
        _mm_storeu_si128(dst.as_mut_ptr() as *mut __m128i, lo);
        _mm_storeu_si128(dst.as_mut_ptr().add(2) as *mut __m128i, hi);
    }

    #[cfg(target_arch = "x86_64")]
    #[inline(always)]
    // SAFETY: caller must ensure SSE2 is available. All inputs are by-value __m128i
    // registers; no pointer dereferences. Shift amounts are masked to 0..63.
    unsafe fn rotl_epi64(x: __m128i, n: i32) -> __m128i {
        use core::arch::x86_64::*;
        let n = ((n as u32) & 63) as i32;
        if n == 0 {
            return x;
        }
        let cnt = _mm_cvtsi32_si128(n);
        let left = _mm_sll_epi64(x, cnt);
        let right = _mm_srl_epi64(x, _mm_cvtsi32_si128(64 - n));
        _mm_or_si128(left, right)
    }

    #[cfg(target_arch = "x86_64")]
    #[inline(always)]
    // SAFETY: caller must ensure SSE2 is available. `tmp` is a stack-owned [u64; 4]
    // providing valid aligned storage for _mm_storeu/_mm_loadu; no out-of-bounds access.
    unsafe fn rotl_words_pair_sse(mut lo: __m128i, mut hi: __m128i, k: i32) -> (__m128i, __m128i) {
        use core::arch::x86_64::*;
        let shift = (k & 3) as usize;
        if shift == 0 {
            return (lo, hi);
        }
        let mut tmp = [0u64; 4];
        _mm_storeu_si128(tmp.as_mut_ptr() as *mut __m128i, lo);
        _mm_storeu_si128(tmp.as_mut_ptr().add(2) as *mut __m128i, hi);
        // Use scalar helper to rotate words to mark it as used without changing semantics
        let tmp = Self::rotl_words_256(tmp, shift);
        lo = _mm_loadu_si128(tmp.as_ptr() as *const __m128i);
        hi = _mm_loadu_si128(tmp.as_ptr().add(2) as *const __m128i);
        (lo, hi)
    }

    // SSSE3 helper: rotate 4x u64 words across (lo,hi) pair by k words using byte-align shuffles
    #[cfg(target_arch = "x86_64")]
    #[inline]
    #[target_feature(enable = "ssse3")]
    // SAFETY: target_feature gate ensures SSSE3 intrinsics (_mm_alignr_epi8) are
    // available. All inputs are by-value __m128i registers; no memory operations.
    unsafe fn rotl_words_pair_ssse3(lo: __m128i, hi: __m128i, k: i32) -> (__m128i, __m128i) {
        use core::arch::x86_64::*;
        let s = (k & 3) as i32;
        match s {
            0 => (lo, hi),
            1 => (
                _mm_alignr_epi8(hi, lo, 8), // [x1,x2]
                _mm_alignr_epi8(lo, hi, 8), // [x3,x0]
            ),
            2 => (hi, lo),
            3 => (
                _mm_alignr_epi8(lo, hi, 8), // [x3,x0]
                _mm_alignr_epi8(hi, lo, 8), // [x1,x2]
            ),
            _ => (lo, hi),
        }
    }

    // SSSE3-optimized MORUS update with in-register word rotations
    #[cfg(target_arch = "x86_64")]
    #[inline]
    #[target_feature(enable = "ssse3")]
    // SAFETY: target_feature gate ensures SSSE3 is available. `self.s` is
    // [[u64;4];5] providing valid aligned storage for load/store intrinsics.
    // `m` is by-value [u64;4]. All pointer arithmetic stays within array bounds.
    unsafe fn update_simd_ssse3(&mut self, m: [u64; 4]) {
        use core::arch::x86_64::*;

        let (s0_lo, s0_hi) = Self::load_u64x4_sse(&self.s[0]);
        let (s1_lo, s1_hi) = Self::load_u64x4_sse(&self.s[1]);
        let (s2_lo, s2_hi) = Self::load_u64x4_sse(&self.s[2]);
        let (s3_lo, s3_hi) = Self::load_u64x4_sse(&self.s[3]);
        let (s4_lo, s4_hi) = Self::load_u64x4_sse(&self.s[4]);
        let (m_lo, m_hi) = Self::load_u64x4_sse(&m);

        // Round 1
        let t0_lo = _mm_xor_si128(_mm_xor_si128(s0_lo, _mm_and_si128(s1_lo, s2_lo)), s3_lo);
        let t0_hi = _mm_xor_si128(_mm_xor_si128(s0_hi, _mm_and_si128(s1_hi, s2_hi)), s3_hi);
        let r1_0_lo = Self::rotl_epi64(t0_lo, 13);
        let r1_0_hi = Self::rotl_epi64(t0_hi, 13);
        let (r1_3_lo, r1_3_hi) = Self::rotl_words_pair_ssse3(s3_lo, s3_hi, 1);

        // Round 2
        let t1_lo = _mm_xor_si128(_mm_xor_si128(s1_lo, _mm_and_si128(s2_lo, r1_3_lo)), s4_lo);
        let t1_lo = _mm_xor_si128(t1_lo, m_lo);
        let t1_hi = _mm_xor_si128(_mm_xor_si128(s1_hi, _mm_and_si128(s2_hi, r1_3_hi)), s4_hi);
        let t1_hi = _mm_xor_si128(t1_hi, m_hi);
        let r2_1_lo = Self::rotl_epi64(t1_lo, 46);
        let r2_1_hi = Self::rotl_epi64(t1_hi, 46);
        let (r2_4_lo, r2_4_hi) = Self::rotl_words_pair_ssse3(s4_lo, s4_hi, 2);

        // Round 3
        let t2_lo = _mm_xor_si128(_mm_xor_si128(s2_lo, _mm_and_si128(r1_3_lo, r2_4_lo)), r1_0_lo);
        let t2_lo = _mm_xor_si128(t2_lo, m_lo);
        let t2_hi = _mm_xor_si128(_mm_xor_si128(s2_hi, _mm_and_si128(r1_3_hi, r2_4_hi)), r1_0_hi);
        let t2_hi = _mm_xor_si128(t2_hi, m_hi);
        let r3_2_lo = Self::rotl_epi64(t2_lo, 38);
        let r3_2_hi = Self::rotl_epi64(t2_hi, 38);
        let (r3_0_lo, r3_0_hi) = Self::rotl_words_pair_ssse3(r1_0_lo, r1_0_hi, 3);

        // Round 4
        let t3_lo = _mm_xor_si128(_mm_xor_si128(r1_3_lo, _mm_and_si128(r2_4_lo, r3_0_lo)), r2_1_lo);
        let t3_lo = _mm_xor_si128(t3_lo, m_lo);
        let t3_hi = _mm_xor_si128(_mm_xor_si128(r1_3_hi, _mm_and_si128(r2_4_hi, r3_0_hi)), r2_1_hi);
        let t3_hi = _mm_xor_si128(t3_hi, m_hi);
        let r4_3_lo = Self::rotl_epi64(t3_lo, 7);
        let r4_3_hi = Self::rotl_epi64(t3_hi, 7);
        let (r4_1_lo, r4_1_hi) = Self::rotl_words_pair_ssse3(r2_1_lo, r2_1_hi, 2);

        // Round 5
        let t4_lo = _mm_xor_si128(_mm_xor_si128(r2_4_lo, _mm_and_si128(r3_0_lo, r4_1_lo)), r3_2_lo);
        let t4_lo = _mm_xor_si128(t4_lo, m_lo);
        let t4_hi = _mm_xor_si128(_mm_xor_si128(r2_4_hi, _mm_and_si128(r3_0_hi, r4_1_hi)), r3_2_hi);
        let t4_hi = _mm_xor_si128(t4_hi, m_hi);
        let new4_lo = Self::rotl_epi64(t4_lo, 4);
        let new4_hi = Self::rotl_epi64(t4_hi, 4);
        let (new2_lo, new2_hi) = Self::rotl_words_pair_ssse3(r3_2_lo, r3_2_hi, 1);

        Self::store_u64x4_sse(&mut self.s[0], r3_0_lo, r3_0_hi);
        Self::store_u64x4_sse(&mut self.s[1], r4_1_lo, r4_1_hi);
        Self::store_u64x4_sse(&mut self.s[2], new2_lo, new2_hi);
        Self::store_u64x4_sse(&mut self.s[3], r4_3_lo, r4_3_hi);
        Self::store_u64x4_sse(&mut self.s[4], new4_lo, new4_hi);
    }

    #[cfg(target_arch = "x86_64")]
    #[inline]
    #[target_feature(enable = "ssse3,sse4.1")]
    // SAFETY: target_feature gate ensures SSSE3 and SSE4.1 are available. All
    // inputs are by-value __m128i registers; no memory operations.
    unsafe fn rotl_words_pair_sse41(lo: __m128i, hi: __m128i, k: i32) -> (__m128i, __m128i) {
        Self::rotl_words_pair_ssse3(lo, hi, k)
    }

    #[cfg(target_arch = "x86_64")]
    #[inline]
    #[target_feature(enable = "ssse3,sse4.1")]
    // SAFETY: target_feature gate ensures SSSE3 and SSE4.1 are available. `self.s` is
    // [[u64;4];5] providing valid aligned storage for SIMD load/store intrinsics.
    // `m` is by-value [u64;4]. All pointer arithmetic stays within array bounds.
    unsafe fn update_simd_sse41(&mut self, m: [u64; 4]) {
        use core::arch::x86_64::*;

        let (s0_lo, s0_hi) = Self::load_u64x4_sse(&self.s[0]);
        let (s1_lo, s1_hi) = Self::load_u64x4_sse(&self.s[1]);
        let (s2_lo, s2_hi) = Self::load_u64x4_sse(&self.s[2]);
        let (s3_lo, s3_hi) = Self::load_u64x4_sse(&self.s[3]);
        let (s4_lo, s4_hi) = Self::load_u64x4_sse(&self.s[4]);
        let (m_lo, m_hi) = Self::load_u64x4_sse(&m);

        // Round 1
        let mut t0_lo = _mm_xor_si128(_mm_xor_si128(s0_lo, _mm_and_si128(s1_lo, s2_lo)), s3_lo);
        let mut t0_hi = _mm_xor_si128(_mm_xor_si128(s0_hi, _mm_and_si128(s1_hi, s2_hi)), s3_hi);
        let r1_0_lo = Self::rotl_epi64(t0_lo, 13);
        let r1_0_hi = Self::rotl_epi64(t0_hi, 13);
        let (r1_3_lo, r1_3_hi) = Self::rotl_words_pair_sse41(s3_lo, s3_hi, 1);

        // Round 2
        t0_lo = _mm_xor_si128(_mm_xor_si128(s1_lo, _mm_and_si128(s2_lo, r1_3_lo)), s4_lo);
        t0_lo = _mm_xor_si128(t0_lo, m_lo);
        t0_hi = _mm_xor_si128(_mm_xor_si128(s1_hi, _mm_and_si128(s2_hi, r1_3_hi)), s4_hi);
        t0_hi = _mm_xor_si128(t0_hi, m_hi);
        let r2_1_lo = Self::rotl_epi64(t0_lo, 46);
        let r2_1_hi = Self::rotl_epi64(t0_hi, 46);
        let (r2_4_lo, r2_4_hi) = Self::rotl_words_pair_sse41(s4_lo, s4_hi, 2);

        // Round 3
        t0_lo = _mm_xor_si128(_mm_xor_si128(s2_lo, _mm_and_si128(r1_3_lo, r2_4_lo)), r1_0_lo);
        t0_lo = _mm_xor_si128(t0_lo, m_lo);
        t0_hi = _mm_xor_si128(_mm_xor_si128(s2_hi, _mm_and_si128(r1_3_hi, r2_4_hi)), r1_0_hi);
        t0_hi = _mm_xor_si128(t0_hi, m_hi);
        let r3_2_lo = Self::rotl_epi64(t0_lo, 38);
        let r3_2_hi = Self::rotl_epi64(t0_hi, 38);
        let (r3_0_lo, r3_0_hi) = Self::rotl_words_pair_sse41(r1_0_lo, r1_0_hi, 3);

        // Round 4
        t0_lo = _mm_xor_si128(_mm_xor_si128(r1_3_lo, _mm_and_si128(r2_4_lo, r3_0_lo)), r2_1_lo);
        t0_lo = _mm_xor_si128(t0_lo, m_lo);
        t0_hi = _mm_xor_si128(_mm_xor_si128(r1_3_hi, _mm_and_si128(r2_4_hi, r3_0_hi)), r2_1_hi);
        t0_hi = _mm_xor_si128(t0_hi, m_hi);
        let r4_3_lo = Self::rotl_epi64(t0_lo, 7);
        let r4_3_hi = Self::rotl_epi64(t0_hi, 7);
        let (r4_1_lo, r4_1_hi) = Self::rotl_words_pair_sse41(r2_1_lo, r2_1_hi, 2);

        // Round 5
        t0_lo = _mm_xor_si128(_mm_xor_si128(r2_4_lo, _mm_and_si128(r3_0_lo, r4_1_lo)), r3_2_lo);
        t0_lo = _mm_xor_si128(t0_lo, m_lo);
        t0_hi = _mm_xor_si128(_mm_xor_si128(r2_4_hi, _mm_and_si128(r3_0_hi, r4_1_hi)), r3_2_hi);
        t0_hi = _mm_xor_si128(t0_hi, m_hi);
        let new4_lo = Self::rotl_epi64(t0_lo, 4);
        let new4_hi = Self::rotl_epi64(t0_hi, 4);
        let (new2_lo, new2_hi) = Self::rotl_words_pair_sse41(r3_2_lo, r3_2_hi, 1);

        Self::store_u64x4_sse(&mut self.s[0], r3_0_lo, r3_0_hi);
        Self::store_u64x4_sse(&mut self.s[1], r4_1_lo, r4_1_hi);
        Self::store_u64x4_sse(&mut self.s[2], new2_lo, new2_hi);
        Self::store_u64x4_sse(&mut self.s[3], r4_3_lo, r4_3_hi);
        Self::store_u64x4_sse(&mut self.s[4], new4_lo, new4_hi);
    }

    // SSE4.2 uses same code as SSE4.1 (no new bit-manipulation instructions needed for MORUS)
    #[cfg(target_arch = "x86_64")]
    #[inline]
    #[target_feature(enable = "ssse3,sse4.1,sse4.2")]
    // SAFETY: target_feature gate ensures SSSE3 through SSE4.2 are available. Delegates to
    // update_simd_sse41 which has its own safety invariants for state access.
    unsafe fn update_simd_sse42(&mut self, m: [u64; 4]) {
        self.update_simd_sse41(m)
    }

    #[cfg(all(target_arch = "x86_64", target_feature = "sse2"))]
    // SAFETY: compile-time target_feature="sse2" guarantees SSE2 availability.
    // `self.s` is [[u64;4];5] providing valid aligned storage for _mm_loadu/_mm_storeu.
    // `m` is by-value [u64;4]. All pointer arithmetic stays within array bounds.
    unsafe fn update_simd_sse2(&mut self, m: [u64; 4]) {
        use core::arch::x86_64::*;

        let (s0_lo, s0_hi) = Self::load_u64x4_sse(&self.s[0]);
        let (s1_lo, s1_hi) = Self::load_u64x4_sse(&self.s[1]);
        let (s2_lo, s2_hi) = Self::load_u64x4_sse(&self.s[2]);
        let (s3_lo, s3_hi) = Self::load_u64x4_sse(&self.s[3]);
        let (s4_lo, s4_hi) = Self::load_u64x4_sse(&self.s[4]);
        let (m_lo, m_hi) = Self::load_u64x4_sse(&m);

        // Round 1
        let t0_lo = _mm_xor_si128(_mm_xor_si128(s0_lo, _mm_and_si128(s1_lo, s2_lo)), s3_lo);
        let t0_hi = _mm_xor_si128(_mm_xor_si128(s0_hi, _mm_and_si128(s1_hi, s2_hi)), s3_hi);
        let r1_0_lo = Self::rotl_epi64(t0_lo, 13);
        let r1_0_hi = Self::rotl_epi64(t0_hi, 13);
        let (r1_3_lo, r1_3_hi) = Self::rotl_words_pair_sse(s3_lo, s3_hi, 1);

        // Round 2
        let t1_lo = _mm_xor_si128(_mm_xor_si128(s1_lo, _mm_and_si128(s2_lo, r1_3_lo)), s4_lo);
        let t1_lo = _mm_xor_si128(t1_lo, m_lo);
        let t1_hi = _mm_xor_si128(_mm_xor_si128(s1_hi, _mm_and_si128(s2_hi, r1_3_hi)), s4_hi);
        let t1_hi = _mm_xor_si128(t1_hi, m_hi);
        let r2_1_lo = Self::rotl_epi64(t1_lo, 46);
        let r2_1_hi = Self::rotl_epi64(t1_hi, 46);
        let (r2_4_lo, r2_4_hi) = Self::rotl_words_pair_sse(s4_lo, s4_hi, 2);

        // Round 3
        let t2_lo = _mm_xor_si128(_mm_xor_si128(s2_lo, _mm_and_si128(r1_3_lo, r2_4_lo)), r1_0_lo);
        let t2_lo = _mm_xor_si128(t2_lo, m_lo);
        let t2_hi = _mm_xor_si128(_mm_xor_si128(s2_hi, _mm_and_si128(r1_3_hi, r2_4_hi)), r1_0_hi);
        let t2_hi = _mm_xor_si128(t2_hi, m_hi);
        let r3_2_lo = Self::rotl_epi64(t2_lo, 38);
        let r3_2_hi = Self::rotl_epi64(t2_hi, 38);
        let (r3_0_lo, r3_0_hi) = Self::rotl_words_pair_sse(r1_0_lo, r1_0_hi, 3);

        // Round 4
        let t3_lo = _mm_xor_si128(_mm_xor_si128(r1_3_lo, _mm_and_si128(r2_4_lo, r3_0_lo)), r2_1_lo);
        let t3_lo = _mm_xor_si128(t3_lo, m_lo);
        let t3_hi = _mm_xor_si128(_mm_xor_si128(r1_3_hi, _mm_and_si128(r2_4_hi, r3_0_hi)), r2_1_hi);
        let t3_hi = _mm_xor_si128(t3_hi, m_hi);
        let r4_3_lo = Self::rotl_epi64(t3_lo, 7);
        let r4_3_hi = Self::rotl_epi64(t3_hi, 7);
        let (r4_1_lo, r4_1_hi) = Self::rotl_words_pair_sse(r2_1_lo, r2_1_hi, 2);

        // Round 5
        let t4_lo = _mm_xor_si128(_mm_xor_si128(r2_4_lo, _mm_and_si128(r3_0_lo, r4_1_lo)), r3_2_lo);
        let t4_lo = _mm_xor_si128(t4_lo, m_lo);
        let t4_hi = _mm_xor_si128(_mm_xor_si128(r2_4_hi, _mm_and_si128(r3_0_hi, r4_1_hi)), r3_2_hi);
        let t4_hi = _mm_xor_si128(t4_hi, m_hi);
        let new4_lo = Self::rotl_epi64(t4_lo, 4);
        let new4_hi = Self::rotl_epi64(t4_hi, 4);
        let (new2_lo, new2_hi) = Self::rotl_words_pair_sse(r3_2_lo, r3_2_hi, 1);

        Self::store_u64x4_sse(&mut self.s[0], r3_0_lo, r3_0_hi);
        Self::store_u64x4_sse(&mut self.s[1], r4_1_lo, r4_1_hi);
        Self::store_u64x4_sse(&mut self.s[2], new2_lo, new2_hi);
        Self::store_u64x4_sse(&mut self.s[3], r4_3_lo, r4_3_hi);
        Self::store_u64x4_sse(&mut self.s[4], new4_lo, new4_hi);
    }

    #[cfg(all(target_arch = "aarch64", target_feature = "neon"))]
    #[inline(always)]
    // SAFETY: compile-time target_feature="neon" guarantees NEON intrinsics are
    // available. All inputs are by-value NEON vector registers; no memory operations.
    unsafe fn rot_words_pair_neon(
        lo: core::arch::aarch64::uint64x2_t,
        hi: core::arch::aarch64::uint64x2_t,
        k: i32,
    ) -> (core::arch::aarch64::uint64x2_t, core::arch::aarch64::uint64x2_t) {
        use core::arch::aarch64::{
            uint8x16_t, vextq_u8, vreinterpretq_u64_u8, vreinterpretq_u8_u64,
        };
        match k & 3 {
            0 => (lo, hi),
            1 => {
                let lo_u8: uint8x16_t = vreinterpretq_u8_u64(lo);
                let hi_u8: uint8x16_t = vreinterpretq_u8_u64(hi);
                let new_lo = vreinterpretq_u64_u8(vextq_u8(lo_u8, hi_u8, 8));
                let new_hi = vreinterpretq_u64_u8(vextq_u8(hi_u8, lo_u8, 8));
                (new_lo, new_hi)
            }
            2 => (hi, lo),
            3 => {
                let lo_u8: uint8x16_t = vreinterpretq_u8_u64(lo);
                let hi_u8: uint8x16_t = vreinterpretq_u8_u64(hi);
                let new_lo = vreinterpretq_u64_u8(vextq_u8(hi_u8, lo_u8, 8));
                let new_hi = vreinterpretq_u64_u8(vextq_u8(lo_u8, hi_u8, 8));
                (new_lo, new_hi)
            }
            _ => {
                debug_assert!(false, "invalid rotate amount");
                (lo, hi)
            }
        }
    }

    #[cfg(all(target_arch = "aarch64", target_feature = "neon"))]
    // SAFETY: compile-time target_feature="neon" guarantees NEON availability.
    // `self.s` is [[u64;4];5]; vld1q_u64_x2 reads 32 bytes per state row and
    // vst1q_u64_x2 writes 32 bytes, both within the 32-byte row bounds.
    // `m` is by-value [u64;4].
    unsafe fn update_simd_neon(&mut self, m: [u64; 4]) {
        use core::arch::aarch64::*;

        let s0_pair = vld1q_u64_x2(self.s[0].as_ptr());
        let s1_pair = vld1q_u64_x2(self.s[1].as_ptr());
        let s2_pair = vld1q_u64_x2(self.s[2].as_ptr());
        let s3_pair = vld1q_u64_x2(self.s[3].as_ptr());
        let s4_pair = vld1q_u64_x2(self.s[4].as_ptr());

        let s0 = s0_pair.0;
        let s0_hi = s0_pair.1;
        let s1 = s1_pair.0;
        let s1_hi = s1_pair.1;
        let s2 = s2_pair.0;
        let s2_hi = s2_pair.1;
        let s3 = s3_pair.0;
        let s3_hi = s3_pair.1;
        let s4 = s4_pair.0;
        let s4_hi = s4_pair.1;

        let m_pair = vld1q_u64_x2(m.as_ptr());
        let m_lo = m_pair.0;
        let m_hi = m_pair.1;

        macro_rules! rotl64_neon {
            ($val:expr, $shift:expr) => {{
                let left = vshlq_n_u64($val, $shift);
                let right = vshrq_n_u64($val, 64 - $shift);
                veorq_u64(left, right)
            }};
        }

        // Round 1
        let t0_lo = veorq_u64(veorq_u64(s0, vandq_u64(s1, s2)), s3);
        let t0_hi = veorq_u64(veorq_u64(s0_hi, vandq_u64(s1_hi, s2_hi)), s3_hi);
        let r1_0_lo = rotl64_neon!(t0_lo, 13);
        let r1_0_hi = rotl64_neon!(t0_hi, 13);
        let (r1_3_lo, r1_3_hi) = Self::rot_words_pair_neon(s3, s3_hi, 1);

        // Round 2
        let t1_lo = veorq_u64(veorq_u64(s1, vandq_u64(s2, r1_3_lo)), s4);
        let t1_lo = veorq_u64(t1_lo, m_lo);
        let t1_hi = veorq_u64(veorq_u64(s1_hi, vandq_u64(s2_hi, r1_3_hi)), s4_hi);
        let t1_hi = veorq_u64(t1_hi, m_hi);
        let r2_1_lo = rotl64_neon!(t1_lo, 46);
        let r2_1_hi = rotl64_neon!(t1_hi, 46);
        let (r2_4_lo, r2_4_hi) = Self::rot_words_pair_neon(s4, s4_hi, 2);

        // Round 3
        let t2_lo = veorq_u64(veorq_u64(s2, vandq_u64(r1_3_lo, r2_4_lo)), r1_0_lo);
        let t2_lo = veorq_u64(t2_lo, m_lo);
        let t2_hi = veorq_u64(veorq_u64(s2_hi, vandq_u64(r1_3_hi, r2_4_hi)), r1_0_hi);
        let t2_hi = veorq_u64(t2_hi, m_hi);
        let r3_2_lo = rotl64_neon!(t2_lo, 38);
        let r3_2_hi = rotl64_neon!(t2_hi, 38);
        let (r3_0_lo, r3_0_hi) = Self::rot_words_pair_neon(r1_0_lo, r1_0_hi, 3);

        // Round 4
        let t3_lo = veorq_u64(veorq_u64(r1_3_lo, vandq_u64(r2_4_lo, r3_0_lo)), r2_1_lo);
        let t3_lo = veorq_u64(t3_lo, m_lo);
        let t3_hi = veorq_u64(veorq_u64(r1_3_hi, vandq_u64(r2_4_hi, r3_0_hi)), r2_1_hi);
        let t3_hi = veorq_u64(t3_hi, m_hi);
        let r4_3_lo = rotl64_neon!(t3_lo, 7);
        let r4_3_hi = rotl64_neon!(t3_hi, 7);
        let (r4_1_lo, r4_1_hi) = Self::rot_words_pair_neon(r2_1_lo, r2_1_hi, 2);

        // Round 5
        let t4_lo = veorq_u64(veorq_u64(r2_4_lo, vandq_u64(r3_0_lo, r4_1_lo)), r3_2_lo);
        let t4_lo = veorq_u64(t4_lo, m_lo);
        let t4_hi = veorq_u64(veorq_u64(r2_4_hi, vandq_u64(r3_0_hi, r4_1_hi)), r3_2_hi);
        let t4_hi = veorq_u64(t4_hi, m_hi);
        let new4_lo = rotl64_neon!(t4_lo, 4);
        let new4_hi = rotl64_neon!(t4_hi, 4);
        let (new2_lo, new2_hi) = Self::rot_words_pair_neon(r3_2_lo, r3_2_hi, 1);

        vst1q_u64_x2(self.s[0].as_mut_ptr(), uint64x2x2_t(r3_0_lo, r3_0_hi));
        vst1q_u64_x2(self.s[1].as_mut_ptr(), uint64x2x2_t(r4_1_lo, r4_1_hi));
        vst1q_u64_x2(self.s[2].as_mut_ptr(), uint64x2x2_t(new2_lo, new2_hi));
        vst1q_u64_x2(self.s[3].as_mut_ptr(), uint64x2x2_t(r4_3_lo, r4_3_hi));
        vst1q_u64_x2(self.s[4].as_mut_ptr(), uint64x2x2_t(new4_lo, new4_hi));
    }

    /// MORUS-1280-128 state update (5 rounds). Message block `m` is added in Rounds 2-5.
    #[inline(always)]
    fn update(&mut self, m: [u64; 4]) {
        // Runtime dispatch to best available backend, with safe scalar fallback
        // Order: SSE4.2 (newest) -> SSE4.1 -> SSSE3 -> SSE2 (oldest)
        #[cfg(target_arch = "x86_64")]
        {
            if is_x86_feature_detected!("sse4.2") && is_x86_feature_detected!("ssse3") {
                // SAFETY: runtime feature detection guarantees SSE4.2; `self.s` is a
                // stack-owned `[[u64;4];5]` providing valid aligned memory for the
                // SIMD load/store intrinsics; `m` is a by-value `[u64;4]`.
                unsafe { self.update_simd_sse42(m) }
                return;
            }
            if is_x86_feature_detected!("sse4.1") && is_x86_feature_detected!("ssse3") {
                // SAFETY: same as SSE4.2 path - runtime detection gates SSE4.1 intrinsics;
                // all data is stack-owned with valid alignment and lifetime.
                unsafe { self.update_simd_sse41(m) }
                return;
            }
            if is_x86_feature_detected!("ssse3") {
                // SAFETY: runtime detection gates SSSE3 intrinsics (_mm_alignr_epi8);
                // state and message are stack-owned arrays with valid alignment.
                unsafe { self.update_simd_ssse3(m) }
                return;
            }
            if is_x86_feature_detected!("sse2") {
                // SAFETY: SSE2 is baseline x86_64; all data is stack-owned with
                // valid 8-byte alignment (u64 arrays), sufficient for _mm_loadu_si128.
                unsafe { self.update_simd_sse2(m) }
                return;
            }
        }
        #[cfg(all(target_arch = "aarch64", target_feature = "neon"))]
        {
            // SAFETY: compile-time target_feature="neon" guarantees NEON availability;
            // `self.s` provides valid aligned storage for vld1q_u64_x2 / vst1q_u64_x2.
            unsafe { self.update_simd_neon(m) }
        }
        // Scalar fallback (compiled on non-NEON aarch64 and other targets)
        #[cfg(not(all(target_arch = "aarch64", target_feature = "neon")))]
        {
            let [s0_0, s0_1, s0_2, s0_3] = self.s[0];
            let [s1_0, s1_1, s1_2, s1_3] = self.s[1];
            let [s2_0, s2_1, s2_2, s2_3] = self.s[2];
            let [s3_0, s3_1, s3_2, s3_3] = self.s[3];
            let [s4_0, s4_1, s4_2, s4_3] = self.s[4];
            let [m0, m1, m2, m3] = m;

            let [r1_3_0, r1_3_1, r1_3_2, r1_3_3] =
                Self::rotl_words_256([s3_0, s3_1, s3_2, s3_3], 1);
            let r1_0_0 = (s0_0 ^ (s1_0 & s2_0) ^ s3_0).rotate_left(13);
            let r1_0_1 = (s0_1 ^ (s1_1 & s2_1) ^ s3_1).rotate_left(13);
            let r1_0_2 = (s0_2 ^ (s1_2 & s2_2) ^ s3_2).rotate_left(13);
            let r1_0_3 = (s0_3 ^ (s1_3 & s2_3) ^ s3_3).rotate_left(13);
            let r1_0 = [r1_0_0, r1_0_1, r1_0_2, r1_0_3];

            let [r2_4_0, r2_4_1, r2_4_2, r2_4_3] =
                Self::rotl_words_256([s4_0, s4_1, s4_2, s4_3], 2);
            let r2_1_0 = (s1_0 ^ (s2_0 & r1_3_0) ^ s4_0 ^ m0).rotate_left(46);
            let r2_1_1 = (s1_1 ^ (s2_1 & r1_3_1) ^ s4_1 ^ m1).rotate_left(46);
            let r2_1_2 = (s1_2 ^ (s2_2 & r1_3_2) ^ s4_2 ^ m2).rotate_left(46);
            let r2_1_3 = (s1_3 ^ (s2_3 & r1_3_3) ^ s4_3 ^ m3).rotate_left(46);
            let r2_1 = [r2_1_0, r2_1_1, r2_1_2, r2_1_3];

            let r3_2_0 = (s2_0 ^ (r1_3_0 & r2_4_0) ^ r1_0_0).rotate_left(38);
            let r3_2_1 = (s2_1 ^ (r1_3_1 & r2_4_1) ^ r1_0_1).rotate_left(38);
            let r3_2_2 = (s2_2 ^ (r1_3_2 & r2_4_2) ^ r1_0_2).rotate_left(38);
            let r3_2_3 = (s2_3 ^ (r1_3_3 & r2_4_3) ^ r1_0_3).rotate_left(38);
            let r3_2 = [r3_2_0, r3_2_1, r3_2_2, r3_2_3];
            let [r3_0_0, r3_0_1, r3_0_2, r3_0_3] = Self::rotl_words_256(r1_0, 3);

            let [r4_1_0, r4_1_1, r4_1_2, r4_1_3] = Self::rotl_words_256(r2_1, 2);
            let r4_3_0 = (r1_3_0 ^ (r2_4_0 & r3_0_0) ^ r2_1_0 ^ m0).rotate_left(7);
            let r4_3_1 = (r1_3_1 ^ (r2_4_1 & r3_0_1) ^ r2_1_1 ^ m1).rotate_left(7);
            let r4_3_2 = (r1_3_2 ^ (r2_4_2 & r3_0_2) ^ r2_1_2 ^ m2).rotate_left(7);
            let r4_3_3 = (r1_3_3 ^ (r2_4_3 & r3_0_3) ^ r2_1_3 ^ m3).rotate_left(7);
            let r4_3 = [r4_3_0, r4_3_1, r4_3_2, r4_3_3];

            let new4_0 = (r2_4_0 ^ (r3_0_0 & r4_1_0) ^ r3_2_0 ^ m0).rotate_left(4);
            let new4_1 = (r2_4_1 ^ (r3_0_1 & r4_1_1) ^ r3_2_1 ^ m1).rotate_left(4);
            let new4_2 = (r2_4_2 ^ (r3_0_2 & r4_1_2) ^ r3_2_2 ^ m2).rotate_left(4);
            let new4_3 = (r2_4_3 ^ (r3_0_3 & r4_1_3) ^ r3_2_3 ^ m3).rotate_left(4);
            let new4 = [new4_0, new4_1, new4_2, new4_3];
            let new2 = Self::rotl_words_256(r3_2, 1);

            self.s[0] = [r3_0_0, r3_0_1, r3_0_2, r3_0_3];
            self.s[1] = [r4_1_0, r4_1_1, r4_1_2, r4_1_3];
            self.s[2] = new2;
            self.s[3] = r4_3;
            self.s[4] = new4;
        }
    }

    /// Initialize MORUS-1280-128 state with key and nonce
    fn init(key: &[u8; 16], nonce: &[u8; 16]) -> Self {
        // k0 = K128 || K128
        let k0 =
            u64::from_le_bytes([key[0], key[1], key[2], key[3], key[4], key[5], key[6], key[7]]);
        let k1 = u64::from_le_bytes([
            key[8], key[9], key[10], key[11], key[12], key[13], key[14], key[15],
        ]);
        let k_block = [k0, k1, k0, k1];

        // IV128 || 0^128
        let n0 = u64::from_le_bytes([
            nonce[0], nonce[1], nonce[2], nonce[3], nonce[4], nonce[5], nonce[6], nonce[7],
        ]);
        let n1 = u64::from_le_bytes([
            nonce[8], nonce[9], nonce[10], nonce[11], nonce[12], nonce[13], nonce[14], nonce[15],
        ]);

        // Constants: const0 || const1 (Fibonacci sequence modulo 256)
        const C0: u64 = 0x0d08050302010100;
        const C1: u64 = 0x6279e99059372215;
        const C2: u64 = 0xf12fc26d55183ddb;
        const C3: u64 = 0xdd28b57342311120;

        let mut state = Self {
            s: [
                [n0, n1, 0, 0],   // S0 = IV128 || 0^128
                k_block,          // S1 = k0
                [u64::MAX; 4],    // S2 = 1^256
                [0u64; 4],        // S3 = 0^256
                [C0, C1, C2, C3], // S4 = const0 || const1
            ],
        };

        // 16 steps with m = 0
        for _ in 0..16 {
            state.update([0u64; 4]);
        }

        // XOR key block into S1 again
        for (i, kv) in k_block.iter().enumerate() {
            state.s[1][i] ^= *kv;
        }

        state
    }

    #[cfg(all(target_arch = "aarch64", target_feature = "neon"))]
    #[inline(always)]
    fn keystream_block(&self) -> [u64; 4] {
        // SAFETY: compile-time target_feature="neon" guarantees NEON availability;
        // `self.s` is a valid `[[u64;4];5]` providing aligned readable storage.
        unsafe { self.keystream_block_neon() }
    }

    #[cfg(not(all(target_arch = "aarch64", target_feature = "neon")))]
    #[inline(always)]
    fn keystream_block(&self) -> [u64; 4] {
        let s0 = self.s[0];
        let s1r = Self::rotl_words_256(self.s[1], 3); // <<< 192
        let s2 = self.s[2];
        let s3 = self.s[3];
        [
            s0[0] ^ s1r[0] ^ (s2[0] & s3[0]),
            s0[1] ^ s1r[1] ^ (s2[1] & s3[1]),
            s0[2] ^ s1r[2] ^ (s2[2] & s3[2]),
            s0[3] ^ s1r[3] ^ (s2[3] & s3[3]),
        ]
    }

    fn finalize(&mut self, ad_len: usize, msg_len: usize) -> [u8; 16] {
        let ad_bits = (ad_len as u64).wrapping_mul(8);
        let msg_bits = (msg_len as u64).wrapping_mul(8);

        // S4 ^= S0
        for i in 0..4 {
            self.s[4][i] ^= self.s[0][i];
        }

        // tmp = (adlen || msglen || 0^128)
        let tmp = [ad_bits, msg_bits, 0, 0];
        for _ in 0..10 {
            self.update(tmp);
        }

        // T0 = S0 XOR (S1 <<< 192) XOR (S2 & S3)
        let t = self.keystream_block();
        let mut tag = [0u8; 16];
        // 128 LSB: words 0 and 1 (little-endian)
        tag[0..8].copy_from_slice(&t[0].to_le_bytes());
        tag[8..16].copy_from_slice(&t[1].to_le_bytes());
        tag
    }

    fn process_ad(&mut self, ad: &[u8]) {
        let mut chunks = ad.chunks_exact(32);
        for chunk in &mut chunks {
            #[cfg(all(target_arch = "aarch64", target_feature = "neon"))]
            {
                let mut tmp = [0u8; 32];
                tmp.copy_from_slice(chunk);
                let block: &[u8; 32] = &tmp;
                // SAFETY: compile-time neon gate; `block` is a valid &[u8;32]
                // providing 32 readable bytes for vld1q_u64 loads.
                unsafe { self.update(Self::load_block32_neon(block)) };
            }
            #[cfg(not(all(target_arch = "aarch64", target_feature = "neon")))]
            {
                self.update(Self::load_block32(chunk));
            }
        }

        let rem = chunks.remainder();
        if !rem.is_empty() {
            let mut padded = [0u8; 32];
            padded[..rem.len()].copy_from_slice(rem);
            self.update(Self::load_block32(&padded));
        }
    }

    fn encrypt(&mut self, plaintext: &mut [u8]) {
        let mut chunks = plaintext.chunks_exact_mut(32);
        for chunk in &mut chunks {
            let mut tmp = [0u8; 32];
            tmp.copy_from_slice(chunk);
            let block: &mut [u8; 32] = &mut tmp;
            let ks = self.keystream_block();
            let plain_words = Self::xor_keystream_block_encrypt(block, &ks);
            self.update(plain_words);
            chunk.copy_from_slice(block);
        }

        let rem = chunks.into_remainder();
        if !rem.is_empty() {
            let ks = self.keystream_block();
            let plain_words = Self::xor_keystream_partial_encrypt(rem, &ks);
            self.update(plain_words);
        }
    }

    fn decrypt(&mut self, ciphertext: &mut [u8]) {
        let mut chunks = ciphertext.chunks_exact_mut(32);
        for chunk in &mut chunks {
            let mut tmp = [0u8; 32];
            tmp.copy_from_slice(chunk);
            let block: &mut [u8; 32] = &mut tmp;
            let ks = self.keystream_block();
            let plain_words = Self::xor_keystream_block_decrypt(block, &ks);
            self.update(plain_words);
            chunk.copy_from_slice(block);
        }

        let rem = chunks.into_remainder();
        if !rem.is_empty() {
            let ks = self.keystream_block();
            let plain_words = Self::xor_keystream_partial_decrypt(rem, &ks);
            self.update(plain_words);
        }
    }
}

impl Morus1280State {
    #[inline(always)]
    fn load_block32(block: &[u8]) -> [u64; 4] {
        debug_assert!(block.len() >= 32);
        // SAFETY: debug_assert guarantees block.len() >= 32. ptr::read_unaligned
        // does not require alignment. Offsets 0, 8, 16, 24 are all within the
        // 32-byte slice, so all four 8-byte reads are in-bounds.
        unsafe {
            [
                u64::from_le(ptr::read_unaligned(block.as_ptr() as *const u64)),
                u64::from_le(ptr::read_unaligned(block.as_ptr().add(8) as *const u64)),
                u64::from_le(ptr::read_unaligned(block.as_ptr().add(16) as *const u64)),
                u64::from_le(ptr::read_unaligned(block.as_ptr().add(24) as *const u64)),
            ]
        }
    }

    #[cfg(all(target_arch = "aarch64", target_feature = "neon"))]
    #[inline(always)]
    // SAFETY: compile-time neon gate. `block` is &[u8; 32] providing 32 readable
    // bytes. vld1q_u8 reads 16 bytes at offsets 0 and 16, both within bounds.
    // `out` is [u64; 4] (32 bytes); vst1q_u64 writes 16 bytes at offsets 0 and 16.
    unsafe fn load_block32_neon(block: &[u8; 32]) -> [u64; 4] {
        use std::arch::aarch64::*;
        let v0 = vld1q_u8(block.as_ptr());
        let v1 = vld1q_u8(block.as_ptr().add(16));
        let mut out = [0u64; 4];
        vst1q_u64(out.as_mut_ptr(), vreinterpretq_u64_u8(v0));
        vst1q_u64(out.as_mut_ptr().add(2), vreinterpretq_u64_u8(v1));
        out
    }

    #[cfg(all(target_arch = "aarch64", target_feature = "neon"))]
    #[inline(always)]
    // SAFETY: compile-time neon gate. `self.s` is [[u64;4];5]; vld1q_u64_x2 reads
    // 32 bytes per row, within the 32-byte row bounds. `out` is stack-owned [u64;4].
    unsafe fn keystream_block_neon(&self) -> [u64; 4] {
        use std::arch::aarch64::*;
        let s0_pair = vld1q_u64_x2(self.s[0].as_ptr());
        let s1_pair = vld1q_u64_x2(self.s[1].as_ptr());
        let s2_pair = vld1q_u64_x2(self.s[2].as_ptr());
        let s3_pair = vld1q_u64_x2(self.s[3].as_ptr());
        let (s1r_lo, s1r_hi) = Self::rot_words_pair_neon(s1_pair.0, s1_pair.1, 3);
        let t0 = veorq_u64(veorq_u64(s0_pair.0, s1r_lo), vandq_u64(s2_pair.0, s3_pair.0));
        let t1 = veorq_u64(veorq_u64(s0_pair.1, s1r_hi), vandq_u64(s2_pair.1, s3_pair.1));
        let mut out = [0u64; 4];
        vst1q_u64(out.as_mut_ptr(), t0);
        vst1q_u64(out.as_mut_ptr().add(2), t1);
        out
    }

    #[inline(always)]
    fn zero_tail(words: &mut [u64; 4], valid_bytes: usize) {
        if valid_bytes >= 32 {
            return;
        }
        let full_words = valid_bytes / 8;
        let tail_bytes = valid_bytes % 8;
        for (idx, w) in words.iter_mut().enumerate().skip(full_words) {
            if idx > full_words {
                *w = 0;
            } else {
                let mask = if tail_bytes == 0 { 0 } else { (1u64 << (tail_bytes * 8)) - 1 };
                *w &= mask;
            }
        }
    }

    #[inline(always)]
    fn xor_keystream_block_encrypt(block: &mut [u8; 32], keystream: &[u64; 4]) -> [u64; 4] {
        let mut plain = [0u64; 4];
        for i in 0..4 {
            let offset = i * 8;
            // SAFETY: `block` is &mut [u8; 32]; offset is 0/8/16/24, so offset+8 <= 32.
            // read_unaligned does not require alignment. Read is within bounds.
            let word = unsafe {
                u64::from_le(ptr::read_unaligned(block.as_ptr().add(offset) as *const u64))
            };
            plain[i] = word;
            let cipher = word ^ keystream[i];
            // SAFETY: same bounds reasoning - offset+8 <= 32, write_unaligned is safe
            // for any alignment. block is exclusively borrowed (&mut).
            unsafe {
                ptr::write_unaligned(block.as_mut_ptr().add(offset) as *mut u64, cipher.to_le());
            }
        }
        plain
    }

    #[inline(always)]
    fn xor_keystream_block_decrypt(block: &mut [u8; 32], keystream: &[u64; 4]) -> [u64; 4] {
        let mut plain = [0u64; 4];
        for i in 0..4 {
            let offset = i * 8;
            // SAFETY: `block` is &mut [u8; 32]; offset is 0/8/16/24, so offset+8 <= 32.
            // read_unaligned does not require alignment. Read is within bounds.
            let cipher = unsafe {
                u64::from_le(ptr::read_unaligned(block.as_ptr().add(offset) as *const u64))
            };
            let word = cipher ^ keystream[i];
            plain[i] = word;
            // SAFETY: same bounds reasoning - offset+8 <= 32, write_unaligned safe
            // for any alignment. block is exclusively borrowed.
            unsafe {
                ptr::write_unaligned(block.as_mut_ptr().add(offset) as *mut u64, word.to_le());
            }
        }
        plain
    }

    #[inline(always)]
    fn xor_keystream_partial_encrypt(block: &mut [u8], keystream: &[u64; 4]) -> [u64; 4] {
        let mut buf = [0u8; 32];
        buf[..block.len()].copy_from_slice(block);
        let mut plain = Self::xor_keystream_block_encrypt(&mut buf, keystream);
        block.copy_from_slice(&buf[..block.len()]);
        Self::zero_tail(&mut plain, block.len());
        plain
    }

    #[inline(always)]
    fn xor_keystream_partial_decrypt(block: &mut [u8], keystream: &[u64; 4]) -> [u64; 4] {
        let mut buf = [0u8; 32];
        buf[..block.len()].copy_from_slice(block);
        let mut plain = Self::xor_keystream_block_decrypt(&mut buf, keystream);
        block.copy_from_slice(&buf[..block.len()]);
        Self::zero_tail(&mut plain, block.len());
        plain
    }

    #[cfg(target_arch = "x86_64")]
    #[inline]
    #[target_feature(enable = "sse2")]
    // SAFETY: target_feature gate ensures SSE2. `block` is &mut [u8; 32] (32 bytes);
    // cast to *mut __m128i for two 16-byte loads/stores at offsets 0 and 1, both
    // within bounds. `keystream` is &[u64; 4] (32 bytes), same layout. `plain` is
    // stack-owned [u64; 4]. Unaligned ops (_mm_loadu/_mm_storeu) handle any alignment.
    unsafe fn xor_keystream_block_encrypt_sse(
        block: &mut [u8; 32],
        keystream: &[u64; 4],
    ) -> [u64; 4] {
        use core::arch::x86_64::*;
        let mut plain = [0u64; 4];
        let ptr = block.as_mut_ptr() as *mut __m128i;
        let b0 = _mm_loadu_si128(ptr);
        let b1 = _mm_loadu_si128(ptr.add(1));
        _mm_storeu_si128(plain.as_mut_ptr() as *mut __m128i, b0);
        _mm_storeu_si128(plain.as_mut_ptr().add(2) as *mut __m128i, b1);
        let ks_ptr = keystream.as_ptr() as *const __m128i;
        let ks_lo = _mm_loadu_si128(ks_ptr);
        let ks_hi = _mm_loadu_si128(ks_ptr.add(1));
        let c0 = _mm_xor_si128(b0, ks_lo);
        let c1 = _mm_xor_si128(b1, ks_hi);
        _mm_storeu_si128(ptr, c0);
        _mm_storeu_si128(ptr.add(1), c1);
        plain
    }

    #[cfg(target_arch = "x86_64")]
    #[inline]
    #[target_feature(enable = "sse2")]
    // SAFETY: target_feature gate ensures SSE2. Same invariants as
    // xor_keystream_block_encrypt_sse: `block` is &mut [u8; 32], `keystream` is
    // &[u64; 4], both 32 bytes. All loads/stores use unaligned intrinsics within bounds.
    unsafe fn xor_keystream_block_decrypt_sse(
        block: &mut [u8; 32],
        keystream: &[u64; 4],
    ) -> [u64; 4] {
        use core::arch::x86_64::*;
        let mut plain = [0u64; 4];
        let ptr = block.as_mut_ptr() as *mut __m128i;
        let c0 = _mm_loadu_si128(ptr);
        let c1 = _mm_loadu_si128(ptr.add(1));
        let ks_ptr = keystream.as_ptr() as *const __m128i;
        let ks_lo = _mm_loadu_si128(ks_ptr);
        let ks_hi = _mm_loadu_si128(ks_ptr.add(1));
        let p0 = _mm_xor_si128(c0, ks_lo);
        let p1 = _mm_xor_si128(c1, ks_hi);
        _mm_storeu_si128(ptr, p0);
        _mm_storeu_si128(ptr.add(1), p1);
        _mm_storeu_si128(plain.as_mut_ptr() as *mut __m128i, p0);
        _mm_storeu_si128(plain.as_mut_ptr().add(2) as *mut __m128i, p1);
        plain
    }

    #[cfg(all(target_arch = "aarch64", target_feature = "neon"))]
    #[inline(always)]
    // SAFETY: compile-time neon gate. `block` is &mut [u8; 32]; vld1q_u8 reads 16
    // bytes at offsets 0 and 16, within bounds. `keystream` is &[u64; 4] (32 bytes);
    // vld1q_u64 reads 16 bytes at offsets 0 and 16. `plain` is stack-owned [u64; 4].
    // vst1q writes stay within bounds of their respective target arrays.
    unsafe fn xor_keystream_block_encrypt_neon(
        block: &mut [u8; 32],
        keystream: &[u64; 4],
    ) -> [u64; 4] {
        use std::arch::aarch64::*;
        let mut plain = [0u64; 4];
        let p0 = vld1q_u8(block.as_ptr());
        let p1 = vld1q_u8(block.as_ptr().add(16));
        vst1q_u64(plain.as_mut_ptr(), vreinterpretq_u64_u8(p0));
        vst1q_u64(plain.as_mut_ptr().add(2), vreinterpretq_u64_u8(p1));
        let ks0 = vld1q_u64(keystream.as_ptr());
        let ks1 = vld1q_u64(keystream.as_ptr().add(2));
        let c0 = veorq_u8(p0, vreinterpretq_u8_u64(ks0));
        let c1 = veorq_u8(p1, vreinterpretq_u8_u64(ks1));
        vst1q_u8(block.as_mut_ptr(), c0);
        vst1q_u8(block.as_mut_ptr().add(16), c1);
        plain
    }

    #[cfg(all(target_arch = "aarch64", target_feature = "neon"))]
    #[inline(always)]
    // SAFETY: compile-time neon gate. Same invariants as
    // xor_keystream_block_encrypt_neon: `block` is &mut [u8; 32], `keystream` is
    // &[u64; 4]. All NEON loads/stores stay within the 32-byte bounds of each array.
    unsafe fn xor_keystream_block_decrypt_neon(
        block: &mut [u8; 32],
        keystream: &[u64; 4],
    ) -> [u64; 4] {
        use std::arch::aarch64::*;
        let mut plain = [0u64; 4];
        let c0 = vld1q_u8(block.as_ptr());
        let c1 = vld1q_u8(block.as_ptr().add(16));
        let ks0 = vld1q_u64(keystream.as_ptr());
        let ks1 = vld1q_u64(keystream.as_ptr().add(2));
        let p0 = veorq_u8(c0, vreinterpretq_u8_u64(ks0));
        let p1 = veorq_u8(c1, vreinterpretq_u8_u64(ks1));
        vst1q_u8(block.as_mut_ptr(), p0);
        vst1q_u8(block.as_mut_ptr().add(16), p1);
        vst1q_u64(plain.as_mut_ptr(), vreinterpretq_u64_u8(p0));
        vst1q_u64(plain.as_mut_ptr().add(2), vreinterpretq_u64_u8(p1));
        plain
    }
}

/// MORUS-1280-128 AEAD cipher with SIMD-dispatched state updates.
#[derive(Clone)]
pub struct MorusAead {
    key: [u8; 16],
    iv: [u8; 12],
}

impl Drop for MorusAead {
    fn drop(&mut self) {
        self.key.zeroize();
        self.iv.zeroize();
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MorusBackend {
    #[cfg(target_arch = "x86_64")]
    Sse42,
    #[cfg(target_arch = "x86_64")]
    Sse41,
    #[cfg(target_arch = "x86_64")]
    Ssse3,
    #[cfg(target_arch = "x86_64")]
    Sse2,
    #[cfg(target_arch = "aarch64")]
    Neon,
    Scalar,
}

static MORUS_BACKEND: OnceLock<MorusBackend> = OnceLock::new();

fn morus_backend() -> MorusBackend {
    *MORUS_BACKEND.get_or_init(|| {
        let det = crate::optimize::FeatureDetector::instance();

        #[cfg(target_arch = "x86_64")]
        {
            use crate::optimize::CpuFeature;
            let has_sse42 = det.has_feature(CpuFeature::SSE42);
            let has_sse41 = det.has_feature(CpuFeature::SSE41) || has_sse42;
            if has_sse42 && det.has_feature(CpuFeature::SSSE3) {
                return MorusBackend::Sse42;
            }
            if has_sse41 && det.has_feature(CpuFeature::SSSE3) {
                return MorusBackend::Sse41;
            }
            if det.has_feature(CpuFeature::SSSE3) {
                return MorusBackend::Ssse3;
            }
            if det.has_feature(CpuFeature::SSE2) {
                return MorusBackend::Sse2;
            }
            return MorusBackend::Scalar;
        }

        #[cfg(target_arch = "aarch64")]
        {
            if det.has_feature(crate::optimize::CpuFeature::NEON) {
                MorusBackend::Neon
            } else {
                MorusBackend::Scalar
            }
        }

        #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
        {
            MorusBackend::Scalar
        }
    })
}

/// AEAD authentication error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AeadError {
    /// Authentication tag did not match during decryption.
    TagMismatch,
}

impl MorusAead {
    /// Create a new MORUS-1280-128 instance from a 16-byte key and 12-byte IV.
    pub fn new(aead_key: &[u8], iv: &[u8]) -> Result<Self, KeyMaterialError> {
        require_exact_key_iv("MORUS-1280-128", aead_key, 16, iv, 12)?;
        let mut key = [0u8; 16];
        key.copy_from_slice(aead_key);
        let mut iv_array = [0u8; 12];
        iv_array.copy_from_slice(iv);
        Ok(Self::from_arrays(&key, &iv_array))
    }

    pub(crate) fn from_arrays(aead_key: &[u8; 16], iv: &[u8; 12]) -> Self {
        Self { key: *aead_key, iv: *iv }
    }

    #[cfg(test)]
    fn encrypt_native(&self, plaintext: &[u8], ad: &[u8], nonce: &[u8; 16]) -> (Vec<u8>, [u8; 16]) {
        crate::optimize::telemetry::MORUS1280_SCALAR_OPS.inc();
        let mut state = Morus1280State::init(&self.key, nonce);
        state.process_ad(ad);

        let mut ciphertext = plaintext.to_vec();
        state.encrypt(&mut ciphertext);

        let tag = state.finalize(ad.len(), plaintext.len());
        (ciphertext, tag)
    }

    /// Encrypt `buffer` in place with associated data; returns the 16-byte authentication tag.
    pub fn encrypt_in_place(&self, buffer: &mut [u8], ad: &[u8], nonce: &[u8; 16]) -> [u8; 16] {
        crate::optimize::telemetry::MORUS1280_SCALAR_OPS.inc();
        let mut state = Morus1280State::init(&self.key, nonce);
        state.process_ad(ad);
        state.encrypt(buffer);
        state.finalize(ad.len(), buffer.len())
    }

    #[cfg(test)]
    fn decrypt_native(
        &self,
        ciphertext: &[u8],
        tag: &[u8; 16],
        ad: &[u8],
        nonce: &[u8; 16],
    ) -> Result<Vec<u8>, ()> {
        crate::optimize::telemetry::MORUS1280_SCALAR_OPS.inc();
        let mut state = Morus1280State::init(&self.key, nonce);
        state.process_ad(ad);

        let mut plaintext = ciphertext.to_vec();
        state.decrypt(&mut plaintext);

        let computed_tag = state.finalize(ad.len(), ciphertext.len());

        if super::subtle_ct_eq(&computed_tag, tag) {
            Ok(plaintext)
        } else {
            Err(())
        }
    }

    /// Decrypt `buffer` in place with associated data and verify the tag.
    pub fn decrypt_in_place(
        &self,
        buffer: &mut [u8],
        tag: &[u8; 16],
        ad: &[u8],
        nonce: &[u8; 16],
    ) -> Result<(), AeadError> {
        crate::optimize::telemetry::MORUS1280_SCALAR_OPS.inc();
        let mut state = Morus1280State::init(&self.key, nonce);
        state.process_ad(ad);
        state.decrypt(buffer);
        let computed_tag = state.finalize(ad.len(), buffer.len());

        if super::subtle_ct_eq(&computed_tag, tag) {
            Ok(())
        } else {
            Err(AeadError::TagMismatch)
        }
    }

    // Optimized methods with runtime CPU feature detection
    #[cfg(test)]
    fn encrypt_optimized(
        &self,
        plaintext: &[u8],
        ad: &[u8],
        nonce: &[u8; 16],
    ) -> (Vec<u8>, [u8; 16]) {
        let mut out = plaintext.to_vec();
        let tag = self.encrypt_in_place_optimized(&mut out, ad, nonce);
        (out, tag)
    }

    #[cfg(test)]
    fn decrypt_optimized(
        &self,
        ciphertext: &[u8],
        tag: &[u8; 16],
        ad: &[u8],
        nonce: &[u8; 16],
    ) -> Result<Vec<u8>, ()> {
        let mut out = ciphertext.to_vec();
        self.decrypt_in_place_optimized(&mut out, tag, ad, nonce).map_err(|_| ())?;
        Ok(out)
    }

    fn encrypt_in_place_optimized(
        &self,
        buffer: &mut [u8],
        ad: &[u8],
        nonce: &[u8; 16],
    ) -> [u8; 16] {
        match morus_backend() {
            #[cfg(target_arch = "x86_64")]
            MorusBackend::Sse42 => {
                if let Some(tag) =
                    unsafe { self.encrypt_morus1280_sse42_inplace(buffer, ad, nonce) }
                {
                    return tag;
                }
            }
            #[cfg(target_arch = "x86_64")]
            MorusBackend::Sse41 => {
                if let Some(tag) = self.encrypt_morus1280_sse41_inplace(buffer, ad, nonce) {
                    return tag;
                }
            }
            #[cfg(target_arch = "x86_64")]
            MorusBackend::Ssse3 => {
                if let Some(tag) = self.encrypt_morus1280_ssse3_inplace(buffer, ad, nonce) {
                    return tag;
                }
            }
            #[cfg(target_arch = "x86_64")]
            MorusBackend::Sse2 => {
                if let Some(tag) = unsafe { self.encrypt_morus1280_sse2_inplace(buffer, ad, nonce) }
                {
                    return tag;
                }
            }
            #[cfg(target_arch = "aarch64")]
            MorusBackend::Neon => {
                if let Some(tag) = self.encrypt_morus1280_neon_inplace(buffer, ad, nonce) {
                    return tag;
                }
            }
            MorusBackend::Scalar => {}
        }
        self.encrypt_in_place(buffer, ad, nonce)
    }

    fn decrypt_in_place_optimized(
        &self,
        buffer: &mut [u8],
        tag: &[u8; 16],
        ad: &[u8],
        nonce: &[u8; 16],
    ) -> Result<(), AeadError> {
        match morus_backend() {
            #[cfg(target_arch = "x86_64")]
            MorusBackend::Sse42 => {
                if let Some(res) =
                    unsafe { self.decrypt_morus1280_sse42_inplace(buffer, tag, ad, nonce) }
                {
                    return res.map_err(|_| AeadError::TagMismatch);
                }
            }
            #[cfg(target_arch = "x86_64")]
            MorusBackend::Sse41 => {
                if let Some(res) = self.decrypt_morus1280_sse41_inplace(buffer, tag, ad, nonce) {
                    return res.map_err(|_| AeadError::TagMismatch);
                }
            }
            #[cfg(target_arch = "x86_64")]
            MorusBackend::Ssse3 => {
                if let Some(res) = self.decrypt_morus1280_ssse3_inplace(buffer, tag, ad, nonce) {
                    return res.map_err(|_| AeadError::TagMismatch);
                }
            }
            #[cfg(target_arch = "x86_64")]
            MorusBackend::Sse2 => {
                if let Some(res) =
                    unsafe { self.decrypt_morus1280_sse2_inplace(buffer, tag, ad, nonce) }
                {
                    return res.map_err(|_| AeadError::TagMismatch);
                }
            }
            #[cfg(target_arch = "aarch64")]
            MorusBackend::Neon => {
                if let Some(res) = self.decrypt_morus1280_neon_inplace(buffer, tag, ad, nonce) {
                    return res.map_err(|_| AeadError::TagMismatch);
                }
            }
            MorusBackend::Scalar => {}
        }
        self.decrypt_in_place(buffer, tag, ad, nonce)
    }

    // SSSE3-boosted MORUS-1280-128 (vectorized XOR/load/store with byte-align shuffles)
    #[cfg(target_arch = "x86_64")]
    fn encrypt_morus1280_ssse3_inplace(
        &self,
        buffer: &mut [u8],
        ad: &[u8],
        nonce: &[u8; 16],
    ) -> Option<[u8; 16]> {
        unsafe { Some(self.encrypt_morus1280_ssse3_inner(buffer, ad, nonce)) }
    }

    #[cfg(target_arch = "x86_64")]
    #[target_feature(enable = "ssse3")]
    unsafe fn encrypt_morus1280_ssse3_inner(
        &self,
        buffer: &mut [u8],
        ad: &[u8],
        nonce: &[u8; 16],
    ) -> [u8; 16] {
        crate::optimize::telemetry::MORUS1280_SSSE3_OPS.inc();
        let mut state = Morus1280State::init(&self.key, nonce);
        state.process_ad(ad);

        {
            let mut chunks = buffer.chunks_exact_mut(32);
            for chunk in &mut chunks {
                let block: &mut [u8; 32] = chunk.try_into().unwrap();
                let ks = state.keystream_block();
                let plain_words =
                    unsafe { Morus1280State::xor_keystream_block_encrypt_sse(block, &ks) };
                state.update_simd_ssse3(plain_words);
            }

            let rem = chunks.into_remainder();
            if !rem.is_empty() {
                let ks = state.keystream_block();
                let plain_words = Morus1280State::xor_keystream_partial_encrypt(rem, &ks);
                state.update_simd_ssse3(plain_words);
            }
        }

        state.finalize(ad.len(), buffer.len())
    }

    #[cfg(target_arch = "x86_64")]
    fn decrypt_morus1280_ssse3_inplace(
        &self,
        buffer: &mut [u8],
        tag: &[u8; 16],
        ad: &[u8],
        nonce: &[u8; 16],
    ) -> Option<Result<(), ()>> {
        unsafe { Some(self.decrypt_morus1280_ssse3_inner(buffer, tag, ad, nonce)) }
    }

    #[cfg(target_arch = "x86_64")]
    #[target_feature(enable = "ssse3")]
    unsafe fn decrypt_morus1280_ssse3_inner(
        &self,
        buffer: &mut [u8],
        tag: &[u8; 16],
        ad: &[u8],
        nonce: &[u8; 16],
    ) -> Result<(), ()> {
        crate::optimize::telemetry::MORUS1280_SSSE3_OPS.inc();
        let mut state = Morus1280State::init(&self.key, nonce);
        state.process_ad(ad);

        {
            let mut chunks = buffer.chunks_exact_mut(32);
            for chunk in &mut chunks {
                let block: &mut [u8; 32] = chunk.try_into().unwrap();
                let ks = state.keystream_block();
                let plain_words =
                    unsafe { Morus1280State::xor_keystream_block_decrypt_sse(block, &ks) };
                state.update_simd_ssse3(plain_words);
            }

            let rem = chunks.into_remainder();
            if !rem.is_empty() {
                let ks = state.keystream_block();
                let plain_words = Morus1280State::xor_keystream_partial_decrypt(rem, &ks);
                state.update_simd_ssse3(plain_words);
            }
        }

        let computed_tag = state.finalize(ad.len(), buffer.len());
        if super::subtle_ct_eq(&computed_tag, tag) {
            Ok(())
        } else {
            Err(())
        }
    }

    #[cfg(target_arch = "x86_64")]
    fn encrypt_morus1280_sse41_inplace(
        &self,
        buffer: &mut [u8],
        ad: &[u8],
        nonce: &[u8; 16],
    ) -> Option<[u8; 16]> {
        crate::optimize::telemetry::MORUS1280_SSE41_OPS.inc();
        unsafe { Some(self.encrypt_morus1280_sse41_inner(buffer, ad, nonce)) }
    }

    #[cfg(target_arch = "x86_64")]
    #[target_feature(enable = "ssse3,sse4.1")]
    unsafe fn encrypt_morus1280_sse41_inner(
        &self,
        buffer: &mut [u8],
        ad: &[u8],
        nonce: &[u8; 16],
    ) -> [u8; 16] {
        let mut state = Morus1280State::init(&self.key, nonce);
        state.process_ad(ad);

        {
            let mut chunks = buffer.chunks_exact_mut(32);
            for chunk in &mut chunks {
                let block: &mut [u8; 32] = chunk.try_into().unwrap();
                let ks = state.keystream_block();
                let plain_words = Morus1280State::xor_keystream_block_encrypt_sse(block, &ks);
                state.update_simd_sse41(plain_words);
            }

            let rem = chunks.into_remainder();
            if !rem.is_empty() {
                let ks = state.keystream_block();
                let plain_words = Morus1280State::xor_keystream_partial_encrypt(rem, &ks);
                state.update_simd_sse41(plain_words);
            }
        }

        state.finalize(ad.len(), buffer.len())
    }

    #[cfg(target_arch = "x86_64")]
    fn decrypt_morus1280_sse41_inplace(
        &self,
        buffer: &mut [u8],
        tag: &[u8; 16],
        ad: &[u8],
        nonce: &[u8; 16],
    ) -> Option<Result<(), ()>> {
        crate::optimize::telemetry::MORUS1280_SSE41_OPS.inc();
        unsafe { Some(self.decrypt_morus1280_sse41_inner(buffer, tag, ad, nonce)) }
    }

    #[cfg(target_arch = "x86_64")]
    #[target_feature(enable = "ssse3,sse4.1")]
    unsafe fn decrypt_morus1280_sse41_inner(
        &self,
        buffer: &mut [u8],
        tag: &[u8; 16],
        ad: &[u8],
        nonce: &[u8; 16],
    ) -> Result<(), ()> {
        let mut state = Morus1280State::init(&self.key, nonce);
        state.process_ad(ad);

        {
            let mut chunks = buffer.chunks_exact_mut(32);
            for chunk in &mut chunks {
                let block: &mut [u8; 32] = chunk.try_into().unwrap();
                let ks = state.keystream_block();
                let plain_words = Morus1280State::xor_keystream_block_decrypt_sse(block, &ks);
                state.update_simd_sse41(plain_words);
            }

            let rem = chunks.into_remainder();
            if !rem.is_empty() {
                let ks = state.keystream_block();
                let plain_words = Morus1280State::xor_keystream_partial_decrypt(rem, &ks);
                state.update_simd_sse41(plain_words);
            }
        }

        let computed_tag = state.finalize(ad.len(), buffer.len());
        if super::subtle_ct_eq(&computed_tag, tag) {
            Ok(())
        } else {
            Err(())
        }
    }

    #[cfg(target_arch = "x86_64")]
    unsafe fn encrypt_morus1280_sse42_inplace(
        &self,
        buffer: &mut [u8],
        ad: &[u8],
        nonce: &[u8; 16],
    ) -> Option<[u8; 16]> {
        crate::optimize::telemetry::MORUS1280_SSE42_OPS.inc();
        Some(self.encrypt_morus1280_sse42_inner(buffer, ad, nonce))
    }

    #[cfg(target_arch = "x86_64")]
    #[target_feature(enable = "ssse3,sse4.1,sse4.2")]
    unsafe fn encrypt_morus1280_sse42_inner(
        &self,
        buffer: &mut [u8],
        ad: &[u8],
        nonce: &[u8; 16],
    ) -> [u8; 16] {
        let mut state = Morus1280State::init(&self.key, nonce);
        state.process_ad(ad);

        {
            let mut chunks = buffer.chunks_exact_mut(32);
            for chunk in &mut chunks {
                let block: &mut [u8; 32] = chunk.try_into().unwrap();
                let ks = state.keystream_block();
                let plain_words = Morus1280State::xor_keystream_block_encrypt_sse(block, &ks);
                state.update_simd_sse42(plain_words);
            }

            let rem = chunks.into_remainder();
            if !rem.is_empty() {
                let ks = state.keystream_block();
                let plain_words = Morus1280State::xor_keystream_partial_encrypt(rem, &ks);
                state.update_simd_sse42(plain_words);
            }
        }

        state.finalize(ad.len(), buffer.len())
    }

    #[cfg(target_arch = "x86_64")]
    unsafe fn decrypt_morus1280_sse42_inplace(
        &self,
        buffer: &mut [u8],
        tag: &[u8; 16],
        ad: &[u8],
        nonce: &[u8; 16],
    ) -> Option<Result<(), ()>> {
        crate::optimize::telemetry::MORUS1280_SSE42_OPS.inc();
        Some(self.decrypt_morus1280_sse42_inner(buffer, tag, ad, nonce))
    }

    #[cfg(target_arch = "x86_64")]
    #[target_feature(enable = "ssse3,sse4.1,sse4.2")]
    unsafe fn decrypt_morus1280_sse42_inner(
        &self,
        buffer: &mut [u8],
        tag: &[u8; 16],
        ad: &[u8],
        nonce: &[u8; 16],
    ) -> Result<(), ()> {
        let mut state = Morus1280State::init(&self.key, nonce);
        state.process_ad(ad);

        {
            let mut chunks = buffer.chunks_exact_mut(32);
            for chunk in &mut chunks {
                let block: &mut [u8; 32] = chunk.try_into().unwrap();
                let ks = state.keystream_block();
                let plain_words = Morus1280State::xor_keystream_block_decrypt_sse(block, &ks);
                state.update_simd_sse42(plain_words);
            }

            let rem = chunks.into_remainder();
            if !rem.is_empty() {
                let ks = state.keystream_block();
                let plain_words = Morus1280State::xor_keystream_partial_decrypt(rem, &ks);
                state.update_simd_sse42(plain_words);
            }
        }

        let computed_tag = state.finalize(ad.len(), buffer.len());
        if super::subtle_ct_eq(&computed_tag, tag) {
            Ok(())
        } else {
            Err(())
        }
    }

    #[cfg(target_arch = "x86_64")]
    #[target_feature(enable = "sse2")]
    unsafe fn encrypt_morus1280_sse2_inplace(
        &self,
        buffer: &mut [u8],
        ad: &[u8],
        nonce: &[u8; 16],
    ) -> Option<[u8; 16]> {
        crate::optimize::telemetry::MORUS1280_SSE2_OPS.inc();
        let mut state = Morus1280State::init(&self.key, nonce);
        state.process_ad(ad);

        {
            let mut chunks = buffer.chunks_exact_mut(32);
            for chunk in &mut chunks {
                let block: &mut [u8; 32] = chunk.try_into().unwrap();
                let ks = state.keystream_block();
                let plain_words = Morus1280State::xor_keystream_block_encrypt_sse(block, &ks);
                state.update_simd_sse2(plain_words);
            }

            let rem = chunks.into_remainder();
            if !rem.is_empty() {
                let ks = state.keystream_block();
                let plain_words = Morus1280State::xor_keystream_partial_encrypt(rem, &ks);
                state.update_simd_sse2(plain_words);
            }
        }

        Some(state.finalize(ad.len(), buffer.len()))
    }

    #[cfg(target_arch = "x86_64")]
    #[target_feature(enable = "sse2")]
    unsafe fn decrypt_morus1280_sse2_inplace(
        &self,
        buffer: &mut [u8],
        tag: &[u8; 16],
        ad: &[u8],
        nonce: &[u8; 16],
    ) -> Option<Result<(), ()>> {
        crate::optimize::telemetry::MORUS1280_SSE2_OPS.inc();
        let mut state = Morus1280State::init(&self.key, nonce);
        state.process_ad(ad);

        {
            let mut chunks = buffer.chunks_exact_mut(32);
            for chunk in &mut chunks {
                let block: &mut [u8; 32] = chunk.try_into().unwrap();
                let ks = state.keystream_block();
                let plain_words = Morus1280State::xor_keystream_block_decrypt_sse(block, &ks);
                state.update_simd_sse2(plain_words);
            }

            let rem = chunks.into_remainder();
            if !rem.is_empty() {
                let ks = state.keystream_block();
                let plain_words = Morus1280State::xor_keystream_partial_decrypt(rem, &ks);
                state.update_simd_sse2(plain_words);
            }
        }

        let computed_tag = state.finalize(ad.len(), buffer.len());
        if super::subtle_ct_eq(&computed_tag, tag) {
            Some(Ok(()))
        } else {
            Some(Err(()))
        }
    }

    #[cfg(all(target_arch = "aarch64", target_feature = "neon"))]
    fn encrypt_morus1280_neon_inplace(
        &self,
        buffer: &mut [u8],
        ad: &[u8],
        nonce: &[u8; 16],
    ) -> Option<[u8; 16]> {
        crate::optimize::telemetry::MORUS1280_NEON_OPS.inc();
        let mut state = Morus1280State::init(&self.key, nonce);
        state.process_ad(ad);

        {
            let mut chunks = buffer.chunks_exact_mut(32);
            for chunk in &mut chunks {
                let mut tmp = [0u8; 32];
                tmp.copy_from_slice(chunk);
                let block: &mut [u8; 32] = &mut tmp;
                let ks = state.keystream_block();
                let plain_words =
                    unsafe { Morus1280State::xor_keystream_block_encrypt_neon(block, &ks) };
                state.update(plain_words);
                chunk.copy_from_slice(block);
            }

            let rem = chunks.into_remainder();
            if !rem.is_empty() {
                let ks = state.keystream_block();
                let plain_words = Morus1280State::xor_keystream_partial_encrypt(rem, &ks);
                state.update(plain_words);
            }
        }

        Some(state.finalize(ad.len(), buffer.len()))
    }

    #[cfg(all(target_arch = "aarch64", not(target_feature = "neon")))]
    fn encrypt_morus1280_neon_inplace(
        &self,
        buffer: &mut [u8],
        ad: &[u8],
        nonce: &[u8; 16],
    ) -> Option<[u8; 16]> {
        let _ = (buffer, ad, nonce);
        None
    }

    #[cfg(all(target_arch = "aarch64", target_feature = "neon"))]
    fn decrypt_morus1280_neon_inplace(
        &self,
        buffer: &mut [u8],
        tag: &[u8; 16],
        ad: &[u8],
        nonce: &[u8; 16],
    ) -> Option<Result<(), ()>> {
        crate::optimize::telemetry::MORUS1280_NEON_OPS.inc();
        let mut state = Morus1280State::init(&self.key, nonce);
        state.process_ad(ad);

        {
            let mut chunks = buffer.chunks_exact_mut(32);
            for chunk in &mut chunks {
                let mut tmp = [0u8; 32];
                tmp.copy_from_slice(chunk);
                let block: &mut [u8; 32] = &mut tmp;
                let ks = state.keystream_block();
                let plain_words =
                    unsafe { Morus1280State::xor_keystream_block_decrypt_neon(block, &ks) };
                state.update(plain_words);
                chunk.copy_from_slice(block);
            }

            let rem = chunks.into_remainder();
            if !rem.is_empty() {
                let ks = state.keystream_block();
                let plain_words = Morus1280State::xor_keystream_partial_decrypt(rem, &ks);
                state.update(plain_words);
            }
        }

        let computed_tag = state.finalize(ad.len(), buffer.len());
        if super::subtle_ct_eq(&computed_tag, tag) {
            Some(Ok(()))
        } else {
            Some(Err(()))
        }
    }

    #[cfg(all(target_arch = "aarch64", not(target_feature = "neon")))]
    fn decrypt_morus1280_neon_inplace(
        &self,
        buffer: &mut [u8],
        tag: &[u8; 16],
        ad: &[u8],
        nonce: &[u8; 16],
    ) -> Option<Result<(), ()>> {
        let _ = (buffer, tag, ad, nonce);
        None
    }
}

// Implement AeadSeal and AeadOpen for MorusAead
impl AeadSeal for MorusAead {
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
        #[cfg(all(target_arch = "x86_64", target_feature = "sse2"))]
        super::prefetch_morus_buffer(pt.as_ptr(), len);
        let nonce16 = super::make_nonce16(&self.iv, counter);
        let tag = self.encrypt_in_place_optimized(pt, ad, &nonce16);
        rest[..16].copy_from_slice(&tag);
        Ok(len + 16)
    }
}

impl AeadOpen for MorusAead {
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
        #[cfg(all(target_arch = "x86_64", target_feature = "sse2"))]
        super::prefetch_morus_buffer(ct.as_ptr(), ct_len);
        let mut tag = [0u8; 16];
        tag.copy_from_slice(&tag_in[..16]);
        let nonce16 = super::make_nonce16(&self.iv, counter);
        self.decrypt_in_place_optimized(ct, &tag, ad, &nonce16)
            .map_err(|_| ConnectionError::CryptoError("crypto failure".into()))?;
        Ok(ct_len)
    }
}

#[cfg(test)]
mod morus_tests {
    use super::*;

    #[test]
    fn test_morus_roundtrip_empty() {
        let key = [0u8; 16];
        let iv = [0u8; 12];
        let nonce = [0u8; 16];
        let plaintext = b"";
        let ad = b"";

        let morus = MorusAead::from_arrays(&key, &iv);
        let (ciphertext, tag) = morus.encrypt_native(plaintext, ad, &nonce);
        let decrypted = morus.decrypt_native(&ciphertext, &tag, ad, &nonce).unwrap();

        assert_eq!(plaintext, &decrypted[..]);
    }

    #[test]
    fn test_morus_roundtrip_1_byte() {
        let key = [1u8; 16];
        let iv = [2u8; 12];
        let nonce = [3u8; 16];
        let plaintext = b"A";
        let ad = b"associated";

        let morus = MorusAead::from_arrays(&key, &iv);
        let (ciphertext, tag) = morus.encrypt_native(plaintext, ad, &nonce);
        let decrypted = morus.decrypt_native(&ciphertext, &tag, ad, &nonce).unwrap();

        assert_eq!(plaintext, &decrypted[..]);
        assert_ne!(plaintext, &ciphertext[..]);
    }

    #[test]
    fn test_morus_roundtrip_16_bytes() {
        let key = [0x42u8; 16];
        let iv = [0x24u8; 12];
        let nonce = [0x13u8; 16];
        let plaintext = b"0123456789ABCDEF";
        let ad = b"additional_data";

        let morus = MorusAead::from_arrays(&key, &iv);
        let (ciphertext, tag) = morus.encrypt_native(plaintext, ad, &nonce);
        let decrypted = morus.decrypt_native(&ciphertext, &tag, ad, &nonce).unwrap();

        assert_eq!(plaintext, &decrypted[..]);
        assert_eq!(ciphertext.len(), plaintext.len());
    }

    #[test]
    fn test_morus_roundtrip_17_bytes() {
        let key = [0xAAu8; 16];
        let iv = [0x55u8; 12];
        let nonce = [0xCCu8; 16];
        let plaintext = b"0123456789ABCDEFG";
        let ad = b"";

        let morus = MorusAead::from_arrays(&key, &iv);
        let (ciphertext, tag) = morus.encrypt_native(plaintext, ad, &nonce);
        let decrypted = morus.decrypt_native(&ciphertext, &tag, ad, &nonce).unwrap();

        assert_eq!(plaintext, &decrypted[..]);
    }

    #[test]
    fn test_morus_roundtrip_32_bytes() {
        let key = [0xDEu8; 16];
        let iv = [0xADu8; 12];
        let nonce = [0xBEu8; 16];
        let plaintext = b"0123456789ABCDEF0123456789ABCDEF";
        let ad = b"long_associated_data_for_testing";

        let morus = MorusAead::from_arrays(&key, &iv);
        let (ciphertext, tag) = morus.encrypt_native(plaintext, ad, &nonce);
        let decrypted = morus.decrypt_native(&ciphertext, &tag, ad, &nonce).unwrap();

        assert_eq!(plaintext, &decrypted[..]);
    }

    #[test]
    fn test_morus_roundtrip_64_bytes() {
        let key = [0x11u8; 16];
        let iv = [0x22u8; 12];
        let nonce = [0x33u8; 16];
        let plaintext = b"0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF";
        let ad = b"associated_data_64_byte_boundary_test";

        let morus = MorusAead::from_arrays(&key, &iv);
        let (ciphertext, tag) = morus.encrypt_native(plaintext, ad, &nonce);
        let decrypted = morus.decrypt_native(&ciphertext, &tag, ad, &nonce).unwrap();

        assert_eq!(plaintext, &decrypted[..]);
    }

    #[test]
    fn test_morus_roundtrip_large() {
        let key = [0x77u8; 16];
        let iv = [0x88u8; 12];
        let nonce = [0x99u8; 16];
        let plaintext = vec![0x5Au8; 1337]; // Prime number for good measure
        let ad = b"large_buffer_test_with_simd_optimization";

        let morus = MorusAead::from_arrays(&key, &iv);
        let (ciphertext, tag) = morus.encrypt_optimized(&plaintext, ad, &nonce);
        let decrypted = morus.decrypt_optimized(&ciphertext, &tag, ad, &nonce).unwrap();

        assert_eq!(plaintext, decrypted);
        assert_eq!(ciphertext.len(), plaintext.len());
    }

    #[test]
    fn test_morus_authentication_failure() {
        let key = [0xFFu8; 16];
        let iv = [0x00u8; 12];
        let nonce = [0xF0u8; 16];
        let plaintext = b"secret_message";
        let ad = b"authenticated_data";

        let morus = MorusAead::from_arrays(&key, &iv);
        let (mut ciphertext, tag) = morus.encrypt_optimized(plaintext, ad, &nonce);

        // Corrupt ciphertext
        ciphertext[0] ^= 1;

        let result = morus.decrypt_optimized(&ciphertext, &tag, ad, &nonce);
        assert!(result.is_err());
    }

    #[test]
    fn test_morus_tag_verification_failure() {
        let key = [0x12u8; 16];
        let iv = [0x34u8; 12];
        let nonce = [0x56u8; 16];
        let plaintext = b"another_secret";
        let ad = b"more_auth_data";

        let morus = MorusAead::from_arrays(&key, &iv);
        let (ciphertext, mut tag) = morus.encrypt_optimized(plaintext, ad, &nonce);

        // Corrupt tag
        tag[0] ^= 1;

        let result = morus.decrypt_optimized(&ciphertext, &tag, ad, &nonce);
        assert!(result.is_err());
    }

    #[test]
    fn test_morus_different_keys() {
        let key1 = [0xABu8; 16];
        let key2 = [0xCDu8; 16];
        let iv = [0xEFu8; 12];
        let nonce = [0x01u8; 16];
        let plaintext = b"cross_key_test";
        let ad = b"";

        let morus1 = MorusAead::from_arrays(&key1, &iv);
        let morus2 = MorusAead::from_arrays(&key2, &iv);

        let (ciphertext, tag) = morus1.encrypt_optimized(plaintext, ad, &nonce);
        let result = morus2.decrypt_optimized(&ciphertext, &tag, ad, &nonce);

        assert!(result.is_err());
    }

    #[test]
    fn test_morus_simd_vs_scalar_consistency() {
        let key = [0x42u8; 16];
        let iv = [0x24u8; 12];
        let nonce = [0x13u8; 16];
        let plaintext = b"simd_scalar_consistency_test_with_longer_message_for_coverage";
        let ad = b"associated_data_for_consistency";

        let morus = MorusAead::from_arrays(&key, &iv);

        // Test that optimized path can decrypt its own output (self-consistency)
        let (ct_opt, tag_opt) = morus.encrypt_optimized(plaintext, ad, &nonce);
        let pt_opt = morus.decrypt_optimized(&ct_opt, &tag_opt, ad, &nonce).unwrap();
        assert_eq!(plaintext, &pt_opt[..]);

        // Test that native path can decrypt its own output (self-consistency)
        let (ct_native, tag_native) = morus.encrypt_native(plaintext, ad, &nonce);
        let pt_native = morus.decrypt_native(&ct_native, &tag_native, ad, &nonce).unwrap();
        assert_eq!(plaintext, &pt_native[..]);

        // Cross-compatibility must hold: optimized and native paths must interoperate.
        let pt_cross_native = morus.decrypt_native(&ct_opt, &tag_opt, ad, &nonce).unwrap();
        assert_eq!(plaintext, &pt_cross_native[..]);

        let pt_cross_opt = morus.decrypt_optimized(&ct_native, &tag_native, ad, &nonce).unwrap();
        assert_eq!(plaintext, &pt_cross_opt[..]);
    }

    #[test]
    fn test_morus_native_vs_optimized_matrix() {
        let key = [0x39u8; 16];
        let iv = [0x5Au8; 12];
        let lengths = [0usize, 1, 2, 15, 16, 17, 31, 32, 33, 63, 64, 65, 127, 128, 129, 255, 511];
        let ad_lengths = [0usize, 1, 7, 15, 16, 17, 31];

        for nonce_seed in 0u8..4 {
            let nonce = [nonce_seed.wrapping_mul(11).wrapping_add(7); 16];
            let morus = MorusAead::from_arrays(&key, &iv);

            for &ad_len in &ad_lengths {
                let mut ad = vec![0u8; ad_len];
                for (idx, byte) in ad.iter_mut().enumerate() {
                    *byte = nonce_seed.wrapping_mul(13).wrapping_add(idx as u8);
                }

                for &len in &lengths {
                    let mut plaintext = vec![0u8; len];
                    for (idx, byte) in plaintext.iter_mut().enumerate() {
                        *byte = nonce_seed
                            .wrapping_mul(19)
                            .wrapping_add((idx as u8).wrapping_mul(5))
                            .wrapping_add(ad_len as u8);
                    }

                    let (ct_native, tag_native) = morus.encrypt_native(&plaintext, &ad, &nonce);
                    let (ct_opt, tag_opt) = morus.encrypt_optimized(&plaintext, &ad, &nonce);

                    assert_eq!(
                        ct_opt, ct_native,
                        "optimized MORUS ciphertext diverged for len={len} ad_len={ad_len}"
                    );
                    assert_eq!(
                        tag_opt, tag_native,
                        "optimized MORUS tag diverged for len={len} ad_len={ad_len}"
                    );

                    let pt_native = morus.decrypt_native(&ct_opt, &tag_opt, &ad, &nonce).unwrap();
                    assert_eq!(pt_native, plaintext);
                    let pt_opt =
                        morus.decrypt_optimized(&ct_native, &tag_native, &ad, &nonce).unwrap();
                    assert_eq!(pt_opt, plaintext);
                }
            }
        }
    }

    #[test]
    fn test_morus_new_rejects_short_key() {
        let short_key = [0xABu8; 8];
        let iv = [0x10u8; 12];
        assert!(MorusAead::new(&short_key, &iv).is_err());
    }

    #[test]
    fn test_morus_nonce_sensitivity() {
        let key = [0x42u8; 16];
        let iv = [0x24u8; 12];
        let nonce_a = [0x01u8; 16];
        let nonce_b = [0x02u8; 16];
        let plaintext = b"nonce sensitivity test payload";
        let ad = b"";

        let morus = MorusAead::from_arrays(&key, &iv);
        let (ct_a, tag_a) = morus.encrypt_native(plaintext, ad, &nonce_a);
        let (ct_b, tag_b) = morus.encrypt_native(plaintext, ad, &nonce_b);

        // Same plaintext, different nonces must produce different ciphertexts
        assert_ne!(ct_a, ct_b, "different nonces must produce different ciphertexts");
        assert_ne!(tag_a, tag_b, "different nonces must produce different tags");
    }

    #[test]
    fn test_morus_ad_affects_tag() {
        let key = [0x55u8; 16];
        let iv = [0x66u8; 12];
        let nonce = [0x77u8; 16];
        let plaintext = b"same plaintext for both";
        let ad_a = b"associated data A";
        let ad_b = b"associated data B";

        let morus = MorusAead::from_arrays(&key, &iv);
        let (ct_a, tag_a) = morus.encrypt_native(plaintext, ad_a, &nonce);
        let (ct_b, tag_b) = morus.encrypt_native(plaintext, ad_b, &nonce);

        // MORUS XORs ciphertext stream from state - AD changes state, so tags differ.
        // Ciphertext may or may not differ depending on stream cipher properties,
        // but tags MUST differ when AD differs.
        assert_ne!(tag_a, tag_b, "different AD must produce different authentication tags");
        // Verify cross-decryption fails: tag from ad_a cannot authenticate ad_b
        let result = morus.decrypt_native(&ct_b, &tag_a, ad_b, &nonce);
        assert!(result.is_err(), "tag from ad_a must not authenticate ad_b");
        let _ = ct_a; // suppress unused warning
    }

    #[test]
    fn test_morus_tag_determinism() {
        let key = [0x88u8; 16];
        let iv = [0x99u8; 12];
        let nonce = [0xAAu8; 16];
        let plaintext = b"determinism check payload";
        let ad = b"determinism ad";

        let morus = MorusAead::from_arrays(&key, &iv);
        let (ct1, tag1) = morus.encrypt_native(plaintext, ad, &nonce);
        let (ct2, tag2) = morus.encrypt_native(plaintext, ad, &nonce);

        assert_eq!(ct1, ct2, "encrypting same data twice must produce identical ciphertext");
        assert_eq!(tag1, tag2, "encrypting same data twice must produce identical tags");
    }

    #[test]
    fn test_morus_decrypt_error_type() {
        let key = [0xBBu8; 16];
        let iv = [0xCCu8; 12];
        let nonce = [0xDDu8; 16];
        let plaintext = b"error type check";
        let ad = b"";

        let morus = MorusAead::from_arrays(&key, &iv);
        let (ciphertext, _tag) = morus.encrypt_native(plaintext, ad, &nonce);

        // Provide a wrong tag
        let wrong_tag = [0xFFu8; 16];
        let mut buf = ciphertext.clone();
        let result = morus.decrypt_in_place(&mut buf, &wrong_tag, ad, &nonce);
        assert_eq!(result, Err(AeadError::TagMismatch));
    }

    #[test]
    fn test_morus_new_rejects_oversized_key() {
        let full_key = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
            0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C,
            0x1D, 0x1E, 0x1F, 0x20,
        ]; // 32 bytes
        let iv = [0x30u8; 12];
        assert!(MorusAead::new(&full_key, &iv).is_err());
    }

    #[test]
    fn test_morus_in_place_roundtrip() {
        let key = [0x13u8; 16];
        let iv = [0x37u8; 12];
        let nonce = [0x42u8; 16];
        let ad = b"in_place_associated_data";
        let mut plaintext = vec![0u8; 256];
        for (idx, byte) in plaintext.iter_mut().enumerate() {
            *byte = (idx as u8).wrapping_mul(31);
        }

        let morus = MorusAead::from_arrays(&key, &iv);
        let (expected_ct, expected_tag) = morus.encrypt_native(&plaintext, ad, &nonce);

        let mut in_place_buf = plaintext.clone();
        let tag = morus.encrypt_in_place(&mut in_place_buf, ad, &nonce);
        assert_eq!(expected_ct, in_place_buf);
        assert_eq!(expected_tag, tag);

        let mut decrypt_buf = expected_ct.clone();
        morus
            .decrypt_in_place(&mut decrypt_buf, &expected_tag, ad, &nonce)
            .expect("decrypt_in_place should succeed");
        assert_eq!(decrypt_buf, plaintext);
    }

    #[test]
    fn morus_kat_vectors() {
        let key: [u8; 16] = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f,
        ];
        let iv = [0u8; 12];
        let nonce: [u8; 16] = [
            0x0f, 0x0e, 0x0d, 0x0c, 0x0b, 0x0a, 0x09, 0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02,
            0x01, 0x00,
        ];
        let ad: [u8; 16] = [
            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
            0x1e, 0x1f,
        ];
        let pt: [u8; 32] = [
            0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d,
            0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b,
            0x3c, 0x3d, 0x3e, 0x3f,
        ];
        let expected_ct: [u8; 32] = [
            0x0e, 0x95, 0x2d, 0x81, 0xd5, 0x90, 0xb2, 0x29, 0x16, 0xfe, 0xf3, 0x56, 0x5c, 0x8f,
            0x49, 0xbe, 0x72, 0x9a, 0x43, 0x13, 0x64, 0x5b, 0x4f, 0x6b, 0xd6, 0xc8, 0x7c, 0x97,
            0x66, 0x3c, 0x4f, 0xb7,
        ];
        let expected_tag: [u8; 16] = [
            0xf0, 0x85, 0xa8, 0xc7, 0x48, 0x70, 0x0b, 0x94, 0x1c, 0xb9, 0xca, 0xa6, 0xcd, 0x0d,
            0x74, 0x18,
        ];

        let morus = MorusAead::from_arrays(&key, &iv);
        let (ct, tag) = morus.encrypt_native(&pt, &ad, &nonce);
        assert_eq!(ct, expected_ct);
        assert_eq!(tag, expected_tag);

        let (ct_opt, tag_opt) = morus.encrypt_optimized(&pt, &ad, &nonce);
        assert_eq!(ct_opt, expected_ct);
        assert_eq!(tag_opt, expected_tag);
    }

    // TODO-395: regression guard — the AeadSeal/AeadOpen trait path must
    // operate in-place on the caller buffer (no intermediate Vec) and produce
    // output identical to the native in-place encrypt/decrypt path.
    #[test]
    fn morus_trait_path_matches_in_place_and_roundtrips() {
        use super::{AeadOpen, AeadSeal};

        let key = [0x5eu8; 16];
        let iv = [0x2cu8; 12];
        let ad = b"trait-path-ad";
        let pt: Vec<u8> = (0u8..200).map(|i| i.wrapping_mul(7)).collect();

        let morus = MorusAead::from_arrays(&key, &iv);

        for counter in 1u64..=16 {
            let nonce16 = super::super::make_nonce16(&iv, counter);

            // Reference: native in-place path.
            let mut ref_buf = pt.clone();
            let ref_tag = morus.encrypt_in_place(&mut ref_buf, ad, &nonce16);

            // Trait path: seal_with_u64_counter (must be in-place, no to_vec).
            let mut trait_buf = vec![0u8; pt.len() + 16];
            trait_buf[..pt.len()].copy_from_slice(&pt);
            let sealed_len = morus
                .seal_with_u64_counter(counter, ad, trait_buf.as_mut_slice(), pt.len(), None)
                .unwrap();
            assert_eq!(sealed_len, pt.len() + 16);
            assert_eq!(&trait_buf[..pt.len()], ref_buf.as_slice());
            assert_eq!(&trait_buf[pt.len()..], &ref_tag);

            // Trait path: open_with_u64_counter must recover plaintext in-place.
            let pt_len =
                morus.open_with_u64_counter(counter, ad, trait_buf.as_mut_slice()).unwrap();
            assert_eq!(pt_len, pt.len());
            assert_eq!(&trait_buf[..pt_len], pt.as_slice());
        }

        // Forgery: a flipped ciphertext bit must fail authentication on the trait path.
        let mut bad = vec![0u8; pt.len() + 16];
        bad[..pt.len()].copy_from_slice(&pt);
        morus.seal_with_u64_counter(99, ad, bad.as_mut_slice(), pt.len(), None).unwrap();
        bad[0] ^= 0xff;
        assert!(
            morus.open_with_u64_counter(99, ad, bad.as_mut_slice()).is_err(),
            "tampered ciphertext must fail authentication"
        );
    }
}
