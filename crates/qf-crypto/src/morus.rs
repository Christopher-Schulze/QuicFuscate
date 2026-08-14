#![allow(unexpected_cfgs)]
//! MORUS-1280-128 AEAD cipher implementation.
//!
//! Specification: <https://competitions.cr.yp.to/round3/morusv2.pdf>

use std::sync::OnceLock;

#[cfg(target_arch = "x86_64")]
use std::arch::x86_64::*;

use crate::crypto::aead::{require_exact_key_iv, AeadOpen, AeadSeal, KeyMaterialError};
use zeroize::Zeroize;

mod state_ops;

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
        let s = k & 3;
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
        let (r1_3_lo, r1_3_hi) = Self::rotl_words_pair_ssse3(s3_lo, s3_hi, 3);

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
        let (r3_0_lo, r3_0_hi) = Self::rotl_words_pair_ssse3(r1_0_lo, r1_0_hi, 1);

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
        let (new2_lo, new2_hi) = Self::rotl_words_pair_ssse3(r3_2_lo, r3_2_hi, 3);

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
        let (r1_3_lo, r1_3_hi) = Self::rotl_words_pair_sse41(s3_lo, s3_hi, 3);

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
        let (r3_0_lo, r3_0_hi) = Self::rotl_words_pair_sse41(r1_0_lo, r1_0_hi, 1);

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
        let (new2_lo, new2_hi) = Self::rotl_words_pair_sse41(r3_2_lo, r3_2_hi, 3);

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
        let (r1_3_lo, r1_3_hi) = Self::rotl_words_pair_sse(s3_lo, s3_hi, 3);

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
        let (r3_0_lo, r3_0_hi) = Self::rotl_words_pair_sse(r1_0_lo, r1_0_hi, 1);

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
        let (new2_lo, new2_hi) = Self::rotl_words_pair_sse(r3_2_lo, r3_2_hi, 3);

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
        let (r1_3_lo, r1_3_hi) = Self::rot_words_pair_neon(s3, s3_hi, 3);

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
        let (r3_0_lo, r3_0_hi) = Self::rot_words_pair_neon(r1_0_lo, r1_0_hi, 1);

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
        let (new2_lo, new2_hi) = Self::rot_words_pair_neon(r3_2_lo, r3_2_hi, 3);

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
                Self::rotl_words_256([s3_0, s3_1, s3_2, s3_3], 3);
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
            let [r3_0_0, r3_0_1, r3_0_2, r3_0_3] = Self::rotl_words_256(r1_0, 1);

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
            let new2 = Self::rotl_words_256(r3_2, 3);

            self.s[0] = [r3_0_0, r3_0_1, r3_0_2, r3_0_3];
            self.s[1] = [r4_1_0, r4_1_1, r4_1_2, r4_1_3];
            self.s[2] = new2;
            self.s[3] = r4_3;
            self.s[4] = new4;
        }
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
        #[cfg(target_arch = "x86_64")]
        {
            let features = qf_cpu::FeatureDetector::instance().features_full();
            let has_sse42 = features.sse42;
            let has_sse41 = features.sse41 || has_sse42;
            if has_sse42 && features.ssse3 {
                return MorusBackend::Sse42;
            }
            if has_sse41 && features.ssse3 {
                return MorusBackend::Sse41;
            }
            if features.ssse3 {
                return MorusBackend::Ssse3;
            }
            if features.sse2 {
                return MorusBackend::Sse2;
            }
            MorusBackend::Scalar
        }

        #[cfg(target_arch = "aarch64")]
        {
            if qf_cpu::FeatureDetector::instance().features_full().neon {
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
        qf_telemetry::MORUS1280_SCALAR_OPS.inc();
        let mut state = Morus1280State::init(&self.key, nonce);
        state.process_ad(ad);

        let mut ciphertext = plaintext.to_vec();
        state.encrypt(&mut ciphertext);

        let tag = state.finalize(ad.len(), plaintext.len());
        (ciphertext, tag)
    }

    /// Encrypt `buffer` in place with associated data; returns the 16-byte authentication tag.
    pub fn encrypt_in_place(&self, buffer: &mut [u8], ad: &[u8], nonce: &[u8; 16]) -> [u8; 16] {
        qf_telemetry::MORUS1280_SCALAR_OPS.inc();
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
        qf_telemetry::MORUS1280_SCALAR_OPS.inc();
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
        qf_telemetry::MORUS1280_SCALAR_OPS.inc();
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
    // SAFETY: the caller dispatches only after runtime SSSE3 verification;
    // full chunks are exactly 32 bytes and all tails use bounded slice helpers.
    unsafe fn encrypt_morus1280_ssse3_inner(
        &self,
        buffer: &mut [u8],
        ad: &[u8],
        nonce: &[u8; 16],
    ) -> [u8; 16] {
        qf_telemetry::MORUS1280_SSSE3_OPS.inc();
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
    // SAFETY: the caller dispatches only after runtime SSSE3 verification;
    // full chunks are exactly 32 bytes and all tails use bounded slice helpers.
    unsafe fn decrypt_morus1280_ssse3_inner(
        &self,
        buffer: &mut [u8],
        tag: &[u8; 16],
        ad: &[u8],
        nonce: &[u8; 16],
    ) -> Result<(), ()> {
        qf_telemetry::MORUS1280_SSSE3_OPS.inc();
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
        qf_telemetry::MORUS1280_SSE41_OPS.inc();
        unsafe { Some(self.encrypt_morus1280_sse41_inner(buffer, ad, nonce)) }
    }

    #[cfg(target_arch = "x86_64")]
    #[target_feature(enable = "ssse3,sse4.1")]
    // SAFETY: the caller dispatches only after runtime SSSE3 and SSE4.1
    // verification; full chunks and tails remain slice-bounded.
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
        qf_telemetry::MORUS1280_SSE41_OPS.inc();
        unsafe { Some(self.decrypt_morus1280_sse41_inner(buffer, tag, ad, nonce)) }
    }

    #[cfg(target_arch = "x86_64")]
    #[target_feature(enable = "ssse3,sse4.1")]
    // SAFETY: the caller dispatches only after runtime SSSE3 and SSE4.1
    // verification; full chunks and tails remain slice-bounded.
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
    // SAFETY: the caller dispatches only after runtime SSSE3, SSE4.1, and
    // SSE4.2 verification; this wrapper calls only the matching inner path.
    unsafe fn encrypt_morus1280_sse42_inplace(
        &self,
        buffer: &mut [u8],
        ad: &[u8],
        nonce: &[u8; 16],
    ) -> Option<[u8; 16]> {
        qf_telemetry::MORUS1280_SSE42_OPS.inc();
        Some(self.encrypt_morus1280_sse42_inner(buffer, ad, nonce))
    }

    #[cfg(target_arch = "x86_64")]
    #[target_feature(enable = "ssse3,sse4.1,sse4.2")]
    // SAFETY: the caller dispatches only after runtime SSSE3, SSE4.1, and
    // SSE4.2 verification; full chunks and tails remain slice-bounded.
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
    // SAFETY: the caller dispatches only after runtime SSSE3, SSE4.1, and
    // SSE4.2 verification; this wrapper calls only the matching inner path.
    unsafe fn decrypt_morus1280_sse42_inplace(
        &self,
        buffer: &mut [u8],
        tag: &[u8; 16],
        ad: &[u8],
        nonce: &[u8; 16],
    ) -> Option<Result<(), ()>> {
        qf_telemetry::MORUS1280_SSE42_OPS.inc();
        Some(self.decrypt_morus1280_sse42_inner(buffer, tag, ad, nonce))
    }

    #[cfg(target_arch = "x86_64")]
    #[target_feature(enable = "ssse3,sse4.1,sse4.2")]
    // SAFETY: the caller dispatches only after runtime SSSE3, SSE4.1, and
    // SSE4.2 verification; full chunks and tails remain slice-bounded.
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
    // SAFETY: x86_64 provides SSE2 and the wrapper receives mutable buffers;
    // full chunks and tails stay within their slice bounds.
    unsafe fn encrypt_morus1280_sse2_inplace(
        &self,
        buffer: &mut [u8],
        ad: &[u8],
        nonce: &[u8; 16],
    ) -> Option<[u8; 16]> {
        qf_telemetry::MORUS1280_SSE2_OPS.inc();
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
    // SAFETY: x86_64 provides SSE2 and the wrapper receives mutable buffers;
    // full chunks and tails stay within their slice bounds.
    unsafe fn decrypt_morus1280_sse2_inplace(
        &self,
        buffer: &mut [u8],
        tag: &[u8; 16],
        ad: &[u8],
        nonce: &[u8; 16],
    ) -> Option<Result<(), ()>> {
        qf_telemetry::MORUS1280_SSE2_OPS.inc();
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
        qf_telemetry::MORUS1280_NEON_OPS.inc();
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
        qf_telemetry::MORUS1280_NEON_OPS.inc();
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
        let sealed = crate::crypto::checked_seal_capacity(buf.len(), len)?;
        let (pt, rest) = buf.split_at_mut(len);
        #[cfg(all(target_arch = "x86_64", target_feature = "sse2"))]
        super::prefetch_morus_buffer(pt.as_ptr(), len);
        let nonce16 = super::make_nonce16(&self.iv, counter)?;
        let tag = self.encrypt_in_place_optimized(pt, ad, &nonce16);
        rest[..16].copy_from_slice(&tag);
        Ok(sealed)
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
        let nonce16 = super::make_nonce16(&self.iv, counter)?;
        self.decrypt_in_place_optimized(ct, &tag, ad, &nonce16)
            .map_err(|_| ConnectionError::CryptoError("crypto failure".into()))?;
        Ok(ct_len)
    }
}

#[cfg(test)]
mod morus_tests;
