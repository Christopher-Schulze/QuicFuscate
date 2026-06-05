use crate::optimize::{telemetry, FeatureDetector};
#[inline(always)]
fn le32(x: &[u8]) -> u32 {
    u32::from_le_bytes([x[0], x[1], x[2], x[3]])
}

#[inline(always)]
fn load_r_clamped(r: &[u8; 16]) -> [u64; 5] {
    // 26-bit limbs, with clamp applied implicitly by masking
    let t0 = le32(&r[0..4]) as u64;
    let t1 = le32(&r[3..7]) as u64;
    let t2 = le32(&r[6..10]) as u64;
    let t3 = le32(&r[9..13]) as u64;
    let t4 = le32(&r[12..16]) as u64;
    let r0 = (t0) & 0x3ffffff;
    let r1 = (t1 >> 2) & 0x3ffffff;
    let r2 = (t2 >> 4) & 0x3ffffff;
    let r3 = (t3 >> 6) & 0x3ffffff;
    let r4 = (t4 >> 8) & 0x3ffffff;
    [r0, r1, r2, r3, r4]
}

#[inline(always)]
// SAFETY: caller must ensure `ptr` points to at least 16 readable bytes.
// Reads 5 overlapping u32 values at offsets 0, 3, 6, 9, 12 - the last read
// at ptr.add(12) reads bytes [12..16], within the 16-byte range. Unaligned
// reads used because u8 pointers have no alignment guarantee.
unsafe fn load_block_full(ptr: *const u8) -> [u64; 5] {
    use core::ptr;

    let t0 = u32::from_le(ptr::read_unaligned(ptr as *const u32)) as u64;
    let t1 = u32::from_le(ptr::read_unaligned(ptr.add(3) as *const u32)) as u64;
    let t2 = u32::from_le(ptr::read_unaligned(ptr.add(6) as *const u32)) as u64;
    let t3 = u32::from_le(ptr::read_unaligned(ptr.add(9) as *const u32)) as u64;
    let t4 = u32::from_le(ptr::read_unaligned(ptr.add(12) as *const u32)) as u64;

    let m0 = t0 & 0x3ffffff;
    let m1 = (t1 >> 2) & 0x3ffffff;
    let m2 = (t2 >> 4) & 0x3ffffff;
    let m3 = (t3 >> 6) & 0x3ffffff;
    let mut m4 = (t4 >> 8) & 0x3ffffff;
    m4 |= 1 << 24;
    [m0, m1, m2, m3, m4]
}

#[inline(always)]
fn load_block(m: &[u8]) -> [u64; 5] {
    if m.len() == 16 {
        // SAFETY: m.len() == 16 satisfies load_block_full's 16-byte requirement.
        unsafe { return load_block_full(m.as_ptr()) };
    }

    let mut block = [0u8; 16];
    block[..m.len()].copy_from_slice(m);
    // SAFETY: block is [u8; 16] - exactly 16 bytes, satisfying load_block_full.
    unsafe { load_block_full(block.as_ptr()) }
}

#[inline(always)]
fn mac_scalar(mut h: [u64; 5], r: [u64; 5], m: &[u8]) -> [u64; 5] {
    // Pre-compute the repeated multipliers once outside the hot loop.
    let r0 = r[0];
    let r1 = r[1];
    let r2 = r[2];
    let r3 = r[3];
    let r4 = r[4];

    let s1 = r1 * 5;
    let s2 = r2 * 5;
    let s3 = r3 * 5;
    let s4 = r4 * 5;

    let r_u128 = [r0 as u128, r1 as u128, r2 as u128, r3 as u128, r4 as u128];
    let s_u128 = [0u128, s1 as u128, s2 as u128, s3 as u128, s4 as u128];

    let mut ptr = m;
    while ptr.len() >= 16 {
        // SAFETY: ptr.len() >= 16, so ptr.as_ptr() points to >= 16 bytes.
        let limbs = unsafe { load_block_full(ptr.as_ptr()) };
        h = mac_scalar_block(h, &r_u128, &s_u128, limbs);
        ptr = &ptr[16..];
    }

    if !ptr.is_empty() {
        let mut block = [0u8; 16];
        block[..ptr.len()].copy_from_slice(ptr);
        // SAFETY: block is [u8; 16] - exactly 16 bytes.
        let limbs = unsafe { load_block_full(block.as_ptr()) };
        h = mac_scalar_block(h, &r_u128, &s_u128, limbs);
    }

    h
}

#[inline(always)]
fn mac_scalar_block(
    mut h: [u64; 5],
    r_u128: &[u128; 5],
    s_u128: &[u128; 5],
    limbs: [u64; 5],
) -> [u64; 5] {
    let hh0 = h[0] + limbs[0];
    let hh1 = h[1] + limbs[1];
    let hh2 = h[2] + limbs[2];
    let hh3 = h[3] + limbs[3];
    let hh4 = h[4] + limbs[4];

    // Accumulate using 128-bit intermediates to preserve exactness.
    let d0 = (hh0 as u128) * r_u128[0]
        + (hh1 as u128) * s_u128[4]
        + (hh2 as u128) * s_u128[3]
        + (hh3 as u128) * s_u128[2]
        + (hh4 as u128) * s_u128[1];

    let mut d1 = (hh0 as u128) * r_u128[1]
        + (hh1 as u128) * r_u128[0]
        + (hh2 as u128) * s_u128[4]
        + (hh3 as u128) * s_u128[3]
        + (hh4 as u128) * s_u128[2];

    let mut d2 = (hh0 as u128) * r_u128[2]
        + (hh1 as u128) * r_u128[1]
        + (hh2 as u128) * r_u128[0]
        + (hh3 as u128) * s_u128[4]
        + (hh4 as u128) * s_u128[3];

    let mut d3 = (hh0 as u128) * r_u128[3]
        + (hh1 as u128) * r_u128[2]
        + (hh2 as u128) * r_u128[1]
        + (hh3 as u128) * r_u128[0]
        + (hh4 as u128) * s_u128[4];

    let mut d4 = (hh0 as u128) * r_u128[4]
        + (hh1 as u128) * r_u128[3]
        + (hh2 as u128) * r_u128[2]
        + (hh3 as u128) * r_u128[1]
        + (hh4 as u128) * r_u128[0];

    // Carry propagation in base 2^26
    let mut carry = (d0 >> 26) as u64;
    h[0] = (d0 & 0x3ffffff) as u64;

    d1 += carry as u128;
    carry = (d1 >> 26) as u64;
    h[1] = (d1 & 0x3ffffff) as u64;

    d2 += carry as u128;
    carry = (d2 >> 26) as u64;
    h[2] = (d2 & 0x3ffffff) as u64;

    d3 += carry as u128;
    carry = (d3 >> 26) as u64;
    h[3] = (d3 & 0x3ffffff) as u64;

    d4 += carry as u128;
    carry = (d4 >> 26) as u64;
    h[4] = (d4 & 0x3ffffff) as u64;

    h[0] += carry * 5;
    let carry2 = h[0] >> 26;
    h[0] &= 0x3ffffff;
    h[1] += carry2;

    h
}

fn mac(h: [u64; 5], r: [u64; 5], m: &[u8]) -> [u64; 5] {
    let features = FeatureDetector::instance().features_full();

    // SAFETY: runtime feature detection verified before dispatch. Each SIMD backend
    // has a matching target_feature gate. h and r are by-value [u64; 5], m is &[u8].
    // All backends process m in 16-byte blocks with offset guards.
    #[cfg(target_arch = "x86_64")]
    unsafe {
        if features.avx512f {
            return mac_avx512(h, r, m);
        }
        if features.avx2 {
            return mac_avx2(h, r, m);
        }
        if features.sse2 {
            return mac_sse2(h, r, m);
        }
    }

    // SAFETY: runtime feature detection verified before dispatch. Same invariants
    // as x86_64 block above.
    #[cfg(target_arch = "aarch64")]
    unsafe {
        if features.sve2 {
            return mac_sve2(h, r, m);
        }
        if features.neon {
            return mac_neon(h, r, m);
        }
    }

    telemetry::POLY1305_SCALAR_OPS.inc();
    mac_scalar(h, r, m)
}

#[cfg(target_arch = "x86_64")]
#[inline(always)]
// SAFETY: requires AVX2 (caller ensures). All inputs are scalar u32 values loaded
// into __m256i via _mm256_set_epi32 (no memory pointers). _mm256_mul_epu32
// performs register-to-register multiplication. Extract via _mm256_castsi256_si128 /
// _mm256_extracti128_si256 / _mm_cvtsi128_si64 - all register operations.
unsafe fn mul_even_u32_avx2(
    a0: u32,
    a1: u32,
    a2: u32,
    a3: u32,
    b0: u32,
    b1: u32,
    b2: u32,
    b3: u32,
) -> [u64; 4] {
    use core::arch::x86_64::*;

    let va = _mm256_set_epi32(0, a3 as i32, 0, a2 as i32, 0, a1 as i32, 0, a0 as i32);
    let vb = _mm256_set_epi32(0, b3 as i32, 0, b2 as i32, 0, b1 as i32, 0, b0 as i32);
    let prod = _mm256_mul_epu32(va, vb);
    let low = _mm256_castsi256_si128(prod);
    let high = _mm256_extracti128_si256(prod, 1);
    let r0 = _mm_cvtsi128_si64(low) as u64;
    let r1 = _mm_cvtsi128_si64(_mm_srli_si128(low, 8)) as u64;
    let r2 = _mm_cvtsi128_si64(high) as u64;
    let r3 = _mm_cvtsi128_si64(_mm_srli_si128(high, 8)) as u64;
    [r0, r1, r2, r3]
}

#[cfg(target_arch = "x86_64")]
#[inline]
#[target_feature(enable = "avx512f")]
// SAFETY: target_feature gate ensures AVX-512F. All inputs are scalar u32 values
// loaded into __m512i via _mm512_setr_epi32. _mm512_mul_epu32 performs
// register-to-register multiplication. _mm512_storeu_si512 writes 64 bytes into
// stack-owned [u64; 8] array. Only first 4 elements used.
unsafe fn mul_even_u32_avx512(
    a0: u32,
    a1: u32,
    a2: u32,
    a3: u32,
    b0: u32,
    b1: u32,
    b2: u32,
    b3: u32,
) -> [u64; 4] {
    use core::arch::x86_64::*;

    let va = _mm512_setr_epi32(
        a0 as i32, 0, a1 as i32, 0, a2 as i32, 0, a3 as i32, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    );
    let vb = _mm512_setr_epi32(
        b0 as i32, 0, b1 as i32, 0, b2 as i32, 0, b3 as i32, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    );
    let prod = _mm512_mul_epu32(va, vb);
    let mut out = [0u64; 8];
    _mm512_storeu_si512(out.as_mut_ptr() as *mut __m512i, prod);
    [out[0], out[1], out[2], out[3]]
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
// SAFETY: target_feature gate ensures AVX2. h and r are by-value [u64; 5].
// m is &[u8]; loop processes 16-byte blocks via load_block (bounds-checked).
// mul_even_u32_avx2 takes scalar u32 args (no pointers). All SIMD ops are
// register-to-register.
unsafe fn mac_avx2(h: [u64; 5], r: [u64; 5], m: &[u8]) -> [u64; 5] {
    telemetry::POLY1305_AVX2_OPS.inc();
    let r0 = r[0] as u32;
    let r1 = r[1] as u32;
    let r2 = r[2] as u32;
    let r3 = r[3] as u32;
    let r4 = r[4] as u32;

    let s1 = (r1 as u64 * 5) as u32;
    let s2 = (r2 as u64 * 5) as u32;
    let s3 = (r3 as u64 * 5) as u32;
    let s4 = (r4 as u64 * 5) as u32;

    let mut h0 = h[0];
    let mut h1 = h[1];
    let mut h2 = h[2];
    let mut h3 = h[3];
    let mut h4 = h[4];

    let mut offset = 0usize;
    while offset < m.len() {
        let take = core::cmp::min(16, m.len() - offset);
        let limbs = load_block(&m[offset..offset + take]);
        offset += take;

        h0 += limbs[0];
        h1 += limbs[1];
        h2 += limbs[2];
        h3 += limbs[3];
        h4 += limbs[4];

        let h0u = h0 as u32;
        let h1u = h1 as u32;
        let h2u = h2 as u32;
        let h3u = h3 as u32;
        let h4u = h4 as u32;

        let prods0 = mul_even_u32_avx2(h0u, h1u, h2u, h3u, r0, s4, s3, s2);
        let mut d0 = (prods0[0] as u128)
            + (prods0[1] as u128)
            + (prods0[2] as u128)
            + (prods0[3] as u128)
            + ((h4u as u128) * (s1 as u128));

        let prods1 = mul_even_u32_avx2(h0u, h1u, h2u, h3u, r1, r0, s4, s3);
        let mut d1 = (prods1[0] as u128)
            + (prods1[1] as u128)
            + (prods1[2] as u128)
            + (prods1[3] as u128)
            + ((h4u as u128) * (s2 as u128));

        let prods2 = mul_even_u32_avx2(h0u, h1u, h2u, h3u, r2, r1, r0, s4);
        let mut d2 = (prods2[0] as u128)
            + (prods2[1] as u128)
            + (prods2[2] as u128)
            + (prods2[3] as u128)
            + ((h4u as u128) * (s3 as u128));

        let prods3 = mul_even_u32_avx2(h0u, h1u, h2u, h3u, r3, r2, r1, r0);
        let mut d3 = (prods3[0] as u128)
            + (prods3[1] as u128)
            + (prods3[2] as u128)
            + (prods3[3] as u128)
            + ((h4u as u128) * (s4 as u128));

        let prods4 = mul_even_u32_avx2(h0u, h1u, h2u, h3u, r4, r3, r2, r1);
        let mut d4 = (prods4[0] as u128)
            + (prods4[1] as u128)
            + (prods4[2] as u128)
            + (prods4[3] as u128)
            + ((h4u as u128) * (r0 as u128));

        let mut carry = d0 >> 26;
        h0 = (d0 & 0x3ffffff) as u64;

        d1 += carry;
        carry = d1 >> 26;
        h1 = (d1 & 0x3ffffff) as u64;

        d2 += carry;
        carry = d2 >> 26;
        h2 = (d2 & 0x3ffffff) as u64;

        d3 += carry;
        carry = d3 >> 26;
        h3 = (d3 & 0x3ffffff) as u64;

        d4 += carry;
        carry = d4 >> 26;
        h4 = (d4 & 0x3ffffff) as u64;
        h0 += (carry as u64) * 5;
        let carry2 = h0 >> 26;
        h0 &= 0x3ffffff;
        h1 += carry2;
    }

    [h0, h1, h2, h3, h4]
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx512f")]
// SAFETY: target_feature gate ensures AVX-512F. h and r are by-value [u64; 5].
// m is &[u8]; loop processes 16-byte blocks via load_block (bounds-checked).
// mul_even_u32_avx512 takes scalar u32 args (no pointers). All SIMD ops are
// register-to-register.
unsafe fn mac_avx512(h: [u64; 5], r: [u64; 5], m: &[u8]) -> [u64; 5] {
    telemetry::POLY1305_AVX512_OPS.inc();
    let r0 = r[0] as u32;
    let r1 = r[1] as u32;
    let r2 = r[2] as u32;
    let r3 = r[3] as u32;
    let r4 = r[4] as u32;

    let s1 = (r1 as u64 * 5) as u32;
    let s2 = (r2 as u64 * 5) as u32;
    let s3 = (r3 as u64 * 5) as u32;
    let s4 = (r4 as u64 * 5) as u32;

    let mut h0 = h[0];
    let mut h1 = h[1];
    let mut h2 = h[2];
    let mut h3 = h[3];
    let mut h4 = h[4];

    let mut offset = 0usize;
    while offset < m.len() {
        let take = core::cmp::min(16, m.len() - offset);
        let limbs = load_block(&m[offset..offset + take]);
        offset += take;

        h0 += limbs[0];
        h1 += limbs[1];
        h2 += limbs[2];
        h3 += limbs[3];
        h4 += limbs[4];

        let h0u = h0 as u32;
        let h1u = h1 as u32;
        let h2u = h2 as u32;
        let h3u = h3 as u32;
        let h4u = h4 as u32;

        let prods0 = mul_even_u32_avx512(h0u, h1u, h2u, h3u, r0, s4, s3, s2);
        let mut d0 = (prods0[0] as u128)
            + (prods0[1] as u128)
            + (prods0[2] as u128)
            + (prods0[3] as u128)
            + ((h4u as u128) * (s1 as u128));

        let prods1 = mul_even_u32_avx512(h0u, h1u, h2u, h3u, r1, r0, s4, s3);
        let mut d1 = (prods1[0] as u128)
            + (prods1[1] as u128)
            + (prods1[2] as u128)
            + (prods1[3] as u128)
            + ((h4u as u128) * (s2 as u128));

        let prods2 = mul_even_u32_avx512(h0u, h1u, h2u, h3u, r2, r1, r0, s4);
        let mut d2 = (prods2[0] as u128)
            + (prods2[1] as u128)
            + (prods2[2] as u128)
            + (prods2[3] as u128)
            + ((h4u as u128) * (s3 as u128));

        let prods3 = mul_even_u32_avx512(h0u, h1u, h2u, h3u, r3, r2, r1, r0);
        let mut d3 = (prods3[0] as u128)
            + (prods3[1] as u128)
            + (prods3[2] as u128)
            + (prods3[3] as u128)
            + ((h4u as u128) * (s4 as u128));

        let prods4 = mul_even_u32_avx512(h0u, h1u, h2u, h3u, r4, r3, r2, r1);
        let mut d4 = (prods4[0] as u128)
            + (prods4[1] as u128)
            + (prods4[2] as u128)
            + (prods4[3] as u128)
            + ((h4u as u128) * (r0 as u128));

        let mut carry = d0 >> 26;
        h0 = (d0 & 0x3ffffff) as u64;

        d1 += carry;
        carry = d1 >> 26;
        h1 = (d1 & 0x3ffffff) as u64;

        d2 += carry;
        carry = d2 >> 26;
        h2 = (d2 & 0x3ffffff) as u64;

        d3 += carry;
        carry = d3 >> 26;
        h3 = (d3 & 0x3ffffff) as u64;

        d4 += carry;
        carry = d4 >> 26;
        h4 = (d4 & 0x3ffffff) as u64;
        h0 += (carry as u64) * 5;
        let carry2 = h0 >> 26;
        h0 &= 0x3ffffff;
        h1 += carry2;
    }

    [h0, h1, h2, h3, h4]
}

#[cfg(target_arch = "x86_64")]
#[inline(always)]
// SAFETY: requires SSE2 (caller ensures, baseline x86_64). All inputs are scalar
// u32 values loaded into __m128i via _mm_set_epi32. _mm_mul_epu32 performs
// register-to-register multiplication. Extracts via _mm_cvtsi128_si64 /
// _mm_unpackhi_epi64 - all register operations.
unsafe fn mul_pair_u32_sse2(a0: u32, a1: u32, b0: u32, b1: u32) -> (u64, u64) {
    use core::arch::x86_64::*;

    let va = _mm_set_epi32(0, a1 as i32, 0, a0 as i32);
    let vb = _mm_set_epi32(0, b1 as i32, 0, b0 as i32);
    let prod = _mm_mul_epu32(va, vb);
    let lo = _mm_cvtsi128_si64(prod) as u64;
    let hi = _mm_cvtsi128_si64(_mm_unpackhi_epi64(prod, prod)) as u64;
    (lo, hi)
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "sse2")]
// SAFETY: target_feature gate ensures SSE2. h and r are by-value [u64; 5].
// m is &[u8]; loop processes 16-byte blocks via load_block (bounds-checked).
// mul_pair_u32_sse2 takes scalar u32 args (no pointers). All SIMD ops are
// register-to-register.
unsafe fn mac_sse2(h: [u64; 5], r: [u64; 5], m: &[u8]) -> [u64; 5] {
    telemetry::POLY1305_SSE2_OPS.inc();
    let r0 = r[0] as u32;
    let r1 = r[1] as u32;
    let r2 = r[2] as u32;
    let r3 = r[3] as u32;
    let r4 = r[4] as u32;

    let s1 = (r1 as u64 * 5) as u32;
    let s2 = (r2 as u64 * 5) as u32;
    let s3 = (r3 as u64 * 5) as u32;
    let s4 = (r4 as u64 * 5) as u32;

    let mut h0 = h[0];
    let mut h1 = h[1];
    let mut h2 = h[2];
    let mut h3 = h[3];
    let mut h4 = h[4];

    let mut offset = 0usize;
    while offset < m.len() {
        let take = core::cmp::min(16, m.len() - offset);
        let limbs = load_block(&m[offset..offset + take]);
        offset += take;

        h0 += limbs[0];
        h1 += limbs[1];
        h2 += limbs[2];
        h3 += limbs[3];
        h4 += limbs[4];

        let h0u = h0 as u32;
        let h1u = h1 as u32;
        let h2u = h2 as u32;
        let h3u = h3 as u32;
        let h4u = h4 as u32;

        let (p0, p1) = mul_pair_u32_sse2(h0u, h1u, r0, s4);
        let (p2, p3) = mul_pair_u32_sse2(h2u, h3u, s3, s2);
        let p4 = (h4u as u128) * (s1 as u128);
        let d0 = (p0 as u128) + (p1 as u128) + (p2 as u128) + (p3 as u128) + p4;

        let (q0, q1) = mul_pair_u32_sse2(h0u, h1u, r1, r0);
        let (q2, q3) = mul_pair_u32_sse2(h2u, h3u, s4, s3);
        let q4 = (h4u as u128) * (s2 as u128);
        let mut d1 = (q0 as u128) + (q1 as u128) + (q2 as u128) + (q3 as u128) + q4;

        let (r0p, r1p) = mul_pair_u32_sse2(h0u, h1u, r2, r1);
        let (r2p, r3p) = mul_pair_u32_sse2(h2u, h3u, r0, s4);
        let r4p = (h4u as u128) * (s3 as u128);
        let mut d2 = (r0p as u128) + (r1p as u128) + (r2p as u128) + (r3p as u128) + r4p;

        let (s0p, s1p) = mul_pair_u32_sse2(h0u, h1u, r3, r2);
        let (s2p, s3p) = mul_pair_u32_sse2(h2u, h3u, r1, r0);
        let s4p = (h4u as u128) * (s4 as u128);
        let mut d3 = (s0p as u128) + (s1p as u128) + (s2p as u128) + (s3p as u128) + s4p;

        let (t0p, t1p) = mul_pair_u32_sse2(h0u, h1u, r4, r3);
        let (t2p, t3p) = mul_pair_u32_sse2(h2u, h3u, r2, r1);
        let t4p = (h4u as u128) * (r0 as u128);
        let mut d4 = (t0p as u128) + (t1p as u128) + (t2p as u128) + (t3p as u128) + t4p;

        let mut carry = d0 >> 26;
        h0 = (d0 & 0x3ffffff) as u64;

        d1 += carry;
        carry = d1 >> 26;
        h1 = (d1 & 0x3ffffff) as u64;

        d2 += carry;
        carry = d2 >> 26;
        h2 = (d2 & 0x3ffffff) as u64;

        d3 += carry;
        carry = d3 >> 26;
        h3 = (d3 & 0x3ffffff) as u64;

        d4 += carry;
        carry = d4 >> 26;
        h4 = (d4 & 0x3ffffff) as u64;
        h0 += (carry as u64) * 5;
        let carry2 = h0 >> 26;
        h0 &= 0x3ffffff;
        h1 += carry2;
    }

    [h0, h1, h2, h3, h4]
}

#[cfg(target_arch = "aarch64")]
#[inline(always)]
// SAFETY: requires NEON (baseline aarch64). All inputs are scalar u32 values loaded
// into uint32x2_t via vdup_n_u32/vset_lane_u32. vmull_u32 performs register-to-register
// widening multiplication. vgetq_lane_u64 extracts register lanes. No memory access.
unsafe fn mul_pair_u32_neon(a0: u32, a1: u32, b0: u32, b1: u32) -> (u64, u64) {
    use core::arch::aarch64::*;

    let mut va = vdup_n_u32(0);
    va = vset_lane_u32(a0, va, 0);
    va = vset_lane_u32(a1, va, 1);
    let mut vb = vdup_n_u32(0);
    vb = vset_lane_u32(b0, vb, 0);
    vb = vset_lane_u32(b1, vb, 1);
    let prod = vmull_u32(va, vb);
    let lo = vgetq_lane_u64(prod, 0);
    let hi = vgetq_lane_u64(prod, 1);
    (lo, hi)
}

#[cfg(target_arch = "aarch64")]
#[inline(always)]
// SAFETY: requires NEON (caller ensures). h and r are by-value [u64; 5].
// m is &[u8]; loop processes 16-byte blocks via load_block (bounds-checked).
// mul_pair_u32_neon takes scalar u32 args (no pointers). All NEON ops are
// register-to-register.
unsafe fn mac_neon_body(mut h: [u64; 5], r: [u64; 5], m: &[u8]) -> [u64; 5] {
    let r0 = r[0] as u32;
    let r1 = r[1] as u32;
    let r2 = r[2] as u32;
    let r3 = r[3] as u32;
    let r4 = r[4] as u32;

    let s1 = (r1 as u64 * 5) as u32;
    let s2 = (r2 as u64 * 5) as u32;
    let s3 = (r3 as u64 * 5) as u32;
    let s4 = (r4 as u64 * 5) as u32;

    let mut offset = 0usize;
    while offset < m.len() {
        let take = core::cmp::min(16, m.len() - offset);
        let limbs = load_block(&m[offset..offset + take]);
        offset += take;

        h[0] += limbs[0];
        h[1] += limbs[1];
        h[2] += limbs[2];
        h[3] += limbs[3];
        h[4] += limbs[4];

        let h0u = h[0] as u32;
        let h1u = h[1] as u32;
        let h2u = h[2] as u32;
        let h3u = h[3] as u32;
        let h4u = h[4] as u32;

        let (p0, p1) = mul_pair_u32_neon(h0u, h1u, r0, s4);
        let (p2, p3) = mul_pair_u32_neon(h2u, h3u, s3, s2);
        let p4 = (h4u as u128) * (s1 as u128);
        let d0 = (p0 as u128) + (p1 as u128) + (p2 as u128) + (p3 as u128) + p4;

        let (q0, q1) = mul_pair_u32_neon(h0u, h1u, r1, r0);
        let (q2, q3) = mul_pair_u32_neon(h2u, h3u, s4, s3);
        let q4 = (h4u as u128) * (s2 as u128);
        let mut d1 = (q0 as u128) + (q1 as u128) + (q2 as u128) + (q3 as u128) + q4;

        let (r0p, r1p) = mul_pair_u32_neon(h0u, h1u, r2, r1);
        let (r2p, r3p) = mul_pair_u32_neon(h2u, h3u, r0, s4);
        let r4p = (h4u as u128) * (s3 as u128);
        let mut d2 = (r0p as u128) + (r1p as u128) + (r2p as u128) + (r3p as u128) + r4p;

        let (s0p, s1p) = mul_pair_u32_neon(h0u, h1u, r3, r2);
        let (s2p, s3p) = mul_pair_u32_neon(h2u, h3u, r1, r0);
        let s4p = (h4u as u128) * (s4 as u128);
        let mut d3 = (s0p as u128) + (s1p as u128) + (s2p as u128) + (s3p as u128) + s4p;

        let (t0p, t1p) = mul_pair_u32_neon(h0u, h1u, r4, r3);
        let (t2p, t3p) = mul_pair_u32_neon(h2u, h3u, r2, r1);
        let t4p = (h4u as u128) * (r0 as u128);
        let mut d4 = (t0p as u128) + (t1p as u128) + (t2p as u128) + (t3p as u128) + t4p;

        let mut carry = d0 >> 26;
        h[0] = (d0 & 0x3ffffff) as u64;

        d1 += carry;
        carry = d1 >> 26;
        h[1] = (d1 & 0x3ffffff) as u64;

        d2 += carry;
        carry = d2 >> 26;
        h[2] = (d2 & 0x3ffffff) as u64;

        d3 += carry;
        carry = d3 >> 26;
        h[3] = (d3 & 0x3ffffff) as u64;

        d4 += carry;
        carry = d4 >> 26;
        h[4] = (d4 & 0x3ffffff) as u64;
        h[0] += (carry as u64) * 5;
        let carry2 = h[0] >> 26;
        h[0] &= 0x3ffffff;
        h[1] += carry2;
    }

    h
}

#[cfg(target_arch = "aarch64")]
#[target_feature(enable = "neon")]
// SAFETY: target_feature gate ensures NEON. Delegates to mac_neon_body.
unsafe fn mac_neon(h: [u64; 5], r: [u64; 5], m: &[u8]) -> [u64; 5] {
    telemetry::POLY1305_NEON_OPS.inc();
    mac_neon_body(h, r, m)
}

#[cfg(all(target_arch = "aarch64", target_feature = "sve2"))]
#[target_feature(enable = "sve2")]
// SAFETY: target_feature gate ensures SVE2. svcntd() checked >= 4 for SVE path;
// otherwise falls back to NEON. svwhilelt_b64 creates a 4-lane predicate.
// svld1_u64 reads from stack-owned [u64; 4] arrays. svmul_u64_x / svaddv_u64
// are register operations. load_block_full called with m.as_ptr().add(offset)
// where offset+16 <= m.len() (while guard). Tail via load_block is safe.
unsafe fn mac_sve2_impl(mut h: [u64; 5], r: [u64; 5], m: &[u8]) -> [u64; 5] {
    use std::arch::aarch64::*;

    if (svcntd() as usize) < 4 {
        telemetry::POLY1305_NEON_OPS.inc();
        return mac_neon_body(h, r, m);
    }

    telemetry::POLY1305_SVE_OPS.inc();

    #[inline(always)]
    // SAFETY: requires SVE2 (caller ensures). svwhilelt_b64(0,4) creates a 4-lane
    // predicate. svld1_u64 reads from stack-owned [u64; 4] arrays (hh_vec, coeff.0).
    // svmul_u64_x / svaddv_u64 are register-to-register. All accumulation is in
    // u128 to prevent overflow. No pointer-based memory access beyond stack arrays.
    unsafe fn mac_sve2_block_wide(
        mut state: [u64; 5],
        coeffs: &[([u64; 4], u64); 5],
        limbs: [u64; 5],
    ) -> [u64; 5] {
        use std::arch::aarch64::*;

        let mut hh0 = state[0] + limbs[0];
        let mut hh1 = state[1] + limbs[1];
        let mut hh2 = state[2] + limbs[2];
        let mut hh3 = state[3] + limbs[3];
        let hh4 = state[4] + limbs[4];

        let hh_vec = [hh0, hh1, hh2, hh3];
        let pg = svwhilelt_b64(0, 4);
        let h_vec = svld1_u64(pg, hh_vec.as_ptr());

        let mut accum = [0u128; 5];
        for (idx, coeff) in coeffs.iter().enumerate() {
            let coeff_vec = svld1_u64(pg, coeff.0.as_ptr());
            let prods = svmul_u64_x(pg, h_vec, coeff_vec);
            let lane_sum = svaddv_u64(pg, prods) as u128;
            accum[idx] = lane_sum + (hh4 as u128) * (coeff.1 as u128);
        }

        let mut carry = (accum[0] >> 26) as u64;
        hh0 = (accum[0] & 0x3ffffff) as u64;

        accum[1] += carry as u128;
        carry = (accum[1] >> 26) as u64;
        hh1 = (accum[1] & 0x3ffffff) as u64;

        accum[2] += carry as u128;
        carry = (accum[2] >> 26) as u64;
        hh2 = (accum[2] & 0x3ffffff) as u64;

        accum[3] += carry as u128;
        carry = (accum[3] >> 26) as u64;
        hh3 = (accum[3] & 0x3ffffff) as u64;

        accum[4] += carry as u128;
        carry = (accum[4] >> 26) as u64;
        let mut hh4_reduced = (accum[4] & 0x3ffffff) as u64;

        hh0 += carry * 5;
        let carry2 = hh0 >> 26;
        hh0 &= 0x3ffffff;
        hh1 += carry2;
        hh4_reduced &= 0x3ffffff;

        state[0] = hh0;
        state[1] = hh1;
        state[2] = hh2;
        state[3] = hh3;
        state[4] = hh4_reduced;
        state
    }

    let s1 = r[1] * 5;
    let s2 = r[2] * 5;
    let s3 = r[3] * 5;
    let s4 = r[4] * 5;

    let coeffs: [([u64; 4], u64); 5] = [
        ([r[0], s4, s3, s2], s1),
        ([r[1], r[0], s4, s3], s2),
        ([r[2], r[1], r[0], s4], s3),
        ([r[3], r[2], r[1], r[0]], s4),
        ([r[4], r[3], r[2], r[1]], r[0]),
    ];

    let mut offset = 0usize;
    while offset + 16 <= m.len() {
        let limbs = load_block_full(m.as_ptr().add(offset));
        h = mac_sve2_block_wide(h, &coeffs, limbs);
        offset += 16;
    }

    if offset < m.len() {
        let limbs = load_block(&m[offset..]);
        h = mac_sve2_block_wide(h, &coeffs, limbs);
    }

    h
}

#[cfg(target_arch = "aarch64")]
// SAFETY: caller verified SVE2 at runtime. Dispatches to mac_sve2_impl (with
// target_feature gate) or falls back to mac_neon_body. All args are by-value
// or borrowed slices.
unsafe fn mac_sve2(h: [u64; 5], r: [u64; 5], m: &[u8]) -> [u64; 5] {
    #[cfg(target_feature = "sve2")]
    {
        return mac_sve2_impl(h, r, m);
    }
    #[cfg(not(target_feature = "sve2"))]
    {
        telemetry::POLY1305_NEON_OPS.inc();
        mac_neon_body(h, r, m)
    }
}

#[cfg(all(test, target_arch = "x86_64"))]
mod tests_x86 {
    use super::*;

    #[test]
    fn mac_sse2_matches_scalar() {
        if !std::arch::is_x86_feature_detected!("sse2") {
            return;
        }

        let r_bytes = [
            0x85, 0xd6, 0x96, 0x6a, 0x4c, 0xcd, 0x62, 0x16, 0x4b, 0xe5, 0x60, 0x47, 0x33, 0x8b,
            0x4f, 0x1f,
        ];
        let r = load_r_clamped(&r_bytes);

        let messages: &[&[u8]] = &[b"", b"hello world", &[0xFF; 31], &[0u8; 128]];

        for msg in messages {
            let h_scalar = mac_scalar([0; 5], r, msg);
            // SAFETY: SSE2 feature detected above; mac_sse2 requires SSE2.
            // Arguments are valid: h=[0;5], r from load_r_clamped, msg is &[u8].
            let h_simd = unsafe { mac_sse2([0; 5], r, msg) };
            assert_eq!(h_scalar, h_simd);
        }
    }

    #[test]
    fn mac_avx2_matches_scalar() {
        if !std::arch::is_x86_feature_detected!("avx2") {
            return;
        }

        let r_bytes = [
            0x85, 0xd6, 0x96, 0x6a, 0x4c, 0xcd, 0x62, 0x16, 0x4b, 0xe5, 0x60, 0x47, 0x33, 0x8b,
            0x4f, 0x1f,
        ];
        let r = load_r_clamped(&r_bytes);

        let messages: &[&[u8]] = &[b"", b"hello world", &[0x01; 47], &[0xAA; 256]];

        for msg in messages {
            let h_scalar = mac_scalar([0; 5], r, msg);
            // SAFETY: AVX2 feature detected above; mac_avx2 requires AVX2.
            // Arguments are valid: h=[0;5], r from load_r_clamped, msg is &[u8].
            let h_simd = unsafe { mac_avx2([0; 5], r, msg) };
            assert_eq!(h_scalar, h_simd);
        }
    }
}

#[cfg(all(test, target_arch = "aarch64"))]
mod tests_neon {
    use super::*;

    #[test]
    fn mac_neon_matches_scalar() {
        if !std::arch::is_aarch64_feature_detected!("neon") {
            return;
        }

        let r_bytes = [
            0x85, 0xd6, 0x96, 0x6a, 0x4c, 0xcd, 0x62, 0x16, 0x4b, 0xe5, 0x60, 0x47, 0x33, 0x8b,
            0x4f, 0x1f,
        ];
        let r = load_r_clamped(&r_bytes);

        let messages: &[&[u8]] = &[b"", b"hello world", &[0x01; 47], &[0xAA; 256]];

        for msg in messages {
            let h_scalar = mac_scalar([0; 5], r, msg);
            // SAFETY: NEON feature detected above; mac_neon requires NEON.
            // Arguments are valid: h=[0;5], r from load_r_clamped, msg is &[u8].
            let h_simd = unsafe { mac_neon([0; 5], r, msg) };
            assert_eq!(h_scalar, h_simd);
        }
    }
}

#[cfg(all(test, target_arch = "aarch64"))]
mod tests_sve2 {
    use super::*;

    #[test]
    fn mac_sve2_matches_scalar() {
        if !std::arch::is_aarch64_feature_detected!("sve2") {
            return;
        }

        let r_bytes = [
            0x85, 0xd6, 0x96, 0x6a, 0x4c, 0xcd, 0x62, 0x16, 0x4b, 0xe5, 0x60, 0x47, 0x33, 0x8b,
            0x4f, 0x1f,
        ];
        let r = load_r_clamped(&r_bytes);

        let messages: &[&[u8]] = &[b"", b"hello world", &[0x02; 63], &[0xCC; 320]];

        for msg in messages {
            let h_scalar = mac_scalar([0; 5], r, msg);
            // SAFETY: SVE2 feature detected above; mac_sve2 requires SVE2.
            // Arguments are valid: h=[0;5], r from load_r_clamped, msg is &[u8].
            let h_simd = unsafe { mac_sve2([0; 5], r, msg) };
            assert_eq!(h_scalar, h_simd);
        }
    }
}

fn finalize(h: &mut [u64; 5], one_time_key: &[u8; 32]) -> [u8; 16] {
    let mut c = h[1] >> 26;
    h[1] &= 0x3ffffff;
    h[2] += c;
    c = h[2] >> 26;
    h[2] &= 0x3ffffff;
    h[3] += c;
    c = h[3] >> 26;
    h[3] &= 0x3ffffff;
    h[4] += c;
    c = h[4] >> 26;
    h[4] &= 0x3ffffff;
    h[0] += c * 5;
    c = h[0] >> 26;
    h[0] &= 0x3ffffff;
    h[1] += c;

    let mut g0 = h[0] + 5;
    let mut c = g0 >> 26;
    g0 &= 0x3ffffff;
    let mut g1 = h[1] + c;
    c = g1 >> 26;
    g1 &= 0x3ffffff;
    let mut g2 = h[2] + c;
    c = g2 >> 26;
    g2 &= 0x3ffffff;
    let mut g3 = h[3] + c;
    c = g3 >> 26;
    g3 &= 0x3ffffff;
    let mut g4 = (h[4] + c).wrapping_sub(1 << 26);
    let mask = (g4 >> 63).wrapping_sub(1);
    g4 &= 0x3ffffff;
    let mut res = [0u64; 5];
    for i in 0..5 {
        let hi = h[i];
        let gi = [g0, g1, g2, g3, g4][i];
        res[i] = (hi & (!mask)) | (gi & mask);
    }

    let f0 = res[0] | (res[1] << 26);
    let f1 = (res[1] >> 6) | (res[2] << 20);
    let f2 = (res[2] >> 12) | (res[3] << 14);
    let f3 = (res[3] >> 18) | (res[4] << 8);

    let mut t = (f0 as u128) | ((f1 as u128) << 32) | ((f2 as u128) << 64) | ((f3 as u128) << 96);
    let mut s = [0u8; 16];
    s.copy_from_slice(&one_time_key[16..32]);
    t = t.wrapping_add(u128::from_le_bytes(s));
    t.to_le_bytes()
}

/// Compute Poly1305 tag over message with 32-byte one-time key (r||s).
pub fn tag(msg: &[u8], one_time_key: &[u8; 32]) -> [u8; 16] {
    let mut r16 = [0u8; 16];
    r16.copy_from_slice(&one_time_key[0..16]);
    r16[3] &= 15;
    r16[7] &= 15;
    r16[11] &= 15;
    r16[15] &= 15;
    r16[4] &= 252;
    r16[8] &= 252;
    r16[12] &= 252;
    let r = load_r_clamped(&r16);

    let mut h = [0u64; 5];
    h = mac(h, r, msg);
    finalize(&mut h, one_time_key)
}

/// AEAD construction for ChaCha20-Poly1305 (tag only) without intermediate allocations.
pub fn aead_tag_chacha20poly1305(
    aad: &[u8],
    ciphertext: &[u8],
    one_time_key: &[u8; 32],
) -> [u8; 16] {
    let mut r16 = [0u8; 16];
    r16.copy_from_slice(&one_time_key[0..16]);
    r16[3] &= 15;
    r16[7] &= 15;
    r16[11] &= 15;
    r16[15] &= 15;
    r16[4] &= 252;
    r16[8] &= 252;
    r16[12] &= 252;
    let r = load_r_clamped(&r16);

    let mut h = [0u64; 5];
    h = mac(h, r, aad);
    h = mac(h, r, ciphertext);

    let mut len_block = [0u8; 16];
    len_block[..8].copy_from_slice(&(aad.len() as u64).to_le_bytes());
    len_block[8..].copy_from_slice(&(ciphertext.len() as u64).to_le_bytes());
    h = mac(h, r, &len_block);

    finalize(&mut h, one_time_key)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_key() -> [u8; 32] {
        let mut k = [0u8; 32];
        for (i, byte) in k.iter_mut().enumerate() {
            *byte = (i as u8).wrapping_mul(7).wrapping_add(0x42);
        }
        k
    }

    #[test]
    fn test_tag_determinism() {
        let key = test_key();
        let msg = b"deterministic poly1305 check";
        let t1 = tag(msg, &key);
        let t2 = tag(msg, &key);
        assert_eq!(t1, t2, "same input must produce identical tags");
    }

    #[test]
    fn test_tag_empty_message() {
        let key = test_key();
        let t1 = tag(b"", &key);
        let t2 = tag(b"", &key);
        assert_eq!(t1, t2, "empty message tag must be deterministic");
        // Tag must not be all zeros (the s-part of the key is added in finalize)
        assert_ne!(t1, [0u8; 16], "empty message tag should not be all zeros");
    }

    #[test]
    fn test_tag_sensitivity_to_message() {
        let key = test_key();
        let msg_a = b"message alpha";
        let mut msg_b = *msg_a;
        msg_b[0] ^= 1; // flip one bit in first byte

        let tag_a = tag(msg_a, &key);
        let tag_b = tag(&msg_b, &key);
        assert_ne!(tag_a, tag_b, "one-bit message change must produce different tag");
    }

    #[test]
    fn test_tag_sensitivity_to_key() {
        let key_a = test_key();
        let mut key_b = key_a;
        key_b[0] ^= 1; // flip one bit in key

        let msg = b"key sensitivity test";
        let tag_a = tag(msg, &key_a);
        let tag_b = tag(msg, &key_b);
        assert_ne!(tag_a, tag_b, "one-bit key change must produce different tag");
    }

    #[test]
    fn test_tag_various_lengths() {
        let key = test_key();
        let lengths: &[usize] = &[1, 15, 16, 17, 31, 32, 33, 100];
        let mut previous_tags: Vec<[u8; 16]> = Vec::new();

        for &len in lengths {
            let msg: Vec<u8> = (0..len).map(|i| (i & 0xFF) as u8).collect();
            let t = tag(&msg, &key);

            // Deterministic: same input twice
            let t2 = tag(&msg, &key);
            assert_eq!(t, t2, "tag must be deterministic for length {len}");

            // Each length should produce a distinct tag (different message content)
            for (idx, prev) in previous_tags.iter().enumerate() {
                assert_ne!(&t, prev, "length {len} tag collides with earlier tag index {idx}");
            }
            previous_tags.push(t);
        }
    }

    #[test]
    fn test_aead_tag_determinism() {
        let key = test_key();
        let aad = b"associated data";
        let ct = b"ciphertext bytes";
        let t1 = aead_tag_chacha20poly1305(aad, ct, &key);
        let t2 = aead_tag_chacha20poly1305(aad, ct, &key);
        assert_eq!(t1, t2, "AEAD tag must be deterministic");
    }

    #[test]
    fn test_aead_tag_empty_inputs() {
        let key = test_key();
        let t1 = aead_tag_chacha20poly1305(b"", b"", &key);
        let t2 = aead_tag_chacha20poly1305(b"", b"", &key);
        assert_eq!(t1, t2, "empty AEAD tag must be deterministic");
        // Even with empty inputs, the length block (16 zero bytes) is still MAC'd
        assert_ne!(t1, [0u8; 16], "empty AEAD tag should not be all zeros");
    }

    #[test]
    fn test_aead_tag_different_aad_different_tag() {
        let key = test_key();
        let ct = b"same ciphertext";
        let tag_a = aead_tag_chacha20poly1305(b"aad alpha", ct, &key);
        let tag_b = aead_tag_chacha20poly1305(b"aad bravo", ct, &key);
        assert_ne!(tag_a, tag_b, "different AAD must produce different AEAD tag");
    }

    #[test]
    fn test_aead_tag_different_ciphertext_different_tag() {
        let key = test_key();
        let aad = b"same aad";
        let tag_a = aead_tag_chacha20poly1305(aad, b"ciphertext alpha", &key);
        let tag_b = aead_tag_chacha20poly1305(aad, b"ciphertext bravo", &key);
        assert_ne!(tag_a, tag_b, "different ciphertext must produce different AEAD tag");
    }
}
