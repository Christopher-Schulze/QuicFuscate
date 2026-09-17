//! Architecture-dispatched GF(2^16) slice operations for the FEC backend.

use qf_cpu::{CpuFeatures, FeatureDetector};

#[doc(hidden)]
pub const GF16_VBMI2_MIN_WORDS: usize = 32;
#[doc(hidden)]
pub const GF16_AVX512_MIN_WORDS: usize = 64;
#[doc(hidden)]
pub const GF16_AVX2_MIN_WORDS: usize = 32;
#[doc(hidden)]
pub const GF16_SSE2_MIN_WORDS: usize = 16;
#[doc(hidden)]
pub const GF16_SVE2_MIN_WORDS: usize = 24;
#[doc(hidden)]
pub const GF16_NEON_MIN_WORDS: usize = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[doc(hidden)]
pub enum SimdLevel {
    None,
    Sse2,
    Avx2,
    Avx512Vbmi2,
    Avx512Vbmi,
    Sve2,
    Neon,
}

#[inline(always)]
#[doc(hidden)]
pub fn fec_simd_level_for_features(features: &CpuFeatures) -> SimdLevel {
    let matrix = features.simd_dispatch_matrix();

    if matrix.avx512_vbmi2 {
        SimdLevel::Avx512Vbmi2
    } else if matrix.avx512_vbmi {
        SimdLevel::Avx512Vbmi
    } else if matrix.avx2 {
        SimdLevel::Avx2
    } else if features.sse2 {
        SimdLevel::Sse2
    } else if matrix.sve2 {
        SimdLevel::Sve2
    } else if matrix.neon {
        SimdLevel::Neon
    } else {
        SimdLevel::None
    }
}

#[inline(always)]
#[doc(hidden)]
pub fn gf16_vector_threshold_words_for_features(features: &CpuFeatures) -> usize {
    match fec_simd_level_for_features(features) {
        SimdLevel::Avx512Vbmi2 => GF16_VBMI2_MIN_WORDS,
        SimdLevel::Avx512Vbmi => GF16_AVX512_MIN_WORDS,
        SimdLevel::Avx2 => GF16_AVX2_MIN_WORDS,
        SimdLevel::Sse2 => GF16_SSE2_MIN_WORDS,
        SimdLevel::Sve2 => GF16_SVE2_MIN_WORDS,
        SimdLevel::Neon => GF16_NEON_MIN_WORDS,
        SimdLevel::None => usize::MAX,
    }
}

#[inline(always)]
fn gf16_vector_threshold_words() -> usize {
    gf16_vector_threshold_words_for_features(FeatureDetector::instance().features_full())
}

/// Nibble lookup tables for GF(2^16) multiply-by-constant: table `k` maps a
/// 4-bit nibble value `n` to `coeff * (n << 4k)`, byte-split into lo/hi halves
/// so each table fits one 16-byte shuffle lane. `t_k[0] == 0` for all `k`, so
/// the zeroed odd bytes of a u16-lane index vector select element 0 and stay
/// harmless — no index masking needed.
#[inline]
fn gf16_nibble_byte_tables(coeff: u16) -> ([[u8; 16]; 4], [[u8; 16]; 4]) {
    let mut lo = [[0u8; 16]; 4];
    let mut hi = [[0u8; 16]; 4];
    for (k, (lo_t, hi_t)) in lo.iter_mut().zip(hi.iter_mut()).enumerate() {
        for n in 0..16usize {
            let value = crate::gf_tables::gf16_mul(coeff, (n as u16) << (4 * k));
            lo_t[n] = value as u8;
            hi_t[n] = (value >> 8) as u8;
        }
    }
    (lo, hi)
}

/// Scalar tail shared by all byte-path kernels: processes whole u16 words only
/// and leaves a trailing odd byte untouched, matching the reference loop.
#[inline]
fn gf16_mul_bytes_tail(coeff: u16, src: &[u8], out_xor: &mut [u8], word: usize, words: usize) {
    let mut w = word;
    while w < words {
        let source = u16::from_be_bytes([src[2 * w], src[2 * w + 1]]);
        let target = u16::from_be_bytes([out_xor[2 * w], out_xor[2 * w + 1]]);
        let value = crate::gf_tables::gf16_mul_add(coeff, source, target).to_be_bytes();
        out_xor[2 * w] = value[0];
        out_xor[2 * w + 1] = value[1];
        w += 1;
    }
}

/// Vectorized GF(2^16) scalar multiply-and-xor over big-endian byte slices.
/// out_xor[j..j+2] ^= gf16_mul(coeff, src[j..j+2]) for all j in steps of 2.
#[inline]
#[doc(hidden)]
pub fn gf16_mul_scalar_slice_u16(coeff: u16, src: &[u8], out_xor: &mut [u8]) {
    let len = src.len().min(out_xor.len());
    let packet_u16_len = len / 2;
    if coeff == 0 || packet_u16_len == 0 {
        return;
    }

    if coeff == 1 {
        for (source, target) in src[..len].iter().zip(out_xor[..len].iter_mut()) {
            *target ^= *source;
        }
        return;
    }

    // One policy resolution per call; the byte-path kernels swap endianness
    // in-register and consume whole packets instead of 64-word stack chunks.
    let dispatched = qf_cpu::dispatch_bitslice(|policy| {
        #[cfg(target_arch = "x86_64")]
        {
            if policy.as_any().is::<qf_cpu::Avx512Vbmi2>() && packet_u16_len >= GF16_VBMI2_MIN_WORDS
            {
                unsafe {
                    gf16_mul_bytes_vbmi2(coeff, src, out_xor);
                }
                return true;
            }
            if policy.as_any().is::<qf_cpu::Avx512>()
                && packet_u16_len >= GF16_AVX512_MIN_WORDS
                && FeatureDetector::instance().features_full().avx512bw
            {
                unsafe {
                    gf16_mul_bytes_avx512(coeff, src, out_xor);
                }
                return true;
            }
            if policy.as_any().is::<qf_cpu::Avx2>() && packet_u16_len >= GF16_AVX2_MIN_WORDS {
                unsafe {
                    gf16_mul_bytes_avx2(coeff, src, out_xor);
                }
                return true;
            }
            if policy.as_any().is::<qf_cpu::Sse2>() && packet_u16_len >= GF16_SSE2_MIN_WORDS {
                unsafe {
                    gf16_mul_bytes_sse2(coeff, src, out_xor);
                }
                return true;
            }
        }
        #[cfg(target_arch = "aarch64")]
        {
            if policy.as_any().is::<qf_cpu::Neon>() && packet_u16_len >= GF16_NEON_MIN_WORDS {
                unsafe {
                    gf16_mul_bytes_neon(coeff, src, out_xor);
                }
                return true;
            }
        }
        let _ = policy;
        false
    });
    if dispatched {
        return;
    }

    // Fallback for the SVE2 and scalar policies: buffered conversion into
    // bounded stack windows, then the native-u16 kernel.
    let vector_threshold = gf16_vector_threshold_words();
    const CHUNK_SIZE: usize = 64;

    if vector_threshold != usize::MAX && packet_u16_len >= vector_threshold {
        let mut offset = 0;
        while offset < packet_u16_len {
            let chunk_len = (packet_u16_len - offset).min(CHUNK_SIZE);
            let mut source_words = [0u16; CHUNK_SIZE];
            let mut target_words = [0u16; CHUNK_SIZE];

            for (index, (source_word, target_word)) in
                source_words.iter_mut().zip(target_words.iter_mut()).take(chunk_len).enumerate()
            {
                let byte_offset = (offset + index) * 2;
                *source_word = u16::from_be_bytes([src[byte_offset], src[byte_offset + 1]]);
                *target_word = u16::from_be_bytes([out_xor[byte_offset], out_xor[byte_offset + 1]]);
            }

            gf16_mul_slice(coeff, &source_words[..chunk_len], &mut target_words[..chunk_len]);

            for (index, value) in target_words[..chunk_len].iter().enumerate() {
                let byte_offset = (offset + index) * 2;
                let bytes = value.to_be_bytes();
                out_xor[byte_offset] = bytes[0];
                out_xor[byte_offset + 1] = bytes[1];
            }

            offset += chunk_len;
        }
    } else {
        let mut offset = 0;
        while offset + 1 < len {
            let source = u16::from_be_bytes([src[offset], src[offset + 1]]);
            let target = u16::from_be_bytes([out_xor[offset], out_xor[offset + 1]]);
            let value = crate::gf_tables::gf16_mul_add(coeff, source, target);
            let bytes = value.to_be_bytes();
            out_xor[offset] = bytes[0];
            out_xor[offset + 1] = bytes[1];
            offset += 2;
        }
    }
}

#[inline]
#[doc(hidden)]
pub fn gf16_mul_scalar_slice_padded(coeff: u16, src: &[u8], out_xor: &mut [u8]) {
    let source_len = src.len().min(out_xor.len());
    let even_len = source_len & !1;
    if even_len > 0 {
        gf16_mul_scalar_slice_u16(coeff, &src[..even_len], &mut out_xor[..even_len]);
    }
    if source_len != even_len && even_len + 1 < out_xor.len() {
        let product = crate::gf_tables::gf16_mul(coeff, u16::from_be_bytes([src[even_len], 0]));
        let bytes = product.to_be_bytes();
        out_xor[even_len] ^= bytes[0];
        out_xor[even_len + 1] ^= bytes[1];
    }
}

#[inline(always)]
#[doc(hidden)]
pub fn bounded_u16_len(src: &[u16], dst: &[u16], requested: usize) -> usize {
    requested.min(src.len()).min(dst.len())
}

/// Paired VBMI2 table registers: contribution `k` is looked up by
/// `permutex2var_epi16` with plain nibble indices for `k = 0` and
/// `nibble + 32` for `k > 0`, so the `a` registers of `k > 0` stay zeroed.
#[cfg(target_arch = "x86_64")]
#[derive(Clone, Copy)]
struct Vbmi2Tables {
    t0a: std::arch::x86_64::__m512i,
    t0b: std::arch::x86_64::__m512i,
    t1a: std::arch::x86_64::__m512i,
    t1b: std::arch::x86_64::__m512i,
    t2a: std::arch::x86_64::__m512i,
    t2b: std::arch::x86_64::__m512i,
    t3a: std::arch::x86_64::__m512i,
    t3b: std::arch::x86_64::__m512i,
    nibble_mask: std::arch::x86_64::__m512i,
    table_offset: std::arch::x86_64::__m512i,
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx512f", enable = "avx512bw", enable = "avx512vbmi2")]
unsafe fn vbmi2_tables(coeff: u16) -> Vbmi2Tables {
    use std::arch::x86_64::*;

    #[repr(align(64))]
    struct Table([u16; 32]);

    let mut table0_a = Table([0u16; 32]);
    let mut table0_b = Table([0u16; 32]);
    let mut table1_b = Table([0u16; 32]);
    let mut table2_b = Table([0u16; 32]);
    let mut table3_b = Table([0u16; 32]);

    for nibble in 0..16u16 {
        let base = nibble as usize;
        let contribution0 = crate::gf_tables::gf16_mul(coeff, nibble);
        table0_a.0[base] = contribution0;
        table0_a.0[base + 16] = contribution0;
        table0_b.0[base] = contribution0;
        table0_b.0[base + 16] = contribution0;

        let contribution1 = crate::gf_tables::gf16_mul(coeff, nibble << 4);
        table1_b.0[base] = contribution1;
        table1_b.0[base + 16] = contribution1;

        let contribution2 = crate::gf_tables::gf16_mul(coeff, nibble << 8);
        table2_b.0[base] = contribution2;
        table2_b.0[base + 16] = contribution2;

        let contribution3 = crate::gf_tables::gf16_mul(coeff, nibble << 12);
        table3_b.0[base] = contribution3;
        table3_b.0[base + 16] = contribution3;
    }

    Vbmi2Tables {
        t0a: _mm512_loadu_si512(table0_a.0.as_ptr() as *const __m512i),
        t0b: _mm512_loadu_si512(table0_b.0.as_ptr() as *const __m512i),
        t1a: _mm512_setzero_si512(),
        t1b: _mm512_loadu_si512(table1_b.0.as_ptr() as *const __m512i),
        t2a: _mm512_setzero_si512(),
        t2b: _mm512_loadu_si512(table2_b.0.as_ptr() as *const __m512i),
        t3a: _mm512_setzero_si512(),
        t3b: _mm512_loadu_si512(table3_b.0.as_ptr() as *const __m512i),
        nibble_mask: _mm512_set1_epi16(0x000F),
        table_offset: _mm512_set1_epi16(32),
    }
}

/// GF(2^16) multiply of one 32-word vector by the constant behind `t`.
#[cfg(target_arch = "x86_64")]
#[inline]
#[target_feature(enable = "avx512f", enable = "avx512bw", enable = "avx512vbmi2")]
unsafe fn vbmi2_product(
    t: &Vbmi2Tables,
    source: std::arch::x86_64::__m512i,
) -> std::arch::x86_64::__m512i {
    use std::arch::x86_64::*;

    let nibble0 = _mm512_and_si512(source, t.nibble_mask);
    let nibble1 = _mm512_and_si512(_mm512_srli_epi16(source, 4), t.nibble_mask);
    let nibble2 = _mm512_and_si512(_mm512_srli_epi16(source, 8), t.nibble_mask);
    let nibble3 = _mm512_srli_epi16(source, 12);

    let index1 = _mm512_add_epi16(nibble1, t.table_offset);
    let index2 = _mm512_add_epi16(nibble2, t.table_offset);
    let index3 = _mm512_add_epi16(nibble3, t.table_offset);

    let contribution0 = _mm512_permutex2var_epi16(t.t0a, nibble0, t.t0b);
    let contribution1 = _mm512_permutex2var_epi16(t.t1a, index1, t.t1b);
    let contribution2 = _mm512_permutex2var_epi16(t.t2a, index2, t.t2b);
    let contribution3 = _mm512_permutex2var_epi16(t.t3a, index3, t.t3b);

    let partial = _mm512_xor_si512(_mm512_xor_si512(contribution0, contribution1), contribution2);
    _mm512_xor_si512(partial, contribution3)
}

/// Per-128-bit-lane byteswap of u16 elements (vpshufb, AVX512BW only needs the
/// broadcasted 16-byte pattern; identical mask in every lane).
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx512f", enable = "avx512bw")]
unsafe fn gf16_swap16_512(w: std::arch::x86_64::__m512i) -> std::arch::x86_64::__m512i {
    use std::arch::x86_64::*;
    let lane = _mm_setr_epi8(1, 0, 3, 2, 5, 4, 7, 6, 9, 8, 11, 10, 13, 12, 15, 14);
    let mask = _mm512_broadcast_i32x4(lane);
    _mm512_shuffle_epi8(w, mask)
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx512f", enable = "avx512bw", enable = "avx512vbmi2")]
/// # Safety
///
/// The caller must prove AVX512F, AVX512BW, and AVX512VBMI2 support. `src` and
/// `dst` must remain valid for the duration of the call; `len` is bounded to
/// both slice lengths before any vector access.
pub unsafe fn gf16_mul_slice_vbmi2(coeff: u16, src: &[u16], dst: &mut [u16], len: usize) {
    use std::arch::x86_64::*;
    let len = bounded_u16_len(src, dst, len);

    if len == 0 {
        return;
    }

    let tables = vbmi2_tables(coeff);

    let mut offset = 0usize;
    while offset + 32 <= len {
        let source = _mm512_loadu_si512(src.as_ptr().add(offset) as *const __m512i);
        let target = _mm512_loadu_si512(dst.as_ptr().add(offset) as *const __m512i);
        let result = _mm512_xor_si512(target, vbmi2_product(&tables, source));
        _mm512_storeu_si512(dst.as_mut_ptr().add(offset) as *mut __m512i, result);
        offset += 32;
    }

    while offset < len {
        dst[offset] ^= crate::gf_tables::gf16_mul(coeff, src[offset]);
        offset += 1;
    }

    qf_telemetry::FEC_GF16_VBMI2_OPS.inc();
}

/// Big-endian byte-payload variant: swaps each 64-byte block into native u16
/// lanes in-register, multiplies, and XORs the swapped product bytes into the
/// destination — no stack conversion buffers.
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx512f", enable = "avx512bw", enable = "avx512vbmi2")]
/// # Safety
///
/// The caller must prove AVX512F, AVX512BW, and AVX512VBMI2 support. `src` and
/// `out_xor` must remain valid for the duration of the call; only whole u16
/// words inside the shared length are touched.
unsafe fn gf16_mul_bytes_vbmi2(coeff: u16, src: &[u8], out_xor: &mut [u8]) {
    use std::arch::x86_64::*;
    let byte_len = src.len().min(out_xor.len());
    let words = byte_len / 2;
    if words == 0 {
        return;
    }

    let tables = vbmi2_tables(coeff);

    let mut word = 0usize;
    while word + 32 <= words {
        let byte_offset = word * 2;
        let raw = _mm512_loadu_si512(src.as_ptr().add(byte_offset) as *const __m512i);
        let product = vbmi2_product(&tables, gf16_swap16_512(raw));
        let product_be = gf16_swap16_512(product);
        let target = _mm512_loadu_si512(out_xor.as_ptr().add(byte_offset) as *const __m512i);
        _mm512_storeu_si512(
            out_xor.as_mut_ptr().add(byte_offset) as *mut __m512i,
            _mm512_xor_si512(target, product_be),
        );
        word += 32;
    }

    gf16_mul_bytes_tail(coeff, src, out_xor, word, words);
    qf_telemetry::FEC_GF16_VBMI2_OPS.inc();
}

/// Combined lo/hi nibble tables for `permutexvar_epi8`: 64 bytes each,
/// `[t0, t1, t2, t3]` laid end to end so nibble `k` is selected by index
/// `n + 16k` (u16 lane add, no carry since `n + 48 <= 63`).
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx512f", enable = "avx512bw", enable = "avx512vbmi")]
unsafe fn avx512_byte_tables(
    coeff: u16,
) -> (std::arch::x86_64::__m512i, std::arch::x86_64::__m512i) {
    use std::arch::x86_64::*;
    let (lo, hi) = gf16_nibble_byte_tables(coeff);
    let mut lo64 = [0u8; 64];
    let mut hi64 = [0u8; 64];
    for k in 0..4 {
        lo64[k * 16..k * 16 + 16].copy_from_slice(&lo[k]);
        hi64[k * 16..k * 16 + 16].copy_from_slice(&hi[k]);
    }
    (
        _mm512_loadu_si512(lo64.as_ptr() as *const __m512i),
        _mm512_loadu_si512(hi64.as_ptr() as *const __m512i),
    )
}

/// GF(2^16) multiply of one 32-word vector via `permutexvar_epi8`: per nibble
/// `k` the index vector `n + 16k` selects the lo byte from `lot` and the hi
/// byte from `hit`; odd index bytes are 0 and select table entry 0, which is
/// always 0 (`t_k[0] = coeff * 0`), so no index masking is required.
#[cfg(target_arch = "x86_64")]
#[inline]
#[target_feature(enable = "avx512f", enable = "avx512bw", enable = "avx512vbmi")]
unsafe fn avx512_product(
    lot: std::arch::x86_64::__m512i,
    hit: std::arch::x86_64::__m512i,
    source: std::arch::x86_64::__m512i,
) -> std::arch::x86_64::__m512i {
    use std::arch::x86_64::*;

    let nibble_mask = _mm512_set1_epi16(0x000F);
    let n0 = _mm512_and_si512(source, nibble_mask);
    let n1 = _mm512_and_si512(_mm512_srli_epi16(source, 4), nibble_mask);
    let n2 = _mm512_and_si512(_mm512_srli_epi16(source, 8), nibble_mask);
    let n3 = _mm512_srli_epi16(source, 12);

    let i1 = _mm512_add_epi16(n1, _mm512_set1_epi16(16));
    let i2 = _mm512_add_epi16(n2, _mm512_set1_epi16(32));
    let i3 = _mm512_add_epi16(n3, _mm512_set1_epi16(48));

    let c0 = _mm512_or_si512(
        _mm512_permutexvar_epi8(n0, lot),
        _mm512_slli_epi16(_mm512_permutexvar_epi8(n0, hit), 8),
    );
    let c1 = _mm512_or_si512(
        _mm512_permutexvar_epi8(i1, lot),
        _mm512_slli_epi16(_mm512_permutexvar_epi8(i1, hit), 8),
    );
    let c2 = _mm512_or_si512(
        _mm512_permutexvar_epi8(i2, lot),
        _mm512_slli_epi16(_mm512_permutexvar_epi8(i2, hit), 8),
    );
    let c3 = _mm512_or_si512(
        _mm512_permutexvar_epi8(i3, lot),
        _mm512_slli_epi16(_mm512_permutexvar_epi8(i3, hit), 8),
    );

    _mm512_xor_si512(_mm512_xor_si512(c0, c1), _mm512_xor_si512(c2, c3))
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx512f", enable = "avx512bw", enable = "avx512vbmi")]
/// # Safety
///
/// The caller must prove AVX512F, AVX512BW, and AVX512VBMI support. `src` and
/// `dst` must remain valid for the duration of the call; `len` is bounded to
/// both slice lengths before the loop accesses either slice.
unsafe fn gf16_mul_slice_avx512(coeff: u16, src: &[u16], dst: &mut [u16], len: usize) {
    use std::arch::x86_64::*;
    let len = bounded_u16_len(src, dst, len);
    if len == 0 {
        return;
    }

    let (lot, hit) = avx512_byte_tables(coeff);

    let mut offset = 0usize;
    while offset + 32 <= len {
        let source = _mm512_loadu_si512(src.as_ptr().add(offset) as *const __m512i);
        let target = _mm512_loadu_si512(dst.as_ptr().add(offset) as *const __m512i);
        let result = _mm512_xor_si512(target, avx512_product(lot, hit, source));
        _mm512_storeu_si512(dst.as_mut_ptr().add(offset) as *mut __m512i, result);
        offset += 32;
    }
    while offset < len {
        dst[offset] ^= crate::gf_tables::gf16_mul(coeff, src[offset]);
        offset += 1;
    }
    qf_telemetry::FEC_AVX512_OPS.inc();
}

/// Big-endian byte-payload variant of the VBMI kernel.
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx512f", enable = "avx512bw", enable = "avx512vbmi")]
/// # Safety
///
/// The caller must prove AVX512F, AVX512BW, and AVX512VBMI support. `src` and
/// `out_xor` must remain valid for the duration of the call; only whole u16
/// words inside the shared length are touched.
unsafe fn gf16_mul_bytes_avx512(coeff: u16, src: &[u8], out_xor: &mut [u8]) {
    use std::arch::x86_64::*;
    let byte_len = src.len().min(out_xor.len());
    let words = byte_len / 2;
    if words == 0 {
        return;
    }

    let (lot, hit) = avx512_byte_tables(coeff);

    let mut word = 0usize;
    while word + 32 <= words {
        let byte_offset = word * 2;
        let raw = _mm512_loadu_si512(src.as_ptr().add(byte_offset) as *const __m512i);
        let product = avx512_product(lot, hit, gf16_swap16_512(raw));
        let product_be = gf16_swap16_512(product);
        let target = _mm512_loadu_si512(out_xor.as_ptr().add(byte_offset) as *const __m512i);
        _mm512_storeu_si512(
            out_xor.as_mut_ptr().add(byte_offset) as *mut __m512i,
            _mm512_xor_si512(target, product_be),
        );
        word += 32;
    }

    gf16_mul_bytes_tail(coeff, src, out_xor, word, words);
    qf_telemetry::FEC_AVX512_OPS.inc();
}

/// AVX2 nibble tables: each 16-byte half-table broadcast into both lanes.
#[cfg(target_arch = "x86_64")]
#[derive(Clone, Copy)]
struct Avx2Tables {
    t0l: std::arch::x86_64::__m256i,
    t1l: std::arch::x86_64::__m256i,
    t2l: std::arch::x86_64::__m256i,
    t3l: std::arch::x86_64::__m256i,
    t0h: std::arch::x86_64::__m256i,
    t1h: std::arch::x86_64::__m256i,
    t2h: std::arch::x86_64::__m256i,
    t3h: std::arch::x86_64::__m256i,
    nibble_mask: std::arch::x86_64::__m256i,
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
unsafe fn avx2_tables(coeff: u16) -> Avx2Tables {
    use std::arch::x86_64::*;
    let (lo, hi) = gf16_nibble_byte_tables(coeff);
    Avx2Tables {
        t0l: _mm256_broadcastsi128_si256(_mm_loadu_si128(lo[0].as_ptr() as *const __m128i)),
        t1l: _mm256_broadcastsi128_si256(_mm_loadu_si128(lo[1].as_ptr() as *const __m128i)),
        t2l: _mm256_broadcastsi128_si256(_mm_loadu_si128(lo[2].as_ptr() as *const __m128i)),
        t3l: _mm256_broadcastsi128_si256(_mm_loadu_si128(lo[3].as_ptr() as *const __m128i)),
        t0h: _mm256_broadcastsi128_si256(_mm_loadu_si128(hi[0].as_ptr() as *const __m128i)),
        t1h: _mm256_broadcastsi128_si256(_mm_loadu_si128(hi[1].as_ptr() as *const __m128i)),
        t2h: _mm256_broadcastsi128_si256(_mm_loadu_si128(hi[2].as_ptr() as *const __m128i)),
        t3h: _mm256_broadcastsi128_si256(_mm_loadu_si128(hi[3].as_ptr() as *const __m128i)),
        nibble_mask: _mm256_set1_epi16(0x000F),
    }
}

/// GF(2^16) multiply of one 16-word vector via `vpshufb`: per nibble `k`,
/// `shuffle(tk_lo, nk)` yields the lo byte (odd index bytes are 0 and select
/// table entry 0, which is always 0), `shuffle(tk_hi, nk) << 8` the hi byte.
#[cfg(target_arch = "x86_64")]
#[inline]
#[target_feature(enable = "avx2")]
unsafe fn avx2_product(
    t: &Avx2Tables,
    source: std::arch::x86_64::__m256i,
) -> std::arch::x86_64::__m256i {
    use std::arch::x86_64::*;

    let n0 = _mm256_and_si256(source, t.nibble_mask);
    let n1 = _mm256_and_si256(_mm256_srli_epi16(source, 4), t.nibble_mask);
    let n2 = _mm256_and_si256(_mm256_srli_epi16(source, 8), t.nibble_mask);
    let n3 = _mm256_srli_epi16(source, 12);

    let c0 = _mm256_or_si256(
        _mm256_shuffle_epi8(t.t0l, n0),
        _mm256_slli_epi16(_mm256_shuffle_epi8(t.t0h, n0), 8),
    );
    let c1 = _mm256_or_si256(
        _mm256_shuffle_epi8(t.t1l, n1),
        _mm256_slli_epi16(_mm256_shuffle_epi8(t.t1h, n1), 8),
    );
    let c2 = _mm256_or_si256(
        _mm256_shuffle_epi8(t.t2l, n2),
        _mm256_slli_epi16(_mm256_shuffle_epi8(t.t2h, n2), 8),
    );
    let c3 = _mm256_or_si256(
        _mm256_shuffle_epi8(t.t3l, n3),
        _mm256_slli_epi16(_mm256_shuffle_epi8(t.t3h, n3), 8),
    );

    _mm256_xor_si256(_mm256_xor_si256(c0, c1), _mm256_xor_si256(c2, c3))
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
/// # Safety
///
/// The caller must prove AVX2 support. `src` and `dst` must remain valid for
/// the duration of the call; `len` is bounded to both slice lengths before
/// the loop accesses either slice.
unsafe fn gf16_mul_slice_avx2(coeff: u16, src: &[u16], dst: &mut [u16], len: usize) {
    use std::arch::x86_64::*;
    let len = bounded_u16_len(src, dst, len);
    if len == 0 {
        return;
    }

    let tables = avx2_tables(coeff);

    let mut offset = 0usize;
    while offset + 16 <= len {
        let source = _mm256_loadu_si256(src.as_ptr().add(offset) as *const __m256i);
        let target = _mm256_loadu_si256(dst.as_ptr().add(offset) as *const __m256i);
        let result = _mm256_xor_si256(target, avx2_product(&tables, source));
        _mm256_storeu_si256(dst.as_mut_ptr().add(offset) as *mut __m256i, result);
        offset += 16;
    }
    while offset < len {
        dst[offset] ^= crate::gf_tables::gf16_mul(coeff, src[offset]);
        offset += 1;
    }
    qf_telemetry::FEC_AVX2_OPS.inc();
}

/// Big-endian byte-payload variant of the AVX2 kernel.
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
/// # Safety
///
/// The caller must prove AVX2 support. `src` and `out_xor` must remain valid
/// for the duration of the call; only whole u16 words inside the shared
/// length are touched.
unsafe fn gf16_mul_bytes_avx2(coeff: u16, src: &[u8], out_xor: &mut [u8]) {
    use std::arch::x86_64::*;
    let byte_len = src.len().min(out_xor.len());
    let words = byte_len / 2;
    if words == 0 {
        return;
    }

    let tables = avx2_tables(coeff);
    let swap = _mm256_broadcastsi128_si256(_mm_setr_epi8(
        1, 0, 3, 2, 5, 4, 7, 6, 9, 8, 11, 10, 13, 12, 15, 14,
    ));

    let mut word = 0usize;
    while word + 16 <= words {
        let byte_offset = word * 2;
        let raw = _mm256_loadu_si256(src.as_ptr().add(byte_offset) as *const __m256i);
        let product = avx2_product(&tables, _mm256_shuffle_epi8(raw, swap));
        let product_be = _mm256_shuffle_epi8(product, swap);
        let target = _mm256_loadu_si256(out_xor.as_ptr().add(byte_offset) as *const __m256i);
        _mm256_storeu_si256(
            out_xor.as_mut_ptr().add(byte_offset) as *mut __m256i,
            _mm256_xor_si256(target, product_be),
        );
        word += 16;
    }

    gf16_mul_bytes_tail(coeff, src, out_xor, word, words);
    qf_telemetry::FEC_AVX2_OPS.inc();
}

/// Vectorized carryless multiply for SSE2 (no byte shuffle exists before
/// SSSE3): 8 u16 lanes processed by a 16-round shift/mask/reduce loop —
/// honest SIMD where the only alternative is the scalar loop.
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "sse2")]
/// # Safety
///
/// The caller must prove SSE2 support. `src` and `dst` must remain valid for
/// the duration of the call; `len` is bounded to both slice lengths before
/// the loop accesses either slice.
unsafe fn gf16_mul_slice_sse2(coeff: u16, src: &[u16], dst: &mut [u16], len: usize) {
    use std::arch::x86_64::*;
    let len = bounded_u16_len(src, dst, len);
    if len == 0 {
        return;
    }

    let one = _mm_set1_epi16(1);
    let polynomial = _mm_set1_epi16(0x100B);

    let mut offset = 0usize;
    while offset + 8 <= len {
        let mut multiplicand = _mm_loadu_si128(src.as_ptr().add(offset) as *const __m128i);
        let mut factor = _mm_set1_epi16(coeff as i16);
        let mut product = _mm_setzero_si128();
        let target = _mm_loadu_si128(dst.as_ptr().add(offset) as *const __m128i);

        for _ in 0..16 {
            let factor_mask = _mm_cmpeq_epi16(_mm_and_si128(factor, one), one);
            product = _mm_xor_si128(product, _mm_and_si128(multiplicand, factor_mask));
            let carry_mask = _mm_cmpeq_epi16(_mm_srli_epi16(multiplicand, 15), one);
            multiplicand = _mm_xor_si128(
                _mm_slli_epi16(multiplicand, 1),
                _mm_and_si128(polynomial, carry_mask),
            );
            factor = _mm_srli_epi16(factor, 1);
        }

        _mm_storeu_si128(
            dst.as_mut_ptr().add(offset) as *mut __m128i,
            _mm_xor_si128(target, product),
        );
        offset += 8;
    }
    while offset < len {
        dst[offset] ^= crate::gf_tables::gf16_mul(coeff, src[offset]);
        offset += 1;
    }
}

/// Big-endian byte-payload variant of the SSE2 kernel; byteswaps via
/// shift-or since SSE2 lacks a byte shuffle.
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "sse2")]
/// # Safety
///
/// The caller must prove SSE2 support. `src` and `out_xor` must remain valid
/// for the duration of the call; only whole u16 words inside the shared
/// length are touched.
unsafe fn gf16_mul_bytes_sse2(coeff: u16, src: &[u8], out_xor: &mut [u8]) {
    use std::arch::x86_64::*;
    let byte_len = src.len().min(out_xor.len());
    let words = byte_len / 2;
    if words == 0 {
        return;
    }

    let one = _mm_set1_epi16(1);
    let polynomial = _mm_set1_epi16(0x100B);

    let mut word = 0usize;
    while word + 8 <= words {
        let byte_offset = word * 2;
        let raw = _mm_loadu_si128(src.as_ptr().add(byte_offset) as *const __m128i);
        let mut multiplicand = _mm_or_si128(_mm_slli_epi16(raw, 8), _mm_srli_epi16(raw, 8));
        let mut factor = _mm_set1_epi16(coeff as i16);
        let mut product = _mm_setzero_si128();

        for _ in 0..16 {
            let factor_mask = _mm_cmpeq_epi16(_mm_and_si128(factor, one), one);
            product = _mm_xor_si128(product, _mm_and_si128(multiplicand, factor_mask));
            let carry_mask = _mm_cmpeq_epi16(_mm_srli_epi16(multiplicand, 15), one);
            multiplicand = _mm_xor_si128(
                _mm_slli_epi16(multiplicand, 1),
                _mm_and_si128(polynomial, carry_mask),
            );
            factor = _mm_srli_epi16(factor, 1);
        }

        let product_be = _mm_or_si128(_mm_slli_epi16(product, 8), _mm_srli_epi16(product, 8));
        let target = _mm_loadu_si128(out_xor.as_ptr().add(byte_offset) as *const __m128i);
        _mm_storeu_si128(
            out_xor.as_mut_ptr().add(byte_offset) as *mut __m128i,
            _mm_xor_si128(target, product_be),
        );
        word += 8;
    }

    gf16_mul_bytes_tail(coeff, src, out_xor, word, words);
}

/// NEON nibble tables: each 16-byte half-table loaded once per call.
#[cfg(target_arch = "aarch64")]
#[derive(Clone, Copy)]
struct NeonTables {
    t0l: std::arch::aarch64::uint8x16_t,
    t1l: std::arch::aarch64::uint8x16_t,
    t2l: std::arch::aarch64::uint8x16_t,
    t3l: std::arch::aarch64::uint8x16_t,
    t0h: std::arch::aarch64::uint8x16_t,
    t1h: std::arch::aarch64::uint8x16_t,
    t2h: std::arch::aarch64::uint8x16_t,
    t3h: std::arch::aarch64::uint8x16_t,
    nibble_mask: std::arch::aarch64::uint16x8_t,
}

#[cfg(target_arch = "aarch64")]
#[target_feature(enable = "neon")]
unsafe fn neon_tables(coeff: u16) -> NeonTables {
    use std::arch::aarch64::*;
    let (lo, hi) = gf16_nibble_byte_tables(coeff);
    NeonTables {
        t0l: vld1q_u8(lo[0].as_ptr()),
        t1l: vld1q_u8(lo[1].as_ptr()),
        t2l: vld1q_u8(lo[2].as_ptr()),
        t3l: vld1q_u8(lo[3].as_ptr()),
        t0h: vld1q_u8(hi[0].as_ptr()),
        t1h: vld1q_u8(hi[1].as_ptr()),
        t2h: vld1q_u8(hi[2].as_ptr()),
        t3h: vld1q_u8(hi[3].as_ptr()),
        nibble_mask: vdupq_n_u16(0x000F),
    }
}

/// GF(2^16) multiply of one 8-word vector via `vqtbl1q_u8`: per nibble `k`,
/// `tbl(tk_lo, nk)` yields the lo byte and `tbl(tk_hi, nk) << 8` the hi byte.
/// Odd index bytes are 0 and select table entry 0, which is always 0.
#[cfg(target_arch = "aarch64")]
#[inline]
#[target_feature(enable = "neon")]
unsafe fn neon_product(
    t: &NeonTables,
    source: std::arch::aarch64::uint16x8_t,
) -> std::arch::aarch64::uint16x8_t {
    use std::arch::aarch64::*;

    let n0 = vandq_u16(source, t.nibble_mask);
    let n1 = vandq_u16(vshrq_n_u16(source, 4), t.nibble_mask);
    let n2 = vandq_u16(vshrq_n_u16(source, 8), t.nibble_mask);
    let n3 = vshrq_n_u16(source, 12);

    let c0 = vorrq_u16(
        vreinterpretq_u16_u8(vqtbl1q_u8(t.t0l, vreinterpretq_u8_u16(n0))),
        vshlq_n_u16(vreinterpretq_u16_u8(vqtbl1q_u8(t.t0h, vreinterpretq_u8_u16(n0))), 8),
    );
    let c1 = vorrq_u16(
        vreinterpretq_u16_u8(vqtbl1q_u8(t.t1l, vreinterpretq_u8_u16(n1))),
        vshlq_n_u16(vreinterpretq_u16_u8(vqtbl1q_u8(t.t1h, vreinterpretq_u8_u16(n1))), 8),
    );
    let c2 = vorrq_u16(
        vreinterpretq_u16_u8(vqtbl1q_u8(t.t2l, vreinterpretq_u8_u16(n2))),
        vshlq_n_u16(vreinterpretq_u16_u8(vqtbl1q_u8(t.t2h, vreinterpretq_u8_u16(n2))), 8),
    );
    let c3 = vorrq_u16(
        vreinterpretq_u16_u8(vqtbl1q_u8(t.t3l, vreinterpretq_u8_u16(n3))),
        vshlq_n_u16(vreinterpretq_u16_u8(vqtbl1q_u8(t.t3h, vreinterpretq_u8_u16(n3))), 8),
    );

    veorq_u16(veorq_u16(c0, c1), veorq_u16(c2, c3))
}

#[cfg(target_arch = "aarch64")]
#[target_feature(enable = "neon")]
/// # Safety
///
/// The caller must prove AArch64 NEON support. `src` and `dst` must remain
/// valid for the duration of the call; `len` is bounded to both slice lengths
/// before vector loads, stores, or scalar tail accesses.
unsafe fn gf16_mul_slice_neon(coeff: u16, src: &[u16], dst: &mut [u16], len: usize) {
    use std::arch::aarch64::*;
    let len = bounded_u16_len(src, dst, len);
    if len == 0 {
        return;
    }

    let tables = neon_tables(coeff);
    let mut offset = 0;

    while offset + 8 <= len {
        let source = vld1q_u16(src.as_ptr().add(offset));
        let target = vld1q_u16(dst.as_ptr().add(offset));
        vst1q_u16(dst.as_mut_ptr().add(offset), veorq_u16(target, neon_product(&tables, source)));
        offset += 8;
    }

    while offset < len {
        dst[offset] ^= crate::gf_tables::gf16_mul(coeff, src[offset]);
        offset += 1;
    }
    qf_telemetry::FEC_NEON_OPS.inc();
}

/// Big-endian byte-payload variant of the NEON kernel: `vrev16q_u8` swaps
/// bytes within u16 elements in-register.
#[cfg(target_arch = "aarch64")]
#[target_feature(enable = "neon")]
/// # Safety
///
/// The caller must prove AArch64 NEON support. `src` and `out_xor` must remain
/// valid for the duration of the call; only whole u16 words inside the shared
/// length are touched.
unsafe fn gf16_mul_bytes_neon(coeff: u16, src: &[u8], out_xor: &mut [u8]) {
    use std::arch::aarch64::*;
    let byte_len = src.len().min(out_xor.len());
    let words = byte_len / 2;
    if words == 0 {
        return;
    }

    let tables = neon_tables(coeff);

    let mut word = 0usize;
    while word + 8 <= words {
        let byte_offset = word * 2;
        let raw = vld1q_u8(src.as_ptr().add(byte_offset));
        let product = neon_product(&tables, vreinterpretq_u16_u8(vrev16q_u8(raw)));
        let product_be = vrev16q_u8(vreinterpretq_u8_u16(product));
        let target = vld1q_u8(out_xor.as_ptr().add(byte_offset));
        vst1q_u8(out_xor.as_mut_ptr().add(byte_offset), veorq_u8(target, product_be));
        word += 8;
    }

    gf16_mul_bytes_tail(coeff, src, out_xor, word, words);
    qf_telemetry::FEC_NEON_OPS.inc();
}

#[cfg(target_arch = "aarch64")]
/// # Safety
///
/// On builds that include the SVE2 block, the caller must prove AArch64 SVE2
/// support. `src` and `dst` must remain valid for the duration of the call;
/// `len` is bounded to both slice lengths before predicated accesses. Builds
/// without SVE2 compile to the NEON fallback, which has its own contract.
unsafe fn gf16_mul_slice_sve2(coeff: u16, src: &[u16], dst: &mut [u16], len: usize) {
    let len = bounded_u16_len(src, dst, len);
    #[cfg(target_feature = "sve2")]
    {
        use std::arch::aarch64::*;

        if len == 0 {
            return;
        }

        let coefficient = svdup_n_u16(coeff);
        let polynomial = svdup_n_u16(0x100B);
        let one = svdup_n_u16(1);
        let mut offset = 0usize;
        let vector_len = svcnth() as usize;

        while offset < len {
            let predicate = svwhilelt_b16(offset as u64, len as u64);
            if !svptest_any(svptrue_b16(), predicate) {
                break;
            }

            // Russian-peasant carryless multiply, matching the NEON kernel and
            // the scalar field (0x1100B with the x^16 term implicit). The old
            // svmul/svmulh integer-product form is not a carryless multiply and
            // used the wrong constant 0x000B, so any SVE2 result diverged from
            // the field.
            let mut multiplicand = svld1_u16(predicate, src.as_ptr().add(offset));
            let mut factor = coefficient;
            let mut product = svdup_n_u16(0);
            let target = svld1_u16(predicate, dst.as_ptr().add(offset));

            let mut round = 0;
            while round < 16 {
                let factor_mask =
                    svcmpeq_u16(predicate, svand_u16_x(svptrue_b16(), factor, one), one);
                product = sveor_u16_m(
                    predicate,
                    product,
                    product,
                    svand_u16_m(predicate, factor_mask, multiplicand, svdup_n_u16(0xFFFF)),
                );
                let carry_mask = svcmpeq_u16(
                    predicate,
                    svand_u16_x(svptrue_b16(), svshr_n_u16(multiplicand, 15), one),
                    one,
                );
                multiplicand = sveor_u16_m(
                    predicate,
                    svlsh1_n_u16_m(predicate, svdup_n_u16(0), multiplicand, 1),
                    svlsh1_n_u16_m(predicate, svdup_n_u16(0), multiplicand, 1),
                    svand_u16_m(predicate, carry_mask, polynomial, svdup_n_u16(0xFFFF)),
                );
                factor = svshr_n_u16_x(svptrue_b16(), factor, 1);
                round += 1;
            }

            let result = sveor_u16_m(predicate, target, target, product);

            svst1_u16(predicate, dst.as_mut_ptr().add(offset), result);
            offset += vector_len;
        }

        qf_telemetry::FEC_SVE2_OPS.inc();
        return;
    }

    gf16_mul_slice_neon(coeff, src, dst, len);
}

/// GF(2^16) multiply-accumulate over u16 slices: `dst[i] ^= coeff * src[i]`.
#[inline(always)]
#[doc(hidden)]
pub fn gf16_mul_slice(coeff: u16, src: &[u16], dst: &mut [u16]) {
    let len = src.len().min(dst.len());
    let src = &src[..len];
    let dst = &mut dst[..len];
    qf_cpu::dispatch_bitslice(|policy| {
        #[cfg(target_arch = "x86_64")]
        {
            if policy.as_any().is::<qf_cpu::Avx512Vbmi2>() && len >= GF16_VBMI2_MIN_WORDS {
                unsafe {
                    return gf16_mul_slice_vbmi2(coeff, src, dst, len);
                }
            }
            if policy.as_any().is::<qf_cpu::Avx512>()
                && len >= GF16_AVX512_MIN_WORDS
                && FeatureDetector::instance().features_full().avx512bw
            {
                unsafe {
                    return gf16_mul_slice_avx512(coeff, src, dst, len);
                }
            }
            if policy.as_any().is::<qf_cpu::Avx2>() && len >= GF16_AVX2_MIN_WORDS {
                unsafe {
                    return gf16_mul_slice_avx2(coeff, src, dst, len);
                }
            }
            if policy.as_any().is::<qf_cpu::Sse2>() && len >= GF16_SSE2_MIN_WORDS {
                unsafe {
                    return gf16_mul_slice_sse2(coeff, src, dst, len);
                }
            }
        }
        #[cfg(target_arch = "aarch64")]
        {
            if policy.as_any().is::<qf_cpu::Sve2>() && len >= GF16_SVE2_MIN_WORDS {
                unsafe {
                    return gf16_mul_slice_sve2(coeff, src, dst, len);
                }
            }
            if policy.as_any().is::<qf_cpu::Neon>() && len >= GF16_NEON_MIN_WORDS {
                unsafe {
                    return gf16_mul_slice_neon(coeff, src, dst, len);
                }
            }
        }

        let mut index = 0;
        while index + 8 <= len {
            dst[index] ^= crate::gf_tables::gf16_mul(coeff, src[index]);
            dst[index + 1] ^= crate::gf_tables::gf16_mul(coeff, src[index + 1]);
            dst[index + 2] ^= crate::gf_tables::gf16_mul(coeff, src[index + 2]);
            dst[index + 3] ^= crate::gf_tables::gf16_mul(coeff, src[index + 3]);
            dst[index + 4] ^= crate::gf_tables::gf16_mul(coeff, src[index + 4]);
            dst[index + 5] ^= crate::gf_tables::gf16_mul(coeff, src[index + 5]);
            dst[index + 6] ^= crate::gf_tables::gf16_mul(coeff, src[index + 6]);
            dst[index + 7] ^= crate::gf_tables::gf16_mul(coeff, src[index + 7]);
            index += 8;
        }
        while index < len {
            dst[index] ^= crate::gf_tables::gf16_mul(coeff, src[index]);
            index += 1;
        }
    });
}

#[cfg(test)]
mod kernel_tests {
    use super::*;

    /// Independent Russian-peasant GF(2^16) reference (poly 0x1100B, x^16
    /// implicit) — deliberately not `gf_tables::gf16_mul` so a broken table
    /// cannot mask a broken kernel.
    fn mul_ref(coeff: u16, word: u16) -> u16 {
        let mut a = word;
        let mut b = coeff;
        let mut product = 0u16;
        while b != 0 {
            if b & 1 != 0 {
                product ^= a;
            }
            b >>= 1;
            let carry = a & 0x8000 != 0;
            a <<= 1;
            if carry {
                a ^= 0x100B;
            }
        }
        product
    }

    fn lcg_words(seed: &mut u64, n: usize) -> Vec<u16> {
        (0..n)
            .map(|_| {
                *seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
                (*seed >> 33) as u16
            })
            .collect()
    }

    fn words_to_be_bytes(words: &[u16]) -> Vec<u8> {
        words.iter().flat_map(|w| w.to_be_bytes()).collect()
    }

    /// Reference outcome of `dst[i] ^= coeff * src[i]` for `i < len.min(...)`.
    fn expected_words(coeff: u16, src: &[u16], dst: &[u16], len: usize) -> Vec<u16> {
        let len = len.min(src.len()).min(dst.len());
        let mut out = dst.to_vec();
        for i in 0..len {
            out[i] ^= mul_ref(coeff, src[i]);
        }
        out
    }

    /// Reference outcome of the big-endian byte path (whole words only; a
    /// trailing odd byte stays untouched).
    fn expected_bytes(coeff: u16, src: &[u8], dst: &[u8]) -> Vec<u8> {
        let byte_len = src.len().min(dst.len());
        let words = byte_len / 2;
        let mut out = dst.to_vec();
        for w in 0..words {
            let s = u16::from_be_bytes([src[2 * w], src[2 * w + 1]]);
            let t = u16::from_be_bytes([out[2 * w], out[2 * w + 1]]);
            let v = (t ^ mul_ref(coeff, s)).to_be_bytes();
            out[2 * w] = v[0];
            out[2 * w + 1] = v[1];
        }
        out
    }

    const TEST_LENS: &[usize] = &[0, 1, 7, 8, 9, 15, 16, 17, 31, 32, 33, 47, 63, 64, 65, 100, 128];
    const TEST_COEFFS: &[u16] = &[0x0001, 0x0002, 0x0003, 0x8000, 0xBEEF, 0xFFFF];

    /// Runs `kernel` for every (len, coeff) pair and compares against the
    /// scalar reference, including overlong `len` requests that must clamp.
    fn check_u16_kernel<F>(name: &str, mut kernel: F)
    where
        F: FnMut(u16, &[u16], &mut [u16], usize),
    {
        let mut seed = 0x9E3779B97F4A7C15u64;
        for &len in TEST_LENS {
            let src = lcg_words(&mut seed, len);
            let dst0 = lcg_words(&mut seed, len);
            for &coeff in TEST_COEFFS {
                for &request in &[len, len + 5] {
                    let mut dst = dst0.clone();
                    kernel(coeff, &src, &mut dst, request);
                    assert_eq!(
                        dst,
                        expected_words(coeff, &src, &dst0, request),
                        "{name}: len={len} request={request} coeff={coeff:#06x}"
                    );
                }
            }
        }
    }

    /// Same for the big-endian byte kernels, incl. odd trailing bytes that
    /// must remain untouched.
    fn check_bytes_kernel<F>(name: &str, mut kernel: F)
    where
        F: FnMut(u16, &[u8], &mut [u8]),
    {
        let mut seed = 0xD1B54A32D192ED03u64;
        for &len in TEST_LENS {
            for odd in [false, true] {
                let mut src = words_to_be_bytes(&lcg_words(&mut seed, len));
                let mut dst0 = words_to_be_bytes(&lcg_words(&mut seed, len));
                if odd {
                    src.push(0xAB);
                    dst0.push(0xCD);
                }
                for &coeff in TEST_COEFFS {
                    let mut dst = dst0.clone();
                    kernel(coeff, &src, &mut dst);
                    assert_eq!(
                        dst,
                        expected_bytes(coeff, &src, &dst0),
                        "{name}: words={len} odd={odd} coeff={coeff:#06x}"
                    );
                }
            }
        }
    }

    #[test]
    fn nibble_byte_tables_match_scalar_reference() {
        let (lo, hi) = gf16_nibble_byte_tables(0xBEEF);
        for k in 0..4 {
            for n in 0..16 {
                let value = mul_ref(0xBEEF, (n as u16) << (4 * k));
                assert_eq!(lo[k][n], value as u8, "lo[{k}][{n}]");
                assert_eq!(hi[k][n], (value >> 8) as u8, "hi[{k}][{n}]");
            }
            assert_eq!(lo[k][0], 0, "t_{k}[0] must stay 0 for index masking");
            assert_eq!(hi[k][0], 0, "t_{k}[0] must stay 0 for index masking");
        }
    }

    #[cfg(target_arch = "aarch64")]
    #[test]
    fn neon_kernels_match_scalar_reference() {
        unsafe {
            check_u16_kernel("neon/u16", |c, s, d, l| {
                gf16_mul_slice_neon(c, s, d, l);
            });
            check_bytes_kernel("neon/bytes", |c, s, d| {
                gf16_mul_bytes_neon(c, s, d);
            });
        }
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn vbmi2_kernels_match_scalar_reference() {
        if !(is_x86_feature_detected!("avx512f")
            && is_x86_feature_detected!("avx512bw")
            && is_x86_feature_detected!("avx512vbmi2"))
        {
            return;
        }
        unsafe {
            check_u16_kernel("vbmi2/u16", |c, s, d, l| {
                gf16_mul_slice_vbmi2(c, s, d, l);
            });
            check_bytes_kernel("vbmi2/bytes", |c, s, d| {
                gf16_mul_bytes_vbmi2(c, s, d);
            });
        }
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn avx512_vbmi_kernels_match_scalar_reference() {
        if !(is_x86_feature_detected!("avx512f")
            && is_x86_feature_detected!("avx512bw")
            && is_x86_feature_detected!("avx512vbmi"))
        {
            return;
        }
        unsafe {
            check_u16_kernel("avx512vbmi/u16", |c, s, d, l| {
                gf16_mul_slice_avx512(c, s, d, l);
            });
            check_bytes_kernel("avx512vbmi/bytes", |c, s, d| {
                gf16_mul_bytes_avx512(c, s, d);
            });
        }
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn avx2_kernels_match_scalar_reference() {
        if !is_x86_feature_detected!("avx2") {
            return;
        }
        unsafe {
            check_u16_kernel("avx2/u16", |c, s, d, l| {
                gf16_mul_slice_avx2(c, s, d, l);
            });
            check_bytes_kernel("avx2/bytes", |c, s, d| {
                gf16_mul_bytes_avx2(c, s, d);
            });
        }
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn sse2_kernels_match_scalar_reference() {
        if !is_x86_feature_detected!("sse2") {
            return;
        }
        unsafe {
            check_u16_kernel("sse2/u16", |c, s, d, l| {
                gf16_mul_slice_sse2(c, s, d, l);
            });
            check_bytes_kernel("sse2/bytes", |c, s, d| {
                gf16_mul_bytes_sse2(c, s, d);
            });
        }
    }
}
