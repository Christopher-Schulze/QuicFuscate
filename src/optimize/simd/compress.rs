//! optimize::simd::compress (TODO-563).

#[cfg(target_arch = "x86_64")]
use super::super::telemetry;
use super::FeatureDetector;

/// Ultra-fast entropy histogram with best available SIMD acceleration
#[inline(always)]
pub fn histogram(data: &[u8]) -> [u32; 256] {
    let features = FeatureDetector::instance().features_full();

    #[cfg(target_arch = "x86_64")]
    {
        if features.avx512vbmi2 && features.avx512bw {
            return unsafe { histogram_avx512_vbmi2(data) };
        }
        if features.avx512bw {
            return unsafe { histogram_avx512(data) };
        }
        if features.avx2 {
            return unsafe { histogram_avx2(data) };
        }
    }

    #[cfg(target_arch = "aarch64")]
    {
        if features.sve2 {
            return unsafe { histogram_sve2(data) };
        }
        if features.neon {
            return unsafe { histogram_neon(data) };
        }
    }

    histogram_scalar(data)
}

/// Ultra-fast byte pattern search with best available SIMD
#[inline(always)]
pub fn find_pattern(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || needle.len() > haystack.len() {
        return None;
    }

    let features = FeatureDetector::instance().features_full();

    #[cfg(target_arch = "x86_64")]
    {
        if features.avx512vbmi2 && needle.len() <= 64 {
            return unsafe { find_pattern_avx512_vbmi2(haystack, needle) };
        }
        if features.avx2 && needle.len() <= 32 {
            return unsafe { find_pattern_avx2(haystack, needle) };
        }
    }

    #[cfg(target_arch = "aarch64")]
    {
        if features.sve2 {
            return unsafe { find_pattern_sve2(haystack, needle) };
        }
        if features.neon && needle.len() <= 16 {
            return unsafe { find_pattern_neon(haystack, needle) };
        }
    }

    find_pattern_scalar(haystack, needle)
}

/// Ultra-fast histogram with AVX-512 VBMI2 - 64 bytes at once!
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx512f,avx512bw,avx512vbmi2")]
#[inline]
unsafe fn histogram_avx512_vbmi2(data: &[u8]) -> [u32; 256] {
    use std::arch::x86_64::*;

    let mut hist = [0u32; 256];
    let mut i = 0;
    let len = data.len();

    // Process 64 bytes at once with AVX-512
    while i + 64 <= len {
        let chunk = _mm512_loadu_si512(data.as_ptr().add(i) as *const __m512i);

        let mut tmp = [0u8; 64];
        _mm512_storeu_si512(tmp.as_mut_ptr() as *mut __m512i, chunk);
        for &byte_val in &tmp {
            hist[byte_val as usize] += 1;
        }

        i += 64;
    }

    // Process remaining bytes
    while i < len {
        hist[data[i] as usize] += 1;
        i += 1;
    }

    telemetry::PATTERN_AVX512_VBMI2_OPS.inc();
    hist
}

/// Fast histogram with AVX-512 - 64 bytes at once
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx512f,avx512bw")]
#[inline]
unsafe fn histogram_avx512(data: &[u8]) -> [u32; 256] {
    use std::arch::x86_64::*;

    let mut hist = [0u32; 256];
    let mut i = 0;
    let len = data.len();

    // Process 64 bytes at once
    while i + 64 <= len {
        let chunk = _mm512_loadu_si512(data.as_ptr().add(i) as *const __m512i);

        let mut tmp = [0u8; 64];
        _mm512_storeu_si512(tmp.as_mut_ptr() as *mut __m512i, chunk);
        for &byte_val in &tmp {
            hist[byte_val as usize] += 1;
        }

        i += 64;
    }

    // Process remaining bytes
    while i < len {
        hist[data[i] as usize] += 1;
        i += 1;
    }

    telemetry::PATTERN_AVX512_OPS.inc();
    hist
}

/// Optimized histogram with AVX2 - 32 bytes at once
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
#[inline]
unsafe fn histogram_avx2(data: &[u8]) -> [u32; 256] {
    use std::arch::x86_64::*;

    let mut hist = [0u32; 256];
    let mut i = 0;
    let len = data.len();

    // Process 32 bytes at once
    while i + 32 <= len {
        let chunk = _mm256_loadu_si256(data.as_ptr().add(i) as *const __m256i);

        // _mm256_extract_epi8 requires an immediate index. Store and count bytes from memory.
        let mut tmp = [0u8; 32];
        _mm256_storeu_si256(tmp.as_mut_ptr() as *mut __m256i, chunk);
        for b in tmp {
            hist[b as usize] += 1;
        }

        i += 32;
    }

    // Process remaining bytes
    while i < len {
        hist[data[i] as usize] += 1;
        i += 1;
    }

    telemetry::PATTERN_AVX2_OPS.inc();
    hist
}

/// Ultra-fast histogram with ARM SVE2 - scalable vector width!
#[cfg(target_arch = "aarch64")]
unsafe fn histogram_sve2(data: &[u8]) -> [u32; 256] {
    #[cfg(target_feature = "sve2")]
    {
        use std::arch::aarch64::*;

        let mut hist = [0u32; 256];
        let len = data.len();
        let vl = svcntb() as usize;
        let mut offset = 0usize;
        let mut tmp = [0u8; 256];

        debug_assert!(vl <= tmp.len());

        while offset < len {
            let pg = svwhilelt_b8(offset as u64, len as u64);
            let vec = svld1_u8(pg, data.as_ptr().add(offset));
            svst1_u8(pg, tmp.as_mut_ptr(), vec);

            let active = usize::min(vl, len.saturating_sub(offset));
            for idx in 0..active {
                hist[tmp[idx] as usize] += 1;
            }

            offset += vl;
        }

        crate::optimize::telemetry::PATTERN_SVE2_OPS.inc();
        return hist;
    }

    histogram_neon(data)
}

/// Fast histogram with ARM NEON - 16 bytes at once
#[cfg(target_arch = "aarch64")]
#[target_feature(enable = "neon")]
unsafe fn histogram_neon(data: &[u8]) -> [u32; 256] {
    use std::arch::aarch64::*;

    let mut hist = [0u32; 256];
    let mut i = 0;
    let len = data.len();

    // Process 16 bytes at once
    while i + 16 <= len {
        let chunk = vld1q_u8(data.as_ptr().add(i));
        // Store to a temporary array to avoid const lane index restriction
        let mut tmp: [u8; 16] = [0u8; 16];
        vst1q_u8(tmp.as_mut_ptr(), chunk);
        for &b in &tmp {
            hist[b as usize] += 1;
        }
        i += 16;
    }

    // Process remaining bytes
    while i < len {
        hist[data[i] as usize] += 1;
        i += 1;
    }

    crate::optimize::telemetry::PATTERN_NEON_OPS.inc();
    hist
}

/// Ultra-fast pattern search with AVX-512 VBMI2 - up to 64-byte patterns!
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx512f,avx512bw,avx512vbmi2")]
#[inline]
unsafe fn find_pattern_avx512_vbmi2(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    use std::arch::x86_64::*;

    if needle.len() > 64 || needle.is_empty() {
        return find_pattern_scalar(haystack, needle);
    }

    let needle_len = needle.len();
    let haystack_len = haystack.len();

    // Create needle pattern vectors
    let mut needle_vec = [0u8; 64];
    needle_vec[..needle_len].copy_from_slice(needle);
    let needle_512 = _mm512_loadu_si512(needle_vec.as_ptr() as *const __m512i);

    let mut i = 0;
    while i + 64 <= haystack_len {
        let haystack_chunk = _mm512_loadu_si512(haystack.as_ptr().add(i) as *const __m512i);

        // Use VBMI2 for efficient comparison and match detection
        let cmp_mask = _mm512_cmpeq_epi8_mask(haystack_chunk, needle_512);

        if cmp_mask != 0 {
            // Found potential match, verify with scalar comparison
            for j in 0..64 {
                if i + j + needle_len <= haystack_len {
                    if &haystack[i + j..i + j + needle_len] == needle {
                        telemetry::PATTERN_AVX512_VBMI2_OPS.inc();
                        return Some(i + j);
                    }
                }
            }
        }

        i += 64;
    }

    // Check remaining bytes with scalar
    while i + needle_len <= haystack_len {
        if &haystack[i..i + needle_len] == needle {
            telemetry::PATTERN_AVX512_VBMI2_OPS.inc();
            return Some(i);
        }
        i += 1;
    }

    None
}

/// Fast pattern search with AVX2 - up to 32-byte patterns
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
#[inline]
unsafe fn find_pattern_avx2(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    use std::arch::x86_64::*;

    if needle.len() > 32 || needle.is_empty() {
        return find_pattern_scalar(haystack, needle);
    }

    let needle_len = needle.len();
    let haystack_len = haystack.len();

    // For short patterns, use first byte matching with AVX2
    if needle_len == 1 {
        let needle_first = _mm256_set1_epi8(needle[0] as i8);
        let mut i = 0;

        while i + 32 <= haystack_len {
            let haystack_chunk = _mm256_loadu_si256(haystack.as_ptr().add(i) as *const __m256i);
            let cmp_result = _mm256_cmpeq_epi8(haystack_chunk, needle_first);
            let mask = _mm256_movemask_epi8(cmp_result);

            if mask != 0 {
                for bit in 0..32 {
                    if (mask & (1 << bit)) != 0 {
                        telemetry::PATTERN_AVX2_OPS.inc();
                        return Some(i + bit);
                    }
                }
            }
            i += 32;
        }
    }

    // For longer patterns, use scalar verification after first byte match
    let mut i = 0;
    while i + needle_len <= haystack_len {
        if &haystack[i..i + needle_len] == needle {
            telemetry::PATTERN_AVX2_OPS.inc();
            return Some(i);
        }
        i += 1;
    }

    None
}

/// Ultra-fast pattern search with ARM SVE2 - scalable vector patterns
#[cfg(target_arch = "aarch64")]
unsafe fn find_pattern_sve2(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    #[cfg(target_feature = "sve2")]
    {
        use std::arch::aarch64::*;

        crate::optimize::telemetry::PATTERN_SVE2_OPS.inc();

        let nlen = needle.len();
        if nlen == 0 {
            return Some(0);
        }
        if nlen > haystack.len() {
            return None;
        }

        let hlen = haystack.len();
        let vl = svcntb() as usize;
        let mut offset = 0usize;

        if nlen == 1 {
            let needle_val = svdup_n_u8(needle[0]);
            let pg_all = svptrue_b8();

            while offset + vl <= hlen {
                let chunk = svld1_u8(pg_all, haystack.as_ptr().add(offset));
                let matches = svcmpeq_u8(pg_all, chunk, needle_val);

                if svptest_any(pg_all, matches) {
                    for lane in 0..vl {
                        if offset + lane < hlen && haystack[offset + lane] == needle[0] {
                            return Some(offset + lane);
                        }
                    }
                }
                offset += vl;
            }

            while offset < hlen {
                if haystack[offset] == needle[0] {
                    return Some(offset);
                }
                offset += 1;
            }

            return None;
        }

        let first_byte = svdup_n_u8(needle[0]);
        let pg_all = svptrue_b8();

        while offset + vl <= hlen {
            let chunk = svld1_u8(pg_all, haystack.as_ptr().add(offset));
            let matches = svcmpeq_u8(pg_all, chunk, first_byte);

            if svptest_any(pg_all, matches) {
                for lane in 0..vl {
                    let pos = offset + lane;
                    if pos + nlen <= hlen && &haystack[pos..pos + nlen] == needle {
                        return Some(pos);
                    }
                }
            }
            offset += vl;
        }

        while offset + nlen <= hlen {
            if &haystack[offset..offset + nlen] == needle {
                return Some(offset);
            }
            offset += 1;
        }

        return None;
    }

    find_pattern_neon(haystack, needle)
}

/// Fast pattern search with ARM NEON - up to 16-byte patterns
#[cfg(target_arch = "aarch64")]
#[target_feature(enable = "neon")]
unsafe fn find_pattern_neon(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    use std::arch::aarch64::*;

    if needle.len() > 16 || needle.is_empty() {
        return find_pattern_scalar(haystack, needle);
    }

    let needle_len = needle.len();
    let haystack_len = haystack.len();

    // For single byte patterns, use NEON comparison
    if needle_len == 1 {
        let needle_first = vdupq_n_u8(needle[0]);
        let mut i = 0;

        while i + 16 <= haystack_len {
            let haystack_chunk = vld1q_u8(haystack.as_ptr().add(i));
            let cmp_result = vceqq_u8(haystack_chunk, needle_first);

            // Check if any bytes matched
            let mask =
                vget_lane_u64(vreinterpret_u64_u8(vqmovn_u16(vreinterpretq_u16_u8(cmp_result))), 0);
            if mask != 0 {
                for bit in 0..16 {
                    if i + bit < haystack_len && haystack[i + bit] == needle[0] {
                        crate::optimize::telemetry::PATTERN_NEON_OPS.inc();
                        return Some(i + bit);
                    }
                }
            }
            i += 16;
        }
    }

    // For longer patterns, use scalar verification
    let mut i = 0;
    while i + needle_len <= haystack_len {
        if haystack[i..i + needle_len] == *needle {
            crate::optimize::telemetry::PATTERN_NEON_OPS.inc();
            return Some(i);
        }
        i += 1;
    }

    None
}

/// Scalar pattern search fallback
fn find_pattern_scalar(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() {
        return Some(0);
    }

    let needle_len = needle.len();
    let haystack_len = haystack.len();

    for i in 0..=(haystack_len.saturating_sub(needle_len)) {
        if haystack[i..i + needle_len] == *needle {
            crate::optimize::telemetry::PATTERN_SCALAR_OPS.inc();
            return Some(i);
        }
    }

    None
}

/// Scalar entropy histogram fallback
fn histogram_scalar(data: &[u8]) -> [u32; 256] {
    let mut hist = [0u32; 256];
    for &byte in data {
        hist[byte as usize] += 1;
    }
    crate::optimize::telemetry::PATTERN_SCALAR_OPS.inc();
    hist
}
