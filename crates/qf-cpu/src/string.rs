//! Runtime-accelerated substring search for stealth and protocol parsing paths.

use super::FeatureDetector;

/// Search for `needle` in `haystack` using the best verified runtime backend.
#[inline(always)]
pub fn string_contains(haystack: &str, needle: &str) -> bool {
    if needle.is_empty() || needle.len() > haystack.len() {
        return needle.is_empty();
    }

    #[cfg(target_arch = "x86_64")]
    {
        let matrix = FeatureDetector::instance().features_full().simd_dispatch_matrix();
        if matrix.avx512_bw {
            return unsafe { string_search_avx512(haystack.as_bytes(), needle.as_bytes()) }
                .is_some();
        }
        if matrix.avx2 {
            return unsafe { string_search_avx2(haystack.as_bytes(), needle.as_bytes()) }.is_some();
        }
    }

    #[cfg(target_arch = "aarch64")]
    {
        let features = FeatureDetector::instance().features_full();
        if features.sve2 {
            return string_search_sve2(haystack.as_bytes(), needle.as_bytes());
        }
        if features.neon {
            return unsafe { string_search_neon(haystack.as_bytes(), needle.as_bytes()) };
        }
    }

    haystack.contains(needle)
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx512f,avx512bw")]
unsafe fn string_search_avx512(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    use std::arch::x86_64::*;

    if needle.len() > 64 {
        return haystack.windows(needle.len()).position(|window| window == needle);
    }

    let first = _mm512_set1_epi8(needle[0] as i8);
    let last = _mm512_set1_epi8(needle[needle.len() - 1] as i8);

    let mut i = 0;
    while i + needle.len() + 63 <= haystack.len() {
        let hay_first = _mm512_loadu_si512(haystack.as_ptr().add(i) as *const __m512i);
        let hay_last =
            _mm512_loadu_si512(haystack.as_ptr().add(i + needle.len() - 1) as *const __m512i);

        let eq_first = _mm512_cmpeq_epi8_mask(hay_first, first);
        let eq_last = _mm512_cmpeq_epi8_mask(hay_last, last);
        let eq_both = eq_first & eq_last;

        if eq_both != 0 {
            let mut mask = eq_both;
            while mask != 0 {
                let bit = mask.trailing_zeros() as usize;
                let pos = i + bit;

                if &haystack[pos..pos + needle.len()] == needle {
                    return Some(pos);
                }

                mask &= mask - 1;
            }
        }

        i += 64;
    }

    haystack[i..]
        .windows(needle.len())
        .position(|window| window == needle)
        .map(|position| i + position)
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
unsafe fn string_search_avx2(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    super::simd_compress::find_pattern(haystack, needle)
}

#[cfg(target_arch = "aarch64")]
#[target_feature(enable = "neon")]
unsafe fn string_search_neon(haystack: &[u8], needle: &[u8]) -> bool {
    use std::arch::aarch64::*;

    if needle.is_empty() {
        return true;
    }

    if needle.len() == 1 {
        return haystack.contains(&needle[0]);
    }

    let first = vdupq_n_u8(needle[0]);
    let last = vdupq_n_u8(needle[needle.len() - 1]);

    let mut i = 0usize;
    while i + needle.len() + 15 <= haystack.len() {
        let hay_first = vld1q_u8(haystack.as_ptr().add(i));
        let last_offset = i + needle.len() - 1;
        if last_offset + 16 > haystack.len() {
            break;
        }
        let hay_last = vld1q_u8(haystack.as_ptr().add(last_offset));

        let eq_first = vceqq_u8(hay_first, first);
        let eq_last = vceqq_u8(hay_last, last);
        let candidates = vandq_u8(eq_first, eq_last);

        let mut lanes = [0u8; 16];
        vst1q_u8(lanes.as_mut_ptr(), candidates);
        for (lane, &flag) in lanes.iter().enumerate() {
            if flag == 0xFF {
                let pos = i + lane;
                if pos + needle.len() <= haystack.len()
                    && &haystack[pos..pos + needle.len()] == needle
                {
                    return true;
                }
            }
        }

        i += 16;
    }

    haystack[i..].windows(needle.len()).any(|window| window == needle)
}

#[cfg(target_arch = "aarch64")]
fn string_search_sve2(haystack: &[u8], needle: &[u8]) -> bool {
    #[cfg(target_feature = "sve2")]
    {
        if needle.is_empty() {
            return true;
        }

        super::simd_compress::find_pattern(haystack, needle).is_some()
    }

    #[cfg(not(target_feature = "sve2"))]
    {
        unsafe { string_search_neon(haystack, needle) }
    }
}
