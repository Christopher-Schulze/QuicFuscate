//! Ultra-sophisticated stealth acceleration module
//! Complete HW acceleration for pattern injection, entropy mixing, HTTP/TLS mimicry

#[cfg(any(target_arch = "x86_64", test, feature = "rust-tests", feature = "benches"))]
use crate::optimize::FeatureDetector;
#[cfg(target_arch = "x86_64")]
use std::arch::x86_64::*;
#[cfg(test)]
use std::time::Duration;

#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct StealthAsciiBenchmarkScenario {
    name: &'static str,
    bytes: usize,
    iterations: usize,
}

#[cfg(test)]
const STEALTH_ASCII_BENCHMARK_SET: [StealthAsciiBenchmarkScenario; 4] = [
    StealthAsciiBenchmarkScenario { name: "headers-small", bytes: 384, iterations: 20_000 },
    StealthAsciiBenchmarkScenario { name: "cookies-medium", bytes: 2048, iterations: 8_000 },
    StealthAsciiBenchmarkScenario { name: "capsule-large", bytes: 16_384, iterations: 1_500 },
    StealthAsciiBenchmarkScenario { name: "burst-xlarge", bytes: 65_536, iterations: 320 },
];

#[cfg(test)]
#[derive(Clone, Copy, Debug)]
struct StealthAsciiPerfThresholds {
    min_mb_per_sec: f64,
}

#[cfg(test)]
const STEALTH_ASCII_INTERNAL_TARGETS: StealthAsciiPerfThresholds =
    StealthAsciiPerfThresholds { min_mb_per_sec: 250.0 };

#[cfg(test)]
impl Default for StealthAsciiPerfThresholds {
    fn default() -> Self {
        STEALTH_ASCII_INTERNAL_TARGETS
    }
}

#[cfg(test)]
fn evaluate_stealth_ascii_perf_smoke(
    processed_bytes: usize,
    elapsed: Duration,
    thresholds: StealthAsciiPerfThresholds,
) -> bool {
    if processed_bytes == 0 || elapsed.is_zero() {
        return true;
    }
    let throughput_mb_per_sec =
        (processed_bytes as f64 / (1024.0 * 1024.0)) / elapsed.as_secs_f64().max(1e-9);
    throughput_mb_per_sec >= thresholds.min_mb_per_sec
}

pub use qf_cpu::ascii::AsciiSimdBackend;

/// Pattern injection with SIMD - 3x faster (AVX2/NEON)
#[inline(always)]
#[cfg(any(test, feature = "rust-tests"))]
pub fn inject_pattern(data: &mut [u8], pattern: &[u8], positions: &[usize]) {
    if pattern.is_empty() || positions.is_empty() {
        return;
    }

    let features = *FeatureDetector::instance().features_full();

    #[cfg(target_arch = "x86_64")]
    {
        let matrix = features.simd_dispatch_matrix();
        if matrix.avx2 {
            // SAFETY: the exact AVX2 runtime feature is proven by the dispatch matrix.
            unsafe { inject_pattern_avx2(data, pattern, positions) };
            return;
        }
        if features.sse2 {
            // SAFETY: SSE2 is a required x86_64 baseline and is checked explicitly.
            unsafe { inject_pattern_sse2(data, pattern, positions) };
            return;
        }
    }

    #[cfg(target_arch = "aarch64")]
    {
        if features.sve2 {
            // SAFETY: the exact runtime SVE2 feature is proven above.
            unsafe { inject_pattern_sve2(data, pattern, positions) };
            return;
        }
        if features.neon {
            // SAFETY: the exact runtime NEON feature is proven above.
            unsafe { inject_pattern_neon(data, pattern, positions) };
            return;
        }
    }

    // Scalar fallback
    for &pos in positions {
        if let Some(end) = complete_pattern_end(data.len(), pos, pattern.len()) {
            data[pos..end].copy_from_slice(pattern);
        }
    }
}

#[inline(always)]
#[cfg(any(test, feature = "rust-tests"))]
fn complete_pattern_end(data_len: usize, position: usize, pattern_len: usize) -> Option<usize> {
    let available = data_len.checked_sub(position)?;
    if pattern_len > available {
        return None;
    }
    position.checked_add(pattern_len)
}

#[cfg(all(target_arch = "x86_64", any(test, feature = "rust-tests")))]
#[target_feature(enable = "avx2")]
/// # Safety
///
/// The caller must prove AVX2 support. Every position is admitted only when
/// the complete pattern fits in `data`; raw vector offsets stay inside those
/// validated windows.
unsafe fn inject_pattern_avx2(data: &mut [u8], pattern: &[u8], positions: &[usize]) {
    if pattern.len() <= 32 {
        for &pos in positions {
            if let Some(end) = complete_pattern_end(data.len(), pos, pattern.len()) {
                data[pos..end].copy_from_slice(pattern);
            }
        }
    } else {
        // Pattern larger than 32 bytes - process in chunks
        for &pos in positions {
            let Some(end) = complete_pattern_end(data.len(), pos, pattern.len()) else {
                continue;
            };
            let mut i = 0;
            while i + 32 <= pattern.len() {
                let pattern_chunk = _mm256_loadu_si256(pattern.as_ptr().add(i) as *const __m256i);
                _mm256_storeu_si256(data.as_mut_ptr().add(pos + i) as *mut __m256i, pattern_chunk);
                i += 32;
            }
            // Handle remainder
            if i < pattern.len() {
                data[pos + i..end].copy_from_slice(&pattern[i..]);
            }
        }
    }
}

#[cfg(all(target_arch = "x86_64", any(test, feature = "rust-tests")))]
#[target_feature(enable = "sse2")]
/// # Safety
///
/// The caller must prove SSE2 support. Every position is admitted only when
/// the complete pattern fits in `data`; the long-pattern vector loop uses
/// offsets bounded by that validated pattern length.
unsafe fn inject_pattern_sse2(data: &mut [u8], pattern: &[u8], positions: &[usize]) {
    use std::arch::x86_64::*;

    if pattern.is_empty() {
        return;
    }

    if pattern.len() <= 16 {
        for &pos in positions {
            if let Some(end) = complete_pattern_end(data.len(), pos, pattern.len()) {
                data[pos..end].copy_from_slice(pattern);
            }
        }
        return;
    }

    for &pos in positions {
        if complete_pattern_end(data.len(), pos, pattern.len()).is_none() {
            continue;
        }

        let chunk_len = pattern.len();
        let mut offset = 0usize;

        while offset + 16 <= chunk_len {
            let pattern_chunk = _mm_loadu_si128(pattern.as_ptr().add(offset) as *const __m128i);
            _mm_storeu_si128(data.as_mut_ptr().add(pos + offset) as *mut __m128i, pattern_chunk);
            offset += 16;
        }

        while offset < chunk_len {
            data[pos + offset] = pattern[offset];
            offset += 1;
        }
    }
}

/// NEON-optimized pattern injection on aarch64.
#[cfg(all(target_arch = "aarch64", any(test, feature = "rust-tests")))]
#[target_feature(enable = "neon")]
/// # Safety
///
/// The caller must prove NEON support. Every position is admitted only when
/// the complete pattern fits in `data`; vector loads and stores use bounded
/// 16-byte chunks within that window.
unsafe fn inject_pattern_neon(data: &mut [u8], pattern: &[u8], positions: &[usize]) {
    use std::arch::aarch64::*;

    if pattern.is_empty() {
        return;
    }

    let len = pattern.len();
    let full_chunks = len / 16;
    let tail = len % 16;

    if full_chunks == 0 {
        // Pattern shorter than 16 bytes - broadcast via masked NEON store
        let mut pattern_buf = [0u8; 16];
        pattern_buf[..tail].copy_from_slice(pattern);
        let pattern_vec = vld1q_u8(pattern_buf.as_ptr());

        let mut mask_bytes = [0u8; 16];
        for byte in &mut mask_bytes[..tail] {
            *byte = 0xFF;
        }
        let mask = vld1q_u8(mask_bytes.as_ptr());

        for &pos in positions {
            if complete_pattern_end(data.len(), pos, tail).is_none() {
                continue;
            }

            let mut target_buf = [0u8; 16];
            target_buf[..tail].copy_from_slice(&data[pos..pos + tail]);
            let target_vec = vld1q_u8(target_buf.as_ptr());
            let blended = vbslq_u8(mask, pattern_vec, target_vec);
            vst1q_u8(target_buf.as_mut_ptr(), blended);
            data[pos..pos + tail].copy_from_slice(&target_buf[..tail]);
        }
        return;
    }

    for &pos in positions {
        if complete_pattern_end(data.len(), pos, len).is_none() {
            continue;
        }

        for chunk in 0..full_chunks {
            let pattern_chunk = vld1q_u8(pattern.as_ptr().add(chunk * 16));
            vst1q_u8(data.as_mut_ptr().add(pos + chunk * 16), pattern_chunk);
        }

        if tail > 0 {
            let start = pos + full_chunks * 16;
            data[start..start + tail].copy_from_slice(&pattern[full_chunks * 16..]);
        }
    }
}

/// TLS record padding with AVX2 broadcast - 3x faster
#[inline(always)]
#[cfg(any(test, feature = "rust-tests", feature = "benches"))]
pub fn add_tls_padding(record: &mut Vec<u8>, target_size: usize, padding_byte: u8) {
    let current_len = record.len();
    if current_len >= target_size {
        return;
    }

    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    let features = *FeatureDetector::instance().features_full();

    #[cfg(target_arch = "x86_64")]
    {
        if features.sse2 && features.gfni {
            let padding_needed = target_size - current_len;
            let seed_lo = (current_len as u64).wrapping_mul(0x9E37_79B1_85EB_CA87)
                ^ (padding_byte as u64).wrapping_mul(0xBF58_476D_1CE4_E5B9);
            let seed_hi = (target_size as u64).wrapping_mul(0x94D0_49BB_1331_11EB)
                ^ (padding_needed as u64).rotate_left(29);
            let pad = unsafe {
                gfni_padding_bytes_unchecked(padding_needed, padding_byte, seed_lo, seed_hi)
            };
            crate::optimize::telemetry::STEALTH_PADDING_GFNI_OPS.inc_by(padding_needed as u64);
            record.extend_from_slice(&pad);
            return;
        }
    }

    #[cfg(target_arch = "x86_64")]
    {
        let matrix = features.simd_dispatch_matrix();
        if matrix.avx2 {
            // SAFETY: the exact AVX2 runtime feature is proven by the dispatch matrix.
            unsafe { add_tls_padding_avx2(record, target_size, padding_byte) };
            return;
        }
        if features.sse2 {
            // SAFETY: SSE2 is a required x86_64 baseline and is checked explicitly.
            unsafe { add_tls_padding_sse2(record, target_size, padding_byte) };
            return;
        }
    }

    #[cfg(target_arch = "aarch64")]
    if features.neon {
        // SAFETY: the exact runtime NEON feature is proven above.
        unsafe { add_tls_padding_neon(record, target_size, padding_byte) };
        return;
    }

    // Scalar fallback
    while record.len() < target_size {
        record.push(padding_byte);
    }
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "sse2", enable = "gfni")]
unsafe fn gfni_padding_bytes_unchecked(
    len: usize,
    pad_byte: u8,
    seed_lo: u64,
    seed_hi: u64,
) -> Vec<u8> {
    use std::arch::x86_64::*;

    if len == 0 {
        return Vec::new();
    }

    let mut out = vec![0u8; len];
    let matrix = _mm_set_epi64x(0xF36E_48E1_2C5D_47C3u64 as i64, 0x9A7F_4D3C_2B1E_0F45u64 as i64);
    let mut state = _mm_set_epi64x(seed_hi as i64, seed_lo as i64);
    let bias = _mm_set1_epi8(pad_byte as i8);
    let mut offset = 0usize;

    while offset < len {
        let tweak = _mm_set_epi64x(
            ((offset as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15)) as i64,
            ((len as u64 - offset as u64).wrapping_mul(0xC2B2_AE3D_27D4_EB4F)) as i64,
        );
        let mixed = _mm_xor_si128(state, tweak);
        let block = _mm_gf2p8affine_epi64_epi8(mixed, matrix, 0xD7);
        state = block;
        let pad = _mm_xor_si128(block, bias);
        let mut scratch = [0u8; 16];
        _mm_storeu_si128(scratch.as_mut_ptr() as *mut __m128i, pad);

        let take = usize::min(16, len - offset);
        out[offset..offset + take].copy_from_slice(&scratch[..take]);
        offset += take;
    }

    out
}

#[cfg(target_arch = "x86_64")]
pub fn gfni_padding_bytes(len: usize, pad_byte: u8, seed_lo: u64, seed_hi: u64) -> Vec<u8> {
    if !FeatureDetector::instance().features_full().gfni {
        return vec![pad_byte; len];
    }
    unsafe { gfni_padding_bytes_unchecked(len, pad_byte, seed_lo, seed_hi) }
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
#[cfg(any(test, feature = "rust-tests", feature = "benches"))]
unsafe fn add_tls_padding_avx2(record: &mut Vec<u8>, target_size: usize, padding_byte: u8) {
    let current_len = record.len();
    if current_len >= target_size {
        return;
    }

    let padding_needed = target_size - current_len;
    record.reserve(padding_needed);

    // Create padding vector
    let padding_vec = _mm256_set1_epi8(padding_byte as i8);

    // Fast fill with AVX2
    let mut written = 0;
    while written + 32 <= padding_needed {
        record.extend_from_slice(&[0; 32]);
        let ptr = record.as_mut_ptr().add(current_len + written) as *mut __m256i;
        _mm256_storeu_si256(ptr, padding_vec);
        written += 32;
    }

    // Handle remainder
    while written < padding_needed {
        record.push(padding_byte);
        written += 1;
    }
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "sse2")]
#[cfg(any(test, feature = "rust-tests", feature = "benches"))]
unsafe fn add_tls_padding_sse2(record: &mut Vec<u8>, target_size: usize, padding_byte: u8) {
    use std::arch::x86_64::*;

    let current_len = record.len();
    if current_len >= target_size {
        return;
    }

    let padding_needed = target_size - current_len;
    record.reserve(padding_needed);

    let fill_vec = _mm_set1_epi8(padding_byte as i8);
    let mut written = 0usize;

    while written + 16 <= padding_needed {
        record.extend_from_slice(&[0u8; 16]);
        let ptr = record.as_mut_ptr().add(current_len + written) as *mut __m128i;
        _mm_storeu_si128(ptr, fill_vec);
        written += 16;
    }

    while written < padding_needed {
        record.push(padding_byte);
        written += 1;
    }
}

#[cfg(target_arch = "aarch64")]
#[target_feature(enable = "neon")]
#[cfg(any(test, feature = "rust-tests", feature = "benches"))]
unsafe fn add_tls_padding_neon(record: &mut Vec<u8>, target_size: usize, padding_byte: u8) {
    use std::arch::aarch64::*;
    let current_len = record.len();
    if current_len >= target_size {
        return;
    }

    let padding_needed = target_size - current_len;
    record.reserve(padding_needed);

    let fill = vdupq_n_u8(padding_byte);
    let mut written = 0usize;

    while written + 16 <= padding_needed {
        record.extend_from_slice(&[0; 16]);
        let ptr = record.as_mut_ptr().add(current_len + written);
        vst1q_u8(ptr, fill);
        written += 16;
    }

    while written < padding_needed {
        record.push(padding_byte);
        written += 1;
    }
}

/// Fake HMAC generation (select accelerated SHA backends when available).
#[inline(always)]
#[cfg(any(test, feature = "rust-tests"))]
pub fn generate_fake_hmac(data: &[u8], key: &[u8; 32]) -> [u8; 32] {
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    let detector = FeatureDetector::instance();

    #[cfg(target_arch = "x86_64")]
    {
        let features = detector.features_full();
        let matrix = features.simd_dispatch_matrix();
        if matrix.sha256_vnni || matrix.avx2 {
            // Route SHA-capable x86 profiles through the centralized SIMD HMAC.
            return crate::simd::crypto::hmac_sha256(key, data);
        }
    }

    #[cfg(target_arch = "aarch64")]
    {
        if detector.features_full().sha2 {
            // Apple M / ARM SHA hardware now active in default builds.
            return crate::simd::crypto::hmac_sha256(key, data);
        }
    }

    // Fallback to simple XOR-based fake HMAC while tracking scalar usage.
    crate::optimize::telemetry::HMAC_SHA256_SCALAR_OPS.inc();
    let mut hmac = [0u8; 32];
    for (i, &byte) in data.iter().enumerate() {
        hmac[i % 32] ^= byte ^ key[i % 32];
    }
    hmac
}
#[cfg(all(target_arch = "aarch64", any(test, feature = "rust-tests")))]
unsafe fn inject_pattern_sve2(data: &mut [u8], pattern: &[u8], positions: &[usize]) {
    #[cfg(target_feature = "sve2")]
    {
        return inject_pattern_sve2_impl(data, pattern, positions);
    }

    #[cfg(not(target_feature = "sve2"))]
    {
        inject_pattern_neon(data, pattern, positions)
    }
}

#[cfg(all(target_arch = "aarch64", target_feature = "sve2", any(test, feature = "rust-tests")))]
#[target_feature(enable = "sve2")]
/// # Safety
///
/// The caller must prove SVE2 support. Each active predicate is bounded by
/// the remaining pattern length and every position is validated as a complete
/// destination window before pointer arithmetic.
unsafe fn inject_pattern_sve2_impl(data: &mut [u8], pattern: &[u8], positions: &[usize]) {
    use std::arch::aarch64::*;

    if pattern.is_empty() {
        return;
    }

    let pat_len = pattern.len();
    let vl = svcntb() as usize;

    for &pos in positions {
        if complete_pattern_end(data.len(), pos, pat_len).is_none() {
            continue;
        }

        let mut offset = 0usize;
        while offset < pat_len {
            let take = usize::min(vl, pat_len - offset);
            let pg = svwhilelt_b8(0, take as u64);
            let chunk = svld1_u8(pg, pattern.as_ptr().add(offset));
            svst1_u8(pg, data.as_mut_ptr().add(pos + offset), chunk);
            offset += take;
        }
    }
}

#[cfg(any(test, feature = "rust-tests"))]
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stealth_ascii_benchmark_set_is_non_empty_and_unique() {
        assert!(matches!(STEALTH_ASCII_BENCHMARK_SET, [_first, ..]));
        let mut names = std::collections::BTreeSet::new();
        for scenario in STEALTH_ASCII_BENCHMARK_SET {
            assert!(scenario.bytes > 0);
            assert!(scenario.iterations > 0);
            assert!(names.insert(scenario.name));
        }
    }

    #[test]
    fn stealth_ascii_perf_smoke_thresholds_pass_and_fail() {
        let pass = evaluate_stealth_ascii_perf_smoke(
            64 * 1024 * 1024,
            Duration::from_millis(120),
            STEALTH_ASCII_INTERNAL_TARGETS,
        );
        assert!(pass);

        let fail = evaluate_stealth_ascii_perf_smoke(
            4 * 1024 * 1024,
            Duration::from_secs(2),
            STEALTH_ASCII_INTERNAL_TARGETS,
        );
        assert!(!fail);
    }

    #[test]
    fn inject_pattern_preserves_short_pattern_length_and_rejects_overflow_positions() {
        for pattern_len in 1..=15 {
            let mut data = vec![0xA5u8; 32];
            let pattern = vec![pattern_len as u8; pattern_len];
            inject_pattern(&mut data, &pattern, &[4, usize::MAX]);
            assert_eq!(&data[4..4 + pattern_len], pattern.as_slice());
            assert!(data[4 + pattern_len..].iter().all(|&byte| byte == 0xA5));
        }
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn inject_pattern_sse2_short_pattern_writes_exact_length() {
        let mut data = vec![0x5Au8; 32];
        let pattern = [1u8, 2, 3, 4, 5];
        // SAFETY: x86_64 guarantees SSE2, and the helper validates the full
        // destination window before using its raw vector stores.
        unsafe { inject_pattern_sse2(&mut data, &pattern, &[8]) };
        assert_eq!(&data[8..13], &pattern);
        assert!(data[13..].iter().all(|&byte| byte == 0x5A));
    }
}
