//! optimize::simd::core (TODO-563).

use super::super::telemetry;
use super::super::{FeatureDetector, SimdDispatch};

/// Central XOR blocks implementation - used by FEC, Crypto, everywhere!
#[inline(always)]
pub fn xor_blocks(dst: &mut [u8], src: &[u8]) {
    SimdDispatch::xor_blocks(dst, src);
}

/// Central population count - used for statistics, pattern matching
#[inline(always)]
pub fn popcnt(data: &[u8]) -> usize {
    SimdDispatch::popcnt(data)
}

/// IEEE CRC-32 computation with hardware acceleration where the polynomial matches.
#[inline(always)]
pub fn crc32(data: &[u8], initial: u32) -> u32 {
    #[cfg(target_arch = "aarch64")]
    {
        let features = FeatureDetector::instance().features_full();
        if features.crc32 {
            // SAFETY: Runtime feature detection matches the callee's target feature.
            // ARM's CRC32 instructions implement the IEEE polynomial used here.
            return unsafe { crc32_armv8(data, initial) };
        }
    }

    // x86 SSE4.2 CRC instructions implement CRC32C (Castagnoli), not IEEE CRC-32.
    crc32_scalar(data, initial)
}

/// XOR payload with a repeating 32-byte key using optimal SIMD.
/// The key must have length 32.
#[inline(always)]
pub fn xor_repeating_key_32(dst: &mut [u8], key32: &[u8; 32]) {
    let features = FeatureDetector::instance().features_full();

    #[cfg(target_arch = "x86_64")]
    unsafe {
        if features.avx2 {
            return xor_repeating_key32_avx2(dst, key32);
        }
        if features.sse2 {
            return xor_repeating_key32_sse2(dst, key32);
        }
    }

    #[cfg(target_arch = "aarch64")]
    unsafe {
        if features.sve2 {
            return xor_repeating_key32_sve2(dst, key32);
        }
        if features.neon {
            return xor_repeating_key32_neon(dst, key32);
        }
    }

    // Scalar fallback
    let mut i = 0usize;
    let n = dst.len();
    while i < n {
        let take = (n - i).min(32);
        for j in 0..take {
            dst[i + j] ^= key32[j];
        }
        i += take;
    }
}

/// XOR payload with a repeating key of arbitrary length and start offset.
#[inline(always)]
pub fn xor_repeating_key(dst: &mut [u8], key: &[u8], start: usize) {
    if key.is_empty() || dst.is_empty() {
        return;
    }

    if key.len() == 32 && start.is_multiple_of(32) {
        if let Ok(k32) = <&[u8; 32]>::try_from(key) {
            xor_repeating_key_32(dst, k32);
            return;
        }
    }

    let features = FeatureDetector::instance().features_full();
    let start_mod = start % key.len();

    #[cfg(target_arch = "x86_64")]
    unsafe {
        if features.avx2 {
            xor_repeating_key_generic_avx2(dst, key, start_mod);
            return;
        }
        if features.sse2 {
            xor_repeating_key_generic_sse2(dst, key, start_mod);
            return;
        }
    }

    #[cfg(target_arch = "aarch64")]
    unsafe {
        if features.sve2 {
            xor_repeating_key_generic_sve2(dst, key, start_mod);
            return;
        }
        if features.neon {
            xor_repeating_key_generic_neon(dst, key, start_mod);
            return;
        }
    }

    xor_repeating_key_scalar(dst, key, start_mod);
}

// x86_64 backends
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
unsafe fn xor_repeating_key32_avx2(dst: &mut [u8], key32: &[u8; 32]) {
    use std::arch::x86_64::*;
    let key_vec = _mm256_loadu_si256(key32.as_ptr() as *const __m256i);
    let mut i = 0usize;
    let n = dst.len();
    while i + 32 <= n {
        let data = _mm256_loadu_si256(dst.as_ptr().add(i) as *const __m256i);
        let result = _mm256_xor_si256(data, key_vec);
        _mm256_storeu_si256(dst.as_mut_ptr().add(i) as *mut __m256i, result);
        i += 32;
    }
    while i < n {
        dst[i] ^= key32[i % 32];
        i += 1;
    }
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "sse2")]
unsafe fn xor_repeating_key32_sse2(dst: &mut [u8], key32: &[u8; 32]) {
    use std::arch::x86_64::*;
    let key_low = _mm_loadu_si128(key32.as_ptr() as *const __m128i);
    let key_high = _mm_loadu_si128(key32.as_ptr().add(16) as *const __m128i);
    let mut i = 0usize;
    let n = dst.len();
    while i + 32 <= n {
        let data_low = _mm_loadu_si128(dst.as_ptr().add(i) as *const __m128i);
        let data_high = _mm_loadu_si128(dst.as_ptr().add(i + 16) as *const __m128i);
        let result_low = _mm_xor_si128(data_low, key_low);
        let result_high = _mm_xor_si128(data_high, key_high);
        _mm_storeu_si128(dst.as_mut_ptr().add(i) as *mut __m128i, result_low);
        _mm_storeu_si128(dst.as_mut_ptr().add(i + 16) as *mut __m128i, result_high);
        i += 32;
    }
    while i < n {
        dst[i] ^= key32[i % 32];
        i += 1;
    }
}

// aarch64 backend
#[cfg(target_arch = "aarch64")]
#[target_feature(enable = "neon")]
unsafe fn xor_repeating_key32_neon(dst: &mut [u8], key32: &[u8; 32]) {
    xor_repeating_key_generic_neon(dst, key32, 0);
}

#[cfg(target_arch = "aarch64")]
unsafe fn xor_repeating_key32_sve2(dst: &mut [u8], key32: &[u8; 32]) {
    #[cfg(target_feature = "sve2")]
    {
        xor_repeating_key32_sve2_impl(dst, key32);
        return;
    }

    #[cfg(not(target_feature = "sve2"))]
    {
        xor_repeating_key32_neon(dst, key32);
    }
}

#[cfg(all(target_arch = "aarch64", target_feature = "sve2"))]
#[target_feature(enable = "sve2")]
unsafe fn xor_repeating_key32_sve2_impl(dst: &mut [u8], key32: &[u8; 32]) {
    xor_repeating_key_generic_sve2_impl(dst, key32, 0);
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
unsafe fn xor_repeating_key_generic_avx2(dst: &mut [u8], key: &[u8], start: usize) {
    use std::arch::x86_64::*;

    if key.is_empty() || dst.is_empty() {
        return;
    }
    let key_len = key.len();
    let mut idx = start % key_len;
    let mut i = 0usize;
    let mut key_buf = [0u8; 32];

    while i + 32 <= dst.len() {
        for lane in key_buf.iter_mut() {
            *lane = key[idx];
            idx += 1;
            if idx == key_len {
                idx = 0;
            }
        }

        let key_vec = _mm256_loadu_si256(key_buf.as_ptr() as *const __m256i);
        let data_vec = _mm256_loadu_si256(dst.as_ptr().add(i) as *const __m256i);
        let result = _mm256_xor_si256(data_vec, key_vec);
        _mm256_storeu_si256(dst.as_mut_ptr().add(i) as *mut __m256i, result);

        i += 32;
    }

    while i < dst.len() {
        dst[i] ^= key[idx];
        idx += 1;
        if idx == key_len {
            idx = 0;
        }
        i += 1;
    }
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "sse2")]
unsafe fn xor_repeating_key_generic_sse2(dst: &mut [u8], key: &[u8], start: usize) {
    use std::arch::x86_64::*;

    if key.is_empty() || dst.is_empty() {
        return;
    }
    let key_len = key.len();
    let mut idx = start % key_len;
    let mut i = 0usize;
    let mut key_buf = [0u8; 16];

    while i + 16 <= dst.len() {
        for lane in key_buf.iter_mut() {
            *lane = key[idx];
            idx += 1;
            if idx == key_len {
                idx = 0;
            }
        }

        let key_vec = _mm_loadu_si128(key_buf.as_ptr() as *const __m128i);
        let data_vec = _mm_loadu_si128(dst.as_ptr().add(i) as *const __m128i);
        let result = _mm_xor_si128(data_vec, key_vec);
        _mm_storeu_si128(dst.as_mut_ptr().add(i) as *mut __m128i, result);

        i += 16;
    }

    while i < dst.len() {
        dst[i] ^= key[idx];
        idx += 1;
        if idx == key_len {
            idx = 0;
        }
        i += 1;
    }
}

#[cfg(target_arch = "aarch64")]
#[target_feature(enable = "neon")]
unsafe fn xor_repeating_key_generic_neon(dst: &mut [u8], key: &[u8], start: usize) {
    use std::arch::aarch64::*;

    if key.is_empty() || dst.is_empty() {
        return;
    }
    let key_len = key.len();
    let mut idx = start % key_len;
    let mut i = 0usize;
    let mut key_buf = [0u8; 16];

    while i + 16 <= dst.len() {
        for lane in key_buf.iter_mut() {
            *lane = key[idx];
            idx += 1;
            if idx == key_len {
                idx = 0;
            }
        }

        let key_vec = vld1q_u8(key_buf.as_ptr());
        let data_vec = vld1q_u8(dst.as_ptr().add(i));
        let result = veorq_u8(data_vec, key_vec);
        vst1q_u8(dst.as_mut_ptr().add(i), result);

        i += 16;
    }

    while i < dst.len() {
        dst[i] ^= key[idx];
        idx += 1;
        if idx == key_len {
            idx = 0;
        }
        i += 1;
    }
}

#[cfg(target_arch = "aarch64")]
unsafe fn xor_repeating_key_generic_sve2(dst: &mut [u8], key: &[u8], start: usize) {
    #[cfg(target_feature = "sve2")]
    {
        xor_repeating_key_generic_sve2_impl(dst, key, start);
        return;
    }

    #[cfg(not(target_feature = "sve2"))]
    {
        xor_repeating_key_generic_neon(dst, key, start);
    }
}

#[cfg(all(target_arch = "aarch64", target_feature = "sve2"))]
#[target_feature(enable = "sve2")]
unsafe fn xor_repeating_key_generic_sve2_impl(dst: &mut [u8], key: &[u8], start: usize) {
    use std::arch::aarch64::*;

    if key.is_empty() || dst.is_empty() {
        return;
    }

    const MAX_SVE_BYTES: usize = 256;
    let len = dst.len();
    let vl = svcntb() as usize;
    debug_assert!(vl <= MAX_SVE_BYTES);

    let key_len = key.len();
    let mut idx = start % key_len;
    let mut offset = 0usize;
    let mut key_buf = [0u8; MAX_SVE_BYTES];

    while offset < len {
        let remaining = len - offset;
        let take = remaining.min(vl);
        let pg = svwhilelt_b8(0, take as u64);

        for lane in 0..take {
            key_buf[lane] = key[idx];
            idx += 1;
            if idx == key_len {
                idx = 0;
            }
        }

        let key_vec = svld1_u8(pg, key_buf.as_ptr());
        let data_vec = svld1_u8(pg, dst.as_ptr().add(offset));
        let result = sveor_u8_m(pg, data_vec, key_vec);
        svst1_u8(pg, dst.as_mut_ptr().add(offset), result);

        offset += take;
    }
}

#[inline(always)]
fn xor_repeating_key_scalar(dst: &mut [u8], key: &[u8], start: usize) {
    if key.is_empty() || dst.is_empty() {
        return;
    }

    let key_len = key.len();
    let mut idx = start % key_len;
    for byte in dst.iter_mut() {
        *byte ^= key[idx];
        idx += 1;
        if idx == key_len {
            idx = 0;
        }
    }
}

/// Ultra-fast CRC32 with ARMv8 CRC32 instructions (aarch64)
#[cfg(target_arch = "aarch64")]
#[target_feature(enable = "crc")]
unsafe fn crc32_armv8(data: &[u8], mut crc: u32) -> u32 {
    use std::arch::aarch64::*;

    crc = !crc; // CRC32 uses inverted initial value
    let mut i = 0;
    let len = data.len();

    // Process 8 bytes at a time with CRC32X instruction
    while i + 8 <= len {
        let chunk = u64::from_le_bytes([
            data[i],
            data[i + 1],
            data[i + 2],
            data[i + 3],
            data[i + 4],
            data[i + 5],
            data[i + 6],
            data[i + 7],
        ]);
        crc = __crc32d(crc, chunk);
        i += 8;
    }

    // Process 4 bytes
    if i + 4 <= len {
        let chunk = u32::from_le_bytes([data[i], data[i + 1], data[i + 2], data[i + 3]]);
        crc = __crc32w(crc, chunk);
        i += 4;
    }

    // Process 2 bytes
    if i + 2 <= len {
        let chunk = u16::from_le_bytes([data[i], data[i + 1]]);
        crc = __crc32h(crc, chunk);
        i += 2;
    }

    // Process remaining byte
    if i < len {
        crc = __crc32b(crc, data[i]);
    }

    telemetry::CRC32_ARM_OPS.inc();
    !crc // Return with final inversion
}

/// Scalar CRC32 fallback implementation
#[inline(always)]
fn crc32_scalar(data: &[u8], mut crc: u32) -> u32 {
    // CRC32 polynomial: 0x04C11DB7 (Ethernet, PNG, etc.)
    const CRC32_TABLE: [u32; 256] = generate_crc32_table();

    crc = !crc; // CRC32 uses inverted initial value

    for &byte in data {
        let table_idx = ((crc ^ byte as u32) & 0xFF) as usize;
        crc = (crc >> 8) ^ CRC32_TABLE[table_idx];
    }

    telemetry::CRC32_SCALAR_OPS.inc();
    !crc // Return with final inversion
}

/// Generate CRC32 lookup table at compile time
const fn generate_crc32_table() -> [u32; 256] {
    let mut table = [0u32; 256];
    let mut i = 0;

    while i < 256 {
        let mut crc = i as u32;
        let mut j = 0;

        while j < 8 {
            if crc & 1 != 0 {
                crc = (crc >> 1) ^ 0xEDB88320; // Reversed polynomial
            } else {
                crc >>= 1;
            }
            j += 1;
        }

        table[i] = crc;
        i += 1;
    }

    table
}
