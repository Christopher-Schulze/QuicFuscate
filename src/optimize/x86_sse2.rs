// x86 SSE2 optimized helpers
// Safety: All functions here require that the CPU supports SSE2.

#[cfg(target_arch = "x86_64")]
use std::arch::x86_64::*;

/// XOR a buffer in-place with a repeating 32-byte key using SSE2.
/// Falls back internally for tail bytes < 16.
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "sse2")]
pub unsafe fn xor_repeating_key32_sse2(dst: &mut [u8], key32: &[u8; 32]) {
    let len = dst.len();
    if len == 0 {
        return;
    }

    // Load key as two 16B lanes
    let k0 = _mm_loadu_si128(key32.as_ptr() as *const __m128i);
    let k1 = _mm_loadu_si128(key32.as_ptr().add(16) as *const __m128i);

    let mut i = 0usize;
    // Process in 32-byte stripes
    while i + 32 <= len {
        let p0 = _mm_loadu_si128(dst.as_ptr().add(i) as *const __m128i);
        let p1 = _mm_loadu_si128(dst.as_ptr().add(i + 16) as *const __m128i);
        let x0 = _mm_xor_si128(p0, k0);
        let x1 = _mm_xor_si128(p1, k1);
        _mm_storeu_si128(dst.as_mut_ptr().add(i) as *mut __m128i, x0);
        _mm_storeu_si128(dst.as_mut_ptr().add(i + 16) as *mut __m128i, x1);
        i += 32;
    }

    // Process remaining 16B chunk if present
    if i + 16 <= len {
        let p = _mm_loadu_si128(dst.as_ptr().add(i) as *const __m128i);
        let x = _mm_xor_si128(p, k0);
        _mm_storeu_si128(dst.as_mut_ptr().add(i) as *mut __m128i, x);
        i += 16;
    }

    // Tail bytes
    while i < len {
        dst[i] ^= key32[i % 32];
        i += 1;
    }
}

/// SSE2-accelerated in-place XOR with an arbitrary key slice (repeats key).
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "sse2")]
pub unsafe fn xor_repeating_sse2(dst: &mut [u8], key: &[u8]) {
    if key.is_empty() {
        return;
    }
    // If key is 32B, fast path
    if key.len() == 32 {
        let mut k32 = [0u8; 32];
        k32.copy_from_slice(key);
        xor_repeating_key32_sse2(dst, &k32);
        return;
    }
    // Generic: process 16B blocks with repeated 16B view
    let len = dst.len();
    let mut i = 0usize;
    while i + 16 <= len {
        let mut kblock = [0u8; 16];
        for j in 0..16 {
            kblock[j] = key[(i + j) % key.len()];
        }
        let k = _mm_loadu_si128(kblock.as_ptr() as *const __m128i);
        let p = _mm_loadu_si128(dst.as_ptr().add(i) as *const __m128i);
        let x = _mm_xor_si128(p, k);
        _mm_storeu_si128(dst.as_mut_ptr().add(i) as *mut __m128i, x);
        i += 16;
    }
    while i < len {
        dst[i] ^= key[i % key.len()];
        i += 1;
    }
}
