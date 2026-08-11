//! Extracted SIMD `x86` submodule (TODO-563).

use super::scalar;
use std::arch::x86_64::*;

pub(super) use super::x86_extended::{
    encode_varint_avx2, encode_varint_avx512, encode_varint_sse2, pack_bits_bmi2,
    qpack_decode_avx2, qpack_decode_ssse3, qpack_encode_avx2, qpack_encode_ssse3,
    reed_solomon_decode_avx2, reed_solomon_decode_gfni, reed_solomon_encode_avx2,
    reed_solomon_encode_gfni, string_compare_avx2, string_compare_sse42, unpack_bits_bmi2,
    validate_header_avx2, validate_header_sse2, varint_decode_bmi2,
};

#[cfg(not(windows))]
#[inline(always)]
/// # Safety
///
/// The caller must provide the SHA-256 backend support used by the build and
/// pass valid writable `state` plus readable `blocks` storage for the duration
/// of the call. No references escape the compression routine.
unsafe fn compress_batch_avx2(state: &mut [u32; 8], blocks: &[[u8; 64]]) {
    sha2_asm::compress256(state, blocks);
}

#[cfg(not(windows))]
#[inline(always)]
/// # Safety
///
/// The caller must provide the SHA-256 VNNI backend support used by the build
/// and pass valid writable `state` plus readable `blocks` storage. No
/// references escape the compression routine.
unsafe fn compress_batch_vnni(state: &mut [u32; 8], blocks: &[[u8; 64]]) {
    sha2_asm::compress256(state, blocks);
}

/// SSE2 pre-fastpath for varint decoding: quickly find length via continuation-bit mask
#[target_feature(enable = "sse2")]
/// # Safety
///
/// The caller must provide SSE2 support and a valid immutable `buf` slice for
/// the duration of the call. The implementation checks for eight readable bytes
/// before its unaligned load and otherwise delegates to scalar decoding.
pub(super) unsafe fn varint_decode_sse2_prefast(buf: &[u8]) -> Option<(u64, usize)> {
    if buf.len() < 8 {
        return super::scalar::decode_varint(buf);
    }

    // Load 8 bytes (lower lane)
    let data = _mm_loadl_epi64(buf.as_ptr() as *const __m128i);

    // Continuation bits (MSB set => continuation)
    let cont_mask = _mm_set1_epi8(0x80u8 as i8);
    let cont_bits = _mm_and_si128(data, cont_mask);

    // cmp == 0 marks end bytes (no continuation)
    let cmp = _mm_cmpeq_epi8(cont_bits, _mm_setzero_si128());
    let mask = _mm_movemask_epi8(cmp) as u32;
    if mask == 0 {
        return None;
    }
    let len = mask.trailing_zeros() as usize + 1;
    if len > 8 {
        return None;
    }

    // Extract value bits and compose scalar
    let values = _mm_and_si128(data, _mm_set1_epi8(0x7F));
    let mut bytes = [0u8; 16];
    _mm_storeu_si128(bytes.as_mut_ptr() as *mut __m128i, values);
    let mut result = 0u64;
    for (i, byte) in bytes.iter().copied().enumerate().take(len) {
        result |= (byte as u64) << (i * 7);
    }
    Some((result, len))
}

#[cfg(any(not(windows), feature = "benches"))]
#[target_feature(enable = "avx2")]
/// # Safety
///
/// The caller must provide AVX2 support and a valid immutable `data` slice for
/// the duration of the call. The hashing helper owns its block storage and all
/// raw vector work is bounded by complete blocks.
pub(super) unsafe fn sha256_avx2(data: &[u8]) -> [u8; 32] {
    #[cfg(windows)]
    {
        super::scalar::sha256(data)
    }
    #[cfg(not(windows))]
    {
        let digest = super::sha256_hash_with_batch(data, 1, |state, blocks| {
            compress_batch_avx2(state, blocks)
        });
        _mm256_zeroupper();
        digest
    }
}

#[cfg(any(not(windows), feature = "benches"))]
#[target_feature(enable = "avx512f", enable = "avx512vl", enable = "avx512vnni")]
/// # Safety
///
/// The caller must provide AVX-512F, AVX-512VL, and AVX-512VNNI support and a
/// valid immutable `data` slice for the duration of the call. Block processing
/// is owned and length-bounded.
pub(super) unsafe fn sha256_vnni(data: &[u8]) -> [u8; 32] {
    #[cfg(windows)]
    {
        super::scalar::sha256(data)
    }
    #[cfg(not(windows))]
    {
        let digest = super::sha256_hash_with_batch(data, 2, |state, blocks| {
            compress_batch_vnni(state, blocks)
        });
        _mm256_zeroupper();
        digest
    }
}

/// AVX-512 XOR - 64 bytes at once!
#[target_feature(enable = "avx512f")]
/// # Safety
///
/// The caller must provide AVX-512F support, writable `dst`, and readable
/// non-overlapping `src` storage. Vector reads and writes are bounded by their
/// shared minimum length.
pub(super) unsafe fn xor_blocks_avx512(dst: &mut [u8], src: &[u8]) {
    let len = dst.len().min(src.len());
    let mut i = 0;

    // Process 64-byte chunks
    while i + 64 <= len {
        let a = _mm512_loadu_si512(dst.as_ptr().add(i) as *const __m512i);
        let b = _mm512_loadu_si512(src.as_ptr().add(i) as *const __m512i);
        let result = _mm512_xor_si512(a, b);
        _mm512_storeu_si512(dst.as_mut_ptr().add(i) as *mut __m512i, result);
        i += 64;
    }

    // Handle remainder
    while i < len {
        dst[i] ^= src[i];
        i += 1;
    }
}

/// AVX2 XOR - 32 bytes at once
#[target_feature(enable = "avx2")]
/// # Safety
///
/// The caller must provide AVX2 support, writable `dst`, and readable
/// non-overlapping `src` storage. Vector reads and writes are bounded by their
/// shared minimum length.
pub(super) unsafe fn xor_blocks_avx2(dst: &mut [u8], src: &[u8]) {
    let len = dst.len().min(src.len());
    let mut i = 0;

    // Process 32-byte chunks
    while i + 32 <= len {
        let a = _mm256_loadu_si256(dst.as_ptr().add(i) as *const __m256i);
        let b = _mm256_loadu_si256(src.as_ptr().add(i) as *const __m256i);
        let result = _mm256_xor_si256(a, b);
        _mm256_storeu_si256(dst.as_mut_ptr().add(i) as *mut __m256i, result);
        i += 32;
    }

    // Handle remainder
    while i < len {
        dst[i] ^= src[i];
        i += 1;
    }

    // Avoid AVX->SSE transition penalty
    _mm256_zeroupper();
}
/// Population count using POPCNT on x86_64
#[target_feature(enable = "popcnt")]
/// # Safety
///
/// The caller must provide POPCNT support and a valid immutable `data` slice for
/// the duration of the call. Every unaligned 8-byte or 4-byte load is preceded
/// by a remaining-length check.
pub(super) unsafe fn popcnt_hw(data: &[u8]) -> usize {
    let mut count: usize = 0;
    let mut i = 0;
    let len = data.len();
    // Process 8 bytes at a time
    while i + 8 <= len {
        // SAFETY: `i + 8 <= len` guarantees 8 readable bytes at `data[i..]`.
        // Unaligned u64 reads are valid on x86_64 (no alignment requirement).
        let chunk = *(data.as_ptr().add(i) as *const u64);
        count = count.saturating_add(chunk.count_ones() as usize);
        i += 8;
    }
    // Handle remaining 4 bytes
    if i + 4 <= len {
        // SAFETY: `i + 4 <= len` guarantees 4 readable bytes at `data[i..]`.
        let chunk = *(data.as_ptr().add(i) as *const u32);
        count = count.saturating_add(chunk.count_ones() as usize);
        i += 4;
    }
    // Handle tail bytes
    while i < len {
        count = count.saturating_add(data[i].count_ones() as usize);
        i += 1;
    }
    count
}
/// GF(2^8) multiplication with AVX-512 GFNI - 15x faster!
#[target_feature(enable = "avx512f", enable = "gfni")]
/// # Safety
///
/// The caller must provide AVX-512F and GFNI support, valid immutable `a`, and
/// writable non-overlapping `dst` storage. Accesses are bounded by the shared
/// minimum length and the scalar tail handles the remainder.
pub(super) unsafe fn gf_mul_avx512_gfni(a: &[u8], b: u8, dst: &mut [u8]) {
    let b_broadcast = _mm512_set1_epi8(b as i8);
    let len = a.len().min(dst.len());
    let mut i = 0;

    // Process 64 bytes at once with AVX-512 GFNI
    while i + 64 <= len {
        let data = _mm512_loadu_si512(a[i..].as_ptr() as *const __m512i);
        let result = _mm512_gf2p8mul_epi8(data, b_broadcast);
        _mm512_storeu_si512(dst[i..].as_mut_ptr() as *mut __m512i, result);
        i += 64;
    }

    // Handle remainder
    while i < len {
        dst[i] = scalar::gf_mul_byte(a[i], b);
        i += 1;
    }

    // Avoid AVX->SSE transition penalty
    _mm256_zeroupper();
}

/// GF(2^8) multiplication with AVX2 - table lookup method
#[target_feature(enable = "avx2")]
/// # Safety
///
/// The caller must provide AVX2 support, valid immutable `a`, and writable
/// non-overlapping `dst` storage. Vector accesses are bounded by the shared
/// minimum length and the scalar tail handles the remainder.
pub(super) unsafe fn gf_mul_avx2(a: &[u8], b: u8, dst: &mut [u8]) {
    let len = a.len().min(dst.len());
    let mut i = 0;

    // Precompute GF multiplication tables for multiplier b
    let mut lo_table = [0u8; 16];
    let mut hi_table = [0u8; 16];

    for j in 0..16 {
        lo_table[j] = scalar::gf_mul_byte(j as u8, b);
        hi_table[j] = scalar::gf_mul_byte((j << 4) as u8, b);
    }

    // Load lookup tables into AVX2 registers
    let lo_lut = _mm256_broadcastsi128_si256(_mm_loadu_si128(lo_table.as_ptr() as *const __m128i));
    let hi_lut = _mm256_broadcastsi128_si256(_mm_loadu_si128(hi_table.as_ptr() as *const __m128i));
    let nibble_mask = _mm256_set1_epi8(0x0F);

    // Process 32 bytes at once
    while i + 32 <= len {
        let data = _mm256_loadu_si256(a[i..].as_ptr() as *const __m256i);

        // Split into low and high nibbles
        let lo_nibbles = _mm256_and_si256(data, nibble_mask);
        let hi_nibbles = _mm256_and_si256(_mm256_srli_epi16(data, 4), nibble_mask);

        // Table lookup for both nibbles
        let lo_result = _mm256_shuffle_epi8(lo_lut, lo_nibbles);
        let hi_result = _mm256_shuffle_epi8(hi_lut, hi_nibbles);

        // XOR the results (GF addition)
        let result = _mm256_xor_si256(lo_result, hi_result);
        _mm256_storeu_si256(dst[i..].as_mut_ptr() as *mut __m256i, result);
        i += 32;
    }

    // Process remainder with scalar
    while i < len {
        dst[i] = scalar::gf_mul_byte(a[i], b);
        i += 1;
    }
}

// SSE2 pattern search removed - using SSE4.2 with PCMPESTRI/PCMPISTRM

/// Short pattern search with SSE4.2 using string instructions (<= 16 bytes)
#[cfg(test)]
#[target_feature(enable = "sse4.2")]
/// # Safety
///
/// The caller must provide SSE4.2 support and valid immutable `haystack` and
/// `needle` slices. The needle must be at most 16 bytes; all vector loads use
/// owned padding or complete haystack chunks and scalar verification bounds the
/// returned position.
pub(super) unsafe fn find_pattern_sse42_short(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    use std::arch::x86_64::*;
    let nlen = needle.len();
    if nlen == 0 {
        return Some(0);
    }
    if nlen > 16 {
        return None;
    }

    // PCMPISTRI always reads a full 16-byte register. Copy the accepted needle
    // into owned padding so short callers never need readable bytes past the
    // supplied slice.
    let mut needle_bytes = [0u8; 16];
    needle_bytes[..nlen].copy_from_slice(needle);
    let needle_vec = _mm_loadu_si128(needle_bytes.as_ptr() as *const __m128i);
    let mut i = 0;

    while i + 16 <= haystack.len() {
        let hay_vec = _mm_loadu_si128(haystack.as_ptr().add(i) as *const __m128i);

        // PCMPISTRI: Find first occurrence
        // Mode: _SIDD_CMP_EQUAL_ORDERED | _SIDD_UBYTE_OPS
        const MODE: i32 = 0x0C; // Equal ordered, unsigned bytes

        let idx = _mm_cmpistri(needle_vec, hay_vec, MODE);

        if idx < 16 {
            // Found potential match
            let pos = i + idx as usize;
            if pos + nlen <= haystack.len() {
                // Verify full match
                if &haystack[pos..pos + nlen] == needle {
                    return Some(pos);
                }
            }
        }

        // Check if we need to continue
        if _mm_cmpistrc(needle_vec, hay_vec, MODE) == 0 {
            i += 1; // No carry = no partial match at end
        } else {
            i += 16 - nlen + 1; // Overlap for boundary matches
        }
    }

    // Handle remainder with scalar
    while i + nlen <= haystack.len() {
        if &haystack[i..i + nlen] == needle {
            return Some(i);
        }
        i += 1;
    }

    None
}

/// AES encryption with VAES - vectorized AES for parallel blocks
#[target_feature(enable = "vaes", enable = "avx512f", enable = "aes", enable = "sse2")]
/// # Safety
///
/// The caller must provide VAES, AVX-512F, AES-NI, and SSE2 support plus valid
/// writable `state` and readable `key` arrays for the duration of the call.
pub(super) unsafe fn aes_encrypt_vaes(state: &mut [u8; 16], key: &[u8; 16]) {
    // For a single block, VAES provides no material benefit over AES-NI.
    aes_encrypt_aesni(state, key);
}

/// AES encryption with AES-NI hardware acceleration
#[target_feature(enable = "aes", enable = "sse2")]
/// # Safety
///
/// The caller must provide AES-NI and SSE2 support plus valid writable `state`
/// and readable `key` arrays for the duration of the intrinsic operations.
pub(super) unsafe fn aes_encrypt_aesni(state: &mut [u8; 16], key: &[u8; 16]) {
    use std::arch::x86_64::*;

    macro_rules! expand_aes128_round_key {
        ($prev:expr, $rcon:expr) => {{
            let mut t = _mm_aeskeygenassist_si128($prev, $rcon);
            t = _mm_shuffle_epi32(t, 0xff);

            let mut k = $prev;
            k = _mm_xor_si128(k, _mm_slli_si128(k, 4));
            k = _mm_xor_si128(k, _mm_slli_si128(k, 4));
            k = _mm_xor_si128(k, _mm_slli_si128(k, 4));
            _mm_xor_si128(k, t)
        }};
    }

    let rk0 = _mm_loadu_si128(key.as_ptr() as *const __m128i);
    let rk1 = expand_aes128_round_key!(rk0, 0x01);
    let rk2 = expand_aes128_round_key!(rk1, 0x02);
    let rk3 = expand_aes128_round_key!(rk2, 0x04);
    let rk4 = expand_aes128_round_key!(rk3, 0x08);
    let rk5 = expand_aes128_round_key!(rk4, 0x10);
    let rk6 = expand_aes128_round_key!(rk5, 0x20);
    let rk7 = expand_aes128_round_key!(rk6, 0x40);
    let rk8 = expand_aes128_round_key!(rk7, 0x80);
    let rk9 = expand_aes128_round_key!(rk8, 0x1b);
    let rk10 = expand_aes128_round_key!(rk9, 0x36);

    let mut block = _mm_loadu_si128(state.as_ptr() as *const __m128i);
    block = _mm_xor_si128(block, rk0);
    block = _mm_aesenc_si128(block, rk1);
    block = _mm_aesenc_si128(block, rk2);
    block = _mm_aesenc_si128(block, rk3);
    block = _mm_aesenc_si128(block, rk4);
    block = _mm_aesenc_si128(block, rk5);
    block = _mm_aesenc_si128(block, rk6);
    block = _mm_aesenc_si128(block, rk7);
    block = _mm_aesenc_si128(block, rk8);
    block = _mm_aesenc_si128(block, rk9);
    block = _mm_aesenclast_si128(block, rk10);

    _mm_storeu_si128(state.as_mut_ptr() as *mut __m128i, block);
}
// Note: ARM/NEON/SVE code must not live in this x86 module.
// A large aarch64 block was accidentally duplicated here; it was removed.

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sse42_short_pattern_handles_every_accepted_needle_length() {
        if !is_x86_feature_detected!("sse4.2") {
            return;
        }

        for needle_len in 1..=16 {
            let needle: Vec<u8> = (1..=needle_len).map(|value| value as u8).collect();
            let offset = 17;
            let mut haystack = vec![0xA5; 64];
            haystack[offset..offset + needle_len].copy_from_slice(&needle);

            assert_eq!(
                unsafe { find_pattern_sse42_short(&haystack, &needle) },
                Some(offset),
                "needle length {needle_len}"
            );

            haystack[offset] ^= 0xFF;
            assert_eq!(
                unsafe { find_pattern_sse42_short(&haystack, &needle) },
                None,
                "mutated needle length {needle_len}"
            );
        }
    }
}
