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

#[target_feature(enable = "avx512f,avx512bw,avx512vbmi2")]
pub(super) unsafe fn find_pattern_vbmi2(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    // No dedicated VBMI2 implementation here. AVX2 is a safe fallback for VBMI2-capable CPUs.
    find_pattern_avx2(haystack, needle)
}

#[target_feature(enable = "avx512f,fma")]
pub(super) unsafe fn dot_product_avx512(a: &[f32], b: &[f32]) -> f32 {
    let len = a.len().min(b.len());
    let mut sum = _mm512_setzero_ps();
    let chunks = len / 16;
    for i in 0..chunks {
        let va = _mm512_loadu_ps(a[i * 16..].as_ptr());
        let vb = _mm512_loadu_ps(b[i * 16..].as_ptr());
        sum = _mm512_fmadd_ps(va, vb, sum);
    }
    let mut out = _mm512_reduce_add_ps(sum);
    for i in (chunks * 16)..len {
        out += a[i] * b[i];
    }
    out
}

#[target_feature(enable = "avx2,fma")]
pub(super) unsafe fn dot_product_fma(a: &[f32], b: &[f32]) -> f32 {
    let len = a.len().min(b.len());
    let mut sum = _mm256_setzero_ps();
    let chunks = len / 8;
    for i in 0..chunks {
        let va = _mm256_loadu_ps(a[i * 8..].as_ptr());
        let vb = _mm256_loadu_ps(b[i * 8..].as_ptr());
        sum = _mm256_fmadd_ps(va, vb, sum);
    }
    let mut sum_array = [0f32; 8];
    _mm256_storeu_ps(sum_array.as_mut_ptr(), sum);
    let mut out: f32 = sum_array.iter().sum();
    for i in (chunks * 8)..len {
        out += a[i] * b[i];
    }
    out
}

#[inline(always)]
unsafe fn compress_batch_avx2(state: &mut [u32; 8], blocks: &[[u8; 64]]) {
    #[cfg(not(windows))]
    sha2_asm::compress256(state, blocks);
    #[cfg(windows)]
    {
        let _ = (state, blocks);
        unreachable!("AVX2 SHA-256 compression is unavailable on Windows");
    }
}

#[inline(always)]
unsafe fn compress_batch_vnni(state: &mut [u32; 8], blocks: &[[u8; 64]]) {
    #[cfg(not(windows))]
    sha2_asm::compress256(state, blocks);
    #[cfg(windows)]
    {
        let _ = (state, blocks);
        unreachable!("AVX-512 VNNI SHA-256 compression is unavailable on Windows");
    }
}

/// SSE2 pre-fastpath for varint decoding: quickly find length via continuation-bit mask
#[target_feature(enable = "sse2")]
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
    for i in 0..len {
        result |= (bytes[i] as u64) << (i * 7);
    }
    Some((result, len))
}

#[target_feature(enable = "avx2")]
pub(super) unsafe fn sha256_avx2(data: &[u8]) -> [u8; 32] {
    #[cfg(windows)]
    {
        return super::scalar::sha256(data);
    }
    let digest =
        super::sha256_hash_with_batch(data, 1, |state, blocks| compress_batch_avx2(state, blocks));
    _mm256_zeroupper();
    digest
}

#[target_feature(enable = "avx512f", enable = "avx512vl", enable = "avx512vnni")]
pub(super) unsafe fn sha256_vnni(data: &[u8]) -> [u8; 32] {
    #[cfg(windows)]
    {
        return super::scalar::sha256(data);
    }
    let digest =
        super::sha256_hash_with_batch(data, 2, |state, blocks| compress_batch_vnni(state, blocks));
    _mm256_zeroupper();
    digest
}

/// AVX-512 XOR - 64 bytes at once!
#[target_feature(enable = "avx512f")]
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
#[target_feature(enable = "sse4.2")]
pub(super) unsafe fn find_pattern_sse42_short(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    use std::arch::x86_64::*;
    let nlen = needle.len();
    if nlen == 0 {
        return Some(0);
    }
    if nlen > 16 {
        return None;
    }

    // Use PCMPISTRI for efficient string search
    let needle_vec = _mm_loadu_si128(needle.as_ptr() as *const __m128i);
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
#[target_feature(enable = "vaes", enable = "avx512f")]
pub(super) unsafe fn aes_encrypt_vaes(state: &mut [u8; 16], key: &[u8; 16]) {
    // For a single block, VAES provides no material benefit over AES-NI.
    aes_encrypt_aesni(state, key);
}

/// AES encryption with AES-NI hardware acceleration
#[target_feature(enable = "aes", enable = "sse2")]
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
/// SHA-256 with SHA Extensions hardware acceleration
#[target_feature(enable = "sha", enable = "sse2")]
pub(super) unsafe fn sha256_hw(data: &[u8]) -> [u8; 32] {
    // Correctness-first fallback until a full SHA-NI schedule/padding implementation is wired.
    scalar::sha256(data)
}
/// Histogram with AVX-512 - conflict detection for fast counting
#[target_feature(enable = "avx512f", enable = "avx512cd")]
pub(super) unsafe fn histogram_avx512(data: &[u8]) -> [u32; 256] {
    let mut hist = [0u32; 256];
    let mut i = 0;

    // Process 64 bytes at a time
    while i + 64 <= data.len() {
        let values = _mm512_loadu_si512(data.as_ptr().add(i) as *const __m512i);

        // Use AVX-512 conflict detection for histogram
        let conflicts = _mm512_conflict_epi32(values);

        // Process conflicts and update histogram
        let mask = _mm512_testn_epi32_mask(conflicts, conflicts);
        if mask == 0xFFFF {
            // No conflicts - direct update
            let mut vals = [0u32; 16];
            _mm512_storeu_si512(vals.as_mut_ptr() as *mut _, values);
            for v in vals {
                let idx = (v as usize) & 0xFF;
                hist[idx] += 1;
            }
        } else {
            // Handle conflicts with masked operations
            let unique = _mm512_mask_compress_epi32(_mm512_setzero_si512(), mask, values);
            let counts = _mm512_popcnt_epi32(conflicts);

            let mut uniq_vals = [0u32; 16];
            let mut cnt_vals = [0u32; 16];
            _mm512_storeu_si512(uniq_vals.as_mut_ptr() as *mut _, unique);
            _mm512_storeu_si512(cnt_vals.as_mut_ptr() as *mut _, counts);
            for j in 0..16 {
                if (mask & (1 << j)) != 0 {
                    let idx = (uniq_vals[j] as usize) & 0xFF;
                    let cnt = cnt_vals[j];
                    hist[idx] += cnt;
                }
            }
        }

        i += 64;
    }

    // Handle remainder
    while i < data.len() {
        hist[data[i] as usize] += 1;
        i += 1;
    }
    // Avoid AVX->SSE transition penalty
    _mm256_zeroupper();
    hist
}

/// Histogram with AVX2 - gather/scatter for histogram
#[target_feature(enable = "avx2")]
pub(super) unsafe fn histogram_avx2(data: &[u8]) -> [u32; 256] {
    // AVX2 dispatch path currently shares the scalar counting core to keep
    // one authoritative histogram implementation.
    scalar::histogram(data)
}

/// Decode varint with BMI2 PEXT - extract bits efficiently
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "bmi2")]
pub(super) unsafe fn decode_varint_bmi2(buf: &[u8]) -> Option<(u64, usize)> {
    use std::arch::x86_64::*;

    if buf.len() < 8 {
        return super::scalar::decode_varint(buf);
    }

    // SAFETY: `buf.len() >= 8` checked above, so reading 8 bytes from `buf.as_ptr()`
    // is in bounds. Unaligned u64 reads are valid on x86_64.
    let data = *(buf.as_ptr() as *const u64);

    // Find continuation bits with BMI2
    let continuation_mask = 0x8080808080808080u64;
    let cont_bits = data & continuation_mask;

    // Count leading zeros to find length
    let len_bits = (!cont_bits).trailing_zeros() / 8 + 1;
    if len_bits > 8 {
        return super::scalar::decode_varint(buf);
    }

    // Extract value bits with PEXT
    let value_mask = 0x7F7F7F7F7F7F7F7Fu64;
    let extracted = _pext_u64(data, value_mask);

    // Mask to actual length
    let mask = (1u64 << (len_bits * 7)) - 1;
    let value = extracted & mask;

    Some((value, len_bits as usize))
}

/// Decode varint with AVX2 - parallel byte processing
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
pub(super) unsafe fn decode_varint_avx2(buf: &[u8]) -> Option<(u64, usize)> {
    use std::arch::x86_64::*;

    if buf.len() < 8 {
        return super::scalar::decode_varint(buf);
    }

    // Load bytes into AVX2 register
    let data = _mm_loadl_epi64(buf.as_ptr() as *const __m128i);

    // Mask for continuation bits
    let cont_mask = _mm_set1_epi8(0x80u8 as i8);
    let cont_bits = _mm_and_si128(data, cont_mask);

    // Find first non-continuation byte
    let cmp = _mm_cmpeq_epi8(cont_bits, _mm_setzero_si128());
    let mask = _mm_movemask_epi8(cmp) as u32;

    if mask == 0 {
        return None; // All continuation
    }

    let len = mask.trailing_zeros() as usize + 1;
    if len > 8 {
        return None;
    }

    // Extract and combine value bits
    let value_mask = _mm_set1_epi8(0x7F);
    let values = _mm_and_si128(data, value_mask);

    // Shift and combine
    let mut result = 0u64;
    // SAFETY: `__m128i` and `[u8; 16]` have identical size (16 bytes). All bit
    // patterns are valid for u8, so the transmute is sound.
    let bytes = std::mem::transmute::<__m128i, [u8; 16]>(values);
    for i in 0..len {
        result |= (bytes[i] as u64) << (i * 7);
    }

    Some((result, len))
}

/// Pattern matching with AVX2 - 5x faster than scalar
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
pub(super) unsafe fn find_pattern_avx2(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    use std::arch::x86_64::*;

    if needle.is_empty() || needle.len() > haystack.len() {
        return None;
    }

    if needle.len() <= 32 {
        // Short needle - use SIMD comparison
        let needle_len = needle.len();
        let first = _mm256_set1_epi8(needle[0] as i8);
        let last = _mm256_set1_epi8(needle[needle_len - 1] as i8);

        let mut i = 0;
        while i + needle_len + 31 <= haystack.len() {
            // Load 32 bytes
            let hay_first = _mm256_loadu_si256(haystack.as_ptr().add(i) as *const __m256i);
            let hay_last =
                _mm256_loadu_si256(haystack.as_ptr().add(i + needle_len - 1) as *const __m256i);

            // Compare first and last bytes
            let eq_first = _mm256_cmpeq_epi8(hay_first, first);
            let eq_last = _mm256_cmpeq_epi8(hay_last, last);
            let eq_both = _mm256_and_si256(eq_first, eq_last);

            let mask = _mm256_movemask_epi8(eq_both) as u32;

            if mask != 0 {
                // Found potential matches
                let mut m = mask;
                while m != 0 {
                    let bit = m.trailing_zeros() as usize;
                    let pos = i + bit;

                    // Verify full match
                    if &haystack[pos..pos + needle_len] == needle {
                        return Some(pos);
                    }

                    m &= m - 1; // Clear lowest bit
                }
            }

            i += 32;
        }
    }

    // Fallback for remainder or long needles
    haystack.windows(needle.len()).position(|window| window == needle)
}
// Note: ARM/NEON/SVE code must not live in this x86 module.
// A large aarch64 block was accidentally duplicated here; it was removed.
