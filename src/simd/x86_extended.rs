//! Extracted SIMD `x86_extended` submodule (TODO-563).

use super::scalar;
use super::*;
use std::arch::x86_64::*;

#[target_feature(enable = "avx2")]
unsafe fn avx2_high_nibbles(value: __m256i) -> __m256i {
    let nibble_mask = _mm256_set1_epi8(0x0F);
    let low_byte_nibbles = _mm256_and_si256(_mm256_srli_epi16(value, 4), nibble_mask);
    let high_byte_nibbles = _mm256_slli_epi16(_mm256_srli_epi16(value, 12), 8);
    _mm256_or_si256(low_byte_nibbles, high_byte_nibbles)
}

/// AVX-512/GFNI feature boundary using the canonical scalar algorithm.
#[target_feature(enable = "avx512f", enable = "gfni")]
pub(super) unsafe fn berlekamp_massey_gfni(syndrome: &[u8], len: usize) -> Vec<u8> {
    // The removed vector loop indexed before the syndrome start for short
    // prefixes and updated overlapping polynomial lanes incorrectly. Keep
    // this feature-gated boundary fail-closed on the canonical algorithm.
    scalar::berlekamp_massey(syndrome, len)
}

/// Berlekamp-Massey with AVX2 acceleration when available.
#[target_feature(enable = "avx2")]
pub(super) unsafe fn berlekamp_massey_avx2(syndrome: &[u8], len: usize) -> Vec<u8> {
    // Keep AVX2 routing separate from GFNI/AVX-512 to avoid unsupported instructions.
    scalar::berlekamp_massey(syndrome, len)
}

/// GF(256) matrix multiplication with GFNI
#[target_feature(enable = "avx512f", enable = "gfni")]
pub(super) unsafe fn matmul_gf256_gfni(
    a: &[u8],
    b: &[u8],
    c: &mut [u8],
    m: usize,
    k: usize,
    n: usize,
) {
    let a_len = m.checked_mul(k);
    debug_assert!(a_len.is_some(), "GFNI matrix dimensions overflow for A");
    let Some(a_len) = a_len else { return };
    let b_len = k.checked_mul(n);
    debug_assert!(b_len.is_some(), "GFNI matrix dimensions overflow for B");
    let Some(b_len) = b_len else { return };
    let c_len = m.checked_mul(n);
    debug_assert!(c_len.is_some(), "GFNI matrix dimensions overflow for C");
    let Some(c_len) = c_len else { return };
    debug_assert!(a.len() >= a_len, "GFNI matrix A is smaller than m * k");
    debug_assert!(b.len() >= b_len, "GFNI matrix B is smaller than k * n");
    debug_assert!(c.len() >= c_len, "GFNI matrix C is smaller than m * n");

    // Zero output matrix
    for elem in c.iter_mut().take(c_len) {
        *elem = 0;
    }

    // Matrix multiplication in GF(256)
    for i in 0..m {
        for kk in 0..k {
            if a[i * k + kk] == 0 {
                continue;
            }

            let a_elem = _mm512_set1_epi8(a[i * k + kk] as i8);
            let mut j = 0;

            // Process 64 elements at once
            while j + 64 <= n {
                let b_vec = _mm512_loadu_si512(b[(kk * n + j)..].as_ptr() as *const __m512i);
                let c_vec = _mm512_loadu_si512(c[(i * n + j)..].as_ptr() as *const __m512i);

                // GF(256) multiply and accumulate
                let prod = _mm512_gf2p8mul_epi8(a_elem, b_vec);
                let result = _mm512_xor_si512(c_vec, prod);

                _mm512_storeu_si512(c[(i * n + j)..].as_mut_ptr() as *mut __m512i, result);
                j += 64;
            }

            // Handle remainder
            while j < n {
                c[i * n + j] ^= scalar::gf_mul_byte(a[i * k + kk], b[kk * n + j]);
                j += 1;
            }
        }
    }
}

/// GF(256) matrix multiplication with AVX2
#[target_feature(enable = "avx2")]
pub(super) unsafe fn matmul_gf256_avx2(
    a: &[u8],
    b: &[u8],
    c: &mut [u8],
    m: usize,
    k: usize,
    n: usize,
) {
    let a_len = m.checked_mul(k);
    debug_assert!(a_len.is_some(), "AVX2 matrix dimensions overflow for A");
    let Some(a_len) = a_len else { return };
    let b_len = k.checked_mul(n);
    debug_assert!(b_len.is_some(), "AVX2 matrix dimensions overflow for B");
    let Some(b_len) = b_len else { return };
    let c_len = m.checked_mul(n);
    debug_assert!(c_len.is_some(), "AVX2 matrix dimensions overflow for C");
    let Some(c_len) = c_len else { return };
    debug_assert!(a.len() >= a_len, "AVX2 matrix A is smaller than m * k");
    debug_assert!(b.len() >= b_len, "AVX2 matrix B is smaller than k * n");
    debug_assert!(c.len() >= c_len, "AVX2 matrix C is smaller than m * n");

    // Use AVX2 with lookup tables for GF multiplication
    for elem in c.iter_mut().take(c_len) {
        *elem = 0;
    }

    for i in 0..m {
        for kk in 0..k {
            if a[i * k + kk] == 0 {
                continue;
            }

            // Build lookup tables for this multiplier
            let mut lo_table = [0u8; 16];
            let mut hi_table = [0u8; 16];
            for j in 0..16 {
                lo_table[j] = scalar::gf_mul_byte(j as u8, a[i * k + kk]);
                hi_table[j] = scalar::gf_mul_byte((j << 4) as u8, a[i * k + kk]);
            }

            let lo_lut =
                _mm256_broadcastsi128_si256(_mm_loadu_si128(lo_table.as_ptr() as *const __m128i));
            let hi_lut =
                _mm256_broadcastsi128_si256(_mm_loadu_si128(hi_table.as_ptr() as *const __m128i));
            let nibble_mask = _mm256_set1_epi8(0x0F);

            let mut j = 0;
            while j + 32 <= n {
                let b_vec = _mm256_loadu_si256(b[(kk * n + j)..].as_ptr() as *const __m256i);
                let c_vec = _mm256_loadu_si256(c[(i * n + j)..].as_ptr() as *const __m256i);

                // GF multiply using shuffle
                let lo_nibbles = _mm256_and_si256(b_vec, nibble_mask);
                let hi_nibbles = avx2_high_nibbles(b_vec);
                let lo_result = _mm256_shuffle_epi8(lo_lut, lo_nibbles);
                let hi_result = _mm256_shuffle_epi8(hi_lut, hi_nibbles);
                let prod = _mm256_xor_si256(lo_result, hi_result);

                // XOR accumulate
                let result = _mm256_xor_si256(c_vec, prod);
                _mm256_storeu_si256(c[(i * n + j)..].as_mut_ptr() as *mut __m256i, result);

                j += 32;
            }

            // Handle remainder
            while j < n {
                c[i * n + j] ^= scalar::gf_mul_byte(a[i * k + kk], b[kk * n + j]);
                j += 1;
            }
        }
    }

    _mm256_zeroupper();
}

#[inline(always)]
fn quic_encode_bytes(val: u64, buf: &mut [u8]) -> Option<usize> {
    let (len, prefix) = super::quic_varint_len_prefix(val)?;
    if buf.len() < len {
        return None;
    }
    let mut bytes = val.to_be_bytes();
    let start = 8 - len;
    bytes[start] = (bytes[start] & 0x3F) | ((prefix as u8) << 6);
    buf[..len].copy_from_slice(&bytes[start..start + len]);
    Some(len)
}

#[target_feature(enable = "sse2")]
pub(super) unsafe fn encode_varint_sse2(val: u64, buf: &mut [u8]) -> Option<usize> {
    quic_encode_bytes(val, buf)
}

#[target_feature(enable = "avx2")]
pub(super) unsafe fn encode_varint_avx2(val: u64, buf: &mut [u8]) -> Option<usize> {
    quic_encode_bytes(val, buf)
}

#[target_feature(enable = "avx512f")]
pub(super) unsafe fn encode_varint_avx512(val: u64, buf: &mut [u8]) -> Option<usize> {
    quic_encode_bytes(val, buf)
}

/// Varint encoding with BMI2 acceleration when available.
#[target_feature(enable = "bmi2")]
pub(super) unsafe fn varint_encode_bmi2(mut value: u64, buf: &mut [u8]) -> usize {
    use std::arch::x86_64::*;

    let required_len =
        if value == 0 { 1 } else { ((64 - value.leading_zeros()) as usize).div_ceil(7) };
    debug_assert!(
        buf.len() >= required_len,
        "BMI2 varint output buffer is smaller than the encoded value"
    );

    if value < 128 {
        buf[0] = value as u8;
        return 1;
    }

    // Use BMI2 instructions for efficient bit manipulation
    let mut pos = 0;
    while value >= 128 {
        // Extract 7 bits and set continuation bit
        let byte = _pext_u64(value, 0x7F) | 0x80;
        buf[pos] = byte as u8;
        value >>= 7;
        pos += 1;
    }

    buf[pos] = value as u8;
    pos + 1
}

/// Varint decoding with BMI2 acceleration when available.
#[target_feature(enable = "bmi2")]
pub(super) unsafe fn varint_decode_bmi2(buf: &[u8]) -> Option<(u64, usize)> {
    use std::arch::x86_64::*;

    if buf.is_empty() {
        return None;
    }

    let mut value = 0u64;
    let mut shift = 0;

    for (i, &byte) in buf.iter().enumerate().take(10) {
        // Use BMI2 to extract and deposit bits efficiently
        let bits = _pext_u64(byte as u64, 0x7F);
        value = _pdep_u64(bits, 0x7F << shift) | value;

        if byte & 0x80 == 0 {
            return Some((value, i + 1));
        }

        shift += 7;
        if shift >= 64 {
            return None; // Overflow
        }
    }

    None
}

/// Batch XOR with multiple keys - runtime dispatch
#[inline(always)]
pub fn xor_multi_key(data: &mut [u8], keys: &[&[u8]]) {
    let detector = FeatureDetector::instance();
    let features = detector.features_full();

    // SAFETY: Runtime feature check matches each callee's `#[target_feature]`.
    // Callees iterate keys with internal length checks and scalar tail handling.
    #[cfg(target_arch = "x86_64")]
    {
        if features.avx512f {
            unsafe { xor_multi_key_avx512(data, keys) };
            return;
        }
        if features.avx2 {
            unsafe { xor_multi_key_avx2(data, keys) };
            return;
        }
    }

    #[cfg(target_arch = "aarch64")]
    {
        if features.neon {
            unsafe { super::arm::xor_multi_key_neon(data, keys) };
            return;
        }
    }

    // Scalar fallback
    for key in keys {
        let key_len = key.len();
        if key_len == 0 {
            continue;
        }
        for (i, b) in data.iter_mut().enumerate() {
            *b ^= key[i % key_len];
        }
    }
}

/// Batch XOR with multiple keys (vectorized when available).
#[target_feature(enable = "avx512f")]
pub(super) unsafe fn xor_multi_key_avx512(data: &mut [u8], keys: &[&[u8]]) {
    use std::arch::x86_64::*;

    for key in keys {
        let key_len = key.len();
        if key_len == 0 {
            continue;
        }

        let mut i = 0;

        if key_len == 64 {
            let key_vec = _mm512_loadu_si512(key.as_ptr() as *const __m512i);

            while i + 64 <= data.len() {
                let data_vec = _mm512_loadu_si512(data.as_ptr().add(i) as *const __m512i);
                let result = _mm512_xor_si512(data_vec, key_vec);
                _mm512_storeu_si512(data.as_mut_ptr().add(i) as *mut __m512i, result);
                i += 64;
            }
        }

        while i < data.len() {
            data[i] ^= key[i % key_len];
            i += 1;
        }
    }
}

/// Batch XOR with multiple keys using AVX2 when available.
#[target_feature(enable = "avx2")]
pub(super) unsafe fn xor_multi_key_avx2(data: &mut [u8], keys: &[&[u8]]) {
    use std::arch::x86_64::*;

    for key in keys {
        let key_len = key.len();
        if key_len == 0 {
            continue;
        }

        let mut i = 0;

        if key_len == 32 {
            let key_vec = _mm256_loadu_si256(key.as_ptr() as *const __m256i);

            while i + 32 <= data.len() {
                let data_vec = _mm256_loadu_si256(data.as_ptr().add(i) as *const __m256i);
                let result = _mm256_xor_si256(data_vec, key_vec);
                _mm256_storeu_si256(data.as_mut_ptr().add(i) as *mut __m256i, result);
                i += 32;
            }
        }

        while i < data.len() {
            data[i] ^= key[i % key_len];
            i += 1;
        }
    }

    _mm256_zeroupper();
}

/// Packet header validation with AVX2 when available.
#[target_feature(enable = "avx2")]
pub(super) unsafe fn validate_header_avx2(header: &[u8]) -> bool {
    // Header validation only depends on the first byte. Keep the AVX2 dispatch
    // boundary for API and feature-selection stability, but avoid a discarded
    // 32-byte load and comparison of unrelated header bytes.
    scalar::validate_header(header)
}

/// Packet header validation with SSE2 when available.
#[target_feature(enable = "sse2")]
pub(super) unsafe fn validate_header_sse2(header: &[u8]) -> bool {
    use std::arch::x86_64::*;

    if header.is_empty() {
        return false;
    }

    // Replicate first byte across lanes
    let first = _mm_set1_epi8(header[0] as i8);

    // Check fixed bit (0x40) is set
    let fixed_mask = _mm_set1_epi8(0x40u8 as i8);
    let fixed = _mm_and_si128(first, fixed_mask);
    let fixed_ok = _mm_cmpeq_epi8(fixed, fixed_mask);
    if _mm_movemask_epi8(fixed_ok) != 0xFFFF {
        return false;
    }

    // For short headers (0x80 not set): reserved bits 0x18 must be zero
    if (header[0] & 0x80) == 0 {
        let reserved_mask = _mm_set1_epi8(0x18u8 as i8);
        let reserved = _mm_and_si128(first, reserved_mask);
        let zero = _mm_setzero_si128();
        let reserved_ok = _mm_cmpeq_epi8(reserved, zero);
        if _mm_movemask_epi8(reserved_ok) != 0xFFFF {
            return false;
        }
    }

    true
}

/// Pack bits with BMI2 acceleration when available.
#[target_feature(enable = "bmi2")]
pub(super) unsafe fn pack_bits_bmi2(src: &[u8], bit_width: u8, dst: &mut [u8]) -> usize {
    use std::arch::x86_64::*;

    if !(1..=8).contains(&bit_width) {
        return 0;
    }

    let mut src_idx = 0;
    let mut dst_idx = 0;
    let mut bit_buffer: u64 = 0;
    let mut bits_in_buffer: u32 = 0;

    while src_idx < src.len() {
        let value = src[src_idx] as u64;
        let mask = (1u64 << bit_width) - 1;
        let packed = _pdep_u64(value, mask << bits_in_buffer);

        bit_buffer |= packed;
        bits_in_buffer += bit_width as u32;

        while bits_in_buffer >= 8 {
            if dst_idx >= dst.len() {
                return dst_idx;
            }
            dst[dst_idx] = bit_buffer as u8;
            dst_idx += 1;
            bit_buffer >>= 8;
            bits_in_buffer -= 8;
        }

        src_idx += 1;
    }

    if bits_in_buffer > 0 && dst_idx < dst.len() {
        dst[dst_idx] = bit_buffer as u8;
        dst_idx += 1;
    }

    dst_idx
}

/// Unpack bits with BMI2 acceleration when available.
#[target_feature(enable = "bmi2")]
pub(super) unsafe fn unpack_bits_bmi2(src: &[u8], bit_width: u8, dst: &mut [u8]) -> usize {
    use std::arch::x86_64::*;

    if !(1..=8).contains(&bit_width) {
        return 0;
    }

    let mut src_idx = 0;
    let mut dst_idx = 0;
    let mut bit_buffer: u64 = 0;
    let mut bits_in_buffer: u32 = 0;

    let bw = bit_width as u32;
    let mask = (1u64 << bit_width) - 1;

    while dst_idx < dst.len() {
        while bits_in_buffer < bw && src_idx < src.len() {
            bit_buffer |= (src[src_idx] as u64) << bits_in_buffer;
            src_idx += 1;
            bits_in_buffer += 8;
        }

        if bits_in_buffer >= bw {
            let value = _pext_u64(bit_buffer, mask) as u8;
            dst[dst_idx] = value;
            dst_idx += 1;

            bit_buffer >>= bw;
            bits_in_buffer -= bw;
        } else {
            break;
        }
    }

    dst_idx
}

/// String comparison with AVX2 when available.
#[target_feature(enable = "avx2")]
pub(super) unsafe fn string_compare_avx2(a: &[u8], b: &[u8]) -> bool {
    use std::arch::x86_64::*;

    let len = a.len();
    if len != b.len() {
        return false;
    }

    let mut i = 0;

    while i + 32 <= len {
        let a_vec = _mm256_loadu_si256(a.as_ptr().add(i) as *const __m256i);
        let b_vec = _mm256_loadu_si256(b.as_ptr().add(i) as *const __m256i);

        let cmp = _mm256_cmpeq_epi8(a_vec, b_vec);
        let mask = _mm256_movemask_epi8(cmp);

        if mask != -1i32 {
            return false;
        }

        i += 32;
    }

    while i < len {
        if a[i] != b[i] {
            return false;
        }
        i += 1;
    }

    _mm256_zeroupper();
    true
}

/// String comparison with SSE4.2 when available.
#[target_feature(enable = "sse4.2")]
pub(super) unsafe fn string_compare_sse42(a: &[u8], b: &[u8]) -> bool {
    use std::arch::x86_64::*;

    let len = a.len();
    if len != b.len() {
        return false;
    }

    let mut i = 0;

    while i + 16 <= len {
        let a_vec = _mm_loadu_si128(a.as_ptr().add(i) as *const __m128i);
        let b_vec = _mm_loadu_si128(b.as_ptr().add(i) as *const __m128i);

        let result =
            _mm_cmpestri(a_vec, 16, b_vec, 16, _SIDD_CMP_EQUAL_EACH | _SIDD_NEGATIVE_POLARITY);

        if result != 16 {
            return false;
        }

        i += 16;
    }

    while i < len {
        if a[i] != b[i] {
            return false;
        }
        i += 1;
    }

    true
}

/// POPCNT with AVX-512 VPOPCNTDQ when available (large bitmaps).
#[target_feature(enable = "avx512f", enable = "avx512vpopcntdq")]
pub(super) unsafe fn popcnt_avx512(data: &[u8]) -> usize {
    use std::arch::x86_64::*;

    let mut count = 0usize;
    let mut i = 0;

    while i + 64 <= data.len() {
        let vec = _mm512_loadu_si512(data.as_ptr().add(i) as *const __m512i);
        let counts = _mm512_popcnt_epi64(vec);
        let sum = _mm512_reduce_add_epi64(counts);
        count += sum as usize;

        i += 64;
    }

    while i < data.len() {
        count += data[i].count_ones() as usize;
        i += 1;
    }

    count
}

/// Reed-Solomon encoding with AVX-512 GFNI when available.
#[target_feature(enable = "avx512f", enable = "gfni")]
pub(super) unsafe fn reed_solomon_encode_gfni(data: &[u8], parity_shards: usize) -> Vec<u8> {
    // Generate parity using GFNI for GF(256) operations
    let shard_size = 256;
    let data_shards = data.len().div_ceil(shard_size);
    let total_shards = data_shards + parity_shards;
    let mut output = vec![0u8; total_shards * shard_size];

    // Copy data
    output[..data.len()].copy_from_slice(data);

    // Generate Vandermonde matrix for encoding
    for i in 0..parity_shards {
        for j in 0..data_shards {
            let coeff = scalar::gf_pow((i + 1) as u8, j as u8);
            let coeff_vec = _mm512_set1_epi8(coeff as i8);

            let mut k = 0;
            while k + 64 <= shard_size {
                let src =
                    _mm512_loadu_si512(output[j * shard_size + k..].as_ptr() as *const __m512i);
                let dst = _mm512_loadu_si512(
                    output[(data_shards + i) * shard_size + k..].as_ptr() as *const __m512i
                );

                let prod = _mm512_gf2p8mul_epi8(src, coeff_vec);
                let result = _mm512_xor_si512(dst, prod);

                _mm512_storeu_si512(
                    output[(data_shards + i) * shard_size + k..].as_mut_ptr() as *mut __m512i,
                    result,
                );
                k += 64;
            }
        }
    }

    output
}

/// Reed-Solomon encoding with AVX2 when available.
#[target_feature(enable = "avx2")]
pub(super) unsafe fn reed_solomon_encode_avx2(data: &[u8], parity_shards: usize) -> Vec<u8> {
    use std::arch::x86_64::*;

    let data_shards = (data.len() + 255) / 256;
    let total_shards = data_shards + parity_shards;
    let shard_size = 256;
    let mut output = vec![0u8; total_shards * shard_size];

    // Copy data shards
    output[..data.len()].copy_from_slice(data);

    // Generate Vandermonde matrix for systematic encoding
    let mut matrix = vec![0u8; parity_shards * data_shards];
    for i in 0..parity_shards {
        for j in 0..data_shards {
            matrix[i * data_shards + j] = scalar::gf_pow((i + 1) as u8, j as u8);
        }
    }

    // Compute parity shards using AVX2
    for p in 0..parity_shards {
        let parity_start = (data_shards + p) * shard_size;
        let mut lookup_tables = Vec::with_capacity(data_shards);

        for d in 0..data_shards {
            let coeff = matrix[p * data_shards + d];
            if coeff == 0 {
                continue;
            }

            let (lo_lut, hi_lut) = gf_mul_avx2_tables(coeff);
            lookup_tables.push((d, lo_lut, hi_lut));
        }

        for i in (0..shard_size).step_by(32) {
            let mut parity_vec = _mm256_setzero_si256();
            for &(data_shard, lo_lut, hi_lut) in &lookup_tables {
                let data_start = data_shard * shard_size;
                let data_vec =
                    _mm256_loadu_si256(output.as_ptr().add(data_start + i) as *const __m256i);

                let prod = gf_mul_avx2_vec(data_vec, lo_lut, hi_lut);
                parity_vec = _mm256_xor_si256(parity_vec, prod);
            }

            _mm256_storeu_si256(
                output.as_mut_ptr().add(parity_start + i) as *mut __m256i,
                parity_vec,
            );
        }
    }

    _mm256_zeroupper();
    output
}

fn build_reed_solomon_decode_matrix(
    shards: &[Vec<u8>],
    indices: &[usize],
) -> Result<(Vec<Vec<u8>>, usize, usize), &'static str> {
    if shards.is_empty() {
        return Err("No shards provided");
    }
    if shards.len() != indices.len() {
        return Err("Shard/index length mismatch");
    }

    let shard_size = shards[0].len();
    if !shards.iter().all(|shard| shard.len() == shard_size) {
        return Err("Shard size mismatch");
    }

    let k = shards.len();
    if k > 256 {
        return Err("Too many shards for GF(256)");
    }
    if indices.iter().any(|&index| index > u8::MAX as usize) {
        return Err("Shard index outside GF(256)");
    }

    let augmented_width = k.checked_mul(2).ok_or("Shard count overflow")?;
    let output_len = k.checked_mul(shard_size).ok_or("Output size overflow")?;
    let mut matrix = vec![vec![0u8; augmented_width]; k];

    for (row, &index) in indices.iter().enumerate() {
        let x = index as u8;
        for column in 0..k {
            matrix[row][column] = scalar::gf_pow(x, column as u8);
        }
        matrix[row][k + row] = 1;
    }

    for pivot in 0..k {
        if matrix[pivot][pivot] == 0 {
            let swap_row = ((pivot + 1)..k).find(|&row| matrix[row][pivot] != 0);
            if let Some(swap_row) = swap_row {
                matrix.swap(pivot, swap_row);
            } else {
                return Err("Matrix not invertible");
            }
        }

        let pivot_inverse = scalar::gf_inv(matrix[pivot][pivot]);
        for column in pivot..augmented_width {
            matrix[pivot][column] = scalar::gf_mul_byte(matrix[pivot][column], pivot_inverse);
        }

        for row in 0..k {
            if row == pivot {
                continue;
            }
            let factor = matrix[row][pivot];
            if factor == 0 {
                continue;
            }
            for column in pivot..augmented_width {
                matrix[row][column] ^= scalar::gf_mul_byte(matrix[pivot][column], factor);
            }
        }
    }

    Ok((matrix, shard_size, output_len))
}

/// Reed-Solomon decoding with GFNI when available.
#[target_feature(enable = "avx512f", enable = "gfni")]
pub(super) unsafe fn reed_solomon_decode_gfni(
    shards: &[Vec<u8>],
    indices: &[usize],
) -> Result<Vec<u8>, &'static str> {
    let (matrix, shard_size, output_len) = build_reed_solomon_decode_matrix(shards, indices)?;
    let k = shards.len();
    let mut output = vec![0u8; output_len];

    for output_row in 0..k {
        let output_start = output_row * shard_size;
        for shard_index in 0..k {
            let coeff = matrix[output_row][k + shard_index];
            if coeff == 0 {
                continue;
            }

            let shard_data = &shards[shard_index];
            let coeff_vec = _mm512_set1_epi8(coeff as i8);
            let mut offset = 0;
            while offset + 64 <= shard_size {
                let data = _mm512_loadu_si512(shard_data.as_ptr().add(offset) as *const __m512i);
                let current = _mm512_loadu_si512(
                    output.as_ptr().add(output_start + offset) as *const __m512i
                );
                let product = _mm512_gf2p8mul_epi8(data, coeff_vec);
                let result = _mm512_xor_si512(current, product);
                _mm512_storeu_si512(
                    output.as_mut_ptr().add(output_start + offset) as *mut __m512i,
                    result,
                );
                offset += 64;
            }

            while offset < shard_size {
                output[output_start + offset] ^= scalar::gf_mul_byte(shard_data[offset], coeff);
                offset += 1;
            }
        }
    }

    Ok(output)
}

#[target_feature(enable = "avx2")]
unsafe fn gf_mul_avx2_tables(coefficient: u8) -> (__m256i, __m256i) {
    let mut lo_table = [0u8; 16];
    let mut hi_table = [0u8; 16];
    for nibble in 0..16 {
        lo_table[nibble] = scalar::gf_mul_byte(nibble as u8, coefficient);
        hi_table[nibble] = scalar::gf_mul_byte((nibble << 4) as u8, coefficient);
    }

    let lo_lut = _mm256_broadcastsi128_si256(_mm_loadu_si128(lo_table.as_ptr() as *const __m128i));
    let hi_lut = _mm256_broadcastsi128_si256(_mm_loadu_si128(hi_table.as_ptr() as *const __m128i));
    (lo_lut, hi_lut)
}

#[target_feature(enable = "avx2")]
unsafe fn gf_mul_avx2_vec(a: __m256i, lo_lut: __m256i, hi_lut: __m256i) -> __m256i {
    let nibble_mask = _mm256_set1_epi8(0x0F);
    let lo_nibbles = _mm256_and_si256(a, nibble_mask);
    let hi_nibbles = avx2_high_nibbles(a);
    let lo_result = _mm256_shuffle_epi8(lo_lut, lo_nibbles);
    let hi_result = _mm256_shuffle_epi8(hi_lut, hi_nibbles);
    _mm256_xor_si256(lo_result, hi_result)
}

/// Reed-Solomon decoding with AVX2
#[target_feature(enable = "avx2")]
pub(super) unsafe fn reed_solomon_decode_avx2(
    shards: &[Vec<u8>],
    indices: &[usize],
) -> Result<Vec<u8>, &'static str> {
    let (matrix, shard_size, output_len) = build_reed_solomon_decode_matrix(shards, indices)?;
    let k = shards.len();
    let mut output = vec![0u8; output_len];

    for output_row in 0..k {
        let output_start = output_row * shard_size;
        for shard_index in 0..k {
            let coeff = matrix[output_row][k + shard_index];
            if coeff == 0 {
                continue;
            }

            let (lo_lut, hi_lut) = gf_mul_avx2_tables(coeff);
            let shard_data = &shards[shard_index];
            let mut offset = 0;
            while offset + 32 <= shard_size {
                let data = _mm256_loadu_si256(shard_data.as_ptr().add(offset) as *const __m256i);
                let current = _mm256_loadu_si256(
                    output.as_ptr().add(output_start + offset) as *const __m256i
                );
                let product = gf_mul_avx2_vec(data, lo_lut, hi_lut);
                let result = _mm256_xor_si256(current, product);
                _mm256_storeu_si256(
                    output.as_mut_ptr().add(output_start + offset) as *mut __m256i,
                    result,
                );
                offset += 32;
            }

            while offset < shard_size {
                output[output_start + offset] ^= scalar::gf_mul_byte(shard_data[offset], coeff);
                offset += 1;
            }
        }
    }

    _mm256_zeroupper();
    Ok(output)
}

/// QPACK Huffman encoding with AVX2
#[target_feature(enable = "avx2")]
pub(super) unsafe fn qpack_encode_avx2(input: &[u8], output: &mut [u8]) -> usize {
    use crate::transport::h3::qpack::{HUFF_CODES, HUFF_LENS};
    use std::arch::x86_64::*;

    let codes_ptr = HUFF_CODES.as_ptr() as *const i32;
    let mut acc: u128 = 0;
    let mut bits: usize = 0;
    let mut written: usize = 0;
    let mut i = 0usize;

    while i + 8 <= input.len() {
        let chunk = _mm_loadl_epi64(input.as_ptr().add(i) as *const __m128i);
        let idx_vec = _mm256_cvtepu8_epi32(chunk);
        let code_vec = _mm256_i32gather_epi32(codes_ptr, idx_vec, 4);

        let mut idx_arr = [0i32; 8];
        let mut code_arr = [0i32; 8];
        _mm256_storeu_si256(idx_arr.as_mut_ptr() as *mut __m256i, idx_vec);
        _mm256_storeu_si256(code_arr.as_mut_ptr() as *mut __m256i, code_vec);

        for lane in 0..8 {
            let sym = idx_arr[lane] as usize;
            let code = code_arr[lane] as u32 as u128;
            let clen = HUFF_LENS[sym] as usize;

            if bits + clen > 120 {
                while bits >= 8 {
                    let shift = bits - 8;
                    let byte = ((acc >> shift) & 0xff) as u8;
                    if written >= output.len() {
                        return written;
                    }
                    output[written] = byte;
                    written += 1;
                    bits -= 8;
                    acc &= (1u128 << shift) - 1;
                }
            }

            acc = (acc << clen) | code;
            bits += clen;

            while bits >= 8 {
                let shift = bits - 8;
                let byte = ((acc >> shift) & 0xff) as u8;
                if written >= output.len() {
                    return written;
                }
                output[written] = byte;
                written += 1;
                bits -= 8;
                acc &= (1u128 << shift) - 1;
            }
        }

        i += 8;
    }

    while i < input.len() {
        let sym = input[i] as usize;
        let code = HUFF_CODES[sym] as u128;
        let clen = HUFF_LENS[sym] as usize;

        if bits + clen > 120 {
            while bits >= 8 {
                let shift = bits - 8;
                let byte = ((acc >> shift) & 0xff) as u8;
                if written >= output.len() {
                    return written;
                }
                output[written] = byte;
                written += 1;
                bits -= 8;
                acc &= (1u128 << shift) - 1;
            }
        }

        acc = (acc << clen) | code;
        bits += clen;

        while bits >= 8 {
            let shift = bits - 8;
            let byte = ((acc >> shift) & 0xff) as u8;
            if written >= output.len() {
                return written;
            }
            output[written] = byte;
            written += 1;
            bits -= 8;
            acc &= (1u128 << shift) - 1;
        }
        i += 1;
    }

    if bits > 0 {
        if written >= output.len() {
            return written;
        }
        let pad_mask = (1u128 << (8 - bits)) - 1;
        let byte = ((acc << (8 - bits)) | pad_mask) as u8;
        output[written] = byte;
        written += 1;
    }

    written
}

/// QPACK Huffman encoding with SSSE3/SSE4.1 fallback
#[target_feature(enable = "ssse3", enable = "sse4.1")]
pub(super) unsafe fn qpack_encode_ssse3(input: &[u8], output: &mut [u8]) -> usize {
    use crate::transport::h3::qpack::{HUFF_CODES, HUFF_LENS};
    use std::arch::x86_64::*;

    let mut acc: u128 = 0;
    let mut bits: usize = 0;
    let mut written: usize = 0;
    let mut i = 0usize;

    while i + 4 <= input.len() {
        let chunk = _mm_cvtsi32_si128(i32::from_le_bytes([
            input[i],
            input[i + 1],
            input[i + 2],
            input[i + 3],
        ]));
        let idx_vec = _mm_cvtepu8_epi32(chunk);
        let mut idx_arr = [0i32; 4];
        _mm_storeu_si128(idx_arr.as_mut_ptr() as *mut __m128i, idx_vec);

        for lane in 0..4 {
            let sym = idx_arr[lane] as usize;
            let code = HUFF_CODES[sym] as u128;
            let clen = HUFF_LENS[sym] as usize;

            if bits + clen > 120 {
                while bits >= 8 {
                    let shift = bits - 8;
                    let byte = ((acc >> shift) & 0xff) as u8;
                    if written >= output.len() {
                        return written;
                    }
                    output[written] = byte;
                    written += 1;
                    bits -= 8;
                    acc &= (1u128 << shift) - 1;
                }
            }

            acc = (acc << clen) | code;
            bits += clen;

            while bits >= 8 {
                let shift = bits - 8;
                let byte = ((acc >> shift) & 0xff) as u8;
                if written >= output.len() {
                    return written;
                }
                output[written] = byte;
                written += 1;
                bits -= 8;
                acc &= (1u128 << shift) - 1;
            }
        }

        i += 4;
    }

    while i < input.len() {
        let sym = input[i] as usize;
        let code = HUFF_CODES[sym] as u128;
        let clen = HUFF_LENS[sym] as usize;

        if bits + clen > 120 {
            while bits >= 8 {
                let shift = bits - 8;
                let byte = ((acc >> shift) & 0xff) as u8;
                if written >= output.len() {
                    return written;
                }
                output[written] = byte;
                written += 1;
                bits -= 8;
                acc &= (1u128 << shift) - 1;
            }
        }

        acc = (acc << clen) | code;
        bits += clen;

        while bits >= 8 {
            let shift = bits - 8;
            let byte = ((acc >> shift) & 0xff) as u8;
            if written >= output.len() {
                return written;
            }
            output[written] = byte;
            written += 1;
            bits -= 8;
            acc &= (1u128 << shift) - 1;
        }
        i += 1;
    }

    if bits > 0 {
        if written >= output.len() {
            return written;
        }
        let pad_mask = (1u128 << (8 - bits)) - 1;
        let byte = ((acc << (8 - bits)) | pad_mask) as u8;
        output[written] = byte;
        written += 1;
    }

    written
}

/// QPACK Huffman decoding with AVX2 helper (delegates to shared decode)
#[target_feature(enable = "avx2")]
pub(super) unsafe fn qpack_decode_avx2(input: &[u8], output: &mut [u8]) -> usize {
    use crate::transport::h3;
    match h3::qpack::huff_decode_into(input, output) {
        Ok(written) => written,
        Err(h3::Error::BufferTooShort) => output.len(),
        Err(_) => 0,
    }
}

/// QPACK Huffman decoding with SSSE3 helper (reuses shared decode)
#[target_feature(enable = "ssse3")]
pub(super) unsafe fn qpack_decode_ssse3(input: &[u8], output: &mut [u8]) -> usize {
    use crate::transport::h3;
    match h3::qpack::huff_decode_into(input, output) {
        Ok(written) => written,
        Err(h3::Error::BufferTooShort) => output.len(),
        Err(_) => 0,
    }
}

#[cfg(all(test, target_arch = "x86_64"))]
mod tests {
    use super::*;
    use crate::transport::h3::qpack;
    use std::is_x86_feature_detected;

    const SAMPLES: &[&[u8]] = &[
        b"",
        b"quicfuscate",
        b"THE QUICK BROWN FOX JUMPS OVER THE LAZY DOG",
        b"content-type: application/json\r\nacceptable: */*\r\n",
    ];

    #[test]
    fn qpack_avx2_matches_scalar() {
        if !is_x86_feature_detected!("avx2") {
            return;
        }

        let mut all_symbols_storage = vec![0xAA];
        all_symbols_storage.extend(0..=u8::MAX);
        let all_symbols = &all_symbols_storage[1..];

        for sample in SAMPLES.iter().copied().chain(std::iter::once(all_symbols)) {
            let mut scalar_buf = vec![0u8; qpack::huff_estimate_len(sample) + 8];
            let scalar_len = qpack::huff_encode_into(sample, &mut scalar_buf);
            scalar_buf.truncate(scalar_len);

            let mut avx_buf = vec![0u8; scalar_len + 8];
            let avx_len = unsafe { qpack_encode_avx2(sample, &mut avx_buf) };
            avx_buf.truncate(avx_len);

            assert_eq!(scalar_buf, avx_buf);

            let mut decode_buf = vec![0u8; sample.len() + 8];
            let decoded = unsafe { qpack_decode_avx2(&avx_buf, &mut decode_buf) };
            assert_eq!(&decode_buf[..decoded], sample);
        }
    }

    #[test]
    fn qpack_ssse3_matches_scalar() {
        if !is_x86_feature_detected!("ssse3") || !is_x86_feature_detected!("sse4.1") {
            return;
        }

        let mut all_symbols_storage = vec![0xAA];
        all_symbols_storage.extend(0..=u8::MAX);
        let all_symbols = &all_symbols_storage[1..];

        for sample in SAMPLES.iter().copied().chain(std::iter::once(all_symbols)) {
            let mut scalar_buf = vec![0u8; qpack::huff_estimate_len(sample) + 8];
            let scalar_len = qpack::huff_encode_into(sample, &mut scalar_buf);
            scalar_buf.truncate(scalar_len);

            let mut sse_buf = vec![0u8; scalar_len + 8];
            let sse_len = unsafe { qpack_encode_ssse3(sample, &mut sse_buf) };
            sse_buf.truncate(sse_len);

            assert_eq!(scalar_buf, sse_buf);

            let mut decode_buf = vec![0u8; sample.len() + 8];
            let decoded = unsafe { qpack_decode_ssse3(&sse_buf, &mut decode_buf) };
            assert_eq!(&decode_buf[..decoded], sample);
        }
    }

    #[test]
    fn avx2_rs_encode_and_decode_roundtrip_with_tail() {
        if !is_x86_feature_detected!("avx2") {
            return;
        }

        let data: Vec<u8> =
            (0..512).map(|index| (index as u8).wrapping_mul(37).wrapping_add(9)).collect();
        let scalar = crate::simd::scalar::reed_solomon_encode_scalar(&data, 2);
        let avx2 = unsafe { reed_solomon_encode_avx2(&data, 2) };
        assert_eq!(avx2, scalar);

        let shard_size = 65;
        let available = vec![avx2[..shard_size].to_vec(), avx2[512..512 + shard_size].to_vec()];
        let decoded = unsafe { reed_solomon_decode_avx2(&available, &[0, 2]) }
            .expect("AVX2 Reed-Solomon decode");
        let expected = [avx2[..shard_size].to_vec(), avx2[256..256 + shard_size].to_vec()].concat();
        assert_eq!(decoded, expected);
    }

    #[test]
    fn avx2_rs_decode_validates_shard_metadata() {
        if !is_x86_feature_detected!("avx2") {
            return;
        }

        let shards = vec![vec![0u8; 65]];
        assert_eq!(
            unsafe { reed_solomon_decode_avx2(&shards, &[]) },
            Err("Shard/index length mismatch")
        );

        let mismatched = vec![vec![0u8; 65], vec![0u8; 64]];
        assert_eq!(
            unsafe { reed_solomon_decode_avx2(&mismatched, &[0, 1]) },
            Err("Shard size mismatch")
        );
    }

    #[test]
    fn avx2_gf256_matmul_matches_scalar_for_all_byte_positions() {
        if !is_x86_feature_detected!("avx2") {
            return;
        }

        let a = [0x57, 0xA3];
        let b: Vec<u8> =
            (0..130).map(|index| (index as u8).wrapping_mul(19).wrapping_add(7)).collect();
        let mut scalar_output = vec![0u8; 65];
        let mut avx2_output = vec![0u8; 65];
        crate::simd::scalar::matmul_gf256(&a, &b, &mut scalar_output, 1, 2, 65);
        unsafe { matmul_gf256_avx2(&a, &b, &mut avx2_output, 1, 2, 65) };
        assert_eq!(avx2_output, scalar_output);
    }

    #[test]
    fn gfni_rs_encode_preserves_partial_input_shard() {
        if !is_x86_feature_detected!("avx512f") || !is_x86_feature_detected!("gfni") {
            return;
        }

        let data: Vec<u8> =
            (0..257).map(|index| (index as u8).wrapping_mul(23).wrapping_add(5)).collect();
        let scalar = crate::simd::scalar::reed_solomon_encode_scalar(&data, 2);
        let gfni = unsafe { reed_solomon_encode_gfni(&data, 2) };

        assert_eq!(gfni, scalar);
        assert_eq!(&gfni[..data.len()], data.as_slice());
        assert!(gfni[data.len()..2 * 256].iter().all(|&byte| byte == 0));
    }

    #[test]
    fn gfni_rs_encode_and_decode_roundtrip_with_tail() {
        if !is_x86_feature_detected!("avx512f") || !is_x86_feature_detected!("gfni") {
            return;
        }

        let data: Vec<u8> =
            (0..512).map(|index| (index as u8).wrapping_mul(41).wrapping_add(3)).collect();
        let scalar = crate::simd::scalar::reed_solomon_encode_scalar(&data, 2);
        let gfni = unsafe { reed_solomon_encode_gfni(&data, 2) };
        assert_eq!(gfni, scalar);

        let shard_size = 65;
        let available = vec![gfni[..shard_size].to_vec(), gfni[512..512 + shard_size].to_vec()];
        let decoded = unsafe { reed_solomon_decode_gfni(&available, &[0, 2]) }
            .expect("GFNI Reed-Solomon decode");
        let expected = [gfni[..shard_size].to_vec(), gfni[256..256 + shard_size].to_vec()].concat();
        assert_eq!(decoded, expected);
    }
}
