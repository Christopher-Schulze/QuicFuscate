//! Ultra-sophisticated string acceleration module
//! SIMD string operations, fast parsing, pattern matching

#[cfg(any(test, feature = "rust-tests"))]
use crate::optimize::FeatureDetector;

/// Compatibility projection for the qf-cpu runtime owner.
pub use qf_cpu::string::string_contains;

/// Rust parity/test-only accelerated base64 encoding helper.
#[inline(always)]
#[cfg(any(test, feature = "rust-tests"))]
pub fn base64_encode(data: &[u8]) -> String {
    #[cfg(target_arch = "aarch64")]
    let features = FeatureDetector::instance().features_full();

    #[cfg(target_arch = "aarch64")]
    {
        if features.sve2 {
            // SAFETY: the exact runtime SVE2 feature is proven above.
            return unsafe { base64_encode_sve2(data) };
        }
        if features.neon {
            // SAFETY: the exact runtime NEON feature is proven above.
            return unsafe { base64_encode_neon(data) };
        }
    }

    // Fallback to standard base64
    base64_encode_scalar(data)
}

#[cfg(any(test, feature = "rust-tests"))]
fn base64_encode_scalar(data: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    let mut result = String::with_capacity(data.len().div_ceil(3) * 4);

    for chunk in data.chunks(3) {
        let b1 = chunk[0];
        let b2 = chunk.get(1).copied().unwrap_or(0);
        let b3 = chunk.get(2).copied().unwrap_or(0);

        let n = ((b1 as usize) << 16) | ((b2 as usize) << 8) | (b3 as usize);

        result.push(TABLE[(n >> 18) & 63] as char);
        result.push(TABLE[(n >> 12) & 63] as char);
        result.push(if chunk.len() > 1 { TABLE[(n >> 6) & 63] } else { b'=' } as char);
        result.push(if chunk.len() > 2 { TABLE[n & 63] } else { b'=' } as char);
    }

    result
}

/// NEON-optimized base64 encoding - 4x faster on ARM
#[cfg(all(target_arch = "aarch64", any(test, feature = "rust-tests")))]
#[target_feature(enable = "neon")]
unsafe fn base64_encode_neon(data: &[u8]) -> String {
    use std::arch::aarch64::*;

    const PACK_PERMUTATION: [u8; 16] =
        [0, 1, 2, 0x80, 3, 4, 5, 0x80, 6, 7, 8, 0x80, 9, 10, 11, 0x80];
    const WORD_SELECT: [u8; 16] =
        [0, 4, 8, 12, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80];
    const OUTPUT_ORDER: [u8; 16] = [0, 8, 16, 24, 1, 9, 17, 25, 2, 10, 18, 26, 3, 11, 19, 27];

    let perm = vld1q_u8(PACK_PERMUTATION.as_ptr());
    let select = vld1q_u8(WORD_SELECT.as_ptr());
    let order = vld1q_u8(OUTPUT_ORDER.as_ptr());
    let mask_6 = vdupq_n_u32(0x3f);

    let mut result = Vec::with_capacity(data.len().div_ceil(3) * 4);
    let mut i = 0;

    while i + 12 <= data.len() {
        let mut block = [0u8; 16];
        block[..12].copy_from_slice(&data[i..i + 12]);

        let src = vld1q_u8(block.as_ptr());
        let packed = vqtbl1q_u8(src, perm);
        let rev = vrev32q_u8(packed);
        let values = vshrq_n_u32(vreinterpretq_u32_u8(rev), 8);

        let idx0 = vandq_u32(vshrq_n_u32(values, 18), mask_6);
        let idx1 = vandq_u32(vshrq_n_u32(values, 12), mask_6);
        let idx2 = vandq_u32(vshrq_n_u32(values, 6), mask_6);
        let idx3 = vandq_u32(values, mask_6);

        let idx0_bytes = vqtbl1q_u8(vreinterpretq_u8_u32(idx0), select);
        let idx1_bytes = vqtbl1q_u8(vreinterpretq_u8_u32(idx1), select);
        let idx2_bytes = vqtbl1q_u8(vreinterpretq_u8_u32(idx2), select);
        let idx3_bytes = vqtbl1q_u8(vreinterpretq_u8_u32(idx3), select);

        let stage0 = vcombine_u8(vget_low_u8(idx0_bytes), vget_low_u8(idx1_bytes));
        let stage1 = vcombine_u8(vget_low_u8(idx2_bytes), vget_low_u8(idx3_bytes));

        let table = uint8x16x2_t(stage0, stage1);
        let indices = vqtbl2q_u8(table, order);
        let ascii = translate_base64_indices(indices);

        let mut tmp = [0u8; 16];
        vst1q_u8(tmp.as_mut_ptr(), ascii);
        result.extend_from_slice(&tmp);

        i += 12;
    }

    if i < data.len() {
        let remainder = &data[i..];
        let remainder_encoded = base64_encode_scalar(remainder);
        result.extend_from_slice(remainder_encoded.as_bytes());
    }

    String::from_utf8_unchecked(result)
}

#[cfg(all(target_arch = "aarch64", any(test, feature = "rust-tests")))]
unsafe fn base64_encode_sve2(data: &[u8]) -> String {
    #[cfg(target_feature = "sve2")]
    {
        base64_encode_sve2_impl(data)
    }

    #[cfg(not(target_feature = "sve2"))]
    {
        base64_encode_neon(data)
    }
}

#[cfg(all(target_arch = "aarch64", target_feature = "sve2", any(test, feature = "rust-tests")))]
#[target_feature(enable = "sve2")]
/// # Safety
///
/// The caller must prove SVE2 support. `groups` keeps both input and output
/// predicates within one vector, and every temporary slice is bounded by
/// `MAX_BUFFER` before the vector loads and store.
unsafe fn base64_encode_sve2_impl(data: &[u8]) -> String {
    use std::arch::aarch64::*;

    const MAX_BUFFER: usize = 512;

    let vl_bytes = svcntb() as usize;
    // Four output bytes are produced for every three input bytes. Keep the
    // output predicate within one SVE vector; using vl/3 here activated only
    // the first vector lanes and then extended unwritten bytes into the String.
    let groups = (vl_bytes / 4).min(MAX_BUFFER / 4);
    if groups == 0 {
        return base64_encode_neon(data);
    }

    let chunk = groups * 3;
    let out_bytes = groups * 4;

    let mut result = Vec::with_capacity(data.len().div_ceil(3) * 4);
    let mut offset = 0usize;

    let mut idx_a = [0u8; MAX_BUFFER];
    let mut idx_b = [0u8; MAX_BUFFER];
    let mut idx_c = [0u8; MAX_BUFFER];
    let mut case = [0u8; MAX_BUFFER];
    let mut tmp_out = [0u8; MAX_BUFFER];

    let mask3 = svdup_u8(0x03);
    let mask15 = svdup_u8(0x0F);
    let mask63 = svdup_u8(0x3F);
    let case0 = svdup_u8(0);
    let case1 = svdup_u8(1);
    let case2 = svdup_u8(2);
    let case3 = svdup_u8(3);

    while offset + chunk <= data.len() {
        idx_a[..out_bytes].fill(0);
        idx_b[..out_bytes].fill(0);
        idx_c[..out_bytes].fill(0);
        case[..out_bytes].fill(0);

        for g in 0..groups {
            let base = (g * 3) as u8;
            let out_idx = g * 4;

            idx_a[out_idx] = base;
            case[out_idx] = 0;

            idx_a[out_idx + 1] = base;
            idx_b[out_idx + 1] = base + 1;
            case[out_idx + 1] = 1;

            idx_b[out_idx + 2] = base + 1;
            idx_c[out_idx + 2] = base + 2;
            case[out_idx + 2] = 2;

            idx_c[out_idx + 3] = base + 2;
            case[out_idx + 3] = 3;
        }

        let pg_in = svwhilelt_b8(0, chunk as u64);
        let mut src = svdup_u8(0);
        let input_vec = svld1_u8(pg_in, data.as_ptr().add(offset));
        src = svsel_u8(pg_in, input_vec, src);

        let pg_out = svwhilelt_b8(0, out_bytes as u64);
        let idx_a_vec = svld1_u8(pg_out, idx_a.as_ptr());
        let idx_b_vec = svld1_u8(pg_out, idx_b.as_ptr());
        let idx_c_vec = svld1_u8(pg_out, idx_c.as_ptr());
        let case_vec = svld1_u8(pg_out, case.as_ptr());

        let a_vals = svtbl_u8(src, idx_a_vec);
        let b_vals = svtbl_u8(src, idx_b_vec);
        let c_vals = svtbl_u8(src, idx_c_vec);

        let mut indices_vec = svdup_u8(0);

        let mask_case0 = svcmpeq_u8(pg_out, case_vec, case0);
        let idx0 = svlsr_n_u8_z(mask_case0, a_vals, 2);
        indices_vec = svsel_u8(mask_case0, idx0, indices_vec);

        let mask_case1 = svcmpeq_u8(pg_out, case_vec, case1);
        let left1 = svlsl_n_u8_z(mask_case1, svand_u8_z(mask_case1, a_vals, mask3), 4);
        let right1 = svlsr_n_u8_z(mask_case1, b_vals, 4);
        let idx1 = svorr_u8(left1, right1);
        indices_vec = svsel_u8(mask_case1, idx1, indices_vec);

        let mask_case2 = svcmpeq_u8(pg_out, case_vec, case2);
        let left2 = svlsl_n_u8_z(mask_case2, svand_u8_z(mask_case2, b_vals, mask15), 2);
        let right2 = svlsr_n_u8_z(mask_case2, c_vals, 6);
        let idx2 = svorr_u8(left2, right2);
        indices_vec = svsel_u8(mask_case2, idx2, indices_vec);

        let mask_case3 = svcmpeq_u8(pg_out, case_vec, case3);
        let idx3 = svand_u8_z(mask_case3, c_vals, mask63);
        indices_vec = svsel_u8(mask_case3, idx3, indices_vec);

        let ascii_vec = translate_base64_indices_sve2(indices_vec, pg_out);
        svst1_u8(pg_out, tmp_out.as_mut_ptr(), ascii_vec);
        result.extend_from_slice(&tmp_out[..out_bytes]);

        offset += chunk;
    }

    if offset < data.len() {
        let remainder = base64_encode_scalar(&data[offset..]);
        result.extend_from_slice(remainder.as_bytes());
    }

    String::from_utf8_unchecked(result)
}

#[cfg(all(target_arch = "aarch64", target_feature = "sve2"))]
#[target_feature(enable = "sve2")]
unsafe fn translate_base64_indices_sve2(
    indices: std::arch::aarch64::svuint8_t,
    pg: std::arch::aarch64::svbool_t,
) -> std::arch::aarch64::svuint8_t {
    use std::arch::aarch64::*;

    let base_upper = svdup_u8(b'A');
    let base_lower = svdup_u8(b'a');
    let base_zero = svdup_u8(b'0');
    let upper_boundary = svdup_u8(26);
    let lower_boundary = svdup_u8(52);
    let digit_boundary = svdup_u8(62);

    let mut out = svdup_u8(b'/');

    let mask_upper = svcmplt_u8(pg, indices, upper_boundary);
    let upper_vals = svadd_u8_z(mask_upper, indices, base_upper);
    out = svsel_u8(mask_upper, upper_vals, out);

    let ge_26 = svcmpge_u8(pg, indices, upper_boundary);
    let lt_52 = svcmplt_u8(pg, indices, lower_boundary);
    let mask_lower = svand_b_z(ge_26, lt_52);
    let lower_vals =
        svadd_u8_z(mask_lower, svsub_u8_z(mask_lower, indices, upper_boundary), base_lower);
    out = svsel_u8(mask_lower, lower_vals, out);

    let ge_52 = svcmpge_u8(pg, indices, lower_boundary);
    let lt_62 = svcmplt_u8(pg, indices, digit_boundary);
    let mask_digits = svand_b_z(ge_52, lt_62);
    let digit_vals =
        svadd_u8_z(mask_digits, svsub_u8_z(mask_digits, indices, lower_boundary), base_zero);
    out = svsel_u8(mask_digits, digit_vals, out);

    let mask_plus = svcmpeq_u8(pg, indices, svdup_u8(62));
    out = svsel_u8(mask_plus, svdup_u8(b'+'), out);

    out
}

#[cfg(all(target_arch = "aarch64", target_feature = "sve2"))]
#[target_feature(enable = "sve2")]
unsafe fn ascii_to_indices_sve2(
    chars: std::arch::aarch64::svuint8_t,
    pg: std::arch::aarch64::svbool_t,
) -> (std::arch::aarch64::svuint8_t, bool) {
    use std::arch::aarch64::*;

    let mut indices = svdup_u8(0xFF);

    let base_upper = svdup_u8(b'A');
    let base_lower = svdup_u8(b'a');
    let base_zero = svdup_u8(b'0');

    let upper_mask =
        svand_b_z(svcmpge_u8(pg, chars, base_upper), svcmple_u8(pg, chars, svdup_u8(b'Z')));
    let upper_vals = svsub_u8_z(upper_mask, chars, base_upper);
    indices = svsel_u8(upper_mask, upper_vals, indices);

    let lower_mask =
        svand_b_z(svcmpge_u8(pg, chars, base_lower), svcmple_u8(pg, chars, svdup_u8(b'z')));
    let lower_vals =
        svadd_u8_z(lower_mask, svsub_u8_z(lower_mask, chars, base_lower), svdup_u8(26));
    indices = svsel_u8(lower_mask, lower_vals, indices);

    let digit_mask =
        svand_b_z(svcmpge_u8(pg, chars, base_zero), svcmple_u8(pg, chars, svdup_u8(b'9')));
    let digit_vals = svadd_u8_z(digit_mask, svsub_u8_z(digit_mask, chars, base_zero), svdup_u8(52));
    indices = svsel_u8(digit_mask, digit_vals, indices);

    let plus_mask = svcmpeq_u8(pg, chars, svdup_u8(b'+'));
    indices = svsel_u8(plus_mask, svdup_u8(62), indices);

    let slash_mask = svcmpeq_u8(pg, chars, svdup_u8(b'/'));
    indices = svsel_u8(slash_mask, svdup_u8(63), indices);

    let invalid_mask = svcmpeq_u8(pg, indices, svdup_u8(0xFF));
    let valid = !svptest_any(pg, invalid_mask);

    (indices, valid)
}

/// Fast base64 decoding (returns `None` on invalid input)
#[inline(always)]
#[cfg(any(test, feature = "rust-tests"))]
pub fn base64_decode(data: &str) -> Option<Vec<u8>> {
    if !data.len().is_multiple_of(4) {
        return None;
    }

    let bytes = data.as_bytes();
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    let features = FeatureDetector::instance().features_full();

    #[cfg(target_arch = "x86_64")]
    {
        if features.simd_dispatch_matrix().avx2 {
            // SAFETY: the exact AVX2 runtime feature is proven by the dispatch matrix.
            return unsafe { base64_decode_avx2(bytes) };
        }
        if features.sse41 {
            // SAFETY: the exact SSE4.1 runtime feature is proven above.
            return unsafe { base64_decode_sse41(bytes) };
        }
    }

    #[cfg(target_arch = "aarch64")]
    {
        if features.sve2 {
            // SAFETY: the exact runtime SVE2 feature is proven above.
            return unsafe { base64_decode_sve2(bytes) };
        }
        if features.neon {
            // SAFETY: the exact runtime NEON feature is proven above.
            return unsafe { base64_decode_neon(bytes) };
        }
    }

    base64_decode_scalar(data)
}

#[cfg(any(test, feature = "rust-tests"))]
fn base64_decode_scalar(data: &str) -> Option<Vec<u8>> {
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine;

    STANDARD.decode(data.as_bytes()).ok()
}

#[cfg(all(target_arch = "x86_64", any(test, feature = "rust-tests")))]
#[target_feature(enable = "sse4.1")]
unsafe fn base64_decode_sse41(bytes: &[u8]) -> Option<Vec<u8>> {
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine;
    use std::arch::x86_64::*;

    let mut out = Vec::with_capacity(bytes.len() / 4 * 3);
    let mut i = 0usize;

    let invalid = _mm_set1_epi8(-1);
    let a_lo = _mm_set1_epi8((b'A' - 1) as i8);
    let z_hi = _mm_set1_epi8((b'Z' + 1) as i8);
    let a_base = _mm_set1_epi8(b'A' as i8);

    let low_a_lo = _mm_set1_epi8((b'a' - 1) as i8);
    let low_z_hi = _mm_set1_epi8((b'z' + 1) as i8);
    let low_base = _mm_set1_epi8((b'a' as i8) - 26);

    let digit_lo = _mm_set1_epi8((b'0' - 1) as i8);
    let digit_hi = _mm_set1_epi8((b'9' + 1) as i8);
    let digit_base = _mm_set1_epi8(b'0' as i8);
    let digit_bias = _mm_set1_epi8(52);

    let plus_chr = _mm_set1_epi8(b'+' as i8);
    let slash_chr = _mm_set1_epi8(b'/' as i8);
    let val_plus = _mm_set1_epi8(62);
    let val_slash = _mm_set1_epi8(63);

    while i + 16 <= bytes.len() {
        let chunk = &bytes[i..i + 16];
        if chunk.contains(&b'=') {
            break;
        }

        let input = _mm_loadu_si128(chunk.as_ptr() as *const __m128i);

        let ge_a = _mm_cmpgt_epi8(input, a_lo);
        let le_z = _mm_cmpgt_epi8(z_hi, input);
        let mask_upper = _mm_and_si128(ge_a, le_z);
        let val_upper = _mm_sub_epi8(input, a_base);

        let ge_low = _mm_cmpgt_epi8(input, low_a_lo);
        let le_low = _mm_cmpgt_epi8(low_z_hi, input);
        let mask_lower = _mm_and_si128(ge_low, le_low);
        let val_lower = _mm_sub_epi8(input, low_base);

        let ge_digit = _mm_cmpgt_epi8(input, digit_lo);
        let le_digit = _mm_cmpgt_epi8(digit_hi, input);
        let mask_digit = _mm_and_si128(ge_digit, le_digit);
        let val_digit = _mm_add_epi8(_mm_sub_epi8(input, digit_base), digit_bias);

        let mask_plus = _mm_cmpeq_epi8(input, plus_chr);
        let mask_slash = _mm_cmpeq_epi8(input, slash_chr);

        let mut values = _mm_blendv_epi8(invalid, val_upper, mask_upper);
        values = _mm_blendv_epi8(values, val_lower, mask_lower);
        values = _mm_blendv_epi8(values, val_digit, mask_digit);
        values = _mm_blendv_epi8(values, val_plus, mask_plus);
        values = _mm_blendv_epi8(values, val_slash, mask_slash);

        let invalid_mask = _mm_cmpeq_epi8(values, invalid);
        if _mm_movemask_epi8(invalid_mask) != 0 {
            return None;
        }

        let mut vals = [0u8; 16];
        _mm_storeu_si128(vals.as_mut_ptr() as *mut __m128i, values);

        for group in 0..4 {
            let idx = group * 4;
            let v0 = vals[idx] as u32;
            let v1 = vals[idx + 1] as u32;
            let v2 = vals[idx + 2] as u32;
            let v3 = vals[idx + 3] as u32;

            out.push(((v0 << 2) | (v1 >> 4)) as u8);
            out.push(((v1 << 4) | (v2 >> 2)) as u8);
            out.push(((v2 << 6) | v3) as u8);
        }

        i += 16;
    }

    if i < bytes.len() {
        let tail = STANDARD.decode(&bytes[i..]).ok()?;
        out.extend_from_slice(&tail);
    }

    Some(out)
}

#[cfg(all(target_arch = "x86_64", any(test, feature = "rust-tests")))]
#[target_feature(enable = "avx2")]
unsafe fn base64_decode_avx2(bytes: &[u8]) -> Option<Vec<u8>> {
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine;
    use std::arch::x86_64::*;

    let mut out = Vec::with_capacity(bytes.len() / 4 * 3);
    let mut i = 0usize;

    let invalid = _mm256_set1_epi8(-1);
    let a_lo = _mm256_set1_epi8((b'A' - 1) as i8);
    let z_hi = _mm256_set1_epi8((b'Z' + 1) as i8);
    let a_base = _mm256_set1_epi8(b'A' as i8);

    let low_a_lo = _mm256_set1_epi8((b'a' - 1) as i8);
    let low_z_hi = _mm256_set1_epi8((b'z' + 1) as i8);
    let low_base = _mm256_set1_epi8((b'a' as i8) - 26);

    let digit_lo = _mm256_set1_epi8((b'0' - 1) as i8);
    let digit_hi = _mm256_set1_epi8((b'9' + 1) as i8);
    let digit_base = _mm256_set1_epi8(b'0' as i8);
    let digit_bias = _mm256_set1_epi8(52);

    let plus_chr = _mm256_set1_epi8(b'+' as i8);
    let slash_chr = _mm256_set1_epi8(b'/' as i8);
    let val_plus = _mm256_set1_epi8(62);
    let val_slash = _mm256_set1_epi8(63);

    while i + 32 <= bytes.len() {
        let chunk = &bytes[i..i + 32];
        if chunk.contains(&b'=') {
            break;
        }

        let input = _mm256_loadu_si256(chunk.as_ptr() as *const __m256i);

        let ge_a = _mm256_cmpgt_epi8(input, a_lo);
        let le_z = _mm256_cmpgt_epi8(z_hi, input);
        let mask_upper = _mm256_and_si256(ge_a, le_z);
        let val_upper = _mm256_sub_epi8(input, a_base);

        let ge_low = _mm256_cmpgt_epi8(input, low_a_lo);
        let le_low = _mm256_cmpgt_epi8(low_z_hi, input);
        let mask_lower = _mm256_and_si256(ge_low, le_low);
        let val_lower = _mm256_sub_epi8(input, low_base);

        let ge_digit = _mm256_cmpgt_epi8(input, digit_lo);
        let le_digit = _mm256_cmpgt_epi8(digit_hi, input);
        let mask_digit = _mm256_and_si256(ge_digit, le_digit);
        let val_digit = _mm256_add_epi8(_mm256_sub_epi8(input, digit_base), digit_bias);

        let mask_plus = _mm256_cmpeq_epi8(input, plus_chr);
        let mask_slash = _mm256_cmpeq_epi8(input, slash_chr);

        let mut values = _mm256_blendv_epi8(invalid, val_upper, mask_upper);
        values = _mm256_blendv_epi8(values, val_lower, mask_lower);
        values = _mm256_blendv_epi8(values, val_digit, mask_digit);
        values = _mm256_blendv_epi8(values, val_plus, mask_plus);
        values = _mm256_blendv_epi8(values, val_slash, mask_slash);

        let invalid_mask = _mm256_cmpeq_epi8(values, invalid);
        if _mm256_movemask_epi8(invalid_mask) != 0 {
            return None;
        }

        let mut vals = [0u8; 32];
        _mm256_storeu_si256(vals.as_mut_ptr() as *mut __m256i, values);

        for group in 0..8 {
            let idx = group * 4;
            let v0 = vals[idx] as u32;
            let v1 = vals[idx + 1] as u32;
            let v2 = vals[idx + 2] as u32;
            let v3 = vals[idx + 3] as u32;

            out.push(((v0 << 2) | (v1 >> 4)) as u8);
            out.push(((v1 << 4) | (v2 >> 2)) as u8);
            out.push(((v2 << 6) | v3) as u8);
        }

        i += 32;
    }

    if i < bytes.len() {
        let tail = STANDARD.decode(&bytes[i..]).ok()?;
        out.extend_from_slice(&tail);
    }

    Some(out)
}

#[cfg(all(target_arch = "aarch64", any(test, feature = "rust-tests")))]
unsafe fn base64_decode_neon(bytes: &[u8]) -> Option<Vec<u8>> {
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine;
    use std::arch::aarch64::*;

    let mut out = Vec::with_capacity(bytes.len() / 4 * 3);
    let mut i = 0usize;

    let base_a = vdupq_n_u8(b'A');
    let base_z = vdupq_n_u8(b'Z');
    let base_a_low = vdupq_n_u8(b'a');
    let base_z_low = vdupq_n_u8(b'z');
    let base_0 = vdupq_n_u8(b'0');
    let base_9 = vdupq_n_u8(b'9');
    let plus_chr = vdupq_n_u8(b'+');
    let slash_chr = vdupq_n_u8(b'/');
    let invalid_sentinel = vdupq_n_u8(0xFF);

    while i + 16 <= bytes.len() {
        let chunk = &bytes[i..i + 16];
        if chunk.contains(&b'=') {
            break;
        }

        let chars = vld1q_u8(chunk.as_ptr());

        let upper_mask = vandq_u8(vcgeq_u8(chars, base_a), vcleq_u8(chars, base_z));
        let lower_mask = vandq_u8(vcgeq_u8(chars, base_a_low), vcleq_u8(chars, base_z_low));
        let digit_mask = vandq_u8(vcgeq_u8(chars, base_0), vcleq_u8(chars, base_9));
        let plus_mask = vceqq_u8(chars, plus_chr);
        let slash_mask = vceqq_u8(chars, slash_chr);

        let upper_vals = vsubq_u8(chars, base_a);
        let lower_vals = vaddq_u8(vsubq_u8(chars, base_a_low), vdupq_n_u8(26));
        let digit_vals = vaddq_u8(vsubq_u8(chars, base_0), vdupq_n_u8(52));

        let mut values = invalid_sentinel;
        values = vbslq_u8(upper_mask, upper_vals, values);
        values = vbslq_u8(lower_mask, lower_vals, values);
        values = vbslq_u8(digit_mask, digit_vals, values);
        values = vbslq_u8(plus_mask, vdupq_n_u8(62), values);
        values = vbslq_u8(slash_mask, vdupq_n_u8(63), values);

        let invalid_mask = vceqq_u8(values, invalid_sentinel);
        if vmaxvq_u8(invalid_mask) != 0 {
            return None;
        }

        let mut vals = [0u8; 16];
        vst1q_u8(vals.as_mut_ptr(), values);

        for group in 0..4 {
            let idx = group * 4;
            let v0 = vals[idx];
            let v1 = vals[idx + 1];
            let v2 = vals[idx + 2];
            let v3 = vals[idx + 3];

            out.push((v0 << 2) | (v1 >> 4));
            out.push((v1 << 4) | (v2 >> 2));
            out.push((v2 << 6) | v3);
        }

        i += 16;
    }

    if i < bytes.len() {
        let tail = STANDARD.decode(&bytes[i..]).ok()?;
        out.extend_from_slice(&tail);
    }

    Some(out)
}

#[cfg(all(target_arch = "aarch64", any(test, feature = "rust-tests")))]
unsafe fn base64_decode_sve2(bytes: &[u8]) -> Option<Vec<u8>> {
    #[cfg(target_feature = "sve2")]
    {
        base64_decode_sve2_impl(bytes)
    }

    #[cfg(not(target_feature = "sve2"))]
    {
        base64_decode_neon(bytes)
    }
}

#[cfg(all(target_arch = "aarch64", target_feature = "sve2", any(test, feature = "rust-tests")))]
#[target_feature(enable = "sve2")]
unsafe fn base64_decode_sve2_impl(bytes: &[u8]) -> Option<Vec<u8>> {
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine;
    use std::arch::aarch64::*;

    const MAX_BUFFER: usize = 512;

    let vl_bytes = svcntb() as usize;
    let groups = vl_bytes / 4;
    if groups == 0 {
        return base64_decode_neon(bytes);
    }

    let chunk_chars = groups * 4;
    let out_bytes = groups * 3;

    let mut out = Vec::with_capacity(bytes.len() / 4 * 3);
    let mut i = 0usize;

    let mut idx_a = [0u8; MAX_BUFFER];
    let mut idx_b = [0u8; MAX_BUFFER];
    let mut case = [0u8; MAX_BUFFER];
    let mut tmp_out = [0u8; MAX_BUFFER];

    let case0 = svdup_u8(0);
    let case1 = svdup_u8(1);
    let case2 = svdup_u8(2);

    while i + chunk_chars <= bytes.len() {
        let chunk = &bytes[i..i + chunk_chars];
        if chunk.contains(&b'=') {
            break;
        }

        let pg_chars = svwhilelt_b8(0, chunk_chars as u64);
        let chars_vec = svld1_u8(pg_chars, chunk.as_ptr());

        let (indices_vec, valid) = ascii_to_indices_sve2(chars_vec, pg_chars);
        if !valid {
            return None;
        }

        idx_a[..out_bytes].fill(0);
        idx_b[..out_bytes].fill(0);
        case[..out_bytes].fill(0);

        for g in 0..groups {
            let base = (g * 4) as u8;
            let out_idx = g * 3;

            idx_a[out_idx] = base;
            idx_b[out_idx] = base + 1;
            case[out_idx] = 0;

            idx_a[out_idx + 1] = base + 1;
            idx_b[out_idx + 1] = base + 2;
            case[out_idx + 1] = 1;

            idx_a[out_idx + 2] = base + 2;
            idx_b[out_idx + 2] = base + 3;
            case[out_idx + 2] = 2;
        }

        let pg_out = svwhilelt_b8(0, out_bytes as u64);
        let idx_a_vec = svld1_u8(pg_out, idx_a.as_ptr());
        let idx_b_vec = svld1_u8(pg_out, idx_b.as_ptr());
        let case_vec = svld1_u8(pg_out, case.as_ptr());

        let val_a = svtbl_u8(indices_vec, idx_a_vec);
        let val_b = svtbl_u8(indices_vec, idx_b_vec);

        let mut bytes_vec = svdup_u8(0);

        let mask_case0 = svcmpeq_u8(pg_out, case_vec, case0);
        let byte0 =
            svorr_u8(svlsl_n_u8_z(mask_case0, val_a, 2), svlsr_n_u8_z(mask_case0, val_b, 4));
        bytes_vec = svsel_u8(mask_case0, byte0, bytes_vec);

        let mask_case1 = svcmpeq_u8(pg_out, case_vec, case1);
        let byte1 =
            svorr_u8(svlsl_n_u8_z(mask_case1, val_a, 4), svlsr_n_u8_z(mask_case1, val_b, 2));
        bytes_vec = svsel_u8(mask_case1, byte1, bytes_vec);

        let mask_case2 = svcmpeq_u8(pg_out, case_vec, case2);
        let byte2 = svorr_u8(
            svlsl_n_u8_z(mask_case2, val_a, 6),
            svand_u8_z(mask_case2, val_b, svdup_u8(0x3F)),
        );
        bytes_vec = svsel_u8(mask_case2, byte2, bytes_vec);

        svst1_u8(pg_out, tmp_out.as_mut_ptr(), bytes_vec);
        out.extend_from_slice(&tmp_out[..out_bytes]);

        i += chunk_chars;
    }

    if i < bytes.len() {
        let tail = STANDARD.decode(&bytes[i..]).ok()?;
        out.extend_from_slice(&tail);
    }

    Some(out)
}

#[cfg(all(target_arch = "aarch64", any(test, feature = "rust-tests")))]
#[target_feature(enable = "neon")]
unsafe fn translate_base64_indices(
    indices: std::arch::aarch64::uint8x16_t,
) -> std::arch::aarch64::uint8x16_t {
    use std::arch::aarch64::*;

    let offset_a = vdupq_n_u8(26);
    let offset_0 = vdupq_n_u8(52);
    let base_a = vdupq_n_u8(b'a');
    let base_0 = vdupq_n_u8(b'0');
    let base_upper = vdupq_n_u8(b'A');
    let plus = vdupq_n_u8(b'+');
    let slash = vdupq_n_u8(b'/');

    let ge_26 = vcgeq_u8(indices, offset_a);
    let ge_52 = vcgeq_u8(indices, offset_0);
    let ge_62 = vcgeq_u8(indices, vdupq_n_u8(62));
    let eq_63 = vceqq_u8(indices, vdupq_n_u8(63));

    let base = vaddq_u8(indices, base_upper);
    let lower = vaddq_u8(vsubq_u8(indices, offset_a), base_a);
    let digits = vaddq_u8(vsubq_u8(indices, offset_0), base_0);

    let res = vbslq_u8(ge_26, lower, base);
    let res = vbslq_u8(ge_52, digits, res);
    let res = vbslq_u8(ge_62, plus, res);
    vbslq_u8(eq_63, slash, res)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- string_contains: basic correctness ----

    #[test]
    fn string_contains_finds_substring_in_middle() {
        assert!(string_contains("hello world", "lo wo"));
    }

    #[test]
    fn string_contains_finds_substring_at_start() {
        assert!(string_contains("hello world", "hello"));
    }

    #[test]
    fn string_contains_finds_substring_at_end() {
        assert!(string_contains("hello world", "world"));
    }

    #[test]
    fn string_contains_full_match() {
        assert!(string_contains("exact", "exact"));
    }

    #[test]
    fn string_contains_single_char_found() {
        assert!(string_contains("abcdef", "d"));
    }

    #[test]
    fn string_contains_single_char_not_found() {
        assert!(!string_contains("abcdef", "z"));
    }

    #[test]
    fn string_contains_empty_needle_returns_true() {
        assert!(string_contains("anything", ""));
    }

    #[test]
    fn string_contains_empty_haystack_empty_needle() {
        assert!(string_contains("", ""));
    }

    #[test]
    fn string_contains_empty_haystack_nonempty_needle() {
        assert!(!string_contains("", "x"));
    }

    #[test]
    fn string_contains_needle_longer_than_haystack() {
        assert!(!string_contains("ab", "abcdef"));
    }

    #[test]
    fn string_contains_no_match() {
        assert!(!string_contains("the quick brown fox", "lazy dog"));
    }

    #[test]
    fn string_contains_case_sensitive() {
        assert!(!string_contains("Hello World", "hello world"));
        assert!(string_contains("Hello World", "Hello"));
        assert!(!string_contains("ABC", "abc"));
    }

    #[test]
    fn string_contains_repeated_pattern() {
        // Needle appears multiple times - should find any occurrence
        assert!(string_contains("abcabcabc", "cab"));
    }

    #[test]
    fn string_contains_overlapping_partial_matches() {
        // "aab" has a false start at position 0 ("aa" matches first two chars but third fails)
        assert!(string_contains("aaab", "aab"));
    }

    #[test]
    fn string_contains_binary_like_content() {
        // Test with bytes that look like binary data (high ASCII in valid UTF-8)
        let haystack = "prefix\u{00FF}\u{00FE}\u{00FD}suffix";
        let needle = "\u{00FE}\u{00FD}";
        assert!(string_contains(haystack, needle));
    }

    #[test]
    fn string_contains_long_haystack_short_needle() {
        // Force SIMD path (>64 bytes for AVX512, >32 for AVX2, >16 for NEON)
        let haystack = "a]".repeat(100) + "NEEDLE" + &"b[".repeat(100);
        assert!(string_contains(&haystack, "NEEDLE"));
        assert!(!string_contains(&haystack, "MISSING"));
    }

    #[test]
    fn string_contains_long_haystack_needle_at_very_end() {
        // Needle in the scalar fallback tail region after SIMD lanes are exhausted
        let haystack = "x".repeat(200) + "FIN";
        assert!(string_contains(&haystack, "FIN"));
    }

    #[test]
    fn string_contains_long_haystack_needle_at_very_start() {
        let haystack = "START".to_string() + &"y".repeat(200);
        assert!(string_contains(&haystack, "START"));
    }

    #[test]
    fn string_contains_parity_with_std() {
        // Verify SIMD path produces same results as std::str::contains for many cases
        let cases: &[(&str, &str)] = &[
            ("", ""),
            ("a", ""),
            ("", "a"),
            ("a", "a"),
            ("a", "b"),
            ("ab", "a"),
            ("ab", "b"),
            ("ab", "ab"),
            ("ab", "abc"),
            ("abc", "bc"),
            ("abc", "abc"),
            ("the quick brown fox jumps over the lazy dog", "fox"),
            ("the quick brown fox jumps over the lazy dog", "cat"),
            ("aaaaaaaa", "aaa"),
            ("TLS 1.3 handshake", "1.3"),
            ("Content-Type: application/octet-stream", "octet-stream"),
        ];
        for &(haystack, needle) in cases {
            assert_eq!(
                string_contains(haystack, needle),
                haystack.contains(needle),
                "mismatch for haystack={:?} needle={:?}",
                haystack,
                needle,
            );
        }
    }

    #[test]
    fn string_contains_long_needle_forces_fallback() {
        // Needle > 64 bytes forces AVX512 to delegate to AVX2/scalar
        let needle = "X".repeat(70);
        let haystack = "Y".repeat(200) + &needle + &"Z".repeat(200);
        assert!(string_contains(&haystack, &needle));
        assert!(!string_contains(&haystack, &"W".repeat(70)));
    }

    // ---- base64 encode/decode roundtrip ----

    #[test]
    fn base64_roundtrip_empty() {
        let encoded = base64_encode(b"");
        assert_eq!(encoded, "");
        let decoded = base64_decode(&encoded);
        assert_eq!(decoded, Some(vec![]));
    }

    #[test]
    fn base64_roundtrip_single_byte() {
        let encoded = base64_encode(b"\x42");
        let decoded = base64_decode(&encoded);
        assert_eq!(decoded, Some(vec![0x42]));
    }

    #[test]
    fn base64_roundtrip_two_bytes() {
        let encoded = base64_encode(b"\xDE\xAD");
        let decoded = base64_decode(&encoded);
        assert_eq!(decoded, Some(vec![0xDE, 0xAD]));
    }

    #[test]
    fn base64_roundtrip_three_bytes_no_padding() {
        let encoded = base64_encode(b"Man");
        assert_eq!(encoded, "TWFu"); // RFC 4648 test vector
        let decoded = base64_decode(&encoded);
        assert_eq!(decoded, Some(b"Man".to_vec()));
    }

    #[test]
    fn base64_encode_known_vectors() {
        // RFC 4648 section 10 test vectors
        assert_eq!(base64_encode(b""), "");
        assert_eq!(base64_encode(b"f"), "Zg==");
        assert_eq!(base64_encode(b"fo"), "Zm8=");
        assert_eq!(base64_encode(b"foo"), "Zm9v");
        assert_eq!(base64_encode(b"foob"), "Zm9vYg==");
        assert_eq!(base64_encode(b"fooba"), "Zm9vYmE=");
        assert_eq!(base64_encode(b"foobar"), "Zm9vYmFy");
    }

    #[test]
    fn base64_roundtrip_all_byte_values() {
        // Ensure every byte value survives encode -> decode
        let data: Vec<u8> = (0..=255).collect();
        let encoded = base64_encode(&data);
        let decoded = base64_decode(&encoded);
        assert_eq!(decoded, Some(data));
    }

    #[test]
    fn base64_roundtrip_large_buffer() {
        // Force SIMD path (>24 bytes for AVX2, >12 for NEON)
        let data: Vec<u8> = (0..512).map(|i| (i % 256) as u8).collect();
        let encoded = base64_encode(&data);
        let decoded = base64_decode(&encoded);
        assert_eq!(decoded, Some(data));
    }

    #[test]
    fn base64_decode_invalid_length() {
        // Length not a multiple of 4
        assert_eq!(base64_decode("abc"), None);
        assert_eq!(base64_decode("abcde"), None);
    }

    #[test]
    fn base64_decode_invalid_chars() {
        // Characters outside the base64 alphabet
        assert_eq!(base64_decode("!@#$"), None);
    }

    #[test]
    fn base64_decode_with_padding() {
        assert_eq!(base64_decode("Zg=="), Some(b"f".to_vec()));
        assert_eq!(base64_decode("Zm8="), Some(b"fo".to_vec()));
        assert_eq!(base64_decode("Zm9v"), Some(b"foo".to_vec()));
    }

    #[test]
    fn base64_scalar_parity_with_crate() {
        // Verify our scalar encoder matches the base64 crate decoder output
        use base64::engine::general_purpose::STANDARD;
        use base64::Engine;

        let test_data: &[&[u8]] = &[
            b"",
            b"a",
            b"ab",
            b"abc",
            b"abcd",
            b"Hello, World!",
            b"\x00\x01\x02\x03\x04\x05",
            &[0xFF; 48],
        ];

        for data in test_data {
            let our_encoded = base64_encode(data);
            let crate_decoded = STANDARD.decode(our_encoded.as_bytes());
            assert_eq!(
                crate_decoded.ok().as_deref(),
                Some(*data),
                "scalar parity failed for {:?}",
                data,
            );
        }
    }

    #[test]
    fn base64_encode_matches_scalar_at_chunk_boundaries() {
        for len in [0usize, 1, 2, 3, 11, 12, 13, 15, 16, 31, 32, 63, 64, 127, 256, 511, 1024] {
            let data: Vec<u8> = (0..len).map(|index| index as u8).collect();
            assert_eq!(base64_encode(&data), base64_encode_scalar(&data), "length={len}");
        }
    }
}
