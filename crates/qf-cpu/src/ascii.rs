//! Runtime-dispatched ASCII append and integer-formatting helpers.

use super::{CpuFeatures, FeatureDetector};

const DEC_DIGITS_LUT: &[u8; 200] = b"00010203040506070809101112131415161718192021222324252627282930313233343536373839404142434445464748495051525354555657585960616263646566676869707172737475767778798081828384858687888990919293949596979899";
const HEX_DIGITS_LUT: &[u8; 16] = b"0123456789abcdef";

/// Hardware-selected byte appender for protocol metadata and numeric fields.
#[derive(Copy, Clone)]
pub struct AsciiSimdBackend {
    features: CpuFeatures,
}

impl AsciiSimdBackend {
    /// Capture the process CPU feature set for repeated append operations.
    #[inline(always)]
    pub fn detect() -> Self {
        Self { features: *FeatureDetector::instance().features_full() }
    }

    /// Append one byte slice without changing its contents.
    #[inline(always)]
    pub fn append_bytes(&self, dst: &mut Vec<u8>, src: &[u8]) {
        append_ascii_with_features(dst, src, self.features);
    }

    /// Append one base-10 `u64` without an intermediate heap allocation.
    #[inline(always)]
    pub fn append_decimal(&self, dst: &mut Vec<u8>, value: u64) {
        let mut scratch = [0u8; 32];
        let digits = decimal_to_ascii(value, &mut scratch);
        append_ascii_with_features(dst, digits, self.features);
    }

    /// Append one lowercase hexadecimal `u64` without an intermediate heap allocation.
    #[inline(always)]
    pub fn append_lower_hex(&self, dst: &mut Vec<u8>, value: u64) {
        let mut scratch = [0u8; 16];
        let digits = lower_hex_to_ascii(value, &mut scratch);
        append_ascii_with_features(dst, digits, self.features);
    }
}

#[inline(always)]
fn decimal_to_ascii(value: u64, scratch: &mut [u8; 32]) -> &[u8] {
    if value == 0 {
        let end = scratch.len();
        scratch[end - 1] = b'0';
        return &scratch[end - 1..end];
    }

    let mut value = value;
    let mut position = scratch.len();
    while value >= 100 {
        let remainder = (value % 100) as usize;
        value /= 100;
        position -= 2;
        let lookup = remainder * 2;
        scratch[position] = DEC_DIGITS_LUT[lookup];
        scratch[position + 1] = DEC_DIGITS_LUT[lookup + 1];
    }

    if value < 10 {
        position -= 1;
        scratch[position] = (value as u8) + b'0';
    } else {
        let lookup = (value as usize) * 2;
        position -= 2;
        scratch[position] = DEC_DIGITS_LUT[lookup];
        scratch[position + 1] = DEC_DIGITS_LUT[lookup + 1];
    }
    &scratch[position..]
}

#[inline(always)]
fn lower_hex_to_ascii(value: u64, scratch: &mut [u8; 16]) -> &[u8] {
    if value == 0 {
        let end = scratch.len();
        scratch[end - 1] = b'0';
        return &scratch[end - 1..end];
    }

    let mut value = value;
    let mut position = scratch.len();
    while value != 0 {
        let nibble = (value & 0xF) as usize;
        value >>= 4;
        position -= 1;
        scratch[position] = HEX_DIGITS_LUT[nibble];
    }
    &scratch[position..]
}

#[inline(always)]
fn append_ascii_with_features(dst: &mut Vec<u8>, src: &[u8], features: CpuFeatures) {
    if src.is_empty() {
        return;
    }

    #[cfg(target_arch = "x86_64")]
    {
        let matrix = features.simd_dispatch_matrix();
        if matrix.avx2 {
            qf_telemetry::STEALTH_ASCII_SIMD_AVX2_BYTES.inc_by(src.len() as u64);
            // SAFETY: the exact AVX2 runtime feature is proven by the dispatch matrix.
            unsafe { append_ascii_avx2(dst, src) };
            return;
        }
        if features.sse2 {
            qf_telemetry::STEALTH_ASCII_SIMD_SSE2_BYTES.inc_by(src.len() as u64);
            // SAFETY: SSE2 is a required x86_64 baseline and is checked explicitly.
            unsafe { append_ascii_sse2(dst, src) };
            return;
        }
    }

    #[cfg(target_arch = "aarch64")]
    if features.neon {
        qf_telemetry::STEALTH_ASCII_SIMD_NEON_BYTES.inc_by(src.len() as u64);
        // SAFETY: the exact runtime NEON feature is proven above.
        unsafe { append_ascii_neon(dst, src) };
        return;
    }

    qf_telemetry::STEALTH_ASCII_SCALAR_BYTES.inc_by(src.len() as u64);
    let start = dst.len();
    dst.resize(start + src.len(), 0);
    dst[start..].copy_from_slice(src);
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
unsafe fn append_ascii_avx2(dst: &mut Vec<u8>, src: &[u8]) {
    use std::arch::x86_64::*;

    let len = src.len();
    let start = dst.len();
    dst.resize(start + len, 0);
    let mut out = dst.as_mut_ptr().add(start);
    let mut index = 0usize;

    while index + 32 <= len {
        let chunk = _mm256_loadu_si256(src.as_ptr().add(index) as *const __m256i);
        _mm256_storeu_si256(out as *mut __m256i, chunk);
        out = out.add(32);
        index += 32;
    }
    if index + 16 <= len {
        let chunk = _mm_loadu_si128(src.as_ptr().add(index) as *const __m128i);
        _mm_storeu_si128(out as *mut __m128i, chunk);
        out = out.add(16);
        index += 16;
    }
    while index < len {
        *out = *src.get_unchecked(index);
        out = out.add(1);
        index += 1;
    }
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "sse2")]
unsafe fn append_ascii_sse2(dst: &mut Vec<u8>, src: &[u8]) {
    use std::arch::x86_64::*;

    let len = src.len();
    let start = dst.len();
    dst.resize(start + len, 0);
    let mut out = dst.as_mut_ptr().add(start);
    let mut index = 0usize;

    while index + 16 <= len {
        let chunk = _mm_loadu_si128(src.as_ptr().add(index) as *const __m128i);
        _mm_storeu_si128(out as *mut __m128i, chunk);
        out = out.add(16);
        index += 16;
    }
    while index < len {
        *out = *src.get_unchecked(index);
        out = out.add(1);
        index += 1;
    }
}

#[cfg(target_arch = "aarch64")]
#[target_feature(enable = "neon")]
unsafe fn append_ascii_neon(dst: &mut Vec<u8>, src: &[u8]) {
    use std::arch::aarch64::*;

    let len = src.len();
    let start = dst.len();
    dst.resize(start + len, 0);
    let mut out = dst.as_mut_ptr().add(start);
    let mut index = 0usize;

    while index + 16 <= len {
        let chunk = vld1q_u8(src.as_ptr().add(index));
        vst1q_u8(out, chunk);
        out = out.add(16);
        index += 16;
    }
    while index < len {
        *out = *src.get_unchecked(index);
        out = out.add(1);
        index += 1;
    }
}

#[cfg(test)]
mod tests {
    use super::AsciiSimdBackend;

    #[test]
    fn appends_bytes_decimal_and_lower_hex_exactly() {
        let backend = AsciiSimdBackend::detect();
        let mut output = Vec::new();
        backend.append_bytes(&mut output, b"prefix:");
        backend.append_decimal(&mut output, u64::MAX);
        backend.append_bytes(&mut output, b":");
        backend.append_lower_hex(&mut output, u64::MAX);
        assert_eq!(output, b"prefix:18446744073709551615:ffffffffffffffff");
    }

    #[test]
    fn zero_and_empty_inputs_preserve_exact_output() {
        let backend = AsciiSimdBackend::detect();
        let mut output = b"seed".to_vec();
        backend.append_bytes(&mut output, b"");
        backend.append_decimal(&mut output, 0);
        backend.append_lower_hex(&mut output, 0);
        assert_eq!(output, b"seed00");
    }
}
