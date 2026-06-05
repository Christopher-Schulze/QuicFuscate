//! SIMD byte classification helpers for compression preprocessing.

#[cfg(target_arch = "x86_64")]
use crate::optimize::CpuFeature;
#[cfg(target_arch = "aarch64")]
use crate::optimize::CpuProfile;
use crate::optimize::FeatureDetector;

#[derive(Copy, Clone, Debug, Default)]
pub struct PayloadCounters {
    pub len: usize,
    pub ascii_printable: u32,
    pub newline: u32,
    pub carriage_return: u32,
    pub tab: u32,
    pub nulls: u32,
    pub high_bytes: u32,
}

impl PayloadCounters {
    #[inline(always)]
    pub fn merge(&mut self, other: &Self) {
        self.len += other.len;
        self.ascii_printable += other.ascii_printable;
        self.newline += other.newline;
        self.carriage_return += other.carriage_return;
        self.tab += other.tab;
        self.nulls += other.nulls;
        self.high_bytes += other.high_bytes;
    }
}

#[inline(always)]
pub fn classify(bytes: &[u8]) -> PayloadCounters {
    if bytes.is_empty() {
        return PayloadCounters::default();
    }

    #[cfg(target_arch = "x86_64")]
    {
        let det = FeatureDetector::instance();
        if det.has_feature(CpuFeature::AVX512F) && det.has_feature(CpuFeature::AVX512BW) {
            unsafe { return classify_avx512(bytes) };
        }
        if det.has_feature(CpuFeature::AVX2) {
            unsafe { return classify_avx2(bytes) };
        }
        if det.has_feature(CpuFeature::SSE2) {
            unsafe { return classify_sse2(bytes) };
        }
    }

    #[cfg(target_arch = "aarch64")]
    {
        let profile = FeatureDetector::instance().profile();
        if matches!(
            profile,
            CpuProfile::ARM_A0
                | CpuProfile::ARM_A1a
                | CpuProfile::ARM_A1b
                | CpuProfile::ARM_A1c
                | CpuProfile::ARM_A1d
                | CpuProfile::ARM_A2
                | CpuProfile::Apple_M
        ) {
            unsafe { return classify_neon(bytes) };
        }
    }

    classify_scalar(bytes)
}

#[inline(always)]
fn classify_scalar(bytes: &[u8]) -> PayloadCounters {
    let mut counters = PayloadCounters { len: bytes.len(), ..Default::default() };
    for &b in bytes {
        if (0x20..=0x7E).contains(&b) {
            counters.ascii_printable += 1;
        } else if b == b'\n' {
            counters.newline += 1;
        } else if b == b'\r' {
            counters.carriage_return += 1;
        } else if b == b'\t' {
            counters.tab += 1;
        }
        if b == 0 {
            counters.nulls += 1;
        }
        if b & 0x80 != 0 {
            counters.high_bytes += 1;
        }
    }
    counters
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "sse2")]
unsafe fn classify_sse2(bytes: &[u8]) -> PayloadCounters {
    use std::arch::x86_64::*;

    let len = bytes.len();
    let mut counters = PayloadCounters { len, ..Default::default() };

    let mut i = 0usize;
    let ascii_lower = _mm_set1_epi8((0x20 - 1) as i8);
    let ascii_upper = _mm_set1_epi8(0x7F as i8);
    let newline = _mm_set1_epi8(b'\n' as i8);
    let carriage = _mm_set1_epi8(b'\r' as i8);
    let tab = _mm_set1_epi8(b'\t' as i8);
    let zero = _mm_setzero_si128();

    while i + 16 <= len {
        let ptr = bytes.as_ptr().add(i) as *const __m128i;
        let v = _mm_loadu_si128(ptr);

        let gt = _mm_cmpgt_epi8(v, ascii_lower);
        let lt = _mm_cmplt_epi8(v, ascii_upper);
        let ascii_mask = _mm_and_si128(gt, lt);
        counters.ascii_printable += _mm_movemask_epi8(ascii_mask).count_ones();

        let newline_mask = _mm_cmpeq_epi8(v, newline);
        counters.newline += _mm_movemask_epi8(newline_mask).count_ones();

        let carriage_mask = _mm_cmpeq_epi8(v, carriage);
        counters.carriage_return += _mm_movemask_epi8(carriage_mask).count_ones();

        let tab_mask = _mm_cmpeq_epi8(v, tab);
        counters.tab += _mm_movemask_epi8(tab_mask).count_ones();

        let zero_mask = _mm_cmpeq_epi8(v, zero);
        counters.nulls += _mm_movemask_epi8(zero_mask).count_ones();

        counters.high_bytes += _mm_movemask_epi8(v).count_ones();
        i += 16;
    }

    if i < len {
        let tail = classify_scalar(&bytes[i..]);
        counters.ascii_printable += tail.ascii_printable;
        counters.newline += tail.newline;
        counters.carriage_return += tail.carriage_return;
        counters.tab += tail.tab;
        counters.nulls += tail.nulls;
        counters.high_bytes += tail.high_bytes;
    }

    counters
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
unsafe fn classify_avx2(bytes: &[u8]) -> PayloadCounters {
    use std::arch::x86_64::*;

    let len = bytes.len();
    let mut counters = PayloadCounters { len, ..Default::default() };
    let mut i = 0usize;

    let ascii_lower = _mm256_set1_epi8((0x20 - 1) as i8);
    let ascii_upper = _mm256_set1_epi8(0x7F as i8);
    let newline = _mm256_set1_epi8(b'\n' as i8);
    let carriage = _mm256_set1_epi8(b'\r' as i8);
    let tab = _mm256_set1_epi8(b'\t' as i8);
    let zero = _mm256_setzero_si256();

    while i + 32 <= len {
        let ptr = bytes.as_ptr().add(i) as *const __m256i;
        let v = _mm256_loadu_si256(ptr);

        let gt = _mm256_cmpgt_epi8(v, ascii_lower);
        let lt = _mm256_cmpgt_epi8(ascii_upper, v);
        let ascii_mask = _mm256_and_si256(gt, lt);
        counters.ascii_printable += _mm256_movemask_epi8(ascii_mask).count_ones();

        let newline_mask = _mm256_cmpeq_epi8(v, newline);
        counters.newline += _mm256_movemask_epi8(newline_mask).count_ones();

        let carriage_mask = _mm256_cmpeq_epi8(v, carriage);
        counters.carriage_return += _mm256_movemask_epi8(carriage_mask).count_ones();

        let tab_mask = _mm256_cmpeq_epi8(v, tab);
        counters.tab += _mm256_movemask_epi8(tab_mask).count_ones();

        let zero_mask = _mm256_cmpeq_epi8(v, zero);
        counters.nulls += _mm256_movemask_epi8(zero_mask).count_ones();

        counters.high_bytes += _mm256_movemask_epi8(v).count_ones();
        i += 32;
    }

    if i < len {
        let tail = classify_scalar(&bytes[i..]);
        counters.ascii_printable += tail.ascii_printable;
        counters.newline += tail.newline;
        counters.carriage_return += tail.carriage_return;
        counters.tab += tail.tab;
        counters.nulls += tail.nulls;
        counters.high_bytes += tail.high_bytes;
    }

    counters
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx512f", enable = "avx512bw")]
unsafe fn classify_avx512(bytes: &[u8]) -> PayloadCounters {
    use std::arch::x86_64::*;

    let len = bytes.len();
    let mut counters = PayloadCounters { len, ..Default::default() };
    let mut i = 0usize;

    let ascii_lower = _mm512_set1_epi8((0x20 - 1) as i8);
    let ascii_upper = _mm512_set1_epi8(0x7F as i8);
    let newline = _mm512_set1_epi8(b'\n' as i8);
    let carriage = _mm512_set1_epi8(b'\r' as i8);
    let tab = _mm512_set1_epi8(b'\t' as i8);
    let zero = _mm512_setzero_si512();

    while i + 64 <= len {
        let ptr = bytes.as_ptr().add(i) as *const __m512i;
        let v = _mm512_loadu_si512(ptr);

        let gt = _mm512_cmpgt_epi8_mask(v, ascii_lower);
        let lt = _mm512_cmpgt_epi8_mask(ascii_upper, v);
        let ascii_mask = gt & lt;
        counters.ascii_printable += ascii_mask.count_ones();

        let newline_mask = _mm512_cmpeq_epi8_mask(v, newline);
        counters.newline += newline_mask.count_ones();

        let carriage_mask = _mm512_cmpeq_epi8_mask(v, carriage);
        counters.carriage_return += carriage_mask.count_ones();

        let tab_mask = _mm512_cmpeq_epi8_mask(v, tab);
        counters.tab += tab_mask.count_ones();

        let zero_mask = _mm512_cmpeq_epi8_mask(v, zero);
        counters.nulls += zero_mask.count_ones();

        counters.high_bytes += _mm512_movepi8_mask(v).count_ones();
        i += 64;
    }

    if i < len {
        let tail = classify_scalar(&bytes[i..]);
        counters.ascii_printable += tail.ascii_printable;
        counters.newline += tail.newline;
        counters.carriage_return += tail.carriage_return;
        counters.tab += tail.tab;
        counters.nulls += tail.nulls;
        counters.high_bytes += tail.high_bytes;
    }

    counters
}

#[cfg(target_arch = "aarch64")]
#[target_feature(enable = "neon")]
unsafe fn classify_neon(bytes: &[u8]) -> PayloadCounters {
    use std::arch::aarch64::*;

    let len = bytes.len();
    let mut counters = PayloadCounters { len, ..Default::default() };
    let mut i = 0usize;

    let lower = vdupq_n_u8(0x20);
    let upper = vdupq_n_u8(0x7E);
    let newline = vdupq_n_u8(b'\n');
    let carriage = vdupq_n_u8(b'\r');
    let tab = vdupq_n_u8(b'\t');
    let zero = vdupq_n_u8(0);
    let high_threshold = vdupq_n_u8(0x80);
    let ones = vdupq_n_u8(1);

    while i + 16 <= len {
        let ptr = bytes.as_ptr().add(i);
        let v = vld1q_u8(ptr);

        let ge = vcgeq_u8(v, lower);
        let le = vcleq_u8(v, upper);
        let ascii_mask = vandq_u8(ge, le);
        counters.ascii_printable += vaddvq_u8(vandq_u8(ascii_mask, ones)) as u32;

        let newline_mask = vceqq_u8(v, newline);
        counters.newline += vaddvq_u8(vandq_u8(newline_mask, ones)) as u32;

        let carriage_mask = vceqq_u8(v, carriage);
        counters.carriage_return += vaddvq_u8(vandq_u8(carriage_mask, ones)) as u32;

        let tab_mask = vceqq_u8(v, tab);
        counters.tab += vaddvq_u8(vandq_u8(tab_mask, ones)) as u32;

        let zero_mask = vceqq_u8(v, zero);
        counters.nulls += vaddvq_u8(vandq_u8(zero_mask, ones)) as u32;

        let high_mask = vcgeq_u8(v, high_threshold);
        counters.high_bytes += vaddvq_u8(vandq_u8(high_mask, ones)) as u32;

        i += 16;
    }

    if i < len {
        let tail = classify_scalar(&bytes[i..]);
        counters.ascii_printable += tail.ascii_printable;
        counters.newline += tail.newline;
        counters.carriage_return += tail.carriage_return;
        counters.tab += tail.tab;
        counters.nulls += tail.nulls;
        counters.high_bytes += tail.high_bytes;
    }

    counters
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_classify_empty() {
        let c = classify(&[]);
        assert_eq!(c.len, 0);
        assert_eq!(c.ascii_printable, 0);
        assert_eq!(c.newline, 0);
        assert_eq!(c.carriage_return, 0);
        assert_eq!(c.tab, 0);
        assert_eq!(c.nulls, 0);
        assert_eq!(c.high_bytes, 0);
    }

    #[test]
    fn test_classify_ascii_printable() {
        let input = b"Hello World";
        let c = classify(input);
        assert_eq!(c.len, 11);
        // All 11 bytes are in 0x20..=0x7E (letters + space)
        assert_eq!(c.ascii_printable, 11);
        assert_eq!(c.newline, 0);
        assert_eq!(c.carriage_return, 0);
        assert_eq!(c.tab, 0);
        assert_eq!(c.nulls, 0);
        assert_eq!(c.high_bytes, 0);
    }

    #[test]
    fn test_classify_whitespace() {
        // 3 newlines, 2 carriage returns, 4 tabs
        let input = b"\n\n\n\r\r\t\t\t\t";
        let c = classify(input);
        assert_eq!(c.len, 9);
        assert_eq!(c.newline, 3);
        assert_eq!(c.carriage_return, 2);
        assert_eq!(c.tab, 4);
        assert_eq!(c.ascii_printable, 0);
        assert_eq!(c.nulls, 0);
        assert_eq!(c.high_bytes, 0);
    }

    #[test]
    fn test_classify_null_bytes() {
        let input = [0u8; 5];
        let c = classify(&input);
        assert_eq!(c.len, 5);
        assert_eq!(c.nulls, 5);
        assert_eq!(c.ascii_printable, 0);
        assert_eq!(c.high_bytes, 0);
    }

    #[test]
    fn test_classify_high_bytes() {
        let input: Vec<u8> = (0x80..=0xFF).collect();
        let c = classify(&input);
        assert_eq!(c.len, 128);
        assert_eq!(c.high_bytes, 128);
        assert_eq!(c.ascii_printable, 0);
        assert_eq!(c.newline, 0);
        assert_eq!(c.carriage_return, 0);
        assert_eq!(c.tab, 0);
        assert_eq!(c.nulls, 0);
    }

    #[test]
    fn test_classify_mixed_content() {
        // Construct a known mix: "AB\n\r\t" + [0x00, 0xFF]
        let input: &[u8] = &[b'A', b'B', b'\n', b'\r', b'\t', 0x00, 0xFF];
        let c = classify(input);
        assert_eq!(c.len, 7);
        assert_eq!(c.ascii_printable, 2); // 'A', 'B'
        assert_eq!(c.newline, 1);
        assert_eq!(c.carriage_return, 1);
        assert_eq!(c.tab, 1);
        assert_eq!(c.nulls, 1);
        assert_eq!(c.high_bytes, 1); // 0xFF
    }

    #[test]
    fn test_classify_len_matches_input() {
        for size in [0, 1, 7, 16, 17, 31, 32, 33, 63, 64, 65, 128, 255, 1000] {
            let input = vec![b'x'; size];
            let c = classify(&input);
            assert_eq!(c.len, size, "len mismatch for input size {size}");
        }
    }

    #[test]
    fn test_classify_all_256_values() {
        // Each byte value 0..=255 must be classified into exactly one bucket
        // (or zero buckets for "other" control chars like 0x01-0x08, 0x0B-0x0C, 0x0E-0x1F, 0x7F).
        for b in 0u8..=255 {
            let c = classify(&[b]);
            assert_eq!(c.len, 1, "byte {b:#04X}: len must be 1");

            let is_printable = (0x20..=0x7E).contains(&b);
            let is_newline = b == b'\n';
            let is_cr = b == b'\r';
            let is_tab = b == b'\t';
            let is_null = b == 0;
            let is_high = b & 0x80 != 0;

            assert_eq!(
                c.ascii_printable,
                u32::from(is_printable),
                "byte {b:#04X}: ascii_printable"
            );
            assert_eq!(c.newline, u32::from(is_newline), "byte {b:#04X}: newline");
            assert_eq!(c.carriage_return, u32::from(is_cr), "byte {b:#04X}: carriage_return");
            assert_eq!(c.tab, u32::from(is_tab), "byte {b:#04X}: tab");
            assert_eq!(c.nulls, u32::from(is_null), "byte {b:#04X}: nulls");
            assert_eq!(c.high_bytes, u32::from(is_high), "byte {b:#04X}: high_bytes");

            // Verify mutual exclusivity: at most one of the primary categories fires
            let primary_count = u32::from(is_printable)
                + u32::from(is_newline)
                + u32::from(is_cr)
                + u32::from(is_tab)
                + u32::from(is_null)
                + u32::from(is_high);
            assert!(
                primary_count <= 1,
                "byte {b:#04X}: classified into {primary_count} categories"
            );
        }
    }

    #[test]
    fn test_merge_sums_fields() {
        let mut a = PayloadCounters {
            len: 10,
            ascii_printable: 5,
            newline: 2,
            carriage_return: 1,
            tab: 1,
            nulls: 0,
            high_bytes: 1,
        };
        let b = PayloadCounters {
            len: 20,
            ascii_printable: 8,
            newline: 3,
            carriage_return: 2,
            tab: 4,
            nulls: 1,
            high_bytes: 2,
        };
        a.merge(&b);
        assert_eq!(a.len, 30);
        assert_eq!(a.ascii_printable, 13);
        assert_eq!(a.newline, 5);
        assert_eq!(a.carriage_return, 3);
        assert_eq!(a.tab, 5);
        assert_eq!(a.nulls, 1);
        assert_eq!(a.high_bytes, 3);
    }

    #[test]
    fn test_classify_large_payload() {
        // 4096 bytes exercises SIMD paths (NEON=16-byte lanes, SSE2=16, AVX2=32, AVX512=64)
        // Pattern: repeating cycle of 8 byte types to cover all categories
        let pattern: &[u8] = &[b'A', b'\n', b'\r', b'\t', 0x00, 0xFF, 0x01, b'~'];
        let input: Vec<u8> = pattern.iter().copied().cycle().take(4096).collect();
        let c = classify(&input);

        assert_eq!(c.len, 4096);
        let repeats = 4096 / 8; // = 512 full cycles
        assert_eq!(c.ascii_printable, repeats as u32 * 2); // 'A' + '~'
        assert_eq!(c.newline, repeats as u32);
        assert_eq!(c.carriage_return, repeats as u32);
        assert_eq!(c.tab, repeats as u32);
        assert_eq!(c.nulls, repeats as u32);
        assert_eq!(c.high_bytes, repeats as u32); // 0xFF
                                                  // 0x01 is "other" - not counted in any bucket

        // Verify totals: counted categories + uncounted "other" = total length
        let counted =
            c.ascii_printable + c.newline + c.carriage_return + c.tab + c.nulls + c.high_bytes;
        let uncounted = 4096 - counted as usize; // 0x01 bytes
        assert_eq!(uncounted, repeats); // 512 bytes of 0x01
    }
}
