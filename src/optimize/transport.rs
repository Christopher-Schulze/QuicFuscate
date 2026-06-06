//! Ultra-sophisticated transport acceleration module
//! ACK range search, bitmap ops, ECN counting, PN decode, stream frame parsing

#[cfg(target_arch = "aarch64")]
use crate::optimize::telemetry::CONGESTION_NEON_BATCHES;
#[cfg(all(
    target_arch = "x86_64",
    any(test, feature = "rust-tests", feature = "unsafe_rust")
))]
use crate::optimize::telemetry::{CONGESTION_AVX2_BATCHES, CONGESTION_VNNI_BATCHES};
#[cfg(any(test, feature = "rust-tests"))]
use crate::optimize::CpuProfile;
use crate::optimize::FeatureDetector;
use crate::transport::Stats;
#[cfg(target_arch = "x86_64")]
use std::arch::x86_64::*;

/// Number of congestion samples kept in rolling window.
pub const CONGESTION_WINDOW_SIZE: usize = 64;

/// Congestion sample capturing core QUIC transport metrics.
#[derive(Clone, Copy, Default, Debug)]
pub struct CongestionSample {
    pub cwnd: u32,
    pub bytes_in_flight: u32,
    pub delivery_rate: u32,
    pub lost_packets: u32,
}

impl CongestionSample {
    #[inline]
    pub fn from_transport_stats(stats: &Stats) -> Self {
        Self {
            cwnd: stats.cwnd.min(u32::MAX as usize) as u32,
            bytes_in_flight: stats.bytes_in_flight.min(u32::MAX as usize) as u32,
            delivery_rate: stats.delivery_rate.min(u32::MAX as u64) as u32,
            lost_packets: stats.lost.min(u32::MAX as usize) as u32,
        }
    }
}

/// Aggregated congestion summary (rolling history window).
#[derive(Clone, Copy, Default, Debug)]
pub struct CongestionSummary {
    pub total_cwnd: u64,
    pub total_bytes_in_flight: u64,
    pub total_delivery_rate: u64,
    pub total_lost_packets: u64,
    pub congestion_score: u64,
}

/// Aggregate congestion samples using the best available backend (VNNI where possible).
#[inline]
pub fn aggregate_congestion(samples: &[CongestionSample]) -> CongestionSummary {
    if samples.is_empty() {
        return CongestionSummary::default();
    }

    #[cfg(target_arch = "x86_64")]
    {
        let features = FeatureDetector::instance().features_full();
        if features.avx512f && features.avx512vnni {
            return unsafe { aggregate_congestion_vnni(samples) };
        }
        if features.avx2 {
            return unsafe { aggregate_congestion_avx2(samples) };
        }
    }

    #[cfg(target_arch = "aarch64")]
    {
        let features = FeatureDetector::instance().features_full();
        if features.sve2 {
            return unsafe { aggregate_congestion_neon(samples) };
        }
        if features.neon {
            return unsafe { aggregate_congestion_neon(samples) };
        }
    }

    aggregate_congestion_scalar(samples)
}

fn aggregate_congestion_scalar(samples: &[CongestionSample]) -> CongestionSummary {
    let mut total_cwnd = 0u64;
    let mut total_inflight = 0u64;
    let mut total_delivery = 0u64;
    let mut total_lost = 0u64;

    for sample in samples {
        total_cwnd += sample.cwnd as u64;
        total_inflight += sample.bytes_in_flight as u64;
        total_delivery += sample.delivery_rate as u64;
        total_lost += sample.lost_packets as u64;
    }

    let congestion_score =
        total_inflight / 1024 + total_lost * 4096 + total_cwnd * 64 + total_delivery / 8192;

    CongestionSummary {
        total_cwnd,
        total_bytes_in_flight: total_inflight,
        total_delivery_rate: total_delivery,
        total_lost_packets: total_lost,
        congestion_score,
    }
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx512f", enable = "avx512vnni")]
unsafe fn aggregate_congestion_vnni(samples: &[CongestionSample]) -> CongestionSummary {
    CONGESTION_VNNI_BATCHES.inc_by(samples.len() as u64);

    // Stack buffers: congestion window is bounded by CONGESTION_WINDOW_SIZE (64).
    let mut cwnd = [0u32; CONGESTION_WINDOW_SIZE];
    let mut inflight = [0u32; CONGESTION_WINDOW_SIZE];
    let mut delivery = [0u32; CONGESTION_WINDOW_SIZE];
    let mut lost = [0u32; CONGESTION_WINDOW_SIZE];
    let n = samples.len().min(CONGESTION_WINDOW_SIZE);
    for (i, sample) in samples.iter().take(n).enumerate() {
        cwnd[i] = sample.cwnd;
        inflight[i] = sample.bytes_in_flight;
        delivery[i] = sample.delivery_rate;
        lost[i] = sample.lost_packets;
    }

    let total_cwnd = sum_u32_vnni(&cwnd[..n]);
    let total_inflight = sum_u32_vnni(&inflight[..n]);
    let total_delivery = sum_u32_vnni(&delivery[..n]);
    let total_lost = sum_u32_vnni(&lost[..n]);

    let congestion_score =
        total_inflight / 1024 + total_lost * 4096 + total_cwnd * 64 + total_delivery / 8192;

    CongestionSummary {
        total_cwnd,
        total_bytes_in_flight: total_inflight,
        total_delivery_rate: total_delivery,
        total_lost_packets: total_lost,
        congestion_score,
    }
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
unsafe fn aggregate_congestion_avx2(samples: &[CongestionSample]) -> CongestionSummary {
    use std::arch::x86_64::*;

    const LANES: usize = 4;
    let mut idx = 0usize;
    let len = samples.len();

    let mut sum_cwnd_lo = _mm_setzero_si128();
    let mut sum_cwnd_hi = _mm_setzero_si128();
    let mut sum_inflight_lo = _mm_setzero_si128();
    let mut sum_inflight_hi = _mm_setzero_si128();
    let mut sum_delivery_lo = _mm_setzero_si128();
    let mut sum_delivery_hi = _mm_setzero_si128();
    let mut sum_lost_lo = _mm_setzero_si128();
    let mut sum_lost_hi = _mm_setzero_si128();

    while idx + LANES <= len {
        let mut cwnd_chunk = [0u32; LANES];
        let mut inflight_chunk = [0u32; LANES];
        let mut delivery_chunk = [0u32; LANES];
        let mut lost_chunk = [0u32; LANES];

        for lane in 0..LANES {
            let sample = samples[idx + lane];
            cwnd_chunk[lane] = sample.cwnd;
            inflight_chunk[lane] = sample.bytes_in_flight;
            delivery_chunk[lane] = sample.delivery_rate;
            lost_chunk[lane] = sample.lost_packets;
        }

        let cwnd_vec = _mm_loadu_si128(cwnd_chunk.as_ptr() as *const __m128i);
        let inflight_vec = _mm_loadu_si128(inflight_chunk.as_ptr() as *const __m128i);
        let delivery_vec = _mm_loadu_si128(delivery_chunk.as_ptr() as *const __m128i);
        let lost_vec = _mm_loadu_si128(lost_chunk.as_ptr() as *const __m128i);

        accumulate_u32_block(cwnd_vec, &mut sum_cwnd_lo, &mut sum_cwnd_hi);
        accumulate_u32_block(inflight_vec, &mut sum_inflight_lo, &mut sum_inflight_hi);
        accumulate_u32_block(delivery_vec, &mut sum_delivery_lo, &mut sum_delivery_hi);
        accumulate_u32_block(lost_vec, &mut sum_lost_lo, &mut sum_lost_hi);

        idx += LANES;
    }

    let mut total_cwnd = reduce_u32_accumulators(sum_cwnd_lo, sum_cwnd_hi);
    let mut total_inflight = reduce_u32_accumulators(sum_inflight_lo, sum_inflight_hi);
    let mut total_delivery = reduce_u32_accumulators(sum_delivery_lo, sum_delivery_hi);
    let mut total_lost = reduce_u32_accumulators(sum_lost_lo, sum_lost_hi);

    for sample in &samples[idx..] {
        total_cwnd += sample.cwnd as u64;
        total_inflight += sample.bytes_in_flight as u64;
        total_delivery += sample.delivery_rate as u64;
        total_lost += sample.lost_packets as u64;
    }

    CONGESTION_AVX2_BATCHES.inc_by(samples.len() as u64);

    let congestion_score =
        total_inflight / 1024 + total_lost * 4096 + total_cwnd * 64 + total_delivery / 8192;

    CongestionSummary {
        total_cwnd,
        total_bytes_in_flight: total_inflight,
        total_delivery_rate: total_delivery,
        total_lost_packets: total_lost,
        congestion_score,
    }
}

#[cfg(target_arch = "x86_64")]
#[inline(always)]
unsafe fn accumulate_u32_block(values: __m128i, acc_lo: &mut __m128i, acc_hi: &mut __m128i) {
    use std::arch::x86_64::*;
    let low = _mm_cvtepu32_epi64(values);
    let shuffled = _mm_shuffle_epi32(values, 0x4E);
    let high = _mm_cvtepu32_epi64(shuffled);
    *acc_lo = _mm_add_epi64(*acc_lo, low);
    *acc_hi = _mm_add_epi64(*acc_hi, high);
}

#[cfg(target_arch = "x86_64")]
#[inline(always)]
unsafe fn reduce_u32_accumulators(lo: __m128i, hi: __m128i) -> u64 {
    use std::arch::x86_64::*;
    let combined = _mm_add_epi64(lo, hi);
    let mut tmp = [0u64; 2];
    _mm_storeu_si128(tmp.as_mut_ptr() as *mut __m128i, combined);
    tmp.iter().copied().sum()
}

#[cfg(target_arch = "aarch64")]
#[target_feature(enable = "neon")]
unsafe fn aggregate_congestion_neon(samples: &[CongestionSample]) -> CongestionSummary {
    use std::arch::aarch64::*;

    const LANES: usize = 4;
    let len = samples.len();
    let mut idx = 0usize;

    let mut sum_cwnd = vdupq_n_u64(0);
    let mut sum_inflight = vdupq_n_u64(0);
    let mut sum_delivery = vdupq_n_u64(0);
    let mut sum_lost = vdupq_n_u64(0);

    while idx + LANES <= len {
        let mut cwnd_chunk = [0u32; LANES];
        let mut inflight_chunk = [0u32; LANES];
        let mut delivery_chunk = [0u32; LANES];
        let mut lost_chunk = [0u32; LANES];

        for lane in 0..LANES {
            let sample = samples[idx + lane];
            cwnd_chunk[lane] = sample.cwnd;
            inflight_chunk[lane] = sample.bytes_in_flight;
            delivery_chunk[lane] = sample.delivery_rate;
            lost_chunk[lane] = sample.lost_packets;
        }

        let cwnd_vec = vld1q_u32(cwnd_chunk.as_ptr());
        let inflight_vec = vld1q_u32(inflight_chunk.as_ptr());
        let delivery_vec = vld1q_u32(delivery_chunk.as_ptr());
        let lost_vec = vld1q_u32(lost_chunk.as_ptr());

        sum_cwnd = neon_add_u32_to_u64(sum_cwnd, cwnd_vec);
        sum_inflight = neon_add_u32_to_u64(sum_inflight, inflight_vec);
        sum_delivery = neon_add_u32_to_u64(sum_delivery, delivery_vec);
        sum_lost = neon_add_u32_to_u64(sum_lost, lost_vec);

        idx += LANES;
    }

    let mut total_cwnd = neon_horizontal_add_u64(sum_cwnd);
    let mut total_inflight = neon_horizontal_add_u64(sum_inflight);
    let mut total_delivery = neon_horizontal_add_u64(sum_delivery);
    let mut total_lost = neon_horizontal_add_u64(sum_lost);

    for sample in &samples[idx..] {
        total_cwnd += sample.cwnd as u64;
        total_inflight += sample.bytes_in_flight as u64;
        total_delivery += sample.delivery_rate as u64;
        total_lost += sample.lost_packets as u64;
    }

    CONGESTION_NEON_BATCHES.inc_by(samples.len() as u64);

    let congestion_score =
        total_inflight / 1024 + total_lost * 4096 + total_cwnd * 64 + total_delivery / 8192;

    CongestionSummary {
        total_cwnd,
        total_bytes_in_flight: total_inflight,
        total_delivery_rate: total_delivery,
        total_lost_packets: total_lost,
        congestion_score,
    }
}

#[cfg(target_arch = "aarch64")]
#[inline(always)]
unsafe fn neon_add_u32_to_u64(
    acc: std::arch::aarch64::uint64x2_t,
    values: std::arch::aarch64::uint32x4_t,
) -> std::arch::aarch64::uint64x2_t {
    use std::arch::aarch64::*;
    let lo = vmovl_u32(vget_low_u32(values));
    let hi = vmovl_u32(vget_high_u32(values));
    vaddq_u64(vaddq_u64(acc, lo), hi)
}

#[cfg(target_arch = "aarch64")]
#[inline(always)]
unsafe fn neon_horizontal_add_u64(vec: std::arch::aarch64::uint64x2_t) -> u64 {
    use std::arch::aarch64::*;
    let mut tmp = [0u64; 2];
    vst1q_u64(tmp.as_mut_ptr(), vec);
    tmp.iter().copied().sum()
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx512f", enable = "avx512vnni")]
unsafe fn sum_u32_vnni(values: &[u32]) -> u64 {
    if values.is_empty() {
        return 0;
    }

    let mut acc64 = _mm512_setzero_si512();
    let mut chunks = values.chunks_exact(16);
    for chunk in &mut chunks {
        let ptr = chunk.as_ptr();
        let lo = _mm256_loadu_si256(ptr as *const __m256i);
        let hi = _mm256_loadu_si256(ptr.add(8) as *const __m256i);
        let lo64 = _mm512_cvtepu32_epi64(lo);
        let hi64 = _mm512_cvtepu32_epi64(hi);
        acc64 = _mm512_add_epi64(acc64, lo64);
        acc64 = _mm512_add_epi64(acc64, hi64);
    }

    let mut lanes = [0u64; 8];
    _mm512_storeu_si512(lanes.as_mut_ptr() as *mut __m512i, acc64);
    let mut total = lanes.iter().copied().sum::<u64>();

    for &rem in chunks.remainder() {
        total += rem as u64;
    }

    total
}

/// Bitmap operations with BMI2 - 2x faster
#[inline(always)]
#[cfg(any(test, feature = "rust-tests"))]
pub fn bitmap_set_range(bitmap: &mut [u64], start: usize, end: usize) {
    let _profile = FeatureDetector::instance().profile();

    #[cfg(target_arch = "x86_64")]
    match _profile {
        CpuProfile::X86_P2b
        | CpuProfile::X86_P3a
        | CpuProfile::X86_P3b
        | CpuProfile::X86_P3c
        | CpuProfile::X86_P3d
        | CpuProfile::X86_P3e
        | CpuProfile::X86_P4a
        | CpuProfile::X86_P4b => unsafe {
            bitmap_set_range_bmi2(bitmap, start, end);
            return;
        },
        _ => {}
    }

    #[cfg(target_arch = "aarch64")]
    match _profile {
        CpuProfile::ARM_A2 => unsafe {
            bitmap_set_range_sve2(bitmap, start, end);
            return;
        },
        CpuProfile::ARM_A0
        | CpuProfile::ARM_A1a
        | CpuProfile::ARM_A1b
        | CpuProfile::ARM_A1c
        | CpuProfile::ARM_A1d
        | CpuProfile::Apple_M => unsafe {
            bitmap_set_range_neon(bitmap, start, end);
            return;
        },
        _ => {}
    }

    // Scalar fallback
    for i in start..=end {
        let word = i / 64;
        let bit = i % 64;
        if word < bitmap.len() {
            bitmap[word] |= 1u64 << bit;
        }
    }
}

#[cfg(all(target_arch = "aarch64", any(test, feature = "rust-tests")))]
#[inline(always)]
fn mask_from_start(bit: usize) -> u64 {
    (!0u64) << bit
}

#[cfg(all(target_arch = "aarch64", any(test, feature = "rust-tests")))]
#[inline(always)]
fn mask_to_end(bit: usize) -> u64 {
    if bit >= 63 {
        !0u64
    } else {
        (!0u64) >> (63 - bit)
    }
}

#[cfg(all(target_arch = "aarch64", any(test, feature = "rust-tests")))]
#[inline(always)]
fn mask_range(start_bit: usize, end_bit: usize) -> u64 {
    mask_from_start(start_bit) & mask_to_end(end_bit)
}

#[cfg(all(target_arch = "aarch64", any(test, feature = "rust-tests")))]
#[target_feature(enable = "neon")]
unsafe fn bitmap_set_range_neon(bitmap: &mut [u64], start: usize, end: usize) {
    use std::arch::aarch64::*;

    let len_words = bitmap.len();
    if len_words == 0 {
        return;
    }

    let len_bits = len_words.saturating_mul(64);
    if start >= len_bits {
        return;
    }

    let max_bit = len_bits - 1;
    let effective_end = end.min(max_bit);
    if start > effective_end {
        return;
    }

    let start_word = start / 64;
    let start_bit = start % 64;
    let end_word = effective_end / 64;
    let end_bit = effective_end % 64;

    if start_word >= len_words {
        return;
    }

    if start_word == end_word {
        bitmap[start_word] |= mask_range(start_bit, end_bit);
        return;
    }

    bitmap[start_word] |= mask_from_start(start_bit);

    if end_word < len_words {
        let mut idx = start_word + 1;
        if idx < end_word {
            let limit = end_word - 1;
            let all_ones = vdupq_n_u64(!0u64);

            while idx < limit {
                let ptr = bitmap.as_mut_ptr().add(idx);
                vst1q_u64(ptr, all_ones);
                idx += 2;
            }

            if idx <= limit {
                bitmap[idx] = !0u64;
            }
        }

        bitmap[end_word] |= mask_to_end(end_bit);
    }
}

#[cfg(all(target_arch = "aarch64", any(test, feature = "rust-tests")))]
unsafe fn bitmap_set_range_sve2(bitmap: &mut [u64], start: usize, end: usize) {
    #[cfg(target_feature = "sve2")]
    {
        bitmap_set_range_sve2_impl(bitmap, start, end);
    }

    #[cfg(not(target_feature = "sve2"))]
    {
        bitmap_set_range_neon(bitmap, start, end);
    }
}

#[cfg(all(target_arch = "aarch64", target_feature = "sve2", any(test, feature = "rust-tests")))]
#[target_feature(enable = "sve2")]
unsafe fn bitmap_set_range_sve2_impl(bitmap: &mut [u64], start: usize, end: usize) {
    use std::arch::aarch64::*;

    let len_words = bitmap.len();
    if len_words == 0 {
        return;
    }

    let len_bits = len_words.saturating_mul(64);
    if start >= len_bits {
        return;
    }

    let max_bit = len_bits - 1;
    let effective_end = end.min(max_bit);
    if start > effective_end {
        return;
    }

    let start_word = start / 64;
    let start_bit = start % 64;
    let end_word = effective_end / 64;
    let end_bit = effective_end % 64;

    if start_word >= len_words {
        return;
    }

    if start_word == end_word {
        bitmap[start_word] |= mask_range(start_bit, end_bit);
        return;
    }

    bitmap[start_word] |= mask_from_start(start_bit);

    let all = svptrue_b64();
    let mut idx = start_word + 1;

    while idx < end_word {
        let pg = svwhilelt_b64(idx as u64, end_word as u64);
        if !svptest_any(all, pg) {
            break;
        }

        svst1_u64(pg, bitmap.as_mut_ptr().add(idx), svdup_n_u64(!0u64));
        let consumed = svcntp_b64(pg, pg) as usize;
        idx += consumed;
    }

    bitmap[end_word] |= mask_to_end(end_bit);
}

#[cfg(all(target_arch = "x86_64", any(test, feature = "rust-tests")))]
#[target_feature(enable = "bmi2")]
unsafe fn bitmap_set_range_bmi2(bitmap: &mut [u64], start: usize, end: usize) {
    let start_word = start / 64;
    let start_bit = start % 64;
    let end_word = end / 64;
    let end_bit = end % 64;

    if start_word == end_word {
        // Range within single word
        let mask = _bzhi_u64(!0u64, (end_bit - start_bit + 1) as u32);
        bitmap[start_word] |= mask << start_bit;
    } else {
        // Set bits in start word
        bitmap[start_word] |= !0u64 << start_bit;

        // Set all bits in middle words
        for word in (start_word + 1)..end_word {
            bitmap[word] = !0u64;
        }

        // Set bits in end word
        bitmap[end_word] |= _bzhi_u64(!0u64, (end_bit + 1) as u32);
    }
}

/// ECN counting with POPCNT - 3x faster
#[inline(always)]
#[cfg(any(test, feature = "rust-tests"))]
pub fn count_ecn_marks(bitmap: &[u64]) -> u32 {
    let _profile = FeatureDetector::instance().profile();

    #[cfg(target_arch = "x86_64")]
    match _profile {
        CpuProfile::X86_P1a
        | CpuProfile::X86_P1b
        | CpuProfile::X86_P1f
        | CpuProfile::X86_P2a
        | CpuProfile::X86_P2b
        | CpuProfile::X86_P3a
        | CpuProfile::X86_P3b
        | CpuProfile::X86_P3c
        | CpuProfile::X86_P3d
        | CpuProfile::X86_P3e
        | CpuProfile::X86_P4a
        | CpuProfile::X86_P4b => {
            return unsafe { count_ecn_marks_popcnt(bitmap) };
        }
        _ => {}
    }

    #[cfg(target_arch = "aarch64")]
    match _profile {
        CpuProfile::ARM_A2 => unsafe {
            return count_ecn_marks_sve2(bitmap);
        },
        CpuProfile::ARM_A0
        | CpuProfile::ARM_A1a
        | CpuProfile::ARM_A1b
        | CpuProfile::ARM_A1c
        | CpuProfile::ARM_A1d
        | CpuProfile::Apple_M => unsafe {
            return count_ecn_marks_neon(bitmap);
        },
        _ => {}
    }

    // Scalar fallback
    bitmap.iter().map(|&word| word.count_ones()).sum()
}

#[cfg(all(target_arch = "x86_64", any(test, feature = "rust-tests")))]
#[target_feature(enable = "popcnt")]
unsafe fn count_ecn_marks_popcnt(bitmap: &[u64]) -> u32 {
    let mut count = 0u32;

    // Process 4 words at a time for better throughput
    let chunks = bitmap.chunks_exact(4);
    let remainder = chunks.remainder();

    for chunk in chunks {
        count += _popcnt64(chunk[0] as i64) as u32;
        count += _popcnt64(chunk[1] as i64) as u32;
        count += _popcnt64(chunk[2] as i64) as u32;
        count += _popcnt64(chunk[3] as i64) as u32;
    }

    for &word in remainder {
        count += _popcnt64(word as i64) as u32;
    }

    count
}

#[cfg(all(target_arch = "aarch64", any(test, feature = "rust-tests")))]
#[target_feature(enable = "neon")]
unsafe fn count_ecn_marks_neon(bitmap: &[u64]) -> u32 {
    use std::arch::aarch64::*;

    let bytes = core::slice::from_raw_parts(bitmap.as_ptr() as *const u8, bitmap.len() * 8);

    let mut i = 0usize;
    let mut acc16 = vdupq_n_u16(0);

    while i + 16 <= bytes.len() {
        let v = vld1q_u8(bytes.as_ptr().add(i));
        let cnt = vcntq_u8(v);
        let cnt_u16 = vpaddlq_u8(cnt); // widen to u16 and pairwise add
        acc16 = vaddq_u16(acc16, cnt_u16);
        i += 16;
    }

    // Horizontal sum
    let mut total: u32 = vaddvq_u16(acc16) as u32;

    // Remainder
    while i < bytes.len() {
        total += bytes[i].count_ones();
        i += 1;
    }

    total
}

#[cfg(all(target_arch = "aarch64", any(test, feature = "rust-tests")))]
#[inline(always)]
unsafe fn count_ecn_marks_sve2(bitmap: &[u64]) -> u32 {
    #[cfg(target_feature = "sve2")]
    {
        use std::arch::aarch64::*;

        // Nibble popcount table (0..15)
        const LUT: [u8; 16] = [0, 1, 1, 2, 1, 2, 2, 3, 1, 2, 2, 3, 2, 3, 3, 4];

        let bytes = core::slice::from_raw_parts(bitmap.as_ptr() as *const u8, bitmap.len() * 8);

        if bytes.is_empty() {
            return 0;
        }

        let tbl = svld1rq_u8(svptrue_b8(), LUT.as_ptr());
        let mask0f = svdup_n_u8(0x0F);
        let mut offset = 0usize;
        let mut total: u32 = 0;

        while offset < bytes.len() {
            let pg = svwhilelt_b8(offset as u64, bytes.len() as u64);
            if !svptest_any(svptrue_b8(), pg) {
                break;
            }
            let v = svld1_u8(pg, bytes.as_ptr().add(offset));
            let lo = svand_u8_x(pg, v, mask0f);
            let hi = svand_u8_x(pg, svlsr_n_u8_z(pg, v, 4), mask0f);
            let c_lo = svtbl_u8(tbl, lo);
            let c_hi = svtbl_u8(tbl, hi);
            let c = svadd_u8_x(pg, c_lo, c_hi);
            // Horizontal sum of counts in this chunk
            let sum_chunk = svaddv_u8(pg, c) as u32;
            total = total.saturating_add(sum_chunk);
            offset += svcntb() as usize;
        }

        return total;
    }

    // Compile-time SVE2 not available: fall back NEON -> Scalar.
    if std::arch::is_aarch64_feature_detected!("neon") {
        return count_ecn_marks_neon(bitmap);
    }
    bitmap.iter().map(|&w| w.count_ones()).sum()
}

/// Fast packet number decoding with BMI2 PEXT
#[inline(always)]
pub fn decode_packet_number(encoded: u32, expected: u64, pn_len: u8) -> u64 {
    if pn_len == 0 {
        return expected;
    }

    #[cfg(target_arch = "x86_64")]
    {
        let features = FeatureDetector::instance().features_full();
        if features.bmi2 {
            return unsafe { decode_packet_number_bmi2(encoded, expected, pn_len) };
        }
    }

    #[cfg(target_arch = "aarch64")]
    {
        let features = FeatureDetector::instance().features_full();
        if features.sve2 {
            return unsafe { decode_packet_number_sve2(encoded, expected, pn_len) };
        }
        if features.neon {
            return unsafe { decode_packet_number_neon(encoded, expected, pn_len) };
        }
    }

    // Scalar fallback
    let pn_bits = (pn_len as u32) * 8;
    let pn_mask = if pn_bits == 64 { u64::MAX } else { (1u64 << pn_bits) - 1 };
    let truncated = encoded as u64 & pn_mask;
    let expected_pn = expected.wrapping_add(1);
    let candidate = (expected_pn & !pn_mask) | truncated;
    finalize_packet_number(candidate, expected_pn, pn_bits)
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "bmi2")]
unsafe fn decode_packet_number_bmi2(encoded: u32, expected: u64, pn_len: u8) -> u64 {
    // Use PEXT to extract packet number bits efficiently
    let pn_bits = (pn_len as u32) * 8;
    let mask = if pn_bits == 64 { u64::MAX } else { (1u64 << pn_bits) - 1 };

    // Extract truncated packet number with PEXT
    let truncated = _pext_u64(encoded as u64, mask);

    // Reconstruct full packet number
    let expected_pn = expected.wrapping_add(1);

    // Use PDEP to deposit bits at correct position
    let candidate = _pdep_u64(truncated, mask) | (expected_pn & !mask);

    finalize_packet_number(candidate, expected_pn, pn_bits)
}

#[inline(always)]
fn finalize_packet_number(candidate: u64, expected_pn: u64, pn_bits: u32) -> u64 {
    debug_assert!(pn_bits > 0 && pn_bits <= 32);
    let range = 1u128 << pn_bits;
    let pn_win = 1u128 << (pn_bits - 1);

    let candidate128 = candidate as u128;
    let expected128 = expected_pn as u128;

    if candidate128 + pn_win <= expected128 {
        (candidate128 + range) as u64
    } else if candidate128 > expected128 + pn_win && candidate128 >= range {
        (candidate128 - range) as u64
    } else {
        candidate
    }
}

#[cfg(target_arch = "aarch64")]
#[target_feature(enable = "neon")]
unsafe fn decode_packet_number_neon(encoded: u32, expected: u64, pn_len: u8) -> u64 {
    use std::arch::aarch64::*;

    let pn_bits = (pn_len as u32) * 8;
    let mask = if pn_bits == 64 { u64::MAX } else { (1u64 << pn_bits) - 1 };

    let mask_vec = vdupq_n_u64(mask);
    let encoded_vec = vdupq_n_u64(encoded as u64);
    let truncated_vec = vandq_u64(encoded_vec, mask_vec);

    let expected_pn = expected + 1;
    let expected_vec = vdupq_n_u64(expected_pn);
    let cleared_vec = vbicq_u64(expected_vec, mask_vec);
    let candidate_vec = vorrq_u64(cleared_vec, truncated_vec);

    let candidate = vgetq_lane_u64(candidate_vec, 0);
    finalize_packet_number(candidate, expected_pn, pn_bits)
}

#[cfg(target_arch = "aarch64")]
unsafe fn decode_packet_number_sve2(encoded: u32, expected: u64, pn_len: u8) -> u64 {
    #[cfg(target_feature = "sve2")]
    {
        decode_packet_number_sve2_impl(encoded, expected, pn_len)
    }

    #[cfg(not(target_feature = "sve2"))]
    {
        decode_packet_number_neon(encoded, expected, pn_len)
    }
}

#[cfg(all(target_arch = "aarch64", target_feature = "sve2"))]
#[target_feature(enable = "sve2")]
unsafe fn decode_packet_number_sve2_impl(encoded: u32, expected: u64, pn_len: u8) -> u64 {
    use std::arch::aarch64::*;

    let pn_bits = (pn_len as u32) * 8;
    let mask = if pn_bits == 64 { u64::MAX } else { (1u64 << pn_bits) - 1 };

    let pg = svptrue_b64();
    let mask_vec = svdup_u64(mask);
    let encoded_vec = svdup_u64(encoded as u64);
    let truncated_vec = svand_u64_x(pg, encoded_vec, mask_vec);

    let expected_pn = expected + 1;
    let expected_vec = svdup_u64(expected_pn);
    let cleared_vec = svbic_u64_x(pg, expected_vec, mask_vec);
    let candidate_vec = svorr_u64_x(pg, cleared_vec, truncated_vec);

    let candidate = svlast_u64(pg, candidate_vec);
    finalize_packet_number(candidate, expected_pn, pn_bits)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_congestion_sample_from_transport_stats() {
        let stats = Stats {
            cwnd: 65535,
            bytes_in_flight: 32768,
            delivery_rate: 1_000_000,
            lost: 42,
            ..Default::default()
        };
        let sample = CongestionSample::from_transport_stats(&stats);
        assert_eq!(sample.cwnd, 65535);
        assert_eq!(sample.bytes_in_flight, 32768);
        assert_eq!(sample.delivery_rate, 1_000_000);
        assert_eq!(sample.lost_packets, 42);
    }

    #[test]
    fn test_congestion_sample_clamps_u32_max() {
        let stats = Stats {
            cwnd: usize::MAX,
            bytes_in_flight: usize::MAX,
            delivery_rate: u64::MAX,
            lost: usize::MAX,
            ..Default::default()
        };
        let sample = CongestionSample::from_transport_stats(&stats);
        assert_eq!(sample.cwnd, u32::MAX);
        assert_eq!(sample.bytes_in_flight, u32::MAX);
        assert_eq!(sample.delivery_rate, u32::MAX);
        assert_eq!(sample.lost_packets, u32::MAX);
    }

    #[test]
    fn test_aggregate_congestion_empty() {
        let summary = aggregate_congestion(&[]);
        assert_eq!(summary.total_cwnd, 0);
        assert_eq!(summary.total_bytes_in_flight, 0);
        assert_eq!(summary.total_delivery_rate, 0);
        assert_eq!(summary.total_lost_packets, 0);
        assert_eq!(summary.congestion_score, 0);
    }

    #[test]
    fn test_aggregate_congestion_single_sample() {
        let samples = [CongestionSample {
            cwnd: 1000,
            bytes_in_flight: 500,
            delivery_rate: 8192,
            lost_packets: 2,
        }];
        let summary = aggregate_congestion(&samples);
        assert_eq!(summary.total_cwnd, 1000);
        assert_eq!(summary.total_bytes_in_flight, 500);
        assert_eq!(summary.total_delivery_rate, 8192);
        assert_eq!(summary.total_lost_packets, 2);
        // Verify congestion score formula: inflight/1024 + lost*4096 + cwnd*64 + delivery/8192
        let expected_score = 2 * 4096 + 1000 * 64 + 1;
        assert_eq!(summary.congestion_score, expected_score);
    }

    #[test]
    fn test_aggregate_congestion_multiple_samples() {
        let samples: Vec<CongestionSample> = (0..CONGESTION_WINDOW_SIZE)
            .map(|i| CongestionSample {
                cwnd: 100,
                bytes_in_flight: 50,
                delivery_rate: 1000,
                lost_packets: i as u32,
            })
            .collect();
        let summary = aggregate_congestion(&samples);
        assert_eq!(summary.total_cwnd, 100 * CONGESTION_WINDOW_SIZE as u64);
        assert_eq!(summary.total_bytes_in_flight, 50 * CONGESTION_WINDOW_SIZE as u64);
        assert_eq!(summary.total_delivery_rate, 1000 * CONGESTION_WINDOW_SIZE as u64);
        // lost_packets: sum of 0..64 = (64*63)/2 = 2016
        let expected_lost: u64 = (0..CONGESTION_WINDOW_SIZE as u64).sum();
        assert_eq!(summary.total_lost_packets, expected_lost);
    }

    #[test]
    fn test_aggregate_congestion_score_formula() {
        // Verify the score formula is consistent across scalar and dispatch paths
        let samples = [
            CongestionSample {
                cwnd: 2048,
                bytes_in_flight: 4096,
                delivery_rate: 16384,
                lost_packets: 10,
            },
            CongestionSample {
                cwnd: 1024,
                bytes_in_flight: 2048,
                delivery_rate: 8192,
                lost_packets: 5,
            },
        ];
        let summary = aggregate_congestion(&samples);
        let scalar = aggregate_congestion_scalar(&samples);
        assert_eq!(summary.total_cwnd, scalar.total_cwnd);
        assert_eq!(summary.total_bytes_in_flight, scalar.total_bytes_in_flight);
        assert_eq!(summary.total_delivery_rate, scalar.total_delivery_rate);
        assert_eq!(summary.total_lost_packets, scalar.total_lost_packets);
        assert_eq!(summary.congestion_score, scalar.congestion_score);
    }

    #[test]
    fn test_aggregate_congestion_non_power_of_two_count() {
        // Non-aligned count to exercise remainder paths in SIMD
        let samples: Vec<CongestionSample> = (0..7)
            .map(|_| CongestionSample {
                cwnd: 10,
                bytes_in_flight: 20,
                delivery_rate: 30,
                lost_packets: 1,
            })
            .collect();
        let summary = aggregate_congestion(&samples);
        assert_eq!(summary.total_cwnd, 70);
        assert_eq!(summary.total_bytes_in_flight, 140);
        assert_eq!(summary.total_delivery_rate, 210);
        assert_eq!(summary.total_lost_packets, 7);
    }

    #[test]
    fn test_bitmap_set_range_single_bit() {
        let mut bitmap = [0u64; 2];
        bitmap_set_range(&mut bitmap, 5, 5);
        assert_eq!(bitmap[0], 1u64 << 5);
        assert_eq!(bitmap[1], 0);
    }

    #[test]
    fn test_bitmap_set_range_cross_word_boundary() {
        let mut bitmap = [0u64; 4];
        bitmap_set_range(&mut bitmap, 60, 68);
        // Bits 60..63 in word 0, bits 0..4 in word 1
        for bit in 60..=68 {
            let word = bit / 64;
            let b = bit % 64;
            assert_ne!(bitmap[word] & (1u64 << b), 0, "bit {} should be set", bit);
        }
    }

    #[test]
    fn test_count_ecn_marks_empty() {
        let bitmap: &[u64] = &[];
        assert_eq!(count_ecn_marks(bitmap), 0);
    }

    #[test]
    fn test_count_ecn_marks_known_values() {
        let bitmap = [0xFFu64, 0x0101_0101_0101_0101u64];
        let count = count_ecn_marks(&bitmap);
        // 0xFF = 8 bits, 0x0101_0101_0101_0101 = 8 bits (one per byte)
        assert_eq!(count, 16);
    }

    #[test]
    fn test_decode_packet_number_1byte() {
        // 1-byte PN encoding: 8 bits
        let decoded = decode_packet_number(0x42, 0x40, 1);
        // expected_pn = 0x41, mask = 0xFF
        // candidate = (0x41 & !0xFF) | 0x42 = 0x42
        assert_eq!(decoded, 0x42);
    }

    #[test]
    fn test_decode_packet_number_2byte() {
        // 2-byte PN encoding
        let decoded = decode_packet_number(0x1234, 0x1230, 2);
        // expected_pn = 0x1231, mask = 0xFFFF
        // candidate = (0x1231 & !0xFFFF) | 0x1234 = 0x1234
        assert_eq!(decoded, 0x1234);
    }

    #[test]
    fn test_decode_packet_number_zero_len_returns_expected() {
        let decoded = decode_packet_number(0xFF, 100, 0);
        assert_eq!(decoded, 100);
    }
}
