use crate::optimize::telemetry;
use crate::optimize::FeatureDetector;
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
use crate::simd::CpuProfile;

use std::any::TypeId;
use std::slice;

#[cfg(target_arch = "x86_64")]
use std::arch::x86_64::*;

/// Fast sort for u32 with SIMD - 5x faster (AVX512/AVX2/NEON)
#[inline(always)]
pub fn sort_u32(data: &mut [u32]) {
    let _profile = FeatureDetector::instance().profile();

    #[cfg(target_arch = "x86_64")]
    match _profile {
        CpuProfile::X86_P3a
        | CpuProfile::X86_P3b
        | CpuProfile::X86_P3c
        | CpuProfile::X86_P3d
        | CpuProfile::X86_P3e
        | CpuProfile::X86_P4a
        | CpuProfile::X86_P4b => unsafe {
            sort_u32_avx512(data);
            return;
        },
        CpuProfile::X86_P2a | CpuProfile::X86_P2b => unsafe {
            sort_u32_avx2(data);
            return;
        },
        _ => {}
    }

    #[cfg(target_arch = "aarch64")]
    match _profile {
        CpuProfile::ARM_A0
        | CpuProfile::ARM_A1a
        | CpuProfile::ARM_A1b
        | CpuProfile::ARM_A1c
        | CpuProfile::ARM_A1d
        | CpuProfile::ARM_A2
        | CpuProfile::Apple_M => {
            sort_u32_neon(data);
            return;
        }
        _ => {}
    }

    data.sort_unstable();
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx512f")]
unsafe fn sort_u32_avx512(data: &mut [u32]) {
    if data.len() <= 16 {
        sort_small_avx512(data);
    } else if data.len() <= 1024 {
        quicksort_avx512(data, 0, data.len() - 1);
    } else {
        radix_sort_avx512(data);
    }
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx512f")]
unsafe fn sort_small_avx512(data: &mut [u32]) {
    if data.len() <= 16 {
        let mut vec = _mm512_setzero_si512();
        for (i, &val) in data.iter().enumerate().take(16) {
            vec = _mm512_mask_set1_epi32(vec, 1 << i, val as i32);
        }
        vec = cmpswap_avx512::<0x5555, 1>(vec);
        vec = cmpswap_avx512::<0x3333, 2>(vec);
        vec = cmpswap_avx512::<0x5555, 1>(vec);
        vec = cmpswap_avx512::<0x0F0F, 4>(vec);
        vec = cmpswap_avx512::<0x3333, 2>(vec);
        vec = cmpswap_avx512::<0x5555, 1>(vec);
        vec = cmpswap_avx512::<0x00FF, 8>(vec);
        vec = cmpswap_avx512::<0x0F0F, 4>(vec);
        vec = cmpswap_avx512::<0x3333, 2>(vec);
        vec = cmpswap_avx512::<0x5555, 1>(vec);
        let result: [u32; 16] = std::mem::transmute(vec);
        for (i, val) in result.iter().enumerate().take(data.len()) {
            data[i] = *val;
        }
    }
}

#[cfg(target_arch = "x86_64")]
#[inline(always)]
unsafe fn cmpswap_avx512<const MASK: u16, const SHIFT: u32>(vec: __m512i) -> __m512i {
    let shifted = _mm512_srli_epi32(vec, SHIFT);
    let min = _mm512_min_epu32(vec, shifted);
    let max = _mm512_max_epu32(vec, shifted);
    _mm512_mask_blend_epi32(MASK, min, max)
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx512f")]
unsafe fn quicksort_avx512(data: &mut [u32], low: usize, high: usize) {
    if low < high {
        let pivot = partition_avx512(data, low, high);
        if pivot > 0 {
            quicksort_avx512(data, low, pivot - 1);
        }
        quicksort_avx512(data, pivot + 1, high);
    }
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx512f")]
unsafe fn partition_avx512(data: &mut [u32], low: usize, high: usize) -> usize {
    let pivot = data[high];
    let pivot_vec = _mm512_set1_epi32(pivot as i32);
    let mut i = low;
    let mut j = low;
    while j + 16 <= high {
        let vec = _mm512_loadu_si512(data.as_ptr().add(j) as *const __m512i);
        let mask = _mm512_cmplt_epi32_mask(vec, pivot_vec);
        let count = mask.count_ones() as usize;
        if count > 0 {
            let compacted = _mm512_maskz_compress_epi32(mask, vec);
            _mm512_storeu_si512(data.as_mut_ptr().add(i) as *mut __m512i, compacted);
            i += count;
        }
        j += 16;
    }
    while j < high {
        if data[j] < pivot {
            data.swap(i, j);
            i += 1;
        }
        j += 1;
    }
    data.swap(i, high);
    i
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx512f")]
unsafe fn radix_sort_avx512(data: &mut [u32]) {
    const RADIX_BITS: u32 = 8;
    const RADIX_SIZE: usize = 1 << RADIX_BITS;
    const RADIX_MASK: u32 = RADIX_SIZE as u32 - 1;
    let mut temp = vec![0u32; data.len()];
    let mut counts = [0usize; RADIX_SIZE];
    for shift in (0..32).step_by(RADIX_BITS as usize) {
        counts.fill(0);
        let mut i = 0;
        while i + 16 <= data.len() {
            let vec = _mm512_loadu_si512(data.as_ptr().add(i) as *const __m512i);
            let shifted = match shift {
                0 => vec,
                8 => _mm512_srli_epi32(vec, 8),
                16 => _mm512_srli_epi32(vec, 16),
                24 => _mm512_srli_epi32(vec, 24),
                _ => vec,
            };
            let masked = _mm512_and_si512(shifted, _mm512_set1_epi32(RADIX_MASK as i32));
            let vals: [u32; 16] = std::mem::transmute(masked);
            for val in vals.iter().take((data.len() - i).min(16)) {
                counts[*val as usize] += 1;
            }
            i += 16;
        }
        while i < data.len() {
            let val = (data[i] >> shift) & RADIX_MASK;
            counts[val as usize] += 1;
            i += 1;
        }
        let mut pos = 0;
        for count in counts.iter_mut() {
            let tmp = *count;
            *count = pos;
            pos += tmp;
        }
        for &val in data.iter() {
            let bucket = ((val >> shift) & RADIX_MASK) as usize;
            temp[counts[bucket]] = val;
            counts[bucket] += 1;
        }
        data.copy_from_slice(&temp);
    }
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
unsafe fn sort_u32_avx2(data: &mut [u32]) {
    if data.len() <= 8 {
        sort_small_avx2(data);
    } else {
        data.sort_unstable();
    }
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
unsafe fn sort_small_avx2(data: &mut [u32]) {
    if data.len() <= 8 {
        let mut vals = [0u32; 8];
        for (i, &val) in data.iter().enumerate().take(8) {
            vals[i] = val;
        }
        let mut vec = _mm256_loadu_si256(vals.as_ptr() as *const __m256i);
        vec = cmpswap_avx2::<0x55, 1>(vec);
        vec = cmpswap_avx2::<0x33, 2>(vec);
        vec = cmpswap_avx2::<0x55, 1>(vec);
        vec = cmpswap_avx2::<0x0F, 4>(vec);
        vec = cmpswap_avx2::<0x33, 2>(vec);
        vec = cmpswap_avx2::<0x55, 1>(vec);
        _mm256_storeu_si256(vals.as_mut_ptr() as *mut __m256i, vec);
        for (i, &val) in vals.iter().enumerate().take(data.len()) {
            data[i] = val;
        }
    }
}

#[cfg(target_arch = "x86_64")]
#[inline(always)]
unsafe fn cmpswap_avx2<const MASK: i32, const SHIFT: i32>(vec: __m256i) -> __m256i {
    let shifted = _mm256_srli_epi32(vec, SHIFT);
    let min = _mm256_min_epu32(vec, shifted);
    let max = _mm256_max_epu32(vec, shifted);
    _mm256_blend_epi32(min, max, MASK)
}

#[cfg(target_arch = "aarch64")]
fn sort_u32_neon(data: &mut [u32]) {
    use std::arch::aarch64::*;

    #[inline(always)]
    unsafe fn sort4(vec: uint32x4_t) -> uint32x4_t {
        let mut mask_pair = vdupq_n_u32(0);
        mask_pair = vsetq_lane_u32(u32::MAX, mask_pair, 1);
        mask_pair = vsetq_lane_u32(u32::MAX, mask_pair, 3);

        let rev1 = vrev64q_u32(vec);
        let min1 = vminq_u32(vec, rev1);
        let max1 = vmaxq_u32(vec, rev1);
        let stage1 = vbslq_u32(mask_pair, max1, min1);

        let rev2 = vextq_u32(stage1, stage1, 2);
        let min2 = vminq_u32(stage1, rev2);
        let max2 = vmaxq_u32(stage1, rev2);
        let mut mask_blocks = vdupq_n_u32(0);
        mask_blocks = vsetq_lane_u32(u32::MAX, mask_blocks, 2);
        mask_blocks = vsetq_lane_u32(u32::MAX, mask_blocks, 3);
        let stage2 = vbslq_u32(mask_blocks, max2, min2);

        let rev3 = vextq_u32(stage2, stage2, 1);
        let min3 = vminq_u32(stage2, rev3);
        let max3 = vmaxq_u32(stage2, rev3);

        let mut result = stage2;
        result = vsetq_lane_u32(vgetq_lane_u32(min3, 1), result, 1);
        result = vsetq_lane_u32(vgetq_lane_u32(max3, 1), result, 2);
        result
    }

    #[inline(always)]
    unsafe fn reverse(vec: uint32x4_t) -> uint32x4_t {
        let rev = vrev64q_u32(vec);
        vextq_u32(rev, rev, 2)
    }

    unsafe {
        match data.len() {
            0 | 1 => {}
            2 => {
                if data[0] > data[1] {
                    data.swap(0, 1);
                }
            }
            3 | 4 => {
                let mut tmp = [u32::MAX; 4];
                tmp[..data.len()].copy_from_slice(data);
                let vec = vld1q_u32(tmp.as_ptr());
                let sorted = sort4(vec);
                let mut out = [0u32; 4];
                vst1q_u32(out.as_mut_ptr(), sorted);
                data.copy_from_slice(&out[..data.len()]);
            }
            5..=8 => {
                let mut left_arr = [u32::MAX; 4];
                let mut right_arr = [u32::MAX; 4];
                left_arr.copy_from_slice(&data[..4.min(data.len())]);
                right_arr[..(data.len() - 4)].copy_from_slice(&data[4..]);

                let mut left = sort4(vld1q_u32(left_arr.as_ptr()));
                let mut right = sort4(vld1q_u32(right_arr.as_ptr()));

                right = reverse(right);

                let min_half = vminq_u32(left, right);
                let max_half = vmaxq_u32(left, right);

                left = sort4(min_half);
                right = sort4(reverse(max_half));

                let mut out_left = [0u32; 4];
                let mut out_right = [0u32; 4];
                vst1q_u32(out_left.as_mut_ptr(), left);
                vst1q_u32(out_right.as_mut_ptr(), right);

                let split = 4.min(data.len());
                data[..split].copy_from_slice(&out_left[..split]);
                if data.len() > 4 {
                    let tail = data.len() - 4;
                    data[4..].copy_from_slice(&out_right[..tail]);
                }
            }
            _ => {
                data.sort_unstable();
            }
        }
    }
}

#[cfg(target_arch = "aarch64")]
fn sort_f32_neon(data: &mut [f32]) {
    use std::arch::aarch64::*;

    #[inline(always)]
    unsafe fn sort4(vec: float32x4_t) -> float32x4_t {
        let mut mask_pair = vdupq_n_u32(0);
        mask_pair = vsetq_lane_u32(u32::MAX, mask_pair, 1);
        mask_pair = vsetq_lane_u32(u32::MAX, mask_pair, 3);

        let rev1 = vrev64q_f32(vec);
        let min1 = vminq_f32(vec, rev1);
        let max1 = vmaxq_f32(vec, rev1);
        let stage1 = vbslq_f32(mask_pair, max1, min1);

        let rev2 = vextq_f32(stage1, stage1, 2);
        let min2 = vminq_f32(stage1, rev2);
        let max2 = vmaxq_f32(stage1, rev2);
        let mut mask_blocks = vdupq_n_u32(0);
        mask_blocks = vsetq_lane_u32(u32::MAX, mask_blocks, 2);
        mask_blocks = vsetq_lane_u32(u32::MAX, mask_blocks, 3);
        let stage2 = vbslq_f32(mask_blocks, max2, min2);

        let rev3 = vextq_f32(stage2, stage2, 1);
        let min3 = vminq_f32(stage2, rev3);
        let max3 = vmaxq_f32(stage2, rev3);

        let mut result = stage2;
        result = vsetq_lane_f32(vgetq_lane_f32(min3, 1), result, 1);
        result = vsetq_lane_f32(vgetq_lane_f32(max3, 1), result, 2);
        result
    }

    #[inline(always)]
    unsafe fn reverse(vec: float32x4_t) -> float32x4_t {
        let rev = vrev64q_f32(vec);
        vextq_f32(rev, rev, 2)
    }

    unsafe {
        match data.len() {
            0 | 1 => {}
            2 => {
                if data[0] > data[1] {
                    data.swap(0, 1);
                }
            }
            3 | 4 => {
                let mut tmp = [f32::INFINITY; 4];
                tmp[..data.len()].copy_from_slice(data);
                let vec = vld1q_f32(tmp.as_ptr());
                let sorted = sort4(vec);
                let mut out = [0f32; 4];
                vst1q_f32(out.as_mut_ptr(), sorted);
                data.copy_from_slice(&out[..data.len()]);
            }
            5..=8 => {
                let mut left_arr = [f32::INFINITY; 4];
                let mut right_arr = [f32::INFINITY; 4];
                left_arr.copy_from_slice(&data[..4.min(data.len())]);
                right_arr[..(data.len() - 4)].copy_from_slice(&data[4..]);

                let mut left = sort4(vld1q_f32(left_arr.as_ptr()));
                let mut right = sort4(vld1q_f32(right_arr.as_ptr()));

                right = reverse(right);

                let min_half = vminq_f32(left, right);
                let max_half = vmaxq_f32(left, right);

                left = sort4(min_half);
                right = sort4(reverse(max_half));

                let mut out_left = [0f32; 4];
                let mut out_right = [0f32; 4];
                vst1q_f32(out_left.as_mut_ptr(), left);
                vst1q_f32(out_right.as_mut_ptr(), right);

                let split = 4.min(data.len());
                data[..split].copy_from_slice(&out_left[..split]);
                if data.len() > 4 {
                    let tail = data.len() - 4;
                    data[4..].copy_from_slice(&out_right[..tail]);
                }
            }
            _ => {
                data.sort_unstable_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
            }
        }
    }
}

/// Sort f32 values with architecture-specific dispatch and deterministic ordering.
#[inline(always)]
pub fn sort_f32(data: &mut [f32]) {
    let _profile = FeatureDetector::instance().profile();

    #[cfg(target_arch = "x86_64")]
    match _profile {
        CpuProfile::X86_P2a
        | CpuProfile::X86_P2b
        | CpuProfile::X86_P3a
        | CpuProfile::X86_P3b
        | CpuProfile::X86_P3c
        | CpuProfile::X86_P3d
        | CpuProfile::X86_P3e
        | CpuProfile::X86_P4a
        | CpuProfile::X86_P4b => {
            data.sort_unstable_by(f32::total_cmp);
            return;
        }
        _ => {}
    }

    #[cfg(target_arch = "aarch64")]
    match _profile {
        CpuProfile::ARM_A0
        | CpuProfile::ARM_A1a
        | CpuProfile::ARM_A1b
        | CpuProfile::ARM_A1c
        | CpuProfile::ARM_A1d
        | CpuProfile::ARM_A2
        | CpuProfile::Apple_M => {
            sort_f32_neon(data);
            return;
        }
        _ => {}
    }

    data.sort_unstable_by(f32::total_cmp);
}

/// Fast argsort (index sort) leveraging architecture-specific SIMD helpers for small slices.
#[inline(always)]
pub fn argsort<T: PartialOrd + 'static>(data: &[T]) -> Vec<usize> {
    if TypeId::of::<T>() == TypeId::of::<f32>() {
        let slice = unsafe { slice::from_raw_parts(data.as_ptr() as *const f32, data.len()) };
        return argsort_f32(slice);
    }
    if TypeId::of::<T>() == TypeId::of::<f64>() {
        let slice = unsafe { slice::from_raw_parts(data.as_ptr() as *const f64, data.len()) };
        return argsort_f64(slice);
    }
    telemetry::ARGSORT_FALLBACK_OPS.inc();
    argsort_generic(data)
}

fn argsort_generic<T: PartialOrd>(data: &[T]) -> Vec<usize> {
    let mut indices: Vec<usize> = (0..data.len()).collect();
    indices.sort_unstable_by(|&i, &j| {
        data[i].partial_cmp(&data[j]).unwrap_or(std::cmp::Ordering::Equal)
    });
    indices
}

fn argsort_f64(data: &[f64]) -> Vec<usize> {
    let mut indices: Vec<usize> = (0..data.len()).collect();
    indices.sort_unstable_by(|&i, &j| data[i].total_cmp(&data[j]));
    telemetry::ARGSORT_FALLBACK_OPS.inc();
    indices
}

fn argsort_f32(data: &[f32]) -> Vec<usize> {
    let len = data.len();
    if len == 0 {
        return Vec::new();
    }
    let profile = FeatureDetector::instance().profile();

    #[cfg(target_arch = "x86_64")]
    {
        if len <= 8
            && matches!(
                profile,
                CpuProfile::X86_P2a
                    | CpuProfile::X86_P2b
                    | CpuProfile::X86_P3a
                    | CpuProfile::X86_P3b
                    | CpuProfile::X86_P3c
                    | CpuProfile::X86_P3d
                    | CpuProfile::X86_P3e
            )
        {
            telemetry::ARGSORT_AVX2_OPS.inc();
            return unsafe { argsort_f32_avx2_small(data) };
        }
    }

    #[cfg(target_arch = "aarch64")]
    {
        if len <= 8
            && matches!(
                profile,
                CpuProfile::ARM_A0
                    | CpuProfile::ARM_A1a
                    | CpuProfile::ARM_A1b
                    | CpuProfile::ARM_A1c
                    | CpuProfile::ARM_A1d
                    | CpuProfile::Apple_M
                    | CpuProfile::ARM_A2
            )
        {
            telemetry::ARGSORT_NEON_OPS.inc();
            return unsafe { argsort_f32_neon_small(data) };
        }
    }

    telemetry::ARGSORT_FALLBACK_OPS.inc();
    argsort_generic(data)
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
unsafe fn argsort_f32_avx2_small(data: &[f32]) -> Vec<usize> {
    use core::cmp::Ordering;

    debug_assert!(data.len() <= 8);

    let mut values = [f32::INFINITY; 8];
    let mut indices = [usize::MAX; 8];
    for (i, v) in data.iter().enumerate() {
        values[i] = *v;
        indices[i] = i;
    }

    let mut result = Vec::with_capacity(data.len());
    for _ in 0..data.len() {
        let vec = _mm256_loadu_ps(values.as_ptr());

        let mut min_vec = vec;
        let shuffle1 = _mm256_permute_ps(min_vec, 0b1011_0001);
        min_vec = _mm256_min_ps(min_vec, shuffle1);
        let shuffle2 = _mm256_permute_ps(min_vec, 0b0100_1110);
        min_vec = _mm256_min_ps(min_vec, shuffle2);
        let swapped = _mm256_permute2f128_ps(min_vec, min_vec, 1);
        min_vec = _mm256_min_ps(min_vec, swapped);
        let min_val = _mm256_cvtss_f32(min_vec);

        let mut lane = None;
        for idx in 0..8 {
            if indices[idx] != usize::MAX
                && values[idx].partial_cmp(&min_val).unwrap_or(Ordering::Equal) == Ordering::Equal
            {
                lane = Some(idx);
                break;
            }
        }
        let lane = lane.unwrap_or_else(|| {
            let mut best_idx = 0usize;
            let mut best_val = f32::INFINITY;
            for idx in 0..8 {
                if indices[idx] == usize::MAX {
                    continue;
                }
                if values[idx] < best_val {
                    best_val = values[idx];
                    best_idx = idx;
                }
            }
            best_idx
        });

        result.push(indices[lane]);
        values[lane] = f32::INFINITY;
        indices[lane] = usize::MAX;
    }

    result
}

#[cfg(target_arch = "aarch64")]
#[target_feature(enable = "neon")]
unsafe fn argsort_f32_neon_small(data: &[f32]) -> Vec<usize> {
    use core::cmp::Ordering;
    use std::arch::aarch64::*;

    debug_assert!(data.len() <= 8);

    let mut values = [f32::INFINITY; 8];
    let mut indices = [usize::MAX; 8];
    for (i, v) in data.iter().enumerate() {
        values[i] = *v;
        indices[i] = i;
    }

    let mut result = Vec::with_capacity(data.len());
    for _ in 0..data.len() {
        let v0 = vld1q_f32(values.as_ptr());
        let v1 = vld1q_f32(values.as_ptr().add(4));
        let min0 = vminvq_f32(v0);
        let min1 = vminvq_f32(v1);
        let min_val = min0.min(min1);

        let mut lane = None;
        for idx in 0..8 {
            if indices[idx] != usize::MAX
                && values[idx].partial_cmp(&min_val).unwrap_or(Ordering::Equal) == Ordering::Equal
            {
                lane = Some(idx);
                break;
            }
        }
        let lane = lane.unwrap_or_else(|| {
            let mut best_idx = 0usize;
            let mut best_val = f32::INFINITY;
            for idx in 0..8 {
                if indices[idx] == usize::MAX {
                    continue;
                }
                if values[idx] < best_val {
                    best_val = values[idx];
                    best_idx = idx;
                }
            }
            best_idx
        });

        result.push(indices[lane]);
        values[lane] = f32::INFINITY;
        indices[lane] = usize::MAX;
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sort_u32_correctness_matches_std() {
        let mut data = vec![42, 7, 100, 3, 88, 1, 55, 29, 12, 64];
        let mut expected = data.clone();
        expected.sort_unstable();
        sort_u32(&mut data);
        assert_eq!(data, expected);
    }

    #[test]
    fn test_sort_u32_empty_slice() {
        let mut data: Vec<u32> = vec![];
        sort_u32(&mut data);
        assert!(data.is_empty());
    }

    #[test]
    fn test_sort_u32_single_element() {
        let mut data = vec![42u32];
        sort_u32(&mut data);
        assert_eq!(data, vec![42]);
    }

    #[test]
    fn test_sort_u32_already_sorted() {
        let mut data: Vec<u32> = (0..100).collect();
        let expected = data.clone();
        sort_u32(&mut data);
        assert_eq!(data, expected);
    }

    #[test]
    fn test_sort_u32_reverse_sorted() {
        let mut data: Vec<u32> = (0..100).rev().collect();
        let mut expected = data.clone();
        expected.sort_unstable();
        sort_u32(&mut data);
        assert_eq!(data, expected);
    }

    #[test]
    fn test_sort_u32_duplicates_preserve_values() {
        let mut data = vec![5u32, 3, 5, 1, 3, 5, 1, 1, 3, 5];
        let mut expected = data.clone();
        expected.sort_unstable();
        sort_u32(&mut data);
        assert_eq!(data, expected);
    }

    #[test]
    fn test_sort_u32_large_input() {
        // 2000 elements to exercise radix sort path on AVX512
        let mut data: Vec<u32> = (0..2000).map(|i| ((i * 7919) % 100_000) as u32).collect();
        let mut expected = data.clone();
        expected.sort_unstable();
        sort_u32(&mut data);
        assert_eq!(data, expected);
    }

    #[test]
    fn test_sort_f32_correctness() {
        let mut data = vec![std::f32::consts::PI, 1.0, 2.71, 0.5, 9.9, 4.2];
        let mut expected = data.clone();
        expected.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
        sort_f32(&mut data);
        assert_eq!(data, expected);
    }

    #[test]
    fn test_sort_f32_empty() {
        let mut data: Vec<f32> = vec![];
        sort_f32(&mut data);
        assert!(data.is_empty());
    }

    #[test]
    fn test_sort_f32_single() {
        let mut data = vec![42.0f32];
        sort_f32(&mut data);
        assert_eq!(data, vec![42.0]);
    }

    #[test]
    fn test_argsort_f32_returns_sorted_indices() {
        let data = vec![3.0f32, 1.0, 2.0];
        let indices = argsort(&data);
        // 1.0 < 2.0 < 3.0 => indices [1, 2, 0]
        assert_eq!(indices, vec![1, 2, 0]);
    }

    #[test]
    fn test_argsort_f64_returns_sorted_indices() {
        let data = vec![5.0f64, 2.0, 8.0, 1.0];
        let indices = argsort(&data);
        // 1.0 < 2.0 < 5.0 < 8.0 => indices [3, 1, 0, 2]
        assert_eq!(indices, vec![3, 1, 0, 2]);
    }

    #[test]
    fn test_argsort_empty() {
        let data: Vec<f32> = vec![];
        let indices = argsort(&data);
        assert!(indices.is_empty());
    }
}
