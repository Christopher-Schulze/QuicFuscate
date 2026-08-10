//! x86 SIMD helpers for ACK range canonicalization/merge
//! AVX2/AVX-512 implementations used by transport layer

use std::arch::x86_64::*;

#[inline]
/// Canonicalize ACK ranges with AVX2 when the current CPU supports it.
///
/// Unsupported CPUs use the scalar canonicalizer.
#[doc(hidden)]
pub fn canonical_ack_blocks_avx2(ranges: &[(u64, u64)]) -> Vec<(u64, u64)> {
    if !is_x86_feature_detected!("avx2") {
        return canonical_ack_blocks_scalar(ranges);
    }
    // SAFETY: the in-process runtime feature check above proves the AVX2 target-feature
    // precondition for this call.
    unsafe { canonical_ack_blocks_avx2_unchecked(ranges) }
}

#[target_feature(enable = "avx2")]
#[inline]
/// # Safety
///
/// The caller must provide AVX2 support and a valid immutable `ranges` slice
/// for the duration of the call. The implementation copies the input before
/// sorting and bounds every unaligned vector load by the copied length.
#[doc(hidden)]
pub(crate) unsafe fn canonical_ack_blocks_avx2_unchecked(ranges: &[(u64, u64)]) -> Vec<(u64, u64)> {
    if ranges.is_empty() {
        return Vec::new();
    }

    let mut sorted = ranges.to_vec();
    sorted.sort_by_key(|r| r.0);

    let len = sorted.len();
    let mut starts: Vec<u64> = Vec::with_capacity(len);
    let mut ends: Vec<u64> = Vec::with_capacity(len);
    for (s, e) in &sorted {
        starts.push(*s);
        ends.push(*e);
    }

    let mut out: Vec<(u64, u64)> = Vec::with_capacity(len);
    let mut idx = 0usize;
    while idx < len {
        let current_start = starts[idx];
        let mut current_end = ends[idx];
        idx += 1;

        loop {
            if idx >= len {
                break;
            }

            let mut local = idx;
            let mut advanced = 0usize;
            let mut max_candidate = current_end;

            while local + 4 <= len {
                // SAFETY: `local + 4 <= len` guarantees at least 4 contiguous u64
                // elements starting at `starts[local]`. Each u64 is 8 bytes, so the
                // 32-byte AVX2 load from `s_ptr` reads exactly 4 * 8 = 32 bytes within
                // the Vec allocation. `_mm256_loadu_si256` does not require alignment.
                let s_ptr = starts.as_ptr().add(local) as *const __m256i;
                let s_vec = _mm256_loadu_si256(s_ptr);
                let end_bcast = _mm256_set1_epi64x(current_end as i64);
                let gt = _mm256_cmpgt_epi64(s_vec, end_bcast);
                // SAFETY: `__m256i` and `__m256d` have identical size (32 bytes) and
                // alignment (32 bytes). The transmute reinterprets the comparison
                // bitmask for `_mm256_movemask_pd` which expects `__m256d`. No value
                // semantics change - only the lane type interpretation differs.
                let gt_pd = core::mem::transmute::<__m256i, __m256d>(gt);
                let mask = _mm256_movemask_pd(gt_pd) as u32; // 1 if start > end
                let le_mask = (!mask) & 0xF;
                if le_mask == 0 {
                    break;
                }
                let count = le_mask.trailing_ones().min(4);

                // SAFETY: Same bounds reasoning as `s_ptr` above - `local + 4 <= len`
                // guarantees 4 contiguous u64 elements at `ends[local]`.
                let e_ptr = ends.as_ptr().add(local) as *const __m256i;
                let e_vec = _mm256_loadu_si256(e_ptr);
                // SAFETY: `__m256i` (32 bytes) has the same size and layout as
                // `[u64; 4]` (4 * 8 = 32 bytes). The transmute extracts lane values
                // for scalar comparison. All bit patterns are valid for u64.
                let tmp: [u64; 4] = core::mem::transmute(e_vec);
                let mut local_max = max_candidate;
                for lane in 0..(count as usize) {
                    if tmp[lane] > local_max {
                        local_max = tmp[lane];
                    }
                }

                max_candidate = local_max;
                advanced += count as usize;
                local += count as usize;
            }

            while local < len && starts[local] <= current_end {
                if ends[local] > max_candidate {
                    max_candidate = ends[local];
                }
                local += 1;
                advanced += 1;
            }

            if advanced == 0 {
                break;
            }
            idx += advanced;
            if max_candidate > current_end {
                current_end = max_candidate;
                continue;
            }
        }

        out.push((current_start, current_end));
    }

    out
}

/// Canonicalize ACK ranges with AVX-512 when the current CPU supports it.
///
/// Unsupported CPUs use the scalar canonicalizer.
#[doc(hidden)]
pub fn canonical_ack_blocks_avx512(ranges: &[(u64, u64)]) -> Vec<(u64, u64)> {
    if !(is_x86_feature_detected!("avx512f") && is_x86_feature_detected!("avx512vl")) {
        return canonical_ack_blocks_scalar(ranges);
    }
    // SAFETY: the in-process runtime feature checks above prove the AVX-512F and AVX-512VL
    // target-feature preconditions for this call.
    unsafe { canonical_ack_blocks_avx512_unchecked(ranges) }
}

#[target_feature(enable = "avx512f", enable = "avx512vl")]
#[inline]
/// # Safety
///
/// The caller must provide AVX-512F and AVX-512VL support and a valid immutable
/// `ranges` slice for the duration of the call. The implementation copies the
/// input before sorting and bounds every unaligned vector load by its length.
#[doc(hidden)]
pub(crate) unsafe fn canonical_ack_blocks_avx512_unchecked(
    ranges: &[(u64, u64)],
) -> Vec<(u64, u64)> {
    if ranges.is_empty() {
        return Vec::new();
    }

    let mut sorted = ranges.to_vec();
    sorted.sort_by_key(|r| r.0);

    let len = sorted.len();
    let mut starts: Vec<u64> = Vec::with_capacity(len);
    let mut ends: Vec<u64> = Vec::with_capacity(len);
    for (s, e) in &sorted {
        starts.push(*s);
        ends.push(*e);
    }

    let mut out: Vec<(u64, u64)> = Vec::with_capacity(len);
    let mut idx = 0usize;
    while idx < len {
        let current_start = starts[idx];
        let mut current_end = ends[idx];
        idx += 1;

        loop {
            if idx >= len {
                break;
            }
            let mut local = idx;
            let mut advanced = 0usize;
            let mut max_candidate = current_end;

            while local + 8 <= len {
                // SAFETY: `local + 8 <= len` guarantees 8 contiguous u64 elements at
                // `starts[local]`. Each u64 is 8 bytes, so the 64-byte AVX-512 load
                // reads exactly 8 * 8 = 64 bytes within the Vec allocation.
                // `_mm512_loadu_si512` does not require alignment.
                let s_ptr = starts.as_ptr().add(local) as *const __m512i;
                let s_vec = _mm512_loadu_si512(s_ptr);
                let end_bcast = _mm512_set1_epi64(current_end as i64);
                // 6 == _MM_CMPINT_NLE, which is equivalent to "greater than".
                let gt_mask = _mm512_cmp_epi64_mask(s_vec, end_bcast, 6);
                let le_mask = (!gt_mask) & 0xFF; // lanes where start <= end
                if le_mask == 0 {
                    break;
                }
                let count = le_mask.trailing_zeros().min(8);

                // SAFETY: Same bounds reasoning as `s_ptr` above - `local + 8 <= len`
                // guarantees 8 contiguous u64 elements at `ends[local]`.
                let e_ptr = ends.as_ptr().add(local) as *const __m512i;
                let e_vec = _mm512_loadu_si512(e_ptr);
                // SAFETY: `__m512i` (64 bytes) has the same size and layout as
                // `[u64; 8]` (8 * 8 = 64 bytes). The transmute extracts lane values
                // for scalar max-finding. All bit patterns are valid for u64.
                let tmp: [u64; 8] = core::mem::transmute(e_vec);
                let mut local_max = max_candidate;
                for lane in 0..(count as usize) {
                    if tmp[lane] > local_max {
                        local_max = tmp[lane];
                    }
                }
                max_candidate = local_max;
                advanced += count as usize;
                local += count as usize;
            }

            while local < len && starts[local] <= current_end {
                if ends[local] > max_candidate {
                    max_candidate = ends[local];
                }
                local += 1;
                advanced += 1;
            }

            if advanced == 0 {
                break;
            }
            idx += advanced;
            if max_candidate > current_end {
                current_end = max_candidate;
                continue;
            }
        }

        out.push((current_start, current_end));
    }

    out
}

/// Canonicalize ACK ranges without an ISA requirement for test wrappers.
pub(crate) fn canonical_ack_blocks_scalar(ranges: &[(u64, u64)]) -> Vec<(u64, u64)> {
    let mut sorted = ranges.to_vec();
    sorted.sort_by_key(|range| range.0);

    let mut out: Vec<(u64, u64)> = Vec::with_capacity(sorted.len());
    for (start, end) in sorted {
        if let Some(last) = out.last_mut() {
            if start <= last.1 {
                last.1 = last.1.max(end);
                continue;
            }
        }
        out.push((start, end));
    }
    out
}
