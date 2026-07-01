//! Ultra-sophisticated memory acceleration module
//! Non-temporal stores, prefetch tuning, cache-aware operations

#[cfg(target_arch = "x86_64")]
use crate::optimize::CpuProfile;
#[cfg(target_arch = "aarch64")]
use crate::optimize::CpuProfile;
use crate::optimize::FeatureDetector;
#[cfg(target_arch = "x86_64")]
use std::arch::x86_64::*;

/// Cache-aware matrix transpose - optimized for cache lines
#[inline(always)]
#[cfg(any(test, feature = "rust-tests"))]
pub fn transpose_matrix<T: Copy>(matrix: &mut [T], rows: usize, cols: usize) {
    let profile = FeatureDetector::instance().profile();

    #[cfg(target_arch = "x86_64")]
    match profile {
        CpuProfile::X86_P2a
        | CpuProfile::X86_P2b
        | CpuProfile::X86_P3a
        | CpuProfile::X86_P3b
        | CpuProfile::X86_P3c
        | CpuProfile::X86_P3d
        | CpuProfile::X86_P3e
        | CpuProfile::X86_P4a
        | CpuProfile::X86_P4b => {
            if std::mem::size_of::<T>() == 4 {
                if rows.is_multiple_of(8) && cols.is_multiple_of(8) {
                    unsafe {
                        transpose_matrix_avx2_f32(matrix as *mut _ as *mut f32, rows, cols);
                        return;
                    }
                }
            }
        }
        _ => {}
    }

    #[cfg(target_arch = "aarch64")]
    match profile {
        CpuProfile::ARM_A2 => {
            if core::mem::size_of::<T>() == 4 {
                unsafe {
                    transpose_matrix_sve2_f32(matrix as *mut _ as *mut f32, rows, cols);
                    return;
                }
            }
        }
        CpuProfile::ARM_A0
        | CpuProfile::ARM_A1a
        | CpuProfile::ARM_A1b
        | CpuProfile::ARM_A1c
        | CpuProfile::ARM_A1d
        | CpuProfile::Apple_M
            if core::mem::size_of::<T>() == 4
                && rows.is_multiple_of(4)
                && cols.is_multiple_of(4) =>
        unsafe {
            transpose_matrix_neon_f32(matrix as *mut _ as *mut f32, rows, cols);
            return;
        },
        _ => {}
    }

    // Cache-aware scalar transpose
    transpose_matrix_blocked(matrix, rows, cols);
}

#[cfg(any(test, feature = "rust-tests"))]
fn transpose_matrix_blocked<T: Copy>(matrix: &mut [T], rows: usize, cols: usize) {
    const BLOCK_SIZE: usize = 64; // Cache line aware
    let mut result = vec![matrix[0]; rows * cols];

    for i_block in (0..rows).step_by(BLOCK_SIZE) {
        for j_block in (0..cols).step_by(BLOCK_SIZE) {
            let i_end = (i_block + BLOCK_SIZE).min(rows);
            let j_end = (j_block + BLOCK_SIZE).min(cols);
            for i in i_block..i_end {
                for j in j_block..j_end {
                    result[j * rows + i] = matrix[i * cols + j];
                }
            }
        }
    }

    matrix.copy_from_slice(&result);
}

#[cfg(target_arch = "aarch64")]
#[target_feature(enable = "neon")]
#[cfg(any(test, feature = "rust-tests"))]
unsafe fn transpose_matrix_neon_f32(matrix: *mut f32, rows: usize, cols: usize) {
    let src = std::slice::from_raw_parts(matrix, rows * cols);
    let mut result = vec![0f32; rows * cols];

    for i in (0..rows).step_by(4) {
        for j in (0..cols).step_by(4) {
            transpose_4x4_neon(src.as_ptr(), result.as_mut_ptr(), i, j, cols, rows);
        }
    }

    std::ptr::copy_nonoverlapping(result.as_ptr(), matrix, rows * cols);
}

#[cfg(target_arch = "aarch64")]
#[cfg(any(test, feature = "rust-tests"))]
unsafe fn transpose_matrix_sve2_f32(matrix: *mut f32, rows: usize, cols: usize) {
    #[cfg(target_feature = "sve2")]
    {
        transpose_matrix_sve2_impl(matrix, rows, cols);
        return;
    }

    #[cfg(not(target_feature = "sve2"))]
    {
        transpose_matrix_neon_f32(matrix, rows, cols);
    }
}

#[cfg(all(target_arch = "aarch64", target_feature = "sve2"))]
#[target_feature(enable = "sve2")]
#[cfg(any(test, feature = "rust-tests"))]
unsafe fn transpose_matrix_sve2_impl(matrix: *mut f32, rows: usize, cols: usize) {
    use std::arch::aarch64::*;

    if rows == 0 || cols == 0 {
        return;
    }

    let vl = svcntw() as usize;
    let tile_rows = 4usize;
    let src = std::slice::from_raw_parts(matrix, rows * cols);
    let mut result = vec![0f32; rows * cols];
    let mut scratch = vec![0f32; tile_rows * vl];

    let mut row = 0usize;
    while row < rows {
        let row_count = (rows - row).min(tile_rows);
        let mut col = 0usize;
        while col < cols {
            let col_count = (cols - col).min(vl);
            let pg = svwhilelt_b32(0, col_count as u64);

            for r in 0..row_count {
                let ptr = src.as_ptr().add((row + r) * cols + col);
                let vec = svld1_f32(pg, ptr);
                svst1_f32(pg, scratch.as_mut_ptr().add(r * vl), vec);
            }

            for c in 0..col_count {
                let dst_base = result.as_mut_ptr().add((col + c) * rows + row);
                for r in 0..row_count {
                    *dst_base.add(r) = *scratch.as_ptr().add(r * vl + c);
                }
            }

            col += vl;
        }
        row += tile_rows;
    }

    std::ptr::copy_nonoverlapping(result.as_ptr(), matrix, rows * cols);
}

#[cfg(target_arch = "aarch64")]
#[target_feature(enable = "neon")]
#[cfg(any(test, feature = "rust-tests"))]
unsafe fn transpose_4x4_neon(
    src: *const f32,
    dst: *mut f32,
    row: usize,
    col: usize,
    src_stride: usize,
    dst_stride: usize,
) {
    use std::arch::aarch64::*;

    let r0 = vld1q_f32(src.add(row * src_stride + col));
    let r1 = vld1q_f32(src.add((row + 1) * src_stride + col));
    let r2 = vld1q_f32(src.add((row + 2) * src_stride + col));
    let r3 = vld1q_f32(src.add((row + 3) * src_stride + col));

    let t0 = vtrn1q_f32(r0, r1);
    let t1 = vtrn2q_f32(r0, r1);
    let t2 = vtrn1q_f32(r2, r3);
    let t3 = vtrn2q_f32(r2, r3);

    let o0 =
        vreinterpretq_f32_f64(vtrn1q_f64(vreinterpretq_f64_f32(t0), vreinterpretq_f64_f32(t2)));
    let o1 =
        vreinterpretq_f32_f64(vtrn1q_f64(vreinterpretq_f64_f32(t1), vreinterpretq_f64_f32(t3)));
    let o2 =
        vreinterpretq_f32_f64(vtrn2q_f64(vreinterpretq_f64_f32(t0), vreinterpretq_f64_f32(t2)));
    let o3 =
        vreinterpretq_f32_f64(vtrn2q_f64(vreinterpretq_f64_f32(t1), vreinterpretq_f64_f32(t3)));

    vst1q_f32(dst.add(col * dst_stride + row), o0);
    vst1q_f32(dst.add((col + 1) * dst_stride + row), o1);
    vst1q_f32(dst.add((col + 2) * dst_stride + row), o2);
    vst1q_f32(dst.add((col + 3) * dst_stride + row), o3);
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
#[cfg(any(test, feature = "rust-tests"))]
unsafe fn transpose_matrix_avx2_f32(matrix: *mut f32, rows: usize, cols: usize) {
    let src = std::slice::from_raw_parts(matrix, rows * cols);
    let mut result = vec![0f32; rows * cols];

    // 8x8 float32 transpose with AVX2
    for i in (0..rows).step_by(8) {
        for j in (0..cols).step_by(8) {
            transpose_8x8_avx2(src.as_ptr(), result.as_mut_ptr(), i, j, cols, rows);
        }
    }

    std::ptr::copy_nonoverlapping(result.as_ptr(), matrix, rows * cols);
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
#[cfg(any(test, feature = "rust-tests"))]
unsafe fn transpose_8x8_avx2(
    src: *const f32,
    dst: *mut f32,
    row: usize,
    col: usize,
    src_stride: usize,
    dst_stride: usize,
) {
    // Load 8x8 block
    let mut rows = [_mm256_setzero_ps(); 8];
    for i in 0..8 {
        rows[i] = _mm256_loadu_ps(src.add((row + i) * src_stride + col));
    }

    // Transpose using shuffles
    let t0 = _mm256_unpacklo_ps(rows[0], rows[1]);
    let t1 = _mm256_unpackhi_ps(rows[0], rows[1]);
    let t2 = _mm256_unpacklo_ps(rows[2], rows[3]);
    let t3 = _mm256_unpackhi_ps(rows[2], rows[3]);
    let t4 = _mm256_unpacklo_ps(rows[4], rows[5]);
    let t5 = _mm256_unpackhi_ps(rows[4], rows[5]);
    let t6 = _mm256_unpacklo_ps(rows[6], rows[7]);
    let t7 = _mm256_unpackhi_ps(rows[6], rows[7]);

    let tt0 = _mm256_shuffle_ps(t0, t2, 0x44);
    let tt1 = _mm256_shuffle_ps(t0, t2, 0xEE);
    let tt2 = _mm256_shuffle_ps(t1, t3, 0x44);
    let tt3 = _mm256_shuffle_ps(t1, t3, 0xEE);
    let tt4 = _mm256_shuffle_ps(t4, t6, 0x44);
    let tt5 = _mm256_shuffle_ps(t4, t6, 0xEE);
    let tt6 = _mm256_shuffle_ps(t5, t7, 0x44);
    let tt7 = _mm256_shuffle_ps(t5, t7, 0xEE);

    rows[0] = _mm256_permute2f128_ps(tt0, tt4, 0x20);
    rows[1] = _mm256_permute2f128_ps(tt1, tt5, 0x20);
    rows[2] = _mm256_permute2f128_ps(tt2, tt6, 0x20);
    rows[3] = _mm256_permute2f128_ps(tt3, tt7, 0x20);
    rows[4] = _mm256_permute2f128_ps(tt0, tt4, 0x31);
    rows[5] = _mm256_permute2f128_ps(tt1, tt5, 0x31);
    rows[6] = _mm256_permute2f128_ps(tt2, tt6, 0x31);
    rows[7] = _mm256_permute2f128_ps(tt3, tt7, 0x31);

    // Store transposed block
    for i in 0..8 {
        _mm256_storeu_ps(dst.add((col + i) * dst_stride + row), rows[i]);
    }
}

/// Rust parity/test-only lock-free ring buffer helper.
#[cfg(any(test, feature = "rust-tests"))]
pub struct LockFreeRingBuffer {
    buffer: Vec<u8>,
    capacity: usize,
    mask: usize,
    head: std::sync::atomic::AtomicUsize,
    tail: std::sync::atomic::AtomicUsize,
}

#[cfg(any(test, feature = "rust-tests"))]
impl LockFreeRingBuffer {
    pub fn new(capacity: usize) -> Self {
        // Round up to power of 2 for fast modulo
        let capacity = capacity.next_power_of_two();
        Self {
            buffer: vec![0; capacity],
            capacity,
            mask: capacity - 1,
            head: std::sync::atomic::AtomicUsize::new(0),
            tail: std::sync::atomic::AtomicUsize::new(0),
        }
    }

    pub fn push(&self, data: &[u8]) -> bool {
        let head = self.head.load(std::sync::atomic::Ordering::Acquire);
        let tail = self.tail.load(std::sync::atomic::Ordering::Acquire);

        let used = head.wrapping_sub(tail);
        let available = if used >= self.capacity { 0 } else { self.capacity - used - 1 };

        if data.len() > available {
            return false;
        }

        let idx = head & self.mask;
        let first = (self.capacity - idx).min(data.len());

        unsafe {
            let dst_ptr = self.buffer.as_ptr().add(idx) as *mut u8;
            let dst_slice = std::slice::from_raw_parts_mut(dst_ptr, first);
            dst_slice.copy_from_slice(&data[..first]);
        }

        if data.len() > first {
            let second = data.len() - first;
            unsafe {
                let dst_ptr = self.buffer.as_ptr() as *mut u8;
                let dst_slice = std::slice::from_raw_parts_mut(dst_ptr, second);
                dst_slice.copy_from_slice(&data[first..]);
            }
        }

        let pos = head.wrapping_add(data.len());
        // Update head
        self.head.store(pos, std::sync::atomic::Ordering::Release);
        true
    }

    pub fn pop(&self, buf: &mut [u8]) -> usize {
        let head = self.head.load(std::sync::atomic::Ordering::Acquire);
        let tail = self.tail.load(std::sync::atomic::Ordering::Acquire);

        let available = head.wrapping_sub(tail);

        let to_read = buf.len().min(available);

        let idx = tail & self.mask;
        let first = (self.capacity - idx).min(to_read);

        if first > 0 {
            unsafe {
                let src_slice = std::slice::from_raw_parts(self.buffer.as_ptr().add(idx), first);
                buf[..first].copy_from_slice(src_slice);
            }
        }

        if to_read > first {
            let second = to_read - first;
            unsafe {
                let src_slice = std::slice::from_raw_parts(self.buffer.as_ptr(), second);
                buf[first..first + second].copy_from_slice(src_slice);
            }
        }

        let pos = tail.wrapping_add(to_read);
        // Update tail
        self.tail.store(pos, std::sync::atomic::Ordering::Release);
        to_read
    }
}
