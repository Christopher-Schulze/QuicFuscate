use super::{telemetry, FeatureDetector};

// ============================================================================
// CENTRAL SIMD SYSTEM
// ============================================================================

/// 3-Level Cache Hierarchy for optimal performance - ZENTRALE DEFINITION
pub struct CacheLevel {
    /// Total cache size in bytes.
    pub size: usize,
    /// Cache line size in bytes (typically 64 or 128).
    pub line_size: usize,
    /// Set associativity (number of ways).
    pub ways: usize,
    /// Approximate access latency in CPU cycles.
    pub latency_cycles: usize,
}

/// Detected 3-level cache hierarchy with prefetch tuning parameters.
pub struct CacheHierarchy {
    /// L1 data cache parameters.
    pub l1_data: CacheLevel,
    /// L1 instruction cache parameters.
    pub l1_inst: CacheLevel,
    /// Unified L2 cache parameters.
    pub l2_unified: CacheLevel,
    /// Shared L3 cache parameters.
    pub l3_shared: CacheLevel,
    /// Optimal software prefetch distance in bytes.
    pub prefetch_distance: usize,
    /// Optimal tile size for cache-blocked algorithms.
    pub blocking_factor: usize,
}

impl CacheHierarchy {
    /// Detect cache hierarchy at runtime
    pub fn detect() -> Self {
        let features = FeatureDetector::instance().features_full();

        // Intel/AMD x86_64 typical
        #[cfg(target_arch = "x86_64")]
        if features.avx512f {
            return Self {
                l1_data: CacheLevel { size: 32768, line_size: 64, ways: 8, latency_cycles: 4 },
                l1_inst: CacheLevel { size: 32768, line_size: 64, ways: 8, latency_cycles: 4 },
                l2_unified: CacheLevel {
                    size: 1048576,
                    line_size: 64,
                    ways: 16,
                    latency_cycles: 12,
                },
                l3_shared: CacheLevel {
                    size: 16777216,
                    line_size: 64,
                    ways: 16,
                    latency_cycles: 40,
                },
                prefetch_distance: 512, // Prefetch 8 cache lines ahead
                blocking_factor: 256,   // Tile size for cache blocking
            };
        }

        // Apple Silicon M-series
        #[cfg(target_arch = "aarch64")]
        if features.apple_m1 || features.apple_m2 || features.apple_m3 {
            return Self {
                l1_data: CacheLevel { size: 131072, line_size: 128, ways: 8, latency_cycles: 3 },
                l1_inst: CacheLevel { size: 196608, line_size: 128, ways: 6, latency_cycles: 3 },
                l2_unified: CacheLevel {
                    size: 4194304,
                    line_size: 128,
                    ways: 12,
                    latency_cycles: 15,
                },
                l3_shared: CacheLevel {
                    size: 16777216,
                    line_size: 128,
                    ways: 16,
                    latency_cycles: 50,
                },
                prefetch_distance: 1024, // More aggressive prefetch
                blocking_factor: 512,    // Larger tiles for bigger caches
            };
        }

        // Default conservative
        Self {
            l1_data: CacheLevel { size: 32768, line_size: 64, ways: 4, latency_cycles: 4 },
            l1_inst: CacheLevel { size: 32768, line_size: 64, ways: 4, latency_cycles: 4 },
            l2_unified: CacheLevel { size: 262144, line_size: 64, ways: 8, latency_cycles: 12 },
            l3_shared: CacheLevel { size: 4194304, line_size: 64, ways: 16, latency_cycles: 40 },
            prefetch_distance: 256,
            blocking_factor: 128,
        }
    }

    /// Calculate optimal tile size for matrix operations
    pub fn optimal_tile_size(&self, element_size: usize) -> usize {
        // Use 1/2 of L1 cache for working set
        let working_set = self.l1_data.size / 2;
        let elements = working_set / element_size;
        // Square root for square tiles
        (elements as f64).sqrt() as usize
    }
}

// ============================================================================
// SIMD DISPATCH - DUPLICATE MODULE REMOVED!
// ============================================================================

/// SIMD operations dispatcher - selects optimal implementation at runtime
pub struct SimdDispatch;

impl SimdDispatch {
    /// XOR blocks with optimal SIMD - up to 64 bytes at once!
    #[inline(always)]
    pub fn xor_blocks(dst: &mut [u8], src: &[u8]) {
        let features = FeatureDetector::instance().features_full();

        #[cfg(target_arch = "x86_64")]
        unsafe {
            if features.avx512f {
                telemetry::AVX512_OPS.inc();
                return Self::xor_blocks_avx512(dst, src);
            }
            if features.avx2 {
                telemetry::AVX2_OPS.inc();
                return Self::xor_blocks_avx2(dst, src);
            }
            // SSE2 removed - fallback to scalar
            // Baseline is SSE4.2 but we only have AVX2/AVX512 SIMD implementations
        }

        #[cfg(target_arch = "aarch64")]
        unsafe {
            if features.sve2 {
                telemetry::SVE2_OPS.inc();
                return Self::xor_blocks_sve2(dst, src);
            }
            if features.neon {
                telemetry::NEON_OPS.inc();
                return Self::xor_blocks_neon(dst, src);
            }
        }

        telemetry::SCALAR_OPS.inc();
        Self::xor_blocks_scalar(dst, src);
    }

    /// Population count with optimal instruction
    #[inline(always)]
    pub fn popcnt(data: &[u8]) -> usize {
        let mut count = 0;

        #[cfg(target_arch = "x86_64")]
        {
            let features = FeatureDetector::instance().features_full();
            if features.popcnt {
                let (chunks, remainder) = data.as_chunks::<8>();
                for chunk in chunks {
                    let val = u64::from_le_bytes(*chunk);
                    count += val.count_ones() as usize;
                }
                for &byte in remainder {
                    count += byte.count_ones() as usize;
                }
                return count;
            }
        }

        // Fallback
        for &byte in data {
            count += byte.count_ones() as usize;
        }
        count
    }

    // x86_64 implementations
    #[cfg(target_arch = "x86_64")]
    #[target_feature(enable = "avx512f")]
    unsafe fn xor_blocks_avx512(dst: &mut [u8], src: &[u8]) {
        use std::arch::x86_64::*;

        let len = dst.len().min(src.len());
        let mut i = 0;

        // Process 64-byte chunks
        while i + 64 <= len {
            let a = _mm512_loadu_si512(dst[i..].as_ptr() as *const __m512i);
            let b = _mm512_loadu_si512(src[i..].as_ptr() as *const __m512i);
            let c = _mm512_xor_si512(a, b);
            _mm512_storeu_si512(dst[i..].as_mut_ptr() as *mut __m512i, c);
            i += 64;
        }

        // AVX-512F does not imply AVX2. Keep the remainder scalar so this
        // function's target-feature contract remains self-contained.
        while i < len {
            dst[i] ^= src[i];
            i += 1;
        }
    }

    #[cfg(target_arch = "x86_64")]
    #[target_feature(enable = "avx2")]
    unsafe fn xor_blocks_avx2(dst: &mut [u8], src: &[u8]) {
        use std::arch::x86_64::*;

        let len = dst.len().min(src.len());
        let mut i = 0;

        // Process 32-byte chunks
        while i + 32 <= len {
            let a = _mm256_loadu_si256(dst[i..].as_ptr() as *const __m256i);
            let b = _mm256_loadu_si256(src[i..].as_ptr() as *const __m256i);
            let c = _mm256_xor_si256(a, b);
            _mm256_storeu_si256(dst[i..].as_mut_ptr() as *mut __m256i, c);
            i += 32;
        }

        // Process remainder with SSE2
        while i + 16 <= len {
            let a = _mm_loadu_si128(dst[i..].as_ptr() as *const __m128i);
            let b = _mm_loadu_si128(src[i..].as_ptr() as *const __m128i);
            let c = _mm_xor_si128(a, b);
            _mm_storeu_si128(dst[i..].as_mut_ptr() as *mut __m128i, c);
            i += 16;
        }

        while i < len {
            dst[i] ^= src[i];
            i += 1;
        }
    }

    // SSE2 xor_blocks removed - baseline is SSE4.2

    // ARM64 implementations
    #[cfg(target_arch = "aarch64")]
    unsafe fn xor_blocks_neon(dst: &mut [u8], src: &[u8]) {
        use std::arch::aarch64::*;

        let len = dst.len().min(src.len());
        let mut i = 0;

        while i + 16 <= len {
            let a = vld1q_u8(dst[i..].as_ptr());
            let b = vld1q_u8(src[i..].as_ptr());
            let c = veorq_u8(a, b);
            vst1q_u8(dst[i..].as_mut_ptr(), c);
            i += 16;
        }

        while i < len {
            dst[i] ^= src[i];
            i += 1;
        }
    }

    #[cfg(target_arch = "aarch64")]
    unsafe fn xor_blocks_sve2(dst: &mut [u8], src: &[u8]) {
        #[cfg(target_feature = "sve2")]
        {
            use std::arch::aarch64::*;

            let len = dst.len().min(src.len());
            let mut offset = 0usize;

            while offset < len {
                let pg = svwhilelt_b8(offset as u64, len as u64);
                let dst_chunk = svld1_u8(pg, dst.as_ptr().add(offset));
                let src_chunk = svld1_u8(pg, src.as_ptr().add(offset));
                let xor_chunk = sveor_u8_z(pg, dst_chunk, src_chunk);
                svst1_u8(pg, dst.as_mut_ptr().add(offset), xor_chunk);
                offset += svcntb() as usize;
            }
            return;
        }

        Self::xor_blocks_neon(dst, src);
    }

    // Scalar fallback
    fn xor_blocks_scalar(dst: &mut [u8], src: &[u8]) {
        let len = dst.len().min(src.len());
        for i in 0..len {
            dst[i] ^= src[i];
        }
    }
}
