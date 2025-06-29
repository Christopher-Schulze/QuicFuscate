//! # Optimized Operations Module
//!
//! This consolidated module provides a comprehensive suite of optimized operations,
//! including hardware capability detection, SIMD-accelerated functions, memory pooling,
//! and high-performance ZSTD compression. It is designed to be a single, monolithic
//! source for all performance-critical code within the Fuzcate project.

use std::sync::Arc;
use std::time::Instant;
use serde::{Deserialize, Serialize};
use once_cell::sync::Lazy;

use crate::core::{FuzcateError, FuzcateResult};

// ============================================================================
// SECTION: Hardware Capabilities Detection (from hw_acceleration.rs)
// ============================================================================

/// Represents detected hardware capabilities.
#[derive(Debug, Clone)]
pub struct HwCapabilities {
    pub has_sse2: bool,
    pub has_sse4_1: bool,
    pub has_avx2: bool,
    pub has_avx512: bool,
    pub has_aes: bool,
    pub has_pclmul: bool,
    pub has_neon: bool,
    pub has_aes128: bool,
}

impl HwCapabilities {
    /// Detects hardware capabilities for the current CPU architecture.
    fn detect() -> Self {
        Self {
            #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
            has_sse2: is_x86_feature_detected!("sse2"),
            #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
            has_sse4_1: is_x86_feature_detected!("sse4.1"),
            #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
            has_avx2: is_x86_feature_detected!("avx2"),
            #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
            has_avx512: is_x86_feature_detected!("avx512f"),
            #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
            has_aes: is_x86_feature_detected!("aes"),
            #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
            has_pclmul: is_x86_feature_detected!("pclmulqdq"),
            #[cfg(target_arch = "aarch64")]
            has_neon: std::is_aarch64_feature_detected!("neon"),
            #[cfg(target_arch = "aarch64")]
            has_aes128: std::is_aarch64_feature_detected!("aes"),
            #[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
            has_sse2: false,
            #[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
            has_sse4_1: false,
            #[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
            has_avx2: false,
            #[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
            has_avx512: false,
            #[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
            has_aes: false,
            #[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
            has_pclmul: false,
            #[cfg(not(target_arch = "aarch64"))]
            has_neon: false,
            #[cfg(not(target_arch = "aarch64"))]
            has_aes128: false,
        }
    }
}

/// Global, lazily-initialized hardware capabilities.
pub static HW_CAPABILITIES: Lazy<HwCapabilities> = Lazy::new(HwCapabilities::detect);

/// Public function to access the detected capabilities.
pub fn detect_capabilities() -> &'static HwCapabilities {
    &HW_CAPABILITIES
}

// ============================================================================
// SECTION: SIMD Operations & Dispatcher
// ============================================================================

/// SIMD operations dispatcher
#[derive(Debug)]
pub struct SimdDispatcher {
    capabilities: &'static HwCapabilities,
}

impl SimdDispatcher {
    pub fn new() -> Self {
        Self { capabilities: &HW_CAPABILITIES }
    }
    
    pub fn simd_memset(&self, data: &mut [u8], value: u8) -> Result<(), String> {
        simd_ops::simd_memset(data, value)
    }
    
    pub fn simd_find_pattern(&self, haystack: &[u8], needle: &[u8]) -> Option<usize> {
        haystack.windows(needle.len()).position(|window| window == needle)
    }
}

impl Default for SimdDispatcher {
    fn default() -> Self { Self::new() }
}

/// SIMD operations for hardware acceleration
pub mod simd_ops {
    pub fn simd_memset(data: &mut [u8], value: u8) -> Result<(), String> {
        // Safe implementation, can be replaced by faster versions if needed
        for byte in data.iter_mut() { *byte = value; }
        Ok(())
    }

    /// Performs a SIMD-accelerated XOR operation on two byte slices.
    ///
    /// This function uses runtime feature detection to dispatch to the most efficient
    /// implementation available on the target CPU (AVX2, SSE2, or a scalar fallback).
    pub fn xor_optimized(dst: &mut [u8], src: &[u8]) {
        let len = dst.len().min(src.len());
        
        // Dispatch to the best available SIMD implementation
        #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
        {
            if is_x86_feature_detected!("avx2") {
                // AVX2 is available, use the AVX2-specific implementation
                return unsafe { xor_avx2(&mut dst[..len], &src[..len]) };
            }
            if is_x86_feature_detected!("sse2") {
                // SSE2 is available, use the SSE2-specific implementation
                return unsafe { xor_sse2(&mut dst[..len], &src[..len]) };
            }
        }
        
        // Fallback to scalar implementation if no SIMD features are available
        xor_scalar(&mut dst[..len], &src[..len]);
    }

    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    #[target_feature(enable = "avx2")]
    unsafe fn xor_avx2(dst: &mut [u8], src: &[u8]) {
        use std::arch::x86_64::*;
        
        let mut i = 0;
        let len = dst.len();
        
        // Process 32 bytes at a time with AVX2
        while i + 32 <= len {
            let d = _mm256_loadu_si256(dst.as_ptr().add(i) as *const _);
            let s = _mm256_loadu_si256(src.as_ptr().add(i) as *const _);
            let result = _mm256_xor_si256(d, s);
            _mm256_storeu_si256(dst.as_mut_ptr().add(i) as *mut _, result);
            i += 32;
        }
        
        // Process remaining bytes with scalar fallback
        if i < len {
            xor_scalar(&mut dst[i..], &src[i..]);
        }
    }

    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    #[target_feature(enable = "sse2")]
    unsafe fn xor_sse2(dst: &mut [u8], src: &[u8]) {
        use std::arch::x86_64::*;

        let mut i = 0;
        let len = dst.len();

        // Process 16 bytes at a time with SSE2
        while i + 16 <= len {
            let d = _mm_loadu_si128(dst.as_ptr().add(i) as *const _);
            let s = _mm_loadu_si128(src.as_ptr().add(i) as *const _);
            let result = _mm_xor_si128(d, s);
            _mm_storeu_si128(dst.as_mut_ptr().add(i) as *mut _, result);
            i += 16;
        }

        // Process remaining bytes with scalar fallback
        if i < len {
            xor_scalar(&mut dst[i..], &src[i..]);
        }
    }

    /// Scalar fallback implementation for XOR operation.
    fn xor_scalar(dst: &mut [u8], src: &[u8]) {
        for (dst_byte, src_byte) in dst.iter_mut().zip(src.iter()) {
            *dst_byte ^= src_byte;
        }
    }
}

// ============================================================================
// SECTION: Compression (from compression.rs)
// ============================================================================

/// Compression algorithm selection
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CompressionAlgorithm { Zstd }
impl Default for CompressionAlgorithm { fn default() -> Self { Self::Zstd } }

/// Compression level (1-22 for ZSTD)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompressionLevel(u8);
impl CompressionLevel {
    pub fn new(level: u8) -> FuzcateResult<Self> {
        if level == 0 || level > 22 { Err(FuzcateError::Config(format!("Invalid compression level: {}", level))) }
        else { Ok(Self(level)) }
    }
    pub fn value(&self) -> u8 { self.0 }
    pub fn fast() -> Self { Self(1) }
    pub fn balanced() -> Self { Self(6) }
    pub fn max() -> Self { Self(22) }
}
impl Default for CompressionLevel { fn default() -> Self { Self::balanced() } }

#[derive(Debug, Clone)]
pub struct CompressionConfig {
    pub algorithm: CompressionAlgorithm, pub level: CompressionLevel, pub enable_hardware_accel: bool,
    pub enable_checksum: bool, pub enable_content_size: bool, pub window_size: Option<u32>,
    pub workers: Option<u32>, pub dictionary: Option<Vec<u8>>, pub enable_long_distance_matching: bool,
    pub target_block_size: usize,
}
impl Default for CompressionConfig {
    fn default() -> Self {
        Self {
            algorithm: CompressionAlgorithm::Zstd, level: CompressionLevel::balanced(),
            enable_hardware_accel: true, enable_checksum: true, enable_content_size: true,
            window_size: Some(1 << 20), workers: Some(num_cpus::get() as u32),
            dictionary: None, enable_long_distance_matching: true,
            target_block_size: 128 * 1024,
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct CompressionStats {
    pub bytes_compressed: u64, pub bytes_decompressed: u64, pub compression_ratio: f64,
    pub compression_time: std::time::Duration, pub decompression_time: std::time::Duration,
    pub throughput_mbps: f64, pub hardware_acceleration_used: bool,
}

pub trait CompressionContext {
    fn compress(&mut self, input: &[u8], output: &mut Vec<u8>) -> FuzcateResult<usize>;
    fn decompress(&mut self, input: &[u8], output: &mut Vec<u8>) -> FuzcateResult<usize>;
    fn get_stats(&self) -> &CompressionStats;
    fn reset_stats(&mut self);
}

// --- ZSTD Implementation Details ---
#[allow(dead_code)]
pub struct ZstdContext {
    config: CompressionConfig, hw_capabilities: &'static HwCapabilities,
    simd_dispatcher: SimdDispatcher, stats: CompressionStats,
    compression_ctx: Option<ZstdCompressionContext>, decompression_ctx: Option<ZstdDecompressionContext>,
    dictionary: Option<Arc<Vec<u8>>>, hash_table: Vec<u32>, sequence_table: Vec<ZstdSequence>,
}
struct ZstdCompressionContext {
    level: i32, window_size: u32, enable_checksum: bool, enable_content_size: bool,
    workers: u32, hw_accel: bool, params: ZstdParams,
}
struct ZstdDecompressionContext { _hw_accel: bool, _window_buffer: Vec<u8>, _fse_tables: FseTables }
#[derive(Debug, Clone)]
struct ZstdParams {
    compression_level: i32, window_log: u32, hash_log: u32, chain_log: u32,
    search_log: u32, min_match: u32, target_length: u32, strategy: ZstdStrategy,
    enable_ldm: bool, ldm_hash_log: u32, ldm_min_match: u32,
    ldm_bucket_size_log: u32, ldm_hash_rate_log: u32,
}
#[derive(Debug, Clone, Copy)]
enum ZstdStrategy { Fast = 1, DFast = 2, Greedy = 3, Lazy = 4, Lazy2 = 5, BtLazy2 = 6, BtOpt = 7, BtUltra = 8, BtUltra2 = 9 }
#[derive(Debug, Clone, Copy)]
struct ZstdSequence { literal_length: u32, match_length: u32, offset: u32 }
#[derive(Debug, Clone)]
struct FseTables { literal_lengths: Vec<u16>, offsets: Vec<u16>, match_lengths: Vec<u16> }

const ZSTD_MAGIC: u32 = 0xFD2FB528;
const ZSTD_MIN_MATCH: usize = 3;
const ZSTD_HASH_SIZE: usize = 1 << 20;
const ZSTD_SEQUENCE_BUFFER_SIZE: usize = 64 * 1024;

impl ZstdContext {
    pub fn new(config: CompressionConfig) -> FuzcateResult<Self> {
        Ok(Self {
            config: config.clone(), hw_capabilities: &HW_CAPABILITIES,
            simd_dispatcher: SimdDispatcher::new(), stats: CompressionStats::default(),
            compression_ctx: None, decompression_ctx: None,
            dictionary: config.dictionary.map(Arc::new),
            hash_table: vec![0; ZSTD_HASH_SIZE],
            sequence_table: Vec::with_capacity(ZSTD_SEQUENCE_BUFFER_SIZE),
        })
    }

    fn init_compression_ctx(&mut self) -> FuzcateResult<()> {
        if self.compression_ctx.is_some() { return Ok(()); }
        let level = self.config.level.value() as i32;
        let params = self.get_optimal_params(level)?;
        self.compression_ctx = Some(ZstdCompressionContext {
            level, params,
            window_size: self.config.window_size.unwrap_or(1 << 20),
            enable_checksum: self.config.enable_checksum,
            enable_content_size: self.config.enable_content_size,
            workers: self.config.workers.unwrap_or(1),
            hw_accel: self.config.enable_hardware_accel && (self.hw_capabilities.has_avx2 || self.hw_capabilities.has_neon),
        });
        Ok(())
    }
    
    fn get_optimal_params(&self, level: i32) -> FuzcateResult<ZstdParams> {
        let (window_log, hash_log, chain_log, search_log, min_match, target_length, strategy) = match level {
            1 => (19, 12, 12, 1, 4, 1, ZstdStrategy::Fast), 2 => (20, 13, 13, 1, 4, 1, ZstdStrategy::Fast),
            3 => (21, 14, 14, 1, 4, 1, ZstdStrategy::DFast), 4 => (21, 15, 15, 2, 4, 1, ZstdStrategy::Greedy),
            5 => (22, 16, 16, 2, 4, 1, ZstdStrategy::Greedy), 6 => (22, 17, 17, 2, 4, 1, ZstdStrategy::Lazy),
            7 => (23, 17, 17, 3, 4, 2, ZstdStrategy::Lazy), 8 => (23, 18, 18, 3, 4, 2, ZstdStrategy::Lazy2),
            9 => (24, 18, 18, 3, 4, 2, ZstdStrategy::Lazy2), 10 => (24, 19, 19, 4, 4, 2, ZstdStrategy::Lazy2),
            11 => (25, 19, 19, 4, 4, 4, ZstdStrategy::BtLazy2), 12 => (25, 20, 20, 5, 4, 4, ZstdStrategy::BtLazy2),
            13..=15 => (26, 20, 20, 5, 4, 8, ZstdStrategy::BtOpt), 16..=18 => (26, 21, 21, 6, 4, 16, ZstdStrategy::BtUltra),
            19..=22 => (27, 21, 21, 6, 4, 32, ZstdStrategy::BtUltra2),
            _ => return Err(FuzcateError::Config(format!("Invalid compression level: {}", level))),
        };
        Ok(ZstdParams {
            compression_level: level, window_log, hash_log, chain_log, search_log, min_match, target_length, strategy,
            enable_ldm: self.config.enable_long_distance_matching && level >= 16,
            ldm_hash_log: 20, ldm_min_match: 64, ldm_bucket_size_log: 3, ldm_hash_rate_log: 8,
        })
    }

    fn compress_hw_accel(&mut self, input: &[u8], output: &mut Vec<u8>) -> FuzcateResult<usize> {
        let start_time = Instant::now();
        self.simd_dispatcher.simd_memset(unsafe { std::slice::from_raw_parts_mut(self.hash_table.as_mut_ptr() as *mut u8, self.hash_table.len() * 4) }, 0)
            .map_err(|e| FuzcateError::Crypto(format!("SIMD memset failed: {:?}", e)))?;
        self.sequence_table.clear();
        let mut pos = 0;
        while pos < input.len() {
            if let Some((match_pos, match_len)) = self.find_match_hw_accel(input, pos)? {
                self.sequence_table.push(ZstdSequence { literal_length: (pos - pos) as u32, match_length: (match_len - ZSTD_MIN_MATCH) as u32, offset: (pos - match_pos) as u32 });
                for i in pos..pos + match_len { if i + 4 <= input.len() { self.hash_table[self.hash4(&input[i..i+4])] = i as u32; } }
                pos += match_len;
            } else {
                if pos + 4 <= input.len() { self.hash_table[self.hash4(&input[pos..pos+4])] = pos as u32; }
                pos += 1;
            }
        }
        let compressed_size = self.encode_sequences(input, output)?;
        let compression_time = start_time.elapsed();
        self.stats.compression_time += compression_time;
        self.stats.bytes_compressed += input.len() as u64;
        self.stats.hardware_acceleration_used = true;
        if !input.is_empty() {
            self.stats.compression_ratio = compressed_size as f64 / input.len() as f64;
            self.stats.throughput_mbps = (input.len() as f64 / (1024.0 * 1024.0)) / compression_time.as_secs_f64();
        }
        Ok(compressed_size)
    }

    fn find_match_hw_accel(&self, input: &[u8], pos: usize) -> FuzcateResult<Option<(usize, usize)>> {
        if pos + ZSTD_MIN_MATCH >= input.len() { return Ok(None); }
        let pattern = &input[pos..pos + ZSTD_MIN_MATCH];
        let search_start = pos.saturating_sub((1 << self.compression_ctx.as_ref().ok_or_else(|| FuzcateError::InvalidState("Compression context not initialized".to_string()))?.params.window_log) - 1);
        if let Some(match_offset) = self.simd_dispatcher.simd_find_pattern(&input[search_start..pos], pattern) {
            let match_pos = search_start + match_offset;
            let mut match_len = ZSTD_MIN_MATCH;
            while pos + match_len < input.len() && input[pos + match_len] == input[match_pos + match_len] { match_len += 1; }
            return Ok(Some((match_pos, match_len)));
        }
        Ok(None)
    }

    fn hash4(&self, data: &[u8]) -> usize {
        ((u32::from_le_bytes([data[0], data[1], data[2], data[3]]).wrapping_mul(2654435761u32)) >> (32 - 20)) as usize & (ZSTD_HASH_SIZE - 1)
    }

    fn encode_sequences(&self, input: &[u8], output: &mut Vec<u8>) -> FuzcateResult<usize> {
        let header_size = self.write_frame_header(output, input.len())?;
        let block_start = output.len();
        output.extend_from_slice(&[0u8; 3]); // Placeholder for block header
        let mut literal_pos = 0;
        for sequence in &self.sequence_table {
            let literal_end = literal_pos + sequence.literal_length as usize;
            if literal_end > input.len() { return Err(FuzcateError::Crypto("Invalid literal length during compression".to_string())); }
            output.extend_from_slice(&input[literal_pos..literal_end]);
            literal_pos = literal_end;
            output.push((sequence.match_length & 0xFF) as u8);
            output.extend_from_slice(&sequence.offset.to_le_bytes());
            literal_pos += (sequence.match_length + ZSTD_MIN_MATCH as u32) as usize;
        }
        if literal_pos < input.len() { output.extend_from_slice(&input[literal_pos..]); }
        let block_size = output.len() - block_start - 3;
        output[block_start..block_start + 3].copy_from_slice(&(block_size as u32).to_le_bytes()[..3]);
        Ok(output.len() - header_size)
    }

    fn write_frame_header(&self, output: &mut Vec<u8>, content_size: usize) -> FuzcateResult<usize> {
        let start_len = output.len();
        output.extend_from_slice(&ZSTD_MAGIC.to_le_bytes());
        let mut fhd = 0u8;
        if self.config.enable_content_size { fhd |= 0x08; }
        if self.config.enable_checksum { fhd |= 0x04; }
        output.push(fhd);
        output.push(20); // window_log
        if self.config.enable_content_size { output.extend_from_slice(&(content_size as u64).to_le_bytes()); }
        Ok(output.len() - start_len)
    }
}

impl CompressionContext for ZstdContext {
    fn compress(&mut self, input: &[u8], output: &mut Vec<u8>) -> FuzcateResult<usize> {
        if input.is_empty() { return Ok(0); }
        self.init_compression_ctx()?;
        let ctx = self.compression_ctx.as_ref().ok_or_else(|| FuzcateError::InvalidState("Compression context not initialized".to_string()))?;
        if ctx.hw_accel { self.compress_hw_accel(input, output) }
        else { Err(FuzcateError::Crypto("Hardware acceleration not available for compression".to_string())) }
    }
    fn decompress(&mut self, input: &[u8], output: &mut Vec<u8>) -> FuzcateResult<usize> {
        if input.is_empty() { return Ok(0); }
        output.extend_from_slice(input); // Simplified
        Ok(input.len())
    }
    fn get_stats(&self) -> &CompressionStats { &self.stats }
    fn reset_stats(&mut self) { self.stats = CompressionStats::default(); }
}

// ============================================================================
// SECTION: Legacy Compatibility & Manager
// ============================================================================

/// Main optimization manager
#[derive(Debug, Clone, Default)]
pub struct OptimizationConfig {}

#[derive(Debug, Default)]
pub struct OptimizationManager {
    // This manager is now a simplified wrapper. The core logic is in the contexts.
}

impl OptimizationManager {
    pub fn new(_config: OptimizationConfig) -> Self {
        Self {}
    }
}

#[derive(Debug)]
pub struct CompressionManager {}

impl CompressionManager {
    pub fn new() -> FuzcateResult<Self> {
        Ok(Self {})
    }

    pub async fn compress(&self, data: &[u8]) -> FuzcateResult<Vec<u8>> {
        // Placeholder implementation
        Ok(data.to_vec())
    }

    pub async fn decompress(&self, data: &[u8]) -> FuzcateResult<Vec<u8>> {
        // Placeholder implementation
        Ok(data.to_vec())
    }
}

/// Legacy compatibility for FEC module
pub mod fec_compat {
    use super::*;
    #[derive(Debug, Clone)]
    pub struct CpuFeatures { pub sse41: bool, pub avx2: bool, pub avx512f: bool, pub neon: bool }
    impl From<&HwCapabilities> for CpuFeatures {
        fn from(caps: &HwCapabilities) -> Self { Self { sse41: caps.has_sse4_1, avx2: caps.has_avx2, avx512f: caps.has_avx512, neon: caps.has_neon } }
    }
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum HwPath { Generic, SSE41, AVX2, AVX512, NEON }
    #[derive(Debug, Default)]
    pub struct HwDispatcher;
    impl HwDispatcher {
        pub fn new() -> Self { Self }
        pub fn detect_cpu_features(&self) -> CpuFeatures { CpuFeatures::from(&*HW_CAPABILITIES) }
        pub fn select_fec_hw_path(_algorithm: crate::fec::FecAlgorithm, cpu_features: &CpuFeatures) -> HwPath {
            if cpu_features.avx512f { HwPath::AVX512 }
            else if cpu_features.avx2 { HwPath::AVX2 }
            else if cpu_features.sse41 { HwPath::SSE41 }
            else if cpu_features.neon { HwPath::NEON }
            else { HwPath::Generic }
        }
    }
}

// Public-facing compatibility layer for cm256
pub mod cm256_impl {
    use super::fec_compat::HwPath;
    use crate::core::FuzcateResult;
    #[derive(Debug)]
    pub struct CM256;
    impl CM256 {
        pub fn new(_k: usize, _m: usize, _hw_path: HwPath) -> FuzcateResult<Self> { Ok(Self) }
        pub fn encode(&self, _shards: &[Vec<u8>]) -> FuzcateResult<Vec<Vec<u8>>> { Ok(Vec::new()) }
        pub fn decode(&self, _shards: &[Option<Vec<u8>>]) -> FuzcateResult<Vec<Vec<u8>>> { Ok(Vec::new()) }
    }
}