//! # Forward Error Correction (FEC) Module
//!
//! This consolidated module provides a comprehensive suite of Forward Error Correction
//! capabilities for the Fuzcate protocol. It includes various FEC algorithms, hardware
//! acceleration, adaptive strategies, and performance metrics, all within a single file
//! for a simplified project structure.

use std::sync::{Arc, Mutex};
use std::collections::HashMap;
use std::time::{Duration, Instant};
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock as AsyncRwLock;
use std::fmt;
use bytes::{Bytes, BytesMut};
use nalgebra::{DMatrix, DVector};
use rand::seq::SliceRandom;
use rand::{Rng, SeedableRng};
use std::collections::VecDeque;

use crate::core::{FuzcateError, FuzcateResult, ValidationError};
use crate::optimized::fec_compat::{CpuFeatures, HwDispatcher, HwPath};
use crate::optimized::cm256_impl as cm256_internal;

// ============================================================================
// SECTION: Network Monitoring & Adaptive Engine
// ============================================================================

/// A unique identifier for a connection.
/// In a real QUIC implementation, this would likely be derived from the connection's context.
pub type ConnectionId = u64;

/// Stores rolling statistics for network conditions.
#[derive(Debug, Clone)]
struct RollingStat {
    samples: VecDeque<f64>,
    window_size: usize,
    sum: f64,
}

impl RollingStat {
    fn new(window_size: usize) -> Self {
        Self {
            samples: VecDeque::with_capacity(window_size),
            window_size,
            sum: 0.0,
        }
    }

    fn add(&mut self, value: f64) {
        if self.samples.len() == self.window_size {
            self.sum -= self.samples.pop_front().unwrap_or(0.0);
        }
        self.samples.push_back(value);
        self.sum += value;
    }

    fn average(&self) -> f64 {
        if self.samples.is_empty() { 0.0 } else { self.sum / self.samples.len() as f64 }
    }

    fn variance(&self) -> f64 {
        if self.samples.len() < 2 { return 0.0; }
        let mean = self.average();
        self.samples.iter().map(|&s| (s - mean).powi(2)).sum::<f64>() / (self.samples.len() - 1) as f64
    }
    
    fn jitter(&self) -> f64 {
        self.variance().sqrt()
    }
}

/// Per-connection network statistics.
#[derive(Debug, Clone)]
pub struct ConnectionStats {
    rtt: RollingStat,
    jitter: RollingStat,
    packet_loss: RollingStat,
    last_rtt_micros: u64,
}

impl ConnectionStats {
    pub fn new(window_size: usize) -> Self {
        Self {
            rtt: RollingStat::new(window_size),
            jitter: RollingStat::new(window_size),
            packet_loss: RollingStat::new(window_size),
            last_rtt_micros: 0,
        }
    }
}

/// Monitors network conditions for multiple connections.
#[derive(Debug, Clone)]
pub struct NetworkMonitor {
    stats: Arc<AsyncRwLock<HashMap<ConnectionId, ConnectionStats>>>,
    window_size: usize,
}

impl NetworkMonitor {
    pub fn new(window_size: usize) -> Self {
        Self {
            stats: Arc::new(AsyncRwLock::new(HashMap::new())),
            window_size,
        }
    }

    pub async fn record_rtt(&self, conn_id: ConnectionId, rtt: Duration) {
        let mut stats_map = self.stats.write().await;
        let entry = stats_map.entry(conn_id).or_insert_with(|| ConnectionStats::new(self.window_size));
        let rtt_micros = rtt.as_micros() as u64;

        entry.rtt.add(rtt_micros as f64);
        
        if entry.last_rtt_micros > 0 {
            let jitter_micros = (rtt_micros as i64 - entry.last_rtt_micros as i64).abs() as f64;
            entry.jitter.add(jitter_micros);
        }
        entry.last_rtt_micros = rtt_micros;
    }

    pub async fn record_packet_loss(&self, conn_id: ConnectionId, loss_rate: f32) {
        let mut stats_map = self.stats.write().await;
        let entry = stats_map.entry(conn_id).or_insert_with(|| ConnectionStats::new(self.window_size));
        entry.packet_loss.add(loss_rate as f64);
    }
    
    pub async fn get_network_stats(&self, conn_id: ConnectionId) -> Option<NetworkStats> {
        let stats_map = self.stats.read().await;
        stats_map.get(&conn_id).map(|s| NetworkStats {
            packet_loss_rate: s.packet_loss.average() as f32,
            average_latency: Duration::from_micros(s.rtt.average() as u64),
            jitter: Duration::from_micros(s.jitter.jitter() as u64),
            // NOTE: Bandwidth is not measured by this monitor and would come from another system.
            // We use a placeholder value here.
            available_bandwidth: 50_000_000,
        })
    }
}

/// The core engine for making adaptive FEC decisions based on network conditions.
#[derive(Debug, Clone)]
pub struct AdaptiveFecEngine {
    monitor: NetworkMonitor,
    config: StrategyConfig,
}

impl AdaptiveFecEngine {
    pub fn new(config: StrategyConfig, monitor: NetworkMonitor) -> Self {
        Self { monitor, config }
    }

    /// Analyzes network conditions and determines the optimal FEC strategy.
    pub async fn determine_strategy(&self, conn_id: ConnectionId) -> FuzcateResult<FecConfig> {
        let stats = self.monitor.get_network_stats(conn_id).await
            .unwrap_or_else(|| NetworkStats::default());

        let (primary_algo, secondary_algo) = self.select_algorithms(&stats);
        let repair_ratio = self.adjust_redundancy(&stats);
        
        // The block size can also be made adaptive.
        let block_size = self.calculate_block_size(stats.average_latency, stats.available_bandwidth);

        // For now, we return a single configuration. The layered protection would be
        // handled by the caller, which could apply the primary and secondary algorithms.
        // We will select the primary algorithm for the main config.
        Ok(FecConfig {
            mode: FecMode::Adaptive,
            algorithm: primary_algo,
            block_size,
            repair_ratio,
            max_recovery_delay: Duration::from_millis((stats.average_latency.as_millis() * 2).max(50) as u64),
            strategy_config: self.config.clone(),
            metrics_config: MetricsConfig::default(),
            // A new field to inform the caller about the secondary choice.
            secondary_algorithm: secondary_algo,
        })
    }

    /// Selects primary and optional secondary FEC algorithms based on network stats.
    fn select_algorithms(&self, stats: &NetworkStats) -> (FecAlgorithm, Option<FecAlgorithm>) {
        let loss = stats.packet_loss_rate;
        let jitter = stats.jitter.as_millis();

        // Rule-based algorithm selection
        if loss > 0.15 || jitter > 50 { // High burst loss or high jitter
            (FecAlgorithm::LDPC, Some(FecAlgorithm::ReedSolomon)) // LDPC for burst, RS for extra safety
        } else if loss > 0.05 { // Moderate, random loss
            (FecAlgorithm::ReedSolomon, Some(FecAlgorithm::StripeXor))
        } else if loss > 0.01 { // Low loss
            (FecAlgorithm::StripeXor, None)
        } else { // Very low loss
            (FecAlgorithm::StripeXor, None) // Keep a lightweight option active
        }
    }

    /// Dynamically adjusts the redundancy rate based on packet loss.
    fn adjust_redundancy(&self, stats: &NetworkStats) -> f32 {
        // Increase redundancy more aggressively as loss increases.
        // Base redundancy + factor * loss^2
        let base_redundancy = 0.05; // 5% base
        let adaptive_redundancy = 1.5 * stats.packet_loss_rate;
        (base_redundancy + adaptive_redundancy).clamp(0.05, 0.75) // Clamp between 5% and 75%
    }
    
    /// Calculates an appropriate block size.
    fn calculate_block_size(&self, latency: Duration, bandwidth: u64) -> usize {
        let base = if latency.as_millis() < 50 { 32 } else { 16 };
        (if bandwidth > 10_000_000 { base * 2 } else { base }).clamp(8, 128)
    }
}

// ============================================================================
// SECTION: Core FEC Data Structures
// ============================================================================

/// FEC packet type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PacketType { Source, Repair }

/// FEC packet structure, optimized for zero-copy operations using Bytes.
#[derive(Debug, Clone)]
pub struct FecPacket {
    pub data: Bytes,
    pub packet_type: PacketType,
    pub index: u32,
    pub block_id: u32,
    pub source_count: u8,
    pub repair_count: u8,
    pub metadata: Vec<u8>,
}

/// Block of packets for FEC processing
#[derive(Debug, Clone)]
pub struct Block {
    pub id: u32,
    pub source_packets: Vec<Option<FecPacket>>,
    pub repair_packets: Vec<Option<FecPacket>>,
    pub algorithm: FecAlgorithm,
    pub hw_path: HwPath,
}

/// Common interface for all FEC algorithms
pub trait FecAlgorithmTrait: Send + Sync + std::fmt::Debug {
    fn algorithm_type(&self) -> FecAlgorithm;
    fn hw_path(&self) -> HwPath;
    fn encode(&self, block: &mut Block) -> FuzcateResult<()>;
    fn decode(&self, block: &mut Block) -> FuzcateResult<Vec<FecPacket>>;
    fn can_recover(&self, available_count: usize, source_count: usize) -> bool;
    fn optimal_repair_count(&self, source_count: usize, loss_rate: f32) -> usize;
}

// ============================================================================
// SECTION: FEC Algorithm Implementations
// ============================================================================

// ----------------------------------------------------------------------------
// SUB-SECTION: Galois Field Arithmetic (from rs_galois.rs)
// ----------------------------------------------------------------------------

/// Represents the Galois Field GF(2^8).
#[derive(Debug, Clone)]
pub struct GaloisField {
    gf_log: [u8; 256],
    gf_exp: [u8; 512],
}

impl GaloisField {
    /// Creates a new instance of the Galois Field and initializes the lookup tables.
    pub fn new() -> Self {
        let mut gf = Self {
            gf_log: [0; 256],
            gf_exp: [0; 512],
        };
        gf.init_tables();
        gf
    }

    /// Initializes the logarithm and exponential lookup tables.
    fn init_tables(&mut self) {
        const PRIMITIVE_POLY: u16 = 0x11D;
        let mut x = 1u16;

        for i in 0..255 {
            self.gf_exp[i] = x as u8;
            self.gf_log[x as usize] = i as u8;
            x <<= 1;
            if x & 0x100 != 0 {
                x ^= PRIMITIVE_POLY;
            }
        }

        for i in 255..512 {
            self.gf_exp[i] = self.gf_exp[i - 255];
        }

        self.gf_log[0] = 0;
    }

    #[inline]
    pub fn mul(&self, a: u8, b: u8) -> u8 {
        if a == 0 || b == 0 { return 0; }
        let log_a = self.gf_log[a as usize] as usize;
        let log_b = self.gf_log[b as usize] as usize;
        self.gf_exp[log_a + log_b]
    }

    #[inline]
    pub fn div(&self, a: u8, b: u8) -> FuzcateResult<u8> {
        if b == 0 { return Err(FuzcateError::Fec("Division by zero".to_string())); }
        if a == 0 { return Ok(0); }
        let log_a = self.gf_log[a as usize] as usize;
        let log_b = self.gf_log[b as usize] as usize;
        Ok(self.gf_exp[log_a + 255 - log_b])
    }

    #[inline]
    pub fn pow(&self, base: u8, exp: u8) -> u8 {
        if base == 0 { return 0; }
        let log_base = self.gf_log[base as usize] as usize;
        let result_log = (log_base * exp as usize) % 255;
        self.gf_exp[result_log]
    }

    #[inline]
    pub fn inv(&self, a: u8) -> FuzcateResult<u8> {
        if a == 0 { return Err(FuzcateError::Fec("Cannot invert zero".to_string())); }
        Ok(self.gf_exp[255 - self.gf_log[a as usize] as usize])
    }
}

impl Default for GaloisField {
    fn default() -> Self { Self::new() }
}

// ----------------------------------------------------------------------------
// SUB-SECTION: Reed-Solomon (from reed_solomon.rs)
// ----------------------------------------------------------------------------

type InverseMatrixCache = Arc<Mutex<HashMap<Vec<bool>, Vec<Vec<u8>>>>>;

#[derive(Debug)]
pub struct ReedSolomon {
    hw_path: HwPath,
    data_shards: usize,
    parity_shards: usize,
    total_shards: usize,
    generator_matrix: Vec<Vec<u8>>,
    inverse_matrix_cache: InverseMatrixCache,
    gf: GaloisField,
}

impl ReedSolomon {
    pub fn new(hw_path: HwPath) -> FuzcateResult<Self> {
        Self::new_with_config(hw_path, 10, 4)
    }

    pub fn new_with_config(hw_path: HwPath, data_shards: usize, parity_shards: usize) -> FuzcateResult<Self> {
        if data_shards == 0 || parity_shards == 0 { return Err(FuzcateError::Fec("Invalid configuration: data_shards or parity_shards cannot be zero".to_string())); }
        let total_shards = data_shards + parity_shards;
        if total_shards > 256 { return Err(FuzcateError::Fec("Invalid configuration: total_shards cannot be greater than 256".to_string())); }

        let mut rs = Self {
            hw_path, data_shards, parity_shards, total_shards,
            generator_matrix: Vec::new(),
            inverse_matrix_cache: Arc::new(Mutex::new(HashMap::new())),
            gf: GaloisField::new(),
        };

        rs.build_generator_matrix();
        Ok(rs)
    }

    fn build_generator_matrix(&mut self) {
        let mut matrix = vec![vec![0u8; self.data_shards]; self.total_shards];
        for i in 0..self.data_shards { matrix[i][i] = 1; }
        for i in 0..self.parity_shards {
            for j in 0..self.data_shards {
                matrix[self.data_shards + i][j] = self.gf.pow(j as u8, i as u8);
            }
        }
        self.generator_matrix = matrix;
    }

    fn matrix_multiply(&self, matrix: &[Vec<u8>], data: &[Vec<u8>]) -> Vec<Vec<u8>> {
        let rows = matrix.len();
        if data.is_empty() || data[0].is_empty() {
            return vec![vec![0u8; 0]; rows];
        }
        let cols = data[0].len();
        let inner = data.len();
        let mut result = vec![vec![0u8; cols]; rows];

        // Choose the best implementation based on runtime CPU features
        #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
        {
            if is_x86_feature_detected!("avx2") {
                 unsafe { self.matrix_multiply_avx2(&mut result, matrix, data) };
                 return result;
            }
            if is_x86_feature_detected!("sse2") {
                 unsafe { self.matrix_multiply_sse2(&mut result, matrix, data) };
                 return result;
            }
        }
        
        // Fallback to scalar implementation
        self.matrix_multiply_scalar(&mut result, matrix, data);
        result
    }

    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    #[target_feature(enable = "sse2")]
    unsafe fn matrix_multiply_sse2(&self, result: &mut [Vec<u8>], matrix: &[Vec<u8>], data: &[Vec<u8>]) {
        use std::arch::x86_64::*;

        let rows = matrix.len();
        let cols = data[0].len();
        let inner = data.len();

        for i in 0..rows {
            for j in (0..cols).step_by(16) {
                let mut sum_vec = _mm_setzero_si128();
                for k in 0..inner {
                    let matrix_val = matrix[i][k];
                    if matrix_val == 0 { continue; }
                    
                    let data_ptr = data[k].as_ptr().add(j);
                    let data_vec = _mm_loadu_si128(data_ptr as *const _);
                    
                    let log_m_val = self.gf.gf_log[matrix_val as usize];
                    let mul_table: [u8; 16] = std::array::from_fn(|idx| {
                        let data_byte = *data_ptr.add(idx);
                        if data_byte == 0 { return 0; }
                        let log_sum = self.gf.gf_log[data_byte as usize] as u16 + log_m_val as u16;
                        self.gf.gf_exp[log_sum as usize]
                    });

                    let mul_vec = _mm_loadu_si128(mul_table.as_ptr() as *const _);
                    sum_vec = _mm_xor_si128(sum_vec, mul_vec);
                }
                _mm_storeu_si128(result[i].as_mut_ptr().add(j) as *mut _, sum_vec);
            }
        }
    }

    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    #[target_feature(enable = "avx2")]
    unsafe fn matrix_multiply_avx2(&self, result: &mut [Vec<u8>], matrix: &[Vec<u8>], data: &[Vec<u8>]) {
        // NOTE: A full AVX2 implementation would be more complex and might involve
        // gather instructions for the lookups, which can have their own performance
        // characteristics. For now, we provide a placeholder and could fall back
        // to the SSE2 version or a scalar version if AVX2 doesn't provide a clear benefit
        // without a more advanced implementation (e.g., using `vpgatherdd`).
        // For the purpose of this optimization, we delegate to the SSE2 version,
        // as it's a safe and significant step up from scalar.
        self.matrix_multiply_sse2(result, matrix, data);
    }

    fn matrix_multiply_scalar(&self, result: &mut [Vec<u8>], matrix: &[Vec<u8>], data: &[Vec<u8>]) {
        let rows = matrix.len();
        let cols = data[0].len();
        let inner = data.len();

        for i in 0..rows {
            for j in 0..cols {
                let mut sum = 0u8;
                for k in 0..inner {
                    sum ^= self.gf.mul(matrix[i][k], data[k][j]);
                }
                result[i][j] = sum;
            }
        }
    }

    fn invert_matrix(&self, matrix: &[Vec<u8>]) -> FuzcateResult<Vec<Vec<u8>>> {
        let n = matrix.len();
        let mut augmented = vec![vec![0u8; 2 * n]; n];

        for i in 0..n {
            for j in 0..n { augmented[i][j] = matrix[i][j]; }
            augmented[i][i + n] = 1;
        }

        for i in 0..n {
            let mut pivot_row = i;
            while pivot_row < n && augmented[pivot_row][i] == 0 { pivot_row += 1; }
            if pivot_row == n { return Err(FuzcateError::Fec("Cannot invert matrix".to_string())); }
            augmented.swap(i, pivot_row);

            let inv_pivot = self.gf.inv(augmented[i][i])?;
            for j in i..2 * n { augmented[i][j] = self.gf.mul(augmented[i][j], inv_pivot); }

            for row in 0..n {
                if row != i {
                    let factor = augmented[row][i];
                    for j in i..2 * n { augmented[row][j] ^= self.gf.mul(factor, augmented[i][j]); }
                }
            }
        }

        let mut inverse = vec![vec![0u8; n]; n];
        for i in 0..n {
            for j in 0..n { inverse[i][j] = augmented[i][j + n]; }
        }
        Ok(inverse)
    }

    fn get_decode_matrix(&self, present: &[bool]) -> FuzcateResult<Vec<Vec<u8>>> {
        let cache_key = present.to_vec();
        let mut cache = self.inverse_matrix_cache.lock().map_err(|_| FuzcateError::InvalidState("FEC inverse matrix cache poisoned".to_string()))?;
        if let Some(matrix) = cache.get(&cache_key) {
            return Ok(matrix.clone());
        }

        let mut sub_matrix = Vec::with_capacity(self.data_shards);
        for i in 0..self.total_shards {
            if present[i] {
                sub_matrix.push(self.generator_matrix[i].clone());
                if sub_matrix.len() == self.data_shards { break; }
            }
        }

        if sub_matrix.len() < self.data_shards { return Err(FuzcateError::Fec("Insufficient data for recovery".to_string())); }

        let inverse = self.invert_matrix(&sub_matrix)?;
        cache.insert(cache_key, inverse.clone());
        Ok(inverse)
    }
}

impl FecAlgorithmTrait for ReedSolomon {
    fn algorithm_type(&self) -> FecAlgorithm { FecAlgorithm::ReedSolomon }
    fn hw_path(&self) -> HwPath { self.hw_path }

    fn encode(&self, block: &mut Block) -> FuzcateResult<()> {
        let source_count = block.source_packets.iter().filter_map(Option::as_ref).count();
        if source_count == 0 { return Ok(()); }

        let max_len = block.source_packets.iter().filter_map(|p| p.as_ref()).map(|p| p.data.len()).max().unwrap_or(0);
        
        // TODO: This section performs copies (`.to_vec()`) and should be optimized later to use slices directly.
        let mut data_shards: Vec<Vec<u8>> = block.source_packets.iter().filter_map(|p| p.as_ref()).map(|p| {
            let mut data = p.data.to_vec();
            data.resize(max_len, 0);
            data
        }).collect();
        
        while data_shards.len() < self.data_shards { data_shards.push(vec![0u8; max_len]); }

        let all_shards = self.matrix_multiply(&self.generator_matrix, &data_shards);

        for i in 0..self.parity_shards {
            if let Some(Some(repair_packet)) = block.repair_packets.get_mut(i) {
                 repair_packet.data = Bytes::from(all_shards[self.data_shards + i].clone());
            }
        }
        Ok(())
    }

    fn decode(&self, block: &mut Block) -> FuzcateResult<Vec<FecPacket>> {
        let present: Vec<bool> = block.source_packets.iter().chain(block.repair_packets.iter()).map(|p| p.is_some()).collect();
        let decode_matrix = self.get_decode_matrix(&present)?;
        let max_len = block.source_packets.iter().chain(block.repair_packets.iter()).filter_map(|p| p.as_ref()).map(|p| p.data.len()).max().unwrap_or(0);

        // TODO: This section performs copies (`.to_vec()`) and should be optimized later to use slices directly.
        let mut available_shards: Vec<Vec<u8>> = block.source_packets.iter().chain(block.repair_packets.iter()).filter_map(|p| p.as_ref()).map(|p| {
            let mut data = p.data.to_vec();
            data.resize(max_len, 0);
            data
        }).take(self.data_shards).collect();

        if available_shards.len() < self.data_shards { return Err(FuzcateError::Fec("Insufficient data for recovery".to_string())); }

        let recovered_data_shards = self.matrix_multiply(&decode_matrix, &available_shards);
        let mut recovered_packets = Vec::new();

        for i in 0..self.data_shards {
            if block.source_packets[i].is_none() {
                let packet_data = recovered_data_shards[i].clone();
                let new_packet = FecPacket {
                    data: Bytes::from(packet_data), packet_type: PacketType::Source, index: i as u32,
                    block_id: block.id, source_count: block.source_packets.len() as u8,
                    repair_count: block.repair_packets.len() as u8, metadata: Vec::new(),
                };
                block.source_packets[i] = Some(new_packet.clone());
                recovered_packets.push(new_packet);
            }
        }
        Ok(recovered_packets)
    }

    fn can_recover(&self, available_count: usize, source_count: usize) -> bool { available_count >= source_count }
    fn optimal_repair_count(&self, source_count: usize, loss_rate: f32) -> usize { (source_count as f32 * loss_rate * 1.2).ceil() as usize }
}

// ----------------------------------------------------------------------------
// SUB-SECTION: CM256 (from cm256.rs)
// ----------------------------------------------------------------------------

#[derive(Debug)]
pub struct CM256 {
    hw_path: HwPath,
    cm256_impl: cm256_internal::CM256,
}

impl CM256 {
    pub fn new(hw_path: HwPath) -> FuzcateResult<Self> {
        Ok(Self {
            hw_path,
            cm256_impl: cm256_internal::CM256::new(10, 4, hw_path).map_err(|e| FuzcateError::Fec(e.to_string()))?,
        })
    }
}

impl FecAlgorithmTrait for CM256 {
    fn algorithm_type(&self) -> FecAlgorithm { FecAlgorithm::CM256 }
    fn hw_path(&self) -> HwPath { self.hw_path }

    fn encode(&self, block: &mut Block) -> FuzcateResult<()> {
        let source_packets: Vec<_> = block.source_packets.iter().filter_map(Option::as_ref).collect();
        if source_packets.is_empty() { return Ok(()); }
        let k = source_packets.len();
        let m = block.repair_packets.len();
        if k == 0 || m == 0 { return Err(FuzcateError::Fec("Invalid block configuration for CM256 encoding".to_string())); }
        let max_len = source_packets.iter().map(|p| p.data.len()).max().unwrap_or(0);
        // TODO: This section performs copies (`.to_vec()`) and should be optimized later to use slices directly.
        let mut shards: Vec<Vec<u8>> = source_packets.iter().map(|p| {
            let mut data = p.data.to_vec();
            data.resize(max_len, 0);
            data
        }).collect();
        let repair_shards = self.cm256_impl.encode(&shards).map_err(|e| FuzcateError::Fec(e.to_string()))?;
        for (i, repair_data) in repair_shards.into_iter().enumerate() {
            if let Some(Some(repair_packet)) = block.repair_packets.get_mut(i) {
                repair_packet.data = Bytes::from(repair_data);
            }
        }
        Ok(())
    }

    fn decode(&self, block: &mut Block) -> FuzcateResult<Vec<FecPacket>> {
        let k = block.source_packets.len();
        let m = block.repair_packets.len();
        let mut shards: Vec<Option<Vec<u8>>> = Vec::with_capacity(k + m);
        let max_len = block.source_packets.iter().chain(block.repair_packets.iter()).filter_map(|p| p.as_ref()).map(|p| p.data.len()).max().unwrap_or(0);

        for p in block.source_packets.iter() {
            shards.push(p.as_ref().map(|pkt| {
                let mut data = pkt.data.to_vec();
                data.resize(max_len, 0);
                data
            }));
        }
        for p in block.repair_packets.iter() {
            shards.push(p.as_ref().map(|pkt| {
                let mut data = pkt.data.to_vec();
                data.resize(max_len, 0);
                data
            }));
        }

        let recovered_shards = self.cm256_impl.decode(&shards).map_err(|e| FuzcateError::Fec(e.to_string()))?;
        let mut recovered_packets = Vec::new();
        for (i, data) in recovered_shards.into_iter().enumerate() {
             if block.source_packets[i].is_none() {
                let new_packet = FecPacket {
                    data: Bytes::from(data), packet_type: PacketType::Source, index: i as u32,
                    block_id: block.id, source_count: k as u8,
                    repair_count: m as u8, metadata: Vec::new(),
                };
                block.source_packets[i] = Some(new_packet.clone());
                recovered_packets.push(new_packet);
             }
        }
        Ok(recovered_packets)
    }

    fn can_recover(&self, available_count: usize, source_count: usize) -> bool { available_count >= source_count }
    fn optimal_repair_count(&self, source_count: usize, loss_rate: f32) -> usize { (source_count as f32 * loss_rate * 1.1).ceil() as usize }
}

// ----------------------------------------------------------------------------
// SUB-SECTION: Sparse RLNC (from sparse_rlnc.rs)
// ----------------------------------------------------------------------------
mod sparse_rlnc_impl {
    use super::{Block, FecPacket, PacketType};
    use crate::core::{FuzcateError, FuzcateResult};
    use crate::optimized::simd_ops;
    use bytes::{Bytes, BytesMut};
    use rand::{seq::SliceRandom, thread_rng};
    use std::collections::{HashMap, VecDeque};

    #[derive(Debug, Clone)]
    struct Equation {
        repair_packet_idx: usize,
        coefficients: Vec<usize>, // Indices of source packets
        is_decoded: bool,
    }

    /// Encodes repair packets using sparse, random linear combinations of source packets.
    pub fn encode(block: &mut Block, density: usize) -> FuzcateResult<()> {
        let source_packets: Vec<_> = block.source_packets.iter().filter_map(Option::as_ref).collect();
        if source_packets.is_empty() {
            return Ok(());
        }

        let source_count = source_packets.len();
        let repair_count = block.repair_packets.len();
        let max_len = source_packets.iter().map(|p| p.data.len()).max().unwrap_or(0);
        let mut rng = thread_rng();
        let source_indices: Vec<usize> = (0..source_count).collect();

        for i in 0..repair_count {
            let num_coeffs = (density.min(source_count)).max(1);
            let coefficients: Vec<usize> = source_indices.choose_multiple(&mut rng, num_coeffs).cloned().collect();

            if coefficients.is_empty() {
                continue;
            }

            let mut repair_data = BytesMut::with_capacity(max_len);
            repair_data.resize(max_len, 0);

            for &coeff_idx in &coefficients {
                if let Some(Some(source_packet)) = block.source_packets.get(coeff_idx) {
                    simd_ops::xor_optimized(&mut repair_data, &source_packet.data);
                }
            }

            if let Some(Some(repair_packet)) = block.repair_packets.get_mut(i) {
                repair_packet.data = repair_data.freeze();
                // Metadata: [coeff_count, coeff1, coeff2, ...]
                repair_packet.metadata = std::iter::once(coefficients.len() as u8)
                    .chain(coefficients.iter().map(|&c| c as u8))
                    .collect();
            }
        }
        Ok(())
    }

    /// Decodes using a Peeling Decoder algorithm.
    pub fn decode(block: &mut Block) -> FuzcateResult<Vec<FecPacket>> {
        let source_count = block.source_packets.len();
        let mut recovered_packets = Vec::new();

        let mut equations: Vec<Equation> = block.repair_packets.iter().enumerate()
            .filter_map(|(idx, p)| p.as_ref().map(|pkt| (idx, pkt)))
            .map(|(idx, pkt)| {
                let coeff_count = pkt.metadata.get(0).copied().unwrap_or(0) as usize;
                let coefficients = pkt.metadata.iter().skip(1).take(coeff_count).map(|&c| c as usize).collect();
                Equation { repair_packet_idx: idx, coefficients, is_decoded: false }
            })
            .collect();

        let mut source_decoded: Vec<bool> = block.source_packets.iter().map(|p| p.is_some()).collect();
        let mut decoding_queue: VecDeque<usize> = VecDeque::new();

        // Initial queue population
        for (eq_idx, eq) in equations.iter().enumerate() {
            let unknown_count = eq.coefficients.iter().filter(|&&src_idx| !source_decoded[src_idx]).count();
            if unknown_count == 1 {
                decoding_queue.push_back(eq_idx);
            }
        }

        while let Some(eq_idx) = decoding_queue.pop_front() {
            if equations[eq_idx].is_decoded { continue; }

            let eq = &equations[eq_idx];
            let unknown_source_idx = match eq.coefficients.iter().find(|&&src_idx| !source_decoded[src_idx]) {
                Some(&idx) => idx,
                None => continue, // Already solved
            };

            let repair_packet = block.repair_packets[eq.repair_packet_idx].as_ref().unwrap();
            let max_len = repair_packet.data.len();
            let mut recovered_data = BytesMut::with_capacity(max_len);
            recovered_data.resize(max_len, 0);
            simd_ops::xor_optimized(&mut recovered_data, &repair_packet.data);

            for &known_source_idx in eq.coefficients.iter() {
                if known_source_idx != unknown_source_idx {
                    if let Some(Some(p)) = block.source_packets.get(known_source_idx) {
                         simd_ops::xor_optimized(&mut recovered_data, &p.data);
                    }
                }
            }

            let new_packet = FecPacket {
                data: recovered_data.freeze(), packet_type: PacketType::Source, index: unknown_source_idx as u32,
                block_id: block.id, source_count: source_count as u8,
                repair_count: block.repair_packets.len() as u8, metadata: Vec::new(),
            };
            
            block.source_packets[unknown_source_idx] = Some(new_packet.clone());
            recovered_packets.push(new_packet);
            source_decoded[unknown_source_idx] = true;
            equations[eq_idx].is_decoded = true;

            // Update other equations
            for (next_eq_idx, next_eq) in equations.iter_mut().enumerate() {
                if !next_eq.is_decoded && next_eq.coefficients.contains(&unknown_source_idx) {
                    let unknown_count = next_eq.coefficients.iter().filter(|&&src_idx| !source_decoded[src_idx]).count();
                    if unknown_count == 1 {
                        decoding_queue.push_back(next_eq_idx);
                    }
                }
            }
        }

        if recovered_packets.is_empty() && block.source_packets.iter().any(|p| p.is_none()) {
            return Err(FuzcateError::Fec("Insufficient data for SparseRLNC recovery".to_string()));
        }

        Ok(recovered_packets)
    }
}

#[derive(Debug)]
pub struct SparseRlnc {
    hw_path: HwPath,
    density: usize,
}

impl SparseRlnc {
    pub fn new(hw_path: HwPath) -> Self { Self { hw_path, density: 4 } }
}

impl FecAlgorithmTrait for SparseRlnc {
    fn algorithm_type(&self) -> FecAlgorithm { FecAlgorithm::SparseRlnc }
    fn hw_path(&self) -> HwPath { self.hw_path }

    fn encode(&self, block: &mut Block) -> FuzcateResult<()> {
        sparse_rlnc_impl::encode(block, self.density)
    }

    fn decode(&self, block: &mut Block) -> FuzcateResult<Vec<FecPacket>> {
        sparse_rlnc_impl::decode(block)
    }

    fn can_recover(&self, available_count: usize, source_count: usize) -> bool {
        // This is an optimistic check. Actual recovery depends on the specific combinations.
        // A better heuristic might require `available_count >= source_count + some_overhead`.
        available_count >= source_count
    }
    
    fn optimal_repair_count(&self, source_count: usize, loss_rate: f32) -> usize {
        // RLNC codes often need a slight overhead compared to the loss rate.
        let required_packets = (source_count as f32 * (loss_rate + 0.05)).ceil() as usize;
        required_packets.max(1).min(source_count * 2)
    }
}

// ----------------------------------------------------------------------------
// SUB-SECTION: Stripe-XOR (from stripe_xor.rs)
// ----------------------------------------------------------------------------

#[derive(Debug)]
pub struct StripeXor { hw_path: HwPath }

impl StripeXor {
    pub fn new(hw_path: HwPath) -> Self { Self { hw_path } }
    fn xor_slices(&self, dst: &mut [u8], src: &[u8]) {
        let len = std::cmp::min(dst.len(), src.len());
        crate::optimized::simd_ops::xor_optimized(&mut dst[..len], &src[..len]);
    }
    fn generate_permutation(&self, len: usize) -> Vec<usize> {
        const INTERLEAVE_SEED: u64 = 0x_DEAD_BEEF_CAFE_BABE;
        let mut rng = rand::rngs::StdRng::seed_from_u64(INTERLEAVE_SEED);
        let mut permutation: Vec<usize> = (0..len).collect();
        permutation.shuffle(&mut rng);
        permutation
    }
    fn interleave(&self, data: &[u8]) -> Vec<u8> {
        let len = data.len();
        if len == 0 { return Vec::new(); }
        let permutation = self.generate_permutation(len);
        let mut interleaved_data = vec![0u8; len];
        for (i, &p) in permutation.iter().enumerate() {
            if p < len { interleaved_data[i] = data[p]; }
        }
        interleaved_data
    }
    fn deinterleave(&self, data: &[u8]) -> Vec<u8> {
        let len = data.len();
        if len == 0 { return Vec::new(); }
        let permutation = self.generate_permutation(len);
        let mut deinterleaved_data = vec![0u8; len];
        for (i, &p) in permutation.iter().enumerate() {
            if i < len { deinterleaved_data[p] = data[i]; }
        }
        deinterleaved_data
    }
}

impl FecAlgorithmTrait for StripeXor {
    fn algorithm_type(&self) -> FecAlgorithm { FecAlgorithm::StripeXor }
    fn hw_path(&self) -> HwPath { self.hw_path }
    fn encode(&self, block: &mut Block) -> FuzcateResult<()> {
        let source_count = block.source_packets.len();
        let repair_count = block.repair_packets.len();
        if source_count == 0 || repair_count == 0 { return Err(FuzcateError::Fec("Invalid block configuration for StripeXor encoding".to_string())); }
        let max_size = block.source_packets.iter().filter_map(|p| p.as_ref()).map(|p| p.data.len()).max().ok_or(FuzcateError::Fec("Could not determine max size of source packets".to_string()))?;
        
        for r in 0..repair_count {
            let mut repair_data = BytesMut::with_capacity(max_size);
            repair_data.resize(max_size, 0);
            let mut packets_used = 0;
            for s in 0..source_count {
                if (s % repair_count) == r {
                    if let Some(ref source_packet) = block.source_packets[s] {
                        let interleaved_data = self.interleave(&source_packet.data);
                        self.xor_slices(&mut repair_data, &interleaved_data);
                        packets_used += 1;
                    }
                }
            }
            let mut metadata = Vec::new();
            metadata.push(packets_used as u8);
            for s in 0..source_count {
                if (s % repair_count) == r { metadata.push(s as u8); }
            }
            let repair_packet = FecPacket {
                data: repair_data.freeze(), packet_type: PacketType::Repair, index: r as u32,
                block_id: block.id, source_count: source_count as u8,
                repair_count: repair_count as u8, metadata,
            };
            block.repair_packets[r] = Some(repair_packet);
        }
        Ok(())
    }
    fn decode(&self, block: &mut Block) -> FuzcateResult<Vec<FecPacket>> {
        let source_count = block.source_packets.len();
        let repair_count = block.repair_packets.len();
        if source_count == 0 || repair_count == 0 { return Err(FuzcateError::Fec("Invalid block configuration for StripeXor decoding".to_string())); }
        
        let missing_indices: Vec<usize> = block.source_packets.iter().enumerate().filter(|(_, p)| p.is_none()).map(|(i, _)| i).collect();
        if missing_indices.is_empty() { return Ok(Vec::new()); }
        
        let mut recovered_packets = Vec::new();
        for &missing_idx in &missing_indices {
            let repair_idx = missing_idx % repair_count;
            if let Some(ref repair_packet) = block.repair_packets[repair_idx] {
                let packets_used = repair_packet.metadata[0] as usize;
                let mut stripe_indices = Vec::new();
                for i in 1..=packets_used {
                    if i < repair_packet.metadata.len() { stripe_indices.push(repair_packet.metadata[i] as usize); }
                }
                
                let mut can_recover = true;
                for &idx in &stripe_indices {
                    if idx != missing_idx && block.source_packets[idx].is_none() {
                        can_recover = false;
                        break;
                    }
                }
                
                if can_recover {
                    // This involves a copy to make the repair data mutable.
                    // This is a point for future optimization if a mutable buffer pool is introduced.
                    let mut recovered_data = repair_packet.data.to_vec();
                    for &idx in &stripe_indices {
                        if idx != missing_idx {
                            if let Some(ref source_packet) = block.source_packets[idx] {
                                let interleaved_data = self.interleave(&source_packet.data);
                                self.xor_slices(&mut recovered_data, &interleaved_data);
                            }
                        }
                    }
                    let deinterleaved_data = self.deinterleave(&recovered_data);
                    let recovered_packet = FecPacket {
                        data: Bytes::from(deinterleaved_data), packet_type: PacketType::Source, index: missing_idx as u32,
                        block_id: block.id, source_count: source_count as u8,
                        repair_count: repair_count as u8, metadata: Vec::new(),
                    };
                    recovered_packets.push(recovered_packet.clone());
                    block.source_packets[missing_idx] = Some(recovered_packet);
                }
            }
        }
        if recovered_packets.is_empty() && !missing_indices.is_empty() { return Err(FuzcateError::Fec("Insufficient data for StripeXor recovery".to_string())); }
        Ok(recovered_packets)
    }
    fn can_recover(&self, available_count: usize, source_count: usize) -> bool { available_count >= source_count }
    fn optimal_repair_count(&self, source_count: usize, loss_rate: f32) -> usize {
        let repair_count = (source_count as f32 * loss_rate * 1.5).ceil() as usize;
        repair_count.max(1).min(source_count)
    }
}

// ----------------------------------------------------------------------------
// SUB-SECTION: LDPC (from ldpc.rs)
// ----------------------------------------------------------------------------

const DEFAULT_MAX_ITERATIONS: usize = 20;

#[derive(Debug)]
pub struct Ldpc {
    hw_path: HwPath,
    h_matrix: DMatrix<u8>,
    g_matrix: DMatrix<u8>, // Generator matrix for systematic encoding
    n: usize,
    k: usize,
    max_iterations: usize,
}

impl Ldpc {
    pub fn new(hw_path: HwPath, n: usize, k: usize, weight_col: usize) -> FuzcateResult<Self> {
        let m = n - k;
        let (h_matrix, g_matrix) = Self::generate_systematic_gallager_matrices(m, n, weight_col)?;
        Ok(Self { hw_path, h_matrix, g_matrix, n, k, max_iterations: DEFAULT_MAX_ITERATIONS })
    }

    /// Generates a systematic parity-check matrix H = [A | I] and corresponding generator matrix G = [A^T | I]
    fn generate_systematic_gallager_matrices(m: usize, n: usize, weight_col: usize) -> FuzcateResult<(DMatrix<u8>, DMatrix<u8>)> {
        if n <= m { return Err(FuzcateError::Config("LDPC n must be greater than m".to_string())); }
        let k = n - m;
        let mut rng = rand::thread_rng();
        
        // This is a simplified construction. A robust one would ensure no cycles of length 4.
        let mut a_matrix = DMatrix::zeros(m, k);
        for j in 0..k {
            let mut row_indices: Vec<usize> = (0..m).collect();
            row_indices.shuffle(&mut rng);
            for i in 0..weight_col {
                a_matrix[(row_indices[i], j)] = 1;
            }
        }

        let mut h_matrix = DMatrix::zeros(m, n);
        h_matrix.view_mut((0, 0), (m, k)).copy_from(&a_matrix);
        h_matrix.view_mut((0, k), (m, m)).fill_diagonal(1);

        let mut g_matrix = DMatrix::zeros(k, n);
        g_matrix.view_mut((0,0), (k,k)).fill_diagonal(1);
        g_matrix.view_mut((0,k), (k,m)).copy_from(&a_matrix.transpose());

        Ok((h_matrix, g_matrix))
    }

    /// XORs two byte slices using SIMD if available.
    fn xor_slices(dst: &mut [u8], src: &[u8]) {
        let len = std::cmp::min(dst.len(), src.len());
        crate::optimized::simd_ops::xor_optimized(&mut dst[..len], &src[..len]);
    }
}

impl FecAlgorithmTrait for Ldpc {
    fn algorithm_type(&self) -> FecAlgorithm { FecAlgorithm::LDPC }
    fn hw_path(&self) -> HwPath { self.hw_path }

    fn encode(&self, block: &mut Block) -> FuzcateResult<()> {
        let source_count = block.source_packets.len();
        if source_count == 0 { return Ok(()); }
        if source_count > self.k { return Err(FuzcateError::Fec(format!("LDPC encoder configured for k={} source packets, but got {}", self.k, source_count))); }

        let max_len = block.source_packets.iter().filter_map(|p| p.as_ref()).map(|p| p.data.len()).max().unwrap_or(0);
        if max_len == 0 { return Ok(()); }

        // The number of repair packets is fixed by the code parameters (m = n - k)
        let repair_count = self.n - self.k;
        if block.repair_packets.len() < repair_count {
            return Err(FuzcateError::Fec(format!("Insufficient repair packet slots for LDPC code. Need {}, have {}", repair_count, block.repair_packets.len())));
        }

        // Convert source packets to bit-vectors for each byte position
        for byte_idx in 0..max_len {
            let mut source_bits = DVector::<u8>::zeros(self.k);
            for i in 0..source_count {
                if let Some(Some(p)) = block.source_packets.get(i) {
                     if let Some(byte) = p.data.get(byte_idx) {
                        for bit_idx in 0..8 {
                            if (byte >> bit_idx) & 1 == 1 {
                                // This is inefficient. A real implementation would operate on bit-packed data.
                                // For now, we simulate it. This part needs significant optimization.
                                source_bits[i] = 1; // Simplified: should be per-bit
                            }
                        }
                    }
                }
            }

            // This is a placeholder for proper bit-level encoding.
            // A real implementation would not do this matrix multiplication per byte.
            let codeword_bits = &self.g_matrix.transpose() * &source_bits;
            let parity_bits = codeword_bits.rows(self.k, self.n - self.k);

            for i in 0..repair_count {
                if let Some(Some(repair_packet)) = block.repair_packets.get_mut(i) {
                    if repair_packet.data.len() < max_len {
                        // This is also a placeholder. Data should be pre-allocated.
                        let mut new_data = BytesMut::with_capacity(max_len);
                        new_data.resize(max_len, 0);
                        new_data[..repair_packet.data.len()].copy_from_slice(&repair_packet.data);
                        repair_packet.data = new_data.freeze();
                    }

                    // Again, simplified logic. This should set the specific bit.
                    if parity_bits[i] % 2 == 1 {
                        // A mock XOR operation for the placeholder logic
                        if let Some(byte) = repair_packet.data.get(byte_idx) {
                             // This is not a real implementation, just a stub to be replaced.
                        }
                    }
                }
            }
        }
        // The above loop is a conceptual placeholder. A performant implementation is complex.
        // For now, we fall back to a simple XOR scheme to have a working placeholder.
        let mut xor_repair = BytesMut::with_capacity(max_len);
        xor_repair.resize(max_len, 0);
        for source_packet in block.source_packets.iter().flatten() {
             Self::xor_slices(&mut xor_repair, &source_packet.data);
        }
        for i in 0..repair_count {
            if let Some(Some(p)) = block.repair_packets.get_mut(i) {
                p.data = Bytes::from(xor_repair.clone());
            }
        }

        Ok(())
    }

    fn decode(&self, block: &mut Block) -> FuzcateResult<Vec<FecPacket>> {
        // NOTE: The Belief Propagation decoder is highly complex to implement correctly
        // and performantly in this context. The logic below is a *conceptual sketch*
        // and is not a fully functional or optimized decoder. It demonstrates the
        // algorithm's structure but omits critical details like byte-to-bit conversion,
        // efficient LLR storage, and SIMD optimizations for the updates.
        
        let missing_indices: Vec<usize> = block.source_packets.iter().enumerate().filter(|(_, p)| p.is_none()).map(|(i, _)| i).collect();
        if missing_indices.is_empty() { return Ok(Vec::new()); }

        // This is a major simplification. In reality, we must decode each byte position's bits.
        // We would need to run this entire decode logic for each byte index across all packets.
        // LLR values would be stored for each bit of each packet.
        let mut llr = DVector::from_fn(self.n, |i, _| {
            if i < self.k && block.source_packets[i].is_some() { 10.0 } // Strong belief in received source
            else if i >= self.k && block.repair_packets[i - self.k].is_some() { 10.0 } // Strong belief in received repair
            else { 0.1 } // Weak belief in lost packets
        });

        for _iter in 0..self.max_iterations {
            // Message passing simulation
            let mut check_to_var = DMatrix::zeros(self.h_matrix.nrows(), self.h_matrix.ncols());
            
            // 1. Variable-to-Check messages (simplified)
            // In a real implementation, this is a matrix of messages, not a single vector.
            let var_to_check_sum = &self.h_matrix.transpose() * &llr;

            // 2. Check-to-Variable messages
            for i in 0..self.h_matrix.nrows() {
                let connected_vars: Vec<usize> = self.h_matrix.row(i).iter().enumerate().filter(|(_, &val)| val == 1).map(|(j, _)| j).collect();
                for &j in &connected_vars {
                    let mut tanh_prod = 1.0;
                    for &k in &connected_vars {
                        if k != j {
                            // Simplified message calculation
                            let incoming_llr = llr[k] - var_to_check_sum[k]; // Approximate incoming message
                            tanh_prod *= (incoming_llr / 2.0).tanh();
                        }
                    }
                    if (1.0 - tanh_prod.abs()) < 1e-9 { // Avoid atanh(1) or atanh(-1)
                        check_to_var[(i, j)] = tanh_prod.signum() * 50.0;
                    } else {
                        check_to_var[(i, j)] = 2.0 * tanh_prod.atanh();
                    }
                }
            }

            // 3. Update LLRs
            for j in 0..self.n {
                let initial_llr = if j < self.k && block.source_packets[j].is_some() { 10.0 } else { 0.1 };
                let mut message_sum = 0.0;
                for i in 0..self.h_matrix.nrows() {
                    if self.h_matrix[(i, j)] == 1 {
                        message_sum += check_to_var[(i, j)];
                    }
                }
                llr[j] = initial_llr + message_sum;
            }

            // 4. Check for completion
            let decoded_bits: DVector<u8> = llr.map(|x| if x > 0.0 { 0 } else { 1 });
            let syndrome = &self.h_matrix * &decoded_bits;
            if syndrome.iter().all(|&x| x % 2 == 0) {
                 // Decoding succeeded, but reconstructing packets from bits is not implemented.
                 return Err(FuzcateError::Fec("LDPC decode succeeded conceptually, but packet reconstruction is not implemented.".to_string()));
            }
        }
        
        Err(FuzcateError::Fec("LDPC decoding failed: max iterations reached".to_string()))
    }

    fn can_recover(&self, _available_count: usize, _source_count: usize) -> bool {
        // Recovery depends on which specific packets are received, not just the count.
        // A true check is too complex here, so we optimistically return true.
        true
    }

    fn optimal_repair_count(&self, _source_count: usize, _loss_rate: f32) -> usize {
        // The number of repair packets is fixed by the code parameters (n-k).
        self.n - self.k
    }
}

// ============================================================================
// SECTION: FEC Manager and Configuration
// ============================================================================

/// FEC operating modes
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FecMode { Disabled, Off, EncodeOnly, DecodeOnly, FullDuplex, Adaptive, Performance, AlwaysOn }

impl std::str::FromStr for FecMode {
    type Err = FuzcateError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "disabled" | "off" => Ok(Self::Off), "encode" | "encode-only" => Ok(Self::EncodeOnly),
            "decode" | "decode-only" => Ok(Self::DecodeOnly), "full" | "full-duplex" => Ok(Self::FullDuplex),
            "adaptive" => Ok(Self::Adaptive), "performance" => Ok(Self::Performance),
            "always" | "always-on" => Ok(Self::AlwaysOn),
            _ => Err(FuzcateError::Config(format!("Invalid FEC mode: {}", s))),
        }
    }
}

/// FEC algorithm types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum FecAlgorithm { StripeXor, SparseRlnc, ReedSolomon, CM256, LDPC }

impl fmt::Display for FecAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FecAlgorithm::StripeXor => write!(f, "Stripe-XOR"), FecAlgorithm::SparseRlnc => write!(f, "Sparse-RLNC"),
            FecAlgorithm::ReedSolomon => write!(f, "Reed-Solomon"), FecAlgorithm::CM256 => write!(f, "CM256"),
            FecAlgorithm::LDPC => write!(f, "LDPC"),
        }
    }
}

/// FEC configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FecConfig {
    pub mode: FecMode, pub algorithm: FecAlgorithm, pub block_size: usize, pub repair_ratio: f32,
    pub max_recovery_delay: Duration, pub strategy_config: StrategyConfig, pub metrics_config: MetricsConfig,
    // Optional secondary algorithm for layered protection.
    pub secondary_algorithm: Option<FecAlgorithm>,
}

impl Default for FecConfig {
    fn default() -> Self {
        Self {
            mode: FecMode::FullDuplex, algorithm: FecAlgorithm::LDPC, block_size: 32, repair_ratio: 0.20,
            max_recovery_delay: Duration::from_millis(100), strategy_config: StrategyConfig::default(),
            metrics_config: MetricsConfig::default(),
            secondary_algorithm: None,
        }
    }
}

/// Factory for creating FEC algorithm implementations
#[derive(Debug)]
pub struct FecAlgorithmFactory;

impl FecAlgorithmFactory {
    pub fn create(algorithm: FecAlgorithm, cpu_features: &CpuFeatures) -> Arc<dyn FecAlgorithmTrait> {
        let hw_path = HwDispatcher::select_fec_hw_path(algorithm, cpu_features);
        match algorithm {
            FecAlgorithm::StripeXor => Arc::new(StripeXor::new(hw_path)),
            FecAlgorithm::ReedSolomon => Arc::new(ReedSolomon::new(hw_path).expect("ReedSolomon creation should not fail with default params")), //TODO: Propagate error
            FecAlgorithm::CM256 => Arc::new(CM256::new(hw_path).expect("CM256 creation should not fail with default params")), //TODO: Propagate error
            FecAlgorithm::SparseRlnc => Arc::new(SparseRlnc::new(hw_path)),
            FecAlgorithm::LDPC => Arc::new(Ldpc::new(hw_path, 128, 100, 4, 3).expect("Failed to create LDPC codec")), //TODO: Propagate error
        }
    }
}

// ... The rest of the manager, core, strategy, and metrics code from mod.rs ...
// This part is omitted for brevity but would be included in the final file.
// NOTE: The following structs and impls are copied directly from the `mod.rs` file.

#[derive(Debug)]
#[allow(dead_code)]
pub struct FecManager {
    _mode: FecMode,
    algorithm: FecAlgorithm,
    encoder: Arc<AsyncRwLock<EncoderCore>>,
    decoder: Arc<AsyncRwLock<DecoderCore>>,
    adaptive_engine: Arc<AdaptiveFecEngine>,
    metrics: Arc<AsyncRwLock<MetricsSampler>>,
    hw_dispatcher: Arc<HwDispatcher>,
    // Store the current config for a connection
    connection_configs: Arc<AsyncRwLock<HashMap<ConnectionId, FecConfig>>>,
}

#[allow(dead_code)]
impl FecManager {
    // Note: The `new` function signature now requires a `NetworkMonitor`.
    pub fn new(config: FecConfig, monitor: NetworkMonitor) -> Self {
        let hw_dispatcher = Arc::new(HwDispatcher::new());
        let cpu_features = hw_dispatcher.detect_cpu_features();
        let encoder = Arc::new(AsyncRwLock::new(EncoderCore::new(config.algorithm, &cpu_features, config.block_size, config.repair_ratio, 1500)));
        let decoder = Arc::new(AsyncRwLock::new(DecoderCore::new(config.algorithm, &cpu_features, config.max_recovery_delay)));
        let adaptive_engine = Arc::new(AdaptiveFecEngine::new(config.strategy_config.clone(), monitor));
        let metrics = Arc::new(AsyncRwLock::new(MetricsSampler::new(config.metrics_config.clone())));
        Self {
            _mode: config.mode,
            algorithm: config.algorithm,
            encoder,
            decoder,
            adaptive_engine,
            metrics,
            hw_dispatcher,
            connection_configs: Arc::new(AsyncRwLock::new(HashMap::new())),
        }
    }

    pub async fn process_received_packet(&self, packet: &FecPacket) -> FuzcateResult<Vec<Bytes>> {
        self.decoder.write().await.process_packet(packet.clone()).await
    }

    // The `encode` function now requires a `ConnectionId` to apply the correct strategy.
    pub async fn encode(&self, conn_id: ConnectionId, packets: Vec<Vec<u8>>) -> FuzcateResult<Vec<FecPacket>> {
        // Ensure the strategy is up-to-date for this connection before encoding.
        if self._mode == FecMode::Adaptive {
            self.update_strategy(conn_id).await?;
        }
        
        let configs = self.connection_configs.read().await;
        // Use default config if none exists for the connection
        let default_config = FecConfig::default();
        let config = configs.get(&conn_id).unwrap_or(&default_config);
        
        // TODO: Implement layered protection encoding if `secondary_algorithm` is Some.
        // This would involve a second encoding pass. For now, we use the primary.
        let mut encoder = self.encoder.write().await;
        encoder.update_algorithm(config.algorithm, &self.hw_dispatcher.detect_cpu_features())?;
        encoder.update_config(config.block_size, config.repair_ratio)?;
        encoder.encode_packets(packets).await
    }

    pub async fn decode(&self, packets: Vec<FecPacket>) -> FuzcateResult<Vec<Bytes>> {
        // TODO: Decoding might also need awareness of the secondary algorithm if layered protection is used.
        self.decoder.write().await.decode_packets(packets).await
    }

    /// This method should be called periodically or based on network events to update the FEC strategy.
    pub async fn update_strategy(&self, conn_id: ConnectionId) -> FuzcateResult<()> {
        let new_config = self.adaptive_engine.determine_strategy(conn_id).await?;
        let mut configs = self.connection_configs.write().await;
        
        if let Some(current_config) = configs.get(&conn_id) {
            if current_config.algorithm != new_config.algorithm {
                self.metrics.write().await.record_algorithm_change(current_config.algorithm, new_config.algorithm);
            }
        } else {
            // First time seeing this connection, record the initial algorithm choice.
             self.metrics.write().await.record_algorithm_change(FecAlgorithm::StripeXor, new_config.algorithm); // Assuming a default start
        }
        
        configs.insert(conn_id, new_config);
        Ok(())
    }

    pub async fn get_metrics(&self) -> FecMetrics { self.metrics.read().await.get_current_metrics() }
}

#[derive(Debug)]
pub struct EncoderCore {
    algorithm: FecAlgorithm, algorithm_impl: Arc<dyn FecAlgorithmTrait>,
    block_size: usize, repair_ratio: f32, max_packet_size: usize,
    block_counter: u32, _pending_blocks: HashMap<u32, Block>,
}

impl EncoderCore {
    pub fn new(algorithm: FecAlgorithm, cpu_features: &CpuFeatures, block_size: usize, repair_ratio: f32, max_packet_size: usize) -> Self {
        let algorithm_impl = FecAlgorithmFactory::create(algorithm, cpu_features);
        Self { algorithm, algorithm_impl, block_size, repair_ratio, max_packet_size, block_counter: 0, _pending_blocks: HashMap::new() }
    }
    pub async fn encode_packets(&mut self, packets: Vec<Vec<u8>>) -> FuzcateResult<Vec<FecPacket>> {
        let mut encoded_packets = Vec::new();
        for chunk in packets.chunks(self.block_size) {
            let block_id = self.block_counter;
            self.block_counter += 1;
            let source_count = chunk.len();
            let repair_count = (source_count as f32 * self.repair_ratio).ceil() as usize;
            let mut source_packets = Vec::with_capacity(source_count);
            for (i, data) in chunk.iter().enumerate() {
                let packet = FecPacket { data: Bytes::from(data.clone()), packet_type: PacketType::Source, index: i as u32, block_id, source_count: source_count as u8, repair_count: repair_count as u8, metadata: Vec::new() };
                source_packets.push(Some(packet.clone()));
                encoded_packets.push(packet);
            }
            let mut repair_packets = Vec::with_capacity(repair_count);
            for i in 0..repair_count {
                repair_packets.push(Some(FecPacket { data: Bytes::new(), packet_type: PacketType::Repair, index: i as u32, block_id, source_count: source_count as u8, repair_count: repair_count as u8, metadata: Vec::new() }));
            }
            let mut block = Block { id: block_id, source_packets, repair_packets, algorithm: self.algorithm, hw_path: self.algorithm_impl.hw_path() };
            self.algorithm_impl.encode(&mut block)?;
            for repair_packet in block.repair_packets.into_iter().flatten() { encoded_packets.push(repair_packet); }
        }
        Ok(encoded_packets)
    }
    pub fn update_algorithm(&mut self, algorithm: FecAlgorithm, cpu_features: &CpuFeatures) -> FuzcateResult<()> {
        if self.algorithm == algorithm { return Ok(()); }
        self._pending_blocks.clear();
        self.algorithm = algorithm;
        self.algorithm_impl = FecAlgorithmFactory::create(algorithm, cpu_features);
        self.block_counter = 0;
        Ok(())
    }
    pub fn update_config(&mut self, block_size: usize, repair_ratio: f32) -> FuzcateResult<()> {
        if block_size == 0 || block_size > 255 || !(0.0..=1.0).contains(&repair_ratio) { return Err(FuzcateError::Fec("Invalid FEC config: invalid block size or repair ratio".to_string())); }
        self.block_size = block_size;
        self.repair_ratio = repair_ratio;
        if self._pending_blocks.len() >= block_size { self._pending_blocks.clear(); }
        Ok(())
    }
}

#[derive(Debug)]
pub struct DecoderCore {
    algorithm: FecAlgorithm, algorithm_impl: Arc<dyn FecAlgorithmTrait>,
    max_recovery_delay: Duration, pending_blocks: HashMap<u32, (Block, Instant)>,
    recovery_stats: RecoveryStats,
}

impl DecoderCore {
    pub fn new(algorithm: FecAlgorithm, cpu_features: &CpuFeatures, max_recovery_delay: Duration) -> Self {
        let algorithm_impl = FecAlgorithmFactory::create(algorithm, cpu_features);
        Self { algorithm, algorithm_impl, max_recovery_delay, pending_blocks: HashMap::new(), recovery_stats: RecoveryStats::default() }
    }
    pub async fn process_packet(&mut self, packet: FecPacket) -> FuzcateResult<Vec<Bytes>> { self.decode_packets(vec![packet]).await }
    pub async fn decode_packets(&mut self, packets: Vec<FecPacket>) -> FuzcateResult<Vec<Bytes>> {
        let mut recovered_data = Vec::new();
        let now = Instant::now();
        let mut blocks: HashMap<u32, Vec<FecPacket>> = HashMap::new();
        for packet in packets { blocks.entry(packet.block_id).or_default().push(packet); }
        for (block_id, block_packets) in blocks {
            if let Some(data) = self.process_block(block_id, block_packets, now)? { recovered_data.extend(data); }
        }
        self.cleanup_expired_blocks(now);
        Ok(recovered_data)
    }
    fn process_block(&mut self, block_id: u32, packets: Vec<FecPacket>, now: Instant) -> FuzcateResult<Option<Vec<Bytes>>> {
        let (mut block, _) = self.pending_blocks.remove(&block_id).unwrap_or_else(|| {
            let p = packets.first();
            let source_count = p.map(|p| p.source_count as usize).unwrap_or(0);
            let repair_count = p.map(|p| p.repair_count as usize).unwrap_or(0);
            let block = Block { id: block_id, source_packets: vec![None; source_count], repair_packets: vec![None; repair_count], algorithm: self.algorithm, hw_path: self.algorithm_impl.hw_path() };
            (block, now)
        });
        for packet in packets {
            let idx = packet.index as usize;
            match packet.packet_type {
                PacketType::Source if idx < block.source_packets.len() => block.source_packets[idx] = Some(packet),
                PacketType::Repair if idx < block.repair_packets.len() => block.repair_packets[idx] = Some(packet),
                _ => {},
            }
        }
        let available = block.source_packets.iter().filter(|p| p.is_some()).count() + block.repair_packets.iter().filter(|p| p.is_some()).count();
        let source_count = block.source_packets.len();
        if self.algorithm_impl.can_recover(available, source_count) {
            let recovered = self.algorithm_impl.decode(&mut block)?;
            self.recovery_stats.blocks_processed += 1;
            if !recovered.is_empty() { self.recovery_stats.packets_recovered += recovered.len(); }
            let source_data = block.source_packets.into_iter().flatten().map(|p| p.data).collect();
            Ok(Some(source_data))
        } else {
            self.pending_blocks.insert(block_id, (block, now));
            Ok(None)
        }
    }
    fn cleanup_expired_blocks(&mut self, now: Instant) {
        self.pending_blocks.retain(|_, (_, ts)| now.duration_since(*ts) < self.max_recovery_delay);
    }
    pub async fn update_algorithm(&mut self, algorithm: FecAlgorithm, cpu_features: &CpuFeatures) -> FuzcateResult<()> {
        if self.algorithm == algorithm { return Ok(()); }
        self.flush_pending_blocks().await?;
        self.algorithm = algorithm;
        self.algorithm_impl = FecAlgorithmFactory::create(algorithm, cpu_features);
        self.pending_blocks.clear();
        self.recovery_stats = RecoveryStats::default();
        Ok(())
    }
    pub async fn flush_pending_blocks(&mut self) -> FuzcateResult<()> {
        for (_block_id, (mut block, _)) in self.pending_blocks.drain() {
            let available = block.source_packets.iter().filter(|p| p.is_some()).count() + block.repair_packets.iter().filter(|p| p.is_some()).count();
            if self.algorithm_impl.can_recover(available, block.source_packets.len()) {
                if let Ok(recovered) = self.algorithm_impl.decode(&mut block) {
                    self.recovery_stats.blocks_processed += 1;
                    self.recovery_stats.packets_recovered += recovered.len();
                }
            }
        }
        self.pending_blocks.clear();
        Ok(())
    }
}

#[derive(Debug, Default, Clone)]
struct RecoveryStats { blocks_processed: usize, packets_recovered: usize }

// The old StrategyController has been replaced by the more advanced AdaptiveFecEngine.
// This section is now removed.

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StrategyConfig {
    pub default_algorithm: FecAlgorithm, pub enable_adaptation: bool,
    pub adaptation_interval: Duration, pub performance_window: usize,
}

impl Default for StrategyConfig {
    fn default() -> Self {
        Self { default_algorithm: FecAlgorithm::LDPC, enable_adaptation: true,
            adaptation_interval: Duration::from_millis(2000), performance_window: 50 }
    }
}

#[derive(Debug)]
pub struct MetricsSampler {
    config: MetricsConfig, samples: Vec<FecSample>, start_time: Instant,
    total_packets_processed: u64, total_packets_recovered: u64,
    total_encoding_time: Duration, total_decoding_time: Duration,
}

impl MetricsSampler {
    pub fn new(config: MetricsConfig) -> Self {
        Self { config, samples: Vec::new(), start_time: Instant::now(), total_packets_processed: 0, total_packets_recovered: 0, total_encoding_time: Duration::ZERO, total_decoding_time: Duration::ZERO }
    }
    pub fn record_encoding(&mut self, packet_count: usize, duration: Duration) {
        self.total_packets_processed += packet_count as u64;
        self.total_encoding_time += duration;
        self.add_sample(FecSample { operation: FecOperation::Encoding, packet_count, duration, success: true, ..Default::default() });
    }
    pub fn record_decoding(&mut self, packet_count: usize, recovered_count: usize, duration: Duration, success: bool) {
        self.total_packets_processed += packet_count as u64;
        if success { self.total_packets_recovered += recovered_count as u64; }
        self.total_decoding_time += duration;
        self.add_sample(FecSample { operation: FecOperation::Decoding, packet_count, duration, success, ..Default::default() });
    }
    pub fn record_algorithm_change(&mut self, from: FecAlgorithm, to: FecAlgorithm) {
        self.add_sample(FecSample { operation: FecOperation::AlgorithmChange, algorithm_from: Some(from), algorithm_to: Some(to), ..Default::default() });
    }
    fn add_sample(&mut self, sample: FecSample) {
        if self.samples.len() >= self.config.max_samples { self.samples.remove(0); }
        self.samples.push(sample);
    }
    pub fn get_current_metrics(&self) -> FecMetrics {
        FecMetrics {
            uptime: self.start_time.elapsed(), total_packets_processed: self.total_packets_processed,
            total_packets_recovered: self.total_packets_recovered,
            recovery_rate: if self.total_packets_processed > 0 { self.total_packets_recovered as f32 / self.total_packets_processed as f32 } else { 0.0 },
            ..Default::default()
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct MetricsConfig {
    pub enable_metrics: bool, pub sample_window: Duration,
    pub max_samples: usize, pub export_interval: Duration,
}

#[derive(Debug, Clone, Default)]
struct FecSample {
    timestamp: Instant, operation: FecOperation, packet_count: usize,
    duration: Duration, success: bool, algorithm_from: Option<FecAlgorithm>,
    algorithm_to: Option<FecAlgorithm>,
}

#[derive(Debug, Clone, Copy, Default)]
enum FecOperation { #[default] Encoding, Decoding, AlgorithmChange }

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct FecMetrics {
    pub uptime: Duration, pub total_packets_processed: u64, pub total_packets_recovered: u64,
    pub encoding_throughput: f64, pub decoding_throughput: f64, pub recovery_rate: f32,
    pub recent_success_rate: f32, pub average_encoding_time: Duration,
    pub average_decoding_time: Duration,
}

#[derive(Debug, Clone, Copy)]
pub struct NetworkStats {
    pub packet_loss_rate: f32,
    pub average_latency: Duration,
    pub jitter: Duration,
    pub available_bandwidth: u64,
}

impl Default for NetworkStats {
    fn default() -> Self {
        Self {
            packet_loss_rate: 0.0,
            average_latency: Duration::from_millis(50),
            jitter: Duration::from_millis(0),
            available_bandwidth: 50_000_000, // Default to 50 Mbps
        }
    }
}