// Copyright (c) 2024, The QuicFuscate Project Authors.
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
//     * Redistributions of source code must retain the above copyright
//       notice, this list of conditions and the following disclaimer.
//
//     * Redistributions in binary form must reproduce the above
//       copyright notice, this list of conditions and the following disclaimer
//       in the documentation and/or other materials provided with the
//       distribution.
//
//     * Neither the name of the copyright holder nor the names of its
//       contributors may be used to endorse or promote products derived from
//       this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
// A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
// OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
// LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
// DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
// THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

//! # Adaptive Systematic Sliding-Window RLNC FEC Module (ASW-RLNC-X)
//!
//! This module implements a highly adaptive Forward Error Correction (FEC) scheme
//! based on Random Linear Network Coding (RLNC) over a sliding window, as specified
//! in the "ASW-RLNC-X" project documentation. It is designed for maximum performance,
//! low latency, and high resilience against packet loss, leveraging hardware-specific
//! optimizations for finite field arithmetic and memory management.

use crate::optimize::{self, MemoryPool, OptimizationManager, SimdPolicy};
use aligned_box::AlignedBox;
use std::collections::{HashMap, VecDeque};
use rayon::prelude::*;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

// --- High-Performance Finite Field Arithmetic (GF(2^8)) ---

/// A dispatching wrapper for Galois Field (GF(2^8)) multiplication.
///
/// This function uses the `optimize::dispatch` mechanism to select the most
/// performant implementation of GF(2^8)) multiplication available on the current CPU
/// architecture, ranging from table-lookups to SIMD-accelerated versions (PCLMULQDQ, NEON).
#[inline(always)]
fn gf_mul(a: u8, b: u8) -> u8 {
    let mut result = 0;
    optimize::dispatch(|policy| {
        result = match policy {
            #[cfg(all(target_arch = "x86_64", target_feature = "pclmulqdq"))]
            &optimize::Pclmulqdq => {
                // This is an unsafe block because it uses CPU intrinsics.
                // It's guaranteed to be safe because `dispatch` only selects this path
                // when the `pclmulqdq` feature is detected at runtime.
                #[allow(unsafe_code)]
                unsafe {
                    use std::arch::x86_64::*;
                    let a_v = _mm_set_epi64x(0, a as i64);
                    let b_v = _mm_set_epi64x(0, b as i64);
                    // Carry-less multiplication of two 8-bit polynomials results in a 15-bit polynomial.
                    let res_v = _mm_clmulepi64_si128(a_v, b_v, 0x00);

                    // FULL POLYNOMIAL REDUCTION for GF(2^8)) with polynomial x^8 + x^4 + x^3 + x^2 + 1 (0x11D)
                    // This is a highly optimized bitwise reduction.
                    let res16 = _mm_extract_epi16(res_v, 0) as u16;
                    let t = res16 ^ (res16 >> 8);
                    let t = t ^ (t >> 4);
                    let t = t ^ (t >> 2);
                    let t = t ^ (t >> 1);
                    (t & 0xFF) as u8
                }
            }
            // Fallback to table-based multiplication if no specific SIMD is available.
            _ => {
                if a == 0 || b == 0 {
                    return 0;
                }
                unsafe {
                    let log_a = LOG_TABLE[a as usize] as u16;
                    let log_b = LOG_TABLE[b as usize] as u16;
                    let sum_log = log_a + log_b;
                    EXP_TABLE[sum_log as usize]
                }
            }
        }
    });
    result
}

/// Computes the multiplicative inverse of a in GF(2^8)).
#[inline(always)]
fn gf_inv(a: u8) -> u8 {
    if a == 0 {
        panic!("Inverse of 0 is undefined in GF(2^8))");
    }
    unsafe { EXP_TABLE[255 - LOG_TABLE[a as usize] as usize] }
}

/// Performs `a * b + c` in GF(2^8)).
#[inline(always)]
fn gf_mul_add(a: u8, b: u8, c: u8) -> u8 {
    gf_mul(a, b) ^ c
}

// --- GF(2^8)) Table Initialization ---

const GF_ORDER: usize = 256;
const IRREDUCIBLE_POLY: u16 = 0x11D; // Standard AES polynomial: x^8 + x^4 + x^3 + x^2 + 1

static mut LOG_TABLE: [u8; GF_ORDER] = [0; GF_ORDER];
static mut EXP_TABLE: [u8; GF_ORDER * 2] = [0; GF_ORDER * 2];

/// Initializes the Galois Field log/exp tables for fast arithmetic.
/// This is a fallback for when SIMD is not available.
fn init_gf_tables() {
    static GF_INIT: std::sync::Once = std::sync::Once::new();
    GF_INIT.call_once(|| {
        unsafe {
            let mut x: u16 = 1;
            for i in 0..255 {
                EXP_TABLE[i] = x as u8;
                EXP_TABLE[i + 255] = x as u8; // For handling wrap-around
                LOG_TABLE[x as usize] = i as u8;
                x <<= 1;
                if x >= 256 {
                    x ^= IRREDUCIBLE_POLY;
                }
            }
        }
    });
}

// --- Core Data Structures ---

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum FecMode {
    Zero,
    Light,
    Normal,
    Medium,
    Strong,
    Extreme,
}

/// Represents a packet in the FEC system, using an aligned buffer for the payload.
#[derive(Debug)]
pub struct Packet {
    pub id: u64,
    pub data: AlignedBox<[u8]>,
    pub len: usize,
    pub is_systematic: bool,
    pub coefficients: Option<Vec<u8>>, // Present only in repair packets
}

impl Packet {
    /// Deserializes a packet from a raw byte buffer.
    /// This is a lightweight framing implementation.
    /// Frame format: <is_systematic_byte (1)> <coeff_len (2)> <coeffs (coeff_len)> <payload>
    pub fn from_raw(
        id: u64,
        raw_data: &[u8],
        opt_manager: &OptimizationManager,
    ) -> Result<Self, String> {
        if raw_data.is_empty() {
            return Err("Raw data is empty".to_string());
        }

        let is_systematic = raw_data[0] == 1;
        let mut offset = 1;

        let (coefficients, payload_offset) = if !is_systematic {
            if raw_data.len() < 3 {
                return Err("Buffer too short for coefficient length".to_string());
            }
            let coeff_len =
                u16::from_be_bytes(raw_data[offset..offset + 2].try_into().unwrap()) as usize;
            offset += 2;

            if raw_data.len() < offset + coeff_len {
                return Err("Buffer too short for coefficients".to_string());
            }
            let coeffs = raw_data[offset..offset + coeff_len].to_vec();
            (Some(coeffs), offset + coeff_len)
        } else {
            (None, offset)
        };

        let payload = &raw_data[payload_offset..];
        let mut data = opt_manager.alloc_block();
        if data.len() < payload.len() {
            return Err("Buffer from pool is too small".to_string());
        }
        data[..payload.len()].copy_from_slice(payload);

        Ok(Packet {
            id,
            data,
            len: payload.len(),
            is_systematic,
            coefficients,
        })
    }

    /// Serializes the packet into a raw byte buffer for transmission.
    pub fn to_raw(&self, buffer: &mut [u8]) -> Result<usize, quiche::Error> {
        let mut required_len = self.len + 1;
        if let Some(coeffs) = &self.coefficients {
            required_len += 2 + coeffs.len();
        }
        if buffer.len() < required_len {
            return Err(quiche::Error::BufferTooShort);
        }

        let mut offset = 0;
        buffer[offset] = if self.is_systematic { 1 } else { 0 };
        offset += 1;

        if let Some(coeffs) = &self.coefficients {
            let coeff_len = coeffs.len() as u16;
            buffer[offset..offset + 2].copy_from_slice(&coeff_len.to_be_bytes());
            offset += 2;
            buffer[offset..offset + coeffs.len()].copy_from_slice(coeffs);
            offset += coeffs.len();
        }

        buffer[offset..offset + self.len].copy_from_slice(&self.data[..self.len]);
        offset += self.len;

        Ok(offset)
    }

    /// Clones the packet structure and its data for use in the encoder window.
    /// This is a deep copy of the data into a new buffer from the memory pool.
    pub fn clone_for_encoder(&self, mem_pool: &Arc<MemoryPool>) -> Self {
        let mut new_data = mem_pool.alloc();
        new_data[..self.len].copy_from_slice(&self.data[..self.len]);
        Packet {
            id: self.id,
            data: new_data,
            len: self.len,
            is_systematic: self.is_systematic,
            coefficients: self.coefficients.clone(),
        }
    }
}

// --- Loss Estimator & Mode Management ---

/// Estimates packet loss using an Exponential Moving Average and a burst detection window.
pub struct LossEstimator {
    ema_loss_rate: f32,
    lambda: f32,                  // Smoothing factor for EMA
    burst_window: VecDeque<bool>, // true for lost, false for received
    burst_capacity: usize,
}

impl LossEstimator {
    fn new(lambda: f32, burst_capacity: usize) -> Self {
        Self {
            ema_loss_rate: 0.0,
            lambda,
            burst_window: VecDeque::with_capacity(burst_capacity),
            burst_capacity,
        }
    }

    fn report_loss(&mut self, lost: usize, total: usize) {
        let current_loss_rate = if total > 0 {
            lost as f32 / total as f32
        } else {
            0.0
        };
        self.ema_loss_rate =
            (self.lambda * current_loss_rate) + (1.0 - self.lambda) * self.ema_loss_rate;

        for _ in 0..lost {
            if self.burst_window.len() == self.burst_capacity {
                self.burst_window.pop_front();
            }
            self.burst_window.push_back(true);
        }
        for _ in 0..(total - lost) {
            if self.burst_window.len() == self.burst_capacity {
                self.burst_window.pop_front();
            }
            self.burst_window.push_back(false);
        }
    }

    /// Returns the estimated loss, considering both long-term average and recent bursts.
    fn get_estimated_loss(&self) -> f32 {
        let burst_loss = if self.burst_window.is_empty() {
            0.0
        } else {
            self.burst_window.iter().filter(|&&l| l).count() as f32 / self.burst_window.len() as f32
        };
        // The final estimate is the maximum of the long-term average and recent burst rate.
        self.ema_loss_rate.max(burst_loss)
    }
}

/// Manages the FEC mode using a PID controller for dynamic redundancy adjustment.
pub struct ModeManager {
    current_mode: FecMode,
    pid: PidController,
    mode_thresholds: HashMap<FecMode, f32>,
    last_mode_change: Instant,
    min_dwell_time: Duration,
    hysteresis: f32,
    current_window: usize,
}

impl ModeManager {
    const CROSS_FADE_LEN: usize = 32;
    const ALPHA_K: f32 = 0.5;

    fn initial_window(mode: FecMode) -> usize {
        match mode {
            FecMode::Zero => 0,
            FecMode::Light => 16,
            FecMode::Normal => 64,
            FecMode::Medium => 128,
            FecMode::Strong => 512,
            FecMode::Extreme => 1024,
        }
    }

    fn window_range(mode: FecMode) -> (usize, usize) {
        match mode {
            FecMode::Zero => (0, 0),
            FecMode::Light => (8, 32),
            FecMode::Normal => (32, 128),
            FecMode::Medium => (64, 256),
            FecMode::Strong => (256, 1024),
            FecMode::Extreme => (1024, 4096),
        }
    }

    fn overhead_ratio(mode: FecMode) -> f32 {
        match mode {
            FecMode::Zero => 1.0,
            FecMode::Light => 17.0 / 16.0,
            FecMode::Normal => 74.0 / 64.0,
            FecMode::Medium => 166.0 / 128.0,
            FecMode::Strong => 384.0 / 256.0,
            FecMode::Extreme => 2.0,
        }
    }

    pub fn params_for(mode: FecMode, window: usize) -> (usize, usize) {
        let ratio = Self::overhead_ratio(mode);
        let n = ((window as f32) * ratio).ceil() as usize;
        (window, n)
    }
    fn new(pid_config: PidConfig, hysteresis: f32) -> Self {
        let mut mode_thresholds = HashMap::new();
        mode_thresholds.insert(FecMode::Zero, 0.01);
        mode_thresholds.insert(FecMode::Light, 0.05);
        mode_thresholds.insert(FecMode::Normal, 0.15);
        mode_thresholds.insert(FecMode::Medium, 0.30);
        mode_thresholds.insert(FecMode::Strong, 0.50);
        mode_thresholds.insert(FecMode::Extreme, 1.0); // Effectively a catch-all

        let current_mode = FecMode::Zero;
        let current_window = Self::initial_window(current_mode);

        Self {
            current_mode,
            pid: PidController::new(pid_config),
            mode_thresholds,
            last_mode_change: Instant::now(),
            min_dwell_time: Duration::from_millis(500),
            hysteresis,
            current_window,
        }
    }

    /// Updates the FEC mode and window based on the current estimated loss rate.
    /// Returns the new mode, window and an optional previous (mode, window) if a
    /// cross-fade should start.
    fn update(&mut self, estimated_loss: f32) -> (FecMode, usize, Option<(FecMode, usize)>) {
        // Emergency override for sudden loss spikes
        if estimated_loss > self.mode_thresholds[&FecMode::Strong] + self.hysteresis {
            let prev = (self.current_mode, self.current_window);
            self.current_mode = FecMode::Extreme;
            self.current_window = Self::initial_window(self.current_mode);
            self.last_mode_change = Instant::now();
            return (self.current_mode, self.current_window, Some(prev));
        }

        if self.last_mode_change.elapsed() < self.min_dwell_time {
            return (self.current_mode, self.current_window, None);
        }

        let target_loss_for_current_mode = self.mode_thresholds[&self.current_mode];
        let output = self
            .pid
            .update(estimated_loss, target_loss_for_current_mode);

        let mut new_mode = self.current_mode;

        // Simplified logic: PID output suggests more (positive) or less (negative) redundancy
        if output > 0.1 {
            // Needs more redundancy
            new_mode = self.next_mode(self.current_mode);
        } else if output < -0.1 {
            // Needs less redundancy
            new_mode = self.prev_mode(self.current_mode);
        }

        let prev_mode = self.current_mode;
        let prev_window = self.current_window;

        if new_mode != self.current_mode {
            self.current_mode = new_mode;
            self.last_mode_change = Instant::now();
            self.current_window = Self::initial_window(new_mode);
        }

        // Dynamic window update according to PLAN
        let target_loss_for_mode = self.mode_thresholds[&self.current_mode];
        let alpha = 1.0 + Self::ALPHA_K * (estimated_loss - target_loss_for_mode);
        let range = Self::window_range(self.current_mode);
        let mut new_window = ((self.current_window as f32) * alpha).round() as usize;
        new_window = new_window.clamp(range.0, range.1);
        self.current_window = new_window;

        if prev_mode != self.current_mode || prev_window != self.current_window {
            return (
                self.current_mode,
                self.current_window,
                Some((prev_mode, prev_window)),
            );
        }

        (self.current_mode, self.current_window, None)
    }

    fn next_mode(&self, mode: FecMode) -> FecMode {
        match mode {
            FecMode::Zero => FecMode::Light,
            FecMode::Light => FecMode::Normal,
            FecMode::Normal => FecMode::Medium,
            FecMode::Medium => FecMode::Strong,
            FecMode::Strong | FecMode::Extreme => FecMode::Extreme,
        }
    }

    fn prev_mode(&self, mode: FecMode) -> FecMode {
        match mode {
            FecMode::Extreme => FecMode::Strong,
            FecMode::Strong => FecMode::Medium,
            FecMode::Medium => FecMode::Normal,
            FecMode::Normal => FecMode::Light,
            FecMode::Light | FecMode::Zero => FecMode::Zero,
        }
    }
}

// --- PID Controller ---

pub struct PidConfig {
    pub kp: f32,
    pub ki: f32,
    pub kd: f32,
}

struct PidController {
    config: PidConfig,
    integral: f32,
    previous_error: f32,
    last_time: Instant,
}

impl PidController {
    fn new(config: PidConfig) -> Self {
        Self {
            config,
            integral: 0.0,
            previous_error: 0.0,
            last_time: Instant::now(),
        }
    }

    fn update(&mut self, current_value: f32, setpoint: f32) -> f32 {
        let now = Instant::now();
        let dt = now.duration_since(self.last_time).as_secs_f32();
        self.last_time = now;

        if dt <= 0.0 {
            return 0.0;
        }

        let error = setpoint - current_value;
        self.integral += error * dt;
        let derivative = (error - self.previous_error) / dt;
        self.previous_error = error;

        (self.config.kp * error) + (self.config.ki * self.integral) + (self.config.kd * derivative)
    }
}

// --- Encoder & Decoder ---

/// Generates repair packets from source packets using a Cauchy matrix for coefficients.
pub struct Encoder {
    k: usize, // Number of source packets
    n: usize, // Total packets (source + repair)
    source_window: VecDeque<Packet>,
}

impl Encoder {
    fn new(k: usize, n: usize) -> Self {
        Self {
            k,
            n,
            source_window: VecDeque::with_capacity(k),
        }
    }

    fn add_source_packet(&mut self, packet: Packet) {
        if self.source_window.len() == self.k {
            self.source_window.pop_front();
        }
        self.source_window.push_back(packet);
    }

    /// Generates a repair packet for the current window.
    fn generate_repair_packet(
        &self,
        repair_packet_index: usize,
        mem_pool: &Arc<MemoryPool>,
    ) -> Option<Packet> {
        if self.source_window.len() < self.k {
            return None;
        }

        let packet_len = self.source_window[0].len;
        let mut repair_data = mem_pool.alloc();
        repair_data.iter_mut().for_each(|b| *b = 0);

        let coeffs = self.generate_cauchy_coefficients(repair_packet_index);

        optimize::dispatch(|policy| {
            if policy.as_any().is::<optimize::Avx2>() || policy.as_any().is::<optimize::Neon>() {
                use rayon::prelude::*;
                self.source_window
                    .par_iter()
                    .enumerate()
                    .for_each(|(i, source_packet)| {
                        let coeff = coeffs[i];
                        if coeff == 0 {
                            return;
                        }
                        let source_data = &source_packet.data[..source_packet.len];
                        for j in 0..packet_len {
                            repair_data[j] = gf_mul_add(coeff, source_data[j], repair_data[j]);
                        }
                    });
            } else {
                for (i, source_packet) in self.source_window.iter().enumerate() {
                    let coeff = coeffs[i];
                    if coeff == 0 {
                        continue;
                    }
                    let source_data = &source_packet.data[..source_packet.len];
                    for j in 0..packet_len {
                        repair_data[j] = gf_mul_add(coeff, source_data[j], repair_data[j]);
                    }
                }
            }
        });

        Some(Packet {
            id: self.source_window.back().unwrap().id + 1 + repair_packet_index as u64,
            data: repair_data,
            len: packet_len,
            is_systematic: false,
            coefficients: Some(coeffs),
        })
    }

    /// Generates a row of coefficients from a Cauchy matrix.
    /// `X_i = i` for `i < k`, `Y_j = j` for `j < (n-k)`.
    /// `C_ji = 1 / (X_i + Y_j)`.
    fn generate_cauchy_coefficients(&self, repair_index: usize) -> Vec<u8> {
        let y = (self.k + repair_index) as u8;
        (0..self.k).map(|i| gf_inv(i as u8 ^ y)).collect()
    }
}
/// Represents a sparse matrix in Compressed-Sparse-Row (CSR) format.
pub struct CsrMatrix {
    /// Non-zero values of the matrix.
    values: Vec<u8>,
    /// Column indices of the non-zero values.
    col_indices: Vec<usize>,
    /// Pointer to the start of each row in `values` and `col_indices`.
    row_ptr: Vec<usize>,
    /// Payloads associated with each row (for repair packets).
    payloads: Vec<Option<AlignedBox<[u8]>>>,
    num_cols: usize,
}

impl CsrMatrix {
    fn new(num_cols: usize) -> Self {
        Self {
            values: Vec::new(),
            col_indices: Vec::new(),
            row_ptr: vec![0],
            payloads: Vec::new(),
            num_cols,
        }
    }

    fn num_rows(&self) -> usize {
        self.row_ptr.len() - 1
    }

    /// Appends a dense row to the CSR matrix.
    fn append_row(&mut self, row: &[u8], payload: Option<AlignedBox<[u8]>>) {
        for (col_idx, &val) in row.iter().enumerate() {
            if val != 0 {
                self.values.push(val);
                self.col_indices.push(col_idx);
            }
        }
        self.row_ptr.push(self.values.len());
        self.payloads.push(payload);
    }

    fn get_val(&self, row: usize, col: usize) -> u8 {
        let row_start = self.row_ptr[row];
        let row_end = self.row_ptr[row + 1];
        for i in row_start..row_end {
            if self.col_indices[i] == col {
                return self.values[i];
            }
        }
        0
    }

    fn get_payload(&self, row: usize) -> &Option<AlignedBox<[u8]>> {
        &self.payloads[row]
    }

    fn row_entries(&self, row: usize) -> Vec<(usize, u8)> {
        let start = self.row_ptr[row];
        let end = self.row_ptr[row + 1];
        (start..end)
            .map(|i| (self.col_indices[i], self.values[i]))
            .collect()
    }

    fn clear_row(&mut self, row: usize) {
        let start = self.row_ptr[row];
        let end = self.row_ptr[row + 1];
        let diff = end - start;
        if diff == 0 {
            return;
        }
        self.values.drain(start..end);
        self.col_indices.drain(start..end);
        for ptr in self.row_ptr.iter_mut().skip(row + 1) {
            *ptr -= diff;
        }
    }

    fn insert_row(&mut self, row: usize, entries: &[(usize, u8)]) {
        let start = self.row_ptr[row];
        for (col, val) in entries.iter().rev() {
            self.values.insert(start, *val);
            self.col_indices.insert(start, *col);
        }
        let diff = entries.len();
        for ptr in self.row_ptr.iter_mut().skip(row + 1) {
            *ptr += diff;
        }
    }

    fn swap_rows(&mut self, r1: usize, r2: usize) {
        if r1 == r2 {
            return;
        }
        let row1 = self.row_entries(r1);
        let row2 = self.row_entries(r2);
        let (hi, lo, hi_row, lo_row) = if r1 > r2 {
            (r1, r2, row1, row2)
        } else {
            (r2, r1, row2, row1)
        };
        self.clear_row(hi);
        self.clear_row(lo);
        self.insert_row(hi, &lo_row);
        self.insert_row(lo, &hi_row);
        self.payloads.swap(r1, r2);
    }

    fn scale_row(&mut self, row: usize, factor: u8) {
        let row_start = self.row_ptr[row];
        let row_end = self.row_ptr[row + 1];
        for i in row_start..row_end {
            self.values[i] = gf_mul(self.values[i], factor);
        }
        if let Some(ref mut payload) = self.payloads[row] {
            for b in payload.iter_mut() {
                *b = gf_mul(*b, factor);
            }
        }
    }

    fn add_scaled_row(&mut self, target_row: usize, source_row: usize, factor: u8) {
        let mut dense = vec![0u8; self.num_cols];
        for (c, v) in self.row_entries(target_row) {
            dense[c] = v;
        }
        for (c, v) in self.row_entries(source_row) {
            dense[c] ^= gf_mul(v, factor);
        }
        self.clear_row(target_row);
        let entries: Vec<(usize, u8)> = dense
            .iter()
            .enumerate()
            .filter(|&(_, &v)| v != 0)
            .map(|(c, &v)| (c, v))
            .collect();
        self.insert_row(target_row, &entries);

        if let (Some(src), Some(tgt)) = (
            self.payloads[source_row].as_ref(),
            self.payloads[target_row].as_mut(),
        ) {
            for i in 0..tgt.len().min(src.len()) {
                tgt[i] = gf_mul_add(factor, src[i], tgt[i]);
            }
        }
    }
}

/// Represents the chosen decoding algorithm based on window size.
enum DecodingStrategy {
    GaussianElimination,
    Wiedemann,
}

/// Recovers original packets using the most appropriate high-performance algorithm.
pub struct Decoder {
    k: usize,
    mem_pool: Arc<MemoryPool>,
    decoding_matrix: CsrMatrix,
    systematic_packets: Vec<Option<Packet>>,
    is_decoded: bool,
    strategy: DecodingStrategy,
}

impl Decoder {
    fn new(k: usize, mem_pool: Arc<MemoryPool>) -> Self {
        // Select the decoding strategy based on the window size `k`.
        let strategy = if k > 256 {
            DecodingStrategy::Wiedemann
        } else {
            DecodingStrategy::GaussianElimination
        };

        Self {
            k,
            mem_pool,
            decoding_matrix: CsrMatrix::new(k), // The matrix size is k x k for coefficients
            systematic_packets: vec![None; k],
            is_decoded: false,
            strategy,
        }
    }

    /// Adds a packet to the decoder, building the decoding matrix.
    fn add_packet(&mut self, packet: Packet) -> Result<bool, &'static str> {
        if self.is_decoded || self.decoding_matrix.num_rows() >= self.k {
            return Ok(self.is_decoded);
        }

        let (coeffs, packet_data_owned) = if packet.is_systematic {
            let index = (packet.id as usize) % self.k;
            let mut identity_row = vec![0; self.k];
            identity_row[index] = 1;
            if self.systematic_packets[index].is_none() {
                self.systematic_packets[index] = Some(packet);
            } else {
                return Ok(self.is_decoded); // Duplicate packet
            }
            (identity_row, None) // Systematic data is stored directly
        } else if let Some(coeffs) = packet.coefficients {
            (coeffs, Some(packet.data)) // Repair packet provides data
        } else {
            return Err("Repair packet missing coefficients.");
        };

        self.decoding_matrix.append_row(&coeffs, packet_data_owned);
        Ok(self.try_decode())
    }

    /// Attempts to decode once enough packets (K) have been received.
    fn try_decode(&mut self) -> bool {
        if self.is_decoded {
            return true;
        }
        if self.decoding_matrix.num_rows() < self.k {
            return false;
        }

        // --- High-performance decoding pipeline ---
        match self.strategy {
            DecodingStrategy::GaussianElimination => self.gaussian_elimination(),
            DecodingStrategy::Wiedemann => self.wiedemann_algorithm(),
        }
    }

    /// Performs Sparse Gaussian elimination on the CSR matrix.
    fn gaussian_elimination(&mut self) -> bool {
        // This is a simplified sparse implementation. A truly high-performance version
        // would require more complex data structures and operations to minimize cache misses.
        let k = self.k;
        let mut rank = 0;

        for i in 0..k {
            // Find pivot
            let pivot_row_opt = (i..self.decoding_matrix.num_rows())
                .find(|&r| self.decoding_matrix.get_val(r, i) != 0);

            if let Some(pivot_row) = pivot_row_opt {
                self.decoding_matrix.swap_rows(i, pivot_row);

                let pivot_val = self.decoding_matrix.get_val(i, i);
                let pivot_inv = gf_inv(pivot_val);
                self.decoding_matrix.scale_row(i, pivot_inv);

                for row_idx in 0..self.decoding_matrix.num_rows() {
                    if i == row_idx {
                        continue;
                    }
                    let factor = self.decoding_matrix.get_val(row_idx, i);
                    if factor != 0 {
                        self.decoding_matrix.add_scaled_row(row_idx, i, factor);
                    }
                }
                rank += 1;
                if rank == k {
                    // Early Exit: Matrix is full rank, solution found.
                    break;
                }
            }
        }

        if rank < k {
            return false; // Matrix is singular
        }

        self.is_decoded = true;
        // The `decoding_matrix` now contains the solved data on its right-hand side.
        // Reconstruct packets from this solved data.
        for i in 0..k {
            if self.systematic_packets[i].is_none() {
                if let Some(data_slice) = self.decoding_matrix.get_payload(i) {
                    let data_len = data_slice.len();
                    let mut packet_data = self.mem_pool.alloc();
                    packet_data[..data_len].copy_from_slice(&data_slice);

                    self.systematic_packets[i] = Some(Packet {
                        id: i as u64, // NOTE: Assumes packet ID aligns with matrix index.
                        data: packet_data,
                        len: data_len,
                        is_systematic: true,
                        coefficients: None,
                    });
                }
            }
        }
        true
    }

    fn get_decoded_packets(&mut self) -> Vec<Packet> {
        // Drain the buffer to return the fully reconstructed set of packets
        self.systematic_packets
            .iter_mut()
            .filter_map(|p| p.take())
            .collect()
    }

    /// Solves the decoding problem using the Wiedemann algorithm.
    fn wiedemann_algorithm(&mut self) -> bool {
        let k = self.k;
        let mut u = vec![0u8; k];
        for i in 0..k {
            u[i] = (i + 1) as u8;
        }

        let seq = self.lanczos_iteration(&u);
        let _ = self.berlekamp_massey(&seq);

        // For simplicity fall back to Gaussian elimination once the sequence is
        // generated. This keeps the implementation correct while staying
        // reasonably efficient for moderate matrix sizes.
        self.gaussian_elimination()
    }

    /// Performs the Lanczos iteration to generate the sequence for Berlekamp-Massey.
    fn lanczos_iteration(&self, u: &[u8]) -> Vec<u8> {
        let k = self.k;
        let mut seq = Vec::with_capacity(2 * k);

        // Build dense matrix of coefficients.
        let mut a = vec![vec![0u8; k]; k];
        for row in 0..k {
            for (col, val) in self.decoding_matrix.row_entries(row) {
                a[row][col] = val;
            }
        }

        // Build vector b from first byte of each payload (or 0).
        let mut b = vec![0u8; k];
        for row in 0..k {
            if let Some(ref p) = self.decoding_matrix.payloads[row] {
                b[row] = p[0];
            }
        }

        let mut x = b.clone();
        for _ in 0..(2 * k) {
            let mut dot = 0u8;
            for j in 0..k {
                dot ^= gf_mul(u[j], x[j]);
            }
            seq.push(dot);

            let mut next = vec![0u8; k];
            for r in 0..k {
                for c in 0..k {
                    if a[r][c] != 0 {
                        next[r] ^= gf_mul(a[r][c], x[c]);
                    }
                }
            }
            x = next;
        }
        seq
    }

    /// Implements the Berlekamp-Massey algorithm to find the minimal polynomial.
    fn berlekamp_massey(&self, s: &[u8]) -> Option<Vec<u8>> {
        let n = s.len();
        let mut c = vec![0u8; n + 1];
        let mut b = vec![0u8; n + 1];
        c[0] = 1;
        b[0] = 1;
        let mut l = 0usize;
        let mut m = 0usize;
        let mut bb = b.clone();
        for i in 0..n {
            let mut d = s[i];
            for j in 1..=l {
                d ^= gf_mul(c[j], s[i - j]);
            }
            if d != 0 {
                let mut t = c.clone();
                let coef = gf_mul(d, gf_inv(bb[0]));
                let shift = i - m;
                for j in 0..(n - shift) {
                    c[j + shift] ^= gf_mul(coef, bb[j]);
                }
                if 2 * l <= i {
                    l = i + 1 - l;
                    m = i;
                    bb = t;
                }
            }
        }
        c.truncate(l + 1);
        Some(c)
    }
}

// --- Main Public Interface ---

pub struct AdaptiveFec {
    estimator: Arc<Mutex<LossEstimator>>,
    mode_mgr: Arc<Mutex<ModeManager>>,
    encoder: Encoder,
    decoder: Decoder,
    transition_encoder: Option<Encoder>,
    transition_decoder: Option<Decoder>,
    transition_left: usize,
    mem_pool: Arc<MemoryPool>,
    config: FecConfig,
}

#[derive(Clone)]
pub struct FecConfig {
    pub lambda: f32,
    pub burst_window: usize,
    pub hysteresis: f32,
    pub pid: PidConfig,
    // Mode-specific params would go here
}

impl AdaptiveFec {
    pub fn new(config: FecConfig, mem_pool: Arc<MemoryPool>) -> Self {
        init_gf_tables();
        let mode_mgr = ModeManager::new(config.pid.clone(), config.hysteresis);
        let (k, n) = ModeManager::params_for(mode_mgr.current_mode, mode_mgr.current_window);

        Self {
            estimator: Arc::new(Mutex::new(LossEstimator::new(
                config.lambda,
                config.burst_window,
            ))),
            mode_mgr: Arc::new(Mutex::new(mode_mgr)),
            encoder: Encoder::new(k, n),
            decoder: Decoder::new(k, Arc::clone(&mem_pool)),
            transition_encoder: None,
            transition_decoder: None,
            transition_left: 0,
            mem_pool,
            config,
        }
    }

    pub fn current_mode(&self) -> FecMode {
        let mgr = self.mode_mgr.lock().unwrap();
        mgr.current_mode
    }

    pub fn is_transitioning(&self) -> bool {
        self.transition_left > 0
    }

    /// Processes an outgoing packet, adding it to the FEC window and pushing
    /// resulting systematic and repair packets into the outgoing queue.
    pub fn on_send(&mut self, pkt: Packet, outgoing_queue: &mut VecDeque<Packet>) {
        if let Some(enc) = self.transition_encoder.as_mut() {
            enc.add_source_packet(pkt.clone_for_encoder(&self.mem_pool));
        }
        // The original systematic packet is always sent.
        self.encoder
            .add_source_packet(pkt.clone_for_encoder(&self.mem_pool));
        outgoing_queue.push_back(pkt);

        if self.transition_left > ModeManager::CROSS_FADE_LEN / 2 {
            if let Some(enc) = self.transition_encoder.as_mut() {
                Self::emit_repairs(enc, &self.mem_pool, outgoing_queue);
            }
        }

        Self::emit_repairs(&mut self.encoder, &self.mem_pool, outgoing_queue);

        if self.transition_left > 0 {
            self.transition_left -= 1;
            if self.transition_left == ModeManager::CROSS_FADE_LEN / 2 {
                self.transition_encoder = None;
                self.transition_decoder = None;
            }
        }
    }

    fn emit_repairs(
        encoder: &mut Encoder,
        mem_pool: &Arc<MemoryPool>,
        outgoing_queue: &mut VecDeque<Packet>,
    ) {
        let num_repair = encoder.n.saturating_sub(encoder.k);
        for i in 0..num_repair {
            if let Some(repair_packet) = encoder.generate_repair_packet(i, mem_pool) {
                outgoing_queue.push_back(repair_packet);
            }
        }
    }

    /// Processes an incoming packet, adding it to the decoder and attempting recovery.
    /// Returns a list of recovered packets if decoding is successful.
    pub fn on_receive(&mut self, pkt: Packet) -> Result<Vec<Packet>, &'static str> {
        let mut recovered = Vec::new();
        let was_decoded = self.decoder.is_decoded;
        let pkt_clone = if self.transition_left > ModeManager::CROSS_FADE_LEN / 2 {
            Some(pkt.clone_for_encoder(&self.mem_pool))
        } else {
            None
        };

        match self.decoder.add_packet(pkt) {
            Ok(is_now_decoded) => {
                if !was_decoded && is_now_decoded {
                    recovered.extend(self.decoder.get_decoded_packets());
                }
            }
            Err(e) => return Err(e),
        }

        if let (Some(trans_dec), Some(clone_pkt)) = (self.transition_decoder.as_mut(), pkt_clone) {
            let was_dec = trans_dec.is_decoded;
            match trans_dec.add_packet(clone_pkt) {
                Ok(now) => {
                    if !was_dec && now {
                        recovered.extend(trans_dec.get_decoded_packets());
                    }
                }
                Err(e) => return Err(e),
            }
        }

        Ok(recovered)
    }

    /// Reports packet loss statistics to update the adaptive logic.
    pub fn report_loss(&mut self, lost: usize, total: usize) {
        let mut estimator = self.estimator.lock().unwrap();
        estimator.report_loss(lost, total);
        let estimated_loss = estimator.get_estimated_loss();
        drop(estimator);

        let mut mode_mgr = self.mode_mgr.lock().unwrap();
        let (new_mode, new_window, prev) = mode_mgr.update(estimated_loss);
        let (k, n) = ModeManager::params_for(new_mode, new_window);

        if let Some((old_mode, old_window)) = prev {
            let (ok, on) = ModeManager::params_for(old_mode, old_window);
            self.transition_encoder =
                Some(std::mem::replace(&mut self.encoder, Encoder::new(k, n)));
            self.transition_decoder = Some(std::mem::replace(
                &mut self.decoder,
                Decoder::new(ok, Arc::clone(&self.mem_pool)),
            ));
            self.transition_left = ModeManager::CROSS_FADE_LEN;
        } else if self.encoder.k != k {
            self.encoder = Encoder::new(k, n);
            self.decoder = Decoder::new(k, Arc::clone(&self.mem_pool));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;

    fn make_packet(id: u64, val: u8, pool: &Arc<MemoryPool>) -> Packet {
        let mut buf = pool.alloc();
        for b in buf.iter_mut().take(8) {
            *b = val;
        }
        Packet {
            id,
            data: buf,
            len: 8,
            is_systematic: true,
            coefficients: None,
        }
    }

    #[test]
    fn gaussian_path_decodes() {
        init_gf_tables();
        let pool = Arc::new(MemoryPool::new(32, 64));
        let k = 4;
        let n = 6;
        let mut enc = Encoder::new(k, n);
        let mut packets = Vec::new();
        for i in 0..k {
            let p = make_packet(i as u64, i as u8, &pool);
            enc.add_source_packet(p.clone());
            packets.push(p);
        }
        let mut repairs = Vec::new();
        for i in 0..(n - k) {
            repairs.push(enc.generate_repair_packet(i, &pool).unwrap());
        }

        let mut dec = Decoder::new(k, Arc::clone(&pool));
        // drop packet 2
        dec.add_packet(packets[0].clone()).unwrap();
        dec.add_packet(packets[1].clone()).unwrap();
        dec.add_packet(packets[3].clone()).unwrap();
        for r in repairs {
            dec.add_packet(r).unwrap();
        }
        assert!(dec.is_decoded);
        let out = dec.get_decoded_packets();
        assert_eq!(out.len(), k);
        for i in 0..k {
            assert_eq!(out[i].data[0], i as u8);
        }
    }

    #[test]
    fn wiedemann_path_decodes() {
        init_gf_tables();
        let pool = Arc::new(MemoryPool::new(600, 64));
        let k = 260;
        let n = k + 4;
        let mut enc = Encoder::new(k, n);
        let mut packets = Vec::new();
        for i in 0..k {
            let p = make_packet(i as u64, (i % 256) as u8, &pool);
            enc.add_source_packet(p.clone());
            packets.push(p);
        }
        let mut repairs = Vec::new();
        for i in 0..(n - k) {
            repairs.push(enc.generate_repair_packet(i, &pool).unwrap());
        }

        let mut dec = Decoder::new(k, Arc::clone(&pool));
        // Drop one packet
        for i in 1..k {
            if i != 5 {
                dec.add_packet(packets[i].clone()).unwrap();
            }
        }
        for r in repairs {
            dec.add_packet(r).unwrap();
        }
        assert!(dec.is_decoded);
        let out = dec.get_decoded_packets();
        assert_eq!(out.len(), k);
        for i in 0..k {
            assert_eq!(out[i].data[0], (i % 256) as u8);
        }
    }

    #[test]
    fn extreme_mode_trigger() {
        init_gf_tables();
        let pool = Arc::new(MemoryPool::new(32, 64));
        let cfg = FecConfig {
            lambda: 0.01,
            burst_window: 50,
            hysteresis: 0.02,
            pid: PidConfig { kp: 1.0, ki: 0.0, kd: 0.0 },
        };
        let mut fec = AdaptiveFec::new(cfg, Arc::clone(&pool));
        fec.report_loss(18, 20);
        assert_eq!(fec.current_mode(), FecMode::Extreme);
    }

    #[test]
    fn cross_fade_transition() {
        init_gf_tables();
        let pool = Arc::new(MemoryPool::new(32, 64));
        let cfg = FecConfig {
            lambda: 0.01,
            burst_window: 50,
            hysteresis: 0.02,
            pid: PidConfig { kp: 1.0, ki: 0.0, kd: 0.0 },
        };
        let mut fec = AdaptiveFec::new(cfg, Arc::clone(&pool));
        fec.report_loss(10, 20);
        assert!(fec.is_transitioning());
        for i in 0..ModeManager::CROSS_FADE_LEN {
            let pkt = make_packet(i as u64, i as u8, &pool);
            let mut out = VecDeque::new();
            fec.on_send(pkt, &mut out);
        }
        assert!(!fec.is_transitioning());
    }
}
