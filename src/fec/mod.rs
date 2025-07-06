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
use log::{debug, error, info};
use aligned_box::AlignedBox;
use rayon::prelude::*;
use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

pub mod gf_tables;
pub mod encoder;
pub use gf_tables::*;
pub mod adaptive;
pub use adaptive::*;
pub mod decoder;
pub use decoder::*;
pub use encoder::*;
pub struct KalmanFilter {
    estimate: f32,
    error_cov: f32,
    q: f32,
    r: f32,
}
impl KalmanFilter {
    fn new(q: f32, r: f32) -> Self {
        Self {
            estimate: 0.0,
            error_cov: 1.0,
            q,
            r,
        }
    }

    fn update(&mut self, measurement: f32) -> f32 {
        self.error_cov += self.q;
        let k = self.error_cov / (self.error_cov + self.r);
        self.estimate += k * (measurement - self.estimate);
        self.error_cov *= 1.0 - k;
        self.estimate
    }
}



            /*
             * In the original implementation this section handled FEC mode
             * transitions using a cross-fade algorithm. The surrounding
             * structs and logic are not present in this trimmed source, so the
             * code would not compile. It is left commented out to avoid stray
             * braces while keeping a hint of the intended behaviour.
             */
            // self.transition_decoder = Some(std::mem::replace(
            //     &mut self.decoder,
            //     DecoderVariant::new(old_mode, ok, Arc::clone(&self.mem_pool)),
            // ));
            // self.transition_left = ModeManager::CROSS_FADE_LEN;
            // } else {
            //     self.encoder = EncoderVariant::new(new_mode, k, n);
            //     self.decoder = DecoderVariant::new(new_mode, k, Arc::clone(&self.mem_pool));
            // }
        // }
        // The corresponding closing blocks for the removed implementation are
        // intentionally omitted in this trimmed version.
    // }

// [Die Tests wurden oben nicht verändert und bleiben wie im Input – ebenfalls konfliktfrei!]
//
//     * Neither the name of the copyright holder nor the names of its
//       contributors may be used to endorse or promote products derived from
//       this

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
            data: Some(buf),
            len: 8,
            is_systematic: true,
            coefficients: None,
            mem_pool: Arc::clone(pool),
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
            assert_eq!(out[i].data.as_ref().unwrap()[0], i as u8);
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
            assert_eq!(out[i].data.as_ref().unwrap()[0], (i % 256) as u8);
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
            pid: PidConfig {
                kp: 1.0,
                ki: 0.0,
                kd: 0.0,
            },
            initial_mode: FecMode::Zero,
            kalman_enabled: false,
            kalman_q: 0.001,
            kalman_r: 0.01,
            window_sizes: FecConfig::default_windows(),
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
            pid: PidConfig {
                kp: 1.0,
                ki: 0.0,
                kd: 0.0,
            },
            initial_mode: FecMode::Zero,
            kalman_enabled: false,
            kalman_q: 0.001,
            kalman_r: 0.01,
            window_sizes: FecConfig::default_windows(),
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

    #[test]
    fn parse_config_toml() {
        let cfg_str = r#"
            [adaptive_fec]
            lambda = 0.05
            burst_window = 30
            hysteresis = 0.01
            pid = { kp = 1.5, ki = 0.2, kd = 0.1 }
            kalman_enabled = true
            kalman_q = 0.002
            kalman_r = 0.02

            [[adaptive_fec.modes]]
            name = "light"
            w0 = 20

            [[adaptive_fec.modes]]
            name = "extreme"
            w0 = 2048
        "#;
        let cfg = FecConfig::from_toml(cfg_str).unwrap();
        assert_eq!(cfg.pid.kp, 1.5);
        assert_eq!(cfg.window_sizes[&FecMode::Light], 20);
        assert_eq!(cfg.window_sizes[&FecMode::Extreme], 2048);
        assert_eq!(cfg.lambda, 0.05);
        assert_eq!(cfg.burst_window, 30);
        assert!(cfg.kalman_enabled);
        assert!((cfg.kalman_q - 0.002).abs() < 1e-6);
        assert!((cfg.kalman_r - 0.02).abs() < 1e-6);
    }

    #[test]
    fn adaptive_transition_from_toml() {
        init_gf_tables();
        let pool = Arc::new(MemoryPool::new(32, 64));
        let cfg_str = r#"
            [adaptive_fec]
            lambda = 0.1
            burst_window = 10
            hysteresis = 0.02
            pid = { kp = 1.0, ki = 0.0, kd = 0.0 }

            [[adaptive_fec.modes]]
            name = "extreme"
            w0 = 1024
        "#;
        let cfg = FecConfig::from_toml(cfg_str).unwrap();
        let mut fec = AdaptiveFec::new(cfg, Arc::clone(&pool));
        fec.report_loss(15, 20);
        assert_eq!(fec.current_mode(), FecMode::Extreme);
    }

    #[test]
    fn recovery_low_loss() {
        init_gf_tables();
        let pool = Arc::new(MemoryPool::new(64, 64));
        let k = 10;
        let n = 12;
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
        for (idx, pkt) in packets.into_iter().enumerate() {
            if idx != 3 {
                dec.add_packet(pkt).unwrap();
            }
        }
        for r in repairs {
            dec.add_packet(r).unwrap();
        }
        assert!(dec.is_decoded);
    }

    #[test]
    fn recovery_high_loss() {
        init_gf_tables();
        let pool = Arc::new(MemoryPool::new(128, 64));
        let k = 16;
        let n = 32;
        let mut enc = Encoder::new(k, n);
        let mut packets = Vec::new();
        for i in 0..k {
            let p = make_packet(i as u64, (i % 255) as u8, &pool);
            enc.add_source_packet(p.clone());
            packets.push(p);
        }
        let mut repairs = Vec::new();
        for i in 0..(n - k) {
            repairs.push(enc.generate_repair_packet(i, &pool).unwrap());
        }
        let mut dec = Decoder::new(k, Arc::clone(&pool));
        for (idx, pkt) in packets.into_iter().enumerate() {
            if idx % 2 == 0 {
                dec.add_packet(pkt).unwrap();
            }
        }
        for (i, r) in repairs.into_iter().enumerate() {
            if i % 3 != 0 {
                dec.add_packet(r).unwrap();
            }
        }
        assert!(dec.is_decoded);
    }

    #[test]
    fn extreme_mode_recovery() {
        init_gf_tables();
        let pool = Arc::new(MemoryPool::new(2048, 64));
        let k = 64;
        let n = k + 16;
        let mut enc = Encoder16::new(k, n);
        let mut packets = Vec::new();
        for i in 0..k {
            let p = make_packet(i as u64, (i % 255) as u8, &pool);
            enc.add_source_packet(p.clone());
            packets.push(p);
        }
        let mut repairs = Vec::new();
        for i in 0..(n - k) {
            repairs.push(enc.generate_repair_packet(i, &pool).unwrap());
        }
        let mut dec = Decoder16::new(k, Arc::clone(&pool));
        for (idx, pkt) in packets.into_iter().enumerate() {
            if idx % 3 != 0 {
                dec.add_packet(pkt).unwrap();
            }
        }
        for r in repairs {
            dec.add_packet(r).unwrap();
        }
        assert!(dec.is_decoded);
        let out = dec.get_decoded_packets();
        assert_eq!(out.len(), k);
        for i in 0..k {
            assert_eq!(out[i].data.as_ref().unwrap()[0], (i % 255) as u8);
        }
    }

    #[test]
    fn very_large_window_recovery() {
        init_gf_tables();
        let pool = Arc::new(MemoryPool::new(4096, 64));
        let k = 1024;
        let n = k + 8;
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
        for (idx, pkt) in packets.into_iter().enumerate() {
            if idx % 5 != 0 {
                dec.add_packet(pkt).unwrap();
            }
        }
        for r in repairs {
            dec.add_packet(r).unwrap();
        }
        assert!(dec.is_decoded);
        let out = dec.get_decoded_packets();
        assert_eq!(out.len(), k);
        for i in 0..k {
            assert_eq!(out[i].data.as_ref().unwrap()[0], (i % 256) as u8);
        }
    }
}
