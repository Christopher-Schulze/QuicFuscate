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

//! # Optimization Module
//!
//! This module provides a framework for runtime CPU feature detection and
//! function dispatching to select the best hardware-accelerated implementation.
//! It also includes foundational structures for zero-copy operations and memory pooling.

use crate::xdp_socket::XdpSocket;
use aligned_box::AlignedBox;
#[cfg(unix)]
use libc::{iovec, msghdr, recvmsg, sendmsg};
use log::info;
use crate::telemetry;
use cpufeatures;
use std::any::Any;
#[cfg(target_arch = "aarch64")]
use std::arch::is_aarch64_feature_detected;
#[cfg(target_arch = "x86_64")]
use std::arch::is_x86_feature_detected;
use std::collections::HashMap;
use std::net::SocketAddr;
#[cfg(unix)]
use std::os::unix::io::RawFd;
use std::sync::{Arc, Once, Mutex};
use std::sync::atomic::{AtomicUsize, Ordering};

// Use cpufeatures for portable runtime detection
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
cpufeatures::new!(feat_avx512f, "avx512f");
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
cpufeatures::new!(feat_avx2, "avx2");
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
cpufeatures::new!(feat_sse2, "sse2");
#[cfg(target_arch = "aarch64")]
cpufeatures::new!(feat_neon, "neon");

/// Configuration for optimization parameters passed from the CLI.
#[derive(Clone, Copy)]
pub struct OptimizeConfig {
    pub pool_capacity: usize,
    pub block_size: usize,
}

impl Default for OptimizeConfig {
    fn default() -> Self {
        Self {
            pool_capacity: 1024,
            block_size: 4096,
        }
    }
}

/// Enumerates the CPU features relevant for QuicFuscate's optimizations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CpuFeature {
    // x86/x64 features
    AVX,
    AVX2,
    SSE2,
    AVX512F,
    VAES,
    AESNI,
    PCLMULQDQ,

    // ARM features
    NEON,
}

/// Singleton for accessing detected CPU features.
/// This ensures that feature detection is performed only once.
pub struct FeatureDetector {
    features: HashMap<CpuFeature, bool>,
}

static INIT: Once = Once::new();
static mut DETECTOR: Option<FeatureDetector> = None;

impl FeatureDetector {
    /// Returns a static reference to the `FeatureDetector` singleton.
    /// The first call will initialize the detector.
    pub fn instance() -> &'static Self {
        INIT.call_once(|| {
            let mut features = HashMap::new();

            // Detect features for the current architecture at runtime.
            #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
            {
                features.insert(CpuFeature::AVX, is_x86_feature_detected!("avx"));
                features.insert(CpuFeature::AVX2, feat_avx2::get());
                features.insert(CpuFeature::SSE2, feat_sse2::get());
                features.insert(CpuFeature::AVX512F, feat_avx512f::get());
                features.insert(CpuFeature::VAES, is_x86_feature_detected!("vaes"));
                features.insert(CpuFeature::AESNI, is_x86_feature_detected!("aes"));
                features.insert(CpuFeature::PCLMULQDQ, is_x86_feature_detected!("pclmulqdq"));
            }
            #[cfg(target_arch = "aarch64")]
            {
                features.insert(CpuFeature::NEON, feat_neon::get());
            }

            // Unsafe block is required to initialize the static mutable variable.
            // `Once::call_once` guarantees this is safe and runs only once.
            unsafe {
                let mask = features.iter().fold(0u64, |m, (k, v)| {
                    if *v {
                        m | (1u64 << (*k as u8))
                    } else {
                        m
                    }
                });
                telemetry::CPU_FEATURE_MASK.set(mask as i64);

                // determine active SIMD policy for telemetry
                let policy = if features.get(&CpuFeature::AVX512F).copied().unwrap_or(false) {
                    3
                } else if features.get(&CpuFeature::AVX2).copied().unwrap_or(false) {
                    2
                } else if features.get(&CpuFeature::SSE2).copied().unwrap_or(false)
                    || features.get(&CpuFeature::NEON).copied().unwrap_or(false)
                {
                    1
                } else {
                    0
                };
                telemetry::SIMD_ACTIVE.set(policy);

                DETECTOR = Some(FeatureDetector { features });
            }
        });
        unsafe { DETECTOR.as_ref().unwrap() }
    }

    /// Checks if a specific CPU feature is supported.
    pub fn has_feature(&self, feature: CpuFeature) -> bool {
        *self.features.get(&feature).unwrap_or(&false)
    }
}

//
// SIMD Dispatching
//

/// Represents the execution policy for SIMD operations.
pub trait SimdPolicy: Any {
    fn as_any(&self) -> &dyn Any;
}

/// Marker struct for AVX-512 execution.
pub struct Avx512;
impl SimdPolicy for Avx512 {
    fn as_any(&self) -> &dyn Any {
        self
    }
}

/// Marker struct for AVX2 execution.
pub struct Avx2;
impl SimdPolicy for Avx2 {
    fn as_any(&self) -> &dyn Any {
        self
    }
}

/// Marker struct for SSE2 execution.
pub struct Sse2;
impl SimdPolicy for Sse2 {
    fn as_any(&self) -> &dyn Any {
        self
    }
}

/// Marker struct for PCLMULQDQ execution.
pub struct Pclmulqdq;
impl SimdPolicy for Pclmulqdq {
    fn as_any(&self) -> &dyn Any {
        self
    }
}

/// Marker struct for ARM NEON execution.
pub struct Neon;
impl SimdPolicy for Neon {
    fn as_any(&self) -> &dyn Any {
        self
    }
}

/// Marker struct for scalar (non-SIMD) execution.
pub struct Scalar;
impl SimdPolicy for Scalar {
    fn as_any(&self) -> &dyn Any {
        self
    }
}

/// Dispatches to the best available SIMD implementation at runtime.
/// The policies are ordered from most to least performant.
pub fn dispatch<F, R>(f: F) -> R
where
    F: Fn(&dyn SimdPolicy) -> R,
{
    let detector = FeatureDetector::instance();

    if detector.has_feature(CpuFeature::AVX512F) {
        f(&Avx512)
    } else if detector.has_feature(CpuFeature::AVX2) {
        f(&Avx2)
    } else if detector.has_feature(CpuFeature::SSE2) {
        f(&Sse2)
    } else if detector.has_feature(CpuFeature::PCLMULQDQ) {
        f(&Pclmulqdq)
    } else if detector.has_feature(CpuFeature::NEON) {
        f(&Neon)
    } else {
        f(&Scalar)
    }
}

//
// Foundational Structures for Global Optimizations
//

/// A high-performance, thread-safe memory pool for fixed-size blocks.
/// This implementation uses a concurrent queue to manage free blocks,
/// minimizing lock contention and fragmentation.
#[derive(Clone)]
pub struct MemoryPool {
    pool: Arc<Mutex<Vec<AlignedBox<[u8]>>>>,
    block_size: usize,
    capacity: Arc<AtomicUsize>,
    in_use: AtomicUsize,
}

impl MemoryPool {
    /// Creates a new memory pool with a specified capacity and block size.
    /// All allocated blocks are 64-byte aligned.
    pub fn new(capacity: usize, block_size: usize) -> Self {
        let mut vec = Vec::with_capacity(capacity);
        for _ in 0..capacity {
            let aligned_box = AlignedBox::slice_from_default(64, block_size).unwrap();
            vec.push(aligned_box);
        }
        telemetry::MEM_POOL_CAPACITY.set(capacity as i64);
        telemetry::MEM_POOL_USAGE_BYTES.set(0);
        Self {
            pool: Arc::new(Mutex::new(vec)),
            block_size,
            capacity: Arc::new(AtomicUsize::new(capacity)),
            in_use: AtomicUsize::new(0),
        }
    }

    fn grow(&self, new_capacity: usize) {
        let mut pool = self.pool.lock().unwrap();
        if new_capacity > pool.len() {
            for _ in pool.len()..new_capacity {
                pool.push(AlignedBox::slice_from_default(64, self.block_size).unwrap());
            }
            self.capacity.store(new_capacity, Ordering::Relaxed);
            telemetry::MEM_POOL_CAPACITY.set(new_capacity as i64);
            let cnt = self.in_use.load(Ordering::Relaxed);
            telemetry::MEM_POOL_USAGE_BYTES.set((cnt * self.block_size) as i64);
        }
    }

    /// Allocates a 64-byte aligned memory block from the pool.
    /// If the pool is empty, a new block is created.
    pub fn alloc(&self) -> AlignedBox<[u8]> {
        let mut pool = self.pool.lock().unwrap();
        if let Some(b) = pool.pop() {
            let cnt = self.in_use.fetch_add(1, Ordering::Relaxed) + 1;
            telemetry::MEM_POOL_IN_USE.set(cnt as i64);
            telemetry::MEM_POOL_USAGE_BYTES.set((cnt * self.block_size) as i64);
            return b;
        }
        drop(pool);
        telemetry::FEC_OVERFLOWS.inc();
        let new_cap = self.capacity.load(Ordering::Relaxed) * 2;
        self.grow(new_cap);
        let mut pool = self.pool.lock().unwrap();
        let block = pool.pop().unwrap();
        let cnt = self.in_use.fetch_add(1, Ordering::Relaxed) + 1;
        telemetry::MEM_POOL_IN_USE.set(cnt as i64);
        telemetry::MEM_POOL_USAGE_BYTES.set((cnt * self.block_size) as i64);
        block
    }

    /// Returns a memory block to the pool.
    /// If the pool is full, the block is dropped.
    pub fn free(&self, mut block: AlignedBox<[u8]>) {
        block.iter_mut().for_each(|x| *x = 0);
        let mut pool = self.pool.lock().unwrap();
        if pool.len() < self.capacity.load(Ordering::Relaxed) {
            pool.push(block);
        }
        let cnt = self.in_use.fetch_sub(1, Ordering::Relaxed) - 1;
        telemetry::MEM_POOL_IN_USE.set(cnt as i64);
        telemetry::MEM_POOL_USAGE_BYTES.set((cnt * self.block_size) as i64);
    }

    /// Adjusts the maximum number of cached blocks at runtime.
    pub fn set_capacity(&self, new_capacity: usize) {
        self.capacity.store(new_capacity, Ordering::Relaxed);
        telemetry::MEM_POOL_CAPACITY.set(new_capacity as i64);
        let mut pool = self.pool.lock().unwrap();
        while pool.len() > new_capacity {
            pool.pop();
        }
        while pool.len() < new_capacity {
            pool.push(AlignedBox::slice_from_default(64, self.block_size).unwrap());
        }
        let cnt = self.in_use.load(Ordering::Relaxed);
        telemetry::MEM_POOL_USAGE_BYTES.set((cnt * self.block_size) as i64);
    }
}

/// A buffer designed for zero-copy vectored I/O operations using `sendmsg`.
/// This allows sending data from multiple non-contiguous memory regions
/// in a single system call, avoiding intermediate copies.
#[cfg(unix)]
pub struct ZeroCopyBuffer<'a> {
    iovecs: Vec<iovec>,
    _marker: std::marker::PhantomData<&'a [u8]>,
}

#[cfg(unix)]
impl<'a> ZeroCopyBuffer<'a> {
    /// Creates a new `ZeroCopyBuffer` from a slice of byte slices.
    pub fn new(buffers: &[&'a [u8]]) -> Self {
        let iovecs = buffers
            .iter()
            .map(|buf| iovec {
                iov_base: buf.as_ptr() as *mut libc::c_void,
                iov_len: buf.len(),
            })
            .collect();
        Self {
            iovecs,
            _marker: std::marker::PhantomData,
        }
    }

    /// Creates a new `ZeroCopyBuffer` from mutable slices for receiving.
    pub fn new_mut(buffers: &mut [&'a mut [u8]]) -> Self {
        let iovecs = buffers
            .iter_mut()
            .map(|buf| iovec {
                iov_base: buf.as_mut_ptr() as *mut libc::c_void,
                iov_len: buf.len(),
            })
            .collect();
        Self {
            iovecs,
            _marker: std::marker::PhantomData,
        }
    }

    /// Sends the data using `sendmsg` for true zero-copy transmission.
    pub fn send(&self, fd: RawFd) -> isize {
        let msg = msghdr {
            msg_name: std::ptr::null_mut(),
            msg_namelen: 0,
            msg_iov: self.iovecs.as_ptr() as *mut _,
            msg_iovlen: self.iovecs.len() as _,
            msg_control: std::ptr::null_mut(),
            msg_controllen: 0,
            msg_flags: 0,
        };
        unsafe { sendmsg(fd, &msg, 0) }
    }

    /// Receives data using `recvmsg` into the buffers.
    pub fn recv(&mut self, fd: RawFd) -> isize {
        let mut msg = msghdr {
            msg_name: std::ptr::null_mut(),
            msg_namelen: 0,
            msg_iov: self.iovecs.as_mut_ptr(),
            msg_iovlen: self.iovecs.len() as _,
            msg_control: std::ptr::null_mut(),
            msg_controllen: 0,
            msg_flags: 0,
        };
        unsafe { recvmsg(fd, &mut msg, 0) }
    }

    /// Returns the total length represented by all iovecs.
    pub fn len(&self) -> usize {
        self.iovecs.iter().map(|iov| iov.iov_len).sum()
    }

    pub fn is_empty(&self) -> bool {
        self.iovecs.is_empty()
    }

    pub fn as_iovecs(&self) -> &[iovec] {
        &self.iovecs
    }
}

#[cfg(unix)]
impl<'a> Drop for ZeroCopyBuffer<'a> {
    fn drop(&mut self) {
        self.iovecs.clear();
    }
}
// --- Placeholder for full integration ---

pub struct OptimizationManager {
    memory_pool: Arc<MemoryPool>,
    xdp_available: bool,
}

impl OptimizationManager {
    pub fn new_with_config(capacity: usize, block_size: usize) -> Self {
        let xdp_available = XdpSocket::is_supported();
        info!("XDP available: {}", xdp_available);
        Self {
            memory_pool: Arc::new(MemoryPool::new(capacity, block_size)),
            xdp_available,
        }
    }

    pub fn from_cfg(cfg: OptimizeConfig) -> Self {
        Self::new_with_config(cfg.pool_capacity, cfg.block_size)
    }

    pub fn new() -> Self {
        Self::new_with_config(1024, 4096)
    }

    pub fn alloc_block(&self) -> AlignedBox<[u8]> {
        self.memory_pool.alloc()
    }

    pub fn free_block(&self, block: AlignedBox<[u8]>) {
        self.memory_pool.free(block);
    }

    pub fn is_xdp_available(&self) -> bool {
        self.xdp_available
    }

    pub fn memory_pool(&self) -> Arc<MemoryPool> {
        Arc::clone(&self.memory_pool)
    }

    pub fn create_xdp_socket(&self, bind: SocketAddr, remote: SocketAddr) -> Option<XdpSocket> {
        if self.xdp_available {
            XdpSocket::new(bind, remote).ok()
        } else {
            None
        }
    }
}

impl Default for OptimizationManager {
    fn default() -> Self {
        Self::new()
    }
}
