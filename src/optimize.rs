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

use aligned_box::{AlignedBox, MIN_ALIGN};
use std::any::Any;
use std::collections::HashMap;
use std::sync::{Arc, Once};
use log::info;
use std::net::SocketAddr;
use crate::xdp_socket::XdpSocket;
use crossbeam_queue::ArrayQueue;
#[cfg(target_arch = "aarch64")]
use std::arch::is_aarch64_feature_detected;
#[cfg(target_arch = "x86_64")]
use std::arch::is_x86_feature_detected;
#[cfg(unix)]
use std::os::unix::io::RawFd;
#[cfg(unix)]
use libc::{msghdr, iovec, sendmsg};

/// Enumerates the CPU features relevant for QuicFuscate's optimizations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CpuFeature {
    // x86/x64 features
    AVX,
    AVX2,
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
            #[cfg(target_arch = "x86_64")]
            {
                features.insert(CpuFeature::AVX, is_x86_feature_detected!("avx"));
                features.insert(CpuFeature::AVX2, is_x86_feature_detected!("avx2"));
                features.insert(CpuFeature::AVX512F, is_x86_feature_detected!("avx512f"));
                features.insert(CpuFeature::VAES, is_x86_feature_detected!("vaes"));
                features.insert(CpuFeature::AESNI, is_x86_feature_detected!("aes"));
                features.insert(CpuFeature::PCLMULQDQ, is_x86_feature_detected!("pclmulqdq"));
            }
            #[cfg(target_arch = "aarch64")]
            {
                features.insert(CpuFeature::NEON, is_aarch64_feature_detected!("neon"));
            }

            // Unsafe block is required to initialize the static mutable variable.
            // `Once::call_once` guarantees this is safe and runs only once.
            unsafe {
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
pub struct MemoryPool {
    pool: Arc<ArrayQueue<AlignedBox<[u8]>>>,
    block_size: usize,
}

impl MemoryPool {
    /// Creates a new memory pool with a specified capacity and block size.
    /// All allocated blocks are 64-byte aligned.
    pub fn new(capacity: usize, block_size: usize) -> Self {
        let pool = ArrayQueue::new(capacity);
        for _ in 0..capacity {
            // Pre-allocate blocks with 64-byte alignment for optimal cache performance.
            let mut aligned_box = AlignedBox::new_zeroed(block_size, MIN_ALIGN);
            pool.push(aligned_box).unwrap();
        }
        Self {
            pool: Arc::new(pool),
            block_size,
        }
    }

    /// Allocates a 64-byte aligned memory block from the pool.
    /// If the pool is empty, a new block is created.
    pub fn alloc(&self) -> AlignedBox<[u8]> {
        self.pool.pop().unwrap_or_else(|| AlignedBox::new_zeroed(self.block_size, MIN_ALIGN))
    }

    /// Returns a memory block to the pool.
    /// If the pool is full, the block is dropped.
    pub fn free(&self, mut block: AlignedBox<[u8]>) {
        // Ensure the block is cleared before reuse to prevent data leaks.
        block.iter_mut().for_each(|x| *x = 0);
        let _ = self.pool.push(block);
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
        Self { iovecs, _marker: std::marker::PhantomData }
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
}
// --- Placeholder for full integration ---

pub struct OptimizationManager {
    memory_pool: MemoryPool,
    xdp_available: bool,
}

impl OptimizationManager {
    pub fn new() -> Self {
        // Default values for capacity and block size, can be made configurable later.
        let xdp_available = XdpSocket::is_supported();
        info!("XDP available: {}", xdp_available);
        Self {
            memory_pool: MemoryPool::new(1024, 4096),
            xdp_available,
        }
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