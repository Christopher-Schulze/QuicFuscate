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

use crate::telemetry;
use crate::xdp_socket::XdpSocket;
use aligned_box::AlignedBox;
use cpufeatures;
#[cfg(unix)]
use libc::{iovec, msghdr, recvmsg, sendmsg};
use log::info;
use std::any::Any;
use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
#[cfg(unix)]
use std::os::unix::io::RawFd;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, Once};

#[cfg(target_os = "linux")]
extern "C" {
    fn numa_available() -> libc::c_int;
    fn numa_tonode_memory(start: *mut libc::c_void, size: libc::size_t, node: libc::c_int);
}

// Use cpufeatures for portable runtime detection
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
cpufeatures::new!(
    cpuid_x86,
    "avx512f",
    "avx2",
    "avx",
    "sse2",
    "vaes",
    "aes",
    "pclmulqdq"
);
#[cfg(target_arch = "aarch64")]
cpufeatures::new!(cpuid_arm, "neon");

/// Configuration for optimization parameters passed from the CLI.
#[derive(Clone, Copy)]
pub struct OptimizeConfig {
    pub pool_capacity: usize,
    pub block_size: usize,
    pub transparent_hugepages: bool,
    pub numa_node: Option<i32>,
}

impl Default for OptimizeConfig {
    fn default() -> Self {
        Self {
            pool_capacity: 1024,
            block_size: 4096,
            transparent_hugepages: false,
            numa_node: None,
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
                let info = cpuid_x86::get();
                features.insert(CpuFeature::AVX, info.has_avx());
                features.insert(CpuFeature::AVX2, info.has_avx2());
                features.insert(CpuFeature::SSE2, info.has_sse2());
                features.insert(CpuFeature::AVX512F, info.has_avx512f());
                features.insert(CpuFeature::VAES, info.has_vaes());
                features.insert(CpuFeature::AESNI, info.has_aes());
                features.insert(CpuFeature::PCLMULQDQ, info.has_pclmulqdq());
            }
            #[cfg(target_arch = "aarch64")]
            {
                let info = cpuid_arm::get();
                features.insert(CpuFeature::NEON, info.has_neon());
            }

            // Unsafe block is required to initialize the static mutable variable.
            // `Once::call_once` guarantees this is safe and runs only once.
            unsafe {
                let mask =
                    features.iter().fold(
                        0u64,
                        |m, (k, v)| {
                            if *v {
                                m | (1u64 << (*k as u8))
                            } else {
                                m
                            }
                        },
                    );
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
        telemetry::SIMD_USAGE_AVX512.inc();
        f(&Avx512)
    } else if detector.has_feature(CpuFeature::AVX2) {
        telemetry::SIMD_USAGE_AVX2.inc();
        f(&Avx2)
    } else if detector.has_feature(CpuFeature::SSE2) {
        telemetry::SIMD_USAGE_SSE2.inc();
        f(&Sse2)
    } else if detector.has_feature(CpuFeature::PCLMULQDQ) {
        f(&Pclmulqdq)
    } else if detector.has_feature(CpuFeature::NEON) {
        telemetry::SIMD_USAGE_NEON.inc();
        f(&Neon)
    } else {
        telemetry::SIMD_USAGE_SCALAR.inc();
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
    use_thp: bool,
    numa_node: Option<i32>,
}

impl MemoryPool {
    /// Creates a new memory pool with a specified capacity and block size.
    /// All allocated blocks are 64-byte aligned.
    pub fn new(capacity: usize, block_size: usize, use_thp: bool, numa_node: Option<i32>) -> Self {
        let mut vec = Vec::with_capacity(capacity);
        for _ in 0..capacity {
            let mut aligned_box = AlignedBox::slice_from_default(64, block_size).unwrap();
            Self::apply_advise(&mut aligned_box, block_size, use_thp, numa_node);
            vec.push(aligned_box);
        }
        telemetry::MEM_POOL_CAPACITY.set(capacity as i64);
        telemetry::MEM_POOL_USAGE_BYTES.set(0);
        telemetry::MEM_POOL_BLOCK_SIZE.set(block_size as i64);
        telemetry::MEM_POOL_TOTAL_BYTES.set((capacity * block_size) as i64);
        telemetry::MEM_POOL_FREE.set(capacity as i64);
        Self {
            pool: Arc::new(Mutex::new(vec)),
            block_size,
            capacity: Arc::new(AtomicUsize::new(capacity)),
            in_use: AtomicUsize::new(0),
            use_thp,
            numa_node,
        }
    }

    fn grow(&self, new_capacity: usize) {
        let pool_arc = Arc::clone(&self.pool);
        let cap = Arc::clone(&self.capacity);
        let block_size = self.block_size;
        let use_thp = self.use_thp;
        let numa_node = self.numa_node;
        std::thread::spawn(move || {
            let mut new_blocks = Vec::new();
            {
                let pool = pool_arc.lock().unwrap();
                if new_capacity <= pool.len() {
                    return;
                }
            }
            for _ in 0..(new_capacity - cap.load(Ordering::Relaxed)) {
                let mut b = AlignedBox::slice_from_default(64, block_size).unwrap();
                MemoryPool::apply_advise(&mut b, block_size, use_thp, numa_node);
                new_blocks.push(b);
            }
            let mut pool = pool_arc.lock().unwrap();
            pool.extend(new_blocks);
            cap.store(new_capacity, Ordering::Relaxed);
            telemetry::MEM_POOL_CAPACITY.set(new_capacity as i64);
            let cnt = cap.load(Ordering::Relaxed);
            let in_use = cnt - pool.len();
            telemetry::MEM_POOL_USAGE_BYTES.set((in_use * block_size) as i64);
            telemetry::MEM_POOL_TOTAL_BYTES.set((cnt * block_size) as i64);
            telemetry::MEM_POOL_FREE.set(pool.len() as i64);
        });
    }

    /// Allocates a 64-byte aligned memory block from the pool.
    /// If the pool is empty, a new block is created.
    pub fn alloc(&self) -> AlignedBox<[u8]> {
        let mut pool = self.pool.lock().unwrap();
        if let Some(b) = pool.pop() {
            let cnt = self.in_use.fetch_add(1, Ordering::Relaxed) + 1;
            telemetry::MEM_POOL_IN_USE.set(cnt as i64);
            telemetry::MEM_POOL_USAGE_BYTES.set((cnt * self.block_size) as i64);
            telemetry::MEM_POOL_FREE.set(pool.len() as i64);
            telemetry::update_memory_usage();
            return b;
        }
        drop(pool);
        telemetry::FEC_OVERFLOWS.inc();
        let new_cap = self.capacity.load(Ordering::Relaxed) * 2;
        self.grow(new_cap);
        let mut block = AlignedBox::slice_from_default(64, self.block_size).unwrap();
        MemoryPool::apply_advise(&mut block, self.block_size, self.use_thp, self.numa_node);
        let cnt = self.in_use.fetch_add(1, Ordering::Relaxed) + 1;
        telemetry::MEM_POOL_IN_USE.set(cnt as i64);
        telemetry::MEM_POOL_USAGE_BYTES.set((cnt * self.block_size) as i64);
        telemetry::MEM_POOL_TOTAL_BYTES
            .set((self.capacity.load(Ordering::Relaxed) * self.block_size) as i64);
        telemetry::MEM_POOL_FREE.set((self.capacity.load(Ordering::Relaxed) - cnt) as i64);
        telemetry::update_memory_usage();
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
        telemetry::MEM_POOL_FREE.set(pool.len() as i64);
        telemetry::update_memory_usage();
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
            let mut b = AlignedBox::slice_from_default(64, self.block_size).unwrap();
            MemoryPool::apply_advise(&mut b, self.block_size, self.use_thp, self.numa_node);
            pool.push(b);
        }
        let cnt = self.in_use.load(Ordering::Relaxed);
        telemetry::MEM_POOL_USAGE_BYTES.set((cnt * self.block_size) as i64);
        telemetry::MEM_POOL_TOTAL_BYTES.set((new_capacity * self.block_size) as i64);
        telemetry::MEM_POOL_FREE.set(pool.len() as i64);
        telemetry::update_memory_usage();
    }

    fn apply_advise(
        block: &mut AlignedBox<[u8]>,
        size: usize,
        use_thp: bool,
        numa_node: Option<i32>,
    ) {
        #[cfg(target_os = "linux")]
        unsafe {
            if use_thp {
                libc::madvise(
                    block.as_mut_ptr() as *mut libc::c_void,
                    size,
                    libc::MADV_HUGEPAGE,
                );
            }
            if let Some(node) = numa_node {
                if numa_available() >= 0 {
                    numa_tonode_memory(
                        block.as_mut_ptr() as *mut libc::c_void,
                        size,
                        node as libc::c_int,
                    );
                }
            }
        }
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

    /// Sends the data to the specified address using `sendmsg`.
    pub fn send_to(&self, fd: RawFd, addr: SocketAddr) -> isize {
        use socket2::SockAddr;
        let sockaddr = SockAddr::from(addr);
        let msg = msghdr {
            msg_name: sockaddr.as_ptr() as *mut _,
            msg_namelen: sockaddr.len(),
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

    /// Receives data and returns the sender address.
    pub fn recv_from(&mut self, fd: RawFd) -> io::Result<(isize, SocketAddr)> {
        use socket2::SockAddr;
        unsafe {
            SockAddr::try_init(|storage, len| {
                let mut msg = msghdr {
                    msg_name: storage.cast(),
                    msg_namelen: *len,
                    msg_iov: self.iovecs.as_mut_ptr(),
                    msg_iovlen: self.iovecs.len() as _,
                    msg_control: std::ptr::null_mut(),
                    msg_controllen: 0,
                    msg_flags: 0,
                };
                let ret = recvmsg(fd, &mut msg, 0);
                if ret < 0 {
                    Err(io::Error::last_os_error())
                } else {
                    *len = msg.msg_namelen;
                    Ok(ret)
                }
            })
            .map(|(ret, addr)| (ret, addr.as_socket().unwrap()))
        }
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
    pub fn new_with_config(
        capacity: usize,
        block_size: usize,
        use_thp: bool,
        numa_node: Option<i32>,
    ) -> Self {
        let xdp_available = XdpSocket::is_supported();
        info!("XDP available: {}", xdp_available);
        Self {
            memory_pool: Arc::new(MemoryPool::new(capacity, block_size, use_thp, numa_node)),
            xdp_available,
        }
    }

    pub fn from_cfg(cfg: OptimizeConfig) -> Self {
        Self::new_with_config(
            cfg.pool_capacity,
            cfg.block_size,
            cfg.transparent_hugepages,
            cfg.numa_node,
        )
    }

    pub fn new() -> Self {
        Self::new_with_config(1024, 4096, false, None)
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
