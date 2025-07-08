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
use crossbeam_queue::SegQueue;
#[cfg(unix)]
use libc::{iovec, msghdr, recvmsg, sendmsg};
use log::info;
use serde::Deserialize;
use std::any::Any;
use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
#[cfg(unix)]
use std::os::unix::io::RawFd;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, Once};
#[cfg(windows)]
use windows_sys::Win32::Networking::WinSock::{WSARecvMsg, WSASendMsg, WSABUF, WSAMSG};

#[cfg(target_os = "linux")]
mod numa {
    use libc::{c_int, c_void, size_t};
    extern "C" {
        pub fn numa_available() -> c_int;
        pub fn numa_num_configured_nodes() -> c_int;
        pub fn numa_node_of_cpu(cpu: c_int) -> c_int;
        pub fn numa_tonode_memory(start: *mut c_void, size: size_t, node: c_int);
    }
    pub fn is_available() -> bool {
        unsafe { numa_available() >= 0 }
    }
    pub fn num_nodes() -> usize {
        if is_available() {
            unsafe { numa_num_configured_nodes() as usize }
        } else {
            1
        }
    }
    pub fn current_node() -> usize {
        if !is_available() {
            return 0;
        }
        let cpu = unsafe { libc::sched_getcpu() };
        if cpu < 0 {
            0
        } else {
            unsafe { numa_node_of_cpu(cpu) as usize }
        }
    }
    pub unsafe fn move_to_node(ptr: *mut u8, size: usize, node: usize) {
        if is_available() {
            numa_tonode_memory(ptr as *mut c_void, size as size_t, node as c_int);
        }
    }
}

#[cfg(not(target_os = "linux"))]
mod numa {
    pub fn is_available() -> bool {
        false
    }
    pub fn num_nodes() -> usize {
        1
    }
    pub fn current_node() -> usize {
        0
    }
    pub unsafe fn move_to_node(_ptr: *mut u8, _size: usize, _node: usize) {}
}

// Use cpufeatures for portable runtime detection
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]

cpufeatures::new!(
    cpuid_x86,
    "avx512f",
    "avx512bw",
    "avx512vbmi",
    "avx2",
    "avx",
    "sse2",
    "vaes",
    "aes",
    "pclmulqdq"
);
#[cfg(target_arch = "aarch64")]
cpufeatures::new!(cpuid_arm, "neon", "aes", "pmull");

/// Configuration for optimization parameters passed from the CLI.
#[derive(Clone, Copy)]
pub struct OptimizeConfig {
    pub pool_capacity: usize,
    pub block_size: usize,
    pub enable_xdp: bool,
}

impl Default for OptimizeConfig {
    fn default() -> Self {
        Self {
            pool_capacity: 1024,
            block_size: 4096,
            enable_xdp: false,
        }
    }
}

impl OptimizeConfig {
    pub fn from_toml(s: &str) -> Result<Self, Box<dyn std::error::Error>> {
        #[derive(Deserialize)]
        struct Root {
            optimize: Option<Section>,
        }
        #[derive(Deserialize)]
        struct Section {
            pool_capacity: Option<usize>,
            block_size: Option<usize>,
            enable_xdp: Option<bool>,
        }
        let root: Root = toml::from_str(s)?;
        let sec = root.optimize.unwrap_or(Section {
            pool_capacity: None,
            block_size: None,
            enable_xdp: None,
        });
        Ok(Self {
            pool_capacity: sec.pool_capacity.unwrap_or(1024),
            block_size: sec.block_size.unwrap_or(4096),
            enable_xdp: sec.enable_xdp.unwrap_or(false),
        })
    }

    pub fn from_file(path: &std::path::Path) -> Result<Self, Box<dyn std::error::Error>> {
        let contents = std::fs::read_to_string(path)?;
        Self::from_toml(&contents)
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.pool_capacity == 0 {
            return Err("pool_capacity must be > 0".into());
        }
        if self.block_size == 0 {
            return Err("block_size must be > 0".into());
        }
        Ok(())
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
    AVX512BW,
    AVX512VBMI,
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
                features.insert(
                    CpuFeature::AVX512F,
                    info.has_avx512f() && info.has_avx512bw(),
                );
                features.insert(CpuFeature::AVX512BW, info.has_avx512bw());
                features.insert(CpuFeature::AVX512VBMI, info.has_avx512vbmi());

                features.insert(CpuFeature::VAES, info.has_vaes());
                features.insert(CpuFeature::AESNI, info.has_aes());
                features.insert(CpuFeature::PCLMULQDQ, info.has_pclmulqdq());
            }
            #[cfg(target_arch = "aarch64")]
            {
                let info = cpuid_arm::get();
                features.insert(CpuFeature::NEON, info.has_neon());
                features.insert(CpuFeature::AESNI, info.has_aes());
                features.insert(CpuFeature::PCLMULQDQ, info.has_pmull());
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
                telemetry!(telemetry::CPU_FEATURE_MASK.set(mask as i64));

                // determine active SIMD policy for telemetry
                let policy = if features.get(&CpuFeature::AVX512F).copied().unwrap_or(false)
                    && features
                        .get(&CpuFeature::AVX512VBMI)
                        .copied()
                        .unwrap_or(false)
                {
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
                telemetry!(telemetry::SIMD_ACTIVE.set(policy));

                DETECTOR = Some(FeatureDetector { features });
            }
        });
        unsafe { DETECTOR.as_ref().unwrap() }
    }

    /// Checks if a specific CPU feature is supported.
    pub fn has_feature(&self, feature: CpuFeature) -> bool {
        *self.features.get(&feature).unwrap_or(&false)
    }

    /// Checks if any of the provided features is supported.
    pub fn has_any(&self, feats: &[CpuFeature]) -> bool {
        feats.iter().any(|f| self.has_feature(*f))
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

    if detector.has_feature(CpuFeature::AVX512F) && detector.has_feature(CpuFeature::AVX512VBMI) {
        telemetry!(telemetry::SIMD_USAGE_AVX512.inc());
        f(&Avx512)
    } else if detector.has_feature(CpuFeature::AVX2) {
        telemetry!(telemetry::SIMD_USAGE_AVX2.inc());
        f(&Avx2)
    } else if detector.has_feature(CpuFeature::SSE2) {
        telemetry!(telemetry::SIMD_USAGE_SSE2.inc());
        f(&Sse2)
    } else if detector.has_feature(CpuFeature::PCLMULQDQ) {
        f(&Pclmulqdq)
    } else if detector.has_feature(CpuFeature::NEON) {
        telemetry!(telemetry::SIMD_USAGE_NEON.inc());
        f(&Neon)
    } else {
        telemetry!(telemetry::SIMD_USAGE_SCALAR.inc());
        f(&Scalar)
    }
}

/// Dispatches specifically for GF bitsliced operations. Only AVX512, AVX2 and
/// NEON are considered; all other architectures fall back to scalar code.
pub fn dispatch_bitslice<F, R>(f: F) -> R
where
    F: Fn(&dyn SimdPolicy) -> R,
{
    let detector = FeatureDetector::instance();

    if detector.has_feature(CpuFeature::AVX512F)
        && detector.has_feature(CpuFeature::AVX512VBMI)
        && detector.has_feature(CpuFeature::PCLMULQDQ)
    {
        f(&Avx512)
    } else if detector.has_feature(CpuFeature::AVX2)
        && detector.has_feature(CpuFeature::PCLMULQDQ)
    {
        f(&Avx2)
    } else if detector.has_feature(CpuFeature::SSE2)
        && detector.has_feature(CpuFeature::PCLMULQDQ)
    {
        f(&Sse2)
    } else if detector.has_feature(CpuFeature::NEON)
        && detector.has_feature(CpuFeature::PCLMULQDQ)
    {
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
    pools: Vec<Arc<SegQueue<AlignedBox<[u8]>>>>,
    block_size: usize,
    num_nodes: usize,
    capacity: AtomicUsize,
    in_use: AtomicUsize,
    available: AtomicUsize,
}

impl MemoryPool {
    /// Allocate a 64-byte aligned block bound to the given NUMA node.
    fn alloc_numa_block(block_size: usize, node: usize) -> AlignedBox<[u8]> {
        let mut block = AlignedBox::slice_from_default(64, block_size).unwrap();
        #[cfg(target_os = "linux")]
        unsafe {
            if numa::is_available() {
                numa::move_to_node(block.as_mut_ptr(), block_size, node);
            }
        }
        block
    }
    /// Creates a new memory pool with a specified capacity and block size.
    /// All allocated blocks are 64-byte aligned.
    pub fn new(capacity: usize, block_size: usize) -> Self {
        let nodes = numa::num_nodes();
        let mut pools = Vec::with_capacity(nodes);
        for n in 0..nodes {
            let node_cap = capacity / nodes + if n < capacity % nodes { 1 } else { 0 };
            let q = Arc::new(SegQueue::new());
            for _ in 0..node_cap {
                q.push(Self::alloc_numa_block(block_size, n));
            }
            pools.push(q);
        }
        telemetry!(telemetry::MEM_POOL_CAPACITY.set(capacity as i64));
        telemetry!(telemetry::MEM_POOL_BLOCK_SIZE.set(block_size as i64));
        telemetry!(telemetry::MEM_POOL_USAGE_BYTES.set(0));
        telemetry!(telemetry::MEM_POOL_FRAGMENTATION.set(0));
        telemetry!(telemetry::MEM_POOL_UTILIZATION.set(0));
        let pool = Self {
            pools,
            block_size,
            num_nodes: nodes,
            capacity: AtomicUsize::new(capacity),
            in_use: AtomicUsize::new(0),
            available: AtomicUsize::new(capacity),
        };
        pool.update_metrics();
        pool
    }

    fn grow(&self, new_capacity: usize) {
        while self.capacity.load(Ordering::Relaxed) < new_capacity {
            for (n, q) in self.pools.iter().enumerate() {
                if self.capacity.load(Ordering::Relaxed) >= new_capacity {
                    break;
                }
                q.push(Self::alloc_numa_block(self.block_size, n));
                self.available.fetch_add(1, Ordering::Relaxed);
                self.capacity.fetch_add(1, Ordering::Relaxed);
            }
        }
        telemetry::MEM_POOL_CAPACITY.set(self.capacity.load(Ordering::Relaxed) as i64);
        self.update_metrics();
    }

    fn update_metrics(&self) {
        let cap = self.capacity.load(Ordering::Relaxed);
        let in_use = self.in_use.load(Ordering::Relaxed);
        let avail = self.available.load(Ordering::Relaxed);
        telemetry!(telemetry::MEM_POOL_IN_USE.set(in_use as i64));
        telemetry!(telemetry::MEM_POOL_USAGE_BYTES.set((in_use * self.block_size) as i64));
        let frag = cap.saturating_sub(in_use + avail);
        telemetry!(telemetry::MEM_POOL_FRAGMENTATION.set(frag as i64));
        let util = if cap == 0 {
            0
        } else {
            (in_use * 100 / cap) as i64
        };
        telemetry!(telemetry::MEM_POOL_UTILIZATION.set(util));
    }

    /// Allocates a 64-byte aligned memory block from the pool.
    /// If the pool is empty, a new block is created.
    pub fn alloc(&self) -> AlignedBox<[u8]> {
        let node = numa::current_node();
        if let Some(queue) = self.pools.get(node) {
            if let Some(mut b) = queue.pop() {
                self.available.fetch_sub(1, Ordering::Relaxed);
                self.in_use.fetch_add(1, Ordering::Relaxed);
                self.update_metrics();
                telemetry!(telemetry::update_memory_usage());
                return b;
            }
        }
        telemetry!(telemetry::FEC_OVERFLOWS.inc());
        let new_cap = self.capacity.load(Ordering::Relaxed) * 2;
        self.grow(new_cap);
        self.in_use.fetch_add(1, Ordering::Relaxed);
        self.update_metrics();
        telemetry!(telemetry::update_memory_usage());
        Self::alloc_numa_block(self.block_size, node)
    }

    /// Returns a memory block to the pool.
    /// If the pool is full, the block is dropped.
    pub fn free(&self, mut block: AlignedBox<[u8]>) {
        block.iter_mut().for_each(|x| *x = 0);
        let node = numa::current_node();
        if self.available.load(Ordering::Relaxed) < self.capacity.load(Ordering::Relaxed) {
            if let Some(q) = self.pools.get(node) {
                q.push(block);
            }
            self.available.fetch_add(1, Ordering::Relaxed);
        }
        self.in_use.fetch_sub(1, Ordering::Relaxed);
        self.update_metrics();
        telemetry!(telemetry::update_memory_usage());
    }

    /// Adjusts the maximum number of cached blocks at runtime.
    pub fn set_capacity(&self, new_capacity: usize) {
        let current = self.capacity.load(Ordering::Relaxed);
        if new_capacity > current {
            self.grow(new_capacity);
        } else {
            // shrink: drop excess blocks
            let mut diff = current - new_capacity;
            while diff > 0 && self.available.load(Ordering::Relaxed) > 0 {
                for q in &self.pools {
                    if diff == 0 {
                        break;
                    }
                    if let Some(_) = q.pop() {
                        self.available.fetch_sub(1, Ordering::Relaxed);
                        self.capacity.fetch_sub(1, Ordering::Relaxed);
                        diff -= 1;
                    }
                }
                if diff == 0 {
                    break;
                }
            }
        }
        telemetry!(telemetry::MEM_POOL_CAPACITY.set(self.capacity.load(Ordering::Relaxed) as i64));
        self.update_metrics();
        telemetry!(telemetry::update_memory_usage());
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

#[cfg(windows)]
pub struct ZeroCopyBuffer<'a> {
    bufs: Vec<WSABUF>,
    _marker: std::marker::PhantomData<&'a [u8]>,
}

#[cfg(windows)]
impl<'a> ZeroCopyBuffer<'a> {
    pub fn new(buffers: &[&'a [u8]]) -> Self {
        let bufs = buffers
            .iter()
            .map(|b| WSABUF {
                len: b.len() as u32,
                buf: b.as_ptr() as *mut i8,
            })
            .collect();
        Self {
            bufs,
            _marker: std::marker::PhantomData,
        }
    }

    pub fn new_mut(buffers: &mut [&'a mut [u8]]) -> Self {
        let bufs = buffers
            .iter_mut()
            .map(|b| WSABUF {
                len: b.len() as u32,
                buf: b.as_mut_ptr() as *mut i8,
            })
            .collect();
        Self {
            bufs,
            _marker: std::marker::PhantomData,
        }
    }

    pub fn send(&self, sock: windows_sys::Win32::Networking::WinSock::SOCKET) -> i32 {
        let mut msg = WSAMSG {
            name: core::ptr::null_mut(),
            namelen: 0,
            lpBuffers: self.bufs.as_ptr() as *mut _,
            dwBufferCount: self.bufs.len() as u32,
            Control: WSABUF {
                len: 0,
                buf: core::ptr::null_mut(),
            },
            dwFlags: 0,
        };
        let mut sent: u32 = 0;
        unsafe { WSASendMsg(sock, &msg, 0, &mut sent, core::ptr::null_mut(), None) };
        sent as i32
    }

    pub fn send_to(
        &self,
        sock: windows_sys::Win32::Networking::WinSock::SOCKET,
        addr: SocketAddr,
    ) -> i32 {
        use socket2::SockAddr;
        let sockaddr = SockAddr::from(addr);
        let mut msg = WSAMSG {
            name: sockaddr.as_ptr() as *mut _,
            namelen: sockaddr.len(),
            lpBuffers: self.bufs.as_ptr() as *mut _,
            dwBufferCount: self.bufs.len() as u32,
            Control: WSABUF {
                len: 0,
                buf: core::ptr::null_mut(),
            },
            dwFlags: 0,
        };
        let mut sent: u32 = 0;
        unsafe { WSASendMsg(sock, &msg, 0, &mut sent, core::ptr::null_mut(), None) };
        sent as i32
    }

    pub fn recv(&mut self, sock: windows_sys::Win32::Networking::WinSock::SOCKET) -> i32 {
        let mut msg = WSAMSG {
            name: core::ptr::null_mut(),
            namelen: 0,
            lpBuffers: self.bufs.as_mut_ptr(),
            dwBufferCount: self.bufs.len() as u32,
            Control: WSABUF {
                len: 0,
                buf: core::ptr::null_mut(),
            },
            dwFlags: 0,
        };
        let mut recvd: u32 = 0;
        unsafe { WSARecvMsg(sock, &mut msg, &mut recvd, core::ptr::null_mut(), None) };
        recvd as i32
    }

    pub fn recv_from(
        &mut self,
        sock: windows_sys::Win32::Networking::WinSock::SOCKET,
    ) -> io::Result<(i32, SocketAddr)> {
        use socket2::SockAddr;
        use windows_sys::Win32::Networking::WinSock::SOCKADDR_STORAGE;
        let mut storage: SOCKADDR_STORAGE = unsafe { core::mem::zeroed() };
        let mut msg = WSAMSG {
            name: &mut storage as *mut _ as *mut _,
            namelen: core::mem::size_of::<SOCKADDR_STORAGE>() as u32,
            lpBuffers: self.bufs.as_mut_ptr(),
            dwBufferCount: self.bufs.len() as u32,
            Control: WSABUF {
                len: 0,
                buf: core::ptr::null_mut(),
            },
            dwFlags: 0,
        };
        let mut recvd: u32 = 0;
        let ret = unsafe { WSARecvMsg(sock, &mut msg, &mut recvd, core::ptr::null_mut(), None) };
        if ret == 0 {
            let addr = unsafe {
                SockAddr::from_raw_parts(&storage as *const _ as *const _, msg.namelen)
                    .as_socket()
                    .unwrap()
            };
            Ok((recvd as i32, addr))
        } else {
            Err(io::Error::last_os_error())
        }
    }

    pub fn len(&self) -> usize {
        self.bufs.iter().map(|b| b.len as usize).sum()
    }

    pub fn is_empty(&self) -> bool {
        self.bufs.is_empty()
    }
}

#[cfg(windows)]
impl<'a> Drop for ZeroCopyBuffer<'a> {
    fn drop(&mut self) {
        self.bufs.clear();
    }
}
// --- Placeholder for full integration ---

pub struct OptimizationManager {
    memory_pool: Arc<MemoryPool>,
    xdp_available: bool,
    use_xdp: bool,
}

impl OptimizationManager {
    pub fn new_with_config(capacity: usize, block_size: usize, enable_xdp: bool) -> Self {
        let supported = XdpSocket::is_supported();
        info!("XDP available: {}", supported);
        let enabled = enable_xdp && supported;
        telemetry!(telemetry::XDP_ACTIVE.set(if enabled { 1 } else { 0 }));
        Self {
            memory_pool: Arc::new(MemoryPool::new(capacity, block_size)),
            xdp_available: supported,
            use_xdp: enabled,
        }
    }

    pub fn from_cfg(cfg: OptimizeConfig) -> Self {
        Self::new_with_config(cfg.pool_capacity, cfg.block_size, cfg.enable_xdp)
    }

    pub fn new() -> Self {
        Self::new_with_config(1024, 4096, false)
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

    pub fn is_xdp_enabled(&self) -> bool {
        self.use_xdp
    }

    pub fn memory_pool(&self) -> Arc<MemoryPool> {
        Arc::clone(&self.memory_pool)
    }

    pub fn create_xdp_socket(&self, bind: SocketAddr, remote: SocketAddr) -> Option<XdpSocket> {
        if !self.xdp_available || !self.use_xdp {
            return None;
        }

        match XdpSocket::new(bind, remote) {
            Ok(sock) => Some(sock),
            Err(e) => {
                info!("XDP init failed, falling back to UDP: {}", e);
                Some(XdpSocket::new_udp(bind, remote).ok()?)
            }
        }
    }
}

impl Default for OptimizationManager {
    fn default() -> Self {
        Self::new()
    }
}
