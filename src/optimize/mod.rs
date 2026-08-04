//! # Optimization Module
//!
//! This module provides a framework for runtime CPU feature detection and
//! function dispatching to select the best hardware-accelerated implementation.
//! It also includes foundational structures for zero-copy operations and memory pooling.

use cpufeatures;
// CPU features re-export removed - use cpufeatures directly
use crossbeam_queue::SegQueue;
/// Brain-driven adaptive optimization hints.
pub mod brain;
/// SIMD-accelerated compression helpers (histogram, entropy).
pub mod compress;
/// SIMD-accelerated cryptographic primitives (AES, ChaCha, GF).
pub mod crypto;
/// SIMD-accelerated iterator utilities (sum, reduce).
pub mod iter;
/// Memory management and cache-aware operations.
#[cfg(any(test, feature = "rust-tests"))]
pub mod memory;
/// Random number generation and shuffle operations.
#[cfg(any(test, feature = "rust-tests", feature = "benches"))]
pub mod random;
/// SIMD-accelerated sorting algorithms.
#[cfg(any(test, feature = "rust-tests", feature = "benches"))]
pub mod sort;
/// Stealth traffic shaping optimization helpers.
pub mod stealth;
/// SIMD-accelerated string and pattern search.
pub mod string;
/// Runtime telemetry counters for optimization subsystems.
pub mod telemetry;
/// Transport-layer optimization helpers.
pub mod transport;
/// UDP fast-path and batched I/O helpers.
pub mod udp;
#[cfg(all(target_os = "linux", feature = "io_uring"))]
pub mod uring_batch;

// ============================================================================
// LIBC IMPORTS - Transport layer (sendmsg, recvmsg)
// ============================================================================
pub use aligned_box::AlignedBox;
#[cfg(all(test, feature = "unsafe_rust"))]
#[doc(hidden)]
pub(crate) mod r#unsafe;
#[cfg(unix)]
use libc::{iovec, msghdr, recvmsg, sendmsg};
use log::{error, warn};
#[cfg(unix)]
use smallvec::SmallVec;
use std::any::Any;
use std::cell::RefCell;
use std::collections::HashSet;
use std::io;
use std::net::SocketAddr;
#[cfg(unix)]
use std::os::unix::io::RawFd;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, OnceLock};

// Modular x86 SSE2 helpers (legacy acceleration)
#[cfg(target_arch = "x86_64")]
#[path = "x86_sse2.rs"]
pub mod x86_sse2;
#[cfg(target_os = "linux")]
#[derive(Clone, Copy, Debug)]
enum NumaPolicy {
    Local,
    Preferred(usize),
    Interleave,
}

#[cfg(target_os = "linux")]
static NUMA_POLICY: OnceLock<NumaPolicy> = OnceLock::new();

#[cfg(target_os = "linux")]
fn resolve_numa_policy() -> NumaPolicy {
    if let Ok(val) = std::env::var("QUICFUSCATE_NUMA_POLICY") {
        let v = val.to_lowercase();
        if v == "local" {
            return NumaPolicy::Local;
        }
        if v == "interleave" {
            return NumaPolicy::Interleave;
        }
        if let Some(rest) = v.strip_prefix("preferred:") {
            if let Ok(n) = rest.parse::<usize>() {
                return NumaPolicy::Preferred(n);
            }
        }
    }
    NumaPolicy::Local
}

#[cfg(target_os = "linux")]
static RR_NODE: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
#[cfg(windows)]
use windows_sys::Win32::Networking::WinSock::{
    WSAGetLastError, WSARecv, WSARecvFrom, WSASend, WSASendTo, WSABUF,
};

#[cfg(target_os = "linux")]
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

    pub(crate) fn move_to_node(_ptr: *mut u8, _size: usize, _node: usize) {
        // Link-free Linux fallback: preserve allocation correctness without libnuma.
    }
}

#[cfg(any(test, feature = "rust-tests"))]
impl<const N: usize> Default for ConstBuffer<N> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(target_os = "windows")]
mod numa {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use windows_sys::Win32::System::Kernel::PROCESSOR_NUMBER;
    use windows_sys::Win32::System::SystemInformation::GROUP_AFFINITY;
    use windows_sys::Win32::System::Threading::{
        GetCurrentProcessorNumberEx, GetCurrentThread, GetNumaHighestNodeNumber,
        GetNumaNodeProcessorMaskEx, GetNumaProcessorNodeEx, SetThreadGroupAffinity,
    };

    static NUMA_NODES: AtomicUsize = AtomicUsize::new(0);

    pub fn is_available() -> bool {
        unsafe {
            let mut highest_node = 0u32;
            if GetNumaHighestNodeNumber(&mut highest_node) != 0 {
                NUMA_NODES.store((highest_node + 1) as usize, Ordering::Relaxed);
                highest_node > 0
            } else {
                false
            }
        }
    }

    pub fn bind_to_node(node: usize) -> Result<(), std::io::Error> {
        let node = u16::try_from(node).map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "NUMA node index exceeds the Windows API range",
            )
        })?;

        unsafe {
            let mut affinity: GROUP_AFFINITY = std::mem::zeroed();
            if GetNumaNodeProcessorMaskEx(node, &mut affinity) == 0 {
                return Err(std::io::Error::last_os_error());
            }

            if SetThreadGroupAffinity(GetCurrentThread(), &affinity, std::ptr::null_mut()) == 0 {
                return Err(std::io::Error::last_os_error());
            }

            Ok(())
        }
    }

    pub fn num_nodes() -> usize {
        let nodes = NUMA_NODES.load(Ordering::Relaxed);
        if nodes > 0 {
            nodes
        } else if is_available() {
            NUMA_NODES.load(Ordering::Relaxed)
        } else {
            1
        }
    }

    pub fn current_node() -> usize {
        unsafe {
            let mut processor: PROCESSOR_NUMBER = std::mem::zeroed();
            GetCurrentProcessorNumberEx(&mut processor);

            let mut node = 0u16;
            if GetNumaProcessorNodeEx(&processor, &mut node) != 0 && node != u16::MAX {
                node as usize
            } else {
                0
            }
        }
    }
}

#[cfg(not(any(target_os = "linux", target_os = "windows")))]
mod numa {
    pub fn num_nodes() -> usize {
        1
    }
    pub fn current_node() -> usize {
        0
    }
}

// ============================================================================
// MEMORY POOL
// ============================================================================

// Global Memory Pool (lazy, shared)
// ----------------------------------------------------------------------------
static GLOBAL_POOL: OnceLock<Arc<MemoryPool>> = OnceLock::new();

/// Returns a process-wide shared adaptive packet MemoryPool instance.
///
/// The configured block size is the adaptive request when MTU-based sizing is
/// enabled. `MemoryPool::block_size()` and the exported block-size gauge report
/// the effective size returned by allocations.
#[inline]
pub fn global_pool() -> Arc<MemoryPool> {
    GLOBAL_POOL
        .get_or_init(|| {
            // Use larger pool for better performance
            let capacity = std::env::var("QUICFUSCATE_POOL_CAPACITY")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(512); // Increased default
            let block_size = std::env::var("QUICFUSCATE_POOL_BLOCK_SIZE")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(65536); // 64 KiB adaptive request for packet buffers
            let pool = Arc::new(MemoryPool::new_adaptive(capacity, block_size));
            // Start auto-tuner thread if enabled
            MemoryPool::start_auto_tuner(Arc::clone(&pool));
            pool
        })
        .clone()
}

/// Initializes the global pool with an explicit capacity and block-size contract.
/// Subsequent calls to `global_pool()` return this instance. Returns `false` if
/// an instance was already initialized.
pub fn init_global_pool(capacity: usize, block_size: usize) -> bool {
    GLOBAL_POOL.set(Arc::new(MemoryPool::new(capacity, block_size))).is_ok()
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
// NOTE: On AArch64, NEON is part of the mandatory baseline and is therefore
// not an individually detectable feature in `cpufeatures` (only optional
// extensions like "aes"/"sha2" are). NEON availability is asserted directly in
// the detection routine below. The generated detector is unused (real runtime
// detection uses /proc/cpuinfo on Linux and sysctl on macOS) but is kept for
// parity with the x86 path.
#[cfg(target_arch = "aarch64")]
cpufeatures::new!(cpuid_arm, "aes");

include!("parts/cpu_dispatch.rs");
include!("parts/memory_pool.rs");
include!("parts/manager.rs");
// ============================================================================
// Memory Pool Implementation
// ============================================================================

/// SIMD-accelerated primitives organized by domain (core, galois, crypto, pattern, neural, compress).
pub mod simd;

include!("parts/cache_and_const.rs");
