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
use crate::env_utils::EnvSnapshot;
#[cfg(unix)]
use libc::{iovec, msghdr, recvmsg, sendmsg};
use log::warn;
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
fn resolve_numa_policy_with_snapshot(environment: &EnvSnapshot) -> NumaPolicy {
    if let Some(value) = environment.first(["QUICFUSCATE_NUMA_POLICY"]) {
        let v = value.to_ascii_lowercase();
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
pub(crate) fn initialize_numa_policy(environment: &EnvSnapshot) {
    NUMA_POLICY.get_or_init(|| resolve_numa_policy_with_snapshot(environment));
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

/// Pure classification of Windows NUMA API results.
///
/// Split out from the FFI module so the decision logic is provable on a non-Windows workspace.
/// The Windows adapter owns the calls; this owns what their outputs mean.
#[cfg(any(target_os = "windows", test))]
mod numa_classification {
    /// Node count implied by a successful `GetNumaHighestNodeNumber`.
    ///
    /// The API reports the highest node *number*, so the count is one more. Saturating rather than
    /// wrapping: a `u32::MAX` highest node is nonsensical but must not overflow into zero nodes.
    pub(super) fn node_count_from_highest(highest_node: u32) -> usize {
        (highest_node as usize).saturating_add(1)
    }

    /// Whether a successful `GetNumaHighestNodeNumber` means NUMA is usable.
    ///
    /// A successful query describes a valid topology even when the machine has exactly one node,
    /// which reports `highest_node == 0`. Treating that as unavailable made every single-node
    /// Windows host look like it had no NUMA support at all, so binding and node queries were
    /// skipped on hardware where they would have worked.
    pub(super) fn available_from_query(query_succeeded: bool) -> bool {
        query_succeeded
    }

    /// Node index implied by a `GetNumaProcessorNodeEx` result.
    ///
    /// `u16::MAX` is the documented sentinel for "this processor has no NUMA node". A failed call
    /// or the sentinel both fall back to node zero, which is the only node guaranteed to exist.
    pub(super) fn node_from_processor_result(query_succeeded: bool, node: u16) -> usize {
        if query_succeeded && node != u16::MAX {
            node as usize
        } else {
            0
        }
    }
}

/// Proof for the Windows NUMA result classification.
///
/// Runs on every target. The FFI calls themselves are Windows-only and remain unproven here, but
/// what their outputs mean is decided by these pure functions and is provable anywhere.
#[cfg(test)]
mod numa_classification_tests {
    use super::numa_classification::*;

    #[test]
    fn single_node_topology_counts_as_available() {
        // `GetNumaHighestNodeNumber` reports the highest node number, so a machine with one node
        // reports 0. Requiring `highest_node > 0` made every single-node Windows host report no
        // NUMA support, skipping binding and node queries that would have worked.
        assert!(available_from_query(true), "a successful query means the topology is usable");
        assert_eq!(node_count_from_highest(0), 1, "highest node 0 means exactly one node");

        assert!(!available_from_query(false), "a failed query means unavailable");
    }

    #[test]
    fn node_count_is_one_more_than_the_highest_and_never_overflows() {
        assert_eq!(node_count_from_highest(1), 2);
        assert_eq!(node_count_from_highest(63), 64);
        // A nonsensical maximum must saturate rather than wrap to zero nodes.
        assert_eq!(node_count_from_highest(u32::MAX), u32::MAX as usize + 1);
        assert!(node_count_from_highest(u32::MAX) > 0);
    }

    #[test]
    fn processor_node_result_honours_failure_and_the_no_node_sentinel() {
        assert_eq!(node_from_processor_result(true, 0), 0);
        assert_eq!(node_from_processor_result(true, 3), 3);

        // u16::MAX is the documented "no NUMA node for this processor" sentinel and must not be
        // reported as node 65535.
        assert_eq!(node_from_processor_result(true, u16::MAX), 0);

        // A failed query falls back to node zero, the only node guaranteed to exist.
        assert_eq!(node_from_processor_result(false, 7), 0);
        assert_eq!(node_from_processor_result(false, u16::MAX), 0);
    }
}

#[cfg(target_os = "windows")]
mod numa {
    use super::numa_classification;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use windows_sys::Win32::System::Kernel::PROCESSOR_NUMBER;
    use windows_sys::Win32::System::SystemInformation::GROUP_AFFINITY;
    use windows_sys::Win32::System::Threading::{
        GetCurrentProcessorNumberEx, GetCurrentThread, GetNumaHighestNodeNumber,
        GetNumaNodeProcessorMaskEx, GetNumaProcessorNodeEx, SetThreadGroupAffinity,
    };

    static NUMA_NODES: AtomicUsize = AtomicUsize::new(0);

    pub fn is_available() -> bool {
        let mut highest_node = 0u32;
        // SAFETY: `highest_node` is an initialized local `u32` that outlives the call, and the
        // callee only writes through the pointer on success. The API takes no other input and
        // borrows nothing beyond this call. A non-zero BOOL means the output was written; the
        // value is not read on failure.
        let query_succeeded = unsafe { GetNumaHighestNodeNumber(&mut highest_node) } != 0;
        if query_succeeded {
            NUMA_NODES.store(
                numa_classification::node_count_from_highest(highest_node),
                Ordering::Relaxed,
            );
        }
        numa_classification::available_from_query(query_succeeded)
    }

    pub fn bind_to_node(node: usize) -> Result<(), std::io::Error> {
        let node = u16::try_from(node).map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "NUMA node index exceeds the Windows API range",
            )
        })?;

        // SAFETY: `affinity` is a zeroed `GROUP_AFFINITY`, which is a plain POD struct for which
        // all-zero is a valid bit pattern, and it outlives both calls. `GetNumaNodeProcessorMaskEx`
        // writes through the pointer only on success and reads only the `u16` node, which the
        // checked conversion above bounded to the API range. `GetCurrentThread()` returns a
        // pseudo-handle that is always valid for the calling thread and needs no close.
        // `SetThreadGroupAffinity` reads `affinity` and writes nothing through the null previous
        // pointer, which the API documents as "discard the previous affinity". Neither pointer
        // escapes this scope, and `last_os_error()` is read only after a checked zero return.
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
        let mut processor: PROCESSOR_NUMBER = unsafe {
            // SAFETY: `PROCESSOR_NUMBER` is a POD struct of integer fields, so an all-zero bit
            // pattern is valid and inhabited. It is fully overwritten by the call below.
            std::mem::zeroed()
        };

        // SAFETY: `GetCurrentProcessorNumberEx` returns no status. It is declared
        // `fn(*mut PROCESSOR_NUMBER)` and the Win32 contract is that it always populates the
        // structure for the calling processor, so there is nothing to classify here. The pointer
        // targets an initialized local that outlives the call and is not aliased.
        unsafe { GetCurrentProcessorNumberEx(&mut processor) };

        let mut node = 0u16;
        // SAFETY: `processor` was populated above and is passed by shared reference, which the
        // callee only reads. `node` is an initialized local written through only on success. Both
        // outlive the call and neither pointer escapes it.
        let query_succeeded = unsafe { GetNumaProcessorNodeEx(&processor, &mut node) } != 0;
        numa_classification::node_from_processor_result(query_succeeded, node)
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
            let environment = EnvSnapshot::capture();
            // Use larger pool for better performance. Both values belong to the
            // same construction snapshot as the adaptive pool policy.
            let capacity =
                environment.parse_positive_usize("QUICFUSCATE_POOL_CAPACITY").unwrap_or(512);
            let block_size =
                environment.parse_positive_usize("QUICFUSCATE_POOL_BLOCK_SIZE").unwrap_or(65536);
            let pool = Arc::new(MemoryPool::new_adaptive_with_snapshot(
                capacity,
                block_size,
                &environment,
            ));
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
