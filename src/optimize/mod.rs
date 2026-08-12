//! # Optimization Module
//!
//! This module provides a framework for runtime CPU feature detection and
//! function dispatching to select the best hardware-accelerated implementation.
//! It also includes foundational structures for zero-copy operations and memory pooling.

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

pub use aligned_box::AlignedBox;
#[cfg(all(test, feature = "unsafe_rust"))]
#[doc(hidden)]
pub(crate) mod r#unsafe;
use crate::env_utils::EnvSnapshot;
use std::sync::{Arc, OnceLock};

#[cfg(any(test, feature = "rust-tests"))]
pub use qf_cpu::{
    __test_set_fec_kernel_override, clear_profile_override_for_tests,
    set_profile_override_for_tests,
};
pub use qf_cpu::{
    dispatch, AmxCapability, Avx2, Avx512, Avx512Gfni, Avx512Vbmi2, CacheHierarchy, CacheLevel,
    CpuFeature, CpuFeatures, CpuProfile, CryptoAeadPlan, FeatureDetector, Neon, NeonCrypto,
    OptimizeConfig, Pclmulqdq, Scalar, SimdDispatch, SimdFeatureMatrix, SimdPolicy, Sse2, Sve,
    Sve2, DEFAULT_DATA_PLANE_AEAD_LEN, VERIFIED_BACKEND,
};
pub(crate) use qf_cpu::{prefetch, PrefetchHint};

// Modular x86 SSE2 helpers (legacy acceleration)
#[cfg(target_arch = "x86_64")]
#[path = "x86_sse2.rs"]
pub mod x86_sse2;
#[cfg(any(test, feature = "rust-tests"))]
impl<const N: usize> Default for ConstBuffer<N> {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// MEMORY POOL
// ============================================================================

#[cfg(any(test, feature = "rust-tests"))]
#[doc(hidden)]
pub use qf_memory_pool::LOCK_BLOCKS_TEST_MUTEX;
pub use qf_memory_pool::{MemoryPool, MemoryPoolError, PooledBlock};
#[cfg(any(unix, windows))]
pub use qf_memory_pool::{
    ZeroCopyBuffer, ZeroCopyError, ZeroCopyRecvBuffer, ZeroCopyResult, ZeroCopyTransfer,
};

/// Linux-only batched UDP I/O via the transport-owned sendmmsg/recvmmsg helpers.
#[cfg(target_os = "linux")]
pub mod zc_batch {
    use std::io;
    use std::os::fd::RawFd;

    /// Sends multiple UDP packets in a single syscall via sendmmsg.
    pub fn sendmmsg(fd: RawFd, packets: &[&[u8]]) -> io::Result<usize> {
        super::udp::send_batch_connected(fd, packets)
    }

    /// Receives multiple UDP packets in a single syscall via recvmmsg.
    pub fn recvmmsg(fd: RawFd, bufs: &mut [&mut [u8]]) -> io::Result<usize> {
        super::udp::recv_batch_connected(fd, bufs)
    }
}

// Global Memory Pool (lazy, shared)
// ----------------------------------------------------------------------------
static GLOBAL_POOL: OnceLock<Arc<MemoryPool>> = OnceLock::new();

/// Returns a process-wide shared adaptive packet MemoryPool instance.
///
/// The configured block size is the adaptive request when MTU-based sizing is
/// enabled. `MemoryPool::block_size()` and the exported block-size gauge report
/// the effective size returned by allocations.
#[inline]
/// Return the process-global pool, creating it and starting the auto-tuner on first use.
///
/// # Lifecycle contract
///
/// This is the authoritative initialization path. The first call captures one [`EnvSnapshot`],
/// builds the adaptive pool from it, and starts the process-global auto-tuner if the resolved
/// runtime enables it. [`init_global_pool`] is the explicit alternative and produces the same
/// worker behaviour; whichever runs first wins, and the pool stays published for the life of the
/// process.
///
/// Callers that must not create the pool as a side effect use [`global_pool_if_initialized`].
pub fn global_pool() -> Arc<MemoryPool> {
    telemetry::install_resource_metrics_refresh_hook();
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
///
/// Subsequent calls to [`global_pool`] return this instance. Returns `false` if an instance was
/// already initialized, in which case nothing is changed and no worker is started.
///
/// # Lifecycle contract
///
/// This is the explicit counterpart to lazy initialization and produces the same worker behaviour:
/// on success it starts the process-global auto-tuner exactly as [`global_pool`] does. Before this
/// parity existed, a caller that initialized explicitly silently got no auto-tuner while a caller
/// that initialized lazily got one, so identical workloads tuned differently depending only on
/// which path ran first.
pub fn init_global_pool(capacity: usize, block_size: usize) -> bool {
    telemetry::install_resource_metrics_refresh_hook();
    let pool = Arc::new(MemoryPool::new(capacity, block_size));
    if GLOBAL_POOL.set(Arc::clone(&pool)).is_err() {
        return false;
    }
    MemoryPool::start_auto_tuner(pool);
    true
}

/// Return the process-global pool only if it already exists.
///
/// Use this from observers such as metrics export, which must report on the pool without bringing
/// it, and the auto-tuner thread, into existence as a side effect of being asked for numbers.
pub fn global_pool_if_initialized() -> Option<Arc<MemoryPool>> {
    GLOBAL_POOL.get().cloned()
}

#[path = "parts/manager.rs"]
mod manager;

pub use manager::OptimizationManager;
// ============================================================================
// Memory Pool Implementation
// ============================================================================

/// SIMD-accelerated primitives organized by domain (core, galois, crypto, pattern, neural, compress).
pub mod simd;

#[path = "parts/cache_and_const.rs"]
mod cache_and_const;

pub use cache_and_const::global_cache_hierarchy;
#[cfg(any(test, feature = "rust-tests"))]
pub use cache_and_const::{ConstBuffer, ConstPacketPool};
