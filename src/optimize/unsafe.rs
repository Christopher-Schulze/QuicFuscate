#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnsafeError {
    CapacityOverflow,
    InvalidPoolConfiguration,
    AllocationFailed,
    CompressionFailed,
    InvalidPointer,
    ForeignPointer,
    DoubleFree,
    InvalidPacket,
    ContextCreationFailed,
    ContextUnavailable,
    DictionaryCreationFailed,
    DictionaryRejected,
    ParameterRejected,
    InvalidCompressionLevel,
    InputTooLarge,
}
// # Unsafe Core - Maximum Performance Optimizations
//
// This module contains all unsafe optimizations for QuicFuscate, providing
// zero-copy operations, SIMD acceleration, and direct memory manipulation
// for maximum throughput and minimum latency.
//
// Safety Invariants
// - Pool-owned blocks are registered by exact base address and live state.
// - Registry transitions are serialized by the pool mutex in every thread.
// - Fallback blocks are tracked separately and never enter the preallocated cache.
// - Packet length and capacity invariants are checked in release builds.
// - Raw callers must keep a block live until every read/write operation completes.
//
// Performance Gains (indicative)
// - Memory Pool: 10-15% CPU reduction, 5% latency improvement
// - Transport: 20-25% CPU reduction, 5-10% latency improvement
// - FEC: 2-3x speedup for GF operations
// - Compression: 10-20% CPU reduction
// - Overall: throughput improvements are workload-dependent and must be validated with benchmarks.

use std::alloc::{alloc, dealloc, Layout};
use std::collections::HashMap;
use std::io::IoSlice;
use std::ptr::{self, NonNull};
use std::slice;
use std::sync::{Arc, Mutex, MutexGuard};

#[cfg(feature = "compression_zstd_ffi")]
use crate::env_utils::EnvSnapshot;

use crate::optimize::{prefetch, PrefetchHint};
use crate::telemetry;

// ============================================================================
// Zero-Copy Memory Pool with MaybeUninit
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AllocationKind {
    Preallocated,
    Fallback,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AllocationState {
    Available,
    InUse,
}

#[derive(Debug, Clone, Copy)]
struct AllocationRecord {
    kind: AllocationKind,
    state: AllocationState,
}

#[derive(Debug, Clone, Copy)]
struct OwnedBlock {
    ptr: NonNull<u8>,
}

// SAFETY: OwnedBlock is accessed only through UnsafeMemoryPool::state, whose Mutex
// serializes every ownership transition. The pointer refers to an allocation owned by
// the pool and is never dereferenced merely by moving this record between threads.
unsafe impl Send for OwnedBlock {}

struct PoolState {
    available: Vec<OwnedBlock>,
    allocations: HashMap<usize, AllocationRecord>,
}

/// Memory pool using a synchronized ownership registry and raw aligned blocks.
pub struct UnsafeMemoryPool {
    /// All available preallocated blocks. Fallback blocks are never stored here.
    state: Mutex<PoolState>,
    block_size: usize,
    capacity: usize,
    layout: Layout,
    numa_node: usize,
}

// Send and Sync are intentionally derived by the compiler for UnsafeMemoryPool. The only
// field carrying allocation ownership is Mutex<PoolState>; OwnedBlock is Send because its
// raw pointer is an address record protected by that mutex. No pool-level unsafe trait impl
// is needed, and no raw pointer is accessed without a live registry record.

impl UnsafeMemoryPool {
    const PREFETCH_DISTANCE: usize = 8;

    /// Creates a new unsafe memory pool with specified capacity and block size.
    ///
    /// This compatibility constructor panics on invalid configuration or allocation failure.
    /// Use [`Self::try_new`] when the caller can recover from those conditions.
    pub fn new(capacity: usize, block_size: usize, numa_node: usize) -> Self {
        Self::try_new(capacity, block_size, numa_node)
            .unwrap_or_else(|error| panic!("UnsafeMemoryPool::new failed: {error:?}"))
    }

    /// Fallible constructor with checked rounding, layout, reservation, and allocation bounds.
    pub fn try_new(
        capacity: usize,
        block_size: usize,
        numa_node: usize,
    ) -> Result<Self, UnsafeError> {
        if capacity == 0 || block_size == 0 {
            return Err(UnsafeError::InvalidPoolConfiguration);
        }
        let block_size = block_size.checked_add(63).ok_or(UnsafeError::CapacityOverflow)? & !63;
        if block_size == 0 {
            return Err(UnsafeError::CapacityOverflow);
        }
        let total_bytes = capacity.checked_mul(block_size).ok_or(UnsafeError::CapacityOverflow)?;
        if total_bytes > isize::MAX as usize {
            return Err(UnsafeError::CapacityOverflow);
        }
        let layout = Layout::from_size_align(block_size, 64)
            .map_err(|_| UnsafeError::InvalidPoolConfiguration)?;

        let mut available: Vec<OwnedBlock> = Vec::new();
        available.try_reserve_exact(capacity).map_err(|_| UnsafeError::AllocationFailed)?;
        let mut allocations = HashMap::new();
        allocations.try_reserve(capacity).map_err(|_| UnsafeError::AllocationFailed)?;

        for _ in 0..capacity {
            // SAFETY: layout was constructed by Layout::from_size_align and remains live for
            // every allocation and deallocation performed by this pool.
            let raw = unsafe { alloc(layout) };
            if raw.is_null() {
                for block in available.drain(..) {
                    // SAFETY: every drained block was allocated with this exact layout.
                    unsafe { dealloc(block.ptr.as_ptr(), layout) };
                }
                return Err(UnsafeError::AllocationFailed);
            }
            // SAFETY: the allocator returned a non-null pointer for this valid layout.
            let block = unsafe { NonNull::new_unchecked(raw) };
            allocations.insert(
                block.as_ptr() as usize,
                AllocationRecord {
                    kind: AllocationKind::Preallocated,
                    state: AllocationState::Available,
                },
            );
            available.push(OwnedBlock { ptr: block });
        }
        telemetry::UNSAFE_POOL_CREATED.inc();
        telemetry::UNSAFE_POOL_CAPACITY
            .store(capacity as u64, std::sync::atomic::Ordering::Relaxed);

        let this = Self {
            state: Mutex::new(PoolState { available, allocations }),
            block_size,
            capacity,
            layout,
            numa_node,
        };

        log::debug!(
            "UnsafeMemoryPool::new -> capacity={}, numa_node={}, block_size={}",
            this.capacity,
            this.numa_node,
            this.block_size
        );

        Ok(this)
    }

    fn lock_state(&self) -> MutexGuard<'_, PoolState> {
        match self.state.lock() {
            Ok(state) => state,
            Err(poisoned) => {
                log::error!("UnsafeMemoryPool ownership registry was poisoned; recovering state");
                poisoned.into_inner()
            }
        }
    }

    fn validate_live_block(&self, ptr: NonNull<u8>) -> Result<(), UnsafeError> {
        if !(ptr.as_ptr() as usize).is_multiple_of(self.layout.align()) {
            return Err(UnsafeError::InvalidPointer);
        }

        let state = self.lock_state();
        match state.allocations.get(&(ptr.as_ptr() as usize)) {
            None => Err(UnsafeError::ForeignPointer),
            Some(record) if record.state != AllocationState::InUse => Err(UnsafeError::DoubleFree),
            Some(_) => Ok(()),
        }
    }

    #[cfg(test)]
    fn available_count(&self) -> usize {
        self.lock_state().available.len()
    }

    #[cfg(test)]
    fn in_use_count(&self) -> usize {
        self.lock_state()
            .allocations
            .values()
            .filter(|record| record.state == AllocationState::InUse)
            .count()
    }

    #[cfg(test)]
    fn allocation_count(&self) -> usize {
        self.lock_state().allocations.len()
    }

    /// Allocates a block without zeroing - maximum performance
    #[inline(always)]
    /// # Safety
    /// The returned pointer is a live full-size block. The caller must not call `free` or
    /// hand the block to another owner until all reads and writes through it are complete.
    pub unsafe fn alloc_uninit(&self) -> NonNull<u8> {
        // SAFETY: This compatibility wrapper preserves the original infallible API. The
        // fallible implementation validates the live pool layout and returns allocation
        // failures before any pointer is exposed.
        unsafe { self.try_alloc_uninit() }
            .unwrap_or_else(|error| panic!("UnsafeMemoryPool::alloc_uninit failed: {error:?}"))
    }

    /// Fallible allocation counterpart to [`Self::alloc_uninit`].
    ///
    /// # Safety
    /// The returned pointer is a live full-size block. The caller must not call `free` or
    /// hand the block to another owner until all reads and writes through it are complete.
    pub unsafe fn try_alloc_uninit(&self) -> Result<NonNull<u8>, UnsafeError> {
        telemetry::UNSAFE_ALLOC_CALLS.inc();

        let cached = {
            let mut state = self.lock_state();
            state.available.pop().and_then(|block| {
                let address = block.ptr.as_ptr() as usize;
                match state.allocations.get_mut(&address) {
                    Some(record) if record.state == AllocationState::Available => {
                        record.state = AllocationState::InUse;
                        Some(block.ptr)
                    }
                    _ => {
                        log::error!("UnsafeMemoryPool available registry invariant violated");
                        None
                    }
                }
            })
        };
        if let Some(ptr) = cached {
            telemetry::UNSAFE_TLS_HITS.inc();
            self.prefetch_block(ptr.as_ptr());
            return Ok(ptr);
        }

        // Fallback: allocate new block
        telemetry::UNSAFE_FALLBACK_ALLOCS.inc();
        let mut state = self.lock_state();
        state.allocations.try_reserve(1).map_err(|_| UnsafeError::AllocationFailed)?;
        // SAFETY: self.layout has valid size and alignment established by try_new().
        let raw = unsafe { alloc(self.layout) };
        if raw.is_null() {
            return Err(UnsafeError::AllocationFailed);
        }
        // SAFETY: the allocator returned a non-null pointer for the validated layout.
        let ptr = unsafe { NonNull::new_unchecked(raw) };
        state.allocations.insert(
            ptr.as_ptr() as usize,
            AllocationRecord { kind: AllocationKind::Fallback, state: AllocationState::InUse },
        );
        Ok(ptr)
    }

    /// Returns a block to the pool
    #[inline(always)]
    /// # Safety
    /// `ptr` must be the exact base address returned by this pool's `alloc_uninit`, and no
    /// other thread or owner may access the block after this call starts. Invalid, foreign,
    /// and already-returned pointers are rejected without changing pool state.
    pub unsafe fn free(&self, ptr: NonNull<u8>) -> Result<(), UnsafeError> {
        telemetry::UNSAFE_FREE_CALLS.inc();

        if !(ptr.as_ptr() as usize).is_multiple_of(self.layout.align()) {
            return Err(UnsafeError::InvalidPointer);
        }

        let kind = {
            let mut state = self.lock_state();
            let address = ptr.as_ptr() as usize;
            let kind = match state.allocations.get_mut(&address) {
                None => return Err(UnsafeError::ForeignPointer),
                Some(record) if record.state != AllocationState::InUse => {
                    return Err(UnsafeError::DoubleFree);
                }
                Some(record) => {
                    let kind = record.kind;
                    if kind == AllocationKind::Preallocated {
                        record.state = AllocationState::Available;
                    }
                    kind
                }
            };

            if kind == AllocationKind::Preallocated {
                state.available.push(OwnedBlock { ptr });
            } else {
                state.allocations.remove(&address);
            }
            kind
        };

        if kind == AllocationKind::Fallback {
            telemetry::UNSAFE_DEALLOCS.inc();
            // SAFETY: the registry admitted this exact pointer as a live fallback block
            // allocated with self.layout, and removed the record before deallocation.
            dealloc(ptr.as_ptr(), self.layout);
        }
        Ok(())
    }

    /// Copies data into a live pool block, clamping the write to the block size.
    #[inline(always)]
    /// # Safety
    /// `ptr` must be a live, correctly aligned block returned by this pool's
    /// `alloc_uninit`, valid for `self.block_size` writable bytes, and not returned through
    /// `free`. The source may overlap the destination; the copy is overlap-safe.
    pub unsafe fn copy_from_slice(
        &self,
        ptr: NonNull<u8>,
        data: &[u8],
    ) -> Result<usize, UnsafeError> {
        self.validate_live_block(ptr)?;
        let len = data.len().min(self.block_size);

        // SAFETY: The caller guarantees that `ptr` points to a live block with
        // `self.block_size` writable bytes. `ptr::copy` is used instead of
        // `copy_nonoverlapping`, so an aliased source slice has defined copy semantics.
        ptr::copy(data.as_ptr(), ptr.as_ptr(), len);
        Ok(len)
    }

    /// Prefetch a memory block for faster access
    #[cfg_attr(feature = "aggressive_inline", inline(always))]
    /// # Safety
    /// `ptr` must be a valid address; this performs hardware prefetch hints only.
    unsafe fn prefetch_block(&self, ptr: *mut u8) {
        let line_count = self.block_size / 64;
        let last_line = line_count.saturating_sub(1).min(Self::PREFETCH_DISTANCE);
        for i in 0..=last_line {
            let p = ptr.add(i * 64);
            prefetch(p as *const u8, PrefetchHint::T0);
        }
    }

    // Unit tests must be defined at module scope; see tests module at the bottom.
}

impl Drop for UnsafeMemoryPool {
    fn drop(&mut self) {
        // SAFETY: Drop has exclusive access to the registry. Only available preallocated
        // blocks are deallocated here. Checked-out blocks are deliberately leaked if the
        // no-live-user precondition is violated, because deallocating them would create a
        // use-after-free for the outstanding raw owner. Valid users must return every block
        // before the final Arc reference to this pool is dropped.
        let state = match self.state.get_mut() {
            Ok(state) => state,
            Err(poisoned) => poisoned.into_inner(),
        };
        let live_count = state
            .allocations
            .values()
            .filter(|record| record.state == AllocationState::InUse)
            .count();
        if live_count != 0 {
            log::error!(
                "UnsafeMemoryPool dropped with {} live blocks; leaking checked-out ownership",
                live_count
            );
        }
        unsafe {
            for block in state.available.drain(..) {
                dealloc(block.ptr.as_ptr(), self.layout);
            }
        }
    }
}

// ============================================================================
// Zero-Copy Transport with IoSlice
// ============================================================================

/// Zero-copy packet structure using a validated live pool block.
pub struct UnsafePacket {
    /// Raw data pointer
    data: NonNull<u8>,
    /// Data length
    len: usize,
    /// Capacity
    capacity: usize,
    /// Pool reference for deallocation
    pool: Arc<UnsafeMemoryPool>,
}

impl UnsafePacket {
    /// Creates a new packet from raw parts
    #[inline(always)]
    /// # Safety
    /// `data` must be the exact base address of a live block returned by `pool` and must not
    /// be returned through `pool.free` while the packet exists. The constructor validates
    /// pool identity, alignment, live state, `capacity <= block_size`, and `len <= capacity`.
    pub unsafe fn from_raw_parts(
        data: NonNull<u8>,
        len: usize,
        capacity: usize,
        pool: Arc<UnsafeMemoryPool>,
    ) -> Result<Self, UnsafeError> {
        if len > capacity || capacity > pool.block_size {
            return Err(UnsafeError::InvalidPacket);
        }
        pool.validate_live_block(data)?;

        Ok(Self { data, len, capacity, pool })
    }

    /// Returns a slice view of the packet data
    #[inline(always)]
    pub fn as_slice(&self) -> &[u8] {
        // SAFETY: `self.data` is a valid NonNull<u8> pointing to `self.capacity` bytes
        // allocated from the pool. `self.len <= self.capacity` is maintained by all
        // constructors and extend_from_slice. The lifetime is tied to &self, preventing
        // use-after-free (pool.free only runs in Drop).
        unsafe { slice::from_raw_parts(self.data.as_ptr(), self.len) }
    }

    /// Creates an IoSlice for zero-copy send
    #[inline(always)]
    pub fn as_io_slice(&self) -> IoSlice<'_> {
        IoSlice::new(self.as_slice())
    }

    /// Extends the packet with data
    #[inline(always)]
    /// # Safety
    /// `self` must retain exclusive ownership of its live block for the duration of the
    /// operation. The source may alias the packet block because the copy is overlap-safe.
    pub unsafe fn extend_from_slice(&mut self, data: &[u8]) -> Result<(), UnsafeError> {
        let new_len = self.len.checked_add(data.len()).ok_or(UnsafeError::CapacityOverflow)?;
        if new_len > self.capacity {
            return Err(UnsafeError::CapacityOverflow);
        }

        // SAFETY: new_len <= capacity bounds the destination within the validated block;
        // data is a valid slice and ptr::copy supports overlap with the source.
        ptr::copy(data.as_ptr(), self.data.as_ptr().add(self.len), data.len());
        self.len = new_len;
        Ok(())
    }
}

impl Drop for UnsafePacket {
    fn drop(&mut self) {
        // SAFETY: from_raw_parts admitted self.data as this pool's live exact-base block.
        unsafe {
            if let Err(error) = self.pool.free(self.data) {
                log::error!("UnsafePacket could not return its pool block: {:?}", error);
            }
        }
    }
}

// ============================================================================
// Direct Compression with zstd_sys
// ============================================================================

pub mod unsafe_compress {
    use super::*;

    // Zstd context and dictionary ownership are represented by concrete branch-specific
    // types. No opaque pointer is used for the safe fallback.

    #[derive(Clone, Copy)]
    pub(super) enum CompressionStrategy {
        Fast,
        DFast,
        Greedy,
        Lazy2,
        #[cfg(feature = "compression_zstd_ffi")]
        BtOpt,
    }

    impl CompressionStrategy {
        #[cfg(feature = "compression_zstd_ffi")]
        fn native_value(self) -> i32 {
            match self {
                Self::Fast => zstd_sys::ZSTD_strategy::ZSTD_fast as i32,
                Self::DFast => zstd_sys::ZSTD_strategy::ZSTD_dfast as i32,
                Self::Greedy => zstd_sys::ZSTD_strategy::ZSTD_greedy as i32,
                Self::Lazy2 => zstd_sys::ZSTD_strategy::ZSTD_lazy2 as i32,
                Self::BtOpt => zstd_sys::ZSTD_strategy::ZSTD_btopt as i32,
            }
        }

        #[cfg(not(feature = "compression_zstd_ffi"))]
        fn fallback_value(self) -> zstd::zstd_safe::Strategy {
            match self {
                Self::Fast => zstd::zstd_safe::Strategy::ZSTD_fast,
                Self::DFast => zstd::zstd_safe::Strategy::ZSTD_dfast,
                Self::Greedy => zstd::zstd_safe::Strategy::ZSTD_greedy,
                Self::Lazy2 => zstd::zstd_safe::Strategy::ZSTD_lazy2,
            }
        }
    }

    #[derive(Clone, Copy)]
    pub(super) struct CompressionPlan {
        pub(super) level: i32,
        pub(super) workers: i32,
        pub(super) target_block: i32,
        pub(super) strategy: CompressionStrategy,
        pub(super) window_log: i32,
        pub(super) checksum: bool,
        pub(super) content_size: bool,
    }

    fn default_strategy(len: usize) -> CompressionStrategy {
        if len <= 8 * 1024 {
            CompressionStrategy::DFast
        } else if len <= 64 * 1024 {
            CompressionStrategy::Fast
        } else if len <= 512 * 1024 {
            CompressionStrategy::Greedy
        } else {
            CompressionStrategy::Lazy2
        }
    }

    // Sweetspot heuristic for minimal CPU usage while retaining good compression.
    #[inline]
    fn sweetspot_params_for(len: usize) -> (i32, i32, i32) {
        // (level, workers, target_block)
        let cpus: i32 = std::thread::available_parallelism().map(|n| n.get() as i32).unwrap_or(2);
        if len <= 8 * 1024 {
            (2, 0, 16 * 1024)
        } else if len <= 64 * 1024 {
            (3, 1, 64 * 1024)
        } else if len <= 256 * 1024 {
            (3, (cpus / 4).clamp(1, 2), 128 * 1024)
        } else {
            (4, (cpus / 2).clamp(2, 4), 256 * 1024)
        }
    }

    #[cfg(feature = "compression_zstd_ffi")]
    #[derive(Clone, Copy)]
    struct ManualCfg {
        enabled: bool,
        level: i32,
        workers: i32,
        block: i32,
    }

    #[cfg(feature = "compression_zstd_ffi")]
    static MANUAL_CFG: std::sync::OnceLock<ManualCfg> = std::sync::OnceLock::new();

    #[cfg(feature = "compression_zstd_ffi")]
    static ZSTD_ENVIRONMENT: std::sync::OnceLock<EnvSnapshot> = std::sync::OnceLock::new();

    #[cfg(feature = "compression_zstd_ffi")]
    #[inline]
    fn zstd_environment() -> &'static EnvSnapshot {
        ZSTD_ENVIRONMENT.get_or_init(EnvSnapshot::capture)
    }

    #[cfg(feature = "compression_zstd_ffi")]
    #[inline]
    fn manual_cfg() -> ManualCfg {
        *MANUAL_CFG.get_or_init(|| {
            let environment = zstd_environment();
            let enabled = match environment.first(["QUICFUSCATE_ZSTD_MODE"]) {
                None => false,
                Some(value) if value.eq_ignore_ascii_case("manual") => true,
                Some(value) if value.eq_ignore_ascii_case("auto") => false,
                Some(value) => {
                    log::warn!(
                        "Invalid QUICFUSCATE_ZSTD_MODE value '{}'; retaining automatic mode",
                        value
                    );
                    false
                }
            };
            let level = zstd_i32_in_range("QUICFUSCATE_ZSTD_LEVEL", 1, 22, 3);
            let workers = zstd_i32_min("QUICFUSCATE_ZSTD_WORKERS", 0, 2);
            let block = zstd_i32_min("QUICFUSCATE_ZSTD_TARGET_BLOCK", 1, 64 * 1024);
            ManualCfg { enabled, level, workers, block }
        })
    }

    #[cfg(feature = "compression_zstd_ffi")]
    #[inline]
    fn zstd_i32_in_range(name: &str, min: i32, max: i32, default: i32) -> i32 {
        match zstd_environment().parse::<i32>(name) {
            None => default,
            Some(value) if (min..=max).contains(&value) => value,
            Some(value) => {
                log::warn!(
                    "{}={} is outside {}..={}; retaining {}",
                    name,
                    value,
                    min,
                    max,
                    default
                );
                default
            }
        }
    }

    #[cfg(feature = "compression_zstd_ffi")]
    #[inline]
    fn zstd_i32_min(name: &str, min: i32, default: i32) -> i32 {
        match zstd_environment().parse::<i32>(name) {
            None => default,
            Some(value) if value >= min => value,
            Some(value) => {
                log::warn!("{}={} must be at least {}; retaining {}", name, value, min, default);
                default
            }
        }
    }

    #[cfg(feature = "compression_zstd_ffi")]
    #[inline]
    fn choose_strategy(len: usize) -> CompressionStrategy {
        if let Some(strategy) = zstd_environment().first(["QUICFUSCATE_ZSTD_STRATEGY"]) {
            match strategy.to_ascii_lowercase().as_str() {
                "fast" => return CompressionStrategy::Fast,
                "dfast" => return CompressionStrategy::DFast,
                "greedy" => return CompressionStrategy::Greedy,
                "lazy2" => return CompressionStrategy::Lazy2,
                "btopt" => return CompressionStrategy::BtOpt,
                _ => {
                    log::warn!(
                        "Invalid QUICFUSCATE_ZSTD_STRATEGY value '{}'; retaining the length-based default",
                        strategy
                    );
                }
            }
        }
        default_strategy(len)
    }

    #[cfg(not(feature = "compression_zstd_ffi"))]
    #[inline]
    fn choose_strategy(len: usize) -> CompressionStrategy {
        default_strategy(len)
    }

    #[cfg(feature = "compression_zstd_ffi")]
    #[inline]
    fn choose_window_log(len: usize) -> i32 {
        let w = zstd_i32_in_range("QUICFUSCATE_ZSTD_WINDOW_LOG", 10, 31, 0);
        if w != 0 {
            return w;
        }
        if len <= 64 * 1024 {
            17
        } else if len <= 256 * 1024 {
            18
        } else {
            19
        }
    }

    #[cfg(not(feature = "compression_zstd_ffi"))]
    #[inline]
    fn choose_window_log(len: usize) -> i32 {
        if len <= 64 * 1024 {
            17
        } else if len <= 256 * 1024 {
            18
        } else {
            19
        }
    }

    #[cfg(feature = "compression_zstd_ffi")]
    #[inline]
    fn zstd_binary_flag(name: &str) -> i32 {
        zstd_i32_in_range(name, 0, 1, 0)
    }

    #[cfg(feature = "compression_zstd_ffi")]
    #[inline]
    fn choose_checksum_flag() -> i32 {
        zstd_binary_flag("QUICFUSCATE_ZSTD_CHECKSUM")
    }

    #[cfg(feature = "compression_zstd_ffi")]
    #[inline]
    fn choose_content_size_flag() -> i32 {
        zstd_binary_flag("QUICFUSCATE_ZSTD_CONTENTSIZE")
    }

    fn compression_plan(len: usize) -> CompressionPlan {
        let (level, workers, target_block) = {
            #[cfg(feature = "compression_zstd_ffi")]
            {
                let manual = manual_cfg();
                if manual.enabled {
                    (manual.level, manual.workers, manual.block)
                } else {
                    sweetspot_params_for(len)
                }
            }
            #[cfg(not(feature = "compression_zstd_ffi"))]
            {
                let (level, _, target_block) = sweetspot_params_for(len);
                (level, 0, target_block)
            }
        };

        #[cfg(feature = "compression_zstd_ffi")]
        let checksum = choose_checksum_flag() != 0;
        #[cfg(not(feature = "compression_zstd_ffi"))]
        let checksum = false;

        #[cfg(feature = "compression_zstd_ffi")]
        let content_size = choose_content_size_flag() != 0;
        #[cfg(not(feature = "compression_zstd_ffi"))]
        let content_size = false;

        CompressionPlan {
            level,
            workers,
            target_block,
            strategy: choose_strategy(len),
            window_log: choose_window_log(len),
            checksum,
            content_size,
        }
    }

    fn validate_compression_level(level: i32) -> Result<(), UnsafeError> {
        if (1..=22).contains(&level) {
            Ok(())
        } else {
            Err(UnsafeError::InvalidCompressionLevel)
        }
    }

    pub(super) fn validate_source_len(len: usize) -> Result<(), UnsafeError> {
        if len <= u32::MAX as usize {
            Ok(())
        } else {
            Err(UnsafeError::InputTooLarge)
        }
    }

    pub(super) fn validate_compression_plan(plan: CompressionPlan) -> Result<(), UnsafeError> {
        if !(1..=22).contains(&plan.level)
            || plan.workers < 0
            || plan.target_block < 1
            || !(10..=31).contains(&plan.window_log)
        {
            return Err(UnsafeError::ParameterRejected);
        }
        Ok(())
    }

    #[cfg(feature = "compression_zstd_ffi")]
    fn native_is_error(code: usize) -> bool {
        // SAFETY: ZSTD_isError only inspects the returned size/error code and does not
        // dereference a pointer.
        unsafe { zstd_sys::ZSTD_isError(code) != 0 }
    }

    #[cfg(feature = "compression_zstd_ffi")]
    pub(super) fn native_set_parameter(
        ctx: NonNull<zstd_sys::ZSTD_CCtx>,
        parameter: zstd_sys::ZSTD_cParameter,
        value: i32,
    ) -> Result<(), UnsafeError> {
        // SAFETY: ctx is a live NonNull context created by ZSTD_createCCtx and held by
        // the owning ZstdContext. The parameter enum and integer value are passed directly
        // to zstd, which validates bounds and returns a status code.
        let result = unsafe { zstd_sys::ZSTD_CCtx_setParameter(ctx.as_ptr(), parameter, value) };
        if native_is_error(result) {
            Err(UnsafeError::ParameterRejected)
        } else {
            Ok(())
        }
    }

    #[cfg(feature = "compression_zstd_ffi")]
    fn native_compression_error(code: usize) -> UnsafeError {
        // SAFETY: ZSTD_getErrorCode only inspects the returned size/error code.
        let error = unsafe { zstd_sys::ZSTD_getErrorCode(code) };
        if error == zstd_sys::ZSTD_ErrorCode::ZSTD_error_dstSize_tooSmall {
            UnsafeError::CapacityOverflow
        } else {
            UnsafeError::CompressionFailed
        }
    }

    #[cfg(feature = "compression_zstd_ffi")]
    fn configure_native(
        ctx: NonNull<zstd_sys::ZSTD_CCtx>,
        plan: CompressionPlan,
    ) -> Result<(), UnsafeError> {
        native_set_parameter(ctx, zstd_sys::ZSTD_cParameter::ZSTD_c_compressionLevel, plan.level)?;
        native_set_parameter(ctx, zstd_sys::ZSTD_cParameter::ZSTD_c_nbWorkers, plan.workers)?;
        native_set_parameter(
            ctx,
            zstd_sys::ZSTD_cParameter::ZSTD_c_targetCBlockSize,
            plan.target_block,
        )?;
        native_set_parameter(
            ctx,
            zstd_sys::ZSTD_cParameter::ZSTD_c_strategy,
            plan.strategy.native_value(),
        )?;
        native_set_parameter(ctx, zstd_sys::ZSTD_cParameter::ZSTD_c_windowLog, plan.window_log)?;
        native_set_parameter(
            ctx,
            zstd_sys::ZSTD_cParameter::ZSTD_c_checksumFlag,
            plan.checksum as i32,
        )?;
        native_set_parameter(
            ctx,
            zstd_sys::ZSTD_cParameter::ZSTD_c_contentSizeFlag,
            plan.content_size as i32,
        )
    }

    #[cfg(not(feature = "compression_zstd_ffi"))]
    fn configure_fallback(
        compressor: &mut zstd::bulk::Compressor<'static>,
        plan: CompressionPlan,
    ) -> Result<(), UnsafeError> {
        let target_block =
            u32::try_from(plan.target_block).map_err(|_| UnsafeError::ParameterRejected)?;
        let window_log =
            u32::try_from(plan.window_log).map_err(|_| UnsafeError::ParameterRejected)?;
        let parameters = [
            zstd::zstd_safe::CParameter::CompressionLevel(plan.level),
            zstd::zstd_safe::CParameter::TargetCBlockSize(target_block),
            zstd::zstd_safe::CParameter::Strategy(plan.strategy.fallback_value()),
            zstd::zstd_safe::CParameter::WindowLog(window_log),
            zstd::zstd_safe::CParameter::ChecksumFlag(plan.checksum),
            zstd::zstd_safe::CParameter::ContentSizeFlag(plan.content_size),
        ];
        for parameter in parameters {
            compressor.set_parameter(parameter).map_err(|_| UnsafeError::ParameterRejected)?;
        }
        Ok(())
    }

    enum ZstdContext {
        #[cfg(feature = "compression_zstd_ffi")]
        Native { ctx: NonNull<zstd_sys::ZSTD_CCtx>, dict: Option<NonNull<zstd_sys::ZSTD_CDict>> },
        #[cfg(not(feature = "compression_zstd_ffi"))]
        Fallback { compressor: zstd::bulk::Compressor<'static>, has_dictionary: bool },
    }

    impl ZstdContext {
        fn new(dict_data: Option<&[u8]>, level: i32) -> Result<Self, UnsafeError> {
            #[cfg(feature = "compression_zstd_ffi")]
            {
                // SAFETY: This is the documented zstd context constructor. The returned
                // pointer is checked immediately and becomes owned by ZstdContext.
                let ctx = NonNull::new(unsafe { zstd_sys::ZSTD_createCCtx() })
                    .ok_or(UnsafeError::ContextCreationFailed)?;
                if let Err(error) = native_set_parameter(
                    ctx,
                    zstd_sys::ZSTD_cParameter::ZSTD_c_compressionLevel,
                    level,
                ) {
                    // SAFETY: ctx is the live allocation returned above and no owner has
                    // been constructed yet.
                    unsafe {
                        let _ = zstd_sys::ZSTD_freeCCtx(ctx.as_ptr());
                    }
                    return Err(error);
                }
                let dict = match dict_data {
                    Some(data) => {
                        // SAFETY: data is borrowed from a valid slice and zstd copies the
                        // dictionary into its owned CDict.
                        let dict = match NonNull::new(unsafe {
                            zstd_sys::ZSTD_createCDict(
                                data.as_ptr() as *const std::ffi::c_void,
                                data.len(),
                                level,
                            )
                        }) {
                            Some(dict) => dict,
                            None => {
                                // SAFETY: ctx remains owned locally because the
                                // ZstdContext enum has not been returned yet.
                                unsafe {
                                    let _ = zstd_sys::ZSTD_freeCCtx(ctx.as_ptr());
                                }
                                return Err(UnsafeError::DictionaryCreationFailed);
                            }
                        };
                        Some(dict)
                    }
                    None => None,
                };
                Ok(Self::Native { ctx, dict })
            }
            #[cfg(not(feature = "compression_zstd_ffi"))]
            {
                let has_dictionary = dict_data.is_some();
                let compressor = match dict_data {
                    Some(data) => zstd::bulk::Compressor::with_dictionary(level, data)
                        .map_err(|_| UnsafeError::DictionaryCreationFailed)?,
                    None => zstd::bulk::Compressor::new(level)
                        .map_err(|_| UnsafeError::ContextCreationFailed)?,
                };
                Ok(Self::Fallback { compressor, has_dictionary })
            }
        }

        fn has_dictionary(&self) -> bool {
            match self {
                #[cfg(feature = "compression_zstd_ffi")]
                Self::Native { dict, .. } => dict.is_some(),
                #[cfg(not(feature = "compression_zstd_ffi"))]
                Self::Fallback { has_dictionary, .. } => *has_dictionary,
            }
        }

        fn compress_into(
            &mut self,
            src: &[u8],
            dst: &mut [u8],
            plan: CompressionPlan,
        ) -> Result<usize, UnsafeError> {
            validate_compression_plan(plan)?;
            #[cfg(feature = "compression_zstd_ffi")]
            {
                match self {
                    Self::Native { ctx, dict } => {
                        // SAFETY: ctx is live and exclusively borrowed through the mutex
                        // guard. reset_session_only is required before the next frame.
                        let reset = unsafe {
                            zstd_sys::ZSTD_CCtx_reset(
                                ctx.as_ptr(),
                                zstd_sys::ZSTD_ResetDirective::ZSTD_reset_session_only,
                            )
                        };
                        if native_is_error(reset) {
                            return Err(UnsafeError::ContextUnavailable);
                        }
                        if let Some(dict) = dict {
                            // SAFETY: dict is live for the whole compressor lifetime and
                            // the context is locked for this complete compression call.
                            let result = unsafe {
                                zstd_sys::ZSTD_CCtx_refCDict(ctx.as_ptr(), dict.as_ptr())
                            };
                            if native_is_error(result) {
                                return Err(UnsafeError::DictionaryRejected);
                            }
                        } else {
                            configure_native(*ctx, plan)?;
                        }
                        // SAFETY: src and dst are valid slices. zstd writes no more than
                        // dst.len() bytes and returns the written length or an error code.
                        let result = unsafe {
                            zstd_sys::ZSTD_compress2(
                                ctx.as_ptr(),
                                dst.as_mut_ptr() as *mut std::ffi::c_void,
                                dst.len(),
                                src.as_ptr() as *const std::ffi::c_void,
                                src.len(),
                            )
                        };
                        if native_is_error(result) {
                            Err(native_compression_error(result))
                        } else {
                            Ok(result)
                        }
                    }
                }
            }
            #[cfg(not(feature = "compression_zstd_ffi"))]
            {
                match self {
                    Self::Fallback { compressor, has_dictionary } => {
                        if !*has_dictionary {
                            configure_fallback(compressor, plan)?;
                        }
                        compressor
                            .compress_to_buffer(src, dst)
                            .map_err(|_| UnsafeError::CompressionFailed)
                    }
                }
            }
        }
    }

    #[cfg(feature = "compression_zstd_ffi")]
    impl Drop for ZstdContext {
        fn drop(&mut self) {
            let Self::Native { ctx, dict } = self;
            // SAFETY: Both pointers are NonNull values created by the matching zstd
            // constructors and are freed exactly once here. The dictionary is released
            // before the context that may reference it.
            unsafe {
                if let Some(dict) = dict {
                    let _ = zstd_sys::ZSTD_freeCDict(dict.as_ptr());
                }
                let _ = zstd_sys::ZSTD_freeCCtx(ctx.as_ptr());
            }
        }
    }

    fn return_output_block(pool: &UnsafeMemoryPool, ptr: NonNull<u8>) {
        // SAFETY: ptr was returned by this pool's alloc_uninit call and has not been
        // transferred to an UnsafePacket on the failure paths that call this helper.
        if let Err(error) = unsafe { pool.free(ptr) } {
            log::error!("UnsafeCompressor could not return output block: {:?}", error);
        }
    }

    /// Direct compression context using zstd C API
    pub struct UnsafeCompressor {
        ctx: Mutex<ZstdContext>,
        dict_meta: Option<(u16, u16)>,
        pool: Arc<UnsafeMemoryPool>,
    }

    // SAFETY: Moving the compressor transfers exclusive ownership of the zstd context.
    // Native raw pointers are only reachable through the owning ZstdContext.
    unsafe impl Send for UnsafeCompressor {}
    // SAFETY: Every context mutation and compression call holds ctx's MutexGuard. The
    // dictionary is immutable after construction and the pool has its own synchronization.
    unsafe impl Sync for UnsafeCompressor {}

    impl UnsafeCompressor {
        /// Creates a new compressor with optional dictionary.
        pub fn new(
            pool: Arc<UnsafeMemoryPool>,
            dict_data: Option<&[u8]>,
            level: i32,
        ) -> Result<Self, UnsafeError> {
            validate_compression_level(level)?;
            let context = ZstdContext::new(dict_data, level)?;
            let dict_meta = dict_data.map(compute_dict_hash_version);
            Ok(Self { ctx: Mutex::new(context), dict_meta, pool })
        }

        /// Compress directly into a pool buffer without an intermediate output allocation.
        #[inline]
        /// # Safety
        /// The returned packet owns the pool block and must be dropped to return it to the pool.
        pub unsafe fn compress_direct(&self, src: &[u8]) -> Result<UnsafePacket, UnsafeError> {
            telemetry::UNSAFE_COMPRESS_CALLS.inc();

            if let Err(error) = validate_source_len(src.len()) {
                telemetry::UNSAFE_COMPRESS_FAILURES.inc();
                return Err(error);
            }

            let mut context = match self.ctx.lock() {
                Ok(guard) => guard,
                Err(_) => {
                    telemetry::UNSAFE_COMPRESS_FAILURES.inc();
                    return Err(UnsafeError::ContextUnavailable);
                }
            };
            let has_dictionary = context.has_dictionary();
            let (header_magic, header_size) =
                if has_dictionary { (0x5D_u8, 9_usize) } else { (0x5A_u8, 5_usize) };
            let compression_bound = zstd::zstd_safe::compress_bound(src.len());
            let required_capacity = match header_size.checked_add(compression_bound) {
                Some(required) => required,
                None => {
                    telemetry::UNSAFE_COMPRESS_FAILURES.inc();
                    return Err(UnsafeError::CapacityOverflow);
                }
            };
            let dst_capacity = self.pool.block_size;
            if dst_capacity < required_capacity {
                telemetry::UNSAFE_COMPRESS_FAILURES.inc();
                return Err(UnsafeError::CapacityOverflow);
            }

            let dst_ptr = self.pool.alloc_uninit();

            let plan = compression_plan(src.len());
            // SAFETY: dst_ptr is a live pool block and the checked capacity leaves a
            // writable suffix after the private header. src is a valid borrowed slice.
            let compressed_size = {
                let dst = slice::from_raw_parts_mut(
                    dst_ptr.as_ptr().add(header_size),
                    dst_capacity - header_size,
                );
                context.compress_into(src, dst, plan)
            };

            let compressed_size = match compressed_size {
                Ok(size) => size,
                Err(error) => {
                    return_output_block(&self.pool, dst_ptr);
                    telemetry::UNSAFE_COMPRESS_FAILURES.inc();
                    return Err(error);
                }
            };
            if compressed_size > dst_capacity - header_size {
                return_output_block(&self.pool, dst_ptr);
                telemetry::UNSAFE_COMPRESS_FAILURES.inc();
                return Err(UnsafeError::CapacityOverflow);
            }

            let total_size = match header_size.checked_add(compressed_size) {
                Some(size) => size,
                None => {
                    return_output_block(&self.pool, dst_ptr);
                    telemetry::UNSAFE_COMPRESS_FAILURES.inc();
                    return Err(UnsafeError::CapacityOverflow);
                }
            };

            // SAFETY: The header offsets are within the block because total_size is no
            // larger than dst_capacity. The source arrays are independent stack values.
            *dst_ptr.as_ptr() = header_magic;
            let len_be = (src.len() as u32).to_be_bytes();
            if header_magic == 0x5A {
                ptr::copy_nonoverlapping(len_be.as_ptr(), dst_ptr.as_ptr().add(1), 4);
            } else {
                let (hash, version) = match self.dict_meta {
                    Some(meta) => meta,
                    None => {
                        return_output_block(&self.pool, dst_ptr);
                        telemetry::UNSAFE_COMPRESS_FAILURES.inc();
                        return Err(UnsafeError::DictionaryRejected);
                    }
                };
                let hash_bytes = hash.to_be_bytes();
                let version_bytes = version.to_be_bytes();
                ptr::copy_nonoverlapping(hash_bytes.as_ptr(), dst_ptr.as_ptr().add(1), 2);
                ptr::copy_nonoverlapping(version_bytes.as_ptr(), dst_ptr.as_ptr().add(3), 2);
                ptr::copy_nonoverlapping(len_be.as_ptr(), dst_ptr.as_ptr().add(5), 4);
            }

            drop(context);
            telemetry::UNSAFE_COMPRESS_BYTES_IN.inc_by(src.len() as u64);
            telemetry::UNSAFE_COMPRESS_BYTES_OUT.inc_by(total_size as u64);

            match UnsafePacket::from_raw_parts(
                dst_ptr,
                total_size,
                dst_capacity,
                Arc::clone(&self.pool),
            ) {
                Ok(packet) => Ok(packet),
                Err(error) => {
                    return_output_block(&self.pool, dst_ptr);
                    telemetry::UNSAFE_COMPRESS_FAILURES.inc();
                    Err(error)
                }
            }
        }
    }

    #[inline]
    fn compute_dict_hash_version(bytes: &[u8]) -> (u16, u16) {
        let mut hash: u16 = 0u16;
        for b in bytes.iter().take(64) {
            hash = hash.wrapping_mul(257).wrapping_add(*b as u16);
        }
        (hash, 1)
    }
}

// ============================================================================
// Testing Infrastructure
// ============================================================================
#[cfg(test)]
mod tests;
