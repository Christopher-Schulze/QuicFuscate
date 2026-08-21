//
// Foundational Structures for Global Optimizations
//

use qf_common::env_utils::EnvSnapshot;
use qf_cpu::{prefetch, PrefetchHint};
use qf_telemetry as telemetry;
use std::cell::RefCell;
use std::collections::HashSet;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, OnceLock};

use aligned_box::AlignedBox;
use crossbeam_queue::SegQueue;
use log::warn;

mod numa;
#[cfg(target_os = "linux")]
use numa::{initialize_numa_policy, NumaPolicy, NUMA_POLICY, RR_NODE};
mod ownership;
use ownership::{PoolBlockLocation, PoolBlockOrigin, PoolOwnershipLedger};

/// A high-performance, thread-safe memory pool for fixed-size blocks.
/// This implementation uses a concurrent queue to manage free blocks,
/// minimizing lock contention and fragmentation.
#[derive(Debug)]
pub struct MemoryPool {
    id: usize,
    lock_blocks: bool,
    lock_ledger: Arc<BlockLockLedger>,
    pools: Vec<Arc<SegQueue<AlignedBox<[u8]>>>>,
    block_size: usize,
    num_nodes: usize,
    capacity: Arc<AtomicUsize>,
    hard_max_capacity: usize,
    in_use: Arc<AtomicUsize>,
    available: Arc<AtomicUsize>,
    ownership: Arc<PoolOwnershipLedger>,
    resize_lock: std::sync::Mutex<()>,
    runtime: Arc<MemoryPoolRuntimeConfig>,
}

#[derive(Debug)]
struct MemoryPoolRuntimeConfig {
    tls_cache_limit: AtomicUsize,
    #[cfg(debug_assertions)]
    debug_slack: usize,
    #[cfg(debug_assertions)]
    debug_grace: usize,
    madvise_hugepage: bool,
    /// Erase block contents on free (TODO-900). Default ON: the pool is
    /// process-global and blocks are reused across connections, so the free-
    /// time memset is the barrier that keeps connection A plaintext out of
    /// connection B buffers after an over-read bug. Benchmarks may disable it
    /// via QUICFUSCATE_POOL_ZEROIZE_ON_FREE=0 to measure its cost.
    zeroize_on_free: bool,
    auto_tune: bool,
    min_capacity: usize,
    max_capacity: usize,
    tick_ms: u64,
    utilization_low: usize,
    utilization_high: usize,
    tls_low: usize,
    tls_high: usize,
}

impl MemoryPoolRuntimeConfig {
    fn from_snapshot(environment: &EnvSnapshot) -> Self {
        let utilization_high = parse_percent(environment, "QUICFUSCATE_POOL_UTIL_HIGH", 80, 5, 95);
        let configured_low = parse_percent(environment, "QUICFUSCATE_POOL_UTIL_LOW", 30, 1, 89);
        let utilization_low = if configured_low + 5 >= utilization_high {
            utilization_high.saturating_sub(10).max(1)
        } else {
            configured_low
        };
        let tls_low = environment.parse_positive_usize("QUICFUSCATE_TLS_LOW").unwrap_or(24);
        let tls_high = environment.parse_positive_usize("QUICFUSCATE_TLS_HIGH").unwrap_or(48);
        Self {
            tls_cache_limit: AtomicUsize::new(
                environment.parse::<usize>("QUICFUSCATE_TLS_CACHE").unwrap_or(tls_high),
            ),
            madvise_hugepage: environment.flag("QUICFUSCATE_MADVISE_HUGEPAGE", true),
            zeroize_on_free: environment.flag("QUICFUSCATE_POOL_ZEROIZE_ON_FREE", true),
            #[cfg(debug_assertions)]
            debug_slack: environment.parse::<usize>("QUICFUSCATE_POOL_DEBUG_SLACK").unwrap_or(256),
            #[cfg(debug_assertions)]
            debug_grace: environment.parse::<usize>("QUICFUSCATE_POOL_DEBUG_GRACE").unwrap_or(64),
            auto_tune: environment.flag("QUICFUSCATE_POOL_AUTO_TUNE", true),
            min_capacity: environment
                .parse_positive_usize("QUICFUSCATE_POOL_MIN_CAP")
                .unwrap_or(64),
            max_capacity: environment
                .parse_positive_usize("QUICFUSCATE_POOL_MAX_CAP")
                .unwrap_or(DEFAULT_AUTO_TUNE_MAX_CAPACITY),
            tick_ms: environment.parse_positive_u64("QUICFUSCATE_POOL_TICK_MS").unwrap_or(1000),
            utilization_low,
            utilization_high,
            tls_low,
            tls_high,
        }
    }
}

fn parse_percent(
    environment: &EnvSnapshot,
    name: &str,
    default: usize,
    min: usize,
    max: usize,
) -> usize {
    match environment.parse::<usize>(name) {
        None => default,
        Some(value) => {
            let clamped = value.clamp(min, max);
            if clamped != value {
                log::warn!(
                    "{} must be between {} and {}; clamping override to {}",
                    name,
                    min,
                    max,
                    clamped
                );
            }
            clamped
        }
    }
}

static NEXT_MEMORY_POOL_ID: AtomicUsize = AtomicUsize::new(1);
const DEFAULT_AUTO_TUNE_MAX_CAPACITY: usize = 1024;
const DEFAULT_POOL_MAX_BYTES: usize = 64 * 1024 * 1024;
const MIN_POOL_BLOCK_SIZE: usize = 2048;
const POOL_ALIGNMENT: usize = 64;

/// Recoverable configuration and allocation failures for `MemoryPool`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemoryPoolError {
    /// The pool must contain at least one accounted block.
    InvalidCapacity,
    /// A zero-sized requested block cannot establish a pool contract.
    InvalidBlockSize,
    /// The requested block size cannot be represented by a valid allocator layout.
    InvalidLayout,
    /// The requested capacity and block size exceed the representable byte bound.
    CapacityOverflow,
    /// The allocator or an internal reservation could not provide memory.
    AllocationFailed,
    /// The requested slice cannot fit in one fixed-size pool block.
    SliceTooLarge { requested: usize, block_size: usize },
    /// The ownership ledger rejected a newly allocated block.
    OwnershipRejected,
}

impl std::fmt::Display for MemoryPoolError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let message = match self {
            Self::InvalidCapacity => "memory pool capacity must be greater than zero",
            Self::InvalidBlockSize => "memory pool block size must be greater than zero",
            Self::InvalidLayout => "memory pool block size cannot form a valid aligned layout",
            Self::CapacityOverflow => {
                "memory pool capacity and block size exceed the addressable byte bound"
            }
            Self::AllocationFailed => "memory pool allocation or reservation failed",
            Self::SliceTooLarge { requested, block_size } => {
                return write!(
                    formatter,
                    "memory pool slice length {requested} exceeds block size {block_size}"
                );
            }
            Self::OwnershipRejected => "memory pool ownership ledger rejected a new block",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for MemoryPoolError {}

fn effective_block_size(requested: usize) -> Result<usize, MemoryPoolError> {
    if requested == 0 {
        return Err(MemoryPoolError::InvalidBlockSize);
    }
    Ok(requested.max(MIN_POOL_BLOCK_SIZE))
}

fn checked_pool_layout(block_size: usize) -> Result<std::alloc::Layout, MemoryPoolError> {
    if block_size == 0 {
        return Err(MemoryPoolError::InvalidBlockSize);
    }
    std::alloc::Layout::from_size_align(block_size, POOL_ALIGNMENT)
        .map_err(|_| MemoryPoolError::InvalidLayout)
}

fn validate_pool_configuration(capacity: usize, block_size: usize) -> Result<(), MemoryPoolError> {
    if capacity == 0 {
        return Err(MemoryPoolError::InvalidCapacity);
    }
    let total_bytes = capacity.checked_mul(block_size).ok_or(MemoryPoolError::CapacityOverflow)?;
    if total_bytes > isize::MAX as usize {
        return Err(MemoryPoolError::CapacityOverflow);
    }
    checked_pool_layout(block_size)?;
    Ok(())
}

#[cfg(any(test, feature = "rust-tests"))]
#[doc(hidden)]
pub static LOCK_BLOCKS_TEST_MUTEX: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[derive(Debug, Default)]
struct BlockLockLedger {
    locked: std::sync::Mutex<HashSet<usize>>,
}

impl BlockLockLedger {
    fn record(&self, ptr: *mut u8) {
        let mut locked = self.locked.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        locked.insert(ptr as usize);
    }

    fn release(&self, ptr: *mut u8, len: usize) {
        let was_locked = {
            let mut locked = self.locked.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
            locked.remove(&(ptr as usize))
        };
        if was_locked {
            let _ = munlock_block(ptr, len);
        }
    }

    fn len(&self) -> usize {
        self.locked.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).len()
    }
}

struct ThreadLocalPoolCache {
    id: usize,
    lock_ledger: Arc<BlockLockLedger>,
    ownership: Arc<PoolOwnershipLedger>,
    blocks: Vec<AlignedBox<[u8]>>,
}

type ThreadLocalPoolCaches = Vec<ThreadLocalPoolCache>;

impl Drop for ThreadLocalPoolCache {
    fn drop(&mut self) {
        while let Some(block) = self.blocks.pop() {
            let _ = self.ownership.discard_available(block.as_ptr(), PoolBlockLocation::Tls);
            self.ownership.release_block(block, &self.lock_ledger);
        }
    }
}

struct AutoTunerHandle {
    stop: Arc<AtomicBool>,
    thread: std::thread::JoinHandle<()>,
}

fn auto_tuner_slot() -> &'static std::sync::Mutex<Option<AutoTunerHandle>> {
    static AUTO_TUNER: OnceLock<std::sync::Mutex<Option<AutoTunerHandle>>> = OnceLock::new();
    AUTO_TUNER.get_or_init(|| std::sync::Mutex::new(None))
}

fn default_hard_max_capacity(initial_capacity: usize, block_size: usize) -> usize {
    initial_capacity.max((DEFAULT_POOL_MAX_BYTES / block_size).max(1))
}

/// Lock a memory region against swap with `mlock(2)` (TODO-516).
/// Best-effort: logs a debug message on failure but does not panic.
/// No-op on non-Unix targets.
#[cfg(unix)]
fn mlock_block(ptr: *mut u8, len: usize) -> bool {
    // SAFETY: ptr points to a valid allocated region of `len` bytes.
    // mlock is a kernel syscall that does not dereference userspace
    // pointers beyond pinning the pages.
    let result = unsafe { libc::mlock(ptr as *const libc::c_void, len) };
    if result == 0 {
        return true;
    }
    let err = std::io::Error::last_os_error();
    // EAGAIN (insufficient RLIMIT_MEMLOCK) is common in unprivileged
    // contexts. Log once at debug to avoid spamming.
    log::debug!(
        "mlock failed for MemoryPool block ({} bytes): {} - \
         consider raising RLIMIT_MEMLOCK or LimitMEMLOCK in systemd",
        len,
        err
    );
    false
}

/// Unlock a successfully locked MemoryPool region before its allocation is dropped.
/// No-op on non-Unix targets.
#[cfg(unix)]
fn munlock_block(ptr: *mut u8, len: usize) -> bool {
    // SAFETY: ptr points to a valid allocated region of `len` bytes owned by the
    // release path that removed it from the lock ledger.
    let result = unsafe { libc::munlock(ptr as *const libc::c_void, len) };
    if result == 0 {
        return true;
    }
    log::debug!(
        "munlock failed for MemoryPool block ({} bytes): {}",
        len,
        std::io::Error::last_os_error()
    );
    false
}

#[cfg(not(unix))]
fn mlock_block(_ptr: *mut u8, _len: usize) -> bool {
    false
}

#[cfg(not(unix))]
fn munlock_block(_ptr: *mut u8, _len: usize) -> bool {
    false
}

fn release_locked_block(mut block: AlignedBox<[u8]>, lock_ledger: &BlockLockLedger) {
    block.as_mut().fill(0);
    lock_ledger.release(block.as_mut_ptr(), block.len());
    drop(block);
}

fn release_pool_queues(
    pools: &[Arc<SegQueue<AlignedBox<[u8]>>>],
    ownership: &PoolOwnershipLedger,
    lock_ledger: &BlockLockLedger,
) {
    for queue in pools {
        while let Some(block) = queue.pop() {
            ownership.discard_available(block.as_ptr(), PoolBlockLocation::Queue);
            ownership.release_block(block, lock_ledger);
        }
    }
}

impl MemoryPool {
    /// Enable or disable mlock on MemoryPool blocks (TODO-516).
    /// Call once during server startup before the pool is created.
    /// When enabled, blocks are locked against swap via `mlock(2)`.
    pub fn set_lock_blocks(enabled: bool) {
        qf_memory_lock::set_lock_blocks(enabled);
    }

    /// Check whether block-level mlocking is enabled.
    pub fn lock_blocks_enabled() -> bool {
        qf_memory_lock::lock_blocks_enabled()
    }

    // Thread-local small cache of blocks to reduce contention on queues
    thread_local! {
        static TLS_CACHES: RefCell<ThreadLocalPoolCaches> = const { RefCell::new(Vec::new()) };
    }

    #[inline]
    fn with_tls_cache<R>(&self, operation: impl FnOnce(&mut Vec<AlignedBox<[u8]>>) -> R) -> R {
        Self::TLS_CACHES.with(|caches| {
            let mut caches = caches.borrow_mut();
            let index = caches.iter().position(|cache| cache.id == self.id).unwrap_or_else(|| {
                caches.push(ThreadLocalPoolCache {
                    id: self.id,
                    lock_ledger: Arc::clone(&self.lock_ledger),
                    ownership: Arc::clone(&self.ownership),
                    blocks: Vec::new(),
                });
                caches.len() - 1
            });
            operation(&mut caches[index].blocks)
        })
    }

    #[inline]
    fn try_cache_block(
        &self,
        block: AlignedBox<[u8]>,
        limit: usize,
    ) -> Result<(), AlignedBox<[u8]>> {
        if limit == 0 {
            return Err(block);
        }
        let has_room = self.with_tls_cache(|cache| cache.len() < limit);
        if !has_room || !self.ownership.return_accounted(block.as_ptr(), PoolBlockLocation::Tls) {
            return Err(block);
        }
        self.with_tls_cache(|cache| cache.push(block));
        Ok(())
    }

    #[inline]
    fn configured_hard_max_capacity(
        initial_capacity: usize,
        block_size: usize,
        environment: &EnvSnapshot,
    ) -> usize {
        let representable_max = (isize::MAX as usize) / block_size;
        let configured = environment.parse_positive_usize("QUICFUSCATE_POOL_HARD_MAX_CAP");
        let requested = configured
            .map(|capacity| capacity.max(initial_capacity))
            .unwrap_or_else(|| default_hard_max_capacity(initial_capacity, block_size));
        if requested > representable_max {
            log::warn!(
                target: "memory_pool",
                "QUICFUSCATE_POOL_HARD_MAX_CAP={} exceeds the representable block count {}; clamping",
                requested,
                representable_max
            );
            representable_max
        } else {
            requested
        }
    }

    #[inline]
    fn tls_limit(&self) -> usize {
        self.runtime.tls_cache_limit.load(Ordering::Relaxed)
    }

    #[inline]
    fn bump_tls_limit(&self, suggested: usize) {
        let cur = self.runtime.tls_cache_limit.load(Ordering::Relaxed);
        if cur == 0 {
            return;
        }
        if suggested != cur {
            self.runtime.tls_cache_limit.store(suggested, Ordering::Relaxed);
        }
    }

    #[inline]
    fn flush_tls_to_queue(&self, node: usize, max: usize) {
        let limit = self.tls_limit();
        let mut to_flush =
            self.with_tls_cache(|cache| core::cmp::min(cache.len().saturating_sub(limit), max));
        let Some(queue) = self.pools.get(node) else {
            return;
        };
        while to_flush > 0 {
            let Some(block) = self.with_tls_cache(|cache| cache.pop()) else {
                break;
            };
            if self.ownership.move_available(
                block.as_ptr(),
                PoolBlockLocation::Tls,
                PoolBlockLocation::Queue,
            ) {
                queue.push(block);
            } else {
                self.ownership.release_block(block, &self.lock_ledger);
            }
            to_flush -= 1;
        }
    }

    /// Creates a pool with an explicit block-size contract.
    ///
    /// The requested block size is retained, subject only to the minimum safe
    /// size. This compatibility constructor is intentionally infallible for
    /// existing callers; use [`MemoryPool::try_new`] when configuration or
    /// allocation failures must be handled by the caller.
    #[allow(clippy::panic)]
    pub fn new(capacity: usize, block_size: usize) -> Self {
        Self::try_new(capacity, block_size)
            .unwrap_or_else(|error| panic!("MemoryPool::new failed: {error}"))
    }

    /// Fallible counterpart to [`MemoryPool::new`].
    pub fn try_new(capacity: usize, block_size: usize) -> Result<Self, MemoryPoolError> {
        let environment = EnvSnapshot::capture();
        Self::try_new_with_snapshot(capacity, block_size, &environment)
    }

    /// Creates a pool using one immutable environment generation.
    ///
    /// This compatibility constructor preserves the original infallible API.
    #[allow(clippy::panic)]
    #[doc(hidden)]
    pub fn new_with_snapshot(
        capacity: usize,
        block_size: usize,
        environment: &EnvSnapshot,
    ) -> Self {
        Self::try_new_with_snapshot(capacity, block_size, environment)
            .unwrap_or_else(|error| panic!("MemoryPool::new_with_snapshot failed: {error}"))
    }

    /// Fallible constructor using one immutable environment generation.
    #[doc(hidden)]
    pub fn try_new_with_snapshot(
        capacity: usize,
        block_size: usize,
        environment: &EnvSnapshot,
    ) -> Result<Self, MemoryPoolError> {
        Self::try_new_with_effective_block_size(capacity, block_size, environment)
    }

    /// Creates a pool whose block size follows the configured MTU profile.
    ///
    /// `QUICFUSCATE_POOL_ADAPTIVE_BLOCK=0|false` disables the MTU selection and
    /// retains the requested size, subject to the minimum safe size. Use the
    /// fallible counterpart when allocation errors must be recovered.
    #[allow(clippy::panic)]
    pub fn new_adaptive(capacity: usize, block_size: usize) -> Self {
        Self::try_new_adaptive(capacity, block_size)
            .unwrap_or_else(|error| panic!("MemoryPool::new_adaptive failed: {error}"))
    }

    /// Fallible counterpart to [`MemoryPool::new_adaptive`].
    pub fn try_new_adaptive(capacity: usize, block_size: usize) -> Result<Self, MemoryPoolError> {
        let environment = EnvSnapshot::capture();
        Self::try_new_adaptive_with_snapshot(capacity, block_size, &environment)
    }

    /// Creates an adaptive pool using one immutable environment generation.
    ///
    /// This compatibility constructor preserves the original infallible API.
    #[allow(clippy::panic)]
    #[doc(hidden)]
    pub fn new_adaptive_with_snapshot(
        capacity: usize,
        block_size: usize,
        environment: &EnvSnapshot,
    ) -> Self {
        Self::try_new_adaptive_with_snapshot(capacity, block_size, environment).unwrap_or_else(
            |error| panic!("MemoryPool::new_adaptive_with_snapshot failed: {error}"),
        )
    }

    /// Fallible adaptive constructor using one immutable environment generation.
    #[doc(hidden)]
    pub fn try_new_adaptive_with_snapshot(
        capacity: usize,
        block_size: usize,
        environment: &EnvSnapshot,
    ) -> Result<Self, MemoryPoolError> {
        if block_size == 0 {
            return Err(MemoryPoolError::InvalidBlockSize);
        }
        Self::try_new_with_effective_block_size(
            capacity,
            Self::adaptive_block_size_with_snapshot(block_size, environment),
            environment,
        )
    }

    fn try_new_with_effective_block_size(
        capacity: usize,
        block_size: usize,
        environment: &EnvSnapshot,
    ) -> Result<Self, MemoryPoolError> {
        let block_size = effective_block_size(block_size)?;
        validate_pool_configuration(capacity, block_size)?;
        checked_pool_layout(block_size)?;
        let lock_blocks = Self::lock_blocks_enabled();
        let lock_ledger = Arc::new(BlockLockLedger::default());
        let runtime = Arc::new(MemoryPoolRuntimeConfig::from_snapshot(environment));
        let capacity_counter = Arc::new(AtomicUsize::new(0));
        let in_use_counter = Arc::new(AtomicUsize::new(0));
        let available_counter = Arc::new(AtomicUsize::new(0));
        let ownership = Arc::new(PoolOwnershipLedger::try_new(
            Arc::clone(&capacity_counter),
            Arc::clone(&in_use_counter),
            Arc::clone(&available_counter),
            capacity,
        )?);
        #[cfg(target_os = "linux")]
        initialize_numa_policy(environment);
        let nodes = numa::num_nodes().max(1);
        let id = NEXT_MEMORY_POOL_ID.fetch_add(1, Ordering::Relaxed);
        let mut pools = Vec::new();
        pools.try_reserve_exact(nodes).map_err(|_| MemoryPoolError::AllocationFailed)?;
        for n in 0..nodes {
            let node_cap = capacity / nodes + if n < capacity % nodes { 1 } else { 0 };
            let q = Arc::new(SegQueue::new());
            pools.push(Arc::clone(&q));
            for _ in 0..node_cap {
                let block = match Self::alloc_numa_block(
                    block_size,
                    n,
                    lock_blocks,
                    &lock_ledger,
                    runtime.madvise_hugepage,
                ) {
                    Ok(block) => block,
                    Err(error) => {
                        release_pool_queues(&pools, &ownership, &lock_ledger);
                        return Err(error);
                    }
                };
                if ownership.register(
                    block.as_ptr(),
                    PoolBlockOrigin::Accounted,
                    PoolBlockLocation::Queue,
                ) {
                    q.push(block);
                } else {
                    ownership.release_block(block, &lock_ledger);
                    release_pool_queues(&pools, &ownership, &lock_ledger);
                    return Err(MemoryPoolError::OwnershipRejected);
                }
            }
        }
        let pool = Self {
            id,
            lock_blocks,
            lock_ledger,
            pools,
            block_size,
            num_nodes: nodes,
            capacity: capacity_counter,
            hard_max_capacity: Self::configured_hard_max_capacity(
                capacity,
                block_size,
                environment,
            ),
            in_use: in_use_counter,
            available: available_counter,
            ownership,
            resize_lock: std::sync::Mutex::new(()),
            runtime,
        };
        // Telemetry init
        telemetry::MEM_POOL_CAPACITY.store(capacity as u64, Ordering::Relaxed);
        telemetry::MEM_POOL_BLOCK_SIZE.store(block_size as u64, Ordering::Relaxed);
        pool.update_metrics();
        Ok(pool)
    }

    #[cfg(debug_assertions)]
    #[inline(always)]
    fn check_invariants(&self) {
        if cfg!(test) {
            return;
        }
        use std::thread;
        let cap = self.capacity.load(Ordering::Acquire);
        let in_use = self.in_use.load(Ordering::Acquire);
        let avail = self.available.load(Ordering::Acquire);
        // Allow transient slack due to non-atomic pair updates of (available,in_use).
        // These diagnostic bounds belong to the pool's construction snapshot.
        let slack = self.runtime.debug_slack;
        let grace = self.runtime.debug_grace;
        if in_use > cap.saturating_add(slack).saturating_add(grace)
            || avail > cap.saturating_add(slack).saturating_add(grace)
        {
            // Re-read once to avoid transient races
            thread::yield_now();
            let cap2 = self.capacity.load(Ordering::SeqCst);
            let in_use2 = self.in_use.load(Ordering::SeqCst);
            let avail2 = self.available.load(Ordering::SeqCst);
            if in_use2 > cap2.saturating_add(slack).saturating_add(grace)
                || avail2 > cap2.saturating_add(slack).saturating_add(grace)
            {
                // One more short backoff for extremely bursty updates
                thread::yield_now();
                let cap3 = self.capacity.load(Ordering::SeqCst);
                let in_use3 = self.in_use.load(Ordering::SeqCst);
                let avail3 = self.available.load(Ordering::SeqCst);
                if in_use3 > cap3.saturating_add(slack).saturating_add(grace).saturating_add(1) {
                    log::warn!(
                      target: "memory_pool",
                      "in_use {} > capacity {} (after retry2, slack={}, grace={}, +1)",
                      in_use3, cap3, slack, grace
                    );
                }
                if avail3 > cap3.saturating_add(slack).saturating_add(grace).saturating_add(1) {
                    log::warn!(
                      target: "memory_pool",
                      "available {} > capacity {} (after retry2, slack={}, grace={}, +1)",
                      avail3, cap3, slack, grace
                    );
                }
            }
        }
    }
    #[cfg(not(debug_assertions))]
    #[inline(always)]
    fn check_invariants(&self) {}

    /// Allocate a 64-byte aligned block bound to the given NUMA node.
    fn alloc_numa_block(
        block_size: usize,
        node: usize,
        lock_blocks: bool,
        lock_ledger: &BlockLockLedger,
        madvise_hugepage: bool,
    ) -> Result<AlignedBox<[u8]>, MemoryPoolError> {
        #[cfg(not(target_os = "linux"))]
        let _ = madvise_hugepage;
        // Use manual aligned allocation to guarantee exact length = block_size.
        let layout = checked_pool_layout(block_size)?;
        let ptr = unsafe { std::alloc::alloc(layout) };
        if ptr.is_null() {
            return Err(MemoryPoolError::AllocationFailed);
        }
        // Zero-initialize for deterministic tests and safety
        unsafe { std::ptr::write_bytes(ptr, 0u8, block_size) };
        let slice = unsafe { std::slice::from_raw_parts_mut(ptr, block_size) };
        // SAFETY: ptr was allocated with the given layout; aligned_box will track layout for dealloc
        #[cfg(target_os = "linux")]
        let mut block = unsafe { AlignedBox::<[u8]>::from_raw_parts(slice, layout) };
        #[cfg(not(target_os = "linux"))]
        let mut block = unsafe { AlignedBox::<[u8]>::from_raw_parts(slice, layout) };
        // Hint huge pages on Linux if enabled
        #[cfg(target_os = "linux")]
        if madvise_hugepage && block_size >= 1_048_576 {
            unsafe {
                let _ = libc::madvise(
                    block.as_mut_ptr() as *mut libc::c_void,
                    block_size,
                    libc::MADV_HUGEPAGE,
                );
            }
        }
        #[cfg(target_os = "linux")]
        {
            if numa::is_available() {
                let policy = *NUMA_POLICY.get_or_init(|| NumaPolicy::Local);
                let nodes = numa::num_nodes().max(1);
                let target = match policy {
                    NumaPolicy::Local => node,
                    NumaPolicy::Preferred(n) => n % nodes,
                    NumaPolicy::Interleave => RR_NODE.fetch_add(1, Ordering::Relaxed) % nodes,
                };
                numa::move_to_node(block.as_mut_ptr(), block_size, target);
                // telemetry hint for policy
                telemetry::MEM_POOL_NUMA_POLICY.store(
                    match policy {
                        NumaPolicy::Local => 0,
                        NumaPolicy::Preferred(_) => 1,
                        NumaPolicy::Interleave => 2,
                    },
                    Ordering::Relaxed,
                );
            }
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = node; // silence unused parameter warning on non-Linux
        }
        // Lock block against swap if enabled (TODO-516).
        if lock_blocks && mlock_block(block.as_mut_ptr(), block_size) {
            lock_ledger.record(block.as_mut_ptr());
        }
        Ok(block)
    }

    /// Returns the effective block size used by every allocation from the pool.
    #[inline]
    pub fn block_size(&self) -> usize {
        self.block_size
    }

    fn try_grow_locked(&self, new_capacity: usize) -> Result<(), MemoryPoolError> {
        let target = core::cmp::min(new_capacity, self.hard_max_capacity);
        while self.capacity.load(Ordering::Acquire) < target {
            for (n, queue) in self.pools.iter().enumerate() {
                if self.capacity.load(Ordering::Acquire) >= target {
                    break;
                }
                let block = Self::alloc_numa_block(
                    self.block_size,
                    n,
                    self.lock_blocks,
                    &self.lock_ledger,
                    self.runtime.madvise_hugepage,
                )?;
                let capacity_before = self.capacity.load(Ordering::Acquire);
                if self.ownership.register(
                    block.as_ptr(),
                    PoolBlockOrigin::Accounted,
                    PoolBlockLocation::Queue,
                ) {
                    queue.push(block);
                    if self.capacity.load(Ordering::Acquire) <= capacity_before {
                        log::debug!(
                            target: "memory_pool",
                            "stopping pool growth because stale-address recovery made no capacity progress"
                        );
                        return Ok(());
                    }
                } else {
                    log::error!(
                        target: "memory_pool",
                        "stopping pool growth because the ownership ledger rejected a new block"
                    );
                    self.ownership.release_block(block, &self.lock_ledger);
                    return Err(MemoryPoolError::OwnershipRejected);
                }
            }
        }
        Ok(())
    }

    fn try_grow(&self, new_capacity: usize) -> Result<(), MemoryPoolError> {
        let _resize_guard =
            self.resize_lock.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        self.try_grow_locked(new_capacity)?;
        self.update_metrics();
        self.check_invariants();
        Ok(())
    }

    fn pop_queue_block(&self, queue: &SegQueue<AlignedBox<[u8]>>) -> Option<AlignedBox<[u8]>> {
        loop {
            let block = queue.pop()?;
            if block.len() != self.block_size {
                log::error!(
                    target: "memory_pool",
                    "discarding an internally mismatched queue block: {} != {}",
                    block.len(),
                    self.block_size
                );
                let _ = self.ownership.discard_available(block.as_ptr(), PoolBlockLocation::Queue);
                self.ownership.release_block(block, &self.lock_ledger);
                continue;
            }
            if self.ownership.checkout(block.as_ptr(), PoolBlockLocation::Queue) {
                return Some(block);
            }
            log::error!(target: "memory_pool", "queue block was absent from the ownership ledger");
            self.ownership.release_block(block, &self.lock_ledger);
        }
    }

    fn update_metrics(&self) {
        let cap = self.capacity.load(Ordering::Relaxed);
        let in_use = self.in_use.load(Ordering::Relaxed);
        let avail = self.available.load(Ordering::Relaxed);
        telemetry::MEM_POOL_IN_USE.store(in_use as u64, Ordering::Relaxed);
        let usage_bytes = in_use.saturating_mul(self.block_size) as u64;
        telemetry::MEM_POOL_USAGE_BYTES.store(usage_bytes, Ordering::Relaxed);
        let total = in_use.saturating_add(avail);
        let _frag = cap.saturating_sub(total);
        // Fragmentation not tracked precisely; leave default 0
        let util =
            if cap == 0 { 0 } else { (in_use.saturating_mul(100).saturating_div(cap)) as u64 };
        telemetry::MEM_POOL_CAPACITY.store(cap as u64, Ordering::Relaxed);
        telemetry::MEM_POOL_UTILIZATION.store(util, Ordering::Relaxed);
    }

    /// Re-publishes pool utilization counters to the telemetry subsystem.
    pub fn refresh_metrics(&self) {
        self.update_metrics();
    }

    /// Snapshot of `(capacity, in_use, available)` for pool-accounting assertions.
    ///
    /// Gated to `cfg(test)` rather than `rust-tests`: every consumer is an in-crate `#[cfg(test)]`
    /// module, so the wider gate compiled it into `rust-tests` library builds where nothing could
    /// reach it, which is what the strict all-target lint reported as dead code.
    #[cfg(any(test, feature = "rust-tests"))]
    #[doc(hidden)]
    pub fn accounting_snapshot(&self) -> (usize, usize, usize) {
        (
            self.capacity.load(Ordering::Acquire),
            self.in_use.load(Ordering::Acquire),
            self.available.load(Ordering::Acquire),
        )
    }

    /// Allocates a 64-byte aligned memory block from the pool.
    /// If the pool is empty, a new block is created. Use [`MemoryPool::try_alloc`]
    /// when allocation failure must be handled by the caller.
    #[inline(always)]
    #[allow(clippy::panic)]
    pub fn alloc(&self) -> AlignedBox<[u8]> {
        self.try_alloc().unwrap_or_else(|error| panic!("MemoryPool::alloc failed: {error}"))
    }

    /// Fallible counterpart to [`MemoryPool::alloc`].
    #[inline(always)]
    pub fn try_alloc(&self) -> Result<AlignedBox<[u8]>, MemoryPoolError> {
        let node = numa::current_node() % self.num_nodes;
        self.flush_tls_to_queue(node, usize::MAX);
        // Fast-path: check TLS cache first
        if let Some(b) = self.with_tls_cache(Vec::pop) {
            if b.len() == self.block_size
                && self.ownership.checkout(b.as_ptr(), PoolBlockLocation::Tls)
            {
                telemetry::MEM_POOL_HITS_TLS.inc();
                // Warm cache for caller
                prefetch(b.as_ptr(), PrefetchHint::T0);
                return Ok(b);
            } else {
                let _ = self.ownership.discard_available(b.as_ptr(), PoolBlockLocation::Tls);
                self.ownership.release_block(b, &self.lock_ledger);
            }
        }

        // Slow-path: try queue, create if needed
        self.alloc_cold()
    }

    /// Allocates an aligned buffer and copies data from the provided slice
    /// using the compatibility infallible API. Use [`MemoryPool::try_alloc_from_slice`]
    /// when oversize input or allocation failure must be handled.
    #[allow(clippy::panic)]
    pub fn alloc_from_slice(&self, data: &[u8]) -> AlignedBox<[u8]> {
        self.try_alloc_from_slice(data)
            .unwrap_or_else(|error| panic!("MemoryPool::alloc_from_slice failed: {error}"))
    }

    /// Fallible counterpart to [`MemoryPool::alloc_from_slice`].
    pub fn try_alloc_from_slice(&self, data: &[u8]) -> Result<AlignedBox<[u8]>, MemoryPoolError> {
        if data.len() > self.block_size {
            return Err(MemoryPoolError::SliceTooLarge {
                requested: data.len(),
                block_size: self.block_size,
            });
        }
        let mut buf = self.try_alloc()?;
        buf[..data.len()].copy_from_slice(data);
        Ok(buf)
    }

    #[cold]
    #[inline(never)]
    fn alloc_cold(&self) -> Result<AlignedBox<[u8]>, MemoryPoolError> {
        let node = numa::current_node() % self.num_nodes;
        // Opportunistically flush some TLS cache back to the global queue
        // to reduce long-term TLS growth under bursty patterns
        self.flush_tls_to_queue(node, 8);
        if let Some(queue) = self.pools.get(node) {
            if let Some(b) = self.pop_queue_block(queue) {
                telemetry::MEM_POOL_HITS_QUEUE.inc();
                self.update_metrics();
                self.check_invariants();
                // telemetry!(telemetry::update_memory_usage());
                // Prefetch freshly popped memory to warm cache for the caller
                prefetch(b.as_ptr(), PrefetchHint::T0);
                return Ok(b);
            }
        }
        // Opportunistically steal from other NUMA queues to reduce growth pressure
        if self.num_nodes > 1 {
            for off in 1..self.num_nodes {
                let idx = (node + off) % self.num_nodes;
                if let Some(q) = self.pools.get(idx) {
                    if let Some(b) = self.pop_queue_block(q) {
                        // Treat as regular queue hit
                        self.update_metrics();
                        self.check_invariants();
                        prefetch(b.as_ptr(), PrefetchHint::T0);
                        return Ok(b);
                    }
                }
            }
        }
        // Attempt growth respecting hard cap
        let cap_now = self.capacity.load(Ordering::Relaxed);
        let limit = self.hard_max_capacity;
        if cap_now < limit {
            let mut target = cap_now.saturating_mul(2);
            if target == 0 {
                target = 1;
            }
            if target > limit {
                target = limit;
            }
            self.try_grow(target)?;
            // Try again after growth
            if let Some(queue) = self.pools.get(node) {
                if let Some(b) = self.pop_queue_block(queue) {
                    telemetry::MEM_POOL_ALLOC_GROW.inc();
                    self.update_metrics();
                    self.check_invariants();
                    prefetch(b.as_ptr(), PrefetchHint::T0);
                    return Ok(b);
                }
            }
        }
        // If we are strictly at the hard cap, we cannot grow. As a last resort, allocate
        // an ephemeral block which is tracked separately and never enters accounted state.
        telemetry::MEM_POOL_ALLOC_EPHEMERAL.inc();
        let block = Self::alloc_numa_block(
            self.block_size,
            node,
            self.lock_blocks,
            &self.lock_ledger,
            self.runtime.madvise_hugepage,
        )?;
        if !self.ownership.register(
            block.as_ptr(),
            PoolBlockOrigin::Ephemeral,
            PoolBlockLocation::CheckedOut,
        ) {
            log::error!(
                target: "memory_pool",
                "returning an untracked emergency block because the ownership ledger rejected ephemeral registration"
            );
            self.ownership.release_block(block, &self.lock_ledger);
            return Err(MemoryPoolError::OwnershipRejected);
        }
        prefetch(block.as_ptr(), PrefetchHint::T0);
        Ok(block)
    }

    /// Returns a memory block to the pool.
    /// If the pool is full, the block is zeroized, unlocked when applicable, and dropped.
    /// Callers own the return boundary and must use this method instead of dropping a pooled
    /// block directly.
    #[inline(always)]
    pub fn free(&self, mut block: AlignedBox<[u8]>) {
        let ptr = block.as_ptr();
        if block.len() != self.block_size {
            log::debug!(
                target: "memory_pool",
                "rejecting block with mismatched length: {} != {}",
                block.len(),
                self.block_size
            );
            self.ownership.discard_released(ptr);
            release_locked_block(block, &self.lock_ledger);
            return;
        }

        let Some(origin) = self.ownership.begin_free(ptr) else {
            log::debug!(target: "memory_pool", "rejecting foreign or non-checked-out block {:p}", ptr);
            self.ownership.discard_released(ptr);
            release_locked_block(block, &self.lock_ledger);
            return;
        };

        // Zeroize efficiently; allows vectorized memset. Policy-driven since
        // TODO-900: QUICFUSCATE_POOL_ZEROIZE_ON_FREE=0 skips the erase so
        // benchmarks can measure its cost. Default stays ON - the pool is
        // process-global and blocks are reused across connections, so this
        // memset is the barrier against cross-connection stale-data leaks.
        if self.runtime.zeroize_on_free {
            block.as_mut().fill(0);
        }

        if origin == PoolBlockOrigin::Ephemeral {
            self.ownership.release_block(block, &self.lock_ledger);
            self.update_metrics();
            return;
        }

        // Try to place into TLS cache
        let limit = self.tls_limit();
        let block = match self.try_cache_block(block, limit) {
            Ok(()) => return,
            Err(block) => block,
        };

        // Fallback: return to global pool queue
        let node = numa::current_node() % self.num_nodes;
        if let Some(queue) = self.pools.get(node) {
            if self.ownership.return_accounted(block.as_ptr(), PoolBlockLocation::Queue) {
                queue.push(block);
                self.update_metrics();
                self.check_invariants();
                return;
            }
        }

        log::error!(target: "memory_pool", "checked-out block lost its ownership record");
        self.ownership.release_block(block, &self.lock_ledger);
        self.update_metrics();
        self.check_invariants();
        // telemetry!(telemetry::update_memory_usage());
    }

    /// Adjusts the maximum number of cached blocks at runtime.
    ///
    /// The compatibility API remains infallible; callers that need an error
    /// result must use [`MemoryPool::try_set_capacity`].
    #[allow(clippy::panic)]
    pub fn set_capacity(&self, new_capacity: usize) {
        self.try_set_capacity(new_capacity)
            .unwrap_or_else(|error| panic!("MemoryPool::set_capacity failed: {error}"));
    }

    /// Fallible counterpart to [`MemoryPool::set_capacity`].
    pub fn try_set_capacity(&self, new_capacity: usize) -> Result<(), MemoryPoolError> {
        let limit = self.hard_max_capacity;
        let clamped = core::cmp::min(new_capacity, limit);
        let node = numa::current_node() % self.num_nodes;
        self.bump_tls_limit(self.tls_limit().min(clamped));
        self.flush_tls_to_queue(node, usize::MAX);

        let _resize_guard =
            self.resize_lock.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let current = self.capacity.load(Ordering::Acquire);
        if clamped > current {
            self.try_grow_locked(clamped)?;
        } else {
            let mut remaining = current - clamped;
            while remaining > 0 {
                let mut removed = false;
                for queue in &self.pools {
                    if remaining == 0 {
                        break;
                    }
                    let Some(block) = queue.pop() else {
                        continue;
                    };
                    if self.ownership.discard_available(block.as_ptr(), PoolBlockLocation::Queue) {
                        self.ownership.release_block(block, &self.lock_ledger);
                        remaining -= 1;
                        removed = true;
                    } else {
                        log::error!(target: "memory_pool", "queue block was absent from the ownership ledger during shrink");
                        self.ownership.release_block(block, &self.lock_ledger);
                    }
                }
                if !removed {
                    break;
                }
            }
        }
        self.update_metrics();
        self.check_invariants();
        Ok(())
    }

    /// Background auto-tuner: periodically adjusts capacity based on usage.
    /// Controlled by env QUICFUSCATE_POOL_AUTO_TUNE (default true),
    /// QUICFUSCATE_POOL_MIN_CAP, QUICFUSCATE_POOL_MAX_CAP, QUICFUSCATE_POOL_TICK_MS.
    /// Determine an adaptive block size based on environment hints and MTU.
    fn adaptive_block_size_with_snapshot(requested: usize, environment: &EnvSnapshot) -> usize {
        if !environment.flag("QUICFUSCATE_POOL_ADAPTIVE_BLOCK", true) {
            return requested;
        }
        // Auto-tune based on common MTU patterns
        let mtu_hint = environment.parse_positive_usize("QUICFUSCATE_MTU_HINT").unwrap_or(1500);
        Self::adaptive_block_size_for_mtu(mtu_hint)
    }

    fn adaptive_block_size_for_mtu(mtu_hint: usize) -> usize {
        if mtu_hint <= 1500 {
            // Standard Ethernet: use 4KB blocks
            4096
        } else if mtu_hint <= 9000 {
            // Jumbo frames: use 16KB blocks (must hold 9000 + tag + FEC, 8192 would truncate)
            16384
        } else {
            // High-speed datacenter: use 64KB blocks
            65536
        }
    }

    /// Spawns a background thread that periodically adjusts pool capacity based on utilization.
    pub fn start_auto_tuner(pool: Arc<MemoryPool>) {
        if !pool.runtime.auto_tune {
            return;
        }

        let mut slot = auto_tuner_slot().lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        if slot.is_some() {
            return;
        }

        let stop = Arc::new(AtomicBool::new(false));
        let thread_stop = Arc::clone(&stop);
        let thread = match std::thread::Builder::new()
            .name("quicfuscate-pool-auto-tuner".to_owned())
            .spawn(move || {
                let min_cap = pool.runtime.min_capacity;
                let max_cap = pool.runtime.max_capacity.max(min_cap);
                let tick_ms = pool.runtime.tick_ms;
                loop {
                    if thread_stop.load(Ordering::Acquire) {
                        break;
                    }

                    let util_high = pool.runtime.utilization_high;
                    let util_low = pool.runtime.utilization_low;
                    let tls_high = pool.runtime.tls_high;
                    let tls_low = pool.runtime.tls_low;

                    let cap = pool.capacity.load(Ordering::Relaxed);
                    let in_use = pool.in_use.load(Ordering::Relaxed);
                    let util = in_use.saturating_mul(100).checked_div(cap).unwrap_or(0);
                    let mut target = cap;
                    if util > util_high {
                        target = core::cmp::min(cap.saturating_mul(2), max_cap);
                        // Under high utilization, raise TLS cache to reduce contention
                        pool.bump_tls_limit(tls_high);
                    } else if util < util_low {
                        target = core::cmp::max(cap / 2, min_cap);
                        // Under low utilization, shrink TLS cache for footprint
                        pool.bump_tls_limit(tls_low);
                    }
                    if target != cap {
                        if let Err(error) = pool.try_set_capacity(target) {
                            warn!(
                                target: "memory_pool",
                                "auto-tuner could not resize MemoryPool to {}: {}",
                                target,
                                error
                            );
                        }
                    }

                    std::thread::park_timeout(std::time::Duration::from_millis(tick_ms));
                }
            }) {
            Ok(thread) => thread,
            Err(error) => {
                warn!(target: "memory_pool", "failed to start auto-tuner thread: {}", error);
                return;
            }
        };

        *slot = Some(AutoTunerHandle { stop, thread });
    }

    /// Stops and joins the process-wide auto-tuner thread when one is running.
    /// Stop and join the process-global auto-tuner worker.
    ///
    /// # Lifecycle contract
    ///
    /// This is a process-final or test-teardown operation, not a pool operation. It stops the one
    /// worker held in the process-global slot and joins it, so no thread survives the call. The
    /// published `GLOBAL_POOL` is intentionally left in place: it is an `OnceLock` and the pool
    /// remains valid and usable for allocation afterwards, just without background tuning.
    ///
    /// Calling it when no worker is running is a no-op. Because the slot is emptied, a caller that
    /// wants tuning back can call [`Self::start_auto_tuner`] again with the existing pool;
    /// [`crate::optimize::global_pool`] will not restart it on its own, since the pool is already
    /// initialized and its initializer never runs a second time.
    ///
    /// `MemoryPool::drop` deliberately does not call this. The worker is process-global while a
    /// pool is not, so tying the two together would let dropping any pool stop tuning for the one
    /// that is still published.
    pub fn shutdown_auto_tuner() {
        let handle = {
            let mut slot =
                auto_tuner_slot().lock().unwrap_or_else(|poisoned| poisoned.into_inner());
            slot.take()
        };
        let Some(handle) = handle else {
            return;
        };

        handle.stop.store(true, Ordering::Release);
        handle.thread.thread().unpark();
        if handle.thread.join().is_err() {
            warn!(target: "memory_pool", "auto-tuner thread terminated with a panic");
        }
    }

    /// Reports whether the process-global auto-tuner worker slot is occupied.
    #[cfg(any(test, feature = "rust-tests"))]
    #[doc(hidden)]
    pub fn auto_tuner_running_for_tests() -> bool {
        auto_tuner_slot().lock().unwrap_or_else(|poisoned| poisoned.into_inner()).is_some()
    }
}

impl Drop for MemoryPool {
    fn drop(&mut self) {
        self.ownership.close();
        for queue in &self.pools {
            while let Some(block) = queue.pop() {
                self.ownership.release_block(block, &self.lock_ledger);
            }
        }

        Self::TLS_CACHES.with(|caches| {
            let mut caches = caches.borrow_mut();
            if let Some(index) = caches.iter().position(|cache| cache.id == self.id) {
                caches.swap_remove(index);
            }
        });

        let remaining = self.lock_ledger.len();
        if remaining != 0 {
            log::debug!(
                target: "memory_pool",
                "MemoryPool dropped with {} checked-out locked block(s); callers must return them through MemoryPool::free",
                remaining
            );
        }
    }
}

/// An owned pool block that returns itself through [`MemoryPool::free`] when dropped.
///
/// Use this guard while a caller still controls a block and may return early, propagate an
/// error, or unwind. Ownership can be transferred to an existing pool-aware wrapper through the
/// crate-internal transfer methods without changing the block's allocation or pool identity.
#[must_use = "dropping a pooled block returns it to its originating MemoryPool"]
pub struct PooledBlock {
    block: Option<AlignedBox<[u8]>>,
    pool: Arc<MemoryPool>,
}

impl PooledBlock {
    /// Allocate a block whose drop path returns it to `pool`.
    pub fn new(pool: Arc<MemoryPool>) -> Self {
        let block = pool.alloc();
        Self { block: Some(block), pool }
    }

    /// Wrap a block already allocated from `pool` so that `Drop` returns it to the pool.
    ///
    /// The caller must guarantee that `block` was allocated from `pool` (e.g. via `pool.alloc()`).
    /// This is exposed as `pub(crate)` because internal modules pass their own checked-out blocks
    /// directly into the FEC packet path.
    ///
    /// Fails closed instead of panicking when the block length does not match the pool block size.
    /// The rejected block is returned to the caller so it can be released through
    /// [`MemoryPool::free`] and pool accounting stays exact.
    #[doc(hidden)]
    pub fn from_pool_block(
        pool: Arc<MemoryPool>,
        block: AlignedBox<[u8]>,
    ) -> Result<Self, AlignedBox<[u8]>> {
        if block.len() != pool.block_size() {
            return Err(block);
        }
        Ok(Self { block: Some(block), pool })
    }

    /// Return the originating pool for an ownership transfer inside the crate.
    #[doc(hidden)]
    pub fn pool(&self) -> Arc<MemoryPool> {
        Arc::clone(&self.pool)
    }

    /// Take the raw block for an ownership transfer inside the crate.
    ///
    /// Once taken, this guard remains a harmless pool keep-alive and no longer returns a block on
    /// drop. Callers must immediately pass the returned block to another owner or to
    /// [`MemoryPool::free`].
    #[doc(hidden)]
    pub fn take_block(&mut self) -> Option<AlignedBox<[u8]>> {
        self.block.take()
    }

    /// Return whether this guard still owns its checked-out block.
    #[doc(hidden)]
    pub fn is_live(&self) -> bool {
        self.block.is_some()
    }
}

impl std::ops::Deref for PooledBlock {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.block.as_deref().unwrap_or(&[])
    }
}

impl std::ops::DerefMut for PooledBlock {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.block.as_deref_mut().unwrap_or(&mut [])
    }
}

impl Drop for PooledBlock {
    fn drop(&mut self) {
        if let Some(block) = self.block.take() {
            self.pool.free(block);
        }
    }
}

mod zero_copy_buffers;
#[cfg(any(unix, windows))]
pub use zero_copy_buffers::{
    ZeroCopyBuffer, ZeroCopyError, ZeroCopyRecvBuffer, ZeroCopyResult, ZeroCopyTransfer,
};

#[cfg(test)]
mod memory_pool_growth_tests;
