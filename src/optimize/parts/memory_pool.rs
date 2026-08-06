//
// Foundational Structures for Global Optimizations
//

use std::collections::HashMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PoolBlockOrigin {
    Accounted,
    Ephemeral,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PoolBlockLocation {
    Queue,
    Tls,
    CheckedOut,
}

#[derive(Debug, Clone, Copy)]
struct PoolBlockRecord {
    origin: PoolBlockOrigin,
    location: PoolBlockLocation,
}

#[derive(Debug, Default)]
struct PoolOwnershipState {
    records: HashMap<usize, PoolBlockRecord>,
}

/// Shared lifetime and ownership state for a `MemoryPool` and its thread-local caches.
/// The `Arc` held by each TLS cache keeps this ledger alive until its blocks are dropped,
/// even when the owning `MemoryPool` has already been dropped on another thread.
#[derive(Debug)]
struct PoolOwnershipLedger {
    state: std::sync::Mutex<PoolOwnershipState>,
    closed: AtomicBool,
    capacity: Arc<AtomicUsize>,
    in_use: Arc<AtomicUsize>,
    available: Arc<AtomicUsize>,
}

impl PoolOwnershipLedger {
    fn new(
        capacity: Arc<AtomicUsize>,
        in_use: Arc<AtomicUsize>,
        available: Arc<AtomicUsize>,
    ) -> Self {
        Self {
            state: std::sync::Mutex::new(PoolOwnershipState::default()),
            closed: AtomicBool::new(false),
            capacity,
            in_use,
            available,
        }
    }

    fn lock_state(&self) -> std::sync::MutexGuard<'_, PoolOwnershipState> {
        self.state.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    #[inline]
    fn decrement(counter: &AtomicUsize) {
        let _ = counter.fetch_update(Ordering::AcqRel, Ordering::Acquire, |value| {
            Some(value.saturating_sub(1))
        });
    }

    fn register(&self, ptr: *const u8, origin: PoolBlockOrigin, location: PoolBlockLocation) -> bool {
        if self.closed.load(Ordering::Acquire) {
            return false;
        }

        let address = ptr as usize;
        let mut state = self.lock_state();
        if self.closed.load(Ordering::Acquire) {
            return false;
        }

        if let Some(previous) = state.records.remove(&address) {
            log::debug!(
                target: "memory_pool",
                "replacing stale ownership record for duplicate block address {:p} (old={previous:?}, new origin={origin:?}, location={location:?})",
                ptr,
            );
            if previous.origin == PoolBlockOrigin::Accounted {
                Self::decrement(&self.capacity);
                match previous.location {
                    PoolBlockLocation::Queue | PoolBlockLocation::Tls => {
                        Self::decrement(&self.available);
                    }
                    PoolBlockLocation::CheckedOut => {
                        Self::decrement(&self.in_use);
                    }
                }
            }
        }
        state.records.insert(address, PoolBlockRecord { origin, location });
        if origin == PoolBlockOrigin::Accounted {
            self.capacity.fetch_add(1, Ordering::AcqRel);
            match location {
                PoolBlockLocation::Queue | PoolBlockLocation::Tls => {
                    self.available.fetch_add(1, Ordering::AcqRel);
                }
                PoolBlockLocation::CheckedOut => {
                    self.in_use.fetch_add(1, Ordering::AcqRel);
                }
            }
        }
        true
    }

    fn checkout(&self, ptr: *const u8, from: PoolBlockLocation) -> bool {
        let mut state = self.lock_state();
        let Some(record) = state.records.get_mut(&(ptr as usize)) else {
            return false;
        };
        if record.origin != PoolBlockOrigin::Accounted || record.location != from {
            return false;
        }
        record.location = PoolBlockLocation::CheckedOut;
        Self::decrement(&self.available);
        self.in_use.fetch_add(1, Ordering::AcqRel);
        true
    }

    fn begin_free(&self, ptr: *const u8) -> Option<PoolBlockOrigin> {
        if self.closed.load(Ordering::Acquire) {
            return None;
        }

        let mut state = self.lock_state();
        let address = ptr as usize;
        let record = state.records.get(&address).copied()?;
        if record.location != PoolBlockLocation::CheckedOut {
            return None;
        }
        if record.origin == PoolBlockOrigin::Ephemeral {
            state.records.remove(&address);
        }
        Some(record.origin)
    }

    fn return_accounted(&self, ptr: *const u8, location: PoolBlockLocation) -> bool {
        let mut state = self.lock_state();
        let Some(record) = state.records.get_mut(&(ptr as usize)) else {
            return false;
        };
        if record.origin != PoolBlockOrigin::Accounted
            || record.location != PoolBlockLocation::CheckedOut
        {
            return false;
        }
        record.location = location;
        Self::decrement(&self.in_use);
        self.available.fetch_add(1, Ordering::AcqRel);
        true
    }

    fn move_available(
        &self,
        ptr: *const u8,
        from: PoolBlockLocation,
        to: PoolBlockLocation,
    ) -> bool {
        let mut state = self.lock_state();
        let Some(record) = state.records.get_mut(&(ptr as usize)) else {
            return false;
        };
        if record.origin != PoolBlockOrigin::Accounted || record.location != from {
            return false;
        }
        record.location = to;
        true
    }

    fn discard_available(&self, ptr: *const u8, location: PoolBlockLocation) -> bool {
        let mut state = self.lock_state();
        let address = ptr as usize;
        let Some(record) = state.records.get(&address).copied() else {
            return false;
        };
        if record.origin != PoolBlockOrigin::Accounted || record.location != location {
            return false;
        }
        state.records.remove(&address);
        Self::decrement(&self.available);
        Self::decrement(&self.capacity);
        true
    }

    /// Removes the ledger record for a block that is about to be physically released.
    ///
    /// This is the fail-closed cleanup path for malformed queue/TLS transitions. The caller
    /// has already removed the block from its physical owner, so retaining any ledger record
    /// would make a future allocator address look like a duplicate live block.
    fn discard_released(&self, ptr: *const u8) -> bool {
        let mut state = self.lock_state();
        let Some(record) = state.records.remove(&(ptr as usize)) else {
            return false;
        };
        if record.origin == PoolBlockOrigin::Accounted {
            Self::decrement(&self.capacity);
            match record.location {
                PoolBlockLocation::Queue | PoolBlockLocation::Tls => {
                    Self::decrement(&self.available);
                }
                PoolBlockLocation::CheckedOut => {
                    Self::decrement(&self.in_use);
                }
            }
        }
        true
    }

    fn release_block(&self, block: AlignedBox<[u8]>, lock_ledger: &BlockLockLedger) {
        self.discard_released(block.as_ptr());
        release_locked_block(block, lock_ledger);
    }

    #[cfg(test)]
    fn assert_consistent(&self) {
        let state = self.lock_state();
        let mut accounted = 0usize;
        let mut available = 0usize;
        let mut in_use = 0usize;
        for record in state.records.values() {
            if record.origin != PoolBlockOrigin::Accounted {
                continue;
            }
            accounted += 1;
            match record.location {
                PoolBlockLocation::Queue | PoolBlockLocation::Tls => available += 1,
                PoolBlockLocation::CheckedOut => in_use += 1,
            }
        }
        assert_eq!(self.capacity.load(Ordering::Acquire), accounted);
        assert_eq!(self.available.load(Ordering::Acquire), available);
        assert_eq!(self.in_use.load(Ordering::Acquire), in_use);
        assert_eq!(available + in_use, accounted);
    }

    fn close(&self) {
        self.closed.store(true, Ordering::Release);
        self.lock_state().records.clear();
    }
}

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
        Self {
            tls_cache_limit: AtomicUsize::new(
                environment.parse::<usize>("QUICFUSCATE_TLS_CACHE").unwrap_or(0),
            ),
            #[cfg(debug_assertions)]
            debug_slack: environment
                .parse::<usize>("QUICFUSCATE_POOL_DEBUG_SLACK")
                .unwrap_or(256),
            #[cfg(debug_assertions)]
            debug_grace: environment
                .parse::<usize>("QUICFUSCATE_POOL_DEBUG_GRACE")
                .unwrap_or(64),
            madvise_hugepage: environment.flag("QUICFUSCATE_MADVISE_HUGEPAGE", true),
            auto_tune: environment.flag("QUICFUSCATE_POOL_AUTO_TUNE", true),
            min_capacity: environment
                .parse_positive_usize("QUICFUSCATE_POOL_MIN_CAP")
                .unwrap_or(64),
            max_capacity: environment
                .parse_positive_usize("QUICFUSCATE_POOL_MAX_CAP")
                .unwrap_or(DEFAULT_AUTO_TUNE_MAX_CAPACITY),
            tick_ms: environment
                .parse_positive_u64("QUICFUSCATE_POOL_TICK_MS")
                .unwrap_or(1000),
            utilization_low,
            utilization_high,
            tls_low: environment
                .parse_positive_usize("QUICFUSCATE_TLS_LOW")
                .unwrap_or(24),
            tls_high: environment
                .parse_positive_usize("QUICFUSCATE_TLS_HIGH")
                .unwrap_or(48),
        }
    }
}

fn parse_percent(environment: &EnvSnapshot, name: &str, default: usize, min: usize, max: usize) -> usize {
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

/// Global flag controlling whether MemoryPool blocks are mlocked against swap
/// (TODO-516). Set once during server startup via [`MemoryPool::set_lock_blocks`].
/// When true, every block allocated in [`MemoryPool::alloc_numa_block`] is
/// locked with `mlock(2)` and tracked until its owning pool release path calls
/// `munlock(2)`. On non-Unix targets this is a no-op.
static LOCK_BLOCKS: AtomicBool = AtomicBool::new(false);
static NEXT_MEMORY_POOL_ID: AtomicUsize = AtomicUsize::new(1);
const DEFAULT_AUTO_TUNE_MAX_CAPACITY: usize = 1024;
const DEFAULT_POOL_MAX_BYTES: usize = 64 * 1024 * 1024;
const MIN_POOL_BLOCK_SIZE: usize = 2048;

#[cfg(test)]
static LOCK_BLOCKS_TEST_MUTEX: std::sync::Mutex<()> = std::sync::Mutex::new(());

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
            let _ = self
                .ownership
                .discard_available(block.as_ptr(), PoolBlockLocation::Tls);
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

impl MemoryPool {
    /// Enable or disable mlock on MemoryPool blocks (TODO-516).
    /// Call once during server startup before the pool is created.
    /// When enabled, blocks are locked against swap via `mlock(2)`.
    pub fn set_lock_blocks(enabled: bool) {
        LOCK_BLOCKS.store(enabled, Ordering::Relaxed);
    }

    /// Check whether block-level mlocking is enabled.
    pub fn lock_blocks_enabled() -> bool {
        LOCK_BLOCKS.load(Ordering::Relaxed)
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
        let configured = environment.parse_positive_usize("QUICFUSCATE_POOL_HARD_MAX_CAP");
        configured
            .map(|capacity| capacity.max(initial_capacity))
            .unwrap_or_else(|| default_hard_max_capacity(initial_capacity, block_size))
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
        let mut to_flush = self.with_tls_cache(|cache| core::cmp::min(cache.len().saturating_sub(limit), max));
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
    /// size. Use [`MemoryPool::new_adaptive`] when MTU-based sizing is desired.
    pub fn new(capacity: usize, block_size: usize) -> Self {
        let environment = EnvSnapshot::capture();
        Self::new_with_snapshot(capacity, block_size, &environment)
    }

    /// Creates a pool using one immutable environment generation.
    pub(crate) fn new_with_snapshot(
        capacity: usize,
        block_size: usize,
        environment: &EnvSnapshot,
    ) -> Self {
        Self::new_with_effective_block_size(capacity, block_size, environment)
    }

    /// Creates a pool whose block size follows the configured MTU profile.
    ///
    /// `QUICFUSCATE_POOL_ADAPTIVE_BLOCK=0|false` disables the MTU selection and
    /// retains the requested size, subject to the minimum safe size.
    pub fn new_adaptive(capacity: usize, block_size: usize) -> Self {
        let environment = EnvSnapshot::capture();
        Self::new_adaptive_with_snapshot(capacity, block_size, &environment)
    }

    /// Creates an adaptive pool using one immutable environment generation.
    pub(crate) fn new_adaptive_with_snapshot(
        capacity: usize,
        block_size: usize,
        environment: &EnvSnapshot,
    ) -> Self {
        Self::new_with_effective_block_size(
            capacity,
            Self::adaptive_block_size_with_snapshot(block_size, environment),
            environment,
        )
    }

    fn new_with_effective_block_size(
        capacity: usize,
        block_size: usize,
        environment: &EnvSnapshot,
    ) -> Self {
        let block_size = block_size.max(MIN_POOL_BLOCK_SIZE);
        let lock_blocks = Self::lock_blocks_enabled();
        let lock_ledger = Arc::new(BlockLockLedger::default());
        let runtime = Arc::new(MemoryPoolRuntimeConfig::from_snapshot(environment));
        let capacity_counter = Arc::new(AtomicUsize::new(0));
        let in_use_counter = Arc::new(AtomicUsize::new(0));
        let available_counter = Arc::new(AtomicUsize::new(0));
        let ownership = Arc::new(PoolOwnershipLedger::new(
            Arc::clone(&capacity_counter),
            Arc::clone(&in_use_counter),
            Arc::clone(&available_counter),
        ));
        #[cfg(target_os = "linux")]
        crate::optimize::initialize_numa_policy(environment);
        let nodes = numa::num_nodes();
        let id = NEXT_MEMORY_POOL_ID.fetch_add(1, Ordering::Relaxed);
        let mut pools = Vec::with_capacity(nodes);
        for n in 0..nodes {
            let node_cap = capacity / nodes + if n < capacity % nodes { 1 } else { 0 };
            let q = Arc::new(SegQueue::new());
            for _ in 0..node_cap {
                let block = Self::alloc_numa_block(
                    block_size,
                    n,
                    lock_blocks,
                    &lock_ledger,
                    runtime.madvise_hugepage,
                );
                if ownership.register(
                    block.as_ptr(),
                    PoolBlockOrigin::Accounted,
                    PoolBlockLocation::Queue,
                ) {
                    q.push(block);
                } else {
                    ownership.release_block(block, &lock_ledger);
                }
            }
            pools.push(q);
        }
        let pool = Self {
            id,
            lock_blocks,
            lock_ledger,
            pools,
            block_size,
            num_nodes: nodes,
            capacity: capacity_counter,
            hard_max_capacity: Self::configured_hard_max_capacity(capacity, block_size, environment),
            in_use: in_use_counter,
            available: available_counter,
            ownership,
            resize_lock: std::sync::Mutex::new(()),
            runtime,
        };
        // Telemetry init
        crate::optimize::telemetry::MEM_POOL_CAPACITY.store(capacity as u64, Ordering::Relaxed);
        crate::optimize::telemetry::MEM_POOL_BLOCK_SIZE.store(block_size as u64, Ordering::Relaxed);
        pool.update_metrics();
        pool
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
    ) -> AlignedBox<[u8]> {
        #[cfg(not(target_os = "linux"))]
        let _ = madvise_hugepage;
        // Use manual aligned allocation to guarantee exact length = block_size.
        let layout = match std::alloc::Layout::from_size_align(block_size.max(1), 64) {
            Ok(l) => l,
            Err(le) => {
                error!(
                    "Invalid allocation layout: {} bytes, 64B: {}. Falling back to minimal alignment.",
                    block_size, le
                );
                let min_align = core::mem::align_of::<u8>().max(1);
                // Safety: we clamp size to at least 1
                unsafe {
                    std::alloc::Layout::from_size_align_unchecked(block_size.max(1), min_align)
                }
            }
        };
        let ptr = unsafe { std::alloc::alloc(layout) };
        if ptr.is_null() {
            // Standard behavior on OOM
            std::alloc::handle_alloc_error(layout);
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
        if madvise_hugepage {
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
                crate::optimize::telemetry::MEM_POOL_NUMA_POLICY.store(
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
        block
    }

    /// Returns the effective block size used by every allocation from the pool.
    #[inline]
    pub fn block_size(&self) -> usize {
        self.block_size
    }

    fn grow_locked(&self, new_capacity: usize) {
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
                );
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
                        return;
                    }
                } else {
                    log::error!(
                        target: "memory_pool",
                        "stopping pool growth because the ownership ledger rejected a new block"
                    );
                    self.ownership.release_block(block, &self.lock_ledger);
                    return;
                }
            }
        }
    }

    fn grow(&self, new_capacity: usize) {
        let _resize_guard = self
            .resize_lock
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        self.grow_locked(new_capacity);
        self.update_metrics();
        self.check_invariants();
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
                let _ = self
                    .ownership
                    .discard_available(block.as_ptr(), PoolBlockLocation::Queue);
                self.ownership.release_block(block, &self.lock_ledger);
                continue;
            }
            if self
                .ownership
                .checkout(block.as_ptr(), PoolBlockLocation::Queue)
            {
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
        crate::optimize::telemetry::MEM_POOL_IN_USE.store(in_use as u64, Ordering::Relaxed);
        let usage_bytes = in_use.saturating_mul(self.block_size) as u64;
        crate::optimize::telemetry::MEM_POOL_USAGE_BYTES.store(usage_bytes, Ordering::Relaxed);
        let total = in_use.saturating_add(avail);
        let _frag = cap.saturating_sub(total);
        // Fragmentation not tracked precisely; leave default 0
        let util =
            if cap == 0 { 0 } else { (in_use.saturating_mul(100).saturating_div(cap)) as u64 };
        crate::optimize::telemetry::MEM_POOL_CAPACITY.store(cap as u64, Ordering::Relaxed);
        crate::optimize::telemetry::MEM_POOL_UTILIZATION.store(util, Ordering::Relaxed);
    }

    /// Re-publishes pool utilization counters to the telemetry subsystem.
    pub fn refresh_metrics(&self) {
        self.update_metrics();
    }

    /// Allocates a 64-byte aligned memory block from the pool.
    /// If the pool is empty, a new block is created.
    #[inline(always)]
    pub fn alloc(&self) -> AlignedBox<[u8]> {
        let node = numa::current_node() % self.num_nodes;
        self.flush_tls_to_queue(node, usize::MAX);
        // Fast-path: check TLS cache first
        if let Some(b) = self.with_tls_cache(Vec::pop) {
            if b.len() == self.block_size
                && self.ownership.checkout(b.as_ptr(), PoolBlockLocation::Tls)
            {
                crate::optimize::telemetry::MEM_POOL_HITS_TLS.inc();
                // Warm cache for caller
                prefetch(b.as_ptr(), PrefetchHint::T0);
                return b;
            } else {
                let _ = self
                    .ownership
                    .discard_available(b.as_ptr(), PoolBlockLocation::Tls);
                self.ownership.release_block(b, &self.lock_ledger);
            }
        }

        // Slow-path: try queue, create if needed
        self.alloc_cold()
    }

    /// Allocates an aligned buffer and copies data from the provided slice
    pub fn alloc_from_slice(&self, data: &[u8]) -> AlignedBox<[u8]> {
        let mut buf = self.alloc();
        let copy_len = data.len().min(buf.len());
        debug_assert!(copy_len <= buf.len());
        buf[..copy_len].copy_from_slice(&data[..copy_len]);
        // Resize the box to match the actual data length if possible
        // For now, just return the full buffer - callers should track actual length
        buf
    }

    #[cold]
    #[inline(never)]
    fn alloc_cold(&self) -> AlignedBox<[u8]> {
        let node = numa::current_node() % self.num_nodes;
        // Opportunistically flush some TLS cache back to the global queue
        // to reduce long-term TLS growth under bursty patterns
        self.flush_tls_to_queue(node, 8);
        if let Some(queue) = self.pools.get(node) {
            if let Some(b) = self.pop_queue_block(queue) {
                crate::optimize::telemetry::MEM_POOL_HITS_QUEUE.inc();
                self.update_metrics();
                self.check_invariants();
                // telemetry!(telemetry::update_memory_usage());
                // Prefetch freshly popped memory to warm cache for the caller
                prefetch(b.as_ptr(), PrefetchHint::T0);
                return b;
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
                        return b;
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
            self.grow(target);
            // Try again after growth
            if let Some(queue) = self.pools.get(node) {
                if let Some(b) = self.pop_queue_block(queue) {
                    crate::optimize::telemetry::MEM_POOL_ALLOC_GROW.inc();
                    self.update_metrics();
                    self.check_invariants();
                    prefetch(b.as_ptr(), PrefetchHint::T0);
                    return b;
                }
            }
        }
        // If we are strictly at the hard cap, we cannot grow. As a last resort, allocate
        // an ephemeral block which is tracked separately and never enters accounted state.
        crate::optimize::telemetry::MEM_POOL_ALLOC_EPHEMERAL.inc();
        let block = Self::alloc_numa_block(
            self.block_size,
            node,
            self.lock_blocks,
            &self.lock_ledger,
            self.runtime.madvise_hugepage,
        );
        if !self.ownership.register(
            block.as_ptr(),
            PoolBlockOrigin::Ephemeral,
            PoolBlockLocation::CheckedOut,
        ) {
            log::error!(
                target: "memory_pool",
                "returning an untracked emergency block because the ownership ledger rejected ephemeral registration"
            );
            // The block remains owned by the caller. `MemoryPool::free` rejects it without
            // changing accounted counters and drops it after zeroization.
            return block;
        }
        prefetch(block.as_ptr(), PrefetchHint::T0);
        block
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

        // Zeroize efficiently; allows vectorized memset
        block.as_mut().fill(0);

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
            if self
                .ownership
                .return_accounted(block.as_ptr(), PoolBlockLocation::Queue)
            {
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
    pub fn set_capacity(&self, new_capacity: usize) {
        let limit = self.hard_max_capacity;
        let clamped = core::cmp::min(new_capacity, limit);
        let node = numa::current_node() % self.num_nodes;
        self.bump_tls_limit(self.tls_limit().min(clamped));
        self.flush_tls_to_queue(node, usize::MAX);

        let _resize_guard = self
            .resize_lock
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let current = self.capacity.load(Ordering::Acquire);
        if clamped > current {
            self.grow_locked(clamped);
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
                    if self
                        .ownership
                        .discard_available(block.as_ptr(), PoolBlockLocation::Queue)
                    {
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
    }

    /// Background auto-tuner: periodically adjusts capacity based on usage.
    /// Controlled by env QUICFUSCATE_POOL_AUTO_TUNE (default true),
    /// QUICFUSCATE_POOL_MIN_CAP, QUICFUSCATE_POOL_MAX_CAP, QUICFUSCATE_POOL_TICK_MS.
    /// Determine an adaptive block size based on environment hints and MTU.
    fn adaptive_block_size_with_snapshot(
        requested: usize,
        environment: &EnvSnapshot,
    ) -> usize {
        if !environment.flag("QUICFUSCATE_POOL_ADAPTIVE_BLOCK", true) {
            return requested;
        }
        // Auto-tune based on common MTU patterns
        let mtu_hint = environment
            .parse_positive_usize("QUICFUSCATE_MTU_HINT")
            .unwrap_or(1500);
        Self::adaptive_block_size_for_mtu(mtu_hint)
    }

    fn adaptive_block_size_for_mtu(mtu_hint: usize) -> usize {
        if mtu_hint <= 1500 {
            // Standard Ethernet: use 4KB blocks
            4096
        } else if mtu_hint <= 9000 {
            // Jumbo frames: use 16KB blocks
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
                        pool.set_capacity(target);
                    }

                    std::thread::park_timeout(std::time::Duration::from_millis(tick_ms));
                }
            })
        {
            Ok(thread) => thread,
            Err(error) => {
                warn!(target: "memory_pool", "failed to start auto-tuner thread: {}", error);
                return;
            }
        };

        *slot = Some(AutoTunerHandle { stop, thread });
    }

    /// Stops and joins the process-wide auto-tuner thread when one is running.
    pub fn shutdown_auto_tuner() {
        let handle = {
            let mut slot = auto_tuner_slot()
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
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

/// A buffer designed for zero-copy vectored I/O operations using `sendmsg`.
/// This allows sending data from multiple non-contiguous memory regions
/// in a single system call, avoiding intermediate copies.
#[cfg(unix)]
pub struct ZeroCopyBuffer<'a> {
    iovecs: SmallVec<[iovec; 4]>,
    _marker: std::marker::PhantomData<&'a [u8]>,
}

#[cfg(unix)]
impl<'a> ZeroCopyBuffer<'a> {
    /// Creates a new `ZeroCopyBuffer` from a slice of byte slices.
    pub fn new(buffers: &[&'a [u8]]) -> Self {
        let mut iovecs: SmallVec<[iovec; 4]> = SmallVec::with_capacity(buffers.len());
        for buf in buffers {
            iovecs.push(iovec { iov_base: buf.as_ptr() as *mut libc::c_void, iov_len: buf.len() });
        }
        Self { iovecs, _marker: std::marker::PhantomData }
    }

    /// Creates a new `ZeroCopyBuffer` from mutable slices for receiving.
    pub fn new_mut(buffers: &mut [&'a mut [u8]]) -> Self {
        let mut iovecs: SmallVec<[iovec; 4]> = SmallVec::with_capacity(buffers.len());
        for buf in buffers.iter_mut() {
            iovecs.push(iovec {
                iov_base: buf.as_mut_ptr() as *mut libc::c_void,
                iov_len: buf.len(),
            });
        }
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
            .and_then(|(ret, addr)| {
                addr.as_socket().map(|sock| (ret, sock)).ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidData, "Invalid socket address")
                })
            })
        }
    }

    /// Returns the total length represented by all iovecs.
    pub fn len(&self) -> usize {
        self.iovecs.iter().map(|iov| iov.iov_len).sum()
    }

    /// Returns true if no iovec entries are registered.
    pub fn is_empty(&self) -> bool {
        self.iovecs.is_empty()
    }

    /// Returns the raw iovec slice for direct syscall use.
    pub fn as_iovecs(&self) -> &[iovec] {
        &self.iovecs
    }
}

#[cfg(unix)]
impl Drop for ZeroCopyBuffer<'_> {
    fn drop(&mut self) {
        self.iovecs.clear();
    }
}

/// Linux-only batched UDP I/O via sendmmsg/recvmmsg syscalls.
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

/// A buffer for scatter/gather I/O using Windows Winsock.
#[cfg(windows)]
pub struct ZeroCopyBuffer<'a> {
    bufs: Vec<WSABUF>,
    _marker: std::marker::PhantomData<&'a [u8]>,
}

#[cfg(windows)]
impl<'a> ZeroCopyBuffer<'a> {
    /// Creates a new `ZeroCopyBuffer` from immutable byte slices.
    pub fn new(buffers: &[&'a [u8]]) -> Self {
        let bufs = buffers
            .iter()
            .map(|b| WSABUF { len: b.len() as u32, buf: b.as_ptr() as *mut u8 })
            .collect();
        Self { bufs, _marker: std::marker::PhantomData }
    }

    /// Creates a new `ZeroCopyBuffer` from mutable byte slices for receiving.
    pub fn new_mut(buffers: &mut [&'a mut [u8]]) -> Self {
        let bufs = buffers
            .iter_mut()
            .map(|b| WSABUF { len: b.len() as u32, buf: b.as_mut_ptr() })
            .collect();
        Self { bufs, _marker: std::marker::PhantomData }
    }

    /// Sends all registered buffers through a connected socket.
    pub fn send(&self, sock: windows_sys::Win32::Networking::WinSock::SOCKET) -> i32 {
        let mut sent: u32 = 0;
        let result = unsafe {
            WSASend(
                sock,
                self.bufs.as_ptr(),
                self.bufs.len() as u32,
                &mut sent,
                0,
                core::ptr::null_mut(),
                None,
            )
        };
        if result == 0 {
            sent as i32
        } else {
            result
        }
    }

    /// Sends all registered buffers to the specified address.
    pub fn send_to(
        &self,
        sock: windows_sys::Win32::Networking::WinSock::SOCKET,
        addr: SocketAddr,
    ) -> i32 {
        use socket2::SockAddr;
        let sockaddr = SockAddr::from(addr);
        let mut sent: u32 = 0;
        let result = unsafe {
            WSASendTo(
                sock,
                self.bufs.as_ptr(),
                self.bufs.len() as u32,
                &mut sent,
                0,
                sockaddr.as_ptr().cast(),
                sockaddr.len(),
                core::ptr::null_mut(),
                None,
            )
        };
        if result == 0 {
            sent as i32
        } else {
            result
        }
    }

    /// Receives data from a connected socket into the registered buffers.
    pub fn recv(&mut self, sock: windows_sys::Win32::Networking::WinSock::SOCKET) -> i32 {
        let mut recvd: u32 = 0;
        let mut flags = 0u32;
        let result = unsafe {
            WSARecv(
                sock,
                self.bufs.as_ptr(),
                self.bufs.len() as u32,
                &mut recvd,
                &mut flags,
                core::ptr::null_mut(),
                None,
            )
        };
        if result == 0 {
            recvd as i32
        } else {
            result
        }
    }

    /// Receives data and returns the sender address.
    pub fn recv_from(
        &mut self,
        sock: windows_sys::Win32::Networking::WinSock::SOCKET,
    ) -> io::Result<(i32, SocketAddr)> {
        use socket2::SockAddr;
        let mut recvd: u32 = 0;
        let mut flags = 0u32;
        let (received, sockaddr) = unsafe {
            SockAddr::try_init(|storage, storage_len| {
                let result = WSARecvFrom(
                    sock,
                    self.bufs.as_ptr(),
                    self.bufs.len() as u32,
                    &mut recvd,
                    &mut flags,
                    storage.cast(),
                    storage_len,
                    core::ptr::null_mut(),
                    None,
                );
                if result == 0 {
                    Ok(recvd as i32)
                } else {
                    Err(io::Error::from_raw_os_error(WSAGetLastError()))
                }
            })
        }?;
        let addr = sockaddr.as_socket().ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "Winsock returned a non-IP address")
        })?;
        Ok((received, addr))
    }

    /// Returns the total byte length across all WSABUF entries.
    pub fn len(&self) -> usize {
        self.bufs.iter().map(|b| b.len as usize).sum()
    }

    /// Returns true if no WSABUF entries are registered.
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

#[cfg(test)]
mod memory_pool_growth_tests {
    use std::sync::atomic::Ordering;

    use super::{
        default_hard_max_capacity, MemoryPool, MemoryPoolRuntimeConfig, PoolBlockLocation,
        PoolBlockOrigin, PoolOwnershipLedger, LOCK_BLOCKS_TEST_MUTEX, DEFAULT_POOL_MAX_BYTES,
    };

    #[test]
    fn default_growth_limit_is_byte_bounded_and_never_below_initial_capacity() {
        assert_eq!(default_hard_max_capacity(512, 65_536), 1_024);
        assert_eq!(default_hard_max_capacity(32_768, 2_048), 32_768);
        assert_eq!(
            default_hard_max_capacity(65_536, 2_048),
            65_536,
            "an explicitly larger initial pool remains valid"
        );
        assert_eq!(DEFAULT_POOL_MAX_BYTES, 64 * 1024 * 1024);
    }

    #[test]
    fn explicit_constructor_preserves_requested_block_size() {
        let pool = MemoryPool::new(1, 128 * 1024);
        assert_eq!(pool.block_size(), 128 * 1024);
        assert_eq!(pool.alloc().len(), 128 * 1024);
    }

    #[test]
    fn explicit_constructor_applies_only_the_minimum_block_size() {
        let pool = MemoryPool::new(1, 1);
        assert_eq!(pool.block_size(), 2048);
        assert_eq!(pool.alloc().len(), 2048);
    }

    #[test]
    fn adaptive_block_profiles_remain_explicitly_selectable() {
        assert_eq!(MemoryPool::adaptive_block_size_for_mtu(1500), 4096);
        assert_eq!(MemoryPool::adaptive_block_size_for_mtu(9000), 16_384);
        assert_eq!(MemoryPool::adaptive_block_size_for_mtu(9001), 65_536);
    }

    #[test]
    fn runtime_policy_is_validated_once_from_one_snapshot() {
        let environment = crate::env_utils::EnvSnapshot::from_pairs([
            ("QUICFUSCATE_POOL_AUTO_TUNE", "off"),
            ("QUICFUSCATE_POOL_MIN_CAP", "0"),
            ("QUICFUSCATE_POOL_MAX_CAP", "invalid"),
            ("QUICFUSCATE_POOL_TICK_MS", " 250 "),
            ("QUICFUSCATE_POOL_UTIL_LOW", "0"),
            ("QUICFUSCATE_POOL_UTIL_HIGH", "110"),
            ("QUICFUSCATE_TLS_CACHE", "8"),
            ("QUICFUSCATE_TLS_LOW", "0"),
            ("QUICFUSCATE_TLS_HIGH", "64"),
        ]);
        let runtime = MemoryPoolRuntimeConfig::from_snapshot(&environment);

        assert!(!runtime.auto_tune);
        assert_eq!(runtime.min_capacity, 64);
        assert_eq!(runtime.max_capacity, super::DEFAULT_AUTO_TUNE_MAX_CAPACITY);
        assert_eq!(runtime.tick_ms, 250);
        assert_eq!(runtime.utilization_low, 1);
        assert_eq!(runtime.utilization_high, 95);
        assert_eq!(runtime.tls_cache_limit.load(std::sync::atomic::Ordering::Relaxed), 8);
        assert_eq!(runtime.tls_low, 24);
        assert_eq!(runtime.tls_high, 64);
    }

    #[test]
    fn thread_local_blocks_remain_owned_by_their_origin_pool() {
        let first_pool = super::MemoryPool::new(1, 2_048);
        let second_pool = super::MemoryPool::new(1, 2_048);
        let first_block = first_pool.alloc();
        let first_pointer = first_block.as_ptr();
        assert!(first_pool.try_cache_block(first_block, 1).is_ok());
        first_pool.ownership.assert_consistent();

        let second_block = second_pool.alloc();
        assert_ne!(second_block.as_ptr(), first_pointer);

        let first_block_again = first_pool.alloc();
        assert_eq!(first_block_again.as_ptr(), first_pointer);
        first_pool.free(first_block_again);
        first_pool.ownership.assert_consistent();
    }

    #[test]
    fn ephemeral_blocks_never_change_accounted_counters() {
        let environment = crate::env_utils::EnvSnapshot::from_pairs([(
            "QUICFUSCATE_POOL_HARD_MAX_CAP",
            "1",
        )]);
        let pool = MemoryPool::new_with_snapshot(1, 2_048, &environment);
        pool.runtime.tls_cache_limit.store(0, Ordering::Relaxed);

        let accounted = pool.alloc();
        let ephemeral = pool.alloc();
        assert_eq!(pool.capacity.load(Ordering::Acquire), 1);
        assert_eq!(pool.in_use.load(Ordering::Acquire), 1);
        assert_eq!(pool.available.load(Ordering::Acquire), 0);

        pool.free(ephemeral);
        assert_eq!(pool.capacity.load(Ordering::Acquire), 1);
        assert_eq!(pool.in_use.load(Ordering::Acquire), 1);
        assert_eq!(pool.available.load(Ordering::Acquire), 0);

        let pointer = accounted.as_ptr();
        pool.free(accounted);
        assert_eq!(pool.ownership.begin_free(pointer), None);
        assert_eq!(pool.capacity.load(Ordering::Acquire), 1);
        assert_eq!(pool.in_use.load(Ordering::Acquire), 0);
        assert_eq!(pool.available.load(Ordering::Acquire), 1);
        pool.ownership.assert_consistent();
    }

    #[test]
    fn duplicate_address_registration_replaces_stale_state_without_counter_drift() {
        use std::sync::Arc;

        let capacity = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let in_use = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let available = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let ledger = PoolOwnershipLedger::new(
            Arc::clone(&capacity),
            Arc::clone(&in_use),
            Arc::clone(&available),
        );
        let pointer = 0x1000usize as *const u8;

        assert!(ledger.register(pointer, PoolBlockOrigin::Accounted, PoolBlockLocation::CheckedOut));
        assert!(ledger.register(pointer, PoolBlockOrigin::Accounted, PoolBlockLocation::Queue));
        assert_eq!(capacity.load(Ordering::Acquire), 1);
        assert_eq!(in_use.load(Ordering::Acquire), 0);
        assert_eq!(available.load(Ordering::Acquire), 1);
        ledger.assert_consistent();
    }

    #[test]
    fn foreign_and_mismatched_blocks_do_not_enter_pool_state() {
        use std::alloc::{alloc, Layout};

        let pool = MemoryPool::new(1, 2_048);
        pool.runtime.tls_cache_limit.store(0, Ordering::Relaxed);
        let foreign_pool = MemoryPool::new(1, 2_048);
        foreign_pool.runtime.tls_cache_limit.store(0, Ordering::Relaxed);

        let foreign = foreign_pool.alloc();
        pool.free(foreign);
        assert_eq!(pool.capacity.load(Ordering::Acquire), 1);
        assert_eq!(pool.available.load(Ordering::Acquire), 1);
        assert_eq!(pool.in_use.load(Ordering::Acquire), 0);
        assert_eq!(foreign_pool.in_use.load(Ordering::Acquire), 1);

        let layout = Layout::from_size_align(1, 64).expect("one-byte layout");
        let raw = unsafe { alloc(layout) };
        assert!(!raw.is_null());
        let slice = unsafe { std::slice::from_raw_parts_mut(raw, 1) };
        let mismatched = unsafe { aligned_box::AlignedBox::<[u8]>::from_raw_parts(slice, layout) };
        pool.free(mismatched);
        assert_eq!(pool.capacity.load(Ordering::Acquire), 1);
        assert_eq!(pool.available.load(Ordering::Acquire), 1);
        assert_eq!(pool.in_use.load(Ordering::Acquire), 0);
        pool.ownership.assert_consistent();
    }

    #[test]
    fn shrink_flushes_tls_and_releases_accounted_capacity() {
        let pool = MemoryPool::new(2, 2_048);
        pool.runtime.tls_cache_limit.store(2, Ordering::Relaxed);
        let first = pool.alloc();
        let second = pool.alloc();
        pool.free(first);
        pool.free(second);
        assert_eq!(pool.available.load(Ordering::Acquire), 2);

        pool.set_capacity(0);
        assert_eq!(pool.capacity.load(Ordering::Acquire), 0);
        assert_eq!(pool.available.load(Ordering::Acquire), 0);
        assert_eq!(pool.in_use.load(Ordering::Acquire), 0);
        pool.ownership.assert_consistent();
    }

    #[test]
    fn concurrent_queue_transitions_preserve_exact_accounting() {
        use std::sync::Arc;

        let pool = Arc::new(MemoryPool::new(4, 2_048));
        pool.runtime.tls_cache_limit.store(0, Ordering::Relaxed);
        let mut workers = Vec::new();
        for _ in 0..8 {
            let pool = Arc::clone(&pool);
            workers.push(std::thread::spawn(move || {
                for _ in 0..100 {
                    let block = pool.alloc();
                    pool.free(block);
                }
            }));
        }
        for worker in workers {
            worker.join().expect("memory pool worker must finish");
        }
        let capacity = pool.capacity.load(Ordering::Acquire);
        assert!(capacity >= 4);
        assert_eq!(pool.available.load(Ordering::Acquire), capacity);
        assert_eq!(pool.in_use.load(Ordering::Acquire), 0);
        pool.ownership.assert_consistent();
    }

    #[test]
    fn tls_ledger_survives_pool_drop_until_thread_cleanup() {
        use std::sync::{mpsc, Arc};

        let pool = Arc::new(MemoryPool::new(1, 2_048));
        pool.runtime.tls_cache_limit.store(1, Ordering::Relaxed);
        let ledger = Arc::clone(&pool.ownership);
        let lock_ledger = Arc::clone(&pool.lock_ledger);
        let (ready_tx, ready_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let worker_pool = Arc::clone(&pool);
        let worker = std::thread::spawn(move || {
            let block = worker_pool.alloc();
            worker_pool.free(block);
            drop(worker_pool);
            ready_tx.send(()).expect("worker must signal TLS ownership");
            release_rx.recv().expect("worker must receive cleanup signal");
        });

        ready_rx.recv().expect("worker must cache a block");
        drop(pool);
        release_tx.send(()).expect("worker cleanup signal must send");
        worker.join().expect("worker must clean up its TLS cache");
        assert!(ledger.closed.load(Ordering::Acquire));
        assert_eq!(lock_ledger.len(), 0);
    }

    #[test]
    fn capacity_shrink_releases_locked_queue_blocks() {
        let _guard = LOCK_BLOCKS_TEST_MUTEX
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let original = MemoryPool::lock_blocks_enabled();
        MemoryPool::set_lock_blocks(true);
        {
            let pool = MemoryPool::new(1, 2_048);
            pool.runtime.tls_cache_limit.store(1, Ordering::Relaxed);
            let block = pool.alloc();
            pool.free(block);
            pool.set_capacity(0);
            assert_eq!(pool.capacity.load(Ordering::Acquire), 0);
            assert_eq!(pool.lock_ledger.len(), 0);
            pool.ownership.assert_consistent();
        }
        MemoryPool::set_lock_blocks(original);
    }
}
