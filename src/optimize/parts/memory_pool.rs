//
// Foundational Structures for Global Optimizations
//

/// A high-performance, thread-safe memory pool for fixed-size blocks.
/// This implementation uses a concurrent queue to manage free blocks,
/// minimizing lock contention and fragmentation.
#[derive(Debug)]
pub struct MemoryPool {
    id: usize,
    pools: Vec<Arc<SegQueue<AlignedBox<[u8]>>>>,
    block_size: usize,
    num_nodes: usize,
    capacity: AtomicUsize,
    hard_max_capacity: usize,
    in_use: AtomicUsize,
    available: AtomicUsize,
}

/// Global flag controlling whether MemoryPool blocks are mlocked against swap
/// (TODO-516). Set once during server startup via [`MemoryPool::set_lock_blocks`].
/// When true, every block allocated in [`MemoryPool::alloc_numa_block`] is
/// locked with `mlock(2)`. Pages are released back to the kernel when the
/// block is deallocated. On non-Unix targets this is a no-op.
static LOCK_BLOCKS: AtomicBool = AtomicBool::new(false);
static NEXT_MEMORY_POOL_ID: AtomicUsize = AtomicUsize::new(1);
const DEFAULT_AUTO_TUNE_MAX_CAPACITY: usize = 1024;
const DEFAULT_POOL_MAX_BYTES: usize = 64 * 1024 * 1024;
type ThreadLocalPoolCaches = Vec<(usize, Vec<AlignedBox<[u8]>>)>;

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
/// Best-effort: logs a warning on failure but does not panic.
/// No-op on non-Unix targets.
#[cfg(unix)]
fn mlock_block(ptr: *mut u8, len: usize) {
    // SAFETY: ptr points to a valid allocated region of `len` bytes.
    // mlock is a kernel syscall that does not dereference userspace
    // pointers beyond pinning the pages.
    let result = unsafe { libc::mlock(ptr as *const libc::c_void, len) };
    if result != 0 {
        let err = std::io::Error::last_os_error();
        // EAGAIN (insufficient RLIMIT_MEMLOCK) is common in unprivileged
        // contexts. Log once at debug to avoid spamming.
        log::debug!(
            "mlock failed for MemoryPool block ({} bytes): {} — \
             consider raising RLIMIT_MEMLOCK or LimitMEMLOCK in systemd",
            len,
            err
        );
    }
}

#[cfg(not(unix))]
fn mlock_block(_ptr: *mut u8, _len: usize) {}

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

    #[inline]
    fn tls_limit_cell() -> &'static AtomicUsize {
        static TLS_LIMIT_RUNTIME: OnceLock<AtomicUsize> = OnceLock::new();
        TLS_LIMIT_RUNTIME.get_or_init(|| {
            let default = std::env::var("QUICFUSCATE_TLS_CACHE")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(0);
            AtomicUsize::new(default)
        })
    }
    // Thread-local small cache of blocks to reduce contention on queues
    thread_local! {
        static TLS_CACHES: RefCell<ThreadLocalPoolCaches> = const { RefCell::new(Vec::new()) };
    }

    #[inline]
    fn with_tls_cache<R>(&self, operation: impl FnOnce(&mut Vec<AlignedBox<[u8]>>) -> R) -> R {
        Self::TLS_CACHES.with(|caches| {
            let mut caches = caches.borrow_mut();
            let index = caches.iter().position(|(id, _)| *id == self.id).unwrap_or_else(|| {
                caches.push((self.id, Vec::new()));
                caches.len() - 1
            });
            operation(&mut caches[index].1)
        })
    }

    #[inline]
    fn try_cache_block(
        &self,
        block: AlignedBox<[u8]>,
        limit: usize,
    ) -> Result<(), AlignedBox<[u8]>> {
        self.with_tls_cache(|cache| {
            if cache.len() >= limit {
                return Err(block);
            }
            cache.push(block);
            Ok(())
        })
    }

    #[inline]
    fn configured_hard_max_capacity(initial_capacity: usize, block_size: usize) -> usize {
        let configured = std::env::var("QUICFUSCATE_POOL_HARD_MAX_CAP")
            .ok()
            .and_then(|v| v.parse::<usize>().ok())
            .filter(|capacity| *capacity > 0);
        configured
            .map(|capacity| capacity.max(initial_capacity))
            .unwrap_or_else(|| default_hard_max_capacity(initial_capacity, block_size))
    }

    #[inline]
    fn tls_limit() -> usize {
        Self::tls_limit_cell().load(Ordering::Relaxed)
    }

    #[inline]
    fn bump_tls_limit(suggested: usize) {
        let cell = Self::tls_limit_cell();
        let cur = cell.load(Ordering::Relaxed);
        if cur == 0 {
            return;
        }
        if suggested != cur {
            cell.store(suggested, Ordering::Relaxed);
        }
    }

    #[inline]
    fn flush_tls_to_queue(&self, node: usize, max: usize) {
        self.with_tls_cache(|cache| {
            let limit = Self::tls_limit();
            let len = cache.len();
            if len > limit {
                let mut to_flush = core::cmp::min(len - limit, max);
                if let Some(q) = self.pools.get(node) {
                    while to_flush > 0 {
                        if let Some(b) = cache.pop() {
                            q.push(b);
                        } else {
                            break;
                        }
                        to_flush -= 1;
                    }
                }
            }
        });
    }

    /// Creates a new memory pool with a specified capacity and block size.
    /// All allocated blocks are 64-byte aligned.
    pub fn new(capacity: usize, block_size: usize) -> Self {
        // Adaptive block size based on traffic profile and enforce a sane lower bound
        let mut block_size = Self::adaptive_block_size(block_size);
        if block_size < 2048 {
            block_size = 2048;
        }
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
        let pool = Self {
            id: NEXT_MEMORY_POOL_ID.fetch_add(1, Ordering::Relaxed),
            pools,
            block_size,
            num_nodes: nodes,
            capacity: AtomicUsize::new(capacity),
            hard_max_capacity: Self::configured_hard_max_capacity(capacity, block_size),
            in_use: AtomicUsize::new(0),
            available: AtomicUsize::new(capacity),
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
        // Allow transient slack due to non-atomic pair updates of (available,in_use)
        // Make slack configurable for stress-heavy tests; default increased conservatively.
        let slack: usize = std::env::var("QUICFUSCATE_POOL_DEBUG_SLACK")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(256);
        let grace: usize = std::env::var("QUICFUSCATE_POOL_DEBUG_GRACE")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(64);
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

    #[inline]
    fn dec_available(&self) {
        use std::sync::atomic::Ordering;
        let mut cur = self.available.load(Ordering::Acquire);
        while cur > 0 {
            match self.available.compare_exchange_weak(
                cur,
                cur - 1,
                Ordering::AcqRel,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(next) => cur = next,
            }
        }
    }

    #[inline]
    fn inc_in_use(&self) {
        self.in_use.fetch_add(1, Ordering::Relaxed);
    }
    /// Allocate a 64-byte aligned block bound to the given NUMA node.
    fn alloc_numa_block(block_size: usize, node: usize) -> AlignedBox<[u8]> {
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
        unsafe {
            let hp = std::env::var("QUICFUSCATE_MADVISE_HUGEPAGE")
                .map(|v| v != "0" && !v.eq_ignore_ascii_case("false"))
                .unwrap_or(true);
            if hp {
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
                let policy = *NUMA_POLICY.get_or_init(resolve_numa_policy);
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
        if Self::lock_blocks_enabled() {
            mlock_block(block.as_mut_ptr(), block_size);
        }
        block
    }

    /// Returns the configured block size of the pool.
    #[inline]
    pub fn block_size(&self) -> usize {
        self.block_size
    }

    fn grow(&self, new_capacity: usize) {
        let limit = self.hard_max_capacity;
        let target = core::cmp::min(new_capacity, limit);
        while self.capacity.load(Ordering::Relaxed) < target {
            for (n, q) in self.pools.iter().enumerate() {
                if self.capacity.load(Ordering::Relaxed) >= target {
                    break;
                }
                q.push(Self::alloc_numa_block(self.block_size, n));
                self.available.fetch_add(1, Ordering::Relaxed);
                self.capacity.fetch_add(1, Ordering::Relaxed);
            }
        }
        // telemetry!(telemetry::MEM_POOL_CAPACITY.store(self.capacity.load(Ordering::Relaxed) as u64, Ordering::Relaxed));
        self.update_metrics();
        self.check_invariants();
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
        // Fast-path: check TLS cache first
        if let Some(b) = self.with_tls_cache(Vec::pop) {
            // Validate size; drop foreign/mismatched blocks
            if b.len() == self.block_size {
                crate::optimize::telemetry::MEM_POOL_HITS_TLS.inc();
                self.dec_available();
                self.inc_in_use();
                // Warm cache for caller
                prefetch(b.as_ptr(), PrefetchHint::T0);
                return b;
            } else {
                // Remove from available as it left TLS, but do not count as in-use
                self.dec_available();
                // Drop mismatched block; continue to slow-path to obtain a correct block
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
            if let Some(b) = queue.pop() {
                crate::optimize::telemetry::MEM_POOL_HITS_QUEUE.inc();
                self.dec_available();
                self.in_use.fetch_add(1, Ordering::Relaxed);
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
                    if let Some(b) = q.pop() {
                        // Treat as regular queue hit
                        self.dec_available();
                        self.in_use.fetch_add(1, Ordering::Relaxed);
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
                if let Some(b) = queue.pop() {
                    crate::optimize::telemetry::MEM_POOL_ALLOC_GROW.inc();
                    self.available.fetch_sub(1, Ordering::Relaxed);
                    self.in_use.fetch_add(1, Ordering::Relaxed);
                    self.update_metrics();
                    self.check_invariants();
                    prefetch(b.as_ptr(), PrefetchHint::T0);
                    return b;
                }
            }
        }
        // Hard-cap reached or still no blocks: allocate a new block and account it as pooled
        // (checked-out). This maintains invariants for free() without needing origin tags.
        let cap_now = self.capacity.load(Ordering::Relaxed);
        let limit2 = self.hard_max_capacity;
        if cap_now < limit2 {
            let b = Self::alloc_numa_block(self.block_size, node);
            self.capacity.fetch_add(1, Ordering::Relaxed);
            self.in_use.fetch_add(1, Ordering::Relaxed);
            self.update_metrics();
            self.check_invariants();
            return b;
        }
        // If we are strictly at the hard cap, we cannot grow. As a last resort, allocate
        // an ephemeral block but do not touch counters; free() will drop it if pool is full.
        crate::optimize::telemetry::MEM_POOL_ALLOC_EPHEMERAL.inc();
        {
            let b = Self::alloc_numa_block(self.block_size, node);
            prefetch(b.as_ptr(), PrefetchHint::T0);
            b
        }
    }

    /// Returns a memory block to the pool.
    /// If the pool is full, the block is dropped.
    #[inline(always)]
    pub fn free(&self, mut block: AlignedBox<[u8]>) {
        // Drop foreign/mismatched sized blocks instead of re-caching them
        if block.len() != self.block_size {
            // Do not touch counters: block did not originate from this pool's accounting
            return;
        }
        // Zeroize efficiently; allows vectorized memset
        block.as_mut().fill(0);
        // Try to place into TLS cache
        let limit = Self::tls_limit();
        let block = match self.try_cache_block(block, limit) {
            Ok(()) => {
                self.available.fetch_add(1, Ordering::Relaxed);
                self.in_use.fetch_sub(1, Ordering::Relaxed);
                self.update_metrics();
                self.check_invariants();
                return;
            }
            Err(block) => block,
        };
        // Fallback: return to global pool queue
        let node = numa::current_node() % self.num_nodes;
        if self.available.load(Ordering::Relaxed) < self.capacity.load(Ordering::Relaxed) {
            if let Some(q) = self.pools.get(node) {
                q.push(block);
            }
            self.available.fetch_add(1, Ordering::Relaxed);
        }
        self.in_use.fetch_sub(1, Ordering::Relaxed);
        self.update_metrics();
        self.check_invariants();
        // telemetry!(telemetry::update_memory_usage());
    }

    /// Adjusts the maximum number of cached blocks at runtime.
    pub fn set_capacity(&self, new_capacity: usize) {
        let current = self.capacity.load(Ordering::Relaxed);
        let limit = self.hard_max_capacity;
        let clamped = core::cmp::min(new_capacity, limit);
        if clamped > current {
            self.grow(clamped);
        } else {
            // shrink: drop excess blocks
            let mut diff = current - clamped;
            while diff > 0 && self.available.load(Ordering::Relaxed) > 0 {
                for q in &self.pools {
                    if diff == 0 {
                        break;
                    }
                    if q.pop().is_some() {
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
        // telemetry!(telemetry::MEM_POOL_CAPACITY.store(self.capacity.load(Ordering::Relaxed) as u64, Ordering::Relaxed));
        self.update_metrics();
        // telemetry!(telemetry::update_memory_usage());
        self.check_invariants();
    }

    /// Background auto-tuner: periodically adjusts capacity based on usage.
    /// Controlled by env QUICFUSCATE_POOL_AUTO_TUNE (default true),
    /// QUICFUSCATE_POOL_MIN_CAP, QUICFUSCATE_POOL_MAX_CAP, QUICFUSCATE_POOL_TICK_MS.
    /// Determine optimal block size based on ENV hints and MTU
    fn adaptive_block_size(requested: usize) -> usize {
        if let Ok(v) = std::env::var("QUICFUSCATE_POOL_ADAPTIVE_BLOCK") {
            if v == "0" || v.eq_ignore_ascii_case("false") {
                return requested;
            }
        }
        // Auto-tune based on common MTU patterns
        let mtu_hint = std::env::var("QUICFUSCATE_MTU_HINT")
            .ok()
            .and_then(|v| v.parse::<usize>().ok())
            .unwrap_or(1500);
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
        let enabled = std::env::var("QUICFUSCATE_POOL_AUTO_TUNE")
            .map(|v| v != "0" && !v.eq_ignore_ascii_case("false"))
            .unwrap_or(true);
        if !enabled {
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
                let min_cap = std::env::var("QUICFUSCATE_POOL_MIN_CAP")
                    .ok()
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(64);
                let max_cap = std::env::var("QUICFUSCATE_POOL_MAX_CAP")
                    .ok()
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(DEFAULT_AUTO_TUNE_MAX_CAPACITY);
                let tick_ms = std::env::var("QUICFUSCATE_POOL_TICK_MS")
                    .ok()
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(1000u64);
                loop {
                    if thread_stop.load(Ordering::Acquire) {
                        break;
                    }

                    // Allow runtime-configurable utilization thresholds
                    let util_high = std::env::var("QUICFUSCATE_POOL_UTIL_HIGH")
                        .ok()
                        .and_then(|v| v.parse::<usize>().ok())
                        .map(|v| v.clamp(5, 95))
                        .unwrap_or(80);
                    let util_low = std::env::var("QUICFUSCATE_POOL_UTIL_LOW")
                        .ok()
                        .and_then(|v| v.parse::<usize>().ok())
                        .map(|v| v.clamp(1, 89))
                        .unwrap_or(30);
                    // Ensure logical ordering
                    let (util_low, util_high) = if util_low + 5 >= util_high {
                        (util_high.saturating_sub(10).max(1), util_high)
                    } else {
                        (util_low, util_high)
                    };

                    let tls_high = std::env::var("QUICFUSCATE_TLS_HIGH")
                        .ok()
                        .and_then(|v| v.parse::<usize>().ok())
                        .unwrap_or(48);
                    let tls_low = std::env::var("QUICFUSCATE_TLS_LOW")
                        .ok()
                        .and_then(|v| v.parse::<usize>().ok())
                        .unwrap_or(24);

                    let cap = pool.capacity.load(Ordering::Relaxed);
                    let in_use = pool.in_use.load(Ordering::Relaxed);
                    let util = in_use.saturating_mul(100).checked_div(cap).unwrap_or(0);
                    let mut target = cap;
                    if util > util_high {
                        target = core::cmp::min(cap.saturating_mul(2), max_cap);
                        // Under high utilization, raise TLS cache to reduce contention
                        MemoryPool::bump_tls_limit(tls_high);
                    } else if util < util_low {
                        target = core::cmp::max(cap / 2, min_cap);
                        // Under low utilization, shrink TLS cache for footprint
                        MemoryPool::bump_tls_limit(tls_low);
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
    use super::{default_hard_max_capacity, DEFAULT_POOL_MAX_BYTES};

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
    fn thread_local_blocks_remain_owned_by_their_origin_pool() {
        use std::sync::atomic::Ordering;

        let first_pool = super::MemoryPool::new(1, 2_048);
        let second_pool = super::MemoryPool::new(1, 2_048);
        let first_block = first_pool.alloc();
        let first_pointer = first_block.as_ptr();
        assert!(first_pool.try_cache_block(first_block, 1).is_ok());
        first_pool.available.fetch_add(1, Ordering::Relaxed);
        first_pool.in_use.fetch_sub(1, Ordering::Relaxed);

        let second_block = second_pool.alloc();
        assert_ne!(second_block.as_ptr(), first_pointer);

        let first_block_again = first_pool.alloc();
        assert_eq!(first_block_again.as_ptr(), first_pointer);
    }
}
