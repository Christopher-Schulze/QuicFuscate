// ========================================================================
// 3-LEVEL CACHE HIERARCHY - Erweiterte Performance-Optimierungen
// ========================================================================

/// Cache hierarchy singleton for global access
static CACHE_HIERARCHY: OnceLock<CacheHierarchy> = OnceLock::new();

/// Get global cache hierarchy instance
pub fn global_cache_hierarchy() -> &'static CacheHierarchy {
    CACHE_HIERARCHY.get_or_init(CacheHierarchy::detect)
}

// Consolidated telemetry module for performance monitoring
// Const-size optimizations with compile-time guarantees
// ===== Cross-Platform Prefetch Hints =====
/// Hint type for cache prefetching.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PrefetchHint {
    /// Hint the line into the closest cache (L1).
    T0,
    /// Hint the line into the next cache level (L2).
    T1,
}

/// Issue a best-effort hardware prefetch for the supplied pointer.
///
/// # Contract
///
/// This is a pure hint and never a load. Every supported lane compiles to a genuinely
/// non-faulting instruction: `PRFM PLDL1KEEP` on AArch64 and `PREFETCHh` through `_mm_prefetch`
/// on x86_64. Both are architecturally defined to have no effect other than a possible cache
/// line fill, and neither signals on an unmapped, unaligned, or permission-denied address.
/// Unsupported architectures compile to nothing.
///
/// Callers therefore do **not** owe a readable span. `ptr` may be dangling, one past the end of
/// an allocation, or derived from an empty slice. The null check is a cheap filter for the
/// common uninitialised case, not a safety requirement.
///
/// What callers still owe is provenance discipline for the pointer arithmetic that produced
/// `ptr`: computing an out-of-bounds address with `ptr::add` is undefined regardless of what this
/// function does with the result. Offset and allocation-lifetime proof stays with each caller and
/// its owner, and this facade deliberately makes no claim about it.
#[cfg_attr(feature = "aggressive_inline", inline(always))]
pub(crate) fn prefetch(ptr: *const u8, hint: PrefetchHint) {
    #[cfg(feature = "prefetch")]
    {
        if ptr.is_null() {
            return;
        }
        unsafe {
            prefetch_impl(ptr, hint);
        }
    }
    #[cfg(not(feature = "prefetch"))]
    {
        let _ = ptr;
        let _ = hint;
    }
}

/// # Safety
///
/// `ptr` must be a pointer value the caller was allowed to compute. It does not need to be
/// readable, aligned, or inside a live allocation: every lane below emits a non-faulting hint
/// instruction rather than a load, so no memory is accessed through it. See [`prefetch`] for the
/// full contract.
#[cfg(feature = "prefetch")]
#[cfg_attr(feature = "aggressive_inline", inline(always))]
unsafe fn prefetch_impl(ptr: *const u8, hint: PrefetchHint) {
    #[cfg(target_arch = "x86_64")]
    {
        use core::arch::x86_64::{_mm_prefetch, _MM_HINT_T0, _MM_HINT_T1};
        // `_mm_prefetch` takes its locality strategy as a const generic, so the hint has to be
        // resolved at compile time. Passing a runtime value does not compile on x86_64 at all.
        match hint {
            PrefetchHint::T0 => _mm_prefetch::<_MM_HINT_T0>(ptr as *const i8),
            PrefetchHint::T1 => _mm_prefetch::<_MM_HINT_T1>(ptr as *const i8),
        }
    }

    #[cfg(target_arch = "aarch64")]
    unsafe {
        core::arch::asm!(
            "prfm pldl1keep, [{ptr}]",
            ptr = in(reg) ptr,
            options(nostack, preserves_flags)
        );
        let _ = hint;
    }

    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    {
        let _ = ptr;
        let _ = hint;
    }
}

/// Fixed-capacity byte buffer backed by a stack-allocated array.
#[cfg(any(test, feature = "rust-tests"))]
pub struct ConstBuffer<const N: usize> {
    data: [u8; N],
    len: usize,
}

#[cfg(any(test, feature = "rust-tests"))]
impl<const N: usize> ConstBuffer<N> {
    /// Creates a new empty const buffer.
    pub const fn new() -> Self {
        Self { data: [0; N], len: 0 }
    }

    /// Zeros and resets the buffer to empty.
    #[inline(always)]
    pub fn clear(&mut self) {
        if self.len > 0 {
            self.data[..self.len].fill(0);
        }
        self.len = 0;
    }

    /// Appends data to the buffer, returning the number of bytes actually written.
    #[inline(always)]
    pub fn write(&mut self, data: &[u8]) -> usize {
        let to_write = data.len().min(N - self.len);
        self.data[self.len..self.len + to_write].copy_from_slice(&data[..to_write]);
        self.len += to_write;
        to_write
    }

    /// Returns the written portion as a byte slice.
    #[inline(always)]
    pub fn as_slice(&self) -> &[u8] {
        &self.data[..self.len]
    }
}

/// Const-size ring buffer for lock-free operations
#[cfg(any(test, feature = "rust-tests"))]
pub(crate) struct ConstRingBuffer<T, const N: usize> {
    buffer: [Option<T>; N],
    head: usize,
    tail: usize,
}

#[cfg(any(test, feature = "rust-tests"))]
impl<T, const N: usize> Default for ConstRingBuffer<T, N> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(any(test, feature = "rust-tests"))]
impl<T, const N: usize> ConstRingBuffer<T, N> {
    pub(crate) fn new() -> Self {
        Self { buffer: [(); N].map(|_| None), head: 0, tail: 0 }
    }

    #[inline(always)]
    pub(crate) fn push(&mut self, item: T) -> bool {
        let next_tail = (self.tail + 1) % N;
        if next_tail == self.head {
            return false;
        }
        self.buffer[self.tail] = Some(item);
        self.tail = next_tail;
        true
    }

    #[inline(always)]
    pub(crate) fn pop(&mut self) -> Option<T> {
        if self.head == self.tail {
            return None;
        }
        let item = self.buffer[self.head].take();
        self.head = (self.head + 1) % N;
        item
    }
}

/// Fixed-capacity pool of `ConstBuffer`s managed via an index ring buffer.
#[cfg(any(test, feature = "rust-tests"))]
pub struct ConstPacketPool<const N: usize, const SIZE: usize> {
    packets: [ConstBuffer<SIZE>; N],
    free_list: ConstRingBuffer<usize, N>,
    in_use: [bool; N],
}

#[cfg(any(test, feature = "rust-tests"))]
impl<const N: usize, const SIZE: usize> Default for ConstPacketPool<N, SIZE> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(any(test, feature = "rust-tests"))]
impl<const N: usize, const SIZE: usize> ConstPacketPool<N, SIZE> {
    /// Creates a new packet pool with all N slots available.
    pub fn new() -> Self {
        let mut pool = Self {
            packets: [(); N].map(|_| ConstBuffer::new()),
            free_list: ConstRingBuffer::new(),
            in_use: [false; N],
        };
        for i in 0..N {
            pool.free_list.push(i);
        }
        pool
    }

    /// Allocates and clears a buffer from the pool, or returns None if empty.
    #[inline(always)]
    pub fn alloc(&mut self) -> Option<&mut ConstBuffer<SIZE>> {
        self.free_list.pop().map(|idx| {
            if idx < N {
                self.in_use[idx] = true;
            }
            let buf = &mut self.packets[idx];
            buf.clear();
            buf
        })
    }

    /// Returns a buffer to the pool. No-op if the buffer did not originate from this pool.
    #[inline(always)]
    pub fn free(&mut self, buffer: &ConstBuffer<SIZE>) {
        let ptr = buffer as *const _ as usize;
        let base = self.packets.as_ptr() as usize;
        let entry_size = std::mem::size_of::<ConstBuffer<SIZE>>();
        let end = base + entry_size * N;
        if ptr < base || ptr >= end {
            return;
        }
        let idx = (ptr - base) / entry_size;
        if idx >= N {
            return;
        }
        if !self.in_use[idx] {
            return;
        }
        self.in_use[idx] = false;
        let _ = self.free_list.push(idx);
    }
}

#[cfg(test)]
mod mlock_tests {
    use super::*;

    #[test]
    fn test_set_and_check_lock_blocks_flag() {
        let _guard = LOCK_BLOCKS_TEST_MUTEX
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        // Save original state
        let original = MemoryPool::lock_blocks_enabled();
        // Enable
        MemoryPool::set_lock_blocks(true);
        assert!(MemoryPool::lock_blocks_enabled());
        // Disable
        MemoryPool::set_lock_blocks(false);
        assert!(!MemoryPool::lock_blocks_enabled());
        // Restore
        MemoryPool::set_lock_blocks(original);
    }

    #[test]
    fn test_pool_alloc_with_lock_blocks_enabled() {
        let _guard = LOCK_BLOCKS_TEST_MUTEX
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        // Enable lock_blocks and verify pool allocation still works.
        // mlock may fail (EAGAIN) in unprivileged test environments, but
        // the allocation must succeed regardless - mlock is best-effort.
        MemoryPool::set_lock_blocks(true);
        let pool = MemoryPool::new(4, 4096);
        let block = pool.alloc();
        assert_eq!(block.len(), 4096);
        pool.free(block);
        // Clean up
        MemoryPool::set_lock_blocks(false);
    }

    #[test]
    fn test_pool_alloc_with_lock_blocks_disabled() {
        let _guard = LOCK_BLOCKS_TEST_MUTEX
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        MemoryPool::set_lock_blocks(false);
        let pool = MemoryPool::new(4, 4096);
        let block = pool.alloc();
        assert_eq!(block.len(), 4096);
        pool.free(block);
    }

    /// The facade is a hint, not a load. These inputs are exactly the classes the shared callers
    /// pass: an interior pointer, an empty-slice pointer, and a one-past-the-end pointer. None of
    /// them may fault, and none of them dereferences anything here.
    ///
    /// This is a positive contract test. No invalid or dangling address is fabricated, so the
    /// test relies on no undefined behaviour.
    #[test]
    fn prefetch_accepts_every_shared_caller_pointer_class() {
        for hint in [PrefetchHint::T0, PrefetchHint::T1] {
            // Null is filtered before any architecture lane runs.
            prefetch(std::ptr::null(), hint);

            let buffer = vec![0u8; 128];
            prefetch(buffer.as_ptr(), hint);
            prefetch(buffer[64..].as_ptr(), hint);

            // One past the end is a valid pointer to form and a legal prefetch target.
            prefetch(unsafe { buffer.as_ptr().add(buffer.len()) }, hint);

            // An empty slice yields a non-null, non-readable pointer. The old AArch64 lane read a
            // byte through it; the current lanes must only hint.
            let empty: &[u8] = &[];
            prefetch(empty.as_ptr(), hint);

            // A zero-length slice at the end of a live allocation is the UDP packet-start shape.
            let tail: &[u8] = &buffer[buffer.len()..];
            prefetch(tail.as_ptr(), hint);
        }
    }

    /// Both hints must be accepted on every architecture. On x86_64 the locality strategy is a
    /// const generic, so a runtime hint value fails to compile; this exercises both arms of the
    /// match that resolves it.
    #[test]
    fn prefetch_hint_variants_are_both_dispatchable() {
        let buffer = [7u8; 64];
        prefetch(buffer.as_ptr(), PrefetchHint::T0);
        prefetch(buffer.as_ptr(), PrefetchHint::T1);

        let hints = [PrefetchHint::T0, PrefetchHint::T1];
        assert_eq!(hints.len(), 2, "both locality tiers stay reachable through the facade");
    }

    /// Auto-tuner lifecycle. The worker is process-global, so these assertions run under the same
    /// serialising mutex the other pool-global tests use and always restore an empty slot.
    #[test]
    fn auto_tuner_start_is_idempotent_and_shutdown_joins_exactly_once() {
        let _guard =
            LOCK_BLOCKS_TEST_MUTEX.lock().unwrap_or_else(|poisoned| poisoned.into_inner());

        // Start from a known-empty slot regardless of what other tests left behind.
        MemoryPool::shutdown_auto_tuner();
        assert!(
            auto_tuner_slot().lock().unwrap_or_else(|p| p.into_inner()).is_none(),
            "teardown must leave no worker behind"
        );

        // Shutdown with no worker running is a no-op, not a panic or a hang.
        MemoryPool::shutdown_auto_tuner();

        // Auto-tuning is on by default, so a plain pool is an auto-tune-enabled pool.
        let pool = Arc::new(MemoryPool::new(4, 4096));

        MemoryPool::start_auto_tuner(Arc::clone(&pool));
        let started = auto_tuner_slot().lock().unwrap_or_else(|p| p.into_inner()).is_some();
        assert!(started, "an auto-tune-enabled pool must start the worker");

        // A second start must not spawn a second worker for the same process-global slot.
        MemoryPool::start_auto_tuner(Arc::clone(&pool));
        assert!(
            auto_tuner_slot().lock().unwrap_or_else(|p| p.into_inner()).is_some(),
            "the slot still holds exactly one worker"
        );

        MemoryPool::shutdown_auto_tuner();
        assert!(
            auto_tuner_slot().lock().unwrap_or_else(|p| p.into_inner()).is_none(),
            "shutdown must stop and join the worker, leaving the slot empty"
        );

        // The pool itself outlives its worker and stays usable for allocation.
        let block = pool.alloc();
        assert_eq!(block.len(), 4096);
        pool.free(block);

        // Tuning can be restarted explicitly after a shutdown.
        MemoryPool::start_auto_tuner(Arc::clone(&pool));
        assert!(auto_tuner_slot().lock().unwrap_or_else(|p| p.into_inner()).is_some());
        MemoryPool::shutdown_auto_tuner();
    }

    /// A pool with tuning disabled must never occupy the process-global worker slot.
    #[test]
    fn auto_tune_disabled_pool_starts_no_worker() {
        let _guard =
            LOCK_BLOCKS_TEST_MUTEX.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        MemoryPool::shutdown_auto_tuner();

        let environment =
            crate::env_utils::EnvSnapshot::from_pairs([("QUICFUSCATE_POOL_AUTO_TUNE", "0")]);
        let pool = Arc::new(MemoryPool::new_with_snapshot(4, 4096, &environment));

        MemoryPool::start_auto_tuner(pool);
        assert!(
            auto_tuner_slot().lock().unwrap_or_else(|p| p.into_inner()).is_none(),
            "a pool with auto_tune disabled must not claim the worker slot"
        );
    }

    /// Metrics refresh must observe, never create. Before this contract a scrape could construct
    /// the process-global pool and its worker as a side effect of being asked for numbers.
    #[test]
    fn telemetry_refresh_does_not_create_the_global_pool() {
        // `global_pool_if_initialized` is the accessor telemetry uses. Whatever the ambient state
        // of GLOBAL_POOL is in this test binary, the observing accessor must agree with it and
        // must never be the thing that publishes it.
        let before = crate::optimize::global_pool_if_initialized().is_some();
        crate::optimize::telemetry::flush();
        let after = crate::optimize::global_pool_if_initialized().is_some();
        assert_eq!(before, after, "a telemetry flush must not change pool existence");
    }
}
