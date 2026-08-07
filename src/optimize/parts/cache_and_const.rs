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

#[cfg(feature = "prefetch")]
#[cfg_attr(feature = "aggressive_inline", inline(always))]
unsafe fn prefetch_impl(ptr: *const u8, hint: PrefetchHint) {
    #[cfg(target_arch = "x86_64")]
    {
        use core::arch::x86_64::{_mm_prefetch, _MM_HINT_T0, _MM_HINT_T1};
        let mode = match hint {
            PrefetchHint::T0 => _MM_HINT_T0,
            PrefetchHint::T1 => _MM_HINT_T1,
        };
        _mm_prefetch(ptr as *const i8, mode);
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
}
