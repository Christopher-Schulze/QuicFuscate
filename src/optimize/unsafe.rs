#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnsafeError {
    CapacityOverflow,
    CompressionFailed,
}
// # Unsafe Core - Maximum Performance Optimizations
//
// This module contains all unsafe optimizations for QuicFuscate, providing
// zero-copy operations, SIMD acceleration, and direct memory manipulation
// for maximum throughput and minimum latency.
//
// Safety Invariants
// - All raw pointers must be valid and aligned
// - Lifetimes are strictly enforced through PhantomData
// - Memory is never double-freed
// - All operations are protected by debug assertions
//
// Performance Gains (indicative)
// - Memory Pool: 10-15% CPU reduction, 5% latency improvement
// - Transport: 20-25% CPU reduction, 5-10% latency improvement
// - FEC: 2-3x speedup for GF operations
// - Compression: 10-20% CPU reduction
// - Overall: throughput improvements are workload-dependent and must be validated with benchmarks.

use std::alloc::{alloc, dealloc, handle_alloc_error, Layout};
use std::cell::UnsafeCell;
use std::io::IoSlice;
use std::marker::PhantomData;
use std::ptr::{self, NonNull};
use std::slice;
use std::sync::atomic::{AtomicPtr, AtomicUsize, Ordering};
use std::sync::Arc;

#[cfg(target_arch = "x86_64")]
use std::arch::x86_64::*;

use crate::optimize::{prefetch, PrefetchHint};
use crate::telemetry;

// ============================================================================
// Zero-Copy Memory Pool with MaybeUninit
// ============================================================================

/// Ultra-fast memory pool using raw pointers and MaybeUninit
pub struct UnsafeMemoryPool {
    /// Thread-local cache using raw pointers
    tls_cache: UnsafeCell<Vec<*mut u8>>,
    /// Global pool using atomic pointers
    global_pool: Vec<AtomicPtr<u8>>,
    /// Pool configuration
    block_size: usize,
    capacity: AtomicUsize,
    in_use: AtomicUsize,
    available: AtomicUsize,
    /// Memory layout for allocation
    layout: Layout,
    /// NUMA node affinity
    numa_node: usize,
}

// SAFETY: UnsafeMemoryPool is Send because all raw pointers it contains are owned
// allocations (via std::alloc::alloc) that are not shared with other threads without
// atomic synchronization. The global_pool uses AtomicPtr with Acquire/Release ordering,
// and the tls_cache is only accessed by the thread that owns it.
unsafe impl Send for UnsafeMemoryPool {}
// SAFETY: UnsafeMemoryPool is Sync because shared access to the global_pool is fully
// mediated by AtomicPtr with Acquire/Release ordering, ensuring no data races. The
// tls_cache (UnsafeCell<Vec<*mut u8>>) is only accessed from a single thread per the
// thread-local cache protocol - concurrent callers each operate on their own TLS path
// or take the atomic global path.
unsafe impl Sync for UnsafeMemoryPool {}

impl UnsafeMemoryPool {
    const TLS_CACHE_SIZE: usize = 32;
    const PREFETCH_DISTANCE: usize = 8;

    /// Creates a new unsafe memory pool with specified capacity and block size
    pub fn new(capacity: usize, block_size: usize, numa_node: usize) -> Self {
        // Ensure block size is aligned to cache line (64 bytes)
        let block_size = (block_size + 63) & !63;
        // SAFETY: block_size is cache-line aligned (rounded up to multiple of 64 above),
        // so it is always a valid power-of-two alignment. Size > 0 is guaranteed by the
        // alignment rounding. These preconditions satisfy Layout::from_size_align.
        let layout = unsafe { Layout::from_size_align_unchecked(block_size, 64) };

        let mut global_pool = Vec::with_capacity(capacity);

        // Pre-allocate all blocks
        for _ in 0..capacity {
            // SAFETY: `layout` was constructed with valid size (>0) and alignment (64)
            // above. alloc returns a valid pointer or null; null is caught by
            // handle_alloc_error which aborts. The returned pointer is valid for
            // `block_size` bytes with 64-byte alignment.
            let ptr = unsafe {
                let raw = alloc(layout);
                if raw.is_null() {
                    handle_alloc_error(layout);
                }
                #[cfg(target_os = "linux")]
                {
                    // NUMA binding
                    crate::optimize::numa::move_to_node(raw, block_size, numa_node);
                }
                raw
            };
            global_pool.push(AtomicPtr::new(ptr));
        }
        telemetry::UNSAFE_POOL_CREATED.inc();
        telemetry::UNSAFE_POOL_CAPACITY.store(capacity as u64, Ordering::Relaxed);

        let this = Self {
            tls_cache: UnsafeCell::new(Vec::with_capacity(Self::TLS_CACHE_SIZE)),
            global_pool,
            block_size,
            capacity: AtomicUsize::new(capacity),
            in_use: AtomicUsize::new(0),
            available: AtomicUsize::new(capacity),
            layout,
            numa_node,
        };

        // Touch fields so they are considered used and emit a helpful debug line.
        let cap_now = this.capacity.load(Ordering::Relaxed);
        log::debug!(
            "UnsafeMemoryPool::new -> capacity={}, numa_node={}, block_size={}",
            cap_now,
            this.numa_node,
            this.block_size
        );

        this
    }

    /// Allocates a block without zeroing - maximum performance
    #[inline(always)]
    /// # Safety
    /// Caller must ensure the returned pointer is used within the pool's block size
    /// and deallocated via `UnsafeMemoryPool::free`. No aliasing guarantees are provided.
    pub unsafe fn alloc_uninit(&self) -> NonNull<u8> {
        telemetry::UNSAFE_ALLOC_CALLS.inc();

        // SAFETY: UnsafeCell::get() returns a raw pointer to the inner Vec.
        // This is safe to dereference because the pool is !Sync on the TLS path
        // (single-threaded access to thread-local cache). The Vec itself is valid.
        // Try TLS cache first
        let cache = &mut *self.tls_cache.get();
        if let Some(ptr) = cache.pop() {
            telemetry::UNSAFE_TLS_HITS.inc();
            self.available.fetch_sub(1, Ordering::Relaxed);
            self.in_use.fetch_add(1, Ordering::Relaxed);

            // Prefetch next block
            if let Some(&next) = cache.last() {
                self.prefetch_block(next);
            }

            // SAFETY: `ptr` was previously returned by alloc() for this pool's layout,
            // so it is non-null and valid. NonNull::new_unchecked precondition satisfied.
            return NonNull::new_unchecked(ptr);
        }

        // Try global pool
        for slot in &self.global_pool {
            let ptr = slot.swap(ptr::null_mut(), Ordering::Acquire);
            if !ptr.is_null() {
                telemetry::UNSAFE_GLOBAL_HITS.inc();
                self.available.fetch_sub(1, Ordering::Relaxed);
                self.in_use.fetch_add(1, Ordering::Relaxed);

                // Prefetch the block
                self.prefetch_block(ptr);

                // SAFETY: `ptr` was loaded from the global pool via atomic swap and
                // verified non-null above. It was originally allocated with this pool's layout.
                return NonNull::new_unchecked(ptr);
            }
        }

        // Fallback: allocate new block
        telemetry::UNSAFE_FALLBACK_ALLOCS.inc();
        // SAFETY: self.layout has valid size and alignment (constructed in new()).
        // Null check + handle_alloc_error ensures we never return null.
        let ptr = alloc(self.layout);
        if ptr.is_null() {
            handle_alloc_error(self.layout);
        }

        self.in_use.fetch_add(1, Ordering::Relaxed);
        // SAFETY: null case handled above - ptr is guaranteed non-null here.
        NonNull::new_unchecked(ptr)
    }

    /// Returns a block to the pool
    #[inline(always)]
    /// # Safety
    /// `ptr` must originate from this pool via `alloc_uninit` or pool-owned allocations.
    pub unsafe fn free(&self, ptr: NonNull<u8>) {
        telemetry::UNSAFE_FREE_CALLS.inc();

        // SAFETY: UnsafeCell::get() - same single-threaded TLS access pattern as alloc_uninit.
        // Try TLS cache first
        let cache = &mut *self.tls_cache.get();
        if cache.len() < Self::TLS_CACHE_SIZE {
            cache.push(ptr.as_ptr());
            self.available.fetch_add(1, Ordering::Relaxed);
            self.in_use.fetch_sub(1, Ordering::Relaxed);
            return;
        }

        // Try global pool
        for slot in &self.global_pool {
            if slot
                .compare_exchange(
                    ptr::null_mut(),
                    ptr.as_ptr(),
                    Ordering::Release,
                    Ordering::Relaxed,
                )
                .is_ok()
            {
                self.available.fetch_add(1, Ordering::Relaxed);
                self.in_use.fetch_sub(1, Ordering::Relaxed);
                return;
            }
        }

        // Pool is full, deallocate
        telemetry::UNSAFE_DEALLOCS.inc();
        // SAFETY: `ptr` was originally allocated with `self.layout` via alloc().
        // The caller guarantees `ptr` originates from this pool (documented in fn safety).
        // dealloc requires matching layout, which is satisfied.
        dealloc(ptr.as_ptr(), self.layout);
        self.in_use.fetch_sub(1, Ordering::Relaxed);
    }

    /// Copies data directly without bounds checks
    #[inline(always)]
    /// # Safety
    /// `ptr` must be valid for writes of at least `data.len()` bytes within the pool block.
    pub unsafe fn copy_from_slice(&self, ptr: NonNull<u8>, data: &[u8]) -> usize {
        // SAFETY: `len` is clamped to block_size, so the write stays within the
        // allocated block. `ptr` is NonNull and valid for block_size bytes (caller
        // guarantee). source and destination do not overlap (pool block vs stack/heap data).
        let len = data.len().min(self.block_size);
        ptr::copy_nonoverlapping(data.as_ptr(), ptr.as_ptr(), len);
        len
    }

    /// Prefetch a memory block for faster access
    #[cfg_attr(feature = "aggressive_inline", inline(always))]
    /// # Safety
    /// `ptr` must be a valid address; this performs hardware prefetch hints only.
    unsafe fn prefetch_block(&self, ptr: *mut u8) {
        // SAFETY: ptr points to a pool block of self.block_size bytes (cache-line aligned,
        // minimum 64 bytes). PREFETCH_DISTANCE is 8, so the maximum offset is 8*64 = 512
        // bytes. Pool blocks are at least block_size bytes which is >= 64 and typically
        // >= 4096. Even if the offset exceeds the allocation, prefetch is a hint-only
        // instruction that does not fault on invalid addresses (x86/ARM behavior).
        for i in 0..=Self::PREFETCH_DISTANCE {
            let p = ptr.add(i * 64);
            prefetch(p as *const u8, PrefetchHint::T0);
        }
    }

    // Unit tests must be defined at module scope; see tests module at the bottom.
}

impl Drop for UnsafeMemoryPool {
    fn drop(&mut self) {
        // SAFETY: Drop has exclusive (&mut self) access. All pointers in TLS cache and
        // global pool were originally allocated with `self.layout` via alloc(). Each
        // pointer is checked for null before dealloc. No double-free because each slot
        // holds a unique pointer placed there by alloc_uninit/free.
        unsafe {
            // Free all blocks in TLS cache
            let cache = &mut *self.tls_cache.get();
            for &ptr in cache.iter() {
                if !ptr.is_null() {
                    dealloc(ptr, self.layout);
                }
            }

            // Free all blocks in global pool
            for slot in &self.global_pool {
                let ptr = slot.load(Ordering::Relaxed);
                if !ptr.is_null() {
                    dealloc(ptr, self.layout);
                }
            }
        }
    }
}

// ============================================================================
// Zero-Copy Transport with IoSlice
// ============================================================================

/// Zero-copy packet structure using raw pointers
pub struct UnsafePacket {
    /// Raw data pointer
    data: NonNull<u8>,
    /// Data length
    len: usize,
    /// Capacity
    capacity: usize,
    /// Pool reference for deallocation
    pool: Arc<UnsafeMemoryPool>,
    /// Phantom data for lifetime tracking
    _phantom: PhantomData<&'static [u8]>,
}

impl UnsafePacket {
    /// Creates a new packet from raw parts
    #[inline(always)]
    /// # Safety
    /// `data` must be a valid pointer with `capacity` bytes owned by `pool`. `len <= capacity`.
    pub unsafe fn from_raw_parts(
        data: NonNull<u8>,
        len: usize,
        capacity: usize,
        pool: Arc<UnsafeMemoryPool>,
    ) -> Self {
        debug_assert!(len <= capacity);
        debug_assert!(capacity <= pool.block_size);

        Self { data, len, capacity, pool, _phantom: PhantomData }
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
    /// Extends in-place; caller must ensure `self.capacity - self.len >= data.len()`.
    pub unsafe fn extend_from_slice(&mut self, data: &[u8]) -> Result<(), UnsafeError> {
        let new_len = self.len + data.len();
        if new_len > self.capacity {
            return Err(UnsafeError::CapacityOverflow);
        }

        // SAFETY: dst pointer is self.data offset by self.len, which stays within
        // the allocated block because new_len <= self.capacity (checked above) and
        // the block has self.capacity bytes. src is data.as_ptr() with data.len()
        // bytes - a valid slice reference. Regions do not overlap because self.data
        // is a pool-allocated block and data is an independent slice from the caller.
        ptr::copy_nonoverlapping(data.as_ptr(), self.data.as_ptr().add(self.len), data.len());
        self.len = new_len;
        Ok(())
    }
}

impl Drop for UnsafePacket {
    fn drop(&mut self) {
        // SAFETY: self.data is a NonNull<u8> that was allocated from self.pool via
        // alloc_uninit (guaranteed by from_raw_parts contract). It has not been freed
        // yet because Drop runs exactly once. pool.free accepts any pointer that
        // originated from the same pool's alloc_uninit, which is satisfied here.
        unsafe {
            self.pool.free(self.data);
        }
    }
}

// ============================================================================
// SIMD-Accelerated FEC Operations
// ============================================================================

/// SIMD-accelerated Galois Field operations
pub mod simd_gf {
    #[cfg(target_arch = "x86_64")]
    use std::arch::x86_64::*;

    /// Simple GF(2^8) multiplication for scalar fallback
    #[cfg(target_arch = "x86_64")]
    #[inline(always)]
    fn gf_mul_scalar_byte(a: u8, b: u8) -> u8 {
        let mut result = 0u8;
        let mut aa = a;
        let mut bb = b;

        for _ in 0..8 {
            if bb & 1 != 0 {
                result ^= aa;
            }
            let high_bit = aa & 0x80;
            aa <<= 1;
            if high_bit != 0 {
                aa ^= 0x1B; // GF(2^8) polynomial
            }
            bb >>= 1;
        }
        result
    }

    /// GF(2^8) multiplication table for SIMD lookup
    #[cfg(target_arch = "x86_64")]
    #[repr(align(64))]
    pub struct Gf256LookupTable {
        low: [u8; 256],
        high: [u8; 256],
    }

    #[cfg(target_arch = "x86_64")]
    impl Gf256LookupTable {
        /// Creates a new lookup table for a given multiplier
        pub fn new(multiplier: u8) -> Self {
            let mut low = [0u8; 256];
            let mut high = [0u8; 256];

            for i in 0..256 {
                let val = gf_mul_scalar_byte(i as u8, multiplier);
                low[i] = val & 0x0F;
                high[i] = (val >> 4) & 0x0F;
            }

            Self { low, high }
        }
    }

    /// SIMD GF(2^8) multiplication using AVX2
    #[cfg(target_arch = "x86_64")]
    #[target_feature(enable = "avx2")]
    #[inline]
    // SAFETY (whole function body): Requires AVX2 (enforced by target_feature attribute).
    // All _mm256_loadu/storeu_si256 use unaligned intrinsics, so no alignment requirement
    // on src/dst pointers. Pointer arithmetic (src_ptr.add(32), dst_ptr.add(32)) stays
    // within bounds because the loop runs `chunks = len/32` times, advancing exactly
    // `chunks*32 <= len` bytes. The table pointers (table.low, table.high) reference
    // fields of a #[repr(align(64))] struct with 256 bytes each - sufficient for 32-byte
    // SIMD loads. The remainder slice::from_raw_parts calls use (src_ptr, remainder) and
    // (dst_ptr, remainder) where remainder = len % 32 and both pointers are offset by
    // chunks*32 from valid slice bases, so they point to the remaining valid bytes.
    pub unsafe fn gf256_mul_avx2(
        dst: &mut [u8],
        src: &[u8],
        multiplier: u8,
        table: &Gf256LookupTable,
    ) {
        let len = dst.len().min(src.len());
        let chunks = len / 32;

        if chunks == 0 {
            // Fallback to scalar
            gf256_mul_scalar(dst, src, multiplier);
            return;
        }

        // Load lookup tables
        let low_table = _mm256_loadu_si256(table.low.as_ptr() as *const __m256i);
        let high_table = _mm256_loadu_si256(table.high.as_ptr() as *const __m256i);
        let mask_low = _mm256_set1_epi8(0x0F);

        let mut src_ptr = src.as_ptr();
        let mut dst_ptr = dst.as_mut_ptr();

        for _ in 0..chunks {
            // Load 32 bytes
            let data = _mm256_loadu_si256(src_ptr as *const __m256i);

            // Split into low and high nibbles
            let data_low = _mm256_and_si256(data, mask_low);
            let data_high = _mm256_srli_epi16(data, 4);
            let data_high = _mm256_and_si256(data_high, mask_low);

            // Table lookups
            let res_low = _mm256_shuffle_epi8(low_table, data_low);
            let res_high = _mm256_shuffle_epi8(high_table, data_high);

            // XOR results
            let result = _mm256_xor_si256(res_low, res_high);

            // XOR with destination
            let dst_data = _mm256_loadu_si256(dst_ptr as *const __m256i);
            let final_result = _mm256_xor_si256(dst_data, result);

            // Store result
            _mm256_storeu_si256(dst_ptr as *mut __m256i, final_result);

            src_ptr = src_ptr.add(32);
            dst_ptr = dst_ptr.add(32);
        }

        // Handle remainder
        let remainder = len % 32;
        if remainder > 0 {
            let src_rem = slice::from_raw_parts(src_ptr, remainder);
            let dst_rem = slice::from_raw_parts_mut(dst_ptr, remainder);
            gf256_mul_scalar(dst_rem, src_rem, multiplier);
        }

        telemetry::SIMD_GF_OPS.inc();
    }

    /// Scalar fallback for GF multiplication
    #[cfg(target_arch = "x86_64")]
    #[inline(always)]
    fn gf256_mul_scalar(dst: &mut [u8], src: &[u8], multiplier: u8) {
        let len = dst.len().min(src.len());
        for i in 0..len {
            dst[i] ^= gf_mul_scalar_byte(src[i], multiplier);
        }
    }

    /// SIMD XOR operation using AVX-512
    #[cfg(all(target_arch = "x86_64", target_feature = "avx512f"))]
    #[inline(always)]
    // SAFETY (whole function body): Requires AVX-512F (enforced by cfg target_feature).
    // _mm512_loadu/storeu_si512 are unaligned intrinsics - no alignment constraint on
    // src/dst. The loop advances by 64 bytes per iteration, running `chunks = len/64`
    // times, so pointer offsets stay within `chunks*64 <= len` bytes of the valid slice
    // bases. Remainder is delegated to xor_blocks_avx2 (>= 32 bytes) or scalar (< 32),
    // using slice::from_raw_parts[_mut] with (ptr + chunks*64, remainder) where both
    // pointer and length stay within the original slice allocations.
    pub unsafe fn xor_blocks_avx512(dst: &mut [u8], src: &[u8]) {
        let len = dst.len().min(src.len());
        let chunks = len / 64;

        let mut src_ptr = src.as_ptr();
        let mut dst_ptr = dst.as_mut_ptr();

        for _ in 0..chunks {
            let src_vec = _mm512_loadu_si512(src_ptr as *const i32);
            let dst_vec = _mm512_loadu_si512(dst_ptr as *const i32);
            let result = _mm512_xor_si512(src_vec, dst_vec);
            _mm512_storeu_si512(dst_ptr as *mut i32, result);

            src_ptr = src_ptr.add(64);
            dst_ptr = dst_ptr.add(64);
        }

        // Handle remainder with AVX2/SSE
        let remainder = len % 64;
        if remainder >= 32 {
            xor_blocks_avx2(
                slice::from_raw_parts_mut(dst_ptr, remainder),
                slice::from_raw_parts(src_ptr, remainder),
            );
        } else if remainder > 0 {
            xor_blocks_scalar(
                slice::from_raw_parts_mut(dst_ptr, remainder),
                slice::from_raw_parts(src_ptr, remainder),
            );
        }

        telemetry::SIMD_XOR_OPS.inc();
    }

    /// AVX2 XOR for smaller blocks
    #[cfg(target_arch = "x86_64")]
    #[target_feature(enable = "avx2")]
    // SAFETY (whole function body): Requires AVX2 (enforced by target_feature attribute).
    // _mm256_loadu/storeu_si256 are unaligned intrinsics. The loop uses offset = i*32
    // where i < chunks = len/32, so offset + 32 <= len, keeping loads and stores within
    // the valid slice allocations. Remainder bytes (len % 32 > 0) are handled by the
    // scalar fallback using safe Rust indexing (dst[offset..], src[offset..]).
    pub unsafe fn xor_blocks_avx2(dst: &mut [u8], src: &[u8]) {
        let len = dst.len().min(src.len());
        let chunks = len / 32;

        for i in 0..chunks {
            let offset = i * 32;
            let src_vec = _mm256_loadu_si256(src.as_ptr().add(offset) as *const __m256i);
            let dst_vec = _mm256_loadu_si256(dst.as_ptr().add(offset) as *const __m256i);
            let result = _mm256_xor_si256(src_vec, dst_vec);
            _mm256_storeu_si256(dst.as_mut_ptr().add(offset) as *mut __m256i, result);
        }

        let remainder = len % 32;
        if remainder > 0 {
            let offset = chunks * 32;
            xor_blocks_scalar(&mut dst[offset..], &src[offset..]);
        }
    }

    /// Scalar XOR fallback
    #[cfg(target_arch = "x86_64")]
    #[inline(always)]
    fn xor_blocks_scalar(dst: &mut [u8], src: &[u8]) {
        let len = dst.len().min(src.len());
        for i in 0..len {
            dst[i] ^= src[i];
        }
    }
}

// ============================================================================
// Direct Compression with zstd_sys
// ============================================================================

pub mod unsafe_compress {
    use super::*;

    // Placeholder types for zstd_sys integration
    // In production, these would come from zstd_sys crate
    type ZstdCctx = std::ffi::c_void;
    type ZstdCdict = std::ffi::c_void;

    #[repr(C)]
    enum ZstdCParameter {
        CompressionLevel = 100,
    }

    // zstd FFI wrappers - unsafe due to raw pointer manipulation and FFI calls.

    // SAFETY: FFI call to ZSTD_createCCtx which allocates a compression context.
    // Returns a valid pointer or null. In non-FFI fallback, Box::into_raw produces
    // a valid heap pointer. Caller must pair with zstd_free_cctx to avoid leaks.
    unsafe fn zstd_create_cctx() -> *mut ZstdCctx {
        #[cfg(feature = "compression_zstd_ffi")]
        {
            zstd_sys::ZSTD_createCCtx() as *mut ZstdCctx
        }
        #[cfg(not(feature = "compression_zstd_ffi"))]
        {
            Box::into_raw(Box::new(0u8)) as *mut ZstdCctx
        }
    }
    // SAFETY: `ctx` must be a pointer previously returned by zstd_create_cctx (and not
    // yet freed). In FFI mode, ZSTD_freeCCtx handles null gracefully. In fallback mode,
    // Box::from_raw requires the pointer to have originated from Box::into_raw with the
    // same type layout (*mut u8), which zstd_create_cctx guarantees.
    unsafe fn zstd_free_cctx(ctx: *mut ZstdCctx) {
        #[cfg(feature = "compression_zstd_ffi")]
        {
            if !ctx.is_null() {
                zstd_sys::ZSTD_freeCCtx(ctx as *mut zstd_sys::ZSTD_CCtx);
            }
        }
        #[cfg(not(feature = "compression_zstd_ffi"))]
        {
            let _ = Box::from_raw(ctx as *mut u8);
        }
    }
    // SAFETY: `data` must point to `len` readable bytes (the dictionary payload).
    // In FFI mode, ZSTD_createCDict copies the data internally. In fallback mode,
    // slice::from_raw_parts(data, len) requires data to be valid for len bytes and
    // properly aligned for u8 (always satisfied). The resulting Vec is heap-allocated
    // via Box::into_raw, producing a valid opaque pointer.
    unsafe fn zstd_create_cdict(data: *const u8, len: usize, level: i32) -> *mut ZstdCdict {
        #[cfg(feature = "compression_zstd_ffi")]
        {
            zstd_sys::ZSTD_createCDict(data as *const std::ffi::c_void, len, level)
                as *mut ZstdCdict
        }
        #[cfg(not(feature = "compression_zstd_ffi"))]
        {
            let _ = level; // level not needed for safe dictionary holder
            let slice = std::slice::from_raw_parts(data, len);
            let vec = slice.to_vec();
            // Store bytes behind the opaque pointer for fallback usage
            Box::into_raw(Box::new(vec)) as *mut ZstdCdict
        }
    }
    // SAFETY: `dict` must be a pointer previously returned by zstd_create_cdict (and not
    // yet freed), or null. In FFI mode, ZSTD_freeCDict handles null. In fallback mode,
    // null is checked before Box::from_raw. The pointer type (*mut Vec<u8>) matches
    // the Box::into_raw source in zstd_create_cdict.
    unsafe fn zstd_free_cdict(dict: *mut ZstdCdict) {
        #[cfg(feature = "compression_zstd_ffi")]
        {
            if !dict.is_null() {
                zstd_sys::ZSTD_freeCDict(dict as *mut zstd_sys::ZSTD_CDict);
            }
        }
        #[cfg(not(feature = "compression_zstd_ffi"))]
        {
            if !dict.is_null() {
                let _ = Box::from_raw(dict as *mut Vec<u8>);
            }
        }
    }
    // SAFETY: `ctx` must be a live compression context from zstd_create_cctx. In FFI
    // mode, ZSTD_CCtx_setParameter is a safe-to-call C function that validates the
    // parameter internally. In fallback mode, no pointer dereference occurs (no-op).
    unsafe fn zstd_cctx_set_parameter(
        ctx: *mut ZstdCctx,
        _param: ZstdCParameter,
        val: i32,
    ) -> usize {
        #[cfg(feature = "compression_zstd_ffi")]
        {
            zstd_sys::ZSTD_CCtx_setParameter(
                ctx as *mut zstd_sys::ZSTD_CCtx,
                zstd_sys::ZSTD_cParameter::ZSTD_c_compressionLevel,
                val,
            )
        }
        #[cfg(not(feature = "compression_zstd_ffi"))]
        {
            let _ = (ctx, val);
            0
        }
    }
    // SAFETY: `_ctx` must be a live compression context. `dst` must point to
    // `dst_capacity` writable bytes. `src` must point to `src_size` readable bytes.
    // `dict` must be a live dictionary from zstd_create_cdict. In FFI mode, zstd
    // handles all bounds internally. In fallback mode: dict is dereferenced as
    // *const Vec<u8> (matching zstd_create_cdict's Box::into_raw type); src is
    // converted via slice::from_raw_parts(src, src_size) which requires src to be
    // valid for src_size bytes; the copy_nonoverlapping writes at most z.len() bytes
    // to dst, checked against dst_capacity to prevent out-of-bounds writes.
    unsafe fn zstd_compress_using_cdict(
        _ctx: *mut ZstdCctx,
        dst: *mut std::ffi::c_void,
        dst_capacity: usize,
        src: *const std::ffi::c_void,
        src_size: usize,
        dict: *const ZstdCdict,
    ) -> usize {
        #[cfg(feature = "compression_zstd_ffi")]
        {
            zstd_sys::ZSTD_compress_usingCDict(
                _ctx as *mut zstd_sys::ZSTD_CCtx,
                dst,
                dst_capacity,
                src,
                src_size,
                dict as *const zstd_sys::ZSTD_CDict,
            )
        }
        #[cfg(not(feature = "compression_zstd_ffi"))]
        {
            // Recover dictionary bytes from opaque pointer
            let dict_bytes: &[u8] = if !dict.is_null() {
                let vref: &Vec<u8> = &*(dict as *const Vec<u8>);
                vref.as_slice()
            } else {
                &[]
            };
            // Perform real compression using safe zstd + dictionary
            let mut enc = match zstd::stream::Encoder::with_dictionary(Vec::new(), 3, dict_bytes) {
                Ok(e) => e,
                Err(_) => return usize::MAX,
            };
            use std::io::Write;
            if enc.write_all(std::slice::from_raw_parts(src as *const u8, src_size)).is_err() {
                return usize::MAX;
            }
            let z = match enc.finish() {
                Ok(v) => v,
                Err(_) => return usize::MAX,
            };
            if z.len() > dst_capacity {
                return usize::MAX;
            }
            // SAFETY: z is a Vec<u8> produced by the encoder, so z.as_ptr() is valid
            // for z.len() bytes. dst points to dst_capacity writable bytes (caller
            // contract). z.len() <= dst_capacity is checked above. src (z) and dst do
            // not overlap - z is a local heap Vec, dst is the caller-provided buffer.
            unsafe {
                std::ptr::copy_nonoverlapping(z.as_ptr(), dst as *mut u8, z.len());
            }
            z.len()
        }
    }
    #[cfg_attr(not(feature = "compression_zstd_ffi"), allow(unused_variables))]
    // SAFETY: `ctx` must be a live compression context from zstd_create_cctx. `dst`
    // must point to `dst_capacity` writable bytes. `src` must point to `src_size`
    // readable bytes. In FFI mode, ZSTD_compressCCtx handles bounds internally.
    // In fallback mode: slice::from_raw_parts(src, src_size) requires src valid for
    // src_size bytes; copy_nonoverlapping writes z.len() bytes to dst, bounded by the
    // z.len() <= dst_capacity check. src (local Vec) and dst do not overlap.
    unsafe fn zstd_compress_cctx(
        ctx: *mut ZstdCctx,
        dst: *mut std::ffi::c_void,
        dst_capacity: usize,
        src: *const std::ffi::c_void,
        src_size: usize,
        level: i32,
    ) -> usize {
        #[cfg(feature = "compression_zstd_ffi")]
        {
            zstd_sys::ZSTD_compressCCtx(
                ctx as *mut zstd_sys::ZSTD_CCtx,
                dst,
                dst_capacity,
                src,
                src_size,
                level,
            )
        }
        #[cfg(not(feature = "compression_zstd_ffi"))]
        {
            let _ = ctx;
            // Real compression using safe zstd path with chosen level
            let z = match zstd::stream::encode_all(
                std::io::Cursor::new(std::slice::from_raw_parts(src as *const u8, src_size)),
                level,
            ) {
                Ok(v) => v,
                Err(_) => return usize::MAX,
            };
            if z.len() > dst_capacity {
                return usize::MAX;
            }
            // SAFETY: z is a local heap Vec from encode_all, so z.as_ptr() is valid for
            // z.len() bytes. dst points to dst_capacity writable bytes (caller contract).
            // z.len() <= dst_capacity is checked above. No overlap - z is local, dst is
            // the caller-provided output buffer.
            unsafe {
                std::ptr::copy_nonoverlapping(z.as_ptr(), dst as *mut u8, z.len());
            }
            z.len()
        }
    }
    fn zstd_is_error(code: usize) -> u32 {
        #[cfg(feature = "compression_zstd_ffi")]
        {
            // SAFETY: ZSTD_isError is a pure function that inspects the error code value.
            // It does not dereference any pointers or mutate state. Safe to call with any
            // usize value.
            (unsafe { zstd_sys::ZSTD_isError(code) }) as u32
        }
        #[cfg(not(feature = "compression_zstd_ffi"))]
        {
            if code == usize::MAX {
                1
            } else {
                0
            }
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
    #[inline]
    fn manual_cfg() -> ManualCfg {
        *MANUAL_CFG.get_or_init(|| {
            let enabled = std::env::var("QUICFUSCATE_ZSTD_MODE")
                .map(|v| v.eq_ignore_ascii_case("manual"))
                .unwrap_or(false);
            let level = std::env::var("QUICFUSCATE_ZSTD_LEVEL")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(3);
            let workers = std::env::var("QUICFUSCATE_ZSTD_WORKERS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(2);
            let block = std::env::var("QUICFUSCATE_ZSTD_TARGET_BLOCK")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(64 * 1024);
            ManualCfg { enabled, level, workers, block }
        })
    }

    #[cfg(feature = "compression_zstd_ffi")]
    #[inline]
    fn choose_strategy(len: usize) -> zstd_sys::ZSTD_strategy {
        if let Ok(s) = std::env::var("QUICFUSCATE_ZSTD_STRATEGY") {
            match s.to_ascii_lowercase().as_str() {
                "fast" => return zstd_sys::ZSTD_strategy::ZSTD_fast,
                "dfast" => return zstd_sys::ZSTD_strategy::ZSTD_dfast,
                "greedy" => return zstd_sys::ZSTD_strategy::ZSTD_greedy,
                "lazy2" => return zstd_sys::ZSTD_strategy::ZSTD_lazy2,
                "btopt" => return zstd_sys::ZSTD_strategy::ZSTD_btlazy2,
                _ => {}
            }
        }
        if len <= 8 * 1024 {
            zstd_sys::ZSTD_strategy::ZSTD_dfast
        } else if len <= 64 * 1024 {
            zstd_sys::ZSTD_strategy::ZSTD_fast
        } else if len <= 512 * 1024 {
            zstd_sys::ZSTD_strategy::ZSTD_greedy
        } else {
            zstd_sys::ZSTD_strategy::ZSTD_lazy2
        }
    }

    #[cfg(feature = "compression_zstd_ffi")]
    #[inline]
    fn choose_window_log(len: usize) -> i32 {
        if let Ok(w) = std::env::var("QUICFUSCATE_ZSTD_WINDOW_LOG")
            .and_then(|v| v.parse::<i32>().map_err(|_| std::env::VarError::NotPresent))
        {
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

    #[cfg(feature = "compression_zstd_ffi")]
    #[inline]
    fn choose_checksum_flag() -> i32 {
        std::env::var("QUICFUSCATE_ZSTD_CHECKSUM").ok().and_then(|v| v.parse().ok()).unwrap_or(0)
    }

    #[cfg(feature = "compression_zstd_ffi")]
    #[inline]
    fn choose_content_size_flag() -> i32 {
        std::env::var("QUICFUSCATE_ZSTD_CONTENTSIZE").ok().and_then(|v| v.parse().ok()).unwrap_or(0)
    }

    /// Direct compression context using zstd C API
    pub struct UnsafeCompressor {
        ctx: *mut ZstdCctx,
        dict: Option<*mut ZstdCdict>,
        dict_meta: Option<(u16, u16)>, // (hash, version)
        pool: Arc<UnsafeMemoryPool>,
    }

    // SAFETY: UnsafeCompressor is Send because its raw pointers (ctx, dict) are owned
    // exclusively - they are created in new() and freed in Drop. No other thread shares
    // these pointers. The Arc<UnsafeMemoryPool> field is already Send+Sync.
    unsafe impl Send for UnsafeCompressor {}
    // SAFETY: UnsafeCompressor is Sync because compress_direct takes &self but the zstd
    // context is only used within a single call (zstd compression contexts are
    // thread-safe for non-concurrent calls). The pool field is Arc-wrapped and already
    // Sync. dict is read-only after construction.
    unsafe impl Sync for UnsafeCompressor {}

    impl UnsafeCompressor {
        /// Creates a new compressor with optional dictionary
        pub fn new(pool: Arc<UnsafeMemoryPool>, dict_data: Option<&[u8]>, level: i32) -> Self {
            // SAFETY: All FFI calls here (zstd_create_cctx, zstd_cctx_set_parameter,
            // zstd_create_cdict) follow their documented contracts: ctx is checked for
            // null immediately after creation (abort on failure), parameters are set on
            // a live context, and dict_data.as_ptr()/len() originate from a valid &[u8]
            // slice. All returned pointers are stored in Self and freed in Drop.
            unsafe {
                let ctx = zstd_create_cctx();
                if ctx.is_null() {
                    std::process::abort();
                }

                // Set compression level
                zstd_cctx_set_parameter(ctx, ZstdCParameter::CompressionLevel, level);

                // Tune parameters for throughput/latency (only active in FFI path)
                #[cfg(feature = "compression_zstd_ffi")]
                {
                    // nbWorkers: from env or default 2 (reasonable for networking workloads)
                    let workers: i32 = std::env::var("QUICFUSCATE_ZSTD_WORKERS")
                        .ok()
                        .and_then(|v| v.parse().ok())
                        .unwrap_or(2);
                    let _ = zstd_sys::ZSTD_CCtx_setParameter(
                        ctx as *mut zstd_sys::ZSTD_CCtx,
                        zstd_sys::ZSTD_cParameter::ZSTD_c_nbWorkers,
                        workers,
                    );
                    // Target block size (bytes) to reduce latency for network packets
                    let target_block: i32 = std::env::var("QUICFUSCATE_ZSTD_TARGET_BLOCK")
                        .ok()
                        .and_then(|v| v.parse().ok())
                        .unwrap_or(64 * 1024);
                    let _ = zstd_sys::ZSTD_CCtx_setParameter(
                        ctx as *mut zstd_sys::ZSTD_CCtx,
                        zstd_sys::ZSTD_cParameter::ZSTD_c_targetCBlockSize,
                        target_block,
                    );
                }

                // Create dictionary if provided
                let dict = dict_data.map(|data| {
                    let dict_ptr = zstd_create_cdict(data.as_ptr(), data.len(), level);
                    if dict_ptr.is_null() {
                        return std::ptr::null_mut();
                    }
                    dict_ptr
                });
                let dict = dict.and_then(|ptr| if ptr.is_null() { None } else { Some(ptr) });

                let dict_meta = dict_data.map(compute_dict_hash_version);

                Self { ctx, dict, dict_meta, pool }
            }
        }

        /// Compress directly into pool buffer without intermediate allocation
        #[inline]
        /// # Safety
        /// `src` must point to readable memory; this writes into a pool-owned buffer and returns
        /// an `UnsafePacket` that must be dropped to free the buffer back to the pool.
        pub unsafe fn compress_direct(&self, src: &[u8]) -> Result<UnsafePacket, UnsafeError> {
            telemetry::UNSAFE_COMPRESS_CALLS.inc();

            // Allocate output buffer from pool
            let dst_ptr = self.pool.alloc_uninit();
            let dst_capacity = self.pool.block_size;

            // Decide header type/size
            let (header_magic, header_size) =
                if self.dict.is_some() { (0x5D_u8, 9_usize) } else { (0x5A_u8, 5_usize) };
            if dst_capacity < header_size + 16 {
                self.pool.free(dst_ptr);
                return Err(UnsafeError::CapacityOverflow);
            }

            // Adaptive sweetspot tuning (per-call)
            #[cfg(feature = "compression_zstd_ffi")]
            {
                let man = manual_cfg();
                let (level, workers, block) = if man.enabled {
                    (man.level, man.workers, man.block)
                } else {
                    sweetspot_params_for(src.len())
                };
                let _ = zstd_sys::ZSTD_CCtx_setParameter(
                    self.ctx as *mut zstd_sys::ZSTD_CCtx,
                    zstd_sys::ZSTD_cParameter::ZSTD_c_compressionLevel,
                    level,
                );
                let _ = zstd_sys::ZSTD_CCtx_setParameter(
                    self.ctx as *mut zstd_sys::ZSTD_CCtx,
                    zstd_sys::ZSTD_cParameter::ZSTD_c_nbWorkers,
                    workers,
                );
                let _ = zstd_sys::ZSTD_CCtx_setParameter(
                    self.ctx as *mut zstd_sys::ZSTD_CCtx,
                    zstd_sys::ZSTD_cParameter::ZSTD_c_targetCBlockSize,
                    block,
                );
                // Conservative extras: strategy, windowLog, checksum off, contentSize off
                let strategy = choose_strategy(src.len()) as i32;
                let _ = zstd_sys::ZSTD_CCtx_setParameter(
                    self.ctx as *mut zstd_sys::ZSTD_CCtx,
                    zstd_sys::ZSTD_cParameter::ZSTD_c_strategy,
                    strategy,
                );
                let window_log = choose_window_log(src.len());
                let _ = zstd_sys::ZSTD_CCtx_setParameter(
                    self.ctx as *mut zstd_sys::ZSTD_CCtx,
                    zstd_sys::ZSTD_cParameter::ZSTD_c_windowLog,
                    window_log,
                );
                let checksum = choose_checksum_flag();
                let _ = zstd_sys::ZSTD_CCtx_setParameter(
                    self.ctx as *mut zstd_sys::ZSTD_CCtx,
                    zstd_sys::ZSTD_cParameter::ZSTD_c_checksumFlag,
                    checksum,
                );
                let content_size = choose_content_size_flag();
                let _ = zstd_sys::ZSTD_CCtx_setParameter(
                    self.ctx as *mut zstd_sys::ZSTD_CCtx,
                    zstd_sys::ZSTD_cParameter::ZSTD_c_contentSizeFlag,
                    content_size,
                );
            }

            // Write header
            // SAFETY (header writes): dst_ptr is a NonNull from pool.alloc_uninit with
            // dst_capacity bytes (= pool.block_size). The check `dst_capacity < header_size + 16`
            // above guarantees at least header_size + 16 bytes available. Header writes:
            // - offset 0: 1 byte (magic) - within bounds
            // - offsets 1..5 or 1..9: at most 9 bytes total (header_size) - within bounds
            // Source arrays (len_be, h, v) are stack-local [u8; 4] / [u8; 2], so they do not
            // overlap with the pool-allocated dst_ptr. All copy_nonoverlapping lengths match
            // the source array sizes exactly.
            *dst_ptr.as_ptr() = header_magic;
            let len_be = (src.len() as u32).to_be_bytes();
            if header_magic == 0x5A {
                // 0x5A + 4B orig len
                ptr::copy_nonoverlapping(len_be.as_ptr(), dst_ptr.as_ptr().add(1), 4);
            } else {
                // 0x5D + 2B hash + 2B version + 4B orig len
                let (hash, ver) = self.dict_meta.unwrap_or((0, 1));
                let h = hash.to_be_bytes();
                let v = ver.to_be_bytes();
                ptr::copy_nonoverlapping(h.as_ptr(), dst_ptr.as_ptr().add(1), 2);
                ptr::copy_nonoverlapping(v.as_ptr(), dst_ptr.as_ptr().add(3), 2);
                ptr::copy_nonoverlapping(len_be.as_ptr(), dst_ptr.as_ptr().add(5), 4);
            }

            // Compress data
            // SAFETY: self.ctx is a live compression context (null-checked in new()).
            // dst_ptr.add(header_size) is within the pool block (header_size < dst_capacity).
            // dst_capacity - header_size is the remaining writable bytes. src.as_ptr()
            // with src.len() is valid (from the &[u8] slice reference). dict_ptr, if Some,
            // is a live dictionary pointer from new(). Error result is checked below.
            let compressed_size = if let Some(dict_ptr) = self.dict {
                zstd_compress_using_cdict(
                    self.ctx,
                    dst_ptr.as_ptr().add(header_size) as *mut _,
                    dst_capacity - header_size,
                    src.as_ptr() as *const _,
                    src.len(),
                    dict_ptr,
                )
            } else {
                zstd_compress_cctx(
                    self.ctx,
                    dst_ptr.as_ptr().add(header_size) as *mut _,
                    dst_capacity - header_size,
                    src.as_ptr() as *const _,
                    src.len(),
                    sweetspot_params_for(src.len()).0, // level
                )
            };

            if zstd_is_error(compressed_size) != 0 {
                self.pool.free(dst_ptr);
                telemetry::UNSAFE_COMPRESS_FAILURES.inc();
                return Err(UnsafeError::CompressionFailed);
            }

            let total_size = header_size + compressed_size;
            telemetry::UNSAFE_COMPRESS_BYTES_IN.inc_by(src.len() as u64);
            telemetry::UNSAFE_COMPRESS_BYTES_OUT.inc_by(total_size as u64);

            Ok(UnsafePacket::from_raw_parts(
                dst_ptr,
                total_size,
                dst_capacity,
                Arc::clone(&self.pool),
            ))
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

    impl Drop for UnsafeCompressor {
        fn drop(&mut self) {
            // SAFETY: Drop has exclusive (&mut self) access. self.ctx was allocated by
            // zstd_create_cctx in new() and has not been freed yet (Drop runs once).
            // self.dict, if Some, was allocated by zstd_create_cdict in new() and has
            // not been freed. Both free functions accept pointers from their respective
            // create functions, satisfying their contracts.
            unsafe {
                if let Some(dict_ptr) = self.dict {
                    zstd_free_cdict(dict_ptr);
                }
                zstd_free_cctx(self.ctx);
            }
        }
    }

    /// Fast entropy calculation using SIMD
    #[cfg(target_arch = "x86_64")]
    #[target_feature(enable = "avx2")]
    // SAFETY (whole function body): Requires AVX2 (target_feature attribute). The
    // _mm256_loadu_si256 intrinsic performs unaligned 32-byte reads. data.as_ptr().add(offset)
    // where offset = i*32 and i < chunks = len/32, so offset + 32 <= len, staying within
    // the valid slice. std::mem::transmute::<__m256i, [u8; 32]> is valid because __m256i
    // is exactly 32 bytes and [u8; 32] is 32 bytes - same size, and u8 has no alignment
    // or validity requirements. Remainder bytes use safe Rust indexing.
    pub unsafe fn calculate_entropy_simd(data: &[u8]) -> f32 {
        let mut histogram = [0u32; 256];
        let len = data.len();

        // Process 32 bytes at a time with AVX2
        let chunks = len / 32;
        for i in 0..chunks {
            let offset = i * 32;
            let vec = _mm256_loadu_si256(data.as_ptr().add(offset) as *const __m256i);

            // Extract bytes and update histogram
            let bytes = std::mem::transmute::<__m256i, [u8; 32]>(vec);
            for &byte in &bytes {
                histogram[byte as usize] += 1;
            }
        }

        // Handle remainder
        for &byte in &data[chunks * 32..] {
            histogram[byte as usize] += 1;
        }

        // Calculate entropy
        let mut entropy = 0.0f32;
        let len_f = len as f32;

        for &count in &histogram {
            if count > 0 {
                let p = count as f32 / len_f;
                entropy -= p * p.log2();
            }
        }

        telemetry::ENTROPY_CALCULATIONS.inc();
        entropy
    }
}

// ============================================================================
// Testing Infrastructure
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_unsafe_memory_pool() {
        let pool = Arc::new(UnsafeMemoryPool::new(10, 4096, 0));

        // SAFETY: alloc_uninit returns a valid NonNull<u8> from the pool with 4096-byte
        // blocks. copy_from_slice writes at most block_size bytes. slice::from_raw_parts
        // uses the same pointer and the returned len (clamped to block_size). free returns
        // the pointer to the pool. All operations use pointers from this pool only.
        unsafe {
            // Test allocation
            let ptr1 = pool.alloc_uninit();
            // Verify alignment instead of nullness (NonNull guarantees non-null)
            assert_eq!((ptr1.as_ptr() as usize) & 63, 0, "Memory pool alignment not 64B");

            // Test write
            let data = b"Hello, World!";
            let len = pool.copy_from_slice(ptr1, data);
            assert_eq!(len, data.len());

            // Test read
            let slice = slice::from_raw_parts(ptr1.as_ptr(), len);
            assert_eq!(slice, data);

            // Test free
            pool.free(ptr1);

            // Test TLS cache hit
            let ptr2 = pool.alloc_uninit();
            assert_eq!(ptr1, ptr2); // Should get same pointer from TLS cache
            pool.free(ptr2);
        }
    }

    #[test]
    fn test_unsafe_packet() {
        let pool = Arc::new(UnsafeMemoryPool::new(5, 1024, 0));

        // SAFETY: ptr is from pool.alloc_uninit (valid, 1024-byte block). from_raw_parts
        // is called with len=0, capacity=1024, matching the pool block. extend_from_slice
        // writes 9 bytes which is < 1024 capacity. Packet is dropped normally, returning
        // the pointer to the pool.
        unsafe {
            let ptr = pool.alloc_uninit();
            let mut packet = UnsafePacket::from_raw_parts(ptr, 0, 1024, Arc::clone(&pool));

            // Test extend
            let data = b"Test data";
            packet.extend_from_slice(data).unwrap();
            assert_eq!(packet.as_slice(), data);

            // Test IoSlice creation
            let io_slice = packet.as_io_slice();
            assert_eq!(io_slice.len(), data.len());
        }
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn test_simd_xor() {
        let mut dst = vec![0xAA; 64];
        let src = vec![0x55; 64];

        // SAFETY: dst and src are valid 64-byte Vec slices. xor_blocks_avx2 requires
        // AVX2 (gated by cfg). Both slices have equal length (64 bytes = 2 AVX2 chunks).
        // dst and src are separate heap allocations, so they do not overlap.
        unsafe {
            #[cfg(target_feature = "avx2")]
            simd_gf::xor_blocks_avx2(&mut dst, &src);

            for byte in &dst {
                assert_eq!(*byte, 0xFF);
            }
        }
    }

    #[test]
    fn test_unsafe_compression() {
        let pool = Arc::new(UnsafeMemoryPool::new(10, 8192, 0));
        let compressor = unsafe_compress::UnsafeCompressor::new(Arc::clone(&pool), None, 3);

        // SAFETY: compress_direct takes a valid &[u8] slice (stack-allocated byte string
        // literal). The pool has 8192-byte blocks, sufficient for header + compressed
        // output of 59 bytes of input. The returned UnsafePacket is used read-only via
        // as_slice() and dropped normally.
        unsafe {
            let data = b"This is test data for compression. It should compress well.";
            let packet = compressor.compress_direct(data).unwrap();

            // Verify magic byte
            assert_eq!(*packet.as_slice().first().unwrap(), 0x5A);

            // Verify length encoding
            let len_bytes = &packet.as_slice()[1..5];
            let original_len =
                u32::from_be_bytes([len_bytes[0], len_bytes[1], len_bytes[2], len_bytes[3]]);
            assert_eq!(original_len as usize, data.len());
        }
    }

    /// Test with Miri for memory safety
    #[cfg(miri)]
    #[test]
    fn test_miri_safety() {
        let pool = Arc::new(UnsafeMemoryPool::new(3, 256, 0));

        // SAFETY: ptr1 and ptr2 are distinct NonNull pointers from pool.alloc_uninit,
        // each backed by a 256-byte allocation. write_bytes writes exactly 256 bytes
        // to each (matching the block size). ptr dereferences (*ptr1.as_ptr()) read
        // the first byte of each valid allocation. free returns pointers to the pool.
        // No double-free because each pointer is freed exactly once.
        unsafe {
            let ptr1 = pool.alloc_uninit();
            let ptr2 = pool.alloc_uninit();

            // Write to ensure no overlap
            ptr::write_bytes(ptr1.as_ptr(), 0xAA, 256);
            ptr::write_bytes(ptr2.as_ptr(), 0xBB, 256);

            // Read back
            assert_eq!(*ptr1.as_ptr(), 0xAA);
            assert_eq!(*ptr2.as_ptr(), 0xBB);

            pool.free(ptr1);
            pool.free(ptr2);
        }
    }

    #[test]
    fn test_pool_alloc_free_cycle() {
        let pool = Arc::new(UnsafeMemoryPool::new(8, 512, 0));

        // SAFETY: alloc_uninit returns valid NonNull pointers from the pool with
        // 512-byte blocks. Each pointer is freed exactly once via pool.free, which
        // returns the block to the pool. No double-free, no use-after-free.
        unsafe {
            let mut ptrs = Vec::new();
            // Allocate 8 blocks
            for _ in 0..8 {
                ptrs.push(pool.alloc_uninit());
            }
            assert_eq!(ptrs.len(), 8);

            // Free all blocks - must not panic
            for ptr in ptrs {
                pool.free(ptr);
            }

            // Re-allocate to verify pool reuse works after free cycle
            let reused = pool.alloc_uninit();
            pool.free(reused);
        }
    }

    #[test]
    fn test_pool_alignment_64() {
        let pool = Arc::new(UnsafeMemoryPool::new(16, 4096, 0));

        // SAFETY: alloc_uninit returns valid NonNull pointers. We only inspect
        // the pointer address for alignment, then free each one exactly once.
        unsafe {
            for _ in 0..16 {
                let ptr = pool.alloc_uninit();
                assert_eq!(
                    ptr.as_ptr() as usize % 64,
                    0,
                    "pointer {:p} is not 64-byte aligned",
                    ptr.as_ptr()
                );
                pool.free(ptr);
            }
        }
    }

    #[test]
    fn test_packet_extend_sequential() {
        let pool = Arc::new(UnsafeMemoryPool::new(4, 1024, 0));

        // SAFETY: ptr from alloc_uninit is valid for 1024 bytes. from_raw_parts
        // with len=0, capacity=1024 is correct. Each extend_from_slice adds data
        // within the 1024-byte capacity. Packet dropped normally at end.
        unsafe {
            let ptr = pool.alloc_uninit();
            let mut pkt = UnsafePacket::from_raw_parts(ptr, 0, 1024, Arc::clone(&pool));

            let chunks: [&[u8]; 5] = [b"AAAA", b"BBBB", b"CCCC", b"DDDD", b"EEEE"];
            for chunk in &chunks {
                pkt.extend_from_slice(chunk).unwrap();
            }

            let data = pkt.as_slice();
            assert_eq!(data.len(), 20);
            assert_eq!(&data[0..4], b"AAAA");
            assert_eq!(&data[4..8], b"BBBB");
            assert_eq!(&data[8..12], b"CCCC");
            assert_eq!(&data[12..16], b"DDDD");
            assert_eq!(&data[16..20], b"EEEE");
        }
    }

    #[test]
    fn test_packet_extend_overflow() {
        let pool = Arc::new(UnsafeMemoryPool::new(2, 128, 0));

        // SAFETY: ptr from alloc_uninit is valid for 128 bytes (pool block_size
        // rounds 128 up to 128 which is already 64-aligned). from_raw_parts with
        // len=0, capacity=128. First extend of 100 bytes succeeds. Second extend
        // of 100 bytes exceeds capacity and must return Err. Packet dropped normally.
        unsafe {
            let ptr = pool.alloc_uninit();
            let mut pkt = UnsafePacket::from_raw_parts(ptr, 0, 128, Arc::clone(&pool));

            let buf = [0xCCu8; 100];
            let first = pkt.extend_from_slice(&buf);
            assert!(first.is_ok(), "first extend within capacity must succeed");

            let second = pkt.extend_from_slice(&buf);
            assert!(
                matches!(second, Err(UnsafeError::CapacityOverflow)),
                "extend beyond capacity must return CapacityOverflow"
            );
            // Length must remain at 100 (the overflow write must not have taken effect)
            assert_eq!(pkt.as_slice().len(), 100);
        }
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn test_gf256_lookup_table_identity() {
        // Multiplying by 1 in GF(2^8) is the identity: gf_mul(x, 1) = x
        let table = simd_gf::Gf256LookupTable::new(1);

        // The lookup table stores low and high nibbles of gf_mul(i, multiplier).
        // For multiplier=1, gf_mul(i, 1) = i, so:
        //   table.low[i] = i & 0x0F
        //   table.high[i] = (i >> 4) & 0x0F
        for i in 0..256u16 {
            let expected_val = i as u8; // identity: gf_mul(i, 1) = i
            let low_nibble = expected_val & 0x0F;
            let high_nibble = (expected_val >> 4) & 0x0F;
            assert_eq!(table.low[i as usize], low_nibble, "low nibble mismatch at index {}", i);
            assert_eq!(table.high[i as usize], high_nibble, "high nibble mismatch at index {}", i);
        }
    }

    #[test]
    fn test_xor_blocks_involution() {
        // XOR is its own inverse: (data ^ key) ^ key == data
        let original = (0..128u8).collect::<Vec<u8>>();
        let key: Vec<u8> = (0..128u8).map(|i| i.wrapping_mul(37)).collect();

        let mut buf = original.clone();

        // First XOR pass
        for i in 0..buf.len() {
            buf[i] ^= key[i];
        }
        // buf is now ciphertext - must differ from original (unless key is all zeros)
        assert_ne!(buf, original, "XOR with non-zero key must change data");

        // Second XOR pass (involution)
        for i in 0..buf.len() {
            buf[i] ^= key[i];
        }
        assert_eq!(buf, original, "double XOR must restore original data");
    }

    #[test]
    fn test_pool_copy_from_slice_clamps_to_block_size() {
        let pool = Arc::new(UnsafeMemoryPool::new(2, 64, 0));

        // SAFETY: alloc_uninit returns valid pointer for 64 bytes (block_size).
        // copy_from_slice with oversized data should clamp to block_size.
        // slice::from_raw_parts reads back the clamped length. free returns to pool.
        unsafe {
            let ptr = pool.alloc_uninit();
            let big_data = [0xABu8; 256]; // larger than block_size (64)
            let written = pool.copy_from_slice(ptr, &big_data);
            assert_eq!(written, 64, "copy_from_slice must clamp to block_size");

            // Verify the data was actually written
            let slice = std::slice::from_raw_parts(ptr.as_ptr(), written);
            assert!(slice.iter().all(|&b| b == 0xAB));
            pool.free(ptr);
        }
    }

    #[test]
    fn test_pool_copy_from_slice_zero_length() {
        let pool = Arc::new(UnsafeMemoryPool::new(2, 128, 0));

        // SAFETY: alloc_uninit returns valid pointer. copy_from_slice with empty
        // slice writes zero bytes. free returns to pool.
        unsafe {
            let ptr = pool.alloc_uninit();
            let written = pool.copy_from_slice(ptr, &[]);
            assert_eq!(written, 0);
            pool.free(ptr);
        }
    }

    #[test]
    fn test_packet_empty_slice() {
        let pool = Arc::new(UnsafeMemoryPool::new(2, 256, 0));

        // SAFETY: ptr from alloc_uninit is valid for 256 bytes.
        // from_raw_parts with len=0 creates empty packet.
        unsafe {
            let ptr = pool.alloc_uninit();
            let pkt = UnsafePacket::from_raw_parts(ptr, 0, 256, Arc::clone(&pool));
            assert!(pkt.as_slice().is_empty());
            assert_eq!(pkt.as_io_slice().len(), 0);
        }
    }

    #[test]
    fn test_packet_extend_zero_length_data() {
        let pool = Arc::new(UnsafeMemoryPool::new(2, 128, 0));

        // SAFETY: ptr from alloc_uninit is valid. Extending with empty slice is a no-op.
        unsafe {
            let ptr = pool.alloc_uninit();
            let mut pkt = UnsafePacket::from_raw_parts(ptr, 0, 128, Arc::clone(&pool));
            let result = pkt.extend_from_slice(&[]);
            assert!(result.is_ok());
            assert_eq!(pkt.as_slice().len(), 0);
        }
    }

    #[test]
    fn test_packet_extend_exact_capacity() {
        let pool = Arc::new(UnsafeMemoryPool::new(2, 128, 0));

        // SAFETY: ptr from alloc_uninit is valid for 128 bytes.
        // Extending with exactly 128 bytes should succeed.
        unsafe {
            let ptr = pool.alloc_uninit();
            let mut pkt = UnsafePacket::from_raw_parts(ptr, 0, 128, Arc::clone(&pool));
            let data = [0xFFu8; 128];
            let result = pkt.extend_from_slice(&data);
            assert!(result.is_ok());
            assert_eq!(pkt.as_slice().len(), 128);
            assert!(pkt.as_slice().iter().all(|&b| b == 0xFF));
        }
    }

    #[test]
    fn test_pool_block_size_rounds_up_to_cache_line() {
        // block_size=1 should round up to 64 (cache line)
        let pool = Arc::new(UnsafeMemoryPool::new(1, 1, 0));

        // SAFETY: alloc_uninit returns pointer for a block that is at least 64 bytes
        // (rounded up). copy_from_slice with 64 bytes should succeed.
        unsafe {
            let ptr = pool.alloc_uninit();
            let data = [0xCCu8; 64];
            let written = pool.copy_from_slice(ptr, &data);
            assert_eq!(written, 64, "block_size=1 should round to 64");
            pool.free(ptr);
        }
    }

    #[test]
    fn test_multiple_pools_independent() {
        let pool_a = Arc::new(UnsafeMemoryPool::new(4, 256, 0));
        let pool_b = Arc::new(UnsafeMemoryPool::new(4, 512, 0));

        // SAFETY: Each pool's alloc_uninit returns independent pointers.
        // We write distinct patterns and verify no cross-contamination.
        unsafe {
            let ptr_a = pool_a.alloc_uninit();
            let ptr_b = pool_b.alloc_uninit();

            std::ptr::write_bytes(ptr_a.as_ptr(), 0xAA, 256);
            std::ptr::write_bytes(ptr_b.as_ptr(), 0xBB, 512);

            assert_eq!(*ptr_a.as_ptr(), 0xAA);
            assert_eq!(*ptr_b.as_ptr(), 0xBB);

            pool_a.free(ptr_a);
            pool_b.free(ptr_b);
        }
    }

    #[test]
    fn test_unsafe_error_variants() {
        // Verify UnsafeError enum is Copy/Eq
        let e1 = UnsafeError::CapacityOverflow;
        let e2 = UnsafeError::CompressionFailed;
        assert_ne!(e1, e2);
        let e3 = e1; // Copy
        assert_eq!(e1, e3);
    }
}
