//
// Foundational Structures for Global Optimizations
//

use qf_common::env_utils::EnvSnapshot;
use qf_cpu::{prefetch, PrefetchHint};
use qf_telemetry as telemetry;
use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, OnceLock};

use aligned_box::AlignedBox;
use crossbeam_queue::SegQueue;
use log::warn;

#[cfg(unix)]
use libc::{iovec, msghdr, recvmsg, sendmsg};
#[cfg(unix)]
use smallvec::SmallVec;
#[cfg(unix)]
use std::os::unix::io::RawFd;
#[cfg(windows)]
use windows_sys::Win32::Networking::WinSock::{
    WSAGetLastError, WSARecv, WSARecvFrom, WSASend, WSASendTo, WSABUF,
};

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
        let value = value.to_ascii_lowercase();
        if value == "local" {
            return NumaPolicy::Local;
        }
        if value == "interleave" {
            return NumaPolicy::Interleave;
        }
        if let Some(rest) = value.strip_prefix("preferred:") {
            if let Ok(node) = rest.parse::<usize>() {
                return NumaPolicy::Preferred(node);
            }
        }
    }
    NumaPolicy::Local
}

#[cfg(target_os = "linux")]
fn initialize_numa_policy(environment: &EnvSnapshot) {
    NUMA_POLICY.get_or_init(|| resolve_numa_policy_with_snapshot(environment));
}

#[cfg(target_os = "linux")]
static RR_NODE: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

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

    pub(crate) fn move_to_node(_ptr: *mut u8, _size: usize, _node: usize) {}
}

/// Pure classification of Windows NUMA API results.
///
/// Split out from the FFI module so the decision logic is provable on a non-Windows workspace.
/// The Windows adapter owns the calls; this owns what their outputs mean.
#[cfg(any(target_os = "windows", test))]
mod numa_classification {
    /// Node count implied by a successful `GetNumaHighestNodeNumber`.
    pub(super) fn node_count_from_highest(highest_node: u32) -> usize {
        (highest_node as usize).saturating_add(1)
    }

    /// Whether a successful `GetNumaHighestNodeNumber` means NUMA is usable.
    pub(super) fn available_from_query(query_succeeded: bool) -> bool {
        query_succeeded
    }

    /// Node index implied by a `GetNumaProcessorNodeEx` result.
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
        assert!(available_from_query(true), "a successful query means the topology is usable");
        assert_eq!(node_count_from_highest(0), 1, "highest node 0 means exactly one node");
        assert!(!available_from_query(false), "a failed query means unavailable");
    }

    #[test]
    fn node_count_is_one_more_than_the_highest_and_never_overflows() {
        assert_eq!(node_count_from_highest(1), 2);
        assert_eq!(node_count_from_highest(63), 64);
        assert_eq!(node_count_from_highest(u32::MAX), u32::MAX as usize + 1);
        assert!(node_count_from_highest(u32::MAX) > 0);
    }

    #[test]
    fn processor_node_result_honours_failure_and_the_no_node_sentinel() {
        assert_eq!(node_from_processor_result(true, 0), 0);
        assert_eq!(node_from_processor_result(true, 3), 3);
        assert_eq!(node_from_processor_result(true, u16::MAX), 0);
        assert_eq!(node_from_processor_result(false, 7), 0);
        assert_eq!(node_from_processor_result(false, u16::MAX), 0);
    }
}

#[cfg(target_os = "windows")]
mod numa {
    use super::numa_classification;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use windows_sys::Win32::System::Kernel::PROCESSOR_NUMBER;
    use windows_sys::Win32::System::Threading::{
        GetCurrentProcessorNumberEx, GetNumaHighestNodeNumber, GetNumaProcessorNodeEx,
    };

    static NUMA_NODES: AtomicUsize = AtomicUsize::new(0);

    pub fn is_available() -> bool {
        let mut highest_node = 0u32;
        let query_succeeded = unsafe { GetNumaHighestNodeNumber(&mut highest_node) } != 0;
        if query_succeeded {
            NUMA_NODES.store(
                numa_classification::node_count_from_highest(highest_node),
                Ordering::Relaxed,
            );
        }
        numa_classification::available_from_query(query_succeeded)
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
        let mut processor: PROCESSOR_NUMBER = unsafe { std::mem::zeroed() };
        unsafe { GetCurrentProcessorNumberEx(&mut processor) };
        let mut node = 0u16;
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
    fn try_new(
        capacity: Arc<AtomicUsize>,
        in_use: Arc<AtomicUsize>,
        available: Arc<AtomicUsize>,
        expected_capacity: usize,
    ) -> Result<Self, MemoryPoolError> {
        let mut state = PoolOwnershipState::default();
        state
            .records
            .try_reserve(expected_capacity)
            .map_err(|_| MemoryPoolError::AllocationFailed)?;
        Ok(Self {
            state: std::sync::Mutex::new(state),
            closed: AtomicBool::new(false),
            capacity,
            in_use,
            available,
        })
    }

    fn lock_state(&self) -> std::sync::MutexGuard<'_, PoolOwnershipState> {
        self.state.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    #[inline]
    fn decrement(counter: &AtomicUsize) {
        let _ = counter
            .try_update(Ordering::AcqRel, Ordering::Acquire, |value| Some(value.saturating_sub(1)));
    }

    fn register(
        &self,
        ptr: *const u8,
        origin: PoolBlockOrigin,
        location: PoolBlockLocation,
    ) -> bool {
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
            debug_slack: environment.parse::<usize>("QUICFUSCATE_POOL_DEBUG_SLACK").unwrap_or(256),
            #[cfg(debug_assertions)]
            debug_grace: environment.parse::<usize>("QUICFUSCATE_POOL_DEBUG_GRACE").unwrap_or(64),
            madvise_hugepage: environment.flag("QUICFUSCATE_MADVISE_HUGEPAGE", true),
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
            tls_low: environment.parse_positive_usize("QUICFUSCATE_TLS_LOW").unwrap_or(24),
            tls_high: environment.parse_positive_usize("QUICFUSCATE_TLS_HIGH").unwrap_or(48),
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

/// Platform-neutral failure values for the synchronous zero-copy syscall boundary.
#[cfg(any(unix, windows))]
#[derive(Debug)]
pub enum ZeroCopyError {
    InvalidBufferCount { count: usize, max: usize },
    BufferLengthTooLarge { index: usize, length: usize, max: usize },
    TotalLengthOverflow,
    InvalidTransferCount { transferred: usize, requested: usize },
    InvalidSocketAddress,
    InvalidSocketAddressLength { length: usize, max: usize },
    Io(io::Error),
}

#[cfg(any(unix, windows))]
impl std::fmt::Display for ZeroCopyError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidBufferCount { count, max } => {
                write!(formatter, "zero-copy buffer count {count} exceeds platform maximum {max}")
            }
            Self::BufferLengthTooLarge { index, length, max } => write!(
                formatter,
                "zero-copy buffer {index} length {length} exceeds platform maximum {max}"
            ),
            Self::TotalLengthOverflow => {
                formatter.write_str("zero-copy buffer lengths overflow usize")
            }
            Self::InvalidTransferCount { transferred, requested } => write!(
                formatter,
                "zero-copy syscall returned {transferred} bytes for {requested} requested bytes"
            ),
            Self::InvalidSocketAddress => {
                formatter.write_str("zero-copy syscall returned a non-IP socket address")
            }
            Self::InvalidSocketAddressLength { length, max } => {
                write!(formatter, "socket address length {length} exceeds platform maximum {max}")
            }
            Self::Io(error) => write!(formatter, "zero-copy syscall failed: {error}"),
        }
    }
}

#[cfg(any(unix, windows))]
impl std::error::Error for ZeroCopyError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            _ => None,
        }
    }
}

#[cfg(any(unix, windows))]
impl From<io::Error> for ZeroCopyError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

#[cfg(any(unix, windows))]
impl From<ZeroCopyError> for io::Error {
    fn from(error: ZeroCopyError) -> Self {
        match error {
            ZeroCopyError::Io(error) => error,
            other => {
                let kind = match &other {
                    ZeroCopyError::InvalidTransferCount { .. } => io::ErrorKind::InvalidData,
                    _ => io::ErrorKind::InvalidInput,
                };
                io::Error::new(kind, other)
            }
        }
    }
}

/// Result type for the platform-specific zero-copy boundary.
#[cfg(any(unix, windows))]
pub type ZeroCopyResult<T> = Result<T, ZeroCopyError>;

/// Explicit byte-count result for one synchronous zero-copy operation.
#[cfg(any(unix, windows))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ZeroCopyTransfer {
    transferred: usize,
    requested: usize,
}

#[cfg(any(unix, windows))]
impl ZeroCopyTransfer {
    fn from_syscall_count(transferred: usize, requested: usize) -> ZeroCopyResult<Self> {
        if transferred > requested {
            return Err(ZeroCopyError::InvalidTransferCount { transferred, requested });
        }
        Ok(Self { transferred, requested })
    }

    pub const fn transferred(self) -> usize {
        self.transferred
    }

    pub const fn requested(self) -> usize {
        self.requested
    }

    pub const fn is_zero(self) -> bool {
        self.transferred == 0
    }

    pub const fn is_complete(self) -> bool {
        self.transferred == self.requested
    }

    pub const fn is_partial(self) -> bool {
        self.transferred != 0 && self.transferred < self.requested
    }
}

#[cfg(any(unix, windows))]
fn checked_total_buffer_length<I>(lengths: I) -> ZeroCopyResult<usize>
where
    I: Iterator<Item = usize>,
{
    let mut total = 0usize;
    for length in lengths {
        total = total.checked_add(length).ok_or(ZeroCopyError::TotalLengthOverflow)?;
    }
    Ok(total)
}

#[cfg(any(unix, windows))]
fn checked_buffer_count(count: usize, max: usize) -> ZeroCopyResult<usize> {
    if count > max {
        return Err(ZeroCopyError::InvalidBufferCount { count, max });
    }
    Ok(count)
}

#[cfg(windows)]
fn checked_windows_buffer_count(count: usize) -> ZeroCopyResult<u32> {
    checked_buffer_count(count, u32::MAX as usize)?;
    u32::try_from(count)
        .map_err(|_| ZeroCopyError::InvalidBufferCount { count, max: u32::MAX as usize })
}

#[cfg(windows)]
fn checked_windows_buffer_length(index: usize, length: usize) -> ZeroCopyResult<u32> {
    if length > u32::MAX as usize {
        return Err(ZeroCopyError::BufferLengthTooLarge { index, length, max: u32::MAX as usize });
    }
    u32::try_from(length).map_err(|_| ZeroCopyError::BufferLengthTooLarge {
        index,
        length,
        max: u32::MAX as usize,
    })
}

#[cfg(windows)]
fn last_winsock_error() -> io::Error {
    // SAFETY: WSAGetLastError has no pointer arguments and reads the calling thread's
    // Winsock error slot immediately after the failed synchronous operation.
    io::Error::from_raw_os_error(unsafe { WSAGetLastError() })
}

#[cfg(unix)]
fn unix_iovec_max() -> usize {
    let abi_max = i32::MAX as usize;
    #[cfg(any(target_os = "android", target_os = "ios", target_os = "linux", target_os = "macos"))]
    {
        // A failed sysconf query is handled fail-closed. The common Linux/macOS
        // paths return the kernel's IOV_MAX value here.
        let configured = unsafe { libc::sysconf(libc::_SC_IOV_MAX) };
        if configured > 0 {
            return (configured as usize).min(abi_max);
        }
    }
    1
}

#[cfg(unix)]
fn checked_unix_iovec_count(count: usize) -> ZeroCopyResult<usize> {
    checked_buffer_count(count, unix_iovec_max())
}

#[cfg(unix)]
fn normalize_unix_count(raw: isize, requested: usize) -> ZeroCopyResult<ZeroCopyTransfer> {
    if raw < 0 {
        return Err(ZeroCopyError::Io(io::Error::last_os_error()));
    }
    ZeroCopyTransfer::from_syscall_count(raw as usize, requested)
}

/// A send-only buffer for synchronous zero-copy vectored I/O.
///
/// The input slices are borrowed for `'a` and must remain valid and unchanged for the
/// duration of every syscall using this value. `send` and `send_to` return a typed byte
/// count. `ZeroCopyTransfer::is_partial` identifies a positive short write; the wrapper
/// never retries because stream retry and datagram atomicity are caller-owned policies.
#[cfg(unix)]
pub struct ZeroCopyBuffer<'a> {
    iovecs: SmallVec<[iovec; 4]>,
    iov_count: usize,
    total_len: usize,
    _marker: std::marker::PhantomData<&'a [u8]>,
}

/// A receive-only buffer for synchronous zero-copy vectored I/O.
///
/// The outer slice and every inner mutable slice remain exclusively borrowed for `'a`,
/// preventing callers from accessing the receive regions while a syscall can write to them.
#[cfg(unix)]
pub struct ZeroCopyRecvBuffer<'a> {
    iovecs: SmallVec<[iovec; 4]>,
    iov_count: usize,
    total_len: usize,
    _marker: std::marker::PhantomData<&'a mut [&'a mut [u8]]>,
}

#[cfg(unix)]
impl<'a> ZeroCopyBuffer<'a> {
    /// Creates a send-only buffer from borrowed byte slices.
    pub fn new(buffers: &[&'a [u8]]) -> ZeroCopyResult<Self> {
        let iov_count = checked_unix_iovec_count(buffers.len())?;
        let total_len = checked_total_buffer_length(buffers.iter().map(|buffer| buffer.len()))?;
        let mut iovecs: SmallVec<[iovec; 4]> = SmallVec::with_capacity(buffers.len());
        for buffer in buffers {
            iovecs.push(iovec {
                iov_base: buffer.as_ptr() as *mut libc::c_void,
                iov_len: buffer.len(),
            });
        }
        Ok(Self { iovecs, iov_count, total_len, _marker: std::marker::PhantomData })
    }

    /// Sends the data using `sendmsg` for true zero-copy transmission.
    pub fn send(&self, fd: RawFd) -> ZeroCopyResult<ZeroCopyTransfer> {
        let msg = msghdr {
            msg_name: std::ptr::null_mut(),
            msg_namelen: 0,
            msg_iov: self.iovecs.as_ptr() as *mut _,
            // `iov_count` is bounded by the runtime IOV_MAX and i32 ABI bound above.
            msg_iovlen: self.iov_count as _,
            msg_control: std::ptr::null_mut(),
            msg_controllen: 0,
            msg_flags: 0,
        };
        normalize_unix_count(unsafe { sendmsg(fd, &msg, 0) }, self.total_len)
    }

    /// Sends the data to the specified address using `sendmsg`.
    pub fn send_to(&self, fd: RawFd, addr: SocketAddr) -> ZeroCopyResult<ZeroCopyTransfer> {
        use socket2::SockAddr;
        let sockaddr = SockAddr::from(addr);
        let msg = msghdr {
            msg_name: sockaddr.as_ptr() as *mut _,
            msg_namelen: sockaddr.len(),
            msg_iov: self.iovecs.as_ptr() as *mut _,
            msg_iovlen: self.iov_count as _,
            msg_control: std::ptr::null_mut(),
            msg_controllen: 0,
            msg_flags: 0,
        };
        normalize_unix_count(unsafe { sendmsg(fd, &msg, 0) }, self.total_len)
    }

    pub fn len(&self) -> usize {
        self.total_len
    }

    pub fn is_empty(&self) -> bool {
        self.iovecs.is_empty()
    }

    pub fn as_iovecs(&self) -> &[iovec] {
        &self.iovecs
    }
}

#[cfg(unix)]
impl<'a> ZeroCopyRecvBuffer<'a> {
    /// Creates a receive-only buffer from exclusively borrowed mutable slices.
    pub fn new_mut(buffers: &'a mut [&'a mut [u8]]) -> ZeroCopyResult<Self> {
        let iov_count = checked_unix_iovec_count(buffers.len())?;
        let total_len = checked_total_buffer_length(buffers.iter().map(|buffer| buffer.len()))?;
        let mut iovecs: SmallVec<[iovec; 4]> = SmallVec::with_capacity(buffers.len());
        for buffer in buffers.iter_mut() {
            iovecs.push(iovec {
                iov_base: buffer.as_mut_ptr() as *mut libc::c_void,
                iov_len: buffer.len(),
            });
        }
        Ok(Self { iovecs, iov_count, total_len, _marker: std::marker::PhantomData })
    }

    /// Receives data using `recvmsg` into the exclusively borrowed buffers.
    pub fn recv(&mut self, fd: RawFd) -> ZeroCopyResult<ZeroCopyTransfer> {
        let mut msg = msghdr {
            msg_name: std::ptr::null_mut(),
            msg_namelen: 0,
            msg_iov: self.iovecs.as_mut_ptr(),
            msg_iovlen: self.iov_count as _,
            msg_control: std::ptr::null_mut(),
            msg_controllen: 0,
            msg_flags: 0,
        };
        normalize_unix_count(unsafe { recvmsg(fd, &mut msg, 0) }, self.total_len)
    }

    /// Receives data and returns the sender address.
    pub fn recv_from(&mut self, fd: RawFd) -> ZeroCopyResult<(ZeroCopyTransfer, SocketAddr)> {
        use socket2::SockAddr;
        let (received, addr) = unsafe {
            SockAddr::try_init(|storage, len| {
                let mut msg = msghdr {
                    msg_name: storage.cast(),
                    msg_namelen: *len,
                    msg_iov: self.iovecs.as_mut_ptr(),
                    msg_iovlen: self.iov_count as _,
                    msg_control: std::ptr::null_mut(),
                    msg_controllen: 0,
                    msg_flags: 0,
                };
                let ret = recvmsg(fd, &mut msg, 0);
                if ret < 0 {
                    Err(io::Error::last_os_error())
                } else {
                    *len = msg.msg_namelen;
                    Ok(ret as usize)
                }
            })
        }
        .map_err(ZeroCopyError::Io)?;
        let socket_addr = addr.as_socket().ok_or(ZeroCopyError::InvalidSocketAddress)?;
        let transfer = ZeroCopyTransfer::from_syscall_count(received, self.total_len)?;
        Ok((transfer, socket_addr))
    }

    pub fn len(&self) -> usize {
        self.total_len
    }

    pub fn is_empty(&self) -> bool {
        self.iovecs.is_empty()
    }

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

#[cfg(unix)]
impl Drop for ZeroCopyRecvBuffer<'_> {
    fn drop(&mut self) {
        self.iovecs.clear();
    }
}

/// A send-only buffer for scatter/gather I/O using Windows Winsock.
#[cfg(windows)]
pub struct ZeroCopyBuffer<'a> {
    bufs: Vec<WSABUF>,
    buffer_count: u32,
    total_len: usize,
    _marker: std::marker::PhantomData<&'a [u8]>,
}

/// A receive-only buffer for scatter/gather I/O using Windows Winsock.
#[cfg(windows)]
pub struct ZeroCopyRecvBuffer<'a> {
    bufs: Vec<WSABUF>,
    buffer_count: u32,
    total_len: usize,
    _marker: std::marker::PhantomData<&'a mut [&'a mut [u8]]>,
}

#[cfg(windows)]
impl<'a> ZeroCopyBuffer<'a> {
    /// Creates a send-only buffer from borrowed immutable byte slices.
    pub fn new(buffers: &[&'a [u8]]) -> ZeroCopyResult<Self> {
        let buffer_count = checked_windows_buffer_count(buffers.len())?;
        let total_len = checked_total_buffer_length(buffers.iter().map(|buffer| buffer.len()))?;
        let mut bufs = Vec::with_capacity(buffers.len());
        for (index, buffer) in buffers.iter().enumerate() {
            let len = checked_windows_buffer_length(index, buffer.len())?;
            bufs.push(WSABUF { len, buf: buffer.as_ptr() as *mut u8 });
        }
        Ok(Self { bufs, buffer_count, total_len, _marker: std::marker::PhantomData })
    }

    /// Sends all registered buffers through a connected socket.
    pub fn send(
        &self,
        sock: windows_sys::Win32::Networking::WinSock::SOCKET,
    ) -> ZeroCopyResult<ZeroCopyTransfer> {
        let mut sent = 0u32;
        let result = unsafe {
            WSASend(
                sock,
                self.bufs.as_ptr(),
                self.buffer_count,
                &mut sent,
                0,
                core::ptr::null_mut(),
                None,
            )
        };
        if result != 0 {
            return Err(ZeroCopyError::Io(last_winsock_error()));
        }
        ZeroCopyTransfer::from_syscall_count(sent as usize, self.total_len)
    }

    /// Sends all registered buffers to the specified address.
    pub fn send_to(
        &self,
        sock: windows_sys::Win32::Networking::WinSock::SOCKET,
        addr: SocketAddr,
    ) -> ZeroCopyResult<ZeroCopyTransfer> {
        use socket2::SockAddr;
        let sockaddr = SockAddr::from(addr);
        let address_length = sockaddr.len();
        let mut sent = 0u32;
        let result = unsafe {
            WSASendTo(
                sock,
                self.bufs.as_ptr(),
                self.buffer_count,
                &mut sent,
                0,
                sockaddr.as_ptr().cast(),
                address_length,
                core::ptr::null_mut(),
                None,
            )
        };
        if result != 0 {
            return Err(ZeroCopyError::Io(last_winsock_error()));
        }
        ZeroCopyTransfer::from_syscall_count(sent as usize, self.total_len)
    }

    pub fn len(&self) -> usize {
        self.total_len
    }

    pub fn is_empty(&self) -> bool {
        self.bufs.is_empty()
    }
}

#[cfg(windows)]
impl<'a> ZeroCopyRecvBuffer<'a> {
    /// Creates a receive-only buffer from exclusively borrowed mutable slices.
    pub fn new_mut(buffers: &'a mut [&'a mut [u8]]) -> ZeroCopyResult<Self> {
        let buffer_count = checked_windows_buffer_count(buffers.len())?;
        let total_len = checked_total_buffer_length(buffers.iter().map(|buffer| buffer.len()))?;
        let mut bufs = Vec::with_capacity(buffers.len());
        for (index, buffer) in buffers.iter_mut().enumerate() {
            let len = checked_windows_buffer_length(index, buffer.len())?;
            bufs.push(WSABUF { len, buf: buffer.as_mut_ptr() });
        }
        Ok(Self { bufs, buffer_count, total_len, _marker: std::marker::PhantomData })
    }

    /// Receives data from a connected socket into the exclusively borrowed buffers.
    pub fn recv(
        &mut self,
        sock: windows_sys::Win32::Networking::WinSock::SOCKET,
    ) -> ZeroCopyResult<ZeroCopyTransfer> {
        let mut received = 0u32;
        let mut flags = 0u32;
        let result = unsafe {
            WSARecv(
                sock,
                self.bufs.as_ptr(),
                self.buffer_count,
                &mut received,
                &mut flags,
                core::ptr::null_mut(),
                None,
            )
        };
        if result != 0 {
            return Err(ZeroCopyError::Io(last_winsock_error()));
        }
        ZeroCopyTransfer::from_syscall_count(received as usize, self.total_len)
    }

    /// Receives data and returns the sender address.
    pub fn recv_from(
        &mut self,
        sock: windows_sys::Win32::Networking::WinSock::SOCKET,
    ) -> ZeroCopyResult<(ZeroCopyTransfer, SocketAddr)> {
        use socket2::SockAddr;
        let mut received_count = 0u32;
        let mut flags = 0u32;
        let (received, sockaddr) = unsafe {
            SockAddr::try_init(|storage, storage_len| {
                let result = WSARecvFrom(
                    sock,
                    self.bufs.as_ptr(),
                    self.buffer_count,
                    &mut received_count,
                    &mut flags,
                    storage.cast(),
                    storage_len,
                    core::ptr::null_mut(),
                    None,
                );
                if result == 0 {
                    Ok(received_count as usize)
                } else {
                    Err(last_winsock_error())
                }
            })
        }
        .map_err(ZeroCopyError::Io)?;
        let addr = sockaddr.as_socket().ok_or(ZeroCopyError::InvalidSocketAddress)?;
        let transfer = ZeroCopyTransfer::from_syscall_count(received, self.total_len)?;
        Ok((transfer, addr))
    }

    pub fn len(&self) -> usize {
        self.total_len
    }

    pub fn is_empty(&self) -> bool {
        self.bufs.is_empty()
    }
}

#[cfg(windows)]
impl Drop for ZeroCopyBuffer<'_> {
    fn drop(&mut self) {
        self.bufs.clear();
    }
}

#[cfg(windows)]
impl Drop for ZeroCopyRecvBuffer<'_> {
    fn drop(&mut self) {
        self.bufs.clear();
    }
}

#[cfg(test)]
mod memory_pool_growth_tests {
    use std::sync::atomic::Ordering;

    use super::{
        default_hard_max_capacity, MemoryPool, MemoryPoolError, MemoryPoolRuntimeConfig,
        PoolBlockLocation, PoolBlockOrigin, PoolOwnershipLedger, PooledBlock,
        DEFAULT_POOL_MAX_BYTES, LOCK_BLOCKS_TEST_MUTEX,
    };

    #[cfg(unix)]
    use super::{ZeroCopyBuffer, ZeroCopyRecvBuffer};
    #[cfg(any(unix, windows))]
    use super::{ZeroCopyError, ZeroCopyTransfer};

    #[cfg(any(unix, windows))]
    #[test]
    fn zero_copy_transfer_classifies_zero_complete_and_partial_progress() {
        let zero = ZeroCopyTransfer::from_syscall_count(0, 8).expect("zero result is valid");
        assert!(zero.is_zero());
        assert!(!zero.is_complete());
        assert!(!zero.is_partial());

        let partial = ZeroCopyTransfer::from_syscall_count(4, 8).expect("partial result is valid");
        assert_eq!(partial.transferred(), 4);
        assert_eq!(partial.requested(), 8);
        assert!(partial.is_partial());
        assert!(!partial.is_complete());

        let complete =
            ZeroCopyTransfer::from_syscall_count(8, 8).expect("complete result is valid");
        assert!(complete.is_complete());
        assert!(!complete.is_partial());
        assert!(matches!(
            ZeroCopyTransfer::from_syscall_count(9, 8),
            Err(ZeroCopyError::InvalidTransferCount { transferred: 9, requested: 8 })
        ));
    }

    #[cfg(unix)]
    #[test]
    fn unix_zero_copy_checks_iovec_count_and_normalizes_syscall_errors() {
        let maximum = super::unix_iovec_max();
        let data = [0u8; 1];
        let buffers = vec![&data[..]; maximum + 1];
        assert!(matches!(
            ZeroCopyBuffer::new(&buffers),
            Err(ZeroCopyError::InvalidBufferCount { .. })
        ));

        let payload = [1u8, 2, 3];
        let send = ZeroCopyBuffer::new(&[&payload[..]]).expect("valid send buffer");
        assert!(matches!(send.send(-1), Err(ZeroCopyError::Io(_))));

        let mut receive_storage = [0u8; 8];
        let mut receive_buffers = [&mut receive_storage[..]];
        let mut receive =
            ZeroCopyRecvBuffer::new_mut(&mut receive_buffers).expect("valid receive buffer");
        assert!(matches!(receive.recv(-1), Err(ZeroCopyError::Io(_))));
    }

    #[cfg(all(windows, target_pointer_width = "64"))]
    #[test]
    fn windows_zero_copy_checks_u32_abi_bounds() {
        assert!(matches!(
            super::checked_windows_buffer_length(0, u32::MAX as usize + 1),
            Err(ZeroCopyError::BufferLengthTooLarge { .. })
        ));
        assert!(matches!(
            super::checked_windows_buffer_count(u32::MAX as usize + 1),
            Err(ZeroCopyError::InvalidBufferCount { .. })
        ));
    }

    #[test]
    fn fallible_constructor_rejects_zero_and_unrepresentable_configuration() {
        assert!(matches!(MemoryPool::try_new(0, 4_096), Err(MemoryPoolError::InvalidCapacity)));
        assert!(matches!(MemoryPool::try_new(1, 0), Err(MemoryPoolError::InvalidBlockSize)));
        assert!(matches!(
            MemoryPool::try_new_adaptive(1, 0),
            Err(MemoryPoolError::InvalidBlockSize)
        ));
        assert!(matches!(
            MemoryPool::try_new(usize::MAX, 2_048),
            Err(MemoryPoolError::CapacityOverflow)
        ));
        assert!(matches!(
            MemoryPool::try_new(1, usize::MAX - 100),
            Err(MemoryPoolError::CapacityOverflow)
        ));
        assert!(matches!(super::checked_pool_layout(0), Err(MemoryPoolError::InvalidBlockSize)));
    }

    #[test]
    fn fallible_allocation_and_resize_preserve_the_existing_contract() {
        let pool = MemoryPool::try_new(1, 2_048).expect("valid fallible pool");
        let block = pool.try_alloc().expect("fallible allocation must succeed");
        assert_eq!(block.len(), 2_048);
        pool.free(block);
        pool.try_set_capacity(2).expect("fallible growth must succeed");
        assert_eq!(pool.capacity.load(Ordering::Acquire), 2);
        pool.try_set_capacity(0).expect("fallible shrink must succeed");
        assert_eq!(pool.capacity.load(Ordering::Acquire), 0);
    }

    #[test]
    fn pooled_block_drop_returns_the_checked_out_block() {
        use std::sync::Arc;

        let pool = Arc::new(MemoryPool::new(1, 2_048));
        let before = pool.accounting_snapshot();
        {
            let mut block = PooledBlock::new(Arc::clone(&pool));
            block[0] = 0xA5;
            assert_eq!(pool.in_use.load(Ordering::Acquire), before.1 + 1);
        }
        assert_eq!(pool.accounting_snapshot(), before);
        pool.ownership.assert_consistent();
    }

    #[test]
    fn pooled_block_transfer_disarms_only_the_guard() {
        use std::sync::Arc;

        let pool = Arc::new(MemoryPool::new(1, 2_048));
        let before = pool.accounting_snapshot();
        let mut guard = PooledBlock::new(Arc::clone(&pool));
        let originating_pool = guard.pool();
        let block = guard.take_block().expect("a new guard owns one block");
        drop(guard);
        assert_eq!(pool.in_use.load(Ordering::Acquire), before.1 + 1);
        originating_pool.free(block);
        assert_eq!(pool.accounting_snapshot(), before);
        pool.ownership.assert_consistent();
    }

    #[test]
    fn fallible_slice_allocation_rejects_oversized_data_and_copies_exact_data() {
        let pool = MemoryPool::try_new(1, 2_048).expect("valid fallible pool");
        let data = vec![0xA5; 2_200];
        assert!(matches!(
            pool.try_alloc_from_slice(&data),
            Err(MemoryPoolError::SliceTooLarge { requested: 2_200, block_size: 2_048 })
        ));
        let data = vec![0xA5; 2_048];
        let block = pool
            .try_alloc_from_slice(&data)
            .expect("fallible slice allocation must succeed for an exact block");
        assert_eq!(block.len(), 2_048);
        assert!(block.iter().all(|byte| *byte == 0xA5));
        pool.free(block);
    }

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
        let environment = qf_common::env_utils::EnvSnapshot::from_pairs([
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
        let environment =
            qf_common::env_utils::EnvSnapshot::from_pairs([("QUICFUSCATE_POOL_HARD_MAX_CAP", "1")]);
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
        let ledger = PoolOwnershipLedger::try_new(
            Arc::clone(&capacity),
            Arc::clone(&in_use),
            Arc::clone(&available),
            1,
        )
        .expect("one-record ledger reservation must succeed");
        let pointer = 0x1000usize as *const u8;

        assert!(ledger.register(
            pointer,
            PoolBlockOrigin::Accounted,
            PoolBlockLocation::CheckedOut
        ));
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
        let _guard = LOCK_BLOCKS_TEST_MUTEX.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
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
